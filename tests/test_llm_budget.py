#!/usr/bin/env python3
"""The LLM budget that stops us throttling ourselves (2026-09-28).

Campaign evidence: total request volume is single-digit per minute against a
1000 RPM provider limit, yet 4 of 5 samples hit HTTP 429. The cause was our own
concurrency - `section_publisher` runs 4 report-section calls at a time (17 then
13) and `agentic_recover_v4` runs 8 function-naming calls at a time - each with a
prompt of tens of thousands of tokens, plus a jitter-free backoff that made N
throttled threads re-fire together.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


def _reset(monkeypatch, rpm="1000", tpm="100000000"):
    monkeypatch.setenv("REVAI_LLM_BUDGET", "1")
    monkeypatch.setenv("REVAI_LLM_RPM", rpm)
    monkeypatch.setenv("REVAI_LLM_TPM", tpm)
    v2_lib.llm_budget_reset()


def test_estimate_scales_with_prompt_size():
    small = v2_lib.estimate_llm_tokens("x" * 3500)
    large = v2_lib.estimate_llm_tokens("x" * 350000)
    assert small > 4000          # 1000 chars + completion allowance
    # 100x the prompt must cost far more than the fixed completion allowance
    assert large > small * 20
    assert large - small > 90000


def test_budget_allows_a_burst_up_to_the_rpm(monkeypatch):
    _reset(monkeypatch, rpm="5", tpm="100000000")
    started = time.time()
    for _ in range(5):
        assert v2_lib.llm_budget_acquire(1000) == 0.0
    assert time.time() - started < 1.0        # no waiting inside the budget
    state = v2_lib.llm_budget_state()
    assert state["calls_in_window"] == 5


def test_budget_blocks_the_sixth_call_over_rpm(monkeypatch):
    """The regression: 6 parallel calls with rpm=5 must not all fire at once."""
    _reset(monkeypatch, rpm="5", tpm="100000000")
    monkeypatch.setattr(v2_lib, "_LLM_BUDGET_WINDOW_S", 0.4)  # keep the test quick
    for _ in range(5):
        v2_lib.llm_budget_acquire(1000)
    started = time.time()
    waited = v2_lib.llm_budget_acquire(1000)
    assert waited >= 0.2, "the 6th call should have waited"
    assert time.time() - started >= 0.2


def test_budget_blocks_on_tokens_not_requests(monkeypatch):
    """A few huge prompts must throttle even when RPM is generous."""
    _reset(monkeypatch, rpm="1000", tpm="20000")
    v2_lib.llm_budget_acquire(9000)
    v2_lib.llm_budget_acquire(9000)
    monkeypatch.setattr(v2_lib, "_LLM_BUDGET_WINDOW_S", 0.4)
    started = time.time()
    waited = v2_lib.llm_budget_acquire(9000)
    assert waited >= 0.2, "token budget should throttle the third huge call"
    assert time.time() - started >= 0.2


def test_parallel_threads_are_serialized_not_deadlocked(monkeypatch):
    """8 threads, rpm=3: all must finish, none may deadlock."""
    _reset(monkeypatch, rpm="3", tpm="100000000")
    monkeypatch.setattr(v2_lib, "_LLM_BUDGET_WINDOW_S", 0.3)
    done: list[int] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        v2_lib.llm_budget_acquire(500)
        with lock:
            done.append(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert len(done) == 8, f"only {len(done)} finished - possible deadlock"
    assert all(not t.is_alive() for t in threads)


def test_budget_can_be_disabled(monkeypatch):
    monkeypatch.setenv("REVAI_LLM_BUDGET", "0")
    monkeypatch.setenv("REVAI_LLM_RPM", "1")
    monkeypatch.setenv("REVAI_LLM_TPM", "1000")
    v2_lib.llm_budget_reset()
    for _ in range(5):
        assert v2_lib.llm_budget_acquire(10_000_000) == 0.0
    assert v2_lib.llm_budget_state()["enabled"] is False


def test_state_reports_the_configured_limits(monkeypatch):
    _reset(monkeypatch, rpm="42", tpm="123456")
    state = v2_lib.llm_budget_state()
    assert state["rpm_limit"] == 42
    assert state["tpm_limit"] == 123456
    assert state["tokens_in_window"] == 0


def _stage_source(name: str) -> str:
    """Read a stage module from either runtime layout.

    A source checkout has revai/<name>.py; the VM's deployed flat layout has
    <name>.py next to the other scripts. Hardcoding the checkout path made this
    test fail on the VM with FileNotFoundError, which meant verify-release.sh
    could never return PASS there -- a gate that cannot pass is not a gate.
    """
    for candidate in (ROOT / "revai" / name, ROOT / name):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError(f"cannot locate {name} under {ROOT}")


def test_stages_that_fire_calls_in_parallel_are_the_reason():
    """Guard the diagnosis: if someone parallelises another LLM stage, this fails."""
    assert "ThreadPoolExecutor" in _stage_source("section_publisher.py")
    assert "ThreadPoolExecutor" in _stage_source("agentic_recover_v4.py")
    # the budget is the only thing standing between those pools and the limiter
    assert hasattr(v2_lib, "llm_budget_acquire")
