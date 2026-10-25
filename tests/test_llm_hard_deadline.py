"""A stalled provider must not hang a report stage forever.

The failure this pins down (2026-10-21, two fresh samples):

  * ``urllib``'s socket timeout is a PER-READ timeout. A provider that keeps
    the connection alive with periodic bytes resets it on every arrival, so a
    request that never completes never trips it.
  * Measured on the analysis VM: a publish stage sat in ``poll()`` for 55
    minutes on ONE request, with a 600 s socket timeout, and had to be killed
    by hand. The stage timeout (4 h) was the only thing that would eventually
    have stopped it, and the report was lost with it.
  * The first attempted fix (a ``signal.SIGALRM`` timer plus a reader thread
    that closed the response) did not work: SIGALRM only fires in the main
    thread, so it breaks every ThreadPoolExecutor caller, and closing a
    response from another thread does not interrupt a blocked read on Linux.

The fix is a real wall-clock deadline: the request runs in a daemon thread and
is ABANDONED at the deadline, so the caller gets a ``TimeoutError`` and the
stage can fail or retry the section instead of hanging.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402


class _StuckResponse:
    """A response whose read never returns."""

    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *_a, **_kw):
        while True:
            time.sleep(0.05)

    def close(self):
        self.closed = True

    def __iter__(self):
        while True:
            time.sleep(0.05)
            yield b""


def _patch_stuck_urlopen(monkeypatch):
    import urllib.request

    def stuck_urlopen(request, timeout=None):
        return _StuckResponse()

    monkeypatch.setattr(urllib.request, "urlopen", stuck_urlopen)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_a, **_kw: 0)
    monkeypatch.setenv("REVAI_LLM_API_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "agnes-3.0-flash")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")


def test_http_post_bytes_returns_when_the_provider_never_answers(monkeypatch):
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_kw: _StuckResponse())
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        v2_lib._http_post_bytes(object(), 1, "test request")
    elapsed = time.monotonic() - start
    assert elapsed < 20, f"deadline did not fire promptly ({elapsed:.1f}s)"


def test_llm_judge_gives_up_on_a_stuck_provider_instead_of_hanging(monkeypatch):
    _patch_stuck_urlopen(monkeypatch)
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "1")
    start = time.monotonic()
    with pytest.raises(Exception) as excinfo:
        v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=1, timeout_s=1)
    elapsed = time.monotonic() - start
    assert elapsed < 60, f"llm_judge hung for {elapsed:.1f}s on a stuck provider"
    assert "deadline" in str(excinfo.value).lower() or "timeout" in str(
        excinfo.value).lower()


def test_a_normal_response_is_not_affected_by_the_deadline(monkeypatch):
    import urllib.request

    payload = {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}

    class _Ok:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *_a, **_kw):
            return json.dumps(payload).encode()

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_kw: _Ok())
    body = v2_lib._http_post_bytes(object(), 30, "test request")
    assert json.loads(body.decode())["choices"][0]["message"]["content"] == "ok"


def test_abandoned_requests_are_capped_so_connections_do_not_pile_up(monkeypatch):
    """A stuck provider must not leave an unbounded pile of open connections."""
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_kw: _StuckResponse())
    saved = list(v2_lib._abandoned_llm_requests)
    try:
        v2_lib._abandoned_llm_requests.clear()
        for _ in range(v2_lib._MAX_ABANDONED_LLM_REQUESTS):
            with pytest.raises(TimeoutError):
                v2_lib._http_post_bytes(object(), 1, "test request")
        assert len(v2_lib._abandoned_llm_requests) == (
            v2_lib._MAX_ABANDONED_LLM_REQUESTS)
        # One more attempt must fail fast rather than open another connection.
        with pytest.raises(TimeoutError) as excinfo:
            v2_lib._http_post_bytes(object(), 30, "test request")
        assert "was not started" in str(excinfo.value)
    finally:
        v2_lib._abandoned_llm_requests[:] = saved
