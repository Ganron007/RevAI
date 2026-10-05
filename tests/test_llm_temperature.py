#!/usr/bin/env python3
"""REVAI_LLM_TEMPERATURE was inert: declared in llm.env, read nowhere.

Found 2026-10-02 while syncing the provider config. The operator's
config-of-record carried `REVAI_LLM_TEMPERATURE=0.2`; the request body hardcoded
`"temperature": 0.0`, so the key was read NOWHERE and the setting did nothing.

Worth a test on its own merits. An inert config key looks exactly like a live
one when you read the file, so it is discovered by reading the code -- and the
failure is invisible in every run: nothing errors, the reports are fine, and the
operator's intent is simply discarded. Same shape as the hollow-success defects
from the previous session.

The default stays 0.0 deliberately. Scripted mode is specified as deterministic,
so making the key work must not change the behaviour of any existing run.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import add_module_dir, resolve, source  # noqa: E402

add_module_dir("revai/v2_lib.py")

import v2_lib  # noqa: E402


def test_default_is_deterministic_zero(monkeypatch):
    monkeypatch.delenv("REVAI_LLM_TEMPERATURE", raising=False)
    assert v2_lib._llm_temperature() == 0.0


def test_operator_value_is_honoured(monkeypatch):
    """The bug: this value used to be discarded."""
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "0.2")
    assert v2_lib._llm_temperature() == 0.2


def test_blank_falls_back_to_zero(monkeypatch):
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "   ")
    assert v2_lib._llm_temperature() == 0.0


def test_garbage_falls_back_instead_of_raising(monkeypatch):
    """A typo in a config file must not take a stage down."""
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "warm")
    assert v2_lib._llm_temperature() == 0.0


def test_out_of_range_is_clamped(monkeypatch):
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "9")
    assert v2_lib._llm_temperature() == 2.0
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "-3")
    assert v2_lib._llm_temperature() == 0.0


def test_the_request_body_actually_uses_it(monkeypatch):
    """Pin the call site.

    A helper that exists but is not wired into the request body is the same
    defect one level up -- this is why the body is inspected, not just the
    function.
    """
    src = source("revai/v2_lib.py")
    assert '"temperature": _llm_temperature()' in src, (
        "the request body hardcodes temperature again; the helper is inert")
    assert '"temperature": 0.0' not in src, (
        "a hardcoded temperature remains alongside the helper")


def test_the_shipped_template_documents_the_key():
    """A key nobody documents is how this drifts in the first place."""
    tmpl = resolve("config/llm.env.template")
    if not tmpl.is_file():
        # The VM deploys scripts flat and does not ship config/; skip rather
        # than fail on a layout the code never runs in.
        import pytest
        pytest.skip("config/llm.env.template not deployed on this host")
    assert "REVAI_LLM_TEMPERATURE" in tmpl.read_text(errors="replace"), (
        "REVAI_LLM_TEMPERATURE is not in the template")

# --------------------------------------------------------------------------
# 2026-10-03: NaN guard + the LangGraph path
# --------------------------------------------------------------------------

def test_nan_and_inf_fall_back_to_the_default(monkeypatch):
    """min(2.0, nan) evaluates to 2.0, so the clamp alone admits NaN.

    Every comparison against NaN is False, which silently produced the HOTTEST
    allowed temperature from a garbage value; the review catch was that the
    docstring claimed unparseable values fall back while nan did not.
    """
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "nan")
    assert v2_lib._llm_temperature() == 0.0
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "inf")
    assert v2_lib._llm_temperature() == 0.0
    monkeypatch.setenv("REVAI_LLM_TEMPERATURE", "-inf")
    assert v2_lib._llm_temperature() == 0.0


def test_the_langgraph_path_uses_the_resolver_too():
    """agentic_langgraph and stage_orchestrator construct ChatOpenAI directly.

    They hardcoded temperature=0.0, so fixing only the urllib body left the
    declared key inert on the agentic path -- the same declared-but-inert
    shape, one layer over. Structural: every request-making ChatOpenAI site
    must go through get_llm_temperature(). (The /api/graph placeholder agent
    never generates and is exempt.)
    """
    for name in ("revai/agentic_langgraph.py", "revai/stage_orchestrator.py"):
        src = source(name)
        assert "temperature=get_llm_temperature()" in src, (
            f"{name}: ChatOpenAI does not use get_llm_temperature(); "
            "REVAI_LLM_TEMPERATURE is inert on this path again")
        assert "temperature=0.0" not in src, (
            f"{name}: a hardcoded temperature remains alongside the resolver")
