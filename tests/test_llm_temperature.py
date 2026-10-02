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
sys.path.insert(0, str(ROOT / "revai"))

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
    src = (ROOT / "revai" / "v2_lib.py").read_text(errors="replace")
    assert '"temperature": _llm_temperature()' in src, (
        "the request body hardcodes temperature again; the helper is inert")
    assert '"temperature": 0.0' not in src, (
        "a hardcoded temperature remains alongside the helper")


def test_the_shipped_template_documents_the_key(monkeypatch):
    """A key nobody documents is how this drifts in the first place."""
    tmpl = ROOT / "config" / "llm.env.template"
    assert tmpl.is_file(), "config/llm.env.template missing"
    assert "REVAI_LLM_TEMPERATURE" in tmpl.read_text(errors="replace"), (
        "REVAI_LLM_TEMPERATURE is not in the template")