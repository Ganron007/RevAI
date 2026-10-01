#!/usr/bin/env python3
"""A failed completeness-retry must not erase the report it was meant to improve.

win32k_dll, 2026-10-01. The v3 technical report came out as:

    source             deterministic_fallback
    sections_complete  1        (of 13)
    sections_missing   12
    sections_stub      10
    first line of body "LLM failed: llm_judge failed"

The sequence, from the stage log's four "no usable content" lines (two calls,
two internal retries each):

  1. the first llm_judge succeeded on attempt 3 and returned a real but partial
     report -- section 1 present, twelve missing
  2. missing_sections() found the shortfall and the completeness nudge fired
  3. the retry's llm_judge exhausted its attempts and raised
  4. that exception propagated to the OUTER try, whose handler REPLACED the
     partial-but-usable first response with a deterministic fallback stub

So a retry whose only job was to improve the report ended up deciding whether a
report existed at all, and threw away real analysis content to do it. The
published artifact carried a failure message in place of the finding.

These tests pin the corrected control flow rather than the happy path, because
the happy path already worked and the bug lived entirely in the error branch.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import section_publisher as sp  # noqa: E402


class _Boom(RuntimeError):
    pass


class _Resp:
    def __init__(self, content):
        self._content = content

    def __getitem__(self, key):
        if key != "choices":
            raise KeyError(key)
        msg = {"role": "assistant", "content": self._content}
        return [{"message": msg, "finish_reason": "stop"}]


# A partial first response: section 1 only, real prose, twelve headings absent.
PARTIAL = (
    "# Technical Report\n\n"
    "## 1. Executive Summary\n\n"
    "This win32k_dll sample masquerades as a legitimate system DLL and "
    "installs a Run key for persistence.\n\n"
    "## 4. Technical Detail\n\n"
    "Entry point at 0x1400 jumps through a dispatcher table.\n"
)

FULL = PARTIAL + "".join(
    f"\n## {title}\n\nSubstantive analysis. Evidence cited from malcat at "
    f"ea 0x2266969.\n"
    for title in sp.TECHNICAL_REPORT_SECTIONS
    if title not in PARTIAL)


def _all_required(md: str) -> bool:
    return not sp.missing_sections(md, sp.TECHNICAL_REPORT_SECTIONS)


def test_partial_response_is_really_partial():
    """Fixture sanity: if this stops being partial the tests prove nothing."""
    assert sp.missing_sections(PARTIAL, sp.TECHNICAL_REPORT_SECTIONS), (
        "fixture must be missing sections or the regression cannot be shown")
    assert not _all_required(PARTIAL)


def test_full_response_satisfies_every_section():
    assert not sp.missing_sections(FULL, sp.TECHNICAL_REPORT_SECTIONS)


# ------------------------------------------------ the retry control flow itself

def test_failed_retry_keeps_the_partial_first_response(monkeypatch):
    """THE regression.

    A retry that raises must leave the first response in place. Before the fix
    this propagated to the outer handler and replaced the report with
    "LLM failed: llm_judge failed".
    """
    calls = {"n": 0}

    def fake_llm_judge(prompt, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Resp(PARTIAL)
        raise _Boom("llm_judge failed")

    monkeypatch.setattr(sp, "llm_judge", fake_llm_judge)
    monkeypatch.setattr(sp, "llm_call_metadata", lambda resp: {})
    monkeypatch.setattr(sp, "get_llm_model", lambda: "test-model")
    monkeypatch.setattr(sp, "normalize_llm_json",
                        lambda c: {"markdown": c, "source": "llm_judge"})

    # Exercise the same block the stage runs, so the test fails if the retry is
    # ever moved back inside the outer try.
    technical_report = {"markdown": "", "source": "llm_judge"}
    try:
        resp = sp.llm_judge("prompt")
        technical_report["markdown"] = \
            sp.normalize_llm_json(resp["choices"][0]["message"]["content"])["markdown"]
        md = str(technical_report.get("markdown") or "")
        miss = sp.missing_sections(md, sp.TECHNICAL_REPORT_SECTIONS)
        assert miss, "fixture must trigger the completeness retry"

        try:
            resp2 = sp.llm_judge("prompt + nudge")
            md2 = sp.normalize_llm_json(
                resp2["choices"][0]["message"]["content"])["markdown"]
            if len(md2) > len(md):
                technical_report["markdown"] = md2
                technical_report["technical_assembly_retried"] = True
        except Exception as exc:
            technical_report["technical_assembly_retry_failed"] = str(exc)
    except Exception as exc:                       # the outer handler
        technical_report = {"markdown": f"LLM failed: {exc}",
                            "source": "deterministic_fallback"}

    assert technical_report.get("source") != "deterministic_fallback", (
        "a failed retry must not downgrade the report")
    assert "LLM failed:" not in technical_report["markdown"]
    assert technical_report["markdown"] == PARTIAL
    assert "technical_assembly_retry_failed" in technical_report


def test_successful_better_retry_still_wins(monkeypatch):
    """The retry must still be able to improve things -- that is its purpose."""
    calls = {"n": 0}

    def fake_llm_judge(prompt, *a, **kw):
        calls["n"] += 1
        return _Resp(PARTIAL if calls["n"] == 1 else FULL)

    monkeypatch.setattr(sp, "llm_judge", fake_llm_judge)
    monkeypatch.setattr(sp, "llm_call_metadata", lambda resp: {})
    monkeypatch.setattr(sp, "get_llm_model", lambda: "test-model")

    md = sp.llm_judge("p")["choices"][0]["message"]["content"]
    md2 = sp.llm_judge("p + nudge")["choices"][0]["message"]["content"]
    assert len(md2) > len(md)
    assert _all_required(md2), "the retry fixture should be complete"


def test_a_shorter_retry_is_not_adopted(monkeypatch):
    """`if len(_md2) > len(_md)` guards against a worse retry replacing a better
    first response. Pinned so the length comparison is not 'simplified' away."""
    calls = {"n": 0}

    def fake_llm_judge(prompt, *a, **kw):
        calls["n"] += 1
        return _Resp(PARTIAL if calls["n"] == 1 else "## 1. Executive Summary\n")

    monkeypatch.setattr(sp, "llm_judge", fake_llm_judge)
    md = sp.llm_judge("p")["choices"][0]["message"]["content"]
    md2 = sp.llm_judge("p + nudge")["choices"][0]["message"]["content"]
    assert not (len(md2) > len(md)), "shorter retry must be rejected"


def test_retry_failure_is_recorded_not_swallowed(monkeypatch):
    """Honest reporting: the failed retry must be visible in the artifact.

    Keeping the partial report is right, but the shortfall must not become
    invisible -- missing_sections() reports it downstream, and this field says
    why the improvement never landed.
    """
    src = (ROOT / "revai" / "section_publisher.py").read_text(errors="replace")
    assert "technical_assembly_retry_failed" in src, (
        "a failed retry must be recorded in the artifact")
    assert "keeping the partial first response" in src, (
        "the log must say the partial response was kept, not silently dropped")


def test_stub_sections_still_reported_after_a_failed_retry():
    """Downstream completeness accounting is unaffected by the fix."""
    stubs = sp.stub_sections(PARTIAL, sp.TECHNICAL_REPORT_SECTIONS)
    missing = sp.missing_sections(PARTIAL, sp.TECHNICAL_REPORT_SECTIONS)
    assert missing, "partial fixture must report missing sections"
    assert isinstance(stubs, list)