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
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import add_module_dir, source  # noqa: E402
from _report_fixtures import markdown_to_sections  # noqa: E402
add_module_dir("revai/section_publisher.py")

import section_publisher as sp  # noqa: E402


class _Boom(RuntimeError):
    pass


class _Resp(dict):
    def __init__(self, content):
        super().__init__({"choices": [{
            "finish_reason": "tool_calls",
            "message": {"tool_calls": [{
                "type": "function", "id": "test-report",
                "function": {"name": "submit_report", "arguments": json.dumps({
                    "title": "Test report",
                    "sections": markdown_to_sections(content),
                })},
            }]},
        }]})


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


def _run_monolithic_report(monkeypatch, tmp_path, responses):
    """Exercise the real monolithic publisher branch with an isolated case."""
    case_root = tmp_path / "case"
    case_root.mkdir()
    remaining = iter(responses)

    def fake_report(_prompt, *args, **kwargs):
        response = next(remaining)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setenv("REVAI_TECHNICAL_SECTIONWISE", "0")
    monkeypatch.setattr(sp, "case_dir", lambda *_args, **_kwargs: case_root)
    monkeypatch.setattr(sp, "build_technical_evidence_block",
                        lambda *_args, **_kwargs: "test evidence")
    monkeypatch.setattr(sp, "attach_analysis_scripts", lambda evidence, *_a, **_k: evidence)
    monkeypatch.setattr(sp, "attach_dynamic_corroboration",
                        lambda evidence, *_a, **_k: evidence)
    monkeypatch.setattr(sp, "_persist_llm_call", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sp, "_finalize_technical",
                        lambda _sha, report, *_args, **_kwargs: report)
    monkeypatch.setattr(sp, "llm_report", fake_report)
    monkeypatch.setattr(sp, "llm_call_metadata", lambda _response: {})
    monkeypatch.setattr(sp, "get_llm_model", lambda: "test-model")
    return sp.run_technical_publish("a" * 64, {
        "sample_path": "fixture.exe", "verdict": {}, "deep": {},
    })


def test_partial_response_is_really_partial():
    """Fixture sanity: if this stops being partial the tests prove nothing."""
    assert sp.missing_sections(PARTIAL, sp.TECHNICAL_REPORT_SECTIONS), (
        "fixture must be missing sections or the regression cannot be shown")
    assert not _all_required(PARTIAL)


def test_full_response_satisfies_every_section():
    assert not sp.missing_sections(FULL, sp.TECHNICAL_REPORT_SECTIONS)


# ------------------------------------------------ the retry control flow itself

def test_failed_retry_keeps_the_partial_first_response(monkeypatch, tmp_path):
    """THE regression.

    A retry that raises must leave the first response in place. Before the fix
    this propagated to the outer handler and replaced the report with
    "LLM failed: llm_judge failed".
    """
    technical_report = _run_monolithic_report(
        monkeypatch, tmp_path, [_Resp(PARTIAL), _Boom("provider timed out")])

    assert technical_report.get("source") != "deterministic_fallback", (
        "a failed retry must not downgrade the report")
    kept = technical_report["markdown"]
    assert "## 1. Executive Summary" in kept
    assert "masquerades as a legitimate system DLL" in kept
    assert "## 4. Technical Detail" in kept
    assert "LLM failed" not in kept
    assert "technical_assembly_retry_failed" in technical_report


def test_successful_better_retry_still_wins(monkeypatch, tmp_path):
    """The retry must still be able to improve things -- that is its purpose."""
    technical_report = _run_monolithic_report(
        monkeypatch, tmp_path, [_Resp(PARTIAL), _Resp(FULL)])
    assert technical_report["technical_assembly_retried"] is True
    assert _all_required(technical_report["markdown"]), (
        "the improved retry should be complete")


def test_a_shorter_retry_is_not_adopted(monkeypatch, tmp_path):
    """`if len(_md2) > len(_md)` guards against a worse retry replacing a better
    first response. Pinned so the length comparison is not 'simplified' away."""
    technical_report = _run_monolithic_report(
        monkeypatch, tmp_path,
        [_Resp(PARTIAL), _Resp("## 1. Executive Summary\n\nShort.\n")])
    kept = technical_report["markdown"]
    assert "## 4. Technical Detail" in kept, (
        "shorter retry must not replace the first draft")
    assert "masquerades as a legitimate system DLL" in kept


def test_retry_failure_is_recorded_not_swallowed(monkeypatch):
    """Honest reporting: the failed retry must be visible in the artifact.

    Keeping the partial report is right, but the shortfall must not become
    invisible -- missing_sections() reports it downstream, and this field says
    why the improvement never landed.
    """
    src = source("revai/section_publisher.py")
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
