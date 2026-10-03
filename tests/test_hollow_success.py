#!/usr/bin/env python3
"""The hollow-success detector must fire on the artifacts that actually shipped.

Each test case here is a real artifact shape from 2026-09-28..10-01, not a
synthetic one: the 110 `unknown_*` names at confidence 0.1, the panel that said
`suspicious` while the lock said `malicious`, the llm_judge call that gave up,
the report that degenerated into one repeated token.

The false-positive direction matters just as much. A detector that fails every
legitimate report is worse than none, because it trains the operator to ignore
it -- so the second half of this file pins the cases that must stay clean.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import hollow_success as hs  # noqa: E402


def _checks(findings, case=None):
    if case:
        findings = [f.check if isinstance(f, hs.Finding) else f["check"]
                    for f in findings]
    else:
        findings = [f.check for f in findings]
    return set(findings)


# ------------------------------------------------------------ the real artifacts

def test_defect_31_recovery_of_nothing():
    """110 results, 0 errors, every name unknown_* at the floor, no pseudocode.

    The stage exited rc=0 and the audit could not see it.
    """
    data = {"function_results": [
        {"source": "llm_judge", "function_name": f"unknown_{i}",
         "confidence": 0.1, "normalized_pseudocode": ""}
        for i in range(110)]}
    got = _checks(hs.check_function_recovery(data))
    assert "recovery.unknown_names" in got, got
    assert "recovery.empty_pseudocode" in got, got
    assert "recovery.confidence_floor" in got, got


def test_defect_32_recovery_with_no_context_but_some_names():
    """Same failure wearing a thinner disguise: names present, bodies absent."""
    data = {"function_results": [
        {"source": "llm_judge", "function_name": f"fn_{i}",
         "confidence": 0.1, "normalized_pseudocode": ""}
        for i in range(60)]}
    got = _checks(hs.check_function_recovery(data))
    assert "recovery.empty_pseudocode" in got, got
    assert "recovery.confidence_floor" in got, got


def test_degenerate_naming_detected():
    data = {"function_results": [
        {"source": "llm_judge", "function_name": "unknown_sub",
         "confidence": 0.5, "normalized_pseudocode": "void f(){}"}
        for _ in range(40)]}
    got = _checks(hs.check_function_recovery(data))
    assert "recovery.degenerate_names" in got, got


def test_fallback_verdict_sources_are_flagged():
    got = _checks(hs.check_verdict_sources(
        {"source": "fallback_v1", "verdict": "suspicious"},
        {"source": "deep_dive_agentic"},
        {"source": "llm_judge"}))
    assert got == {"verdict.fallback_source.quick_scan"}, got


def test_publish_fallback_is_flagged_separately():
    got = _checks(hs.check_verdict_sources(
        {"source": "llm_judge"}, {"source": "deep_dive_agentic"},
        {"source": "deterministic_fallback"}))
    assert got == {"verdict.fallback_source.publish"}, got


def test_verdict_panel_disagreement_detected(tmp_path):
    (tmp_path / "REPORT-MASTER-v2.md").write_text(
        "| **Final** | **suspicious** |\n", encoding="utf-8")
    (tmp_path / "REPORT-TECHNICAL-v2.md").write_text(
        "| **Final** | **unknown** |\n", encoding="utf-8")
    got = _checks(hs.check_verdict_panel_agreement(tmp_path))
    assert "verdict.panel_disagreement" in got, got


def test_exhausted_llm_calls_detected(tmp_path):
    (tmp_path / "pipeline_single.log").write_text(
        "[llm_judge] attempt 1/3 failed (HTTPError: 500)\n"
        "[llm_judge] attempt 3/3 failed (HTTPError: 500)\n"
        "[publish_report_v2] llm_judge failed\n", encoding="utf-8")
    got = _checks(hs.check_exhausted_llm_calls(tmp_path))
    assert "llm.exhausted" in got, got
    assert "llm.terminal_abort" in got, got


def test_degenerate_report_text_detected():
    md = "## 1. Executive Summary\n\n" + ("final_placeholder " * 400)
    got = _checks(hs.check_report_degenerate(md))
    assert "report.degenerate_repetition" in got, got


def test_duplicate_sections_detected():
    body = "identical content here\n" * 20
    md = (f"# 1. Executive Summary\n{body}\n"
          f"# 2. Sample Metadata\n{body}\n")
    got = _checks(hs.check_duplicate_sections(md))
    assert "report.duplicate_sections" in got, got


# --------------------------------------------------------- must NOT fire (noise)

def test_real_recovery_from_win32k_is_clean():
    """The 2026-09-30 win32k_dll artifact: real names, real bodies, real spread."""
    results = [
        {"source": "llm_judge", "function_name": "memset", "confidence": 0.92,
         "normalized_pseudocode": "void *memset(void *s, int c, size_t n){}"},
        {"source": "llm_judge", "function_name": "heap_realloc",
         "confidence": 0.92, "normalized_pseudocode": "void *heap_realloc(){}"},
        {"source": "llm_judge", "function_name": "atomic_increment",
         "confidence": 0.95, "normalized_pseudocode": "int atomic_increment(){}"},
        {"source": "llm_judge", "function_name": "spin_delay",
         "confidence": 0.72, "normalized_pseudocode": "void spin_delay(){}"},
        {"source": "existing_symbol", "function_name": "FUN_00401000",
         "confidence": 0.0, "normalized_pseudocode": ""},
    ]
    results += [
        {"source": "llm_judge", "function_name": f"helper_{i}",
         "confidence": 0.6 + (i % 3) / 10,
         "normalized_pseudocode": f"int helper_{i}(){{ return {i}; }}"}
        for i in range(15)
    ]
    assert hs.check_function_recovery(
        {"function_results": results}) == [], \
        hs.check_function_recovery({"function_results": results})


def test_small_result_sets_are_not_judged_on_ratios():
    """Three functions should not fail for having three placeholders."""
    data = {"function_results": [
        {"source": "llm_judge", "function_name": "unknown_a", "confidence": 0.1,
         "normalized_pseudocode": ""}]}
    assert hs.check_function_recovery(data) == []


def test_low_confidence_but_real_content_is_not_hollow():
    """Honest low confidence is a finding, not a failure."""
    data = {"function_results": [
        {"source": "llm_judge", "function_name": f"fn_{i}", "confidence": 0.3,
         "normalized_pseudocode": f"int fn_{i}(){{}}"} for i in range(30)]}
    assert hs.check_function_recovery(data) == []


def test_agreeing_panels_and_real_judges_are_clean(tmp_path):
    for name in ("REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md"):
        (tmp_path / name).write_text(
            "| **Final** | **malicious** |\n", encoding="utf-8")
    assert hs.check_verdict_panel_agreement(tmp_path) == []
    assert hs.check_verdict_sources({"source": "llm_judge"},
                                    {"source": "deep_dive_agentic"},
                                    {"source": "llm_judge"}) == []


def test_clean_logs_do_not_trip_the_exhaustion_check(tmp_path):
    (tmp_path / "pipeline_single.log").write_text(
        "[llm_judge] attempt 1/3 HTTP 429; retrying in 2.8s\n"
        "[llm_judge] attempt 1/3 returned no usable content; retrying\n",
        encoding="utf-8")
    assert hs.check_exhausted_llm_calls(tmp_path) == []


def test_normal_report_text_is_clean():
    md = ("# 1. Executive Summary\n\nThis sample is a banking trojan that "
          "installs a Run key for persistence and beacons to a C2 host. " * 20)
    assert hs.check_report_degenerate(md) == []
    assert hs.check_duplicate_sections(md) == []


# ------------------------------------------------------------------- aggregate

def test_evaluate_case_aggregates_and_is_read_only(tmp_path):
    """The entry point must combine everything and never raise on missing files."""
    (tmp_path / "function_recovery.json").write_text(json.dumps({
        "function_results": [
            {"source": "llm_judge", "function_name": "unknown_x",
             "confidence": 0.1, "normalized_pseudocode": ""}] * 30,
    }), encoding="utf-8")
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is False
    assert out["count"] == len(out["findings"]) >= 1
    assert all("check" in f and "detail" in f for f in out["findings"])


def test_evaluate_case_on_an_empty_dir_is_clean_not_an_error(tmp_path):
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is True
    assert out["findings"] == []


def test_partial_naming_is_advisory_not_a_gate():
    """52% unknown_* with real content must be reported, not failed.

    Measured on 2026-10-01: raas (a green case) left 53% of recovered functions
    unnamed with real pseudocode and a real confidence spread. Gating that would
    be wrong -- the artifact has content -- but ignoring it would hide the reason
    `function_recovery.json` reports 87 of 200 llm_candidates on big samples.
    """
    results = [
        {"source": "llm_judge", "function_name": "unknown_x",
         "confidence": 0.7, "normalized_pseudocode": "void f(){}"}
        if i % 2 else
        {"source": "llm_judge", "function_name": f"real_{i}",
         "confidence": 0.8, "normalized_pseudocode": "int g(){}"}
        for i in range(60)
    ]
    data = {"function_results": results,
            "triage": {"llm_candidates": 200}}
    assert hs.check_function_recovery(data) == [], "must not gate"

    adv = hs._advisory(data)
    assert adv["judged"] is True
    assert 0.45 < adv["unresolved_name_ratio"] < 0.55, adv
    assert adv["results_vs_candidates"] == "60/200", adv
    assert "not a hollow success" in adv["note"]


def test_advisory_absent_for_tiny_or_missing_recovery():
    assert hs._advisory(None) == {}
    tiny = {"function_results": [
        {"source": "llm_judge", "function_name": "unknown_a",
         "confidence": 0.1, "normalized_pseudocode": ""}]}
    adv = hs._advisory(tiny)
    assert adv["judged"] is False
    assert "unresolved_name_ratio" not in adv


# --------------------------------------------------------------------------
# 2026-10-03: stale artifacts from a previous run must not be judged
# --------------------------------------------------------------------------

import os  # noqa: E402
import time  # noqa: E402


def _write_run_banner(case):
    """Append a RUN START banner whose timestamp is genuinely in the past.

    `_run_start_epoch` parses the banner TEXT, so the stamp must be a real
    UTC instant before now -- a hardcoded date drifts into the future as the
    machine clock advances, and `time.mktime` would misread it as local time.
    """
    past = time.time() - 3600
    utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(past))
    (case / "pipeline_single.log").write_text(
        f"old run's exhausted call line: llm_judge failed\n"
        f"===== RUN START {utc} =====\n"
        "this run so far has no failures\n",
        encoding="utf-8")


def test_exhausted_call_needles_before_the_banner_are_not_this_runs():
    case = Path(__import__("tempfile").mkdtemp())
    _write_run_banner(case)
    got = _checks(hs.check_exhausted_llm_calls(case))
    assert "llm.exhausted" not in got, got


def test_sidecar_older_than_the_banner_is_skipped():
    case = Path(__import__("tempfile").mkdtemp())
    _write_run_banner(case)
    stale = case / "report-technical-v3.json"
    stale.write_text(json.dumps({
        "source": "deterministic_fallback",
        "sections_missing": list(range(12)), "sections_stub": [],
        "sections_complete": 1}), encoding="utf-8")
    stamp = time.time() - 7200
    os.utime(stale, (stamp, stamp))
    got = _checks(hs.check_report_sidecars(case))
    assert not got, f"stale sidecar was judged as this run's: {got}"


def test_sidecar_written_after_the_banner_is_judged():
    case = Path(__import__("tempfile").mkdtemp())
    _write_run_banner(case)
    fresh = case / "report-technical-v3.json"
    fresh.write_text(json.dumps({
        "source": "deterministic_fallback",
        "sections_missing": list(range(12)), "sections_stub": [],
        "sections_complete": 1}), encoding="utf-8")
    got = _checks(hs.check_report_sidecars(case))
    assert "report.fallback_source" in got, got


def test_no_banner_means_everything_is_judged():
    """The boundary is opt-in: other runners and legacy cases are unchanged."""
    case = Path(__import__("tempfile").mkdtemp())
    (case / "report-technical-v3.json").write_text(json.dumps({
        "source": "deterministic_fallback",
        "sections_missing": list(range(12)), "sections_stub": [],
        "sections_complete": 1}), encoding="utf-8")
    got = _checks(hs.check_report_sidecars(case))
    assert "report.fallback_source" in got, got
