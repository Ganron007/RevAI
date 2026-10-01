#!/usr/bin/env python3
"""The detector missed a hollow report, because it enumerated instead of discovering.

On 2026-10-01 the win32k_dll run produced report-technical-v3.json declaring:

    source             deterministic_fallback
    sections_complete  1          (of 13)
    sections_missing   12
    sections_stub      10

and `evaluate_case` returned `ok=True, findings=0`. The cause was structural,
not a missing filename: evaluate_case iterated a hardcoded pair

    ("REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md")

so v3 markdown was never examined, and no check opened the sidecars at all --
even though the sidecars carry the stage's OWN machine-checkable verdict on
completeness. The detector was re-deriving quality from prose while the
authoritative answer sat in a file it never read.

Three properties are pinned here, in this order of importance:

  1. a hollow report of the measured shape is RED
  2. the known-good shapes stay clean (a detector that cries wolf is worse
     than none, because it trains the operator to ignore it)
  3. coverage is by DISCOVERY, so a version that did not exist when this file
     was written is still covered -- asserted by inventing a v4

Every fixture here is a shape actually observed on the VM, not an invented one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import hollow_success as hs  # noqa: E402


def _write(case: Path, name: str, payload: dict) -> None:
    (case / name).write_text(json.dumps(payload), encoding="utf-8")


def _checks(findings):
    return {f.check for f in findings}


# ------------------------------------------------- the real hollow v3 shape

def test_real_hollow_v3_technical_is_red(tmp_path):
    """The exact sidecar from the win32k_dll run that the detector missed."""
    _write(tmp_path, "report-technical-v3.json", {
        "title": "Technical Report 8088f08a5636",
        "source": "deterministic_fallback",
        "sections_complete": 1,
        "sections_missing": [
            "1. Executive Summary", "2. Sample Metadata",
            "3. File Layout & Structural Analysis",
            "5. Behavioral & Dynamic Analysis",
            "6. Network Indicators & C2"],
        "sections_stub": [
            "1. Executive Summary", "2. Sample Metadata",
            "3. File Layout & Structural Analysis",
            "5. Behavioral & Dynamic Analysis"],
    })
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is False, "the missed defect must now be RED"
    got = _checks(hs.check_report_sidecars(tmp_path))
    assert got == {"report.fallback_source", "report.stub_sections",
                   "report.sections_missing"}, got


def test_every_dimension_is_reported_separately(tmp_path):
    """Three independent signals: a reader must see which one fired."""
    _write(tmp_path, "report-x.json", {
        "source": "deterministic_fallback", "sections_complete": 1,
        "sections_missing": ["a"], "sections_stub": ["a"]})
    findings = hs.check_report_sidecars(tmp_path)
    by_check = {f.check: f for f in findings}
    assert set(by_check) == {"report.fallback_source",
                             "report.sections_missing",
                             "report.stub_sections"}
    assert "deterministic_fallback" in by_check["report.fallback_source"].detail
    assert "12" not in by_check["report.sections_missing"].detail  # count is 1 here
    ev = by_check["report.sections_missing"].evidence
    assert ev["sections_complete"] == 1
    assert ev["missing"] == 1


def test_hollow_report_names_the_offending_file(tmp_path):
    """A finding must say WHICH artifact, or it is not actionable."""
    _write(tmp_path, "report-technical-v3.json", {
        "source": "deterministic_fallback", "sections_complete": 0,
        "sections_missing": ["9. Detection Engineering"]})
    details = " ".join(f.detail for f in hs.check_report_sidecars(tmp_path))
    assert "report-technical-v3.json" in details, details


# ------------------------------------------------------- green must stay clean

def test_measured_green_sidecar_is_clean(tmp_path):
    """raas / winservices / fgg_js all report exactly this shape."""
    _write(tmp_path, "report-technical-v2.json", {
        "source": "llm_judge", "sections_complete": 13,
        "sections_missing": [], "sections_stub": []})
    _write(tmp_path, "report-v2.json", {
        "source": "llm_judge", "sections_complete": 17,
        "sections_missing": [], "sections_stub": [],
        "verdict": "malicious"})
    assert hs.check_report_sidecars(tmp_path) == []


def test_green_manifest_with_llm_ok_true_is_clean(tmp_path):
    """The v3 master shape: 17 sections, pass1 17 / pass2 14, all llm_ok."""
    _write(tmp_path, "section-results-v3.json", {
        "pass1_count": 17, "pass2_count": 14,
        "sections": [{"name": f"s{i}", "llm_ok": True, "markdown": "x"}
                     for i in range(17)],
        "timings": {}})
    assert hs.check_section_manifests(tmp_path) == []


def test_absent_llm_ok_is_not_treated_as_failure(tmp_path):
    """Absence of provenance is not evidence of a hollow section."""
    _write(tmp_path, "section-results-v9.json", {
        "sections": [{"name": "a", "markdown": "x"},
                     {"name": "b", "llm_ok": True}]})
    assert hs.check_section_manifests(tmp_path) == []


def test_manifest_with_a_failed_section_is_red(tmp_path):
    _write(tmp_path, "section-results-v3.json", {
        "sections": [{"name": "ok", "llm_ok": True},
                     {"name": "bad", "llm_ok": False},
                     {"name": "worse", "llm_ok": False}]})
    got = _checks(hs.check_section_manifests(tmp_path))
    assert got == {"report.section_llm_failed"}, got
    ev = hs.check_section_manifests(tmp_path)[0].evidence
    assert ev["failed"] == 2 and ev["total"] == 3


# ------------------------------------------------------- coverage by discovery

def test_a_version_that_did_not_exist_is_still_covered(tmp_path):
    """The regression this whole change exists to prevent.

    Hardcoded lists are how v3 became invisible. A v4 must be caught with no
    edit to this detector.
    """
    _write(tmp_path, "report-technical-v4.json", {
        "source": "deterministic_fallback", "sections_complete": 2,
        "sections_missing": ["1. Executive Summary"]})
    got = _checks(hs.check_report_sidecars(tmp_path))
    assert got, "a v4 hollow report must be detected with no code change"
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is False


def test_markdown_checks_cover_every_version(tmp_path):
    """Degeneration is checked on v3 markdown too, not just v2."""
    body = "final_placeholder " * 400
    (tmp_path / "REPORT-TECHNICAL-v3.md").write_text(
        f"## 1. Summary\n\n{body}", encoding="utf-8")
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is False, "v3 markdown must be examined"
    assert any("degenerate" in f["check"] for f in out["findings"]), out["findings"]


def test_no_report_filenames_are_hardcoded():
    """Tripwire for the defect itself.

    Flags *enumerated concrete* filenames only. A glob pattern is discovery and
    is the intended mechanism -- `"REPORT-*.md"` must be allowed, while
    `"REPORT-MASTER-v2.md"` means coverage has gone back to being a hand-kept
    list, and the next version added will be invisible again.
    """
    src = (ROOT / "revai" / "hollow_success.py").read_text(errors="replace")
    code = "\n".join(
        line for line in src.splitlines()
        if not line.lstrip().startswith("#"))
    import re
    literals = [s for s in re.findall(r'"(REPORT-[^"]+\.md)"', code)
                if not any(ch in s for ch in "*?[")]
    assert not literals, (
        f"hardcoded report filenames in code: {literals}. Discover them with a "
        "glob so a new report version cannot silently escape the checks.")


# ---------------------------------------------------------------- robustness

def test_malformed_sidecar_does_not_crash_the_detector(tmp_path):
    """A truncated JSON file must not take the audit down with it."""
    (tmp_path / "report-v2.json").write_text("{not json", encoding="utf-8")
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is True, "unparseable must read as no-finding, not an error"
    assert out["findings"] == []


def test_sidecar_with_no_recognised_fields_is_ignored(tmp_path):
    _write(tmp_path, "report-v2.json", {"unrelated": True})
    assert hs.check_report_sidecars(tmp_path) == []


def test_empty_case_still_clean(tmp_path):
    assert hs.evaluate_case(tmp_path)["ok"] is True