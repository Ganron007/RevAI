"""Regression tests for exact report section boundaries and quality gating."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from audit_pipeline import _technical_v3_quality_checks  # noqa: E402
from report_quality import _section_bodies, stub_sections  # noqa: E402


def test_narrative_mention_does_not_truncate_required_section():
    required = ["10. MITRE ATT&CK Mapping", "11. What We Don't Know"]
    gaps = "\n".join(
        f"- Gap {number}: the available evidence does not establish this behavior."
        for number in range(1, 10)
    )
    report = (
        "## 10. MITRE ATT&CK Mapping\n"
        + ("This mapping is based on observed evidence. " * 20)
        + "The analyst should compare it with 11. What We Don't Know below.\n\n"
        + "## 11. What We Don't Know\n"
        + "The following limits remain after tool review:\n"
        + gaps
        + "\n"
    )

    bodies = _section_bodies(report, required)
    assert "Gap 9" in bodies[required[1]]
    assert len(bodies[required[1]]) > 600
    assert required[1] not in stub_sections(report, required)


def test_short_pointer_section_still_fails_stub_gate():
    required = ["1. Executive Summary", "2. Sample Metadata"]
    report = (
        "## 1. Executive Summary\n"
        "Full structured evidence pack is appended; see appendix.\n\n"
        "## 2. Sample Metadata\n"
        + ("The file metadata was independently extracted and verified. " * 12)
    )
    assert stub_sections(report, required) == ["1. Executive Summary"]


def test_audit_rejects_technical_v3_stub_metadata(tmp_path):
    technical = tmp_path / "REPORT-TECHNICAL-v3.md"
    technical.write_text("current report", encoding="utf-8")
    deep_mtime = time.time() - 60
    os.utime(technical, (time.time(), time.time()))
    checks = _technical_v3_quality_checks(
        {
            "source": "section_publisher",
            "sections_missing": [],
            "sections_stub": ["11. What We Don't Know"],
        },
        technical,
        deep_mtime,
    )
    assert checks["tech3_source_ok"]
    assert checks["tech3_fresh_vs_deep"]
    assert checks["tech3_no_missing_sections"]
    assert not checks["tech3_no_stubs"]


def test_audit_requires_current_llm_complete_technical_v3(tmp_path):
    technical = tmp_path / "REPORT-TECHNICAL-v3.md"
    technical.write_text("current report", encoding="utf-8")
    now = time.time()
    os.utime(technical, (now, now))
    good = _technical_v3_quality_checks(
        {
            "source": "section_publisher",
            "sections_missing": [],
            "sections_stub": [],
        },
        technical,
        now - 60,
    )
    assert all(good.values())

    stale = _technical_v3_quality_checks(
        {
            "source": "section_publisher",
            "sections_missing": [],
            "sections_stub": [],
        },
        technical,
        now + 60,
    )
    assert not stale["tech3_fresh_vs_deep"]

    missing_contract = _technical_v3_quality_checks(
        {"source": "deterministic_fallback"}, technical, now - 60
    )
    assert not missing_contract["tech3_source_ok"]
    assert not missing_contract["tech3_no_missing_sections"]
    assert not missing_contract["tech3_no_stubs"]
