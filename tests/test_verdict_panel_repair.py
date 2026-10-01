#!/usr/bin/env python3
"""The verdict lock must also reach the markdown the audit actually reads.

The lock corrects the STRUCTURED verdict and reports `lock_ok=True`, but
`report_quality` reads the verdict panel out of the markdown
(`_VERDICT_PANEL_RE` -> `_panel_final_verdict`). On win32k_dll (2026-10-01) the
master panel still read `**suspicious**` and the technical panel `**unknown**`
while the locked verdict was `malicious`, which the audit then reported as
`cross_report:master_tech_verdict_mismatch`.

So the panel is repaired deterministically after the lock, counted in the report
JSON, and never silently left to the model's compliance. The regex here is
pinned against the audit's own so the two cannot drift apart unnoticed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import publish_report_v2 as pub  # noqa: E402
import report_quality as rq  # noqa: E402


def _panel(md: str) -> str:
    """Read the verdict back the way the audit does."""
    return rq._panel_final_verdict(md)


def test_regex_matches_exactly_what_the_audits_own_parser_matches():
    """The repair regex and the audit regex must agree on which rows are panels.

    Not "both match these samples" -- agreement in BOTH directions. A row the
    audit reads but the repair skips would leave drift in place; a row the
    repair rewrites but the audit ignores would be needless churn.
    """
    samples = [
        "| **Final** | **suspicious** |",
        "| **Final** | **malicious** |",
        "|  **Final**  |  **unknown**  |",
        "| **Final Verdict** | **malicious** |",   # audit requires **Final**
        "| **Confidence** | **90** |",             # not a panel
        "no table here at all",
    ]
    for s in samples:
        audit_matches = bool(rq._VERDICT_PANEL_RE.search(s))
        repair_matches = bool(pub._VERDICT_PANEL_ROW_RE.search(s))
        assert audit_matches == repair_matches, (
            f"parsers disagree on {s!r}: audit={audit_matches} "
            f"repair={repair_matches}")
        if audit_matches:
            repaired, n = pub.repair_verdict_panel(s, "malicious")
            if n:
                assert _panel(repaired) == "malicious", (
                    f"after repair the audit reads {_panel(repaired)!r} "
                    f"from {s!r}")


def test_repair_overwrites_the_drifted_label():
    md = (
        "## 1. Executive Summary\n\n"
        "| Field | Value |\n|---|---|\n"
        "| **Final** | **suspicious** |\n\nSome prose about the sample.\n"
    )
    repaired, n = pub.repair_verdict_panel(md, "malicious")
    assert n == 1
    assert _panel(repaired) == "malicious"
    assert "suspicious" not in repaired
    # surrounding content untouched
    assert "Some prose about the sample." in repaired
    assert "| Field | Value |" in repaired


def test_repair_is_a_no_op_when_the_label_already_matches():
    md = "| **Final** | **malicious** |\n"
    repaired, n = pub.repair_verdict_panel(md, "malicious")
    assert n == 0
    assert repaired == md


def test_repair_is_case_insensitive_on_the_existing_label():
    md = "| **Final** | **MALICIOUS** |\n"
    _, n = pub.repair_verdict_panel(md, "malicious")
    assert n == 0, "a differently-cased but identical label is not drift"


def test_no_verdict_leaves_the_document_alone():
    md = "| **Final** | **suspicious** |\n"
    for locked in (None, "", "   "):
        repaired, n = pub.repair_verdict_panel(md, locked)
        assert n == 0 and repaired == md, (
            f"must not rewrite without a locked verdict (got {locked!r})")


def test_master_and_technical_converge_on_the_locked_label():
    """The exact win32k_dll failure: two drifted panels, one locked label."""
    master = "| **Final** | **suspicious** |\n"
    technical = (
        "# 1. Executive Summary\n\n| Field | Value |\n|---|---|\n"
        "| **Final** | **unknown** |\n"
    )
    m, n1 = pub.repair_verdict_panel(master, "malicious")
    t, n2 = pub.repair_verdict_panel(technical, "malicious")
    assert (n1, n2) == (1, 1)
    assert _panel(m) == _panel(t) == "malicious", (
        "the audit would still report a master/technical mismatch")


def test_multiple_panels_are_all_repaired():
    md = ("| **Final** | **suspicious** |\n\ntext\n\n"
          "| **Final** | **unknown** |\n")
    repaired, n = pub.repair_verdict_panel(md, "malicious")
    assert n == 2
    assert "suspicious" not in repaired and "unknown" not in repaired


def test_non_panel_rows_are_not_touched():
    md = ("| **Final Verdict** | **malicious** |\n"
          "| **Confidence** | **90** |\n"
          "| **Reviewer** | **unknown** |\n")
    repaired, n = pub.repair_verdict_panel(md, "malicious")
    assert n == 0
    assert repaired == md, "only the Final row may be rewritten"
