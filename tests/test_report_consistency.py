#!/usr/bin/env python3
"""test_report_consistency.py — cross-report consistency + factual-number sanity.

Pure-logic tests for the 2026-08-12 publication-quality checks added after the
#2 night run: master-vs-technical contradictions (getdown-class defect) and
entropy citations that contradict the file's measured whole-file entropy.
No VM, no samples, no LLM required.

    python3 tests/test_report_consistency.py
    python3 test_report_consistency.py          # from tests/ dir

Exit 0 on pass, 1 on fail.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_IMPORT_DIR = ROOT / "revai"
if not _IMPORT_DIR.is_dir():
    _IMPORT_DIR = ROOT
sys.path.insert(0, str(_IMPORT_DIR))

from report_quality import (  # noqa: E402
    _cross_report_consistency,
    _file_shannon_entropy,
    _panel_final_verdict,
)

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  PASS {name}")
    else:
        msg = f"  FAIL {name}" + (f" — {detail}" if detail else "")
        print(msg)
        FAILURES.append(name)


MASTER_GETDOWN_STYLE = """# Malware Analysis Report: getdown.exe

## Executive Summary
This report details a trojan downloader. No dynamic analysis (e.g., sandbox,
Speakeasy, Frida) was performed in this triage. Therefore, no runtime behavior
was observed.

## 5. Behavioral Analysis
No dynamic analysis was performed in this triage.

## 1. Sample Identification
| **Entropy** | 1.04 (within normal range for compiled code) |
"""

TECH_GETDOWN_STYLE = """# Technical Malware Analysis Report v2

# Verdict sources (multi-source)
| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |

## 5. Behavioral & Dynamic Analysis
### 5.1 Speakeasy Emulation
Speakeasy emulation completed successfully (`speakeasy_ok: True`) but recorded
zero API calls.

### 5.2 Frida Probe
Frida identified the following hook candidates for dynamic instrumentation.
"""

MASTER_PANEL_MAL = "# Verdict sources (multi-source)\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n\n## Executive Summary\nSample is a dropper."
TECH_PANEL_SUS = "# Verdict sources (multi-source)\n| Source | Verdict |\n|--------|--------|\n| **Final** | **suspicious** |\n\n## 1. Executive Summary\nTechnical analysis."

GETDOWN_FILE_ENTROPY = 5.535


# ---------------------------------------------------------------------------
# 1. getdown-class defect: master negates dynamic analysis, tech has findings
# ---------------------------------------------------------------------------
def test_master_negation_vs_tech_evidence() -> None:
    r = _cross_report_consistency(MASTER_GETDOWN_STYLE, TECH_GETDOWN_STYLE, "", None)
    check("negation+evidence -> violation", not r["ok"])
    check(
        "violation text correct",
        any("master_claims_no_dynamic_analysis" in v for v in r["violations"]),
        repr(r["violations"]),
    )


def test_negation_with_parenthetical_matches() -> None:
    # Real getdown wording: "No dynamic analysis (e.g., sandbox, Speakeasy,
    # Frida) was performed in this triage." — parenthetical must not break it.
    r = _cross_report_consistency(MASTER_GETDOWN_STYLE, TECH_GETDOWN_STYLE, "", None)
    check(
        "parenthetical phrasing caught",
        any("master_claims_no_dynamic_analysis" in v for v in r["violations"]),
        repr(r["violations"]),
    )


def test_master_negation_without_tech_evidence_ok() -> None:
    tech_empty = "## 5. Behavioral & Dynamic Analysis\nNo runtime instrumentation available in this environment."
    r = _cross_report_consistency(MASTER_GETDOWN_STYLE, tech_empty, "", None)
    ok_violations = [v for v in r["violations"] if "master_claims_no_dynamic_analysis" in v]
    check("negation w/o tech evidence -> no dyn violation", not ok_violations, repr(r["violations"]))


def test_tech_evidence_without_negation_ok() -> None:
    r = _cross_report_consistency(MASTER_PANEL_MAL, TECH_GETDOWN_STYLE, "", None)
    dyn_v = [v for v in r["violations"] if "master_claims_no_dynamic_analysis" in v]
    check("tech evidence w/o negation -> no dyn violation", not dyn_v, repr(r["violations"]))


# ---------------------------------------------------------------------------
# 2. Verdict panel consistency
# ---------------------------------------------------------------------------
def test_verdict_panel_mismatch() -> None:
    r = _cross_report_consistency(MASTER_PANEL_MAL, TECH_PANEL_SUS, "", None)
    check("panel mismatch -> violation", not r["ok"], repr(r["violations"]))
    check(
        "mismatch text correct",
        any("master_tech_verdict_mismatch" in v for v in r["violations"]),
        repr(r["violations"]),
    )


def test_verdict_panel_match_ok() -> None:
    r = _cross_report_consistency(MASTER_PANEL_MAL, MASTER_PANEL_MAL, "", None)
    mm = [v for v in r["violations"] if "master_tech_verdict_mismatch" in v]
    check("panel match -> no mismatch violation", not mm, repr(r["violations"]))


def test_panel_verdict_extraction() -> None:
    check("master panel parse", _panel_final_verdict(MASTER_PANEL_MAL) == "malicious")
    check("tech panel parse", _panel_final_verdict(TECH_PANEL_SUS) == "suspicious")
    check("no panel -> empty", _panel_final_verdict("## Intro\nNo panel here.") == "")


# ---------------------------------------------------------------------------
# 3. Entropy factual-number sanity (ground truth = whole-file Shannon)
# ---------------------------------------------------------------------------
def test_entropy_quoted_vs_file_mismatch() -> None:
    # getdown real case: report quotes 1.04 (malcat's field, not file entropy);
    # the file's real whole-file entropy is 5.535.
    r = _cross_report_consistency(MASTER_GETDOWN_STYLE, "", "", GETDOWN_FILE_ENTROPY)
    ev = [v for v in r["violations"] if "entropy_quoted_vs_file_mismatch" in v]
    check("1.04 vs file 5.535 -> violation", bool(ev), repr(r["violations"]))


def test_entropy_quote_matches_file_ok() -> None:
    md = "## 1. Sample Identification\n| **Entropy** | 6.31 |\nCompiled-code entropy."
    r = _cross_report_consistency(md, "", "", 6.31)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("correct quote -> ok", not ev, repr(r["violations"]))


def test_entropy_normal_claim_on_low_file_value() -> None:
    # Number matches the file (1.04), but "normal range" claim contradicts it.
    md = "| **Entropy** | 1.04 (within normal range for compiled code) |"
    r = _cross_report_consistency(md, "", "", 1.04)
    ev = [v for v in r["violations"] if "entropy_normal_claim" in v]
    check("1.04 called normal -> violation", bool(ev), repr(r["violations"]))


def test_entropy_section_scoped_skipped() -> None:
    # rk-dropper real case: section-scoped citation must NOT be compared to
    # whole-file entropy.
    md = "| Entropy | High (7.9 bits in .text, 7.8 in overlay) |"
    r = _cross_report_consistency(md, "", "", 4.666)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("section-scoped entropy skipped", not ev, repr(r["violations"]))


def test_entropy_raw_scale_normalization() -> None:
    md = "| malcat | file_summary | entropy=104 |"
    r = _cross_report_consistency(md, "", "", 1.04)
    ev = [v for v in r["violations"] if "entropy_quoted_vs_file_mismatch" in v]
    check("raw-scale 104 vs file 1.04 -> no mismatch", not ev, repr(r["violations"]))


def test_entropy_no_mention_ok() -> None:
    r = _cross_report_consistency("## Intro\nNo entropy discussion.", "", "", 6.3)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("no entropy mention -> ok", not ev, repr(r["violations"]))


def test_entropy_compound_anomaly_names_skipped() -> None:
    # Anomaly-table rows like "| BigBufferNoXrefMediumToHighEntropy | 3 |"
    # contain "Entropy" inside a compound name — never a metric citation.
    md = "| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 |\n| HighEntropy | 2 | entropy | 0 |"
    r = _cross_report_consistency(md, "", "", 6.46)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("compound anomaly names skipped", not ev, repr(r["violations"]))


def test_entropy_anomaly_category_cell_skipped() -> None:
    # The standalone "entropy" cell in anomaly-definition rows sits in a later
    # column — skip it; only first-column entropy citations are file claims.
    md = "| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 | some text here |"
    r = _cross_report_consistency(md, "", "", 6.46)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("anomaly category cell skipped", not ev, repr(r["violations"]))


def test_entropy_identification_row_flagged() -> None:
    # "| Entropy | 135 (high) |" — entropy in the first column IS a file claim.
    md = "| Entropy | 135 (high, consistent with packed content) |"
    r = _cross_report_consistency(md, "", "", 6.46)
    ev = [v for v in r["violations"] if "entropy_quoted_vs_file_mismatch" in v]
    check("identification-row entropy flagged", bool(ev), repr(r["violations"]))


def test_entropy_unit_suffix_skipped() -> None:
    # drtg false positive (2026-08-13): "medium-to-high-entropy 10KB+ buffer"
    # — 10KB+ is a buffer SIZE, not an entropy metric.
    md = "BigBufferNoXrefMediumToHighEntropy: a medium-to-high-entropy 10KB+ buffer"
    r = _cross_report_consistency(md, "", "", 6.46)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("entropy followed by KB size -> no violation", not ev, repr(r["violations"]))


def test_entropy_theoretical_max_skipped() -> None:
    # raas false positive (2026-08-13): "approaches the maximum entropy of
    # 8.0" is a theory fact (max bits/byte), not the file's measured value.
    md = "The high entropy value of 7.39 is a strong indicator of packing, as "
    md += "random data approaches the maximum entropy of 8.0."
    r = _cross_report_consistency(md, "", "", 7.39)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("theoretical max entropy -> no violation", not ev, repr(r["violations"]))


def test_entropy_threshold_skipped() -> None:
    # koti.xlsm false positive (2026-08-13): "Flag XLSM files with entropy
    # above 7.0" is a detection-recommendation threshold, not a file metric.
    md = "Flag XLSM files with entropy above 7.0 and containing macrosheets."
    r = _cross_report_consistency(md, "", "", 7.56)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("threshold statement -> no violation", not ev, repr(r["violations"]))
    md2 = "Malcat anomaly HighEntropy (overall > 200)"
    r2 = _cross_report_consistency(md2, "", "", 7.56)
    ev2 = [v for v in r2["violations"] if "entropy" in v]
    check("greater-than threshold -> no violation", not ev2, repr(r2["violations"]))


def test_entropy_word_suffix_digits_skipped() -> None:
    # loveyou.js guard FP (2026-08-14): "entropy, strings, and Base64" /
    # "entropy. YARA ... C2" — the digits belong to Base64/C2, not entropy.
    md = "Provided file summary, entropy, strings, and Base64 constant identification."
    r = _cross_report_consistency(md, "", "", 5.74)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("Base64 suffix digit -> no violation", not ev, repr(r["violations"]))
    md2 = "The file has high entropy. YARA rules suggest potential C2 domain patterns."
    r2 = _cross_report_consistency(md2, "", "", 5.74)
    ev2 = [v for v in r2["violations"] if "entropy" in v]
    check("C2 suffix digit -> no violation", not ev2, repr(r2["violations"]))


def test_entropy_appendix_dump_skipped() -> None:
    # Raw evidence lines in appendices are verbatim tool output, not narrative.
    md = "## Executive Summary\nHigh entropy.\n\n## Appendix A: Tool Evidence Trail\nentropy: 135\n"
    r = _cross_report_consistency(md, "", "", 6.46)
    ev = [v for v in r["violations"] if "entropy" in v]
    check("appendix dump lines skipped", not ev, repr(r["violations"]))


def test_entropy_evidence_dump_line_flagged() -> None:
    # Raw evidence lines ("entropy: 135") inside the technical report cite
    # malcat's field as if it were file entropy — a true factual defect.
    md = "entropy: 135"
    r = _cross_report_consistency(md, "", "", 6.46)
    ev = [v for v in r["violations"] if "entropy_quoted_vs_file_mismatch" in v]
    check("raw dump entropy line flagged", bool(ev), repr(r["violations"]))


def test_entropy_duplicate_mentions_deduped() -> None:
    md = "| **Entropy** | 1.04 |\n| **Entropy** | 1.04 |"
    r = _cross_report_consistency(md, "", "", GETDOWN_FILE_ENTROPY)
    ev = [v for v in r["violations"] if "entropy_quoted_vs_file_mismatch" in v]
    check("duplicate quotes -> one violation", len(ev) == 1, repr(r["violations"]))


# ---------------------------------------------------------------------------
# 4. Whole-file Shannon entropy computation
# ---------------------------------------------------------------------------
def test_file_shannon_entropy_uniform() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "u.bin"
        p.write_bytes(bytes(range(256)))
        check("uniform 256 bytes -> 8.0", abs((_file_shannon_entropy(p) or 0) - 8.0) < 1e-9)


def test_file_shannon_entropy_constant() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "c.bin"
        p.write_bytes(b"\x00" * 1024)
        check("constant bytes -> 0.0", _file_shannon_entropy(p) == 0.0)


def test_file_shannon_entropy_missing() -> None:
    check("missing file -> None", _file_shannon_entropy(None) is None)
    check("empty path -> None", _file_shannon_entropy(Path("/nonexistent/x.bin")) is None)


if __name__ == "__main__":
    for fn in (
        test_master_negation_vs_tech_evidence,
        test_negation_with_parenthetical_matches,
        test_master_negation_without_tech_evidence_ok,
        test_tech_evidence_without_negation_ok,
        test_verdict_panel_mismatch,
        test_verdict_panel_match_ok,
        test_panel_verdict_extraction,
        test_entropy_quoted_vs_file_mismatch,
        test_entropy_quote_matches_file_ok,
        test_entropy_normal_claim_on_low_file_value,
        test_entropy_section_scoped_skipped,
        test_entropy_raw_scale_normalization,
        test_entropy_no_mention_ok,
        test_entropy_compound_anomaly_names_skipped,
        test_entropy_anomaly_category_cell_skipped,
        test_entropy_unit_suffix_skipped,
        test_entropy_theoretical_max_skipped,
        test_entropy_threshold_skipped,
        test_entropy_word_suffix_digits_skipped,
        test_entropy_identification_row_flagged,
        test_entropy_appendix_dump_skipped,
        test_entropy_evidence_dump_line_flagged,
        test_entropy_duplicate_mentions_deduped,
        test_file_shannon_entropy_uniform,
        test_file_shannon_entropy_constant,
        test_file_shannon_entropy_missing,
    ):
        fn()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nALL CONSISTENCY-CHECK TESTS PASS")
