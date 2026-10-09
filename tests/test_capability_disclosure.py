"""#56 (c): the report must disclose the capabilities it could not examine.

A capability domain the run never examined is a gap in the ANALYSIS. It must
never be read as a finding about the sample, and it must never be silently
absent from the report. This gate is what the coverage ledger feeds.
"""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/report_quality.py").parent))
import report_quality as R  # noqa: E402
import v2_lib  # noqa: E402

SHA = "a" * 64


def _run(tmp_path, statuses):
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    hist = [{"tool": f"domain:{k}", "result": {
        "status": st, "answer": f"{k} answer", "evidence": ["e"],
        "tool_calls_used": 3, "format": "json"}} for k, st in statuses.items()]
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": statuses}},
         "history": hist}), encoding="utf-8")
    return case


ALL = {"surface": "understood", "persistence": "understood",
       "c2_network": "partial", "evasion": "partial",
       "execution_injection": "partial", "credential_access": "partial",
       "exfiltration": "partial", "defense_impairment": "understood",
       "crypto": "partial"}


def test_no_domain_graph_run_is_not_applicable(tmp_path):
    """Flat engine / REVAI_DOMAIN_GRAPH off: nothing to disclose."""
    out = R.evaluate_capability_disclosure(tmp_path / "logs" / SHA, SHA,
                                           ["a report"])
    assert out["ok"] is True and out["applicable"] is False


def test_a_fully_examined_run_passes(tmp_path):
    _run(tmp_path, ALL)
    out = R.evaluate_capability_disclosure(tmp_path / "logs" / SHA, SHA,
                                           ["a report naming nothing"])
    assert out["ok"] is True and out["applicable"] is True


def test_an_undisclosed_gap_fails(tmp_path):
    d = dict(ALL)
    d["crypto"] = "not-explored"
    _run(tmp_path, d)
    out = R.evaluate_capability_disclosure(tmp_path / "logs" / SHA, SHA,
                                           ["a report that names nothing"])
    assert out["ok"] is False
    assert out["undisclosed"] == ["crypto"]
    assert "capability_disclosure_missing" in out["violation"]
    # The framing is load-bearing: the gap belongs to the ANALYSIS, not the
    # sample. Rewording it as a claim about the sample is the exact confusion
    # this ledger exists to prevent.
    v = out["violation"].lower()
    assert "gap in the analysis" in v
    assert "not a finding about the sample" in v
    assert "the sample does not" not in v
    assert "the run could not examine" in v


def test_a_disclosed_gap_passes(tmp_path):
    """Unknown is allowed -- SILENT unknown is not."""
    d = dict(ALL)
    d["crypto"] = "not-explored"
    d["credential_access"] = "not-reconstructed"
    _run(tmp_path, d)
    out = R.evaluate_capability_disclosure(
        tmp_path / "logs" / SHA, SHA,
        ["This run could not examine crypto or credential_access; both are "
         "gaps in the analysis."])
    assert out["ok"] is True
    assert set(out["unknown"]) == {"crypto", "credential_access"}


def test_partial_disclosure_still_fails_on_the_rest(tmp_path):
    d = dict(ALL)
    d["crypto"] = "not-explored"
    d["credential_access"] = "not-explored"
    _run(tmp_path, d)
    out = R.evaluate_capability_disclosure(
        tmp_path / "logs" / SHA, SHA, ["we could not examine crypto"])
    assert out["ok"] is False
    assert out["undisclosed"] == ["credential_access"]


def test_the_ledger_section_itself_counts_as_disclosure(tmp_path):
    """The rendered ledger names every unknown domain, so attaching it
    satisfies the gate by construction."""
    d = dict(ALL)
    d["crypto"] = "not-explored"
    _run(tmp_path, d)
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    section = v2_lib.format_capability_coverage(cov)
    out = R.evaluate_capability_disclosure(tmp_path / "logs" / SHA, SHA,
                                           [section])
    assert out["ok"] is True, (
        "the ledger names its own gaps, so a report carrying it must pass")
