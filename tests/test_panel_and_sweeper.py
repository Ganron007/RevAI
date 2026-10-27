"""RC-28 (deterministic verdict panel) and RC-29 (bounded section sweeper).

Run `683066829c23` shipped a master report with NO verdict panel row at all --
the panel's existence depended on the writer happening to render a table -- so
the hollow check could not compare panels (`verdict.panels_unreadable`). The
panel is machine data: `ensure_verdict_panel` makes exactly one panel state the
published verdict-of-record. The same run also lost two grounded technical
sections to provider stalls that ate both the first call and the RC-22 bounded
retry; the bounded sweeper re-calls ONLY the lost groups once, in order.
"""
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402
import report_quality as RQ  # noqa: E402

from _report_fixtures import structured_tool_response  # noqa: E402

SHA = "a" * 64


def _md_with_note() -> str:
    return (
        "# Executive Summary\n\n"
        "> **[Verdict calibration]** The published verdict for this sample "
        "is **suspicious**. The raw publish-model claim (malicious) was "
        "calibrated to suspicious.\n\n"
        "- The pipeline-locked verdict for this sample is \"malicious\".\n"
    )


def test_a_missing_panel_is_inserted_after_the_calibration_note():
    out = v2_lib.ensure_verdict_panel(_md_with_note(), "suspicious")
    note_at = out.find("[Verdict calibration]")
    panel_at = out.find("| Verdict | suspicious |")
    assert panel_at > note_at > -1, out
    assert out.count("| Verdict |") == 1, out
    assert RQ._panel_final_verdict(out) == "suspicious", out


def test_without_a_note_the_panel_follows_the_first_heading():
    md = "# Executive Summary\n\n- A finding.\n"
    out = v2_lib.ensure_verdict_panel(md, "malicious")
    assert out.index("| Verdict | malicious |") > out.index("# Executive")
    assert RQ._panel_final_verdict(out) == "malicious"


def test_a_correct_panel_is_kept_byte_for_byte():
    md = _md_with_note() + "| Verdict | suspicious |\n"
    assert v2_lib.ensure_verdict_panel(md, "suspicious") == md


def test_a_disagreeing_panel_is_corrected_to_the_published_label():
    md = _md_with_note() + "| Verdict | malicious |\n"
    out = v2_lib.ensure_verdict_panel(md, "suspicious")
    assert out.count("| Verdict |") == 1, out
    assert "| Verdict | suspicious |" in out, out
    assert "| Verdict | malicious |" not in out, out


def test_duplicate_panels_are_deduped():
    md = ("# Executive Summary\n\n| Verdict | benign |\n\nmiddle\n\n"
          "| Verdict | suspicious |\n")
    out = v2_lib.ensure_verdict_panel(md, "suspicious")
    assert out.count("| Verdict |") == 1, out
    assert RQ._panel_final_verdict(out) == "suspicious"


def test_an_unknown_label_leaves_the_report_unchanged():
    md = _md_with_note()
    assert v2_lib.ensure_verdict_panel(md, "") == md
    assert v2_lib.ensure_verdict_panel(md, "unknown") == md


def test_the_hollow_panel_check_passes_after_the_fix(tmp_path):
    import hollow_success

    master = _md_with_note()          # no panel: the run-5 defect
    technical = "# Technical Report\n\n| Verdict | suspicious |\n"
    case = tmp_path / "case"
    case.mkdir()
    (case / "REPORT-MASTER-v2.md").write_text(master, encoding="utf-8")
    (case / "REPORT-TECHNICAL-v2.md").write_text(technical, encoding="utf-8")
    before = hollow_success.check_verdict_panel_agreement(case)
    assert any(f.check == "verdict.panels_unreadable" for f in before), before
    (case / "REPORT-MASTER-v2.md").write_text(
        v2_lib.ensure_verdict_panel(master, "suspicious"), encoding="utf-8")
    after = hollow_success.check_verdict_panel_agreement(case)
    assert not after, [f.detail for f in after]


# ------------------------------------------------------------------ sweeper
def _fake_llm_with_stall(monkeypatch, fail_title: str, fail_times: int,
                         calls: dict | None = None):
    import publish_report_v2 as pub
    seen = calls if calls is not None else {}

    def fake(prompt, **kwargs):
        head = prompt.split("Rules", 1)[0]
        titles = [t for t in pub.TECHNICAL_REPORT_SECTIONS if f"- {t}" in head]
        for t in titles:
            seen[t] = seen.get(t, 0) + 1
        if fail_title in titles and seen.get(fail_title, 0) <= fail_times:
            raise RuntimeError("HTTP Error 500: Internal Server Error")
        body = "\n\n".join(
            f"## {t}\n\nGrounded analysis of {t.split('. ', 1)[-1]} explains "
            "the observed artifact, its source and the limits of the finding. "
            "The import table is small and the strings are listed in the "
            "evidence appendix."
            for t in titles)
        return structured_tool_response(body), {"markdown": body}

    monkeypatch.setattr(pub, "llm_report_structured", fake)
    return seen


def test_a_stall_lost_section_is_recovered_by_the_sweeper(monkeypatch):
    import publish_report_v2 as pub
    calls: dict[str, int] = {}
    _fake_llm_with_stall(monkeypatch, "9. Detection Engineering",
                         fail_times=2, calls=calls)
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", dynamic_status={})
    assert "## 9. Detection Engineering" in md, errors
    # Order is preserved: the recovered section sits between 8 and 10, not at
    # the end where a naive append would leave it.
    assert md.index("## 8. Indicators of Compromise")
    assert md.index("## 9. Detection Engineering") \
        < md.index("## 10. MITRE ATT&CK Mapping")
    assert any(a.get("sweeper") for a in audits), audits
    # Two failed attempts (first call + RC-22 retry) then one sweeper call.
    assert calls.get("9. Detection Engineering") == 3, calls


def test_a_section_the_sweeper_also_loses_stays_lost(monkeypatch):
    import publish_report_v2 as pub
    calls: dict[str, int] = {}
    _fake_llm_with_stall(monkeypatch, "9. Detection Engineering",
                         fail_times=99, calls=calls)
    md, _audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", dynamic_status={})
    assert "## 9. Detection Engineering" not in md
    assert "## 10. MITRE ATT&CK Mapping" in md, "other sections were lost too"
    # Bounded: first attempt + its RC-22 retry, then the sweeper attempt + its
    # retry = 4 calls for one title, then the section stays honestly lost.
    assert calls.get("9. Detection Engineering") == 4, calls
    assert errors, "the loss was not recorded"


def test_healthy_groups_cost_no_sweeper_calls(monkeypatch):
    import publish_report_v2 as pub
    calls: dict[str, int] = {}
    _fake_llm_with_stall(monkeypatch, "9. Detection Engineering",
                         fail_times=0, calls=calls)
    _md, _audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", dynamic_status={})
    assert not errors, errors
    for title, n in calls.items():
        assert n == 1, (title, n)
