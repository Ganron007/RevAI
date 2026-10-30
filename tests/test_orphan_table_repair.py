"""RC-32: one bounded orphan-table repair pass for both v2 reports.

Run `a2386cbd` failed publish on exactly one issue -- `orphan_tables:3`
against the gate's cap of 2 -- with both reports complete and every other
check clean. RC-11 removed the schema rejection so repairs cannot lose
sections; the writer is told to separate tables but still occasionally dumps
them back to back. The repair mirrors the stub retry: regenerate ONLY the
sections containing orphan pairs, once, and keep a replacement only when it
carries no orphan pair itself.
"""
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import report_quality as RQ  # noqa: E402

from _report_fixtures import structured_tool_response  # noqa: E402

SHA = "a" * 64
BROKEN_TITLE = "6. Network Indicators & C2"


def _broken_section(title: str) -> str:
    table = "| col | val |\n| --- | --- |\n| r1 | v1 |"
    return (f"## {title}\n\n" + "\n\n".join([table] * 4) +
            "\n\nThe tables above repeat the evidence rows for review, and "
            "this section carries enough prose to satisfy the style gate.")


def _fixed_section(title: str) -> str:
    table = "| col | val |\n| --- | --- |\n| r1 | v1 |"
    prose = ("The table above is bound to its cited evidence rows; the next "
             "one adds the domain indicators observed in the same corpus.")
    return (f"## {title}\n\n"
            + f"\n\n{prose}\n\n".join([table] * 4)
            + "\n\nTogether the tables summarise the indicator set with no "
              "dump-style layout.")


def test_count_table_orphans_matches_the_gate_rule():
    assert RQ.count_table_orphans(_broken_section(BROKEN_TITLE)) == 3
    assert RQ.count_table_orphans(_fixed_section(BROKEN_TITLE)) == 0
    # A table closed by a trailing blank line with no interpretation is an
    # EOF orphan (the gate's own rule, preserved byte-for-byte by the
    # refactored counter).
    assert RQ.count_table_orphans("| a |\n| --- |\n| b |\n\n") == 1


def _fake_llm(monkeypatch, break_titles: set[str]):
    import publish_report_v2 as pub
    calls: list[str] = []

    def fake(prompt, **kwargs):
        calls.append(prompt)
        head = prompt.split("Rules", 1)[0]
        titles = [t for t in pub.TECHNICAL_REPORT_SECTIONS if f"- {t}" in head]
        bodies = []
        for t in titles:
            if "table-orphan gate" in prompt and t in break_titles:
                bodies.append(_fixed_section(t))
            elif t in break_titles:
                bodies.append(_broken_section(t))
            else:
                bodies.append(
                    f"## {t}\n\nGrounded analysis of {t.split('. ', 1)[-1]} "
                    "explains the observed artifact, its source and the "
                    "limits of the finding. The import table is small and "
                    "the strings are listed in the evidence appendix.")
        body = "\n\n".join(bodies)
        return structured_tool_response(body), {"markdown": body}

    monkeypatch.setattr(pub, "llm_report_structured", fake)
    return calls


def test_the_repair_pass_fires_and_cleans_the_report(monkeypatch):
    import publish_report_v2 as pub
    calls = _fake_llm(monkeypatch, {BROKEN_TITLE})
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", dynamic_status={})
    assert not errors, errors
    assert RQ.count_table_orphans(md) <= 2, RQ.count_table_orphans(md)
    assert any(a.get("part") == "orphan-retry-result" and a.get("accepted")
               for a in audits), audits
    assert any("table-orphan gate" in c for c in calls), \
        "the repair pass did not fire"


def test_a_still_orphaned_repair_is_rejected(monkeypatch):
    import publish_report_v2 as pub

    def fake(prompt, **kwargs):
        head = prompt.split("Rules", 1)[0]
        titles = [t for t in pub.TECHNICAL_REPORT_SECTIONS if f"- {t}" in head]
        bodies = []
        for t in titles:
            if t == BROKEN_TITLE:
                # The retry returns the SAME broken layout.
                bodies.append(_broken_section(t))
            else:
                bodies.append(
                    f"## {t}\n\nGrounded analysis of {t.split('. ', 1)[-1]} "
                    "explains the observed artifact, its source and the "
                    "limits of the finding. The import table is small and "
                    "the strings are listed in the evidence appendix.")
        body = "\n\n".join(bodies)
        return structured_tool_response(body), {"markdown": body}

    monkeypatch.setattr(pub, "llm_report_structured", fake)
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", dynamic_status={})
    assert RQ.count_table_orphans(md) > 2, "the gate would have passed"
    assert any(a.get("part") == "orphan-retry-result"
               and not a.get("accepted") for a in audits), audits
    assert any("orphan-table retry" in e for e in errors), errors


def test_a_healthy_report_costs_no_repair_calls(monkeypatch):
    import publish_report_v2 as pub
    calls = _fake_llm(monkeypatch, set())
    _md, audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", dynamic_status={})
    assert not errors, errors
    assert not any("table-orphan gate" in c for c in calls)
    assert not any(a.get("part") == "orphan-retry-result" for a in audits)


def test_the_helper_keeps_the_original_on_failure(tmp_path):
    import publish_report_v2 as pub
    md = _broken_section(BROKEN_TITLE) + "\n\n## 7. Capabilities\n\nProse."
    calls = []

    def bad_retry(section, original):
        calls.append(section)
        return _broken_section(section)  # still broken

    out, attempts = pub.retry_orphan_table_sections(
        md, [BROKEN_TITLE], bad_retry)
    assert calls == [BROKEN_TITLE]
    assert attempts and not attempts[0]["accepted"]
    assert RQ.count_table_orphans(out) == 3  # unchanged


def test_the_helper_accepts_a_clean_replacement():
    import publish_report_v2 as pub
    md = _broken_section(BROKEN_TITLE) + "\n\n## 7. Capabilities\n\nProse."
    out, attempts = pub.retry_orphan_table_sections(
        md, [BROKEN_TITLE], lambda s, o: _fixed_section(s))
    assert attempts and attempts[0]["accepted"]
    assert RQ.count_table_orphans(out) == 0
    assert "## 7. Capabilities" in out  # the rest of the report is intact


# --------------------------------------------------------------------------
# RC-33 (2026-10-30, run 0aa935f2): the technical IoC section is assembled
# deterministically from iocs.json — the model cannot invent indicator-shaped
# strings there (the #42 MachineGuid class).
# --------------------------------------------------------------------------
def test_the_technical_ioc_section_is_deterministic(monkeypatch):
    import publish_report_v2 as pub
    calls = _fake_llm(monkeypatch, set())
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", dynamic_status={})
    assert not errors, errors
    # The LLM was never ASKED for the IoC section (its title may still appear
    # in other prompts' section lists or the wrap's prior-section text).
    for c in calls:
        head = c.split("Rules", 1)[0]
        requested = [t for t in pub.TECHNICAL_REPORT_SECTIONS
                     if f"- {t}" in head]
        assert "8. Indicators of Compromise" not in requested, requested
    # The deterministic section is present with its honesty note (the test
    # case has no iocs.json, so the absent-indicator branch renders).
    assert "## 8. Indicators of Compromise" in md
    assert "No indicator set was produced for this sample" in md
    assert "Nothing is claimed here" in md
    assert any(a.get("part", "").startswith("body-") and a.get("deterministic")
               for a in audits), audits


def test_v3_and_v2_ioc_renderers_agree():
    import section_publisher as sp
    import v2_lib
    assert sp._build_ioc_section("b" * 64) == \
        v2_lib.deterministic_ioc_section_md("b" * 64)
