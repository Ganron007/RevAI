"""#6: claim-level entailment -- does each claim follow from the evidence it cites?

The gate fires on a CIRCULAR citation: a claim offering the analysis's own prose
as the evidence for itself. Measured across five real reports at 1-20 per report
(feodo_banking: 20 of 592 claims), it is the one class that is structural rather
than textual, and therefore the one class that can be gated without an alias map.

The classes deliberately NOT gated are recorded here too, because a gate that
fires on its own blind spots is worse than no gate:

  * unresolved-source -- provenance-label spellings the alias map does not
    cover (12-56 per report on healthy runs).
  * unresolved-row -- the citation parser truncates at commas
    (`load_library (T1129` from `load_library (T1129, ...)`), and a model's
    characterisation of a table is not a literal row. 16 of 16 on packed_rook
    were one of those two.
"""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/entailment.py").parent))
import entailment as E  # noqa: E402


def _case(tmp_path, reports: dict, artifacts: dict | None = None):
    case = tmp_path / "logs" / ("a" * 64) / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    for name, md in reports.items():
        (case / name).write_text(md, encoding="utf-8")
    for rel, txt in (artifacts or {}).items():
        p = case / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")
    return case


# ------------------------------------------------------------- literal vs summary
@pytest.mark.parametrize("row,expect", [
    ("KERNEL32 (21", False),
    ('"KERNEL32 (21', False),
    ("MFC42 (131), MSVCRT (25)", False),
    ("Ghidra=104 vs IDA=218 (2.1x", False),
    ("load_library (T1129", True),
    ("CreateRemoteThread", True),
    ("offset 0x401000", True),
    ("contains_base64@51729", True),
    ("UPX", False),
    ('says "cmd.exe /c" inside', True),
])
def test_a_literal_row_is_distinguished_from_a_summary(row, expect):
    assert E._row_is_literal(row) is expect, row


# ------------------------------------------------------------------- circular
def test_a_claim_citing_the_summary_as_its_evidence_is_circular():
    c = {"source": "llm_judge", "query": "summary",
         "row": "GUI subsystem with zero window APIs", "text": "the sample"}
    assert E.verify_claim(c, "llm_judge was called", None)["status"] == "circular"


def test_verdict_summary_is_also_circular():
    """feodo cited `query_or_table: verdict summary` 20 times."""
    c = {"source": "llm_judge", "query": "verdict summary",
         "row": "C2 URLs hardcoded", "text": "the sample"}
    assert E.verify_claim(c, "llm_judge", None)["status"] == "circular"


def test_a_real_citation_is_not_circular():
    c = {"source": "ghidra_query", "query": "imports",
         "row": "CreateRemoteThread", "text": "the sample injects"}
    r = E.verify_claim(c, "ghidra_query import table", Path("."))
    assert r["status"] != "circular", r


# ----------------------------------------------------------------- extraction
def test_claims_are_extracted_with_their_citation():
    md = ("The sample writes an HKCU Run key for persistence "
          "(source: ghidra_query, query_or_table: imports, "
          "row_or_rule: RegSetValueExA).")
    claims = E.extract_claims(md)
    assert len(claims) == 1
    assert claims[0]["source"] == "ghidra_query"
    assert claims[0]["row"] == "RegSetValueExA"


def test_a_sentence_about_the_analysis_is_not_a_claim():
    """`(source: <engine>)` is the report explaining its own format."""
    md = ("All citations use the format `(source: <engine>)` and reference the "
          "exact table, rule name, or SQL query that produced the evidence.")
    assert E.extract_claims(md) == []


def test_uncited_sentences_are_not_claims():
    assert E.extract_claims("The sample is malicious and does bad things.") == []


def test_fenced_blocks_are_not_claims():
    md = "```\nsome evidence dump (source: yara)\n```"
    assert E.extract_claims(md) == []


# ------------------------------------------------------------------- the gate
def test_the_gate_fires_on_a_circular_citation(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample uses WinINet for C2 "
            "{source: llm_judge, query_or_table: summary, "
            "row_or_rule: \"WinINet observed\"}."},
        {"deep_dive/01-tools-raw.json": '{"yara": []}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["ok"] is False
    assert res["by_status"]["circular"] == 1
    assert res["violations"][0]["status"] == "circular"


def test_the_gate_passes_a_report_with_real_citations(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample calls CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/agentic_deep_dive.json": '{"imports": "CreateRemoteThread"}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["ok"] is True, res["violations"]
    assert res["by_status"].get("circular", 0) == 0


def test_a_summary_citation_is_reported_not_gated(tmp_path):
    """A model's characterisation of a table is not a literal row.

    `KERNEL32 (21), USER32 (10)` names a real import table but is not itself a
    row. Gating on it would fail a sound report for citation style -- and 16 of
    packed_rook's unresolved rows were exactly this shape.
    """
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "Imports are KERNEL32 (21), USER32 (10) "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: KERNEL32 (21), USER32 (10))."},
        {"deep_dive/agentic_deep_dive.json":
             '{"imports": ["KERNEL32"]}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["by_status"].get("summary-citation", 0) == 1, (
        "a characterisation must be counted as such")
    assert res["ok"] is True, "and must not gate"


def test_an_unresolved_literal_row_is_counted(tmp_path):
    """A literal that resolves nowhere IS counted -- reported, not gated.

    The literal/summary distinction exists so the count means something: a
    literal that resolves nowhere is either a fabrication or the checker's own
    blind spot, and both need to be visible.
    """
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample calls CreateRemoteThread (source: ghidra_query, "
            "query_or_table: imports, row_or_rule: CreateRemoteThread)."},
        {"deep_dive/agentic_deep_dive.json": '{"imports": ["ExitProcess"]}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["by_status"].get("unresolved-row", 0) == 1
    assert res["ok"] is True, (
        "reported, not gated -- until the alias map and row parsing are proven "
        "against a corpus, this class is a count and not a gate")


def test_no_reports_is_not_applicable(tmp_path):
    case = _case(tmp_path, {}, {})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["applicable"] is False


def test_the_cli_emits_parseable_json(tmp_path, capsys):
    case = _case(tmp_path, {"REPORT-MASTER-v2.md":
                            "The sample persists "
                            "(source: ghidra_query, query_or_table: imports, "
                            "row_or_rule: RegSetValueExA)."},
                 {"deep_dive/01-tools-raw.json": '{"imports": "RegSetValueExA"}'})
    argv = sys.argv
    sys.argv = ["entailment.py", "a" * 64, "--case", str(case)]
    try:
        rc = E._cli()
        out = capsys.readouterr().out
    finally:
        sys.argv = argv
    assert rc == 0
    json.loads(out), "the CLI must emit parseable JSON, not a truncated document"


def test_the_cli_fails_on_a_circular_citation(tmp_path, capsys):
    case = _case(tmp_path, {"REPORT-MASTER-v2.md":
                            "The sample persists "
                            "{source: llm_judge, query_or_table: summary, "
                            "row_or_rule: \"persistence\"}."})
    argv = sys.argv
    sys.argv = ["entailment.py", "a" * 64, "--case", str(case)]
    try:
        rc = E._cli()
        out = capsys.readouterr().out
    finally:
        sys.argv = argv
    assert rc == 1
    assert json.loads(out)["by_status"]["circular"] == 1
