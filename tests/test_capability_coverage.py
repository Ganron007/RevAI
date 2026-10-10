"""#56 capability-coverage ledger -- the report must show what was examined.

The measured defect (2026-10-09, tiny_msil_dotnet): the domain graph produced a
complete 9-domain coverage record and only 4 of the 9 capability names appeared
anywhere in the published report, because 05-deep-dive.json -- the artifact the
report reads -- carried no domain_graph key. The structural answer to "did we
extract every capability" was computed and then discarded.

These pin the ledger: deterministic, generated from the analysis record, names
the UNKNOWN domains rather than omitting them, and reports honest absence when
there is no domain-graph run.
"""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402

SHA = "a" * 64


def _case(tmp_path, domains, answers=None, evidence_for_partial=False):
    """Write a domain-graph run in the layout v2_lib reads."""
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    hist = []
    for k, st in domains.items():
        # `understood` nodes cite evidence; `partial` nodes cite none unless
        # asked -- that is the distinction the provenance tier measures. (A
        # `partial` node WITH evidence is still observed: the label is the
        # model's mood, the citation is the measurement.)
        ev = ["e1", "e2"] if (st == "understood" or evidence_for_partial) else []
        hist.append({"tool": f"domain:{k}",
                     "result": {"status": st,
                                "answer": (answers or {}).get(k, f"{k} answer"),
                                "evidence": ev,
                                "tool_calls_used": 3,
                                "format": "json"}})
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(
        json.dumps({"findings": {"domain_graph": {"domains": domains,
                                                  "complete": True}},
                    "history": hist}), encoding="utf-8")
    return case


ALL = {"surface": "understood", "persistence": "understood",
       "c2_network": "partial", "evasion": "partial",
       "execution_injection": "partial", "credential_access": "partial",
       "exfiltration": "partial", "defense_impairment": "understood",
       "crypto": "partial"}


def test_the_ledger_reads_the_domain_record(tmp_path):
    _case(tmp_path, ALL)
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    assert cov["domains_total"] == 9
    assert len(cov["understood"]) == 3 and len(cov["partial"]) == 6
    assert cov["unknown"] == []
    assert cov["honest"] is True
    assert cov["tool_calls_used"] == 27


def test_a_domain_missing_from_the_record_still_gets_a_row(tmp_path):
    """A key ABSENT from the domain record is not the same as a bad status.

    The renderer has a separate branch for it, and it must still name the
    domain -- a capability the graph never visited is exactly the gap the
    ledger exists to expose.
    """
    _case(tmp_path, ALL)
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    del cov["domains"]["crypto"]
    md = v2_lib.format_capability_coverage(cov)
    assert "Encryption / obfuscation" in md, (
        "a domain absent from the record was dropped from the ledger")
    assert "**unknown**" in md
    assert "not examined" in md


def test_an_unexamined_domain_is_named_unknown_not_omitted(tmp_path):
    d = dict(ALL)
    d["crypto"] = "not-explored"
    d["credential_access"] = "not-reconstructed"
    _case(tmp_path, d)
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    assert set(cov["unknown"]) == {"crypto", "credential_access"}
    md = v2_lib.format_capability_coverage(cov)
    assert "**unknown**" in md
    assert "Encryption / obfuscation" in md, (
        "an unexamined domain must appear in the table, not be dropped")
    # unknown follows DOMAIN_KEYS order, not the dict's insertion order
    import domain_graph as dg
    expect = ", ".join(k for k in dg.DOMAIN_KEYS if k in cov["unknown"])
    assert f"unknown: {expect}" in md


def test_the_rendered_section_names_every_capability_domain(tmp_path):
    _case(tmp_path, ALL)
    md = v2_lib.format_capability_coverage(
        v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs"))
    for title in ("Surface", "Persistence", "C2 / network", "Evasion",
                  "Execution / injection", "Credential access", "Exfiltration",
                  "Defense impairment", "Encryption / obfuscation"):
        assert title in md, title
    assert md.count("|") > 20, "one row per domain plus the header"


def test_a_truncated_or_self_contradicting_domain_is_flagged(tmp_path):
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps({
        "findings": {"domain_graph": {"domains": ALL}},
        "history": [{"tool": "domain:c2_network",
                     "result": {"status": "partial", "answer": "x",
                                "truncated": True}},
                    {"tool": "domain:crypto",
                     "result": {"status": "partial", "answer": "y",
                                "status_contradicts_answer": True}}],
    }), encoding="utf-8")
    md = v2_lib.format_capability_coverage(
        v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs"))
    assert "truncated" in md
    assert "contradicts its own answer" in md


def test_no_domain_graph_run_is_honest_absence(tmp_path):
    """Flat engine / REVAI_DOMAIN_GRAPH off: absent, never fabricated."""
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    assert cov == {}
    assert v2_lib.format_capability_coverage(cov) == ""
    assert v2_lib.attach_capability_coverage("BODY", SHA) == "BODY"


def test_the_section_is_appended_and_opt_out_is_honoured(tmp_path, monkeypatch):
    _case(tmp_path, ALL)
    body = "## Report\n\ncontent\n"
    out = v2_lib.attach_capability_coverage(body, SHA, logs_dir=tmp_path / "logs")
    assert out.startswith(body.rstrip())
    assert "## Capability Coverage" in out
    monkeypatch.setenv("REVAI_DISABLE_CAPABILITY_COVERAGE", "1")
    assert v2_lib.attach_capability_coverage(
        body, SHA, logs_dir=tmp_path / "logs") == body


def test_the_report_actually_gets_every_capability(tmp_path):
    """The measured fix: 4/9 capability names reached the report; now 9/9."""
    _case(tmp_path, ALL)
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    md = v2_lib.format_capability_coverage(cov)
    import domain_graph as dg
    for d in dg.DOMAINS:
        assert d["key"].split("_")[0] in md.lower() or d["title"] in md, d["key"]


# ---------------------------------------------------- #56 (b) provenance tiers
def test_provenance_is_observed_only_with_evidence(tmp_path):
    """The tier measures the CITATION, not the model's self-assessed label.

    Measured on stealers_redline_stealc: a node that found the HKCU Run key
    with RegSetValueExA, the rundll32 string at 0x40E9A4 and two citing
    functions (six evidence items) labelled itself `partial` because it was
    hedging -- and was scored `inferred`. So was the node that found WinINet,
    the XOR-0x59 payload and the full POST chain with three evidence items.
    Gating on the label under-reported extraction by three domains.
    """
    _case(tmp_path, ALL)          # understood cite, partial do not
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    assert cov["provenance_counts"]["observed"] == 3
    assert cov["provenance_counts"]["inferred"] == 6

    # A node that labels itself `partial` but DOES cite evidence is observed.
    assert v2_lib._capability_provenance("partial", 6, False, False) == \
        v2_lib.PROV_OBSERVED, (
            "a hedge label must not downgrade an evidence-backed determination")
    # A node with no citation is inference whatever it calls itself.
    assert v2_lib._capability_provenance("understood", 0, False, False) == \
        v2_lib.PROV_INFERRED


def test_provenance_is_unknown_when_never_examined(tmp_path):
    d = dict(ALL)
    d["crypto"] = "not-explored"
    _case(tmp_path, d)
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    assert cov["provenance_counts"]["unknown"] == 1
    assert (cov["provenance"]["unknown"]) == ["crypto"]
    md = v2_lib.format_capability_coverage(cov)
    assert "Capabilities this run cannot speak to" in md
    assert "gaps in the analysis, not findings about the sample" in md


def test_a_truncated_or_contradicting_node_is_inferred_not_observed(tmp_path):
    """A node that ran out of steps, or that claims it never looked while
    answering, has not established anything."""
    import v2_lib
    assert v2_lib._capability_provenance("understood", 3, True, False) == \
        v2_lib.PROV_INFERRED
    assert v2_lib._capability_provenance("understood", 3, False, True) == \
        v2_lib.PROV_INFERRED
    assert v2_lib._capability_provenance("understood", 3, False, False) == \
        v2_lib.PROV_OBSERVED


def test_provenance_is_not_derived_from_the_answer_text():
    """The #57 lesson: reading 'not observed' out of prose is over-matching.

    The tier comes from status + evidence count only, never the answer text.
    """
    import v2_lib
    # A 'not observed' determination WITH evidence is still OBSERVED -- the
    # absence was established, not guessed.
    assert v2_lib._capability_provenance("understood", 2, False, False) == \
        v2_lib.PROV_OBSERVED


def test_the_provenance_line_states_the_counts(tmp_path):
    _case(tmp_path, ALL)
    md = v2_lib.format_capability_coverage(
        v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs"))
    assert "**Extraction provenance: 3 observed, 6 inferred, 0 unknown.**" in md
    # No unknown set -> no "cannot speak to" block
    assert "cannot speak to" not in md
