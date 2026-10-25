"""Report-gate defect regressions from run 0a357baa (2026-10-23).

Three gates went red on a run whose reports were complete, schema-valid and
factually correct. Each one is pinned here in both directions, because a gate
that cannot pass a truthful report is as broken as one that cannot fail a
dishonest one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import entailment as E  # noqa: E402
import report_quality as RQ  # noqa: E402
import v2_lib  # noqa: E402

SHA = "a" * 64

#: The real master-report sentence that the keyword heuristic mis-read, plus
#: the cited FLOSS observation that carries the word "benign".
MASTER_HEAD = """# Executive Summary

- **[Assessment]** We assess this sample as a malicious multi-vector Windows dropper.
- The triage verdict for this sample is 'malicious' with a score of 90. (source: verdict, query_or_table: verdict.json, row_or_rule: $.verdict)
- **[Assessment]** Treat this sample as confirmed malicious.
"""

MASTER_FLOSS_LINE = """- The zero-substituted 'm' suggests a deliberate spelling variant to evade
  keyword-based detection of the benign 'move.txt' filename. (source: floss,
  query_or_table: deep_dive/01-tools-raw.json, row_or_rule: $.floss.strings[3])
"""


# --------------------------------------------------------------------------
# 1. Verdict inference: an explicit, subject-naming, quoted verdict wins.
# --------------------------------------------------------------------------
def test_explicit_verdict_naming_its_subject_and_quoting_its_label():
    for text in (
        "The triage verdict for this sample is 'malicious' with a score of 90.",
        "The pipeline verdict of this binary is \"malicious\".",
        "Final verdict: MALICIOUS",
        "**Verdict: SUSPICIOUS (score 30)**",
    ):
        value = (v2_lib.infer_publish_verdict_from_markdown(text) or "").lower()
        assert value in {"malicious", "suspicious"}, (text, value)


def test_a_cited_observation_cannot_clear_a_report_that_states_malicious():
    """The exact 2026-10-23 false positive: 'the benign move.txt filename'."""
    md = MASTER_FLOSS_LINE + "\n" + MASTER_HEAD
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "malicious"


def test_the_keyword_heuristic_still_reads_an_uncited_benign_assessment():
    md = (
        "# Executive Summary\n\n"
        "- **[Assessment]** This is a legitimate signed Microsoft utility. It is\n"
        "  benign and its network activity is ordinary telemetry.\n"
    )
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "benign"


def test_a_benign_verdict_with_a_cited_observation_around_it_still_reads_benign():
    md = (
        "# Executive Summary\n\n"
        "- **[Assessment]** The sample is benign: a legitimate remote administration tool.\n"
        "- It references the string 'http://example.test'. (source: floss, "
        "query_or_table: deep_dive/01-tools-raw.json, row_or_rule: $.floss.strings[0])\n"
    )
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "benign"


# --------------------------------------------------------------------------
# 2. Dynamic-execution claim: a truthful status sentence is not a run claim.
# --------------------------------------------------------------------------
def _dyn_status_absent() -> dict:
    return {
        "any_dynamic_performed": False,
        "sentence": (
            "Run-scoped status -- RevAI Speakeasy: emulation stage produced no "
            "oracle result; RevAI Frida probe: static-only, not sample execution; "
            "WinRE detonation: no runtime pack or run status; launch unverified."
        ),
        "speakeasy": {"present": False},
        "frida_runtime": {"trace_artifact_present": False},
        "winre": {"pack_present": False},
        "packet_capture": {"present": False},
    }


def test_a_truthful_status_sentence_is_not_flagged_as_a_run_claim():
    md = (
        "# 5. Behavioral Analysis\n\n"
        "- Speakeasy emulation ran and recorded zero API calls and zero key events, "
        "consistent with the emulation stage producing no oracle result. "
        "(source: speakeasy, query_or_table: deep_dive/01-tools-raw.json, "
        "row_or_rule: $.speakeasy.api_calls)\n"
    )
    result = RQ._cross_report_consistency(
        md, md, "", 6.96, _dyn_status_absent())
    assert not any("dynamic_execution_claimed" in v
                   for v in result["violations"]), result["violations"]


def test_an_affirmative_run_claim_is_still_flagged():
    """A report that says the detonation ran, with no such run, must fail."""
    md = (
        "# 1. Executive Summary\n\n"
        "- The WinRE detonation ran and produced 200 runtime events.\n"
    )
    result = RQ._cross_report_consistency(
        md, md, "", 6.96, _dyn_status_absent())
    assert any("dynamic_execution_claimed" in v
               for v in result["violations"]), result["violations"]


def test_an_absence_of_a_different_component_does_not_excuse_the_claim():
    """'detonation ran and no packet capture was produced' still claims a run.

    NOTE: this shape is currently suppressed by the PRE-EXISTING after-verb
    negation rule (`_DYN_NEGATED_AFTER_RE`), which accepts "and no ..." as
    negating the verb. That rule predates this change and is deliberately left
    alone here: it exists to accept "Frida instrumentation was not performed",
    and narrowing it needs its own measurement. This test pins the CURRENT
    contract so the gap is visible rather than assumed fixed.
    """
    md = (
        "# 1. Executive Summary\n\n"
        "- The WinRE detonation ran and no packet capture was produced.\n"
    )
    result = RQ._cross_report_consistency(
        md, md, "", 6.96, _dyn_status_absent())
    # Known limitation (see docstring): not flagged by the after-verb rule.
    assert result["checks"]["dyn_executed_claim"] is False


# --------------------------------------------------------------------------
# 3. EA=<decimal> locators resolve to their unique evidence row.
# --------------------------------------------------------------------------
def _artifact_tree(tmp_path: Path) -> Path:
    case = tmp_path / "logs" / SHA / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "malcat": {
            "views": {"strings": [
                {"ea": 49314, "summary": "SeDebugPrivilege"},
                {"ea": 47146, "summary": "PendingFileRenameOperations"},
            ]},
        },
    }), encoding="utf-8")
    return case


def test_ea_locator_resolves_to_its_unique_row(tmp_path):
    case = _artifact_tree(tmp_path)
    for row, want in (("EA=47146", "PendingFileRenameOperations"),
                      ("EA=49314", "SeDebugPrivilege")):
        located, check = E._ground_citation(
            {"source": "malcat", "query": "deep_dive/01-tools-raw.json",
             "row": row}, case)
        assert located is not None, (row, check)
        assert check["status"] == "traceable-row", check
        assert want in located["excerpt"], located["excerpt"]


def test_an_ambiguous_or_absent_ea_stays_unresolved(tmp_path):
    case = _artifact_tree(tmp_path)
    for row in ("EA=99999", "EA=0"):
        located, check = E._ground_citation(
            {"source": "malcat", "query": "deep_dive/01-tools-raw.json",
             "row": row}, case)
        assert located is None, (row, located)
        assert check["status"] == "unresolved-row", check


def test_a_duplicated_ea_is_ambiguous_and_not_guessed(tmp_path):
    case = tmp_path / "logs" / SHA / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "malcat": {
            "views": {"strings": [{"ea": 47146, "summary": "pending"}]},
            "functions": [{"ea": 47146, "name": "sub_4021a0"}],
        },
    }), encoding="utf-8")
    located, check = E._ground_citation(
        {"source": "malcat", "query": "deep_dive/01-tools-raw.json",
         "row": "EA=47146"}, case)
    assert located is None
    assert check["status"] == "unresolved-row"


# --------------------------------------------------------------------------
# 4. A stray claim ID must not abort the whole claim review.
#
# These use the fully-bound case fixture from test_entailment (execution
# context + report manifest + artifact provenance), because a hand-built case
# returns "provenance-invalid" before any claim is reviewed -- and a test that
# asserts on an empty result list cannot fail.
# --------------------------------------------------------------------------
from test_entailment import _case  # noqa: E402


def _review_reports() -> dict:
    return {
        "REPORT-MASTER-v2.md": (
            "The string table records PendingFileRenameOperations at EA 47146 "
            "(source: malcat, query_or_table: deep_dive/01-tools-raw.json, "
            "row_or_rule: EA=47146).\n\n"
            "FLOSS recovered the path C:\\unm0ve.txt "
            "(source: floss, query_or_table: deep_dive/01-tools-raw.json, "
            "row_or_rule: $.floss.strings[0]).\n"
        ),
    }


def _review_artifacts() -> dict:
    return {
        "deep_dive/01-tools-raw.json": json.dumps({
            "malcat": {"views": {"strings": [
                {"ea": 47146, "summary": "PendingFileRenameOperations"},
            ]}},
            "floss": {"strings": ["C:\\unm0ve.txt"]},
        }),
    }


def _statuses(result: dict) -> list:
    return [row.get("status") for row in (result.get("claims") or [])]


def test_the_fixture_really_reaches_the_claim_review(tmp_path):
    """Guard against a vacuous test: the review must actually run."""
    case = _case(tmp_path, _review_reports(), _review_artifacts())
    seen = []

    def reviewer(batch):
        seen.extend(batch)
        return {"reviews": [{
            "id": item["id"], "verdict": "supported",
            "evidence_ids": [row["evidence_id"] for row in item["evidence"]],
        } for item in batch]}

    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=reviewer, use_cache=False)
    assert seen, result
    assert _statuses(result), result


def test_a_hallucinated_claim_id_does_not_abort_the_review(tmp_path):
    """Measured 2026-10-23: an unknown ID raised StopIteration at batch 21/88.

    The generic handler then failed the entire review closed and every claim
    became `verification-error`, so a run whose reports were complete went red
    on one stray row. A decision for an unknown claim carries no information:
    it is discarded, while every EXPECTED claim still requires its own verdict.
    """
    case = _case(tmp_path, _review_reports(), _review_artifacts())

    def reviewer(batch):
        rows = [{
            "id": item["id"], "verdict": "supported",
            "evidence_ids": [row["evidence_id"] for row in item["evidence"]],
        } for item in batch]
        rows.append({"id": "deadbeef-not-a-claim", "verdict": "supported",
                     "evidence_ids": []})
        return {"reviews": rows}

    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=reviewer, use_cache=False)
    assert "verification-error" not in _statuses(result), result
    assert result.get("review_error") in (None, ""), result


def test_an_omitted_claim_verdict_still_fails_closed(tmp_path):
    """Every expected claim needs its own decision; dropping one is still fatal."""
    case = _case(tmp_path, _review_reports(), _review_artifacts())

    def reviewer(batch):
        return {"reviews": [{
            "id": batch[0]["id"], "verdict": "supported",
            "evidence_ids": [row["evidence_id"] for row in batch[0]["evidence"]],
        }]}

    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=reviewer, use_cache=False)
    assert "verification-error" in _statuses(result), result


def test_the_digit_form_of_a_zero_result_is_a_status_description():
    """Reports write "recorded 0 API calls", not only "zero API calls".

    Measured 2026-10-24 on run 67eb72cf: three emulation sentences used digits
    ("Speakeasy emulation ran and recorded 0 API calls and 0 key events") and
    were failed as run claims, so the word-only marker list was incomplete.
    """
    md = (
        "# 5. Behavioral Analysis\n\n"
        "- Speakeasy emulation ran and recorded 0 API calls and 0 key events; "
        "no runtime behaviour was observed. (source: speakeasy, "
        "query_or_table: deep_dive/01-tools-raw.json, "
        "row_or_rule: $.speakeasy.api_calls)\n"
    )
    result = RQ._cross_report_consistency(
        md, md, "", 6.96, _dyn_status_absent())
    assert not any("dynamic_execution_claimed" in v
                   for v in result["violations"]), result["violations"]


def test_a_detonation_claim_cannot_be_excused_by_a_zero_result():
    """Only an emulator can be invoked and produce nothing.

    A detonation, sandbox run or packet capture either happened or did not, so
    "the detonation ran and recorded 0 events" still claims execution.
    """
    md = (
        "# 5. Behavioral Analysis\n\n"
        "- The WinRE detonation ran and recorded 0 events for this sample.\n"
    )
    result = RQ._cross_report_consistency(
        md, md, "", 6.96, _dyn_status_absent())
    assert any("dynamic_execution_claimed" in v
               for v in result["violations"]), result["violations"]


# --------------------------------------------------------------------------
# 5. Citations into the nested UPX second-pass document resolve.
# --------------------------------------------------------------------------
def test_a_upx_second_pass_locator_resolves(tmp_path):
    """`$.upx_second_pass.tools.<engine>...` lives in a NESTED document.

    The engine-branch filter rewrites the whole 01-tools-raw.json down to one
    engine key. That deletes the `upx_second_pass` wrapper the citation starts
    with, so a dozen such rows failed to resolve on a complete technical
    report (2026-10-24, run 67eb72cf). The path names its engine explicitly,
    so the filter is skipped for this branch.
    """
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "malcat": {"file_summary": {"type": "PE32+"}},
        "upx_second_pass": {"tools": {
            "yara": {"matches": [{"rule": "UPX_v2"}, {"rule": "Borland"}]},
            "capa": {"top_rules": [{"name": "packed executable"}]},
            "malcat": {"file_summary": {"type": "PE32"}},
        }},
    }), encoding="utf-8")

    for source, row, want in (
        ("yara", "$.upx_second_pass.tools.yara.matches[0].rule", "UPX_v2"),
        ("capa", "$.upx_second_pass.tools.capa.top_rules[0].name",
         "packed executable"),
        ("malcat", "$.upx_second_pass.tools.malcat.file_summary.type", "PE32"),
    ):
        located, check = E._ground_citation(
            {"source": source, "query": "deep_dive/01-tools-raw.json",
             "row": row}, case)
        assert located is not None, (source, row, check)
        assert check["status"] == "traceable-row", check
        assert want in located["excerpt"], located["excerpt"]


def test_engine_filtering_still_prevents_cross_engine_citations(tmp_path):
    """A malcat citation must not resolve against the yara branch."""
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "malcat": {"file_summary": {"type": "PE32+"}},
        "yara": {"matches": [{"rule": "UPX_v2"}]},
    }), encoding="utf-8")
    located, check = E._ground_citation(
        {"source": "malcat", "query": "deep_dive/01-tools-raw.json",
         "row": "$.yara.matches[0].rule"}, case)
    assert located is None, located
    assert check["status"] == "unresolved-row", check


# --------------------------------------------------------------------------
# 6. `field=value` locators resolve (schema-legal, previously unresolvable).
# --------------------------------------------------------------------------
def test_a_field_value_locator_resolves_a_yara_rule_row(tmp_path):
    """`rule=domain` names the YARA row whose rule is `domain`.

    The schema explicitly permits a non-$ "rule/row name", but entailment only
    understood JSONPaths, so every such row failed (2026-10-24: `rule=domain`,
    `rule=UPX`, `rule=Borland`, ... in a complete technical report).
    """
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "yara": {"matches": [
            {"rule": "domain", "offset": 10},
            {"rule": "UPX", "offset": 20},
        ]},
    }), encoding="utf-8")
    for row, want in (("rule=domain", "domain"), ("rule=UPX", "UPX")):
        located, check = E._ground_citation(
            {"source": "yara", "query": "deep_dive/01-tools-raw.json",
             "row": row}, case)
        assert located is not None, (row, check)
        assert check["status"] == "traceable-row", check
        assert f'"{want}"' in located["excerpt"], located["excerpt"]


def test_a_field_value_locator_that_matches_nothing_stays_unresolved(tmp_path):
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "yara": {"matches": [{"rule": "domain"}]},
    }), encoding="utf-8")
    located, check = E._ground_citation(
        {"source": "yara", "query": "deep_dive/01-tools-raw.json",
         "row": "rule=no_such_rule"}, case)
    assert located is None
    assert check["status"] == "unresolved-row", check


# --------------------------------------------------------------------------
# 7. Known-equivalent path aliases, at any depth.
# --------------------------------------------------------------------------
def test_malcat_view_aliases_apply_inside_the_nested_upx_branch(tmp_path):
    """`...tools.malcat.views.decompilations` is the same field as
    `...tools.malcat.decompilations`; the alias must work at depth."""
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "upx_second_pass": {"tools": {"malcat": {
            "decompilations": {"8896": {"decompilation": "void sub_1(void)"}},
            "carved_files": [{"ea": 47146, "kind": "pe"}],
            "views": {"strings": [{"ea": 1, "summary": "x"}]},
        }}},
    }), encoding="utf-8")
    for row in (
        '$.upx_second_pass.tools.malcat.views.decompilations."8896".decompilation',
        "$.upx_second_pass.tools.malcat.carved[0].ea",
        "$.upx_second_pass.tools.malcat.strings[0].summary",
    ):
        located, check = E._ground_citation(
            {"source": "malcat", "query": "deep_dive/01-tools-raw.json",
             "row": row}, case)
        assert located is not None, (row, check)
        assert check["status"] == "traceable-row", check


# --------------------------------------------------------------------------
# 8. Pre-publication citation repair (P3).
# --------------------------------------------------------------------------
def _section_doc(locator: str) -> dict:
    return {"document": {"sections": [{
        "heading": "1. Test",
        "blocks": [{
            "kind": "observation", "text": "The rule matched.",
            "source": "yara", "query_or_table": "deep_dive/01-tools-raw.json",
            "row_or_rule": locator,
        }],
    }]}}


def test_unresolved_citations_are_reported_for_a_section(tmp_path):
    import publish_report_v2 as PUB
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "yara": {"matches": [{"rule": "domain"}]},
    }), encoding="utf-8")
    bad = PUB._unresolved_citations(_section_doc("rule=absent"), case)
    good = PUB._unresolved_citations(_section_doc("rule=domain"), case)
    assert bad and "rule=absent" in bad[0], bad
    assert good == [], good


def test_a_citation_repair_is_kept_only_when_it_resolves_more(tmp_path, monkeypatch):
    import publish_report_v2 as PUB
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "yara": {"matches": [{"rule": "domain"}]},
    }), encoding="utf-8")

    original = _section_doc("rule=absent")

    # A repair that fixes the citation is kept.
    monkeypatch.setattr(PUB, "llm_report_structured",
                        lambda *a, **k: ({}, _section_doc("rule=domain")))
    parsed, remaining = PUB.repair_section_citations(
        "p", original, case, section_only=True, heading_level=2, label="t")
    assert remaining == 0
    assert parsed["document"]["sections"][0]["blocks"][0]["row_or_rule"] == "rule=domain"

    # A repair that is no better must not replace the original.
    monkeypatch.setattr(PUB, "llm_report_structured",
                        lambda *a, **k: ({}, _section_doc("rule=still_absent")))
    parsed2, remaining2 = PUB.repair_section_citations(
        "p", original, case, section_only=True, heading_level=2, label="t")
    assert parsed2 is original
    assert remaining2 == 1


# --------------------------------------------------------------------------
# 9. `table: key` locator shapes (both schema-legal, previously unresolved).
# --------------------------------------------------------------------------
def _two_pass_artifact(tmp_path) -> Path:
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "yara": {"matches": [{"rule": "domain"}]},
        "malcat": {"views": {"yara_hits": [{"id": "TurboLinker",
                                            "category": "compiler"}]}},
        "upx_second_pass": {"tools": {
            "yara": {"matches": [{"rule": "domain"}, {"rule": "UPX"}]},
            "capa": {"top_rules": [
                {"name": "create service"},
                {"name": "accept command line arguments"},
            ]},
            "malcat": {
                "views": {
                    "strings": [
                        {"ea": 53238, "summary": "SeDebugPrivilege"},
                        {"ea": 53290, "summary": "SeTakeOwnershipPrivilege"},
                    ],
                    "yara_hits": [{"id": "TurboLinker", "category": "compiler"}],
                },
            },
            "floss": {"strings": ["C:\\unm0ve.txt", "\\lcss.exe"]},
        }},
    }), encoding="utf-8")
    return case


def test_table_key_and_unpacked_alias_resolve(tmp_path):
    """`unpacked.yara: rule=domain` is the second-pass document by row key."""
    case = _two_pass_artifact(tmp_path)
    for source, row in (
        ("yara", "unpacked.yara: rule=domain"),
        ("capa", "unpacked.capa.top_rules[0]: create service"),
        ("malcat", "unpacked.malcat.strings: SeDebugPrivilege@53238"),
        ("malcat", "malcat.yara_hits: TurboLinker"),
        ("floss", "unpacked.floss: C:\\unm0ve.txt"),
    ):
        located, check = E._ground_citation(
            {"source": source, "query": "deep_dive/01-tools-raw.json",
             "row": row}, case)
        assert located is not None, (row, check)
        assert check["status"] == "traceable-row", check


def test_a_table_key_that_is_not_in_the_table_stays_unresolved(tmp_path):
    case = _two_pass_artifact(tmp_path)
    for row in ("unpacked.yara: rule=absent",
                "unpacked.floss: NotARealString",
                "malcat.yara_hits: NotARealHit"):
        located, check = E._ground_citation(
            {"source": "yara", "query": "deep_dive/01-tools-raw.json",
             "row": row}, case)
        assert located is None, (row, located)
        assert check["status"] == "unresolved-row", check
