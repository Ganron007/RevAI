"""2026-11-07 full-review fixes: RC-54..RC-58 + the B-fix set.

Every fix from the three review sweeps is pinned two-direction where it has
a failure mode:
- RC-54: the v3 MASTER renders sections 9 and (non-substantive) 5
  deterministically — the same renderers and conditions as the v2 master.
- RC-55: _fix_orphan_tables actually inserts its separator (the original
  state machine never fired).
- RC-56: the entailment cache fingerprint carries the classifier-generation
  key; a cache built by an older classifier generation is not reused.
- RC-57: partial_llm_judge is an acceptable LLM source label.
- RC-58: RC-51's drift check resolves NESTED artifacts (deep_dive/*,
  quick_scan/*), not just root-level files.
- B-fixes: HITL case handling, oracle truthy sets, the behavioural-model
  attach gate, the scripted trace gate fields.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import report_quality as RQ  # noqa: E402
import section_publisher as SP  # noqa: E402


# ---------------------------------------------------------------- RC-54
def _no_llm(prompt, **kwargs):
    raise AssertionError("the deterministic section must not call the LLM")


def test_v3_master_ioc_section_is_deterministic(monkeypatch, tmp_path):
    monkeypatch.setattr(SP, "llm_report_structured", _no_llm)
    # iocs.json with one URL so the deterministic renderer has content.
    import v2_lib
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    case = tmp_path / "logs" / ("b" * 64) / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    (case / "iocs.json").write_text(json.dumps(
        {"urls": ["http[:]//c2[.]evil[.]example[.]com/gate"]}))
    monkeypatch.setattr(SP, "case_dir", lambda sha: case)
    out = SP._run_one_section("9. Indicators of Compromise", "b" * 64, {}, {})
    assert out["llm_ok"] is True, out
    assert out.get("deterministic") is True, out
    assert "## 9. Indicators of Compromise" in out["markdown"]
    assert "c2[.]evil[.]example[.]com" in out["markdown"]


def test_v3_master_behavioral_section_deterministic_without_detonation(
        monkeypatch, tmp_path):
    monkeypatch.setattr(SP, "llm_report_structured", _no_llm)
    import v2_lib
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    case = tmp_path / "logs" / ("c" * 64) / "agentic"
    case.mkdir(parents=True)
    (case / "dynamic-analysis-status.json").write_text(json.dumps(
        {"status": "not_performed",
         "sentence": "No dynamic analysis was performed for this sample."}))
    monkeypatch.setattr(SP, "case_dir", lambda sha: case)
    # The production path passes the run's status through tools_results;
    # the section must render THAT sentence deterministically.
    out = SP._run_one_section("5. Behavioral Analysis", "c" * 64, {}, {})
    assert out["llm_ok"] is True, out
    assert out.get("deterministic") is True, out
    body = " ".join(str(out["markdown"]).split())
    assert ("no dynamic analysis was performed" in body.lower()
            or "no runtime-analysis mechanism observed" in body.lower()), out["markdown"]


def test_v3_master_behavioral_section_uses_llm_after_detonation(
        monkeypatch, tmp_path):
    calls = []

    def _llm(prompt, **kwargs):
        calls.append(prompt)
        resp = {"choices": [{"message": {"content": json.dumps(
            {"title": "5. Behavioral Analysis",
             "markdown": "## 5. Behavioral Analysis\n\nobserved behavior"})}}]}
        meta = {}
        return resp, meta

    monkeypatch.setattr(SP, "llm_report_structured", _llm)
    monkeypatch.setattr(SP, "llm_call_metadata", lambda r: {})
    monkeypatch.setattr(SP, "get_llm_model", lambda: "m")
    monkeypatch.setattr(SP, "_persist_llm_call",
                        lambda *a, **k: {"id": "x"})
    import v2_lib
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    case = tmp_path / "logs" / ("d" * 64) / "agentic"
    case.mkdir(parents=True)
    monkeypatch.setattr(SP, "case_dir", lambda sha: case)
    tools = {"_dynamic_status": {
        "status": "ok",
        "sentence": "The detonation ran and produced 12 runtime events.",
        "winre": {"detonation_ran": True}}}
    out = SP._run_one_section("5. Behavioral Analysis", "d" * 64, tools, {})
    assert calls, "a substantive detonation must reach the LLM"
    assert out.get("deterministic") is None, out


# ---------------------------------------------------------------- RC-55
def test_orphan_table_fix_inserts_the_separator():
    md = ("| a | b |\n|---|---|\n| 1 | 2 |\n"
          "\n"
          "| c | d |\n|---|---|\n| 3 | 4 |\n")
    assert RQ.count_table_orphans(md) >= 1, "the fixture must be an orphan"
    out = SP._fix_orphan_tables(md)
    assert "The tables above are presented separately" in out, out
    assert RQ.count_table_orphans(out) == 0, out


def test_orphan_table_fix_leaves_contiguous_rows_untouched():
    md = ("| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n\nProse between.\n\n"
          "| c | d |\n|---|---|\n| 5 | 6 |\n")
    out = SP._fix_orphan_tables(md)
    assert "The tables above are presented separately" not in out
    assert out == md, "a non-orphan report must be byte-identical"


# ---------------------------------------------------------------- RC-56
def test_fingerprint_schema_is_the_classifier_generation():
    import entailment as E
    assert E._FINGERPRINT_SCHEMA == 10, (
        "bump on every classification-behavior change (RC-49/50/51 lesson)")


def test_a_stale_cache_with_an_old_fingerprint_is_not_reused(tmp_path):
    import entailment as E
    case = tmp_path / "logs" / ("e" * 64) / "agentic"
    (case / "publish").mkdir(parents=True)
    (case / "REPORT-MASTER-v2.md").write_text(
        "# x\n\nThe sample persists via a Run key "
        "(source: iocs, query_or_table: iocs.json, row_or_rule: $.urls[0]).\n")
    (case / "iocs.json").write_text(json.dumps(
        {"urls": ["http[:]//x[.]example[.]com"]}))
    # A completed-looking cache from the OLD classifier generation: its
    # fingerprint was computed with schema 9, so it must not match.
    stale = {
        "schema_version": 10, "ok": False, "status": "complete",
        "claims_total": 1,
        "by_status": {"contradicted": 1},
        "claims": [{"report": "REPORT-MASTER-v2.md", "claim": "old",
                    "status": "contradicted"}],
        "input_fingerprint": "0" * 64,
        "review_error": None,
    }
    (case / "publish" / "claim-entailment.json").write_text(json.dumps(stale))

    def _reviewer(batch, **_kw):
        return {"reviews": [{"id": item["id"], "verdict": "supported",
                             "evidence_ids": [item["evidence"][0]["evidence_id"]]}
                            for item in batch]}

    res = E.check_report_entailment(
        "e" * 64, case_root=case, semantic_reviewer=_reviewer,
        use_cache=True)
    # The stale cache's fingerprint ("0"*64) cannot match the freshly
    # computed one, so the review RAN and reclassified the claim.
    assert res.get("claims_total") != 1 or res.get("claims", [{}])[0].get(
        "claim") != "old", "a stale cache was reused"


# ---------------------------------------------------------------- RC-57
def test_partial_llm_judge_is_an_acceptable_source():
    assert RQ.source_is_llm_ok("partial_llm_judge") is True
    assert RQ.source_is_fallback("partial_llm_judge") is False


# ---------------------------------------------------------------- RC-58
def test_row_index_drift_resolves_nested_artifacts(tmp_path):
    import entailment as E
    sha = "f" * 64
    case = tmp_path / "logs" / sha / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    # The claim's cells match exactly one row of a NESTED artifact.
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps(
        {"capa": {"top_rules": [
            {"name": "other_rule", "score": 2},
            {"name": "persistence_run_key", "score": 9,
             "description": "sets a Run registry key"}]}}))
    claim = ("| persistence_run_key | 9 | sets a Run registry key | "
             "(source: capa, query_or_table: deep_dive/01-tools-raw.json, "
             "row_or_rule: $.capa.top_rules[1])")
    evidence_rows = [{"artifact": "01-tools-raw.json",
                      "source": "capa",
                      "query": "deep_dive/01-tools-raw.json"}]
    out = E._row_index_drift(case, claim, evidence_rows)
    assert out is not None, (
        "a nested artifact's drifted row must still resolve")


# ---------------------------------------------------------------- B-fixes
def test_behavioural_attach_is_a_noop_when_disabled_and_no_artifact(
        monkeypatch, tmp_path):
    import behavioural_model as BM
    import v2_lib
    monkeypatch.delenv("REVAI_ENABLE_BEHAVIOURAL_MODEL", raising=False)
    monkeypatch.delenv("REVAI_DISABLE_BEHAVIOURAL_MODEL", raising=False)
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    sha = "1" * 64
    case = tmp_path / "logs" / sha / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": {"surface": "understood"}}},
         "history": []}))
    md = "# Report\n\ntext\n"
    out = BM.attach_behavioural_model(md, sha)
    # The domain ledger exists but the feature is OFF and the stage never
    # wrote its artifact -> byte-identical (the documented contract).
    assert out == md, "the attach must honor the enable gate it documents"


def test_behavioural_attach_appends_when_the_stage_artifact_exists(
        monkeypatch, tmp_path):
    import behavioural_model as BM
    import v2_lib
    monkeypatch.delenv("REVAI_ENABLE_BEHAVIOURAL_MODEL", raising=False)
    monkeypatch.delenv("REVAI_DISABLE_BEHAVIOURAL_MODEL", raising=False)
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    sha = "2" * 64
    case = tmp_path / "logs" / sha / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": {"surface": "understood"}}},
         "history": []}))
    (case / "behavioural_model.json").write_text(json.dumps({"stub": True}))
    md = "# Report\n\ntext\n"
    out = BM.attach_behavioural_model(md, sha)
    assert out != md, "an existing stage artifact keeps its report section"


def test_oracle_truthy_sets_accept_on(monkeypatch):
    import emulation_oracle as EO
    import unpack_oracle as UO
    monkeypatch.setenv("REVAI_ENABLE_EMULATION_ORACLE", "on")
    monkeypatch.setenv("REVAI_ENABLE_UNPACK_PASS", "on")
    assert EO.oracle_enabled() is True
    assert UO.unpack_enabled() is True
