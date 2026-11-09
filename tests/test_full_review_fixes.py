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


# ---------------------------------------------------------------- RC-59/60
# Found live on S1-scripted (331bcdf17104, 2026-11-07): the RC-55 separator
# was counted as an UNCITED CLAIM by the quality gate, and the v3 writer's
# compressed range domain (uni02e5-02e9.cn) went out as an unverified IoC
# because _strip_unverified_indicators covered registry shapes only.
def test_orphan_separator_carries_the_note_marker():
    md = ("| a | b |\n|---|---|\n| 1 | 2 |\n"
          "\n"
          "| c | d |\n|---|---|\n| 3 | 4 |\n")
    out = SP._fix_orphan_tables(md)
    sep = [l for l in out.splitlines() if "presented separately" in l][0]
    assert sep.lstrip().startswith("**[Note]**"), sep
    # The gate's own exemption must accept the line.
    from report_schema import is_non_factual_markdown_line
    assert is_non_factual_markdown_line(sep) is True, sep


def test_indicator_scrubber_covers_domains_and_urls(tmp_path, monkeypatch):
    sha = "9" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "iocs.json").write_text(json.dumps(
        {"domains": ["known[.]evil[.]example[.]com"],
         "urls": ["http[:]//known[.]evil[.]example[.]com/gate"]}))
    monkeypatch.setattr(SP, "case_dir", lambda s: case)
    md = ("## 6. Network\n\n"
          "- C2 at unknown-range-domain.cn (source: iocs, "
          "query_or_table: iocs.json, row_or_rule: $.domains[0])\n"
          "- C2 at known[.]evil[.]example[.]com\n"
          "- Fetches http://never-seen-anywhere.example.com/payload\n"
          "Prose paragraph mentioning windows.com stays untouched.\n")
    out = SP._strip_unverified_indicators(md, sha)
    assert "unknown-range-domain.cn" not in out, out
    assert "[redacted: not in evidence]" in out
    assert "known[.]evil[.]example[.]com" in out, (
        "a corpus-backed value must be kept")
    assert "http://never-seen-anywhere.example.com/payload" not in out
    assert "windows.com" in out, "prose paragraphs must not be scrubbed"
    assert "(source: iocs, query_or_table: iocs.json, row_or_rule: $.domains[0])" in out, (
        "citations must never be scrubbed")


# ---------------------------------------------------------------- RC-61
# S2-agentic surfaced that the v3 MASTER had NO unverified-IoC repair;
# 4 invented indicators in master prose caused section_publish rc=1.
# Ported RC-36's keep-only-if-clean regeneration to the v3 master:
# accepted when cleaned, retained honestly when still dirty or stub.
def test_rc61_v3_master_unverified_ioc_repair_accepted(tmp_path, monkeypatch):
    sha = "a" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "iocs.json").write_text(json.dumps({"domains": [], "urls": []}))
    monkeypatch.setattr(SP, "case_dir", lambda s: case)
    monkeypatch.setenv("_SECTION_SHA", sha)

    # Offending draft containing an invented indicator
    invented_ioc = "HKCU\\Software\\Classes\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}"
    dirty_sec = (f"## 7. Capabilities Assessment\n\nThe malware establishes persistence via "
                 f"{invented_ioc} in COM registration.\n")
    clean_sec = (
        "## 7. Capabilities Assessment\n\n"
        "The malware establishes persistence through Windows service creation and scheduled task "
        "execution across the host environment. The persistence mechanisms were observed in static "
        "decompilation of the service installer subroutines. COM CLSID registration was not observed "
        "in any tool artifact, and the indicators previously cited were removed because they do not "
        "appear anywhere in the evidence corpus.\n"
    )

    full_md = (f"# RE Report — {sha[:12]}\n\n"
               + "\n\n".join(f"## {s}\n\nSubstantive analysis for {s} with valid citations and findings across the whole sample."
                             for s in SP.REPORT_MASTER_SECTIONS if s != "7. Capabilities Assessment")
               + "\n\n" + dirty_sec)

    # Test retry_unverified_ioc_sections directly with clean replacement
    repaired_md, attempts = SP.retry_unverified_ioc_sections(
        full_md, ["7. Capabilities Assessment"], [invented_ioc],
        lambda sec, orig: clean_sec
    )
    assert len(attempts) == 1
    assert attempts[0]["accepted"] is True
    assert attempts[0]["section"] == "7. Capabilities Assessment"
    assert invented_ioc not in repaired_md
    assert "Windows service creation and scheduled task" in repaired_md


def test_rc61_v3_master_unverified_ioc_repair_retained(tmp_path, monkeypatch):
    sha = "b" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "iocs.json").write_text(json.dumps({"domains": [], "urls": []}))
    monkeypatch.setattr(SP, "case_dir", lambda s: case)

    invented_ioc = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"
    dirty_sec = (f"## 7. Capabilities Assessment\n\nPersistence is configured through "
                 f"{invented_ioc} registry hook.\n")
    # Retry still contains the invented indicator and is long enough not to be a stub
    still_dirty_sec = (
        f"## 7. Capabilities Assessment\n\n"
        f"Rewritten section still mentioning {invented_ioc} because the writer refused to drop it. "
        "The sample configures persistence across multiple registry hooks and service installations "
        "as observed across various decompilation routines and disassembly listings recovered from "
        "the static analysis stage.\n"
    )

    full_md = (f"# RE Report — {sha[:12]}\n\n"
               + "\n\n".join(f"## {s}\n\nSubstantive content for {s} with sufficient detailed findings."
                             for s in SP.REPORT_MASTER_SECTIONS if s != "7. Capabilities Assessment")
               + "\n\n" + dirty_sec)

    repaired_md, attempts = SP.retry_unverified_ioc_sections(
        full_md, ["7. Capabilities Assessment"], [invented_ioc],
        lambda sec, orig: still_dirty_sec
    )
    assert len(attempts) == 1
    assert attempts[0]["accepted"] is False
    assert "still contains the unverified indicator" in attempts[0]["reason"]
    # Original section is preserved honestly
    assert dirty_sec.strip() in repaired_md


# ---------------------------------------------------------------- RC-62
# S2's 239 unresolved-rows were caused by _strip_unverified_indicators
# mutilating citations (e.g. tools.malcat, 00-tools-raw.json) into
# [redacted: not in evidence]. Citations, JSONPaths, and file extensions
# must NEVER be scrubbed. Also, UPX second-pass rows must be present in
# section row manifests for packed samples.
def test_rc62_indicator_scrubber_preserves_citations_and_paths(tmp_path, monkeypatch):
    sha = "c" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "iocs.json").write_text(json.dumps({"domains": [], "urls": []}))
    monkeypatch.setattr(SP, "case_dir", lambda s: case)

    md = (
        "## 4. Static Analysis\n\n"
        "- Capa matched create service on unpacked image. (source: capa, "
        "query_or_table: deep_dive/01-tools-raw.json, row_or_rule: $.upx_second_pass.tools.capa.top_rules[6])\n"
        "- YARA fired on sample. (source: yara, query_or_table: quick_scan/00-tools-raw.json, "
        "row_or_rule: $.upx_second_pass.tools.yara.matches[3])\n"
        "- The file sample_unpacked.exe imports kernel32.dll. (source: malcat, "
        "query_or_table: deep_dive/01-tools-raw.json, row_or_rule: $.upx_second_pass.tools.malcat.file_summary.sha256)\n"
        "- C2 at bad-unknown-range.cn (source: iocs, query_or_table: iocs.json, row_or_rule: $.domains[0])\n"
    )
    out = SP._strip_unverified_indicators(md, sha)
    # The actual unverified domain must be scrubbed:
    assert "bad-unknown-range.cn" not in out
    assert "[redacted: not in evidence]" in out
    # But citations, JSONPaths, and file extensions must be 100% intact:
    assert "query_or_table: deep_dive/01-tools-raw.json" in out
    assert "row_or_rule: $.upx_second_pass.tools.capa.top_rules[6]" in out
    assert "query_or_table: quick_scan/00-tools-raw.json" in out
    assert "row_or_rule: $.upx_second_pass.tools.yara.matches[3]" in out
    assert "sample_unpacked.exe" in out
    assert "kernel32.dll" in out
    assert "row_or_rule: $.upx_second_pass.tools.malcat.file_summary.sha256" in out
    assert "query_or_table: iocs.json" in out


def test_rc62_section_row_manifest_includes_upx_second_pass(tmp_path, monkeypatch):
    import v2_lib
    sha = "d" * 64
    case = tmp_path / "logs" / sha / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    tools_raw = {
        "upx_second_pass": {
            "tools": {
                "malcat": {
                    "views": {
                        "anomalies": [{"name": "SuspiciousSection", "ea": 4096}],
                        "strings": [{"value": "C:\\unm0ve.txt", "ea": 50936}],
                    }
                },
                "capa": {
                    "top_rules": [{"rule": "create service", "category": "persistence"}]
                },
                "yara": {
                    "matches": [{"rule": "CreateService", "offset": 9124}]
                }
            }
        }
    }
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps(tools_raw))
    monkeypatch.setattr(v2_lib, "case_dir", lambda s, mode=None: case)

    manifest_sec3 = v2_lib.build_section_row_manifest(sha, "3. File Layout & Structural Analysis")
    assert "upx_second_pass.tools.malcat.views.anomalies[0]" in manifest_sec3

    manifest_sec4 = v2_lib.build_section_row_manifest(sha, "4. Static Code Analysis")
    assert "upx_second_pass.tools.malcat.views.strings[0]" in manifest_sec4

    manifest_sec7 = v2_lib.build_section_row_manifest(sha, "7. Capabilities Assessment")
    assert "upx_second_pass.tools.capa.top_rules[0]" in manifest_sec7


# ---------------------------------------------------------------- RC-64
def test_rc64_threat_intel_domains_are_benign():
    from ioc_confidence import is_benign_domain
    assert is_benign_domain("abuse.ch") is True
    assert is_benign_domain("Abuse.ch") is True
    assert is_benign_domain("virustotal.com") is True
    assert is_benign_domain("hybrid-analysis.com") is True
    assert is_benign_domain("mandiant.com") is True
    assert is_benign_domain("evil-c2.com") is False


def test_rc64_verdict_metalinguistic_filtering():
    import v2_lib
    body = (
        "## 2. Classification\n"
        "- The iocs.json tool verdict for this sample is 'malicious'.\n"
        "- **[Note]** The v1_summary (verdict: malicious, score: 290)\n"
        "- **[Assessment]** The pipeline-selected verdict is 'suspicious' rather than 'malicious'.\n"
    )
    inferred = v2_lib.infer_publish_verdict_from_markdown(body)
    assert inferred == "suspicious", inferred


def test_rc64_v3_reports_ensure_verdict_panel(tmp_path, monkeypatch):
    import v2_lib
    sha = "e" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "verdict-calibration.json").write_text(json.dumps({
        "from": "malicious", "to": "suspicious", "reason": "obfuscation only"
    }))
    raw_md = "# RE Report\n\nSome findings."
    panelled = v2_lib.ensure_verdict_panel(raw_md, "suspicious")
    assert "| Verdict | suspicious |" in panelled
    assert v2_lib.infer_publish_verdict_from_markdown(panelled) == "suspicious"


