"""The dynamic-analysis fabrication fix.

The section report once described dynamic execution from the model's reading of
tool names, and asserted "Speakeasy and Frida executed successfully" for a
sample whose emulation oracle FAILED and where no Frida or WinRE pack exists.
This pins the three-layer fix:

  1. dynamic_analysis_status reads the truth from artifacts;
  2. the audit gate flags an execution claim when the status says none ran --
     and does NOT flag the honest "not performed" status sentence;
  3. the section gets the status injected so the report states it verbatim.
"""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve, source  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402
import report_quality as RQ  # noqa: E402
import section_publisher as SP  # noqa: E402
import publish_report_v2 as PR  # noqa: E402


def _report_tool_response(markdown):
    from _report_fixtures import structured_tool_response
    return structured_tool_response(markdown)


# ------------------------------------------------------------- the status helper
def _start_run(tmp_path, monkeypatch, sha, mode="scripted"):
    logs = tmp_path / "logs"
    monkeypatch.setattr(v2_lib, "LOGS_DIR", logs)
    monkeypatch.setenv("REVAI_RUN_MODE", mode)
    monkeypatch.delenv("REVAI_RUN_ID", raising=False)
    context = v2_lib.begin_execution(sha, mode=mode, engine="test")
    return logs, context


def test_status_reports_a_failed_oracle_as_not_performed(tmp_path, monkeypatch):
    """The .NET case: oracle present but ok=False."""
    logs, context = _start_run(tmp_path, monkeypatch, "ab")
    case = logs / "ab" / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    oracle = v2_lib.stamp_case_artifact(
        {"ok": False, "engine": "emulation_oracle",
         "error": "SpeakeasyError: Emulator not initialized"},
        "ab", "deep_dive/03-oracle.json")
    (case / "deep_dive" / "03-oracle.json").write_text(
        json.dumps(oracle),
        encoding="utf-8")
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))
    st = v2_lib.dynamic_analysis_status("ab", logs_dir=logs)
    assert st["any_dynamic_performed"] is False
    assert "NOT performed" in st["emulation"]["state"]
    assert "not performed" in st["sentence"].lower()
    assert st["run_id"] == context["run_id"]


def test_status_reports_a_successful_oracle(tmp_path, monkeypatch):
    logs, _context = _start_run(tmp_path, monkeypatch, "cd")
    case = logs / "cd" / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    oracle = v2_lib.stamp_case_artifact(
        {"ok": True, "engine": "emulation_oracle"},
        "cd", "deep_dive/03-oracle.json")
    (case / "deep_dive" / "03-oracle.json").write_text(
        json.dumps(oracle),
        encoding="utf-8")
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))
    st = v2_lib.dynamic_analysis_status("cd", logs_dir=logs)
    assert st["any_dynamic_performed"] is True
    assert "produced a trace" in st["emulation"]["state"]


def test_dynamic_status_is_persisted_as_citable_evidence(tmp_path, monkeypatch):
    logs, _context = _start_run(tmp_path, monkeypatch, "a" * 64)
    status = {
        "sentence": "Run-scoped status -- WinRE detonation: sample launch confirmed.",
        "any_dynamic_performed": True,
    }
    monkeypatch.setattr(v2_lib, "dynamic_analysis_status", lambda *_a, **_k: status)

    record = v2_lib.persist_dynamic_analysis_status("a" * 64)
    case_root = logs / ("a" * 64) / "scripted"
    persisted = json.loads((case_root / "dynamic-analysis-status.json").read_text())
    import entailment

    evidence, used = RQ.collect_evidence_text(case_root)
    claim = {
        "source": "dynamic_analysis_status",
        "query": "run-scoped status",
        "row": "run-scoped status",
        "text": status["sentence"],
    }

    assert record == persisted
    assert persisted["status"] == status
    assert "dynamic-analysis-status.json" in used
    assert entailment.verify_claim(claim, evidence, case_root)["checks"]["row_resolves"]


def test_status_with_no_oracle_says_so(tmp_path, monkeypatch):
    logs, _context = _start_run(tmp_path, monkeypatch, "zz")
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))
    st = v2_lib.dynamic_analysis_status("zz", logs_dir=logs)
    assert st["emulation"]["present"] is False
    assert st["any_dynamic_performed"] is False


def test_status_reads_execution_context_from_the_supplied_logs_root(
        tmp_path, monkeypatch):
    sha = "d" * 64
    run_id = "e" * 32
    logs = tmp_path / "custom-logs"
    case = logs / sha / "agentic"
    oracle_path = case / "deep_dive" / "03-oracle.json"
    oracle_path.parent.mkdir(parents=True)
    context = {
        "schema": "revai-execution-context/v1", "run_id": run_id,
        "sha256": sha, "mode": "agentic", "engine": "test",
        "started_at": "2026-10-18T00:00:00+00:00",
    }
    (case / "execution-context.json").write_text(json.dumps(context))
    oracle = {
        "ok": True, "engine": "emulation_oracle",
        "_cadre_provenance": {
            "schema": "revai-artifact-provenance/v1", "sha256": sha,
            "run_id": run_id, "mode": "agentic",
            "artifact": "deep_dive/03-oracle.json",
            "generated_at": "2026-10-18T00:00:01+00:00",
        },
    }
    oracle_path.write_text(json.dumps(oracle))
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "different-default")
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.delenv("REVAI_RUN_ID", raising=False)
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))

    status = v2_lib.dynamic_analysis_status(sha, logs_dir=logs)

    assert status["run_id"] == run_id
    assert status["emulation"]["present"] is True
    assert status["emulation"]["state"] == "emulation produced a trace"


def test_status_separates_winre_launch_runtime_trace_and_passive_capture(
        tmp_path, monkeypatch):
    sha = "e" * 64
    winre = tmp_path / "winre"
    dyn = winre / sha / "agentic" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "META.json").write_text(json.dumps({"ok": True}))
    (dyn / "META.job.json").write_text(json.dumps({
        "detonation_ran": True, "sample_pid": 7368, "frida_events": 577,
    }))
    (dyn / "frida_summary.json").write_text(json.dumps({"events": 577}))
    (dyn / "frida_trace.jsonl").write_text('{"event":"call"}\n')
    (dyn / "off_box" / "network_raw").mkdir(parents=True)
    (dyn / "off_box" / "network_raw" / "vmnet2.pcap").write_bytes(b"pcap")
    (dyn / "off_box" / "capture.json").write_text(json.dumps({
        "requested": True, "status": "collected", "mode": "passive",
        "interface": "ens32", "guest_ip": "192.168.77.42",
        "capture_filter": "host 192.168.77.42", "packets_captured": 37,
        "pcap_sha256": "a" * 64,
        "path": "off_box/network_raw/vmnet2.pcap",
    }))
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(winre))

    st = v2_lib.dynamic_analysis_status(sha, logs_dir=tmp_path / "logs")
    assert st["any_dynamic_performed"] is True
    assert st["winre"]["detonation_ran"] is True
    assert st["winre"]["sample_pid"] == 7368
    assert st["frida_runtime"]["observed_runtime_events"] is True
    assert st["frida_runtime"]["events"] == 577
    assert st["packet_capture"]["present"] is True
    assert st["packet_capture"]["external_capture"]["packets_captured"] == 37
    assert "static-only" in st["sentence"]
    assert "sample launch confirmed" in st["sentence"]


def test_status_uses_meta_event_count_when_job_count_is_explicitly_null(
        tmp_path, monkeypatch):
    sha = "2" * 64
    dyn = tmp_path / "winre" / sha / "agentic" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "META.json").write_text(json.dumps({
        "ok": True, "detonation_ran": True, "frida_events": 639,
    }))
    (dyn / "META.job.json").write_text(json.dumps({
        "detonation_ran": True, "sample_pid": 1948, "frida_events": None,
    }))
    (dyn / "frida_summary.json").write_text(json.dumps({"status": "ok"}))
    (dyn / "frida_trace.jsonl").write_text('{"event":"call"}\n')
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "winre"))

    st = v2_lib.dynamic_analysis_status(sha, logs_dir=tmp_path / "logs")

    assert st["frida_runtime"]["events"] == 639
    assert st["frida_runtime"]["observed_runtime_events"] is True
    assert st["any_dynamic_performed"] is True


def test_status_preserves_explicit_zero_event_count(tmp_path, monkeypatch):
    sha = "3" * 64
    dyn = tmp_path / "winre" / sha / "agentic" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "META.json").write_text(json.dumps({
        "ok": True, "detonation_ran": True, "frida_events": 639,
    }))
    (dyn / "META.job.json").write_text(json.dumps({
        "detonation_ran": True, "frida_events": 0,
    }))
    (dyn / "frida_summary.json").write_text(json.dumps({"status": "ok"}))
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "winre"))

    st = v2_lib.dynamic_analysis_status(sha, logs_dir=tmp_path / "logs")

    assert st["frida_runtime"]["events"] == 0
    assert st["frida_runtime"]["observed_runtime_events"] is False


def test_pack_without_launch_attestation_is_not_reported_as_a_run(
        tmp_path, monkeypatch):
    sha = "f" * 64
    dyn = tmp_path / "winre" / sha / "agentic" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "META.json").write_text(json.dumps({"ok": True}))
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "winre"))

    st = v2_lib.dynamic_analysis_status(sha, logs_dir=tmp_path / "logs")
    assert st["winre"]["pack_present"] is True
    assert st["winre"]["detonation_ran"] is None
    assert st["any_dynamic_performed"] is None


def test_snapshot_gate_skip_record_proves_dynamic_was_not_launched(
        tmp_path, monkeypatch):
    sha = "9" * 64
    run_id = "a" * 32
    dyn = tmp_path / "winre" / sha / "agentic" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "META.json").write_text(json.dumps({
        "sha256": sha, "run_id": run_id, "aborted": True,
    }))
    (dyn / "STAGE.json").write_text(json.dumps({
        "stage": "dynamic", "ok": False, "gate_pass": False,
        "state": "blocked by snapshot gate",
    }))
    (dyn / "SKIP.json").write_text(json.dumps({
        "schema": "winre-dynamic-skip/v1", "stage": "dynamic",
        "ran": False, "skipped": True, "ok": False,
        "reason": "snapshot_gate_blocked",
        "has_detonation_evidence": False,
        "summary": "blocked before launch",
    }))
    monkeypatch.setenv("REVAI_RUN_ID", run_id)
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "winre"))

    status = v2_lib.dynamic_analysis_status(sha, logs_dir=tmp_path / "logs")

    assert status["winre"]["detonation_ran"] is False
    assert status["winre"]["launch_state"] == "not_performed"
    assert status["winre"]["skip_reason"] == "snapshot_gate_blocked"
    assert status["any_dynamic_performed"] is False
    assert "sample launch not performed" in status["sentence"]
    consistency = RQ._cross_report_consistency(
        status["sentence"], "", "", None, status
    )
    assert consistency["ok"] is True, consistency["violations"]


def test_unmatched_run_status_is_not_used_as_current_launch_proof(
        tmp_path, monkeypatch):
    sha = "1" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "winre-run.json").write_text(json.dumps({
        "state": "skipped", "finished_at": "2026-10-14T10:00:00+00:00",
    }))
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))

    st = v2_lib.dynamic_analysis_status(sha, logs_dir=tmp_path / "logs")
    assert st["winre"]["detonation_ran"] is None
    assert "not correlated to this analysis run" in st["winre"]["state"]
    assert "latest recorded WinRE request was skipped" in st["winre"]["state"]
    assert "launch did not occur" not in st["sentence"]
    assert "sample launch confirmed" not in st["sentence"]


# ------------------------------------------------------------- the audit gate
def test_gate_flags_a_fabricated_execution_when_none_ran():
    st = {"any_dynamic_performed": False,
          "sentence": "Dynamic analysis -- emulation NOT performed"}
    fabricated = "We confirm the dynamic runs executed successfully."
    c = RQ._cross_report_consistency(fabricated, "", "", None, st)
    assert c["ok"] is False
    assert any("dynamic_execution_claimed_but_none_performed" in v
               for v in c["violations"]), c["violations"]


def test_gate_does_not_flag_the_honest_status_sentence():
    st = {"any_dynamic_performed": False,
          "sentence": "Dynamic analysis in this run -- emulation NOT performed "
                      "(failed); Frida: not performed; WinRE: not performed."}
    # A report that states the truth must not trip the fabrication gate.
    c = RQ._cross_report_consistency(st["sentence"], "", "", None, st)
    assert not any("dynamic_execution_claimed" in v for v in c["violations"]), \
        c["violations"]


def test_gate_does_not_flag_a_negated_dynamic_claim():
    """The honest negation this fix is meant to produce.

    The first re-run produced exactly this sentence and my own regex flagged
    it: 'No dynamic/Speakeasy/Frida trace was captured for this sample'. A
    negation is not a claim -- this is the _signal_hits negation-guard class.
    """
    st = {"any_dynamic_performed": False, "sentence": "emulation NOT performed"}
    honest = ("No dynamic/Speakeasy/Frida trace was captured for this sample; "
              "the runtime behaviour described above is inferred from static IL "
              "and string recovery, not observed in a sandbox.")
    c = RQ._cross_report_consistency(honest, "", "", None, st)
    assert not any("dynamic_execution_claimed" in v for v in c["violations"]), \
        f"an honest negation was flagged as a fabrication: {c['violations']}"


def test_gate_still_flags_a_genuine_affirmative_claim():
    """The negation guard must not make the gate blind."""
    st = {"any_dynamic_performed": False, "sentence": "emulation NOT performed"}
    c = RQ._cross_report_consistency(
        "The dynamic runs executed successfully during triage.", "", "", None, st)
    assert any("dynamic_execution_claimed_but_none_performed" in v
               for v in c["violations"]), c["violations"]


def test_gate_preserves_unverified_dynamic_status_as_unknown():
    st = {
        "any_dynamic_performed": None,
        "winre": {"pack_present": True, "detonation_ran": None},
        "sentence": "WinRE pack present; launch state unverified.",
    }
    c = RQ._cross_report_consistency(
        "Dynamic analysis executed successfully.", "", "", None, st)
    assert c["checks"]["dynamic_performed"] is None
    assert c["checks"]["dynamic_status_unverified"] is True
    assert any("dynamic_execution_status_unverified" in v
               for v in c["violations"]), c["violations"]
    assert not any("dynamic_execution_claimed_but_none_performed" in v
                   for v in c["violations"]), c["violations"]


def test_negation_guard_helper():
    assert RQ._affirmative_dynamic_claim("No Frida trace was captured") is None
    assert RQ._affirmative_dynamic_claim("") is None
    assert RQ._affirmative_dynamic_claim("we did not run frida") is None
    got = RQ._affirmative_dynamic_claim("The dynamic runs executed successfully")
    assert got and "executed" in got


def test_negation_after_the_verb_is_not_a_claim():
    """The msil_crypt_dotnet agentic case (2026-10-13): the truthful sentence
    "Frida instrumentation was not performed" MATCHES _DYN_EXECUTED_RE
    (frida ... instrumentation ... was) and negates only in what follows. The
    guard looked exclusively backwards, so a correct report was failed as a
    fabrication and the orchestrator burned a retry cycle re-publishing it.
    """
    assert RQ._affirmative_dynamic_claim(
        "Frida instrumentation was not performed") is None
    assert RQ._affirmative_dynamic_claim(
        "Frida instrumentation was, in fact, not performed") is None
    assert RQ._affirmative_dynamic_claim(
        "Frida instrumentation was not performed, and WinRE detonation "
        "was not run") is None
    # The affirmative form must still be caught, including a "without" that
    # describes the claim rather than negating the verb.
    assert RQ._affirmative_dynamic_claim(
        "Frida instrumentation was performed") is not None
    assert RQ._affirmative_dynamic_claim(
        "Frida instrumentation was performed without errors") is not None


def test_gate_flags_the_genuine_claim_in_a_mixed_report():
    """A report that states the truth AND carries one genuine claim is failed
    for the claim, not for the truth: the first NON-negated match wins."""
    st = {"any_dynamic_performed": False,
          "sentence": "emulation NOT performed; Frida: not performed"}
    tech3 = (
        "Frida instrumentation was not performed, so no runtime API hooking "
        "or memory access monitoring occurred. "
        "Frida instrumentation probe was configured for the analysis "
        "environment, with results as follows: the hook fired twice."
    )
    c = RQ._cross_report_consistency("", "", tech3, None, st)
    assert any("dynamic_execution_claimed_but_none_performed" in v
               for v in c["violations"]), c["violations"]


def test_gate_passes_a_truthful_only_report():
    """The mirror image: every mention negated -> no violation at all."""
    st = {"any_dynamic_performed": False,
          "sentence": "emulation NOT performed; Frida: not performed"}
    tech3 = (
        "Frida instrumentation was not performed, so no runtime API hooking, "
        "memory access monitoring, or managed code execution tracing took "
        "place. Frida instrumentation was not performed, and WinRE detonation "
        "was not run, so no network traffic or C2 handshake patterns were "
        "observed."
    )
    c = RQ._cross_report_consistency("", "", tech3, None, st)
    assert not any("dynamic_execution_claimed" in v
                   for v in c["violations"]), c["violations"]


# ------------------------------------------- no post-generation claim rewriting
def test_gate_flags_a_fabricated_claim_without_rewriting_report_text():
    """Contradictory model prose stays visible and makes the run fail quality.

    A publisher must never turn a bad answer into a superficially green one by
    replacing the sentence after generation. The artifact-backed gate is the
    backstop; the report remains the model's original output for review.
    """
    st = {"any_dynamic_performed": False,
          "sentence": "WinRE detonation: sample did not launch"}
    md = "The dynamic runs executed successfully during triage."
    c = RQ._cross_report_consistency(md, "", "", None, st)
    assert any("dynamic_execution_claimed_but_none_performed" in v
               for v in c["violations"]), c["violations"]
    assert "The dynamic runs executed successfully" in md


def test_publishers_do_not_rewrite_dynamic_claims_after_generation():
    """The prompt and quality gate own accuracy; publishers keep model prose."""
    pub = source("revai/publish_report_v2.py")
    sec = source("revai/section_publisher.py")
    for publisher in (pub, sec):
        assert "scrub_dynamic_execution_claims" not in publisher
        assert "dynamic_claim_scrub" not in publisher


def test_v3_dynamic_status_is_injected_into_every_authored_technical_section(monkeypatch):
    sentinel = "STATUS SENTINEL: WinRE sample launch confirmed; 577 events; pcap present."
    captured = []

    def fake_llm(prompt):
        captured.append(prompt)
        return _report_tool_response(
            "## Section\n\nEvidence-grounded section.")

    monkeypatch.setattr(SP, "_dynamic_status_sentence", lambda sha: sentinel)
    monkeypatch.setattr(SP, "llm_report", fake_llm)
    monkeypatch.setattr(SP, "llm_call_metadata", lambda response: {})
    monkeypatch.setattr(SP, "get_llm_model", lambda: "configured-llm")

    for name in SP.TECHNICAL_SECTION_DESCRIPTIONS:
        if name == "8. Indicators of Compromise":
            # This section is rendered deterministically from iocs.json and
            # does not make model-authored execution claims.
            continue
        if name == "5. Behavioral & Dynamic Analysis":
            # Evidence-conditioned (RC-27): with no detonation on record this
            # section renders deterministically and authors nothing; its own
            # two-direction coverage lives in
            # test_conditional_dynamic_section.py.
            continue
        result = SP._generate_technical_section(name, [], "context", "a" * 64)
        assert result["llm_ok"], result
        assert result["markdown"].startswith(f"## {name}")
        assert "Evidence-grounded section." in result["markdown"]
        assert sentinel in captured[-1]


def test_gate_does_not_fire_on_a_static_hook_candidate():
    """The original mislabel: a STATIC 'hook candidate identified' on a failed
    oracle must not be read as dynamic evidence."""
    st = {"any_dynamic_performed": False,
          "sentence": "emulation NOT performed"}
    tech = "We report the probe as completed and a hook candidate identified."
    master = "No dynamic or sandbox analysis was performed; all findings are static."
    c = RQ._cross_report_consistency(master, tech, "", None, st)
    assert not any("master_claims_no_dynamic" in v for v in c["violations"]), \
        "the old backwards mislabel must be gone"
    # And neither the static hook candidate nor a plain negation is a
    # fabrication of execution.
    assert not any("dynamic_execution_claimed" in v for v in c["violations"]), \
        c["violations"]


def test_gate_flags_a_flat_negation_when_dynamic_did_run():
    st = {"any_dynamic_performed": True, "sentence": "emulation produced a trace"}
    c = RQ._cross_report_consistency("No dynamic analysis was performed.", "",
                                     "", None, st)
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_flags_report_that_omits_recorded_winre_run_and_capture():
    st = {
        "any_dynamic_performed": True,
        "sentence": "WinRE detonation: sample launch confirmed; WinRE Frida "
                    "runtime: runtime events captured (577); packet capture: "
                    "1 capture file(s) present.",
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "No sandbox execution, no network capture, no registry monitoring, "
        "no credential-access monitoring, no process-tree tracing was "
        "performed for this sample."
    )
    c = RQ._cross_report_consistency("", "", report, None, st)
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


# ------------------------------------------------------------- scope-aware checks
def test_full_master_prompt_receives_component_status_and_winre_evidence():
    prompt = PR.build_prompt_full(
        {"sha256": "a" * 64, "sample_path": "sample.exe"},
        verdict=None, deep=None, yara_meta=None, audit=[],
        dynamic_status={
            "sentence": "WinRE detonation: sample launch confirmed; "
                        "Frida runtime: runtime events captured (577).",
            "frida_static_probe": {"state": "static-only"},
        },
        dynamic_evidence="## Dynamic Analysis (WinRE detonation)\n- events: 577",
    )
    assert "authoritative execution status" in prompt
    assert "candidate hooks" in prompt
    assert "sample launch confirmed" in prompt
    assert "WinRE runtime record" in prompt
    assert "events: 577" in prompt


def test_gate_catches_winre_contradictions_even_if_other_section_has_caveat():
    st = {
        "any_dynamic_performed": True,
        "emulation": {"ok": False},
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True,
                           "trace_artifact_present": True, "events": 577},
        "packet_capture": {"present": True},
    }
    master = (
        "No dynamic-analysis tool (Speakeasy, Frida, sandbox VM) was invoked.\n"
        "No Speakeasy or Frida dynamic-instrumentation trace is present.\n"
        "No network traffic capture (pcap) was collected.\n"
        "Coverage is window-bounded and delayed behavior may be missed."
    )
    c = RQ._cross_report_consistency(master, "", "", None, st)
    assert not c["ok"]
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_allows_absent_speakeasy_when_winre_ran():
    st = {
        "any_dynamic_performed": True,
        "emulation": {"ok": False},
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True,
                           "trace_artifact_present": True, "events": 577},
        "packet_capture": {"present": True},
    }
    report = (
        "No RevAI Speakeasy emulation was performed. The RevAI Frida static "
        "probe is static-only. WinRE detonation ran and its Frida trace "
        "recorded 577 events."
    )
    c = RQ._cross_report_consistency(report, "", "", None, st)
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]


def test_gate_allows_explanation_that_static_probe_absence_does_not_mean_no_dynamic():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True,
                           "trace_artifact_present": True, "events": 577},
        "packet_capture": {"present": True},
    }
    report = (
        "No execution is proven by this component. (source: execution_status, "
        "query_or_table: frida_static_probe, row_or_rule: execution_proven=false, "
        'state="static candidate analysis only", why: the absence of execution '
        "here does not mean no dynamic analysis was performed; WinRE and Frida "
        "runtime are separate paths.)"
    )
    c = RQ._cross_report_consistency("", "", report, None, st)
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]


def test_gate_allows_evidence_limited_dynamic_claim_with_winre_and_capture():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True,
                           "trace_artifact_present": True, "events": 639},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "No dynamic behaviour has been asserted beyond what the WinRE "
        "detonation and packet capture recorded."
    )

    c = RQ._cross_report_consistency(report, "", "", None, st)

    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]

    # Scope limits must not be mistaken for a denial that dynamic analysis ran.
    limited = RQ._cross_report_consistency(
        "No behavior beyond captured evidence is asserted.", "", "", None, st
    )
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in limited["violations"]), limited["violations"]


def test_gate_allows_double_negative_for_completed_dynamic_paths():
    st = {
        "any_dynamic_performed": True,
        "emulation": {"ok": True},
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "No dynamic analysis was skipped: all four runtime paths (emulation, "
        "Frida static probe, Frida runtime, WinRE detonation) were available "
        "and executed."
    )
    c = RQ._cross_report_consistency(report, "", "", None, st)
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]


def test_double_negative_does_not_hide_a_later_dynamic_denial():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
    }
    report = (
        "No dynamic analysis was skipped: all four paths ran, but no WinRE "
        "detonation was performed."
    )
    c = RQ._cross_report_consistency(report, "", "", None, st)
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_still_rejects_direct_winre_and_capture_denials():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 639},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "No WinRE detonation was performed. No network traffic capture "
        "(pcap) was collected."
    )

    c = RQ._cross_report_consistency(report, "", "", None, st)

    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_still_catches_real_contradiction_after_meta_negated_clause():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
    }
    report = (
        "The static probe's absence does not mean no dynamic analysis was "
        "performed; WinRE and Frida runtime are separate paths, but no WinRE "
        "detonation was performed."
    )
    c = RQ._cross_report_consistency("", "", report, None, st)
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_allows_frida_absence_scoped_to_static_probe_when_winre_ran():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "Because the probe was explicitly marked static-only, no Frida "
        "instrumentation was attached to a live process and no runtime events "
        "were captured by this component. Any Frida-derived runtime data in "
        "this report comes exclusively from the WinRE detonation path."
    )
    c = RQ._cross_report_consistency("", "", report, None, st)
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]


def test_gate_allows_frida_static_probe_absence_in_following_sentence():
    st = {
        "any_dynamic_performed": True,
        "emulation": {"ok": True},
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 133},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "The Frida probe component operated in static-only mode and did not "
        "execute the sample. No Frida-instrumented execution trace or hook "
        "output is recorded for this probe."
    )

    c = RQ._cross_report_consistency("", "", report, None, st)

    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]


def test_gate_allows_frida_table_row_scoped_to_probe_path_when_winre_ran():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
    }
    report = (
        "| RevAI Frida probe | Static-only; sample not executed | "
        "No runtime events from this path. |"
    )
    c = RQ._cross_report_consistency("", "", report, None, st)
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]


def test_gate_does_not_join_dynamic_claims_across_markdown_table_cells():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 286},
    }
    report = (
        "| RevAI Frida probe | Static-only, no execution | "
        "DYNAMIC-ANALYSIS STATUS | Re-run in exec mode or use WinRE trace |"
    )
    c = RQ._cross_report_consistency(report, "", "", None, st)
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]

    # Keep a real denial in one cell gated; only cross-cell inference is invalid.
    denied = "| Dynamic analysis | No dynamic analysis was performed |"
    c = RQ._cross_report_consistency(denied, "", "", None, st)
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_understands_explicit_double_negation_of_dynamic_absence():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
    }
    report = (
        "WinRE captured runtime behavior; it is not the case that no dynamic "
        "analysis was performed in this run."
    )
    result = RQ._cross_report_consistency(report, "", "", None, st)
    assert not any("dynamic_performed_but_report_says_none" in violation
                   for violation in result["violations"]), result


def test_gate_allows_inner_pe_dynamic_gap_when_outer_sample_ran():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 577},
    }
    report = (
        "The embedded 34 KB PE was not extracted by this pass. No subsequent "
        "dynamic execution of the inner PE is therefore available in this run."
    )
    c = RQ._cross_report_consistency("", "", report, None, st)
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in c["violations"]), c["violations"]


def test_inner_pe_gap_exemption_does_not_hide_blanket_dynamic_denial():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
    }
    report = (
        "No subsequent dynamic execution of the inner PE is available in this "
        "run, but no dynamic analysis of the sample was performed."
    )
    c = RQ._cross_report_consistency("", "", report, None, st)
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_rejects_zero_frida_event_claim_when_runtime_events_exist():
    st = {
        "any_dynamic_performed": True,
        "emulation": {"ok": False},
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True,
                           "trace_artifact_present": True, "events": 577},
        "packet_capture": {"present": True},
    }
    report = (
        "Dynamic analysis was performed in this triage (Speakeasy emulation "
        "and Frida probing ran); both tools recorded zero runtime events. "
        "Neither Speakeasy nor Frida was executed on this sample."
    )
    c = RQ._cross_report_consistency(report, "", "", None, st)
    assert any("dynamic_performed_but_report_says_none" in v
               for v in c["violations"]), c["violations"]


def test_gate_allows_absence_of_one_api_event_after_positive_runtime_count():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True,
                           "trace_artifact_present": True, "events": 133},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "The WinRE Frida runtime captured 133 events, but no event "
        "corresponded to a socket call."
    )

    result = RQ._cross_report_consistency("", "", report, None, st)

    assert not any("dynamic_performed_but_report_says_none" in violation
                   for violation in result["violations"]), result


def test_gate_ignores_dynamic_words_inside_a_citation_locator():
    st = {
        "any_dynamic_performed": True,
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "events": 133},
        "packet_capture": {"present": True, "files": 1},
    }
    report = (
        "Because the WinRE Frida runtime captured 133 events and one packet-"
        "capture file is present, we cannot assert that the sample produced no "
        "runtime behaviour (source: dynamic-analysis-status, "
        "query_or_table: run-scoped status block, row_or_rule: "
        "\"WinRE Frida runtime: runtime events captured (133)\"; "
        "\"packet capture: 1 capture file(s) present\")."
    )

    result = RQ._cross_report_consistency("", "", report, None, st)

    assert not any("dynamic_performed_but_report_says_none" in violation
                   for violation in result["violations"]), result


# ------------------------------------------------------------- section injection
def test_the_dynamic_section_prompt_carries_the_status(monkeypatch):
    """The section prompt must receive the authoritative status line, so the
    model states it rather than inferring execution from tool names.

    This is the source-layer fix: without it the model had to decide whether
    the oracle 'ran' and got it wrong.
    """
    captured = {}

    def fake_judge(prompt, **kw):
        captured["prompt"] = prompt
        return _report_tool_response("m")

    monkeypatch.setattr(SP, "llm_report", fake_judge)
    monkeypatch.setattr(
        SP, "_dynamic_status_sentence",
        lambda sha: "Dynamic analysis in this run -- emulation NOT performed; "
                    "Frida: not performed; WinRE detonation: not performed.")
    result = SP._run_one_section("5. Behavioral Analysis", "ab", {}, {})
    assert "DYNAMIC-ANALYSIS STATUS" in captured["prompt"], (
        "the authoritative status was not injected into the section prompt")
    assert "emulation NOT performed" in captured["prompt"]
    assert result["markdown"].startswith("## 5. Behavioral Analysis")
    assert "- m " in result["markdown"]
    assert "source: test" in result["markdown"]


def test_the_dynamic_status_is_injected_into_every_master_section(monkeypatch):
    """A filtered section must not mistake omitted evidence for run absence."""
    captured = {}

    def fake_judge(prompt, **kw):
        captured["prompt"] = prompt
        return _report_tool_response("m")

    monkeypatch.setattr(SP, "llm_report", fake_judge)
    monkeypatch.setattr(SP, "_dynamic_status_sentence", lambda sha: "STATUS")
    SP._run_one_section("4. Static Analysis", "ab", {}, {})
    assert "DYNAMIC-ANALYSIS STATUS (authoritative" in captured.get("prompt", "")
    assert "STATUS (source: dynamic_analysis_status" in captured.get("prompt", "")


def test_master_v3_dynamic_consistency_checks_the_master_v3_report():
    status = {
        "any_dynamic_performed": False,
        "sentence": "WinRE detonation: sample did not launch",
    }
    report = "Dynamic analysis was performed during this run."

    result = RQ._cross_report_consistency(
        "", "", "", None, status, master_v3_md=report,
    )

    assert any(
        "dynamic_execution_claimed_but_none_performed" in violation
        for violation in result["violations"]
    ), result
