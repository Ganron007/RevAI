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


# ------------------------------------------------------------- the status helper
def test_status_reports_a_failed_oracle_as_not_performed(tmp_path, monkeypatch):
    """The .NET case: oracle present but ok=False."""
    case = tmp_path / "logs" / "ab" / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "03-oracle.json").write_text(
        json.dumps({"ok": False, "engine": "emulation_oracle",
                    "error": "SpeakeasyError: Emulator not initialized"}),
        encoding="utf-8")
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))
    st = v2_lib.dynamic_analysis_status("ab", logs_dir=tmp_path / "logs")
    assert st["any_dynamic_performed"] is False
    assert "NOT performed" in st["emulation"]["state"]
    assert "not performed" in st["sentence"].lower()


def test_status_reports_a_successful_oracle(tmp_path, monkeypatch):
    case = tmp_path / "logs" / "cd" / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "03-oracle.json").write_text(
        json.dumps({"ok": True, "engine": "emulation_oracle"}),
        encoding="utf-8")
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))
    st = v2_lib.dynamic_analysis_status("cd", logs_dir=tmp_path / "logs")
    assert st["any_dynamic_performed"] is True
    assert "produced a trace" in st["emulation"]["state"]


def test_status_with_no_oracle_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path / "nowhere"))
    st = v2_lib.dynamic_analysis_status("zz", logs_dir=tmp_path / "logs")
    assert st["emulation"]["present"] is False
    assert st["any_dynamic_performed"] is False


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


# ------------------------------------------------- dynamic-claim scrubber
def test_scrub_replaces_the_fabricated_claim_and_keeps_the_truth():
    """The measured defect: the model narrates a static probe's availability +
    hook candidates as a runtime execution. The scrub replaces the SENTENCE
    with the run's ground truth and records exactly what was removed."""
    md = (
        "Frida instrumentation was not performed, so no runtime API hooking "
        "occurred.\n"
        "Frida instrumentation probe was configured for the analysis "
        "environment, with results as follows: the hook fired twice.\n"
        "The sample imports CreateProcessW, which is consistent with "
        "injection."
    )
    out, meta = RQ.scrub_dynamic_execution_claims(
        Path("/opt/samples/logs/abc123/agentic"), md, "technical_v3")
    assert meta["claims_removed"] == 1, meta
    assert "the hook fired twice" not in out, out
    assert "Frida instrumentation was not performed, so no runtime API hooking" in out, (
        "the truthful sentence must survive the scrub")
    assert "No dynamic analysis was performed in this run" in out, out
    assert meta["removals"][0]["ground_truth"], meta
    assert "CreateProcessW" in out


def test_scrub_leaves_a_truthful_report_unchanged():
    md = ("Frida instrumentation was not performed, and WinRE detonation was "
          "not run, so no network traffic was observed.")
    out, meta = RQ.scrub_dynamic_execution_claims(
        Path("/opt/samples/logs/abc123/agentic"), md, "technical_v3")
    assert out == md
    assert meta["claims_removed"] == 0


def test_scrub_is_inert_when_dynamic_did_run(monkeypatch):
    """Only the 'claimed but none performed' direction is scrubbed; a report
    that understates a real dynamic run is the gate's contradiction to
    report, not a sentence to rewrite."""
    monkeypatch.setattr(v2_lib, "dynamic_analysis_status",
                        lambda sha, **kw: {"any_dynamic_performed": True,
                                           "sentence": "emulation ran"})
    md = "The dynamic runs executed successfully during triage."
    out, meta = RQ.scrub_dynamic_execution_claims(
        Path("/opt/samples/logs/abc123/agentic"), md, "technical_v3")
    assert out == md
    assert meta.get("applicable") is False


def test_scrub_is_idempotent():
    """The replacement sentence must not itself read as a claim, or a second
    publish pass would 'fix' the fix."""
    md = ("Frida instrumentation probe was configured for the analysis "
          "environment, with results as follows: the hook fired twice.")
    case = Path("/opt/samples/logs/abc123/agentic")
    once, _ = RQ.scrub_dynamic_execution_claims(case, md, "technical_v3")
    twice, meta2 = RQ.scrub_dynamic_execution_claims(case, once, "technical_v3")
    assert twice == once
    assert meta2["claims_removed"] == 0


def test_scrub_handles_two_claims_without_double_replacing():
    """Two claims in ONE sentence: one replacement, not two overlapping ones
    leaving half a sentence behind."""
    md = ("Frida instrumentation was invoked and the sandbox execution "
          "completed, recording twelve API calls. Static findings follow.")
    out, meta = RQ.scrub_dynamic_execution_claims(
        Path("/opt/samples/logs/abc123/agentic"), md, "technical_v3")
    assert meta["claims_removed"] == 1, meta
    assert "Static findings follow." in out
    assert "twelve API calls" not in out


def test_the_scrub_is_wired_and_recorded_at_every_publish_site():
    """The NameError class, pinned.

    The msil agentic re-run (2026-10-13) crashed in section_publisher: the
    master_v3 call site assigned its record to `report[...]` -- a variable
    that does not exist in that scope (the record belongs in
    section-results-v3.json, the e879318 lesson: a scrub record assigned and
    read nowhere is a lost tripwire). py_compile passes on that; only a
    source-shape pin catches it. All four call sites must both call the
    scrubber AND persist the record.
    """
    pub = source("revai/publish_report_v2.py")
    assert 'scrub_dynamic_execution_claims(case, md, "master_v2")' in pub
    assert 'report["dynamic_claim_scrub"] = _dyn_scrub' in pub
    assert 'scrub_dynamic_execution_claims(\n            case, tech_md, "technical_v2")' in pub
    assert 'technical_report["dynamic_claim_scrub"] = _tech_dyn_scrub' in pub
    sec = source("revai/section_publisher.py")
    assert 'scrub_dynamic_execution_claims(\n        case_dir(sha), report_markdown, "master_v3")' in sec
    # master_v3's record is persisted into section-results-v3.json -- there is
    # no `report` variable in that scope, and assigning to one crashed the
    # publisher mid-run.
    assert '"master_v3_dynamic_claim_scrub": _master_dyn_scrub' in sec
    assert "report[" not in sec.split("master_v3")[1].split("redact_model_names")[0], (
        "the master_v3 site must not assign to an undefined `report` variable")
    assert 'scrub_dynamic_execution_claims(\n        case_dir(sha), tech_md, "technical_v3")' in sec
    assert 'technical_report["dynamic_claim_scrub"] = _tech_dyn_scrub' in sec


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
        return {"choices": [{"message": {"content": json.dumps(
            {"title": "t", "markdown": "m"})}}]}

    monkeypatch.setattr(SP, "llm_judge", fake_judge)
    monkeypatch.setattr(
        SP, "_dynamic_status_sentence",
        lambda sha: "Dynamic analysis in this run -- emulation NOT performed; "
                    "Frida: not performed; WinRE detonation: not performed.")
    SP._run_one_section("5. Behavioral Analysis", "ab", {}, {})
    assert "DYNAMIC-ANALYSIS STATUS" in captured["prompt"], (
        "the authoritative status was not injected into the section prompt")
    assert "emulation NOT performed" in captured["prompt"]


def test_the_dynamic_status_is_not_injected_into_other_sections(monkeypatch):
    """The injection is scoped to the dynamic section only."""
    captured = {}

    def fake_judge(prompt, **kw):
        captured["prompt"] = prompt
        return {"choices": [{"message": {"content": json.dumps(
            {"title": "t", "markdown": "m"})}}]}

    monkeypatch.setattr(SP, "llm_judge", fake_judge)
    monkeypatch.setattr(SP, "_dynamic_status_sentence", lambda sha: "STATUS")
    SP._run_one_section("4. Static Analysis", "ab", {}, {})
    # The shared prompt always instructs the author to state the status line;
    # what must NOT be present is the INJECTED block carrying the value.
    assert "DYNAMIC-ANALYSIS STATUS (authoritative" not in captured.get("prompt", "")
