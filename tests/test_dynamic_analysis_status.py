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
from _layout import resolve  # noqa: E402

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
