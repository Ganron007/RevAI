"""Verdict calibration must read EVIDENCE, not the agent's own vocabulary.

ghyte.exe (a59b2cb9) returned `malicious`/70 on packer-only evidence --
Safeguard/ZProtect YARA, a 24-import GUI-only table, every examined behavioural
domain "not observed". The calibration CEILING should have demoted it to
`suspicious` and did not. Three separate over-matches, all the same class:

  1. `lg_api_lookup_24/28/39` -- the agent looked up what CreateRemoteThread,
     WriteProcessMemory, VirtualAllocEx, "run key" and "startup" MEAN. Those
     definitions satisfied the intent scan.
  2. `history_tools` -- the tool history contains the literal `domain:persistence`,
     so the NAME of the tool that investigated persistence was read as the
     capability being present.
  3. The negation guard looked only BACKWARD, but the deep dive writes
     "Persistence: not observed" -- the negation comes AFTER the signal.

Each is pinned below, together with the cases that must still be detected.
"""
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib as v  # noqa: E402

SIG = ["persistence", "process injection", "createremotethread", "run key"]


# ------------------------------------------------------- 1. lookup definitions
def test_an_api_lookup_definition_is_not_behavioural_intent():
    findings = {
        "lg_api_lookup_24": "CreateRemoteThread: creates a thread that runs in "
                            "the virtual address space of another process...",
        "lg_api_lookup_28": "run key: a registry persistence location under "
                            "CurrentVersion\\Run",
        "real_finding": "24 imports, all GUI/window-management",
    }
    ev = v.calibration_evidence_text("", [], findings, ["ghidra_query"])
    hits = v._signal_hits(ev.lower(), SIG)
    assert not hits, f"a lookup definition satisfied the intent gate: {hits}"


def test_a_real_finding_still_supplies_intent():
    findings = {"imports": "CreateRemoteThread, WriteProcessMemory, VirtualAllocEx"}
    ev = v.calibration_evidence_text("", [], findings, [])
    assert v._signal_hits(ev.lower(), SIG), (
        "excluding lookups must not blind the gate to real evidence")


# ------------------------------------------------------------ 2. tool history
def test_the_tool_history_is_not_evidence():
    """`domain:persistence` is the name of what investigated persistence."""
    ev = v.calibration_evidence_text("", [], {"a": 1},
                                     ["ghidra_query", "domain:persistence",
                                      "domain:c2_network"])
    assert "domain:persistence" not in ev, (
        "the tool history reached the calibration gate")
    assert not v._signal_hits(ev.lower(), SIG)


# ------------------------------------------------------- 3. forward negation
@pytest.mark.parametrize("text,expect", [
    ("Persistence: not observed - no registry Run-key mutations", False),
    ("C2/network communication: not observed", False),
    ("Exfiltration: not observed - no upload paths", False),
    ("Credential access: not observed", False),
    ("no persistence was observed", False),
    ("persistence was observed via an HKCU Run key", True),
    ("the sample writes a run key for persistence", True),
    ("CreateRemoteThread is imported and used for injection", True),
])
def test_negation_is_detected_on_both_sides(text, expect):
    assert bool(v._signal_hits(text, SIG)) is expect, text


def test_the_forward_negation_is_narrow():
    """A negation much later in the sentence must not swallow a real signal."""
    text = ("persistence is established through a run key. No other "
            "persistence was observed.")
    assert v._signal_hits(text, SIG), (
        "a real intent signal was dismissed by a distant negation")


# --------------------------------------------------------- the whole gate
def test_a_packer_only_sample_is_demoted_to_suspicious():
    """The ghyte case, end to end through calibrate_verdict."""
    verdict = {"verdict": "malicious", "confidence": 70,
               "summary": "Safeguard/ZProtect packed stub. Persistence: not "
                          "observed. Exfiltration: not observed. Evasion: "
                          "observed (packer).",
               "key_evidence": ["yara: Safeguard_103_Simonzh",
                                "24 imports, all GUI-centric"]}
    ev = v.calibration_evidence_text(
        verdict["summary"], verdict["key_evidence"],
        {"lg_api_lookup_39": "CreateRemoteThread definition",
         "domain:persistence": "not observed"}, ["domain:persistence"])
    out = v.calibrate_verdict(dict(verdict), ev)
    assert out["verdict"] == "suspicious", out
    assert out.get("verdict_calibrated") is True


def test_a_sample_with_real_intent_stays_malicious():
    """The ceiling must not become a floor-dropper."""
    verdict = {"verdict": "malicious", "confidence": 85,
               "summary": "Writes an HKCU Run key and injects via "
                          "CreateRemoteThread.",
               "key_evidence": ["imports: CreateRemoteThread, "
                                "WriteProcessMemory"]}
    ev = v.calibration_evidence_text(
        verdict["summary"], verdict["key_evidence"], {}, [])
    out = v.calibrate_verdict(dict(verdict), ev)
    assert out["verdict"] == "malicious", out
