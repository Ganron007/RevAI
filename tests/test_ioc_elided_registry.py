#!/usr/bin/env python3
"""Abbreviated registry paths in report prose are not indicator claims.

`HKCU\\...\\Run` is analyst shorthand naming a *mechanism*, not a single
location, so it can never match raw tool evidence verbatim. The canonical-run
template exemption only ever matched the fully written-out path, so every
elided path fell through to the verbatim comparison and was reported
unverified. That is what put `report:unverified_iocs` on two real audits:

    winservices  unverified=2  HKCU\\...\\Run, HKEY_CURRENT_USER\\...\\Run
    win32k_dll   unverified=7  same shape

Both samples genuinely write Run keys; the report simply abbreviated them in
prose while the deterministic IoC section (rendered from data) held the concrete
paths.

The fix is not to exempt elisions -- that would let any hand-waved
"HKCU\\...\\Whatever" pass unchallenged. It is to *resolve* them: an elided path
counts as verified when the evidence contains a concrete path under the same
hive whose trailing subkey matches. That is a stricter test than skipping, and
an elided path with nothing corresponding to it still lands in `unverified`.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import report_quality as rq  # noqa: E402

# The evidence as the tool records it: a real Run-key write with full path.
# Single backslashes, as JSON escapes them -- an earlier fixture used doubled
# ones and tested a string that appears in no real artifact.
EVIDENCE = (
    '{\n'
    '  "artifacts": [\n'
    '    {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",\n'
    '     "value": "C:\\Users\\Public\\svc.exe"},\n'
    '    {"path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",\n'
    '     "value": "rundll32"},\n'
    '    {"url": "http://c2.example.net/gate.php"}\n'
    '  ]\n'
    '}'
)


def _run(md: str, evidence: str = EVIDENCE):
    out = rq.verify_claimed_iocs(md, evidence)
    return out, {(i["type"], i["value"]): i for i in out.get("unverified_items", [])}


# ---------------------------------------------------------------- the real cases

def test_abbreviated_run_key_is_resolved_not_flagged():
    """The exact claim that reddened two audits."""
    out, unverified = _run(
        "Persistence is established by a Run-key write at `HKCU\\...\\Run`.")
    assert ("registry_key", "HKCU\\...\\Run") not in unverified, unverified
    assert out["unverified"] == 0, out


def test_long_form_hive_alias_resolves_too():
    """HKEY_CURRENT_USER and HKCU name the same location."""
    out, unverified = _run(
        "The sample writes `HKEY_CURRENT_USER\\...\\Run` on start-up.")
    assert out["unverified"] == 0, out
    assert ("registry_key", "HKEY_CURRENT_USER\\...\\Run") not in unverified


def test_resolution_records_the_concrete_path_it_referred_to():
    """The substitution must be auditable, or 'verified' is unfalsifiable."""
    out = rq.verify_claimed_iocs(
        "Persistence via `HKCU\\...\\Run`.", EVIDENCE)
    resolved = out.get("resolved_abbreviations") or []
    assert resolved, out
    assert resolved[0]["value"] == "HKCU\\...\\Run", resolved
    assert resolved[0]["abbreviated_from"] == \
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", resolved[0]
    assert out["verified"] == 1 and out["unverified"] == 0, out


def test_runonce_claim_resolves_to_the_runonce_path():
    out = rq.verify_claimed_iocs(
        "A `HKLM\\...\\RunOnce` entry is created.", EVIDENCE)
    assert out["unverified"] == 0, out
    assert out["resolved_abbreviations"][0]["abbreviated_from"] == \
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", out


def test_runonce_does_not_absorb_a_plain_run_path():
    """The trailing subkey has to match exactly, not by prefix."""
    # Evidence has HKCU\...\Run but the report claims HKCU\...\RunOnce.
    out = rq.verify_claimed_iocs(
        "A `HKCU\\...\\RunOnce` entry is created.", EVIDENCE)
    assert out["unverified"] == 1, out
    assert out["resolved_abbreviations"] == [], out


def test_unicode_ellipsis_form_is_recognised():
    out = rq.verify_claimed_iocs("Persistence at `HKCU\\…\\Run`.", EVIDENCE)
    assert out["unverified"] == 0, out


# ------------------------------------------------------ must still be strict

def test_abbreviation_with_nothing_in_evidence_stays_unverified():
    """Skipping elisions would let any hand-wave through. This must not."""
    out, unverified = _run(
        "Persistence via `HKCU\\...\\Run`.",
        evidence='{"artifacts": [{"url": "http://c2.example.net/x"}]}')
    assert out["unverified"] == 1, out
    key = ("registry_key", "HKCU\\...\\Run")
    assert key in unverified, out
    assert "abbreviated" in unverified[key]["reason"], unverified[key]


def test_wrong_hive_does_not_ground():
    """A Run key under HKLM does not verify a claim about HKCU."""
    out = rq.verify_claimed_iocs(
        "Persistence via `HKCU\\...\\Run`.",
        evidence_text=r'{"p": "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"}')
    assert out["unverified"] == 1, out


def test_mismatched_subkey_does_not_ground():
    out = rq.verify_claimed_iocs(
        "Persistence via `HKCU\\...\\Services`.",
        evidence_text=r'{"p": "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"}')
    assert out["unverified"] == 1, out


def test_deeper_concrete_path_wins_over_a_shallow_one():
    """Prefer the most specific match so the finding is informative."""
    evidence = (r'{"a": "HKCU\Run"}'
                r'{"b": "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"}')
    out = rq.verify_claimed_iocs("Persistence via `HKCU\\...\\Run`.", evidence)
    hit = out["resolved_abbreviations"]
    assert hit[0]["abbreviated_from"] == \
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", hit[0]


# -------------------------------------------------- existing behaviour intact

def test_concrete_path_still_verifies_by_verbatim_match():
    out = rq.verify_claimed_iocs(
        r"Writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.",
        EVIDENCE)
    assert out["unverified"] == 0, out


def test_fabricated_concrete_path_is_still_unverified():
    out = rq.verify_claimed_iocs(
        r"Writes `HKCU\Software\EvilCorp\Backdoor`.", EVIDENCE)
    assert out["unverified"] == 1, out


def test_resolved_path_keeps_evidence_casing():
    """The audit trail must read like the evidence it points at."""
    out = rq.verify_claimed_iocs("Persistence via `HKCU\\...\\Run`.", EVIDENCE)
    resolved = out["resolved_abbreviations"][0]["abbreviated_from"]
    assert resolved.startswith("HKCU\\Software"), resolved
    assert resolved == resolved.strip("."), resolved


def test_hive_plus_one_subkey_is_still_excluded_as_generic():
    """`HKEY_CURRENT_USER\\Run` is a hive plus one segment, not a path."""
    out = rq.verify_claimed_iocs(
        "Registry hive `HKEY_CURRENT_USER\\Run` used.", EVIDENCE)
    assert out["unverified"] == 0, out
    excl = {e["value"] for e in out.get("excluded_items", [])}
    assert "HKEY_CURRENT_USER\\Run" in excl, out


def test_bare_hive_name_is_not_a_claim_at_all():
    """No backslash, so the claim regex never matches: nothing to judge."""
    out = rq.verify_claimed_iocs(
        "Registry hive `HKEY_CURRENT_USER` used.", EVIDENCE)
    assert out["claims"] == 0, out
    assert out["unverified"] == 0, out


def test_url_claims_are_unaffected():
    out = rq.verify_claimed_iocs("C2 at http://c2.example.net/gate.php", EVIDENCE)
    assert out["unverified"] == 0, out


def test_elided_helper_rejects_non_registry_text():
    assert rq._ground_elided_regkey("not a registry path", EVIDENCE) is None
    assert rq._regkey_parts("nopath") is None


def test_empty_evidence_grounds_nothing():
    out = rq.verify_claimed_iocs("Persistence via `HKCU\\...\\Run`.", "")
    assert out["unverified"] == 1, out