#!/usr/bin/env python3
"""Two defects in the registry-path evidence extractor, found one from the other.

Both were reproduced before being fixed. They matter because the extractor is
what decides whether a report's registry claim is grounded: a candidate that
cannot be found makes a real key look unobserved, and a candidate that swallows
its neighbours makes evidence appear to be something it is not.

1. The evidence-side regex could match ACROSS newlines.

   The `Windows NT` space rule used `\\s+`, which matches newlines. So given a
   three-line evidence blob the regex produced ONE candidate spanning all of it,
   with subkeys like ``'run\\nhkey_local_machine'`` -- meaning no single-line
   candidate was ever produced and every real key failed to match. Reproduced:

       MERGED 'HKEY_LOCAL_MACHINE\\SYSTEM\\...\\Interface\\nHKEY_CURRENT_USER\\
               Software\\...\\Run\\nHKEY_LOCAL_MACHINE\\SOFTWARE\\...\\Winlogon'

   Now `[ \\t]+`, so a newline always terminates a path.

2. Elided grounding matched on ONE shared segment.

   `HKLM\\...\\Services\\MyDriver\\Parameters` was "verified" against
   `HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interface`
   because `Parameters` appears in both. `Parameters`, `Services`, `Run` and
   `Shell` are exactly the leaves an LLM reaches for when reconstructing a path
   from training data, so the loose rule turned fabrication into GREEN -- and a
   gate certifying an invented path is worse than one failing to ground it.

   Every named segment must now appear in the candidate, in the order written.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import add_module_dir  # noqa: E402

add_module_dir("revai/report_quality.py")

import report_quality as rq  # noqa: E402

#: Three real keys, one per line - the shape an evidence blob actually has.
EVIDENCE = (
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interface"
    "\n"
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
    "\n"
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)


# ---------------------------------------------------------------- 1. newlines

def test_a_registry_candidate_never_spans_a_newline():
    """The bug: one match swallowed the whole evidence blob."""
    cands = [m.group(0) for m in rq._EVIDENCE_REGKEY_RE.finditer(EVIDENCE)]
    assert cands, "no candidates found at all"
    for c in cands:
        assert "\n" not in c, f"candidate spans a newline: {c!r}"
    assert len(cands) == 3, cands


def test_each_key_is_found_independently():
    cands = [m.group(0).lower() for m in rq._EVIDENCE_REGKEY_RE.finditer(EVIDENCE)]
    joined = "|".join(cands)
    for want in ("currentcontrolset", "currentversion\\run",
                 "windows nt\\currentversion\\winlogon"):
        assert want in joined, f"{want} not in {joined}"


def test_windows_nt_is_still_one_path():
    """The space rule exists for this; restricting it must not lose it."""
    cands = [m.group(0) for m in rq._EVIDENCE_REGKEY_RE.finditer(EVIDENCE)]
    assert any("Windows NT\\CurrentVersion\\Winlogon" in c for c in cands), cands


def test_a_grounded_elision_is_found_through_the_regex():
    """With the merge fixed, `HKCU\\...\\Run` finally grounds its own observation."""
    got = rq._ground_elided_regkey(r"HKCU\...\Run".lower(), EVIDENCE.lower())
    assert got, "the Run abbreviation no longer grounds a real observation"
    assert got.endswith("\\run"), got


# ------------------------------------------------- 2. one shared leaf is not enough

def test_a_fabricated_path_is_not_grounded_by_one_shared_segment():
    """`Parameters` appears in both; `MyDriver` appears in neither."""
    got = rq._ground_elided_regkey(
        r"HKLM\...\Services\MyDriver\Parameters".lower(), EVIDENCE.lower())
    assert got is None, f"grounded a fabricated path via: {got}"


def test_a_fabricated_run_key_is_not_grounded_by_the_real_one():
    """`HKCU\\...\\Policies\\Explorer\\Run` vs the real `...\\CurrentVersion\\Run`."""
    got = rq._ground_elided_regkey(
        r"HKCU\...\Policies\Explorer\Run".lower(), EVIDENCE.lower())
    assert got is None, f"grounded a fabricated path via: {got}"


def test_a_multi_segment_abbreviation_still_grounds():
    got = rq._ground_elided_regkey(
        r"HKLM\...\CurrentControlSet\Services\Tcpip\Parameters".lower(),
        EVIDENCE.lower())
    assert got and got.lower().endswith("parameters\\interface"), got


def test_fabricated_claims_reach_unverified_not_verified():
    """The point of the whole exercise: the gate must see them."""
    md = ("Run keys `HKLM\\...\\Services\\MyDriver\\Parameters` are set; "
          "`HKCU\\...\\Policies\\Explorer\\Run` writes policy.")
    out = rq.verify_claimed_iocs(md, EVIDENCE)
    unver = [i.get("value") for i in out["unverified_items"]]
    assert any("MyDriver" in v for v in unver), out["unverified_items"]
    assert any("Policies" in v for v in unver), out["unverified_items"]
    assert out["unverified"] >= 2, out


def test_the_hive_must_match():
    """A HKCU claim cannot be grounded by an HKLM observation."""
    got = rq._ground_elided_regkey(
        r"HKCU\...\CurrentControlSet\Services\Tcpip\Parameters".lower(),
        EVIDENCE.lower())
    assert got is None, got