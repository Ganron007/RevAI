#!/usr/bin/env python3
"""A registry path named in defender guidance is not an indicator claim.

After resolving elided paths, one unverified claim survived on each real audit.
Both were the same thing -- a location the report tells the analyst to look at,
not one it attributes to the sample:

    winservices  "**Registry:** Monitor `RegSetValueExA` / `RegCreateKeyExA` on
                 `HKLM\\...\\FirewallPolicy` and the `Run` key"
    win32k_dll   "2. Remove registry persistence entries:
                 - HKLM\\Software\\Microsoft\\Windows NT\\...\\UserList
                  (delete added values)"

That is the same speech act as the canonical persistence template the verifier
already exempts ("a verification target, not an observed artifact"), so it is
reported under `guidance_references` rather than counted as a claim.

The risk here is obvious and is tested just as hard as the fix: a guidance verb
elsewhere in the document must not launder a real claim. The window is the
enclosing list item or sentence, and a findings-section claim that happens to
follow a remediation section must still be judged.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import report_quality as rq  # noqa: E402

EV = r'{"p": "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"}'


def _unverified(md: str, ev: str = EV):
    return [i["value"] for i in
            rq.verify_claimed_iocs(md, ev)["unverified_items"]]


# -------------------------------------------------- the real shapes (now clean)

def test_monitoring_guidance_is_not_a_claim():
    """The exact winservices line."""
    md = ("- **Registry:** Monitor `RegSetValueExA` / `RegCreateKeyExA` on "
          r"`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
          r"\FirewallPolicy` and the `Run` key.")
    assert _unverified(md) == []
    out = rq.verify_claimed_iocs(md, EV)
    assert out["guidance_references"] == 1, out
    assert out["claims"] == 0, out


def test_remediation_bullets_are_not_claims():
    """The exact win32k remediation list."""
    md = ("2. Remove registry persistence entries:\n"
          "   - HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
          "\\SpecialAccounts\\UserList (delete added values)\n"
          "   - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    assert _unverified(md) == [], _unverified(md)
    out = rq.verify_claimed_iocs(md, EV)
    # Only the first bullet is guidance. The second names a path that IS in the
    # evidence, so it is verified by the ordinary verbatim match -- guidance
    # framing must not become a way to skip verification.
    assert out["guidance_references"] == 1, out
    assert out["verified"] == 1, out
    assert out["claims"] == 1, out


def test_guidance_items_are_still_reported_not_dropped():
    md = ("Remove `HKLM\\EvilCorp\\Backdoor` after remediation.")
    out = rq.verify_claimed_iocs(md, EV)
    assert out["guidance_references"] == 1, out
    assert out["guidance_items"][0]["value"] == r"HKLM\EvilCorp\Backdoor", out
    assert "defender guidance" in out["guidance_items"][0]["reason"], out


def test_imperative_verbs_across_the_variants():
    for verb in ("Monitor", "Delete", "Inspect", "Scan", "Clean", "Hunt",
                 "Verify", "Look for", "Audit"):
        md = f"{verb} `HKLM\\Some\\Location` on the host."
        assert _unverified(md) == [], f"{verb} not recognised: {_unverified(md)}"


# ------------------------------------------------------ must NOT launder claims

def test_a_real_claim_is_still_unverified():
    """No guidance verb anywhere: a plain assertion is still judged."""
    md = "The sample writes `HKLM\\EvilCorp\\Backdoor` at start-up."
    assert r"HKLM\EvilCorp\Backdoor" in _unverified(md)


def test_guidance_in_another_section_does_not_excuse_a_later_claim():
    """The regression this design exists to prevent.

    A remediation section full of imperatives, then a findings claim: the
    guidance must not bleed across the section boundary.
    """
    md = ("## 12. Remediation\n"
          "Remove `HKLM\\Foo\\Bar`.\n"
          "Delete `HKLM\\Baz\\Qux`.\n"
          "\n"
          "## 4. Observed behaviour\n"
          "The malware creates `HKLM\\EvilCorp\\Backdoor` for persistence.\n")
    unv = _unverified(md)
    assert r"HKLM\EvilCorp\Backdoor" in unv, unv


def test_claim_in_a_sentence_that_merely_mentions_removal_elsewhere():
    md = ("Remove persistence. The observed write was "
          "`HKLM\\EvilCorp\\Backdoor` in section 4.")
    assert r"HKLM\EvilCorp\Backdoor" in _unverified(md)


def test_non_registry_claims_are_untouched_by_guidance_logic():
    """Guidance framing must not excuse a fabricated URL."""
    md = "Remove the C2 indicator http://c2.example.net/gate.php now."
    assert "http://c2.example.net/gate.php" in _unverified(md)


def test_guidance_detection_is_scoped_to_the_item():
    md = ("- Monitor persistence\n"
          "- The sample writes `HKLM\\EvilCorp\\Backdoor`.\n")
    assert r"HKLM\EvilCorp\Backdoor" in _unverified(md)


def test_empty_and_verbatim_paths_behave_as_before():
    """Sanity: the classic paths still resolve through their own rules."""
    assert _unverified("Remove `HKCU\\...\\Run`.", EV) == []
    assert rq.verify_claimed_iocs("", EV)["claims"] == 0