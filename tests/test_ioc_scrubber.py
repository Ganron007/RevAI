#!/usr/bin/env python3
"""Plan #42: the report must stop asserting indicator values no tool observed.

Context (win32k_dll, 2026-10-02). With the v2 reports fixed, one red remained:
`report:unverified_iocs:6`. Two prompt-level attempts to stop the model naming
canonical registry paths had already failed, so this closes the class by making
the report accurate after the fact rather than by prompting harder.

The five registry claims were the archetype `HKCU\\...\\CurrentVersion\\Run` --
`CurrentVersion` appears zero times in the evidence pack, while `Run`,
`RegSetValue` and `T1112`/`T1543.003` all do. So the persistence *capability* was
genuinely evidenced and the concrete *path* was a training-data fill-in. That
distinction drives the design: neutralise the path, keep the finding.

The sixth was a verifier false positive, not a hallucination: `icanhazip.com`
written as `` `http://icanhazip.com`** `` was captured with its markdown
punctuation attached, failed its own evidence match, and was reported unverified
while appearing 10 times in the evidence pack and 4 times in iocs.json.

Nothing here relaxes a check. No claim is exempted and no exclusion list grows;
the fabricated text stops existing, so there is nothing left to fail.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from report_quality import (  # noqa: E402
    scrub_unverified_indicators,
    verify_claimed_iocs,
)

#: What the evidence pack genuinely said about persistence on win32k_dll.
EVIDENCE = (
    "capa: T1027 / T1083 / T1012 / T1016 / T1057 / T1489 / T1543.003; "
    "set_registry_value RegSetValue T1112; "
    "advapi32.RegSetValueExW IMPORT 1; "
    "ip-discovery http://icanhazip.com malcat strings/urls; "
    "hardcoded 203.183.172.196:3478; "
    "yara: run-key persistence rule matched"
)

#: The registry path the model filled in. Absent from EVIDENCE on purpose.
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

#: The spelling that actually failed the gate.
#:
#: `_CANONICAL_REGISTRY_TEMPLATE_RE` matches `HKCU\...` but NOT the long
#: `HKEY_*` form, and both name the identical hive. So `HKCU\...\Run` is excluded
#: as a canonical template while `HKEY_CURRENT_USER\...\Run` -- the same path --
#: falls through to a verbatim evidence match and is reported unverified. The
#: fixtures below use the long form because that is the case that went red.
LONG = "HKEY_CURRENT_USER\\" + RUN_KEY
SHORT = "HKCU\\" + RUN_KEY


def _report() -> str:
    return (
        "## Persistence\n"
        "Code paths that write to `HKEY_CURRENT_USER\\\\" + RUN_KEY + "` and "
        "create scheduled tasks (source: yara). capa maps T1112 Modify "
        "Registry.\n"
        "\n"
        "The same location as `HKEY_CURRENT_USER\\" + RUN_KEY + "` appears in "
        "the appendix.\n"
        "\n"
        "## Network\n"
        "Hardcoded IP 203.183.172.196:3478 and `http://icanhazip.com`** for "
        "public-IP discovery; cross-validated in bot config.\n"
        "\n"
        "```\n"
        "HKEY_CURRENT_USER\\" + RUN_KEY + "   # fenced, must survive\n"
        "```\n"
    )


# --------------------------------------------------------------------------
# The verifier bugs found alongside the scrubber
# --------------------------------------------------------------------------

def test_markdown_punctuation_does_not_make_a_real_indicator_unverified():
    """`http://icanhazip.com`** is a genuine indicator, not an unverified one.

    This was a false positive, not a hallucination: the value is in the evidence
    pack and in iocs.json. Trailing markdown emphasis must not be able to fail
    verification.
    """
    out = verify_claimed_iocs(
        "Beacon `http://icanhazip.com`** observed.", EVIDENCE)
    values = [i["value"] for i in out["unverified_items"]]
    assert not any("icanhazip" in v for v in values), out["unverified_items"]
    assert out["unverified"] == 0, out["unverified_items"]
    assert out["verified"] >= 1


def test_backslash_runs_collapse_so_one_path_is_one_claim():
    """The escaped and plain spellings of a path are the same claim.

    Left unnormalised they hashed to two entries, so one indicator was counted
    twice in `unverified` -- which is exactly how the audit reported the same
    HKEY_CURRENT_USER Run key twice.
    """
    md = ("`HKEY_CURRENT_USER\\\\" + RUN_KEY + "` and `HKEY_CURRENT_USER\\"
          + RUN_KEY + "`\n")
    out = verify_claimed_iocs(md, EVIDENCE)
    regkeys = [i for i in out["unverified_items"] if i["type"] == "registry_key"]
    assert len(regkeys) == 1, (
        f"one path in two spellings counted {len(regkeys)} times: {regkeys}")


def test_elided_path_is_detected_in_its_escaped_spelling():
    """`HKCU\\...\\Run` must be recognised as shorthand, not compared verbatim.

    Before the normalisation this escaped `_ELIDED_REGISTRY_RE` (the regex wants
    one separator then the ellipsis, and the text had two), so it fell through
    to a verbatim evidence comparison. Recognition is observable: it now reaches
    the elision branch, whose outcome is either a grounded concrete path or an
    explicit "abbreviated" reason.
    """
    md = "Inspect `HKCU\\\\...\\\\Run` for persistence.\n"
    out = verify_claimed_iocs(md, EVIDENCE)
    # `verified` and `unverified` are COUNTS; the item lists are separate.
    regkeys = (out["unverified_items"] + out["resolved_abbreviations"]
               + out["guidance_items"])
    assert regkeys, "escaped elided path was not recognised at all"
    assert any("abbreviated" in i.get("reason", "") or "abbreviated_from" in i
               for i in regkeys), (
        f"elided spelling did not reach the elision branch: {regkeys}")


def test_scrubber_removes_both_spellings_of_the_same_path():
    """Regression: the first version removed one rendering and left the other.

    `remaining_unverified` staying above zero is what exposed it -- the scrub
    reported success while an indicator value was still in the report.
    """
    scrubbed, _, meta = scrub_unverified_indicators(_report(), EVIDENCE)
    assert meta["remaining_unverified"] == 0, meta
    prose = scrubbed.split("```")[0]
    assert RUN_KEY not in prose, "one rendering of the path survived in prose"


def test_scrubber_handles_a_path_followed_by_a_value_name():
    """Regression found on the real report, not by a test.

    win32k_dll's technical v3 explained its own method with
    ``HKEY_CURRENT_USER\\...\\CurrentVersion\\Run\\<value_name>``. The trailing
    boundary rejected a match whenever a separator followed, so that occurrence
    survived and `remaining_unverified` stayed at 1 -- a scrub that reported
    partial success.
    """
    md = ("Give the exact registry key path, e.g. "
          "`HKEY_CURRENT_USER\\" + RUN_KEY + "\\<value_name>`.\n")
    scrubbed, removed, meta = scrub_unverified_indicators(md, EVIDENCE)
    assert removed, "the value_name form was skipped"
    assert meta["remaining_unverified"] == 0, meta
    assert RUN_KEY not in scrubbed


def test_longer_paths_are_not_left_in_fragments():
    """Regression found on the real report, not by a test.

    `HKLM\\...\\Microsoft\\Windows` is a prefix of
    `HKLM\\...\\Microsoft\\Windows\\CurrentVersion\\Run`, and the LONGER path is
    *excluded* from `unverified` by _CANONICAL_REGISTRY_TEMPLATE_RE -- so it is
    absent from the scrubber's work list while the shorter one still matched
    inside it. The result was the marker followed by a dangling
    `\\CurrentVersion\\Run` in the published report.
    """
    long_key = "HKLM\\" + RUN_KEY
    short_key = "HKLM\\Software\\Microsoft\\Windows"
    md = f"Observed `{long_key}` and separately `{short_key}`.\n"
    scrubbed, _, _ = scrub_unverified_indicators(md, EVIDENCE)
    # The excluded canonical path must survive untouched...
    assert long_key in scrubbed, (
        f"an excluded canonical path was damaged: {scrubbed!r}")
    # ...and the removed one must not leave a tail behind it.
    assert "]\\CurrentVersion" not in scrubbed, (
        f"a longer path was left in fragments: {scrubbed!r}")
    assert scrubbed.count("[registry path not observed in evidence]") == 1


def test_a_longer_word_is_its_own_claim_not_a_partial_match():
    r"""`...\RunOnce` is a different claim from `...\Run`.

    _CLAIM_REGKEY_RE is greedy over `[^\s"'<>|]+`, so it extracts the whole
    `RunOnce` token and it is judged on its own merits. The check that matters
    is that the boundary rejects a match when the continuation is alphanumeric,
    so `...\Run` is never treated as satisfied by `...\RunOnce`.
    """
    from report_quality import _flex_claim_re
    long_key = "HKLM\\" + RUN_KEY
    rx = _flex_claim_re(long_key)
    assert not rx.search("Observed `HKLM\\" + RUN_KEY + "Once` here.\n"), (
        "matched inside an alphanumeric continuation")
    # And the placeholder form IS matched whole, so nothing dangles.
    assert rx.search("key `HKLM\\" + RUN_KEY + "\\<value_name>` here.\n"), (
        "the placeholder form must match so it is removed whole")


# --------------------------------------------------------------------------
# The scrubber
# --------------------------------------------------------------------------

def test_scrubber_removes_unobserved_values_and_leaves_observed_ones():
    scrubbed, removed, meta = scrub_unverified_indicators(_report(), EVIDENCE)
    assert meta["unverified_before"] >= 1
    assert meta["remaining_unverified"] == 0, meta
    # Nothing grounded was touched.
    assert "203.183.172.196" in scrubbed, "removed a verified IP"
    assert "http://icanhazip.com" in scrubbed, "removed a verified URL"
    assert "RegSetValue" in scrubbed or "T1112" in scrubbed, (
        "the evidenced capability must survive")
    # Nothing unobserved survived in the prose. The fenced copy is meant to.
    prose = scrubbed.split("```")[0]
    assert RUN_KEY not in prose, "an unobserved registry path survived in prose"
    assert removed and all(r["occurrences"] >= 1 for r in removed)


def test_scrubber_preserves_the_evidenced_finding_not_just_deletes_the_path():
    """The point of replacing rather than deleting.

    capa matched T1112 and a yara rule fired, so persistence IS a real finding.
    A scrub that deleted the sentence would make the report less informative
    while also being honest. The design keeps the capability and drops only the
    value no tool produced.
    """
    scrubbed, _, _ = scrub_unverified_indicators(_report(), EVIDENCE)
    assert "create scheduled tasks" in scrubbed
    assert "[registry path not observed in evidence]" in scrubbed


def test_scrubber_leaves_fenced_code_blocks_untouched():
    scrubbed, _, _ = scrub_unverified_indicators(_report(), EVIDENCE)
    fenced = scrubbed.split("```")[1]
    assert RUN_KEY in fenced, (
        "claims are only collected outside fences, so a value inside one is an "
        "illustration and must survive")


def test_scrubber_records_what_it_removed():
    """The removal must be auditable, not silent."""
    _, removed, meta = scrub_unverified_indicators(_report(), EVIDENCE)
    kinds = {r["type"] for r in removed}
    assert "registry_key" in kinds, removed
    for r in removed:
        assert r["value"] and r["replaced_with"] and r["occurrences"] >= 1, r
    assert meta["indicators_removed"] == len(removed)


def test_scrubber_is_a_noop_when_everything_verifies():
    md = "Only grounded indicators: 203.183.172.196 and http://icanhazip.com.\n"
    scrubbed, removed, meta = scrub_unverified_indicators(md, EVIDENCE)
    assert scrubbed == md, "scrubber altered a clean report"
    assert removed == []
    assert meta["indicators_removed"] == 0


def test_scrubber_does_not_grow_an_exclusion_list():
    """Guard against the tempting shortcut.

    The temptation when an audit goes red on these claims is to exempt them.
    That would turn the gate green while the report still asserted paths no tool
    observed. The scrubber must never change classification -- only text.
    """
    before = verify_claimed_iocs(_report(), EVIDENCE)
    after = verify_claimed_iocs(_report(), EVIDENCE)
    assert before["excluded"] == after["excluded"], (
        "exclusion counts must not depend on scrubbing")
    scrubbed, _, meta = scrub_unverified_indicators(_report(), EVIDENCE)
    post = verify_claimed_iocs(scrubbed, EVIDENCE)
    assert post["excluded"] == before["excluded"], (
        "scrubbing changed which claims are exempt")


def test_registry_segments_containing_a_space_are_not_truncated():
    r"""Regression found by reading the published report, not by a metric.

    `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` is a real key. The
    old extractor stopped at the space, so the claim was read as
    `...\Microsoft\Windows`, the scrubber replaced that prefix, and the report
    shipped the orphan tail ` NT\CurrentVersion\Winlogon` next to the marker --
    with `remaining_unverified` at 0, because the tail is not itself a claim.
    """
    from report_quality import _CLAIM_REGKEY_RE
    path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    found = [m.group(0) for m in _CLAIM_REGKEY_RE.finditer(f"uses {path} for logon")]
    assert found == [path], found

    scrubbed, _, meta = scrub_unverified_indicators(
        f"uses {path} for logon", EVIDENCE)
    assert "NT\\CurrentVersion\\Winlogon" not in scrubbed, scrubbed
    assert not meta["orphan_fragments"], meta["orphan_fragments"]


def test_bare_hive_aliases_in_prose_are_not_claims():
    """`via HKCU/HKLM auto-run keys` names hives, not paths."""
    from report_quality import _CLAIM_REGKEY_RE
    t = "supports persistence via HKCU/HKLM auto-run keys"
    assert not [m.group(0) for m in _CLAIM_REGKEY_RE.finditer(t)]


def test_orphan_fragment_is_reported_even_when_no_claim_remains():
    r"""`remaining_unverified == 0` is necessary but not sufficient.

    A leftover path tail is not a registry claim, so the verifier cannot see it.
    The fragment check is what makes a clean result trustworthy: without it the
    scrubber reported success while shipping ` NT\CurrentVersion\Winlogon`.
    """
    md = ("Replaced marker [registry path not observed in evidence] "
          r"NT\CurrentVersion\Winlogon here.")
    from report_quality import _ORPHAN_FRAGMENT_RE
    assert _ORPHAN_FRAGMENT_RE.findall(md), (
        "the orphan fragment pattern must catch a path tail after a marker")
    # And a marker with ordinary prose after it is not a fragment.
    clean = ("Replaced marker [registry path not observed in evidence] "
             "for persistence.")
    assert not _ORPHAN_FRAGMENT_RE.findall(clean)


def test_empty_markdown_is_handled():
    """The meta keys are present even on the no-op paths.

    A caller reading `indicators_removed` must not have to branch on whether
    anything was found -- that inconsistency was a bug in the first version.
    """
    scrubbed, removed, meta = scrub_unverified_indicators("", EVIDENCE)
    assert scrubbed == "" and removed == []
    assert meta["indicators_removed"] == 0
    assert meta["remaining_unverified"] == 0