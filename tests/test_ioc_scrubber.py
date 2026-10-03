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

import report_quality as rq  # noqa: E402
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
    r"""`HKCU\\...\\Run` must be recognised as shorthand, not compared verbatim.

    Before the span-key normalisation (2026-10-03) the escaped spelling's
    guidance lookup MISSED -- the spans are keyed on the _plain_claim form with
    single backslashes, the lookup stripped but did not collapse -- so
    "Inspect `HKCU\\...\\Run`" fell through guidance into the elision branch.
    Recognising it as guidance is the correct classification (same speech act
    as the plain spelling of the same sentence), and either way it must never
    reach a verbatim evidence comparison. Both spellings are pinned: escaped
    lands in guidance, and a non-guidance sentence reaches the elision branch
    (grounded, or an explicit "abbreviated" reason).
    """
    md = "Inspect `HKCU\\\\...\\\\Run` for persistence.\n"
    out = verify_claimed_iocs(md, EVIDENCE)
    guidance = [i for i in out["guidance_items"] if i["type"] == "registry_key"]
    assert guidance, (
        f"escaped elided path inside guidance was not classified as guidance: "
        f"{out}")
    md2 = "Persistence via `HKCU\\...\\Run` was noted by the analyst.\n"
    out2 = verify_claimed_iocs(md2, EVIDENCE)
    regkeys = (out2["unverified_items"] + out2["resolved_abbreviations"]
               + out2["guidance_items"])
    assert regkeys, "elided path was not recognised at all"
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
    r"""Regression found on the real report, not by a test.

    `HKLM\\...\\Microsoft\\Windows` is a prefix of
    `HKLM\\...\\Microsoft\\Windows\\CurrentVersion\\Run`. The LONGER path must
    be absent from the scrubber's work list while the shorter one is scrubbed
    -- whichever branch keeps it out (verification-target exclusion here) -- or
    the shorter match cuts a dangling `\\CurrentVersion\\Run` out of the middle
    of it. Since 2026-10-03 a bare unobserved canonical path is scrubbed like
    any claim, so the fixture names it as a verification target ("not
    observed") to keep it excluded.
    """
    long_key = "HKLM\\" + RUN_KEY
    short_key = "HKLM\\Software\\Microsoft\\Windows"
    md = ("A RegSetValue under `" + long_key + "` (or equivalent) was not "
          f"observed. Separately, `{short_key}` was seen in the import table.\n")
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


def test_scrubber_does_not_run_against_an_empty_evidence_corpus():
    """HIGH-2, found 2026-10-03 by review. The severe one.

    `collect_evidence_text` returns `("", [])` with NO exception when the root
    holds none of the evidence files -- so the scrubber's `except` never fired.
    Every claim then failed its evidence match, every claim was "unverified", and
    every claim was DELETED, including the sample's own sha256 and its C2 URLs,
    with `remaining_unverified: 0` self-certifying the success.

    That is the e879318 failure (wrong evidence root) reproducing silently: the
    report loses all its indicators and nothing records that it happened. An
    absent corpus and an EMPTY corpus must behave the same way -- refuse.
    """
    import tempfile

    from report_quality import collect_evidence_text

    empty = Path(tempfile.mkdtemp())
    assert collect_evidence_text(empty)[1] == [], "premise: empty root"

    md = ("- Sample sha256: 8d7e3e41cd993d5a41f4e96d6076c4f7\n"
          "- C2: http://203.183.172.196:3478\n")
    out, meta = rq.scrub_report_indicators(empty, md, "probe")
    assert meta["indicators_removed"] == 0, meta
    assert "error" in meta and meta["error"], (
        "an empty corpus must be recorded as an error, not silently scrubbed")
    assert out == md, "markdown must be untouched when there is no evidence"
    assert "8d7e3e41cd993d5a41f4e96d6076c4f7" in out, "sha256 was deleted"


def test_a_real_corpus_still_scrubs(tmp_path):
    """The guard must not disable the scrubber where it SHOULD act."""
    (tmp_path / "iocs.json").write_text(
        '{"urls": ["http://icanhazip.com"]}', encoding="utf-8")
    md = ("- Real C2: http://icanhazip.com\n"
          "- Invented: http://evil.example.org/x\n")
    out, meta = rq.scrub_report_indicators(tmp_path, md, "probe")
    assert meta.get("evidence_files"), "a real corpus must list its files"
    assert meta["indicators_removed"] >= 1, meta
    assert "icanhazip" in out, "a GROUNDED indicator was removed"
    assert "evil.example.org" not in out, "an ungrounded indicator survived"


def test_master_v3_scrub_record_is_persisted():
    """HIGH-1: the record existed and was read nowhere.

    `_master_ioc_scrub` was assigned in section_publisher and never read, so for
    REPORT-MASTER-v3 the removal was invisible. The sibling publish paths all
    record theirs; master_v3 was left out. And REPORT-MASTER-v3 is not the
    report `claimed_ioc_verification` reads (report_quality picks
    tech3 -> tech2 -> master), so the audit would never have seen the loss
    either -- leaving the e879318 bug undetectable for that report.
    """
    import sys as _sys

    _sys.path.insert(0, str(ROOT / "revai"))
    import section_publisher

    src = (ROOT / "revai" / "section_publisher.py").read_text(errors="replace")
    assert src.count("_master_ioc_scrub") >= 2, (
        "master_v3's scrub record is assigned but never read; that is the only "
        "tripwire the wrong-evidence-root bug has for this report")
    assert "master_v3_indicator_scrub" in src, (
        "the record must be written into section-results-v3.json")
    assert callable(section_publisher.scrub_report_indicators)


def test_empty_markdown_is_handled():
    """The meta keys are present even on the no-op paths.

    A caller reading `indicators_removed` must not have to branch on whether
    anything was found -- that inconsistency was a bug in the first version.
    """
    scrubbed, removed, meta = scrub_unverified_indicators("", EVIDENCE)
    assert scrubbed == "" and removed == []
    assert meta["indicators_removed"] == 0
    assert meta["remaining_unverified"] == 0

# --------------------------------------------------------------------------
# 2026-10-03: the canonical-template exclusion, boundary and variant fixes
# --------------------------------------------------------------------------

def test_bare_canonical_template_is_a_claim_not_an_exclusion():
    r"""The template branch must not exempt a fabrication that names the Run key.

    Before the context check, ANY unobserved mention of the canonical Run key
    went to `excluded` -- so a model-invented "persists via HKCU\...\Run"
    shipped while the audit counted zero. That was the exact #42 class
    surviving inside the checker built to catch it.
    """
    md = "The sample persists via `HKCU\\" + RUN_KEY + "` on every boot.\n"
    out = verify_claimed_iocs(md, EVIDENCE)
    assert out["unverified"] == 1, out
    scrubbed, _, meta = scrub_unverified_indicators(md, EVIDENCE)
    assert RUN_KEY not in scrubbed
    assert meta["remaining_unverified"] == 0, meta


def test_canonical_template_target_is_still_excluded():
    """The verification-target phrasing keeps its exemption."""
    md = ("A RegSetValue under `HKCU\\" + RUN_KEY + "` (or equivalent) was "
          "not observed in this run.\n")
    out = verify_claimed_iocs(md, EVIDENCE)
    assert out["excluded"] == 1, out
    assert out["unverified"] == 0, out


def test_canonical_template_treats_both_hive_spellings_alike():
    r"""`HKEY_CURRENT_USER\...\Run` and `HKCU\...\Run` are the same path.

    The old template regex only accepted the short hive form, so within one
    report the short spelling was excluded while the long spelling of the
    identical string was flagged unverified -- opposite treatment for one path.
    """
    targeting = "A write to `{}` (or equivalent) was not observed."
    for spelling in (SHORT, LONG):
        out = verify_claimed_iocs(targeting.format(spelling), EVIDENCE)
        assert out["excluded"] == 1, (spelling, out)
    for spelling in (SHORT, LONG):
        md = f"The sample writes to `{spelling}` on boot.\n"
        out = verify_claimed_iocs(md, EVIDENCE)
        assert out["unverified"] == 1, (spelling, out)


def test_observed_canonical_path_verifies_in_both_hive_spellings():
    """An observed Run key verifies even across the hive alias."""
    ev = r"procmon: HKCU\Software\Microsoft\Windows\CurrentVersion\Run set value Foo"
    for spelling in (SHORT, LONG):
        out = verify_claimed_iocs(f"Writes to `{spelling}`.\n", ev)
        assert out["verified"] == 1, (spelling, out)


def test_subdomain_is_not_mangled_by_a_scrubbed_parent():
    """Scrubbing `evil.com` must not cut into a longer `sub.evil.com`.

    The claim extractor can see `evil.com` as its own (unverified) claim while
    `sub.evil.com` appears elsewhere in the report; the removal regex then
    matched inside the longer domain and published
    `sub[domain not observed in evidence]`. Pinned at the regex level, with the
    sentence-final period still accepted in both spellings.
    """
    from report_quality import _flex_claim_re
    assert not _flex_claim_re("evil.com").search("sub.evil.com")
    assert not _flex_claim_re("1.2.3.4").search("1.2.3.4.5")
    assert _flex_claim_re("evil.com").search("contact evil.com.")
    assert _flex_claim_re("evil[.]com").search("contact evil.com.")
    assert _flex_claim_re("evil.com").search("contact evil[.]com.")
    assert _flex_claim_re("hxxp://evil.com").search("see hxxp://evil.com;")
    assert not _flex_claim_re("HKLM\\Software").search(
        "HKLM\\Software\\Microsoft\\Windows")


def test_partial_ip_is_not_cut_out_of_a_longer_one():
    """`1.2.3.4` is not a claim satisfied by, or cut out of, `1.2.3.4.5`."""
    ev = "observed 1.2.3.4.5 in a version string only"
    md = "Version bump 1.2.3.4.5 noted; last-seen beacon 1.2.3.4.\n"
    scrubbed, _, meta = scrub_unverified_indicators(md, ev)
    assert "1.2.3.4.5" in scrubbed, scrubbed
    assert meta["remaining_unverified"] == 0, meta


def test_both_defang_spellings_of_one_claim_are_removed():
    """The scrub must not stop at the first spelling it sees.

    `evil.com` in prose and `evil[.]com` in a table row are ONE claim; removing
    only the rendering the work list happened to carry left the other in the
    published report while the meta said the scrub had succeeded.
    """
    md = ("Beacon to evil.com every 30s. Defanged table: evil[.]com.\n")
    scrubbed, _, meta = scrub_unverified_indicators(md, "")
    assert "evil.com" not in scrubbed and "evil[.]com" not in scrubbed, scrubbed
    assert meta["remaining_unverified"] == 0, meta


def test_evidence_side_registry_paths_keep_their_spaced_segments():
    r"""Grounding needs `Windows NT` intact on the EVIDENCE side too.

    The claim-side extractor was fixed earlier; the evidence-side regex still
    stopped at the space, so an elided claim of the real Winlogon path could
    never resolve to the concrete path sitting in the evidence pack.
    """
    ev = (r"autoruns: HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
          r"\Winlogon\Shell = explorer.exe")
    md = "Persistence: `HKCU\\...\\Winlogon`.\n"
    out = verify_claimed_iocs(md, ev)
    assert out["resolved_abbreviations"], out


def test_evidence_paths_do_not_swallow_prose_into_a_candidate():
    r"""A space must not let one candidate eat the next path.

    With a loose space rule, `HKCU\Run and HKLM\RunOnce` parsed as one
    candidate with tail `runonce` under hive hkcu -- grounding an
    `HKCU\...\RunOnce` claim the evidence never supported.
    """
    ev = r"note: HKCU\Run and HKLM\RunOnce differ"
    md = "Persistence: `HKCU\\...\\RunOnce`.\n"
    out = verify_claimed_iocs(md, ev)
    assert not out["resolved_abbreviations"], out
    assert out["unverified"] == 1, out


def test_guidance_then_assertion_is_judged_as_a_claim():
    """A later bare assertion must not be excused by an earlier guidance mention.

    Classification used the FIRST occurrence's window, so a value first named
    in "Monitor ..." guidance and later asserted plainly ("The sample writes
    to X") was never judged as the claim it also was.
    """
    path = r"HKLM\Software\Microsoft\Windows NT\...\UserList"
    md = (f"Remediation: remove `{path}` if present.\n"
          f"The sample writes to `{path}` on install.\n")
    out = verify_claimed_iocs(md, EVIDENCE)
    assert out["unverified"] == 1, out
    assert out["guidance_references"] == 0, out


def test_unterminated_fence_keeps_its_claims_verbatim():
    """An odd number of ``` markers must not turn code into prose claims.

    The extractor removed balanced fences and the splitter kept balanced
    fences, so with an unterminated fence one pass treated the tail as code
    and the other as prose -- the tail's indicators were scrubbed from the
    published report while the design says fenced illustrations survive.
    """
    md = ("```\n"
          "HKEY_CURRENT_USER\\" + RUN_KEY + "   # unterminated fence\n")
    out = verify_claimed_iocs(md, EVIDENCE)
    assert out["unverified"] == 0, out
    scrubbed, _, _ = scrub_unverified_indicators(md, EVIDENCE)
    assert RUN_KEY in scrubbed, "scrubbed inside an unterminated fence"


def test_hkcc_paths_are_extracted_as_claims():
    """HKCC is a real hive; omitting it made claims in it invisible."""
    md = "Config: `HKCC\\Software\\Fonts\\Foo`.\n"
    out = verify_claimed_iocs(md, EVIDENCE)
    kinds = [i for i in out["unverified_items"] if i["type"] == "registry_key"]
    assert kinds and "HKCC" in kinds[0]["value"].upper(), out


def test_ellipsis_tailed_claim_is_removed_whole():
    r"""`HKCU\...\Run\...` and `...\FirewallPolicy\...` must scrub, not dangle.

    Live finding on the winservices re-run (2026-10-03): the report wrote a
    claim followed by a backslash + ellipsis tail -- the flex regex consumed
    `<value_name>` continuations but not `\...`, so the strict trailing
    boundary rejected the match, the scrub skipped the claim, and the audit
    stayed red on 2 claims the scrubber reported handling. The ellipsis names
    no concrete value, so consuming it is the same rule as the placeholder.
    """
    md = "The sample persists under `HKCU\\" + RUN_KEY + "\\...` on boot.\n"
    scrubbed, _, meta = scrub_unverified_indicators(md, EVIDENCE)
    assert meta["remaining_unverified"] == 0, meta
    assert RUN_KEY not in scrubbed, scrubbed


def test_honesty_prose_keeps_the_template_target_exemption():
    """`no specific ... appears in the evidence` is verification language.

    The winservices report explained its own honesty with exactly that shape;
    treating it as a bare assertion would scrub a sentence that asserts
    nothing. The value stays (it is an example of what was looked for) and is
    classified excluded, not unverified.
    """
    md = ("No specific registry key path (e.g., `HKCU\\" + RUN_KEY + "\\...`) "
          "appears in the evidence.\n")
    out = verify_claimed_iocs(md, EVIDENCE)
    assert out["excluded"] == 1, out
    assert out["unverified"] == 0, out
    scrubbed, _, _ = scrub_unverified_indicators(md, EVIDENCE)
    assert RUN_KEY in scrubbed, "an excluded verification target was scrubbed"
