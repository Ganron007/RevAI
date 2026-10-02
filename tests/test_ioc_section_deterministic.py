#!/usr/bin/env python3
"""Section 8 is rendered from iocs.json, never authored by the model.

Measured 2026-10-02 on win32k_dll. With the technical report complete, the audit
failed on `report:unverified_iocs:11` -- all eleven canonical Windows registry
paths (`...\\CurrentVersion\\Run`, `...\\Winlogon`, `...\\Policies\\...`), none of
which appear anywhere in the evidence pack. `iocs.json` for that sample has
`registry_keys: []`: the model was writing well-known Windows locations from
training, not reporting observations.

Two prompt-level instructions had already failed to prevent this (winservices 2,
win32k_dll 11), because an empty indicator section reads like a failed analysis.
So the list is rendered rather than generated. An indicator no engine produced
cannot enter, because nothing invents it.

The important property is not "section 8 calls no LLM" -- it is that the section
cannot contain an indicator absent from `iocs.json`, AND that it reports absence
explicitly rather than filling the gap. Both are pinned below, using the real
win32k_dll `iocs.json` values including the NUL-padded URL.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import section_publisher as sp  # noqa: E402

# Verbatim from the win32k_dll case. Note registry_keys is EMPTY and the URL
# carries NUL padding plus trailing text -- both are the real shapes.
REAL_IOCS = {
    "sha256": "8" * 64,
    "family": "Modular C2 backdoor / dropper masquerading as win32k",
    "verdict": "malicious",
    "hashes": {"sha256": "8" * 64, "sha1": "a" * 40, "md5": "b" * 32},
    "domains": ["icanhazip[.]com"],
    "ips": [],
    "urls": ["http[:]//icanhazip[.]com\x00\x00\x00\x00No"],
    "files": ["shutdown.exe"],
    "registry_keys": [],
    "mutexes": [],
    "wallets_btc": [],
    "source": ["verdict.key_evidence", "verdict.iocs",
               "floss/xor cache", "ghidra/ida strings"],
    "note": "Deterministic regex extraction; analyst review before sharing",
}


def _write_iocs(tmp_path, payload):
    """Point case_dir() at a tmp case holding this iocs.json."""
    case = tmp_path / "scripted"
    case.mkdir(parents=True, exist_ok=True)
    (case / "iocs.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def _build(tmp_path, payload=REAL_IOCS, monkeypatch=None):
    """Write the iocs.json fixture, point case_dir() at it, build the section.

    The payload is written on every call, so a caller that needs a variant must
    pass it here rather than writing the file separately -- a separate write is
    silently overwritten by this helper, which is how two of these tests were
    briefly asserting against the wrong data.
    """
    _write_iocs(tmp_path, payload)
    if monkeypatch is not None:
        monkeypatch.setattr(sp, "case_dir", lambda sha: tmp_path / "scripted")
    return sp._build_ioc_section("8" * 64)


# ------------------------------------------------------- cannot invent anything

def test_no_registry_path_can_appear_when_none_were_observed(tmp_path, monkeypatch):
    """THE regression: this sample has NO registry keys.

    The model previously filled section 8 with the canonical Run key. Nothing
    generates that string now, so it cannot appear.
    """
    md = _build(tmp_path, monkeypatch=monkeypatch)
    lowered = md.lower()
    for forbidden in ("currentversion\\run", "currentversion\\winlogon",
                      "hkey_local_machine", "hkey_current_user",
                      "software\\microsoft\\windows"):
        assert forbidden not in lowered, (
            f"section 8 emitted {forbidden!r} which iocs.json does not contain")


def test_only_values_present_in_iocs_json_appear(tmp_path, monkeypatch):
    md = _build(tmp_path, monkeypatch=monkeypatch)
    assert "icanhazip[.]com" in md
    assert "shutdown.exe" in md
    assert ("8" * 64) in md and ("a" * 40) in md


def test_no_llm_call_is_possible_for_this_section(tmp_path, monkeypatch):
    monkeypatch.setattr(sp, "case_dir", lambda sha: tmp_path / "scripted")

    def explode(*a, **kw):
        raise AssertionError("section 8 must not call the LLM")

    monkeypatch.setattr(sp, "llm_judge", explode)
    md = sp._build_ioc_section("8" * 64)
    assert "Indicators of Compromise" in md


# -------------------------------------------------------------- honest absence

def test_absence_is_stated_and_attributed(tmp_path, monkeypatch):
    """An empty category must be reported, not quietly omitted."""
    md = _build(tmp_path, monkeypatch=monkeypatch)
    assert "Not observed" in md
    assert "Registry keys" in md
    assert "Mutexes" in md
    # The point of stating it: absence is about what the tools recovered.
    assert "not a claim that the behaviour is absent" in md


def test_engines_are_attributed(tmp_path, monkeypatch):
    md = _build(tmp_path, monkeypatch=monkeypatch)
    for engine in ("verdict.key_evidence", "floss/xor cache",
                   "ghidra/ida strings"):
        assert engine in md, f"missing attribution: {engine}"


def test_total_is_reported_and_points_at_the_source(tmp_path, monkeypatch):
    md = _build(tmp_path, monkeypatch=monkeypatch)
    assert "Total indicators" in md
    assert "iocs.json" in md


def test_sharing_caveat_is_kept(tmp_path, monkeypatch):
    """iocs.json carries an incident-response sensitivity note. Do not drop it."""
    md = _build(tmp_path, monkeypatch=monkeypatch)
    assert "analyst review before sharing" in md.lower()


# ------------------------------------------------------------- value hygiene

def test_nul_padded_value_is_truncated_and_fenced(tmp_path, monkeypatch):
    """The real URL is `http[:]//icanhazip[.]com` + NULs + `No`.

    Rendering it raw would embed invisible bytes and a stray fragment in the
    markdown; the report must show what the tool actually found. The assertion
    targets the URL line itself -- matching a bare "No" against the whole
    document would trip over ordinary words like "Nothing".
    """
    assert sp._ioc_value("http[:]//icanhazip[.]com\x00\x00\x00\x00No") == \
        "http[:]//icanhazip[.]com"

    md = _build(tmp_path, monkeypatch=monkeypatch)
    assert "\x00" not in md, "control bytes must not reach the report"
    url_lines = [ln for ln in md.splitlines()
                 if ln.startswith("- ") and "http" in ln]
    assert url_lines, f"URL not rendered as a list item:\n{md}"
    for ln in url_lines:
        assert ln.strip() == "- `http[:]//icanhazip[.]com`", (
            f"trailing junk survived: {ln!r}")


def test_control_characters_are_stripped_from_values():
    assert "\x00" not in sp._ioc_value("a\x00b")
    assert sp._ioc_value("a\x00b") == "a"
    assert sp._ioc_value("  spaced  ") == "spaced"
    assert sp._ioc_value("trail\\") == "trail"
    assert sp._ioc_value("") == ""
    # dict-valued indicators render key=value rather than a bare repr
    assert sp._ioc_value({"a": "1"}) == "a=1"


# ----------------------------------------------------------------- robustness

def test_missing_iocs_json_is_handled_honestly(tmp_path, monkeypatch):
    # Deliberately do NOT write iocs.json -- this is the no-extraction case.
    case = tmp_path / "scripted"
    case.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sp, "case_dir", lambda sha: case)
    md = sp._build_ioc_section("8" * 64)
    assert "No indicator set was produced" in md
    assert "not that the sample is clean" in md


def test_corrupt_iocs_json_does_not_crash_the_section(tmp_path, monkeypatch):
    case = tmp_path / "scripted"
    case.mkdir(parents=True, exist_ok=True)
    (case / "iocs.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(sp, "case_dir", lambda sha: case)
    md = sp._build_ioc_section("8" * 64)
    assert "could not be read" in md


def _empty_indicator_lists_do_not_produce_empty_rows(tmp_path, monkeypatch):
    payload = dict(REAL_IOCS, domains=[], urls=[], files=[], ips=[],
                   registry_keys=["HKLM\\SOFTWARE\\Real\\Observed"])
    md = _build(tmp_path, payload, monkeypatch=monkeypatch)
    assert "HKLM\\SOFTWARE\\Real\\Observed" in md
    # Categories with nothing must not emit a heading with no values.
    assert "**Domains**" not in md
    assert "**URLs**" not in md


def test_empty_indicator_lists_do_not_produce_empty_rows(tmp_path, monkeypatch):
    _empty_indicator_lists_do_not_produce_empty_rows(tmp_path, monkeypatch)


def test_large_categories_are_truncated_with_a_count(tmp_path, monkeypatch):
    payload = dict(REAL_IOCS,
                   domains=[f"host{i}.example[.]com" for i in range(60)])
    md = _build(tmp_path, payload, monkeypatch=monkeypatch)
    assert "host0.example[.]com" in md
    assert "host59.example[.]com" not in md, "cap not applied"
    assert "and 20 more" in md, "the truncation must be disclosed"
    assert "iocs.json" in md, "the full set must remain reachable"