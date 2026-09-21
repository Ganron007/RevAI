#!/usr/bin/env python3
"""Regression: generated YARA rules must not be near-universal.

WinRE flagged the auto-generated CADRE_v2 ruleset: the condition
`uint16(0) == 0x5A4D and 2 of them` counted the DOS-header hex signature
(4D 5A 90 00...) plus one generic API string, so benign system binaries
matched. These tests pin the fixed shape: header bytes are never rule
tokens, generic DLL/API/CRT strings are excluded, and the condition counts
distinctive strings only ($s*), with imphash as an independent branch.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from yara_gen_v2 import (  # noqa: E402
    build_yara_rule,
    distinctive_strings,
    is_generic_rule_string,
)


def test_generic_classifier():
    assert is_generic_rule_string("KERNEL32.dll")
    assert is_generic_rule_string("ExitProcess")
    assert is_generic_rule_string("SetUnhandledExceptionFilter")
    assert is_generic_rule_string("AllocateAndInitializeSid")
    assert is_generic_rule_string("WTSEnumerateProcessesW")
    assert is_generic_rule_string("RtlLookupFunctionEntry")
    assert is_generic_rule_string("??0exception@@QEAA@AEBQEBD@Z")
    assert is_generic_rule_string("?what@exception@@UEBAPEBDXZ")
    assert is_generic_rule_string("This program cannot be run in DOS mode")
    assert is_generic_rule_string("api-ms-win-core-file-l1-1-0")
    assert is_generic_rule_string("© M2-Team and Contributors. All rights reserved.")
    assert not is_generic_rule_string("E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb")
    assert not is_generic_rule_string("C2 beacon /mega/endpoint/v2")
    assert not is_generic_rule_string("Software\\Microsoft\\Windows\\CurrentVersion\\Run")


def test_distinctive_filter_keeps_only_specific():
    kept = distinctive_strings([
        "KERNEL32.dll",
        "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
        "ExitProcess",
        "xmrig-pool://donate.example.net:3333",
    ])
    assert kept == [
        "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
        "xmrig-pool://donate.example.net:3333",
    ]


def test_vidar_like_rule_is_specific():
    strings = [
        "© M2-Team and Contributors. All rights reserved.",
        "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
        "??0exception@@QEAA@AEBQEBD@Z",
        "InitializeCriticalSectionEx",
        "SetUnhandledExceptionFilter",
        "InterlockedPushEntrySList",
    ]
    rule = build_yara_rule("vidar", "0c00aedf97071653", strings,
                           imphash="55fa9bd502457bea13d3626a68dc1cad")
    assert "$h" not in rule                    # no hex-signature tokens
    assert "4D 5A 90" not in rule              # DOS stub never emitted
    assert "2 of them" not in rule             # never the near-universal form
    assert "of ($s*)" in rule                  # strings-only counting
    assert "NSudo.pdb" in rule                 # distinctive string kept
    assert "InitializeCriticalSectionEx" not in rule
    assert "SetUnhandledExceptionFilter" not in rule
    assert 'pe.imphash() == "55fa9bd502457bea13d3626a68dc1cad"' in rule


def test_generic_only_without_imphash_degrades_honestly():
    rule = build_yara_rule("nope", "a" * 64, ["KERNEL32.dll", "ExitProcess"])
    assert 'confidence = "low"' in rule
    assert "2 of them" not in rule


def test_elf_condition_uses_dollar_s_only():
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        p = Path(f.name)
    try:
        rule = build_yara_rule("linuxthing", "b" * 64,
                               ["/tmp/evil/persist.sock", "/etc/ld.so.preload"],
                               sample_path=p)
        assert "0x464C457F" in rule
        assert "of ($s*)" in rule
        assert "2 of them" not in rule
    finally:
        p.unlink(missing_ok=True)


def test_imphash_only_rule_omits_empty_strings_section():
    """Deployment-rehearsal regression (2026-09-21): when every string is generic
    but the sample has an imphash, the rule was emitted with an empty
    `strings:` block -> yara-x E001 syntax error -> yara_gen stage red."""
    rule = build_yara_rule(
        "protected_gui_application_potential_keygen_or_cr", "c" * 64,
        ["KERNEL32.dll", "ExitProcess", "This program cannot be run in DOS mode"],
        imphash="a3e8b5e80d5f9f266119a4ac18211954",
    )
    assert "    strings:" not in rule          # empty block must not be emitted
    assert "$s0" not in rule
    assert 'import "pe"' in rule
    assert 'pe.imphash() == "a3e8b5e80d5f9f266119a4ac18211954"' in rule


def test_imphash_only_rule_compiles():
    """The imphash-only shape must compile with the real engine."""
    import pytest

    try:
        import yara_x
    except ImportError:  # pragma: no cover - engine optional in some checkouts
        pytest.skip("yara_x not installed")
    rule = build_yara_rule(
        "protected_gui_application_potential_keygen_or_cr", "c" * 64,
        ["KERNEL32.dll", "ExitProcess"],
        imphash="a3e8b5e80d5f9f266119a4ac18211954",
    )
    yara_x.compile(rule)  # must not raise E001/E000
