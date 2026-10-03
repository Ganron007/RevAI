#!/usr/bin/env python3
"""FLOSS sampling starved `static_strings`, and the report paid for it.

Found 2026-10-02 on win32k_dll. The DLL contains seven UTF-16 registry paths,
including

    Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList

which is a logon-hijack plus account-enumeration chain. FLOSS reported every one
of them under `static_strings` (817 strings in that category). The sampler took
80 in category-priority order, `static_strings` is consumed LAST, and the first
category alone had 89 entries -- so `static_strings` contributed exactly zero.

The report was then written without the evidence and reconstructed the paths from
training data, which is where `Software\\Microsoft\\Version\\Winlogon` came from
(a path that does not exist; `Version` is a corruption of `CurrentVersion`).

The important part of that story is not the LLM. It was asked to write about
evidence it was never given. Nothing here was a model hallucination in the usual
sense -- it was correct behaviour on incomplete input.

These tests pin the fix at both levels: the predicate, and the ordering.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import add_module_dir  # noqa: E402

add_module_dir("revai/v2_lib.py")

import v2_lib  # noqa: E402

#: The seven real strings, verbatim from the binary (UTF-16, file offsets
#: 0x019c48..0x01a920).
WIN32K_STRINGS = [
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
    r"SYSTEM\CurrentControlSet\Control\Lsa",
    r"SYSTEM\CurrentControlSet\Control\Terminal Server",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SYSTEM\CurrentControlSet\services",
]


# --------------------------------------------------------------------------
# The predicate
# --------------------------------------------------------------------------

def test_every_real_win32k_string_is_recognised_as_ioc_shaped():
    """All seven must claim budget. This is the regression that matters."""
    missed = [s for s in WIN32K_STRINGS if not v2_lib._is_ioc_shaped(s)]
    assert not missed, f"not recognised as indicators: {missed}"


def test_urls_ips_and_emails_are_indicators():
    for s in ("http://icanhazip.com", "https://c2.example.net/gate.php",
              "203.183.172.196", "1.2.3.4:3478", "admin@target.local",
              "ftp://drop.example.com/x"):
        assert v2_lib._is_ioc_shaped(s), s


def test_paths_executables_and_mutexes_are_indicators():
    for s in (r"C:\Users\Public\svchost.exe", r"\\fileserver\share\a.dll",
              r"%APPDATA%\3cf8b0572394551a.bin", "powershell.exe -enc",
              r"Global\WinlogonHelperMutex", r"Local\MtxSession"):
        assert v2_lib._is_ioc_shaped(s), s


def test_ordinary_program_text_is_not_an_indicator():
    """The predicate has to be selective or the priority buys nothing.

    `kernel32.dll` is the case that shaped the extension list: it is a library
    name from the import table, not an indicator, and it was the first false
    positive the naive extension rule produced.
    """
    for s in ("CreateFileW", "kernel32.dll", "ntdll.dll", "advapi32.dll",
              "This program cannot be run in DOS mode",
              "abcdefghijklmnop", "Enter the password", "Hello world, friend"):
        assert not v2_lib._is_ioc_shaped(s), s


# --------------------------------------------------------------------------
# The ordering -- the actual defect
# --------------------------------------------------------------------------

def _floss_payload(static: list[str], decoded: list[str]) -> dict:
    return {"strings": {
        "decoded_strings": decoded,
        "stack_strings": [],
        "tight_strings": [],
        "language_strings": [],
        "static_strings": static,
    }}


def test_static_strings_are_no_longer_starved():
    """The bug: 89 decoded strings consumed all 80 slots, static got none."""
    decoded = [f"decoded filler {i} aaaaaaaaaaaaaaaaaaaa" for i in range(89)]
    sample, per_cat, total, ioc = v2_lib._collect_floss_strings(
        _floss_payload(WIN32K_STRINGS, decoded), max_strings=80)
    assert per_cat["static_strings"] == 7
    for s in WIN32K_STRINGS:
        assert s in sample, f"real indicator dropped from the sample: {s}"
    # And the count of indicators the artifact must now report.
    assert ioc["ioc_shaped_total"] == 7, ioc
    assert ioc["ioc_shaped_sampled"] == 7, ioc
    assert ioc["ioc_shaped_dropped"] == 0, ioc


def test_indicators_beat_filler_regardless_of_category_order():
    """An indicator late in the order still displaces early filler."""
    lots_of_filler = [f"decoded filler {i} aaaaaaaaaaaaaaaaaaaa" for i in range(500)]
    sample, _, _, ioc = v2_lib._collect_floss_strings(
        _floss_payload(WIN32K_STRINGS, lots_of_filler), max_strings=80)
    assert ioc["ioc_shaped_sampled"] == 7
    assert len(sample) <= 80, "budget exceeded"
    assert all(s in sample for s in WIN32K_STRINGS)


def test_budget_is_respected_and_overflow_is_reported_not_hidden():
    """Truncation must be visible in the artifact, never silent."""
    many_ioc = [rf"http://c{i}.example.com/p" for i in range(500)]
    sample, _, total, ioc = v2_lib._collect_floss_strings(
        _floss_payload(many_ioc, []), max_strings=80)
    assert len(sample) == 80
    assert total == 500, "total must still count every string"
    assert ioc["ioc_shaped_total"] == 500
    assert ioc["ioc_shaped_sampled"] == 80
    assert ioc["ioc_shaped_dropped"] == 420, ioc
    assert ioc["sample_budget"] == 80


def test_total_still_counts_every_string():
    """per_category / string_count are accuracy signals and must not change."""
    data = _floss_payload([f"static{i} aaaaaaaaaaaaaaa" for i in range(817)],
                          [f"dec{i} aaaaaaaaaaaaaaa" for i in range(89)])
    _, per_cat, total, _ = v2_lib._collect_floss_strings(data, max_strings=80)
    assert total == 906, total
    assert per_cat["static_strings"] == 817
    assert per_cat["decoded_strings"] == 89


def test_dedup_still_holds_across_categories():
    data = {"strings": {
        "decoded_strings": [r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"],
        "static_strings": [r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                           r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"],
    }}
    sample, _, total, ioc = v2_lib._collect_floss_strings(data)
    assert sum(1 for s in sample if "Winlogon" in s) == 1
    assert ioc["ioc_shaped_sampled"] == 1


def test_flat_payload_shape_still_works():
    """FLOSS also emits categories at the top level; keep that path working."""
    data = {"static_strings": WIN32K_STRINGS, "decoded_strings": []}
    sample, per_cat, total, ioc = v2_lib._collect_floss_strings(data, max_strings=50)
    assert total == 7
    assert all(s in sample for s in WIN32K_STRINGS)
    assert ioc["ioc_shaped_sampled"] == 7


def test_floss_extract_default_budget_is_configurable(monkeypatch):
    """The old hardcoded 80 was the volume half of the defect."""
    import inspect
    sig = inspect.signature(v2_lib.floss_extract)
    assert sig.parameters["max_strings"].default is None, (
        "max_strings must be resolvable from the environment, not hardcoded")
    monkeypatch.setenv("REVAI_FLOSS_MAX_STRINGS", "42")
    src = inspect.getsource(v2_lib.floss_extract)
    assert "REVAI_FLOSS_MAX_STRINGS" in src

# --------------------------------------------------------------------------
# 2026-10-03: escape-token false positives + IPv6/GUID coverage
# --------------------------------------------------------------------------

def test_hex_escape_runs_are_not_paths():
    r"""`\x41\x42\x43` is decoder text, not a backslash path.

    The generic two-segment alternative matched ANY two segments between
    backslashes, so hex-escape runs and embedded regex fragments claimed the
    IOC budget before filler -- displacing the real strings the priority was
    built to protect.
    """
    for s in (r"\x41\x42\x43", r"\x68\x74\x74\x70\x3a\x2f\x2f",
              r"\u0041\u0042\u0043", r"\d+\.\d+\.\d+"):
        assert not v2_lib._is_ioc_shaped(s), s


def test_real_paths_with_escape_prefixes_are_still_paths():
    r"""Decoder output that CONTAINS a path must still claim budget."""
    assert v2_lib._is_ioc_shaped(r"\x41\x42\Software\Microsoft\Run")
    assert v2_lib._is_ioc_shaped(r"HKCU\Software\Microsoft\Windows")


def test_guids_and_ipv6_are_indicators():
    for s in ("{1a2b3c4d-5e6f-4a0b-8c9d-0e1f2a3b4c5d}",
              "2001:db8:dead:beef::1", "fe80::1",
              "C2 fell back to 2001:db8:1:2:3:4:5:6 after the v4 was blocked"):
        assert v2_lib._is_ioc_shaped(s), s


def test_cpp_style_scope_is_not_ipv6():
    """`std::vector`-shaped text must not read as a compressed IPv6 literal."""
    for s in ("std::vector allocate", "Module::Function called", "a::b",
              "::1"):
        assert not v2_lib._is_ioc_shaped(s), s


def test_ioc_stats_report_unique_alongside_occurrences():
    """`total` counts occurrences; sampled/dropped are unique-based.

    A string seen in three categories inflated the total three times, so the
    artifact overstated evidence loss. `ioc_shaped_unique` is the honest
    denominator next to the unique sampled/dropped pair.
    """
    data = {"strings": {
        "decoded_strings": [
            {"string": "http://a.example.com"},
            {"string": "HKCU\Software\X"},
            {"string": "http://a.example.com"},   # duplicate occurrence
        ],
        "static_strings": [
            {"string": "http://a.example.com"},   # same value, other category
            {"string": "plain filler text here"},
        ],
    }}
    _, _, total, stats = v2_lib._collect_floss_strings(data, max_strings=10)
    assert stats["ioc_shaped_total"] == 4
    assert stats["ioc_shaped_unique"] == 2
    assert stats["ioc_shaped_dropped"] == 0
