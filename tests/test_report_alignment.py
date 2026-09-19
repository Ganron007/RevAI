#!/usr/bin/env python3
"""Regression: dynamic-aware report alignment (plan #12 deterministic half).

Covers the report-facing WinRE dynamic section and the "What We Don't Know"
section: presence gating, content pulled from the pack, public-report hygiene
(no lab host), and the opt-out env switches.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

from test_dynamic_pack import SHA, _make_pack  # tests dir is on sys.path

import v2_lib  # noqa: E402
from v2_lib import (  # noqa: E402
    attach_dynamic_analysis_section,
    attach_what_we_dont_know,
    format_dynamic_analysis_section,
    format_what_we_dont_know,
    load_dynamic_pack,
)


# --- dynamic section ------------------------------------------------------


def test_dynamic_section_absent_pack_is_empty():
    assert format_dynamic_analysis_section(None) == ""
    assert format_dynamic_analysis_section({"present": False}) == ""


def test_dynamic_section_renders_pack(tmp_path):
    _make_pack(tmp_path)
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    text = format_dynamic_analysis_section(pack)

    assert "## Dynamic Analysis (WinRE detonation)" in text
    assert "requested=150s effective=6s" in text
    assert "adaptive=True" in text
    assert "stop_reason=idle" in text
    assert "bounded by that window" in text
    assert "static_yara_wins`=True" in text
    # Runtime network: DGA-shaped count and the observed names.
    assert "DGA-shaped `.biz`: 1" in text
    assert "pywolwnvd.biz" in text
    assert "talks.vg" in text
    # Dropped path from the Frida summary (system path filtered out).
    assert "3cf8b057.bin" in text
    assert "ntdll.dll" not in text
    # Unpack artifact honesty.
    assert "x64_demo_unpacked.exe" in text
    assert "heap" in text
    assert "pesieve_imp" in text
    assert "not PE-parsable" in text
    # Public-report hygiene: the lab host must never leak.
    assert "192.168.77.42" not in text


def test_dynamic_section_attach_gating(tmp_path, monkeypatch):
    monkeypatch.delenv("REVAI_DISABLE_DYNAMIC_SECTION", raising=False)
    # No pack -> unchanged.
    assert attach_dynamic_analysis_section(
        "body", SHA, winre_root=tmp_path) == "body"
    _make_pack(tmp_path)
    out = attach_dynamic_analysis_section("body", SHA, winre_root=tmp_path)
    assert out.startswith("body")
    assert "Dynamic Analysis (WinRE detonation)" in out
    # Opt-out.
    monkeypatch.setenv("REVAI_DISABLE_DYNAMIC_SECTION", "1")
    assert attach_dynamic_analysis_section(
        "body", SHA, winre_root=tmp_path) == "body"


# --- what we don't know ---------------------------------------------------


def test_gap_section_without_dynamic(tmp_path):
    text = format_what_we_dont_know("", None)
    assert "## What We Don't Know" in text
    assert "Dynamic behaviour: not performed" in text


def test_gap_section_with_pack(tmp_path):
    _make_pack(tmp_path)
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    text = format_what_we_dont_know("", pack)
    assert "window-bounded" in text
    assert "could not be statically re-analyzed" in text


def test_gap_section_collects_report_negations():
    report = (
        "# Report\n"
        "- Persistence: not observed in this sample.\n"
        "- C2: no evidence of beaconing was found.\n"
        "This line is a normal statement.\n"
    )
    text = format_what_we_dont_know(report, None)
    assert "Persistence: not observed" in text
    assert "C2: no evidence" in text
    assert "normal statement" not in text
    assert text.count("- ") >= 2


def test_gap_section_uses_scan_text_not_appended_text(tmp_path, monkeypatch):
    """Our own caveat wording must never be quoted back as a gap."""
    monkeypatch.delenv("REVAI_DISABLE_GAP_SECTION", raising=False)
    _make_pack(tmp_path)
    original = "# Report\n- Exfiltration: not observed.\n"
    md = original
    md = attach_dynamic_analysis_section(md, SHA, winre_root=tmp_path)
    md = attach_what_we_dont_know(md, SHA, scan_text=original, winre_root=tmp_path)
    assert "Exfiltration: not observed" in md
    # The dynamic section's own "may be absent" line is not echoed into gaps.
    gap_part = md.split("## What We Don't Know", 1)[1]
    assert "may be absent" not in gap_part


def test_gap_section_opt_out_and_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("REVAI_DISABLE_GAP_SECTION", "1")
    assert attach_what_we_dont_know("body", SHA, pack=None) == "body"
    monkeypatch.delenv("REVAI_DISABLE_GAP_SECTION")
    # Pack present, no window/artifact, empty report -> nothing to say.
    assert format_what_we_dont_know("", {"present": True}) == ""
