#!/usr/bin/env python3
"""Tests for the derived alignment sections: component inventory, analysis
environment, and MBC vocabulary (plan #12, prose half)."""

import json
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_DIR.parent / "revai"))

from test_revai_tools_core import _minimal_pe  # noqa: E402

import report_sections as rs  # noqa: E402


# --- component inventory --------------------------------------------------


def test_component_inventory_renders_pe(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_minimal_pe())
    text = rs.format_component_inventory(sample)

    assert "## Component Inventory" in text
    assert "PE32" in text
    assert "| Section | Raw | Virtual | Entropy | Flags | Role |" in text
    assert "| `.text` |" in text
    assert "executable code" in text
    assert "Structure only" in text  # honest scope note


def test_component_inventory_skips_non_pe(tmp_path):
    blob = tmp_path / "thing.bin"
    blob.write_bytes(b"\x00\x01\x02not a pe at all")
    assert rs.format_component_inventory(blob) == ""
    assert rs.format_component_inventory(tmp_path / "missing.exe") == ""
    assert rs.format_component_inventory(None) == ""


# --- analysis environment -------------------------------------------------


def _write_tools(case: Path, payload: dict) -> None:
    (case / "quick_scan").mkdir(parents=True, exist_ok=True)
    (case / "quick_scan" / "00-tools-raw.json").write_text(json.dumps(payload))


def test_analysis_environment_renders_versions_and_provenance(tmp_path):
    case = tmp_path / "case"
    _write_tools(case, {
        "capa": {"capa_bin": "/opt/capa/capa", "engine": "capa-rs"},
        "malcat": {"version": "3.1.0"},
        "floss": {"duration_s": 12.5},  # numbers must not be mistaken for versions
    })
    text = rs.format_analysis_environment(case, provenance={
        "commit": "abc1234", "engine": "langgraph"})

    assert "## Appendix: Analysis Environment" in text
    assert "RevAI commit" in text and "abc1234" in text
    assert "capa.capa_bin" in text and "/opt/capa/capa" in text
    assert "malcat.version" in text and "3.1.0" in text
    assert "duration_s" not in text
    assert "not a full environment manifest" in text


def test_analysis_environment_provenance_only_or_empty(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    assert rs.format_analysis_environment(case) == ""
    text = rs.format_analysis_environment(case, provenance={"commit": "deadbeef"})
    assert "deadbeef" in text and "| Component | Version |" not in text


# --- MBC vocabulary -------------------------------------------------------


def test_mbc_vocabulary_from_capa_metadata(tmp_path):
    case = tmp_path / "case"
    _write_tools(case, {"capa": {"top_rules": [{
        "name": "encode data using XOR",
        "mbc": [{"parts": ["Defense Evasion", "Obfuscated Files or Information",
                           "Encoding-Standard Algorithm"],
                 "objective": "Defense Evasion",
                 "behavior": "Obfuscated Files or Information",
                 "method": "Encoding-Standard Algorithm",
                 "id": "E1027.m02"}],
    }]}})
    text = rs.format_mbc_vocabulary(case)
    assert "## MBC Vocabulary (from capa rule metadata)" in text
    assert "E1027.m02" in text
    assert "Encoding-Standard Algorithm" in text
    assert "| MBC ID | Objective | Behavior | Method |" in text


def test_mbc_vocabulary_absent_is_empty(tmp_path):
    case = tmp_path / "case"
    _write_tools(case, {"capa": {"top_rules": [{"name": "no mbc here"}]}})
    assert rs.format_mbc_vocabulary(case) == ""
    assert rs.format_mbc_vocabulary(None) == ""


# --- attachment -----------------------------------------------------------


def test_attach_alignment_sections_is_additive_and_gated(tmp_path):
    # Nothing available -> unchanged.
    assert rs.attach_alignment_sections("body") == "body"

    case = tmp_path / "case"
    _write_tools(case, {
        "capa": {"top_rules": [{"mbc": [{"id": "B0001", "behavior": "Test"}]}]},
        "malcat": {"version": "9.9.9"},
    })
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_minimal_pe())

    out = rs.attach_alignment_sections("body", case_root=case, sample_path=sample,
                                       provenance={"commit": "c0ffee"})
    assert out.startswith("body")
    assert "## Component Inventory" in out
    assert "## MBC Vocabulary" in out
    assert "## Appendix: Analysis Environment" in out
    # Inventory precedes MBC precedes environment
    assert out.index("Component Inventory") < out.index("MBC Vocabulary")
    assert out.index("MBC Vocabulary") < out.index("Analysis Environment")


def test_attach_alignment_sections_resolves_sample_from_session(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    sample = tmp_path / "from_session.exe"
    sample.write_bytes(_minimal_pe())
    (case / "session.json").write_text(json.dumps({"sample_path": str(sample)}))
    out = rs.attach_alignment_sections("body", case_root=case)
    assert "## Component Inventory" in out


def test_attach_alignment_sections_survives_broken_input(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "quick_scan").mkdir()
    (case / "quick_scan" / "00-tools-raw.json").write_text("{not json")
    assert rs.attach_alignment_sections("body", case_root=case) == "body"
