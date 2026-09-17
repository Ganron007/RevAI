#!/usr/bin/env python3
"""Regression: deterministic per-IOC confidence block in technical reports (#14e).

Covers the pure formatter, presence gating (no iocs.json -> report unchanged),
mode-aware lookup and the opt-out env switch.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402
from v2_lib import attach_ioc_confidence, format_ioc_confidence_block  # noqa: E402

SHA = "b" * 64

BLOCK = {
    "version": 1,
    "counts": {"high": 1, "medium": 1, "low": 1},
    "items": [
        {"type": "ip", "value": "10[.]0[.]0[.]5", "tier": "low", "score": 30,
         "reasons": ["private address range (RFC1918)"]},
        {"type": "domain", "value": "evil-c2[.]biz", "tier": "high", "score": 95,
         "reasons": ["host component of an extracted URL",
                     "appears in more than one indicator type"]},
        {"type": "file", "value": "dropper.exe", "tier": "medium", "score": 60,
         "reasons": ["filename pattern from string evidence"]},
    ],
}


def test_formatter_empty_block():
    assert format_ioc_confidence_block({}) == ""
    assert format_ioc_confidence_block({"confidence": {"items": []}}) == ""


def test_formatter_orders_tiers_and_caps():
    text = format_ioc_confidence_block({"confidence": BLOCK}, limit=2)
    assert "Indicator confidence (deterministic)" in text
    assert "Counts: high 1, medium 1, low 1." in text
    lines = [ln for ln in text.splitlines() if ln.startswith("| ")]
    # header row, then data rows in tier order (high before medium)
    assert lines[0].startswith("| Type |")
    assert lines[1].startswith("| domain | evil-c2[.]biz | high |")
    assert lines[2].startswith("| file | dropper.exe | medium |")
    assert "1 more indicators" in text
    # low tier is pushed out by the cap
    assert "10[.]0[.]0[.]5" not in text


def test_attach_is_gated_on_iocs_json(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path)
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    (tmp_path / SHA).mkdir()
    md = "# Report\nbody\n"
    assert attach_ioc_confidence(md, SHA) == md  # no iocs.json -> unchanged


def test_attach_appends_when_confidence_present(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path)
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    case = tmp_path / SHA
    case.mkdir()
    (case / "iocs.json").write_text(json.dumps({"urls": [], "confidence": BLOCK}))
    md = "# Report\nbody"
    out = attach_ioc_confidence(md, SHA)
    assert out.startswith("# Report")
    assert "Indicator confidence (deterministic)" in out
    assert "evil-c2[.]biz" in out


def test_attach_is_mode_aware(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path)
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    case = tmp_path / SHA / "agentic"
    case.mkdir(parents=True)
    (case / "iocs.json").write_text(json.dumps({"confidence": BLOCK}))
    out = attach_ioc_confidence("body", SHA)
    assert "Indicator confidence (deterministic)" in out


def test_attach_opt_out_env(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path)
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    monkeypatch.setenv("REVAI_DISABLE_IOC_CONFIDENCE", "1")
    case = tmp_path / SHA
    case.mkdir()
    (case / "iocs.json").write_text(json.dumps({"confidence": BLOCK}))
    assert attach_ioc_confidence("body", SHA) == "body"


def test_attach_ignores_malformed_iocs(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path)
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    case = tmp_path / SHA
    case.mkdir()
    (case / "iocs.json").write_text("{not json")
    assert attach_ioc_confidence("body", SHA) == "body"
