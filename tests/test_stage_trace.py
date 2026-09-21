#!/usr/bin/env python3
"""Regression (rehearsal 2026-09-22): stage_trace must never report green from a
stale audit file. An aborted run left `all_green=True` (and exit 0) because the
trace reader found the previous run's pipeline-audit.json on disk."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from pipeline_single import finalize_trace  # noqa: E402


def _trace(stages):
    return {"sha256": "a" * 64, "stages": stages}


def test_aborted_run_is_not_green_despite_stale_audit(tmp_path):
    audit = tmp_path / "pipeline-audit.json"
    audit.write_text('{"all_green": true, "stage_ok": {"intake": true}}')
    trace = _trace([
        {"stage": "intake", "rc": 0, "ok": True},
        {"stage": "quick_scan", "rc": 0, "ok": True},
        {"stage": "deep_dive", "rc": 1, "ok": False},
    ])
    out = finalize_trace(trace, audit)
    assert out["all_green"] is False
    assert out["aborted"] is True
    assert "deep_dive" in out["aborted_reason"]
    assert out["stage_ok"]["deep_dive"] is False


def test_stale_audit_ignored_when_audit_stage_missing(tmp_path):
    audit = tmp_path / "pipeline-audit.json"
    audit.write_text('{"all_green": true}')
    out = finalize_trace(_trace([{"stage": "intake", "rc": 0, "ok": True}]), audit)
    assert out["all_green"] is False
    assert "audit stage did not run" in out["aborted_reason"]


def test_fresh_audit_is_used(tmp_path):
    audit = tmp_path / "pipeline-audit.json"
    audit.write_text('{"all_green": true, "stage_ok": {"intake": true}}')
    out = finalize_trace(
        _trace([
            {"stage": "intake", "rc": 0, "ok": True},
            {"stage": "audit", "rc": 0, "ok": True},
        ]),
        audit,
    )
    assert out["all_green"] is True
    assert out["stage_ok"] == {"intake": True}


def test_failed_audit_is_not_green(tmp_path):
    audit = tmp_path / "pipeline-audit.json"
    audit.write_text('{"all_green": true}')
    out = finalize_trace(
        _trace([
            {"stage": "intake", "rc": 0, "ok": True},
            {"stage": "audit", "rc": 1, "ok": False},
        ]),
        audit,
    )
    assert out["all_green"] is False
    assert "audit stage rc=1" in out["aborted_reason"]
