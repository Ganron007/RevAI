#!/usr/bin/env python3
"""The audit must fail an explicitly schema-less report, but read old reports.

`schema_used` is written by the claim-level publishers. Reports produced before
the schema existed do not carry the key; they stay readable for historical
cases. An explicit False is different: the publisher knows it fell back to
free-form Markdown or lost a model-authored section.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import add_module_dir  # noqa: E402

add_module_dir("revai/audit_pipeline.py")
from audit_pipeline import _schema_provenance_checks  # noqa: E402


def test_absent_schema_flags_are_legacy_compatible():
    checks = _schema_provenance_checks({}, {}, {}, {})
    assert all(checks.values()), checks


def test_explicit_schema_used_passes():
    checks = _schema_provenance_checks(
        {"schema_used": True}, {"schema_used": True},
        {"schema_used": True}, {"schema_used": True})
    assert all(checks.values()), checks


def test_explicit_schema_false_fails_each_report():
    checks = _schema_provenance_checks(
        {"schema_used": False}, {"schema_used": False},
        {"schema_used": False}, {"schema_used": False})
    assert checks == {
        "master_schema_ok": False,
        "master_v3_schema_ok": False,
        "tech2_schema_ok": False,
        "tech3_schema_ok": False,
    }
