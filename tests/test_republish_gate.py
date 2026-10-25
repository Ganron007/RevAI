"""RC-16 (operator decision 2026-10-25: allow a narrow republish).

A provider-stub publish failure used to consume the sample: the report-stage
stop guard blocks every publisher after a failure by design (the 2026-10-20
restart defect), so a transient provider 5xx permanently cost a fresh SHA. The
operator authorized ONE explicit, auditable re-run on UNCHANGED evidence for
the provider-stub class only. These tests pin the gate in both directions.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/publish_report_v2.py").parent))
import publish_report_v2  # noqa: E402

MANIFEST = "m" * 64


def _record(**overrides):
    record = {
        "schema": "publish-failure/v1",
        "class": "provider-stub",
        "manifest_sha256": MANIFEST,
        "master_stubs": ["8. IoCs"],
        "master_missing": [],
        "tech_stubs": ["10. MITRE"],
        "publish_source": "llm_incomplete",
        "verdict_lock_ok": True,
        "republish_count": 0,
    }
    record.update(overrides)
    return record


def _case(tmp_path, record):
    case = tmp_path / "logs" / ("a" * 64) / "agentic"
    case.mkdir(parents=True)
    (case / "publish-failure.json").write_text(
        json.dumps(record), encoding="utf-8")
    return case


def test_a_valid_provider_stub_record_authorizes_one_republish(tmp_path):
    case = _case(tmp_path, _record())
    record = publish_report_v2._authorize_republish(case, MANIFEST)
    assert record is not None
    # Consumed immediately: a republish that crashes has still used its shot.
    stored = json.loads((case / "publish-failure.json").read_text(encoding="utf-8"))
    assert stored["republish_count"] == 1
    assert stored.get("republished_at")


def test_a_consumed_authorization_denies_the_second_attempt(tmp_path):
    case = _case(tmp_path, _record(republish_count=1))
    assert publish_report_v2._authorize_republish(case, MANIFEST) is None


def test_a_non_stub_failure_class_is_never_authorized(tmp_path):
    case = _case(tmp_path, _record(**{
        "class": "other", "verdict_lock_ok": False}))
    assert publish_report_v2._authorize_republish(case, MANIFEST) is None


def test_changed_evidence_denies_the_republish(tmp_path):
    case = _case(tmp_path, _record())
    assert publish_report_v2._authorize_republish(case, "f" * 64) is None


def test_a_missing_or_malformed_record_denies(tmp_path):
    case = tmp_path / "logs" / ("a" * 64) / "agentic"
    case.mkdir(parents=True)
    assert publish_report_v2._authorize_republish(case, MANIFEST) is None
    (case / "publish-failure.json").write_text("not json", encoding="utf-8")
    assert publish_report_v2._authorize_republish(case, MANIFEST) is None


def test_stub_failures_with_a_green_lock_are_classified_provider_stub(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    publish_report_v2._record_publish_failure(
        case, MANIFEST, master_stubs=["8. IoCs"], master_missing=[],
        tech_stubs=["10. MITRE"], lock_ok=True, source="llm_incomplete")
    stored = json.loads((case / "publish-failure.json").read_text(encoding="utf-8"))
    assert stored["class"] == "provider-stub"
    assert stored["republish_count"] == 0


def test_a_verdict_conflict_is_classified_other(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    publish_report_v2._record_publish_failure(
        case, MANIFEST, master_stubs=[], master_missing=[],
        tech_stubs=[], lock_ok=False, source="llm_judge")
    stored = json.loads((case / "publish-failure.json").read_text(encoding="utf-8"))
    assert stored["class"] == "other"


def test_a_prior_consumed_count_is_carried_forward(tmp_path):
    """A second stub failure must not mint a fresh authorization."""
    case = _case(tmp_path, _record(republish_count=1))
    publish_report_v2._record_publish_failure(
        case, MANIFEST, master_stubs=["8. IoCs"], master_missing=[],
        tech_stubs=[], lock_ok=True, source="llm_incomplete")
    stored = json.loads((case / "publish-failure.json").read_text(encoding="utf-8"))
    assert stored["class"] == "provider-stub"
    assert stored["republish_count"] == 1
