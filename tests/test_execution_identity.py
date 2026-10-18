from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import audit_pipeline  # noqa: E402
import v2_lib  # noqa: E402


SHA = "c" * 64


def test_begin_execution_persists_and_resolves_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    # Register the pre-test value with monkeypatch before begin_execution writes
    # REVAI_RUN_ID directly. If the variable was initially absent, delenv alone
    # records no undo action, and the generated ID leaks into later tests when
    # this file is run outside tests/conftest.py (for example, as a stale
    # top-level copy left by an older deployment).
    monkeypatch.setenv("REVAI_RUN_ID", "invalid-test-run-id")
    monkeypatch.delenv("REVAI_RUN_ID", raising=False)
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")

    context = v2_lib.begin_execution(SHA, mode="agentic", engine="langgraph")
    path = tmp_path / "logs" / SHA / "agentic" / "execution-context.json"

    assert len(context["run_id"]) == 32
    assert path.is_file()
    assert json.loads(path.read_text())["run_id"] == context["run_id"]
    assert v2_lib.current_run_id(SHA) == context["run_id"]
    monkeypatch.delenv("REVAI_RUN_ID")
    assert v2_lib.revai_provenance(SHA)["run_id"] == context["run_id"]


def test_begin_execution_archives_prior_report_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    root = tmp_path / "logs" / SHA / "agentic"
    root.mkdir(parents=True)
    old_context = {
        "schema": "revai-execution-context/v1", "sha256": SHA,
        "run_id": "a" * 32, "mode": "agentic", "engine": "test",
        "started_at": "2026-10-17T00:00:00+00:00",
    }
    (root / "execution-context.json").write_text(json.dumps(old_context))
    (root / "REPORT-MASTER-v3.md").write_text("old report")
    (root / "section-results-v3.json").write_text("{}")
    (root / "verdict.json").write_text("{\"old\": true}")
    (root / "publish").mkdir()
    (root / "publish" / "report-output-manifest.json").write_text("{}")

    current = v2_lib.begin_execution(SHA, mode="agentic", engine="test")
    history = root / "publish" / "history" / f"{'a' * 32}-{current['run_id']}"

    assert not (root / "REPORT-MASTER-v3.md").exists()
    assert (history / "REPORT-MASTER-v3.md").read_text() == "old report"
    assert (history / "section-results-v3.json").is_file()
    assert (history / "verdict.json").is_file()
    assert (history / "publish" / "report-output-manifest.json").is_file()
    assert json.loads((root / "execution-context.json").read_text())["run_id"] == current["run_id"]


def test_begin_execution_rejects_malformed_shared_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    with pytest.raises(ValueError, match="32 lowercase hexadecimal"):
        v2_lib.begin_execution(SHA, mode="agentic", engine="langgraph", run_id="bad")


def test_audit_requires_reports_and_winre_pack_from_current_run(tmp_path):
    run_id = "a" * 32
    for name in (
        "report-v2.json", "report-technical-v2.json",
        "section-results-v3.json", "report-technical-v3.json",
    ):
        (tmp_path / name).write_text(json.dumps({"run_id": run_id}))
    (tmp_path / "winre-run.json").write_text(json.dumps({
        "run_id": run_id, "state": "ok", "pack_present": True,
        "pack_correlation": {"ok": True},
    }))

    assert audit_pipeline.audit_execution_identity(
        tmp_path, run_id, winre_requested=True)["ok"] is True

    (tmp_path / "winre-run.json").write_text(json.dumps({
        "run_id": "b" * 32, "state": "ok", "pack_present": True,
        "pack_correlation": {"ok": True},
    }))
    result = audit_pipeline.audit_execution_identity(
        tmp_path, run_id, winre_requested=True)
    assert result["ok"] is False
    assert result["checks"]["winre-run.json"] is False


def test_audit_separates_matching_winre_identity_from_failed_execution(tmp_path):
    run_id = "c" * 32
    for name in (
        "report-v2.json", "report-technical-v2.json",
        "section-results-v3.json", "report-technical-v3.json",
    ):
        (tmp_path / name).write_text(json.dumps({"run_id": run_id}))
    (tmp_path / "winre-run.json").write_text(json.dumps({
        "run_id": run_id, "state": "failed", "pack_present": True,
        "pack_correlation": {"ok": True},
    }))

    result = audit_pipeline.audit_execution_identity(
        tmp_path, run_id, winre_requested=True
    )

    assert result["ok"] is True
    assert result["checks"]["winre-run.json"] is True
    assert result["execution_status_ok"] is False
    assert result["execution_checks"]["winre-run.json"] is False
