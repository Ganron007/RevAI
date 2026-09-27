"""Regression: the attempt-1 syntax error must not poison the final #11 status.

Found by the 2026-09-27 six-sample campaign: fgg_js reported status="failed" even
though the correction pass ran cleanly and produced 2 re-derived artifacts, because
a single `syntax_ok` flag was set on attempt 1 and never reset.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import artifact_gen as ag  # noqa: E402

SHA = "c" * 64


def _stage(tmp: Path, monkeypatch) -> tuple[Path, Path]:
    case = tmp / SHA
    (case / "artifact_gen").mkdir(parents=True)
    sample = tmp / "sample.bin"
    sample.write_bytes(b"MZ" + b"payload-bytes-here" + b"\x00" * 32)
    monkeypatch.setattr(ag, "load_session", lambda _s: {"sample_path": str(sample)})
    monkeypatch.setattr(ag, "case_dir", lambda _s, mode=None: case)
    monkeypatch.setattr(ag, "revai_provenance", lambda: {"commit": "test"})
    monkeypatch.setattr(ag, "hitl_checkpoint", lambda *a, **k: {})
    return case, sample


def _response(script: str) -> dict:
    return {"choices": [{"message": {"content": json.dumps({
        "applicability": "applicable", "targets": ["t"], "script": script})}}]}


GOOD = ("import json, sys\n"
        "data = open(sys.argv[1], 'rb').read()\n"
        "value = data[2:16].decode()\n"
        "json.dump({'artifacts': [{'kind': 'config', 'value': value, 'offset': 2,\n"
        "                          'method': 'raw'}]}, open(sys.argv[2] + '/result.json', 'w'))\n")


def test_syntax_error_on_attempt_one_then_good_retry_is_ran(tmp_path, monkeypatch):
    """The campaign bug: attempt 1 unparseable, attempt 2 clean -> status ran."""
    case, _ = _stage(tmp_path, monkeypatch)
    calls = {"n": 0}

    def fake_llm(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            return _response("def broken(:\n  pass\n")     # SyntaxError
        return _response(GOOD)

    monkeypatch.setattr(ag, "llm_judge", fake_llm)
    summary = ag.run_stage(SHA, force=True)

    assert summary["status"] == "ran", summary
    assert summary["syntax_ok"] is True
    assert summary["artifacts_total"] == 1
    assert summary["artifacts_verified"] == 1
    assert len(summary["attempts"]) == 2
    assert "syntax_error" in summary["attempts"][0]


def test_unparseable_after_both_attempts_is_not_applicable_not_failed(tmp_path, monkeypatch):
    case, _ = _stage(tmp_path, monkeypatch)
    monkeypatch.setattr(ag, "llm_judge", lambda *a, **k: _response("def broken(:\n"))
    summary = ag.run_stage(SHA, force=True)
    assert summary["status"] == "not_applicable"
    assert "not valid Python" in summary["reason"]
    assert summary["ok"] is True          # nothing failed in the pipeline
    assert summary["artifacts_total"] == 0


def test_script_that_finds_nothing_is_not_applicable(tmp_path, monkeypatch):
    """Ran fine, claimed nothing: honest 'nothing extractable', not a failure."""
    case, _ = _stage(tmp_path, monkeypatch)
    empty = "import json, sys\njson.dump({'artifacts': []}, open(sys.argv[2] + '/result.json', 'w'))\n"
    monkeypatch.setattr(ag, "llm_judge", lambda *a, **k: _response(empty))
    summary = ag.run_stage(SHA, force=True)
    assert summary["status"] == "not_applicable"
    assert "claimed no extractable artifact" in summary["reason"]
    assert summary["ok"] is True


def test_crashing_script_is_failed(tmp_path, monkeypatch):
    """A script that actually errors is a real failure and says so."""
    case, _ = _stage(tmp_path, monkeypatch)
    boom = "raise SystemExit(3)\n"
    monkeypatch.setattr(ag, "llm_judge", lambda *a, **k: _response(boom))
    summary = ag.run_stage(SHA, force=True)
    assert summary["status"] == "failed"
    assert summary["execution"]["rc"] == 3
    assert summary["ok"] is False
