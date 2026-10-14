"""Regression tests for the bounded, bidirectional environment contract check."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import verify_pipeline as vp  # noqa: E402


def _run_contract(tmp_path, monkeypatch, source, docs):
    repo = tmp_path / "repo"
    code = repo / "revai"
    docs_dir = repo / "docs"
    code.mkdir(parents=True)
    docs_dir.mkdir()
    (code / "example.py").write_text(source, encoding="utf-8")
    (docs_dir / "CONFIGURE.md").write_text(docs, encoding="utf-8")
    monkeypatch.setattr(vp, "REPO", repo)
    monkeypatch.setattr(vp, "CODE", code)
    vp.RESULTS.clear()
    vp.FAILURES.clear()
    vp.WARNINGS.clear()
    vp.check_env_contract()
    return next(result for result in vp.RESULTS
                if result["check"] == "env.documented")


def test_env_contract_resolves_constants_and_simple_helper_indirection(tmp_path, monkeypatch):
    source = '''import os
KEY = "REVAI_INDIRECT"
def read_env(name):
    return os.getenv(name)
def wrapper(name):
    return read_env(name)
def run():
    return wrapper(KEY)
'''
    result = _run_contract(
        tmp_path, monkeypatch, source,
        "`REVAI_INDIRECT` is read by the pipeline.\n",
    )

    assert result["ok"] is True
    assert "REVAI_INDIRECT" in vp._env_reads_in_python(
        vp.CODE / "example.py")


def test_env_contract_catches_documented_name_absent_from_runtime_source(tmp_path, monkeypatch):
    source = '''import os
os.environ.get("REVAI_ACTUAL")
'''
    result = _run_contract(
        tmp_path, monkeypatch, source,
        "`REVAI_ACTUAL` works. `REVAI_INVENTED` is also supported.\n",
    )

    assert result["ok"] is False
    assert "REVAI_INVENTED" in result["detail"]
