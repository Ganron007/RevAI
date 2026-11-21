"""RC-97/A2 (2026-11-21): the unpacked payload reaches the SQL engines.

The operator's completeness standard: "we got malcat/Ghidra/IDA Pro with
which we should be able to decipher every piece of code within the PE."
idasql analyzes RAW BINARIES directly (the server bootstrap falls back to
`sample_path` when no .i64 exists), so the payload's function table is
reachable by IDA's SQL interface without a bootstrap pass — cross-engine
corroboration of malcat's enumeration, recorded as citable rows.

The pass is failure-safe (an engine that cannot open the payload is
recorded with its reason, never raised), gated on the recovery stage's own
enable flag, and closes its server so the recovery stage starts clean.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import deep_dive_agentic as DDA  # noqa: E402


class _FakeSqlClient:
    def __init__(self, rows=None, fail=False):
        self.rows = rows or []
        self.fail = fail
        self.closed: list[str] = []
        self.queries: list[str] = []

    def query_binary(self, binary_path, sql, max_rows=200, sha=None,
                     session_tag="payload"):
        self.queries.append(sql)
        if self.fail:
            raise RuntimeError("idasql HTTP unreachable: [Errno 111]")
        if "COUNT(*)" in sql:
            return {"rows": [{"n": len(self.rows)}]}
        return {"rows": self.rows[:max_rows]}

    def close(self, sid):
        self.closed.append(sid)


@pytest.fixture()
def sql_env(monkeypatch):
    monkeypatch.setenv("REVAI_ENABLE_AGENTIC_RECOVERY", "1")
    holder = {}

    def install(client):
        holder["client"] = client
        import ida_sql_client as ISC
        monkeypatch.setattr(ISC, "get_ida_sql_client", lambda: client)
        return client

    return holder, install


def _run_pass(tools_raw, findings, history, sha="a" * 64, tmp_path=None):
    payload = Path(tmp_path or Path.cwd()) / "payload.exe"
    if not payload.is_file():
        payload.write_bytes(b"\x4D\x5A\x90\x00" + b"\x00" * 64)
    DDA._run_payload_feedback_pass(
        upx_r={"upx_ok": True, "unpacked_path": str(payload)},
        findings=findings, tools_raw=tools_raw, history=history, sha=sha)


def test_payload_sql_pass_records_the_function_table(sql_env, monkeypatch, tmp_path):
    holder, install = sql_env
    install(_FakeSqlClient(rows=[{"addr": 4096, "name": "start"},
                                 {"addr": 4200, "name": "resolve_apis"}]))
    monkeypatch.setattr(DDA, "run_post_upx_second_pass",
                        lambda path, profile="deep": {
                            "ok": True, "tool_ok": True,
                            "tools": {"malcat": {"file_summary": {}}}})
    tools_raw, findings, history = {}, {}, []
    _run_pass(tools_raw, findings, history, tmp_path=tmp_path)
    rec = tools_raw.get("payload_sql") or {}
    assert rec.get("ok") is True
    assert rec.get("function_count") == 2
    assert len(rec.get("functions") or []) == 2
    assert rec["functions"][0]["name"] == "start"
    assert holder["client"].closed, (
        "the payload server is closed so the recovery stage starts clean")


def test_sql_failure_is_recorded_never_raised(sql_env, tmp_path):
    holder, install = sql_env
    install(_FakeSqlClient(fail=True))
    tools_raw, findings, history = {}, {}, []
    _run_pass(tools_raw, findings, history, tmp_path=tmp_path)  # must not raise
    rec = tools_raw.get("payload_sql") or {}
    assert rec.get("ok") is False
    assert "idasql HTTP unreachable" in (rec.get("error") or "")
    assert any(h.get("tool") == "payload_sql" for h in history)


def test_gate_off_skips_without_a_server(monkeypatch, tmp_path):
    monkeypatch.delenv("REVAI_ENABLE_AGENTIC_RECOVERY", raising=False)
    monkeypatch.delenv("ENABLE_AGENTIC_RECOVERY", raising=False)
    tools_raw, findings, history = {}, {}, []
    _run_pass(tools_raw, findings, history, tmp_path=tmp_path)
    rec = tools_raw.get("payload_sql") or {}
    assert rec.get("skipped_reason") == (
        "not_applicable:REVAI_ENABLE_AGENTIC_RECOVERY off")
    assert "payload_feedback" in tools_raw, (
        "the static tools still ran")


def test_no_payload_means_no_sql_bookkeeping(monkeypatch):
    monkeypatch.setenv("REVAI_ENABLE_AGENTIC_RECOVERY", "1")
    tools_raw, findings, history = {}, {}, []
    DDA._run_payload_feedback_pass(
        upx_r={}, findings=findings, tools_raw=tools_raw, history=history,
        sha="a" * 64)
    assert "payload_sql" not in tools_raw, (
        "a payload-less run leaves no bookkeeping key in its evidence")
