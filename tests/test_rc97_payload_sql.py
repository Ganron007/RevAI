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


class _FakeGhidraSqlClient:
    def __init__(self, rows=None, fail=False):
        self.rows = rows or []
        self.fail = fail
        self.queries = []

    def query_binary(self, binary_path, sql, max_rows=200, *, sha=None, timeout=180):
        self.queries.append((binary_path, sql, sha))
        if self.fail:
            raise RuntimeError("ghidrasql headless crashed")
        return {"rows": self.rows[:max_rows]}


def test_payload_sql_pass_records_ghidra_corroboration(sql_env, monkeypatch, tmp_path):
    _, install = sql_env
    install(_FakeSqlClient(rows=[{"addr": 4096, "name": "start"}]))
    import ghidra_sql_client as GSC
    fake_g = _FakeGhidraSqlClient(rows=[
        {"n": "428", "addr": "4198652", "name": "thunk_FUN_0040110e"},
        {"n": "428", "addr": "4198670", "name": "FUN_0040110e"},
    ])
    monkeypatch.setattr(GSC, "get_ghidra_sql_client", lambda: fake_g)
    monkeypatch.setattr(DDA, "run_post_upx_second_pass",
                        lambda path, profile="deep": {
                            "ok": True, "tool_ok": True,
                            "tools": {"malcat": {"file_summary": {}}}})
    tools_raw, findings, history = {}, {}, []
    _run_pass(tools_raw, findings, history, tmp_path=tmp_path)
    rec = tools_raw.get("payload_sql") or {}
    gh = rec.get("ghidra") or {}
    assert gh.get("ok") is True
    assert gh.get("engine") == "ghidrasql"
    assert gh.get("function_count") == 428
    assert len(gh.get("functions") or []) == 2
    assert gh["functions"][0] == {"addr": "4198652", "name": "thunk_FUN_0040110e"}
    assert len(fake_g.queries) == 1
    assert history[-1]["result"]["ghidra_function_count"] == 428


def test_ghidra_payload_sql_failure_is_recorded_never_raised(sql_env, monkeypatch, tmp_path):
    _, install = sql_env
    install(_FakeSqlClient(rows=[{"addr": 4096, "name": "start"}]))
    import ghidra_sql_client as GSC
    monkeypatch.setattr(GSC, "get_ghidra_sql_client", lambda: _FakeGhidraSqlClient(fail=True))
    monkeypatch.setattr(DDA, "run_post_upx_second_pass",
                        lambda path, profile="deep": {
                            "ok": True, "tool_ok": True,
                            "tools": {"malcat": {"file_summary": {}}}})
    tools_raw, findings, history = {}, {}, []
    _run_pass(tools_raw, findings, history, tmp_path=tmp_path)
    rec = tools_raw.get("payload_sql") or {}
    assert rec.get("ok") is True
    gh = rec.get("ghidra") or {}
    assert gh.get("ok") is False
    assert "ghidrasql headless crashed" in (gh.get("error") or "")


def test_ghidra_query_binary_parses_cli_json(monkeypatch, tmp_path):
    import ghidra_sql_client as GSC
    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    fake_bin = tmp_path / "ghidrasql"
    fake_bin.write_text("#!/bin/sh\n")
    fake_home = tmp_path / "ghidra"
    fake_home.mkdir()
    monkeypatch.setattr(GSC, "GHIDRASQL_BIN", str(fake_bin))
    monkeypatch.setattr(GSC, "GHIDRA_HOME", str(fake_home))

    class _Proc:
        returncode = 0
        stdout = (
            "INFO  HEADLESS: execution starts\n"
            '{"columns":["n","addr","name"],"elapsed_ms":98,"partial":false,'
            '"row_count":2,"rows":[["428","4198652","entry"],["428","4198670","fn_1"]],"success":true}\n'
            "INFO  LibGhidraHeadlessServer.java> LIBGHIDRA_HEADLESS_EXIT\n"
        )

    captured = {}
    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(GSC.subprocess, "run", _fake_run)
    client = GSC.GhidraSqlClient()
    res = client.query_binary(str(sample), "SELECT COUNT(*) OVER() AS n, addr, name FROM funcs", sha="a" * 64)
    assert "--shutdown" in captured["cmd"] and "discard" in captured["cmd"]
    assert res["row_count"] == 2
    assert res["rows"][0] == {"n": "428", "addr": "4198652", "name": "entry"}
