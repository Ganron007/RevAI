#!/usr/bin/env python3
"""One Ghidra server per process, and Ghidra work off the worker threads.

Incident (2026-09-28, sample winservices, agentic_recover_v4): the function
naming pool runs 8 workers that share one `GhidraSqlClient`. ghidrasql is
single-tenant per .gpr - it takes an exclusive GPR lock - and `_ensure_server`
only recorded a started server *after* it was healthy. So all 8 threads saw
"no server", each started its own, and each killed the others' (the reuse-miss
path calls `_kill_pid` / `_kill_any_ghidrasql`). The evidence in
ghidrasql-server.log: 108 x

    ERROR Abort due to Headless analyzer error:
    ghidra.framework.store.LockException: Unable to lock project!

with the java server PID churning (11230 -> 15137) and every worker parked in
do_poll until the 900 s QUERY_TIMEOUT. The stage produced no function context
at all, so a "green" run would have been a fake green.

These tests pin the two invariants that prevent a repeat.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import ghidra_sql_client as gsql  # noqa: E402


class _FakeProc:
    """Stands in for the ghidrasql Popen handle."""

    def __init__(self, pid: int = 4242):
        self.pid = pid
        self.returncode = None

    def poll(self):
        return None


def _stub_server_layer(monkeypatch, tmp_path, popen_calls, kill_calls):
    """Neutralize everything that would touch a real ghidrasql/Ghidra."""
    gpr = tmp_path / "proj.gpr"
    gpr.write_text("stub", encoding="utf-8")
    monkeypatch.setattr(gsql, "case_dir", lambda sha: tmp_path)
    monkeypatch.setattr(gsql, "_port_in_use", lambda port: False)
    monkeypatch.setattr(gsql, "_probe", lambda url, timeout=1.5: True)
    monkeypatch.setattr(gsql.GhidraSqlClient, "_find_existing_ghidrasql",
                        staticmethod(lambda stem: None))

    def _fake_popen(cmd, **kwargs):
        popen_calls.append(cmd)
        return _FakeProc()

    monkeypatch.setattr(gsql.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(gsql.GhidraSqlClient, "_kill_pid",
                        staticmethod(lambda pid: kill_calls.append(("pid", pid))))
    monkeypatch.setattr(gsql.GhidraSqlClient, "_kill_any_ghidrasql",
                        staticmethod(lambda: kill_calls.append(("any", None))))
    return {"session_id": "s1", "gpr_path": str(gpr), "sha256": "a" * 64}


def test_concurrent_ensure_server_starts_exactly_one(monkeypatch, tmp_path):
    """8 threads, one project -> one server start, zero kill-storm."""
    popen_calls: list = []
    kill_calls: list = []
    session = _stub_server_layer(monkeypatch, tmp_path, popen_calls, kill_calls)
    gsql._SHARED_SERVERS.clear()

    client = gsql.GhidraSqlClient()
    urls: list[str] = []
    errors: list[str] = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)      # maximize the overlap
            urls.append(client._ensure_server(session))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len(urls) == 8
    # The actual bug was N starts and N kill passes.
    assert len(popen_calls) == 1, f"started {len(popen_calls)} servers, want 1"
    # The one thread that starts the server may sweep other projects first
    # (pre-existing behavior); what must never happen is killing a server that
    # this process already owns and other threads are querying.
    assert not [k for k in kill_calls if k[0] == "pid"], kill_calls
    assert len([k for k in kill_calls if k[0] == "any"]) <= 1, kill_calls
    assert len(set(urls)) == 1, f"threads disagreed on the server: {set(urls)}"
    gsql._SHARED_SERVERS.clear()


def test_second_client_instance_reuses_the_running_server(monkeypatch, tmp_path):
    """A second client in the same process must adopt, not start a rival."""
    popen_calls: list = []
    kill_calls: list = []
    session = _stub_server_layer(monkeypatch, tmp_path, popen_calls, kill_calls)
    gsql._SHARED_SERVERS.clear()

    first = gsql.GhidraSqlClient()
    url_a = first._ensure_server(session)
    kill_calls.clear()          # the first start may sweep other projects
    second = gsql.GhidraSqlClient()
    url_b = second._ensure_server(session)

    assert url_a == url_b
    assert len(popen_calls) == 1, f"rival server started: {len(popen_calls)}"
    assert not kill_calls, f"a live shared server was killed: {kill_calls}"
    gsql._SHARED_SERVERS.clear()


def test_close_does_not_kill_a_server_other_sessions_use(monkeypatch, tmp_path):
    """close() releases the claim; only close_all() tears the server down."""
    popen_calls: list = []
    kill_calls: list = []
    session = _stub_server_layer(monkeypatch, tmp_path, popen_calls, kill_calls)
    gsql._SHARED_SERVERS.clear()

    client = gsql.GhidraSqlClient()
    client._ensure_server(session)
    kill_calls.clear()          # the first start may sweep other projects
    client.close(session["session_id"])
    assert not kill_calls, f"close() killed a shared server: {kill_calls}"

    client._ensure_server(session)          # re-claim
    client.close_all()
    assert kill_calls, "close_all() must still tear the server down"
    gsql._SHARED_SERVERS.clear()


def test_analyze_function_uses_prebuilt_context(monkeypatch):
    """The LLM phase must not re-query Ghidra (that is phase 1's job)."""
    sys.path.insert(0, str(ROOT / "revai"))
    import agentic_recover_v4 as ar

    built: list = []

    class _CB:
        def build(self, *a, **kw):
            built.append(a)
            raise AssertionError("Ghidra queried from the LLM phase")

    prebuilt = {
        "target_address": "0x401000", "target_name": "FUN_401000",
        "target_size": 42, "obfuscation": {}, "normalized_pseudocode": "x",
        "raw_pseudocode": "x", "string_refs": {}, "data_xrefs": {},
        "callees": {}, "callers": {}, "neighbors": {},
    }
    seen: dict = {}

    def _fake_judge(prompt, model=None):
        seen["prompt"] = prompt
        return {"choices": [{"message": {"content": (
            '{"function_name":"net_send","confidence":0.9,'
            '"parameters":[],"return_type":"int","notes":"",'
            '"behavior_tags":["network"]}')}}]}

    monkeypatch.setattr(ar, "llm_judge", _fake_judge)
    monkeypatch.setattr(ar, "llm_call_metadata", lambda resp: {})

    rec = ar.analyze_function(
        {"address": "4198400"}, {"obfuscation": {}}, {},
        "SYS", "USER {{target_name}}", "m", _CB(), prebuilt_ctx=prebuilt)

    assert not built, "prebuilt context was ignored; Ghidra was queried again"
    assert rec["function_name"] == "net_send"
    assert "net_send" in seen["prompt"] or "FUN_401000" in seen["prompt"]
    assert rec["source"] == "llm_judge"
