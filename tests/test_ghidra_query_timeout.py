#!/usr/bin/env python3
"""A wedged ghidrasql request must cost seconds, not the 900 s bulk default.

Observed 2026-09-28 on winservices: during the recovery context phase a query
was accepted by the ghidrasql HTTP server and then never answered. The java
process sat at a constant CPU time (00:00:35 across a 45 s sample) while the
client blocked in poll. Two such stalls cost 439 s each, and the only thing that
would have released them was the 900 s QUERY_TIMEOUT in ghidra_sql_client --
sized for whole-program queries, not for a per-function pseudocode lookup.

So: per-function context queries get their own bound, one retry, and a loud
error row rather than an exception that unwinds the stage.
"""
from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import ghidra_sql_client as gsql  # noqa: E402
from recovery import context_builder as cbmod  # noqa: E402


class _SilentHandler(BaseHTTPRequestHandler):
    """Accepts the request and never replies -- the failure being pinned."""

    def do_POST(self):  # noqa: N802
        try:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
        except Exception:
            pass
        # deliberately no response

    def log_message(self, *a):
        pass


def _stalling_server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _SilentHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


class _Client:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.calls: list[int | None] = []

    def ghidra_query(self, session_id, sql, max_rows=200, timeout=None):
        self.calls.append(timeout)
        req = gsql.urllib.request.Request(
            f"{self.base_url}/query", data=sql.encode(),
            headers={"Content-Type": "text/plain"}, method="POST")
        try:
            with gsql.urllib.request.urlopen(req, timeout=timeout) as resp:
                return {"rows": []}
        except (TimeoutError, socket.timeout, OSError) as e:
            raise RuntimeError(f"ghidrasql query timed out after {timeout}s") from e


def test_context_queries_use_the_tight_bound():
    assert 15 <= cbmod.CONTEXT_QUERY_TIMEOUT_S <= 600, (
        f"context bound is {cbmod.CONTEXT_QUERY_TIMEOUT_S}s; it must be far "
        f"below the {gsql.QUERY_TIMEOUT}s bulk default")
    assert cbmod.CONTEXT_QUERY_TIMEOUT_S < gsql.QUERY_TIMEOUT


def test_env_override_is_honored(monkeypatch):
    monkeypatch.setenv("REVAI_GHIDRA_CONTEXT_TIMEOUT_S", "240")
    assert cbmod._context_query_timeout() == 240
    monkeypatch.setenv("REVAI_GHIDRA_CONTEXT_TIMEOUT_S", "not-a-number")
    assert cbmod._context_query_timeout() == 120      # falls back
    monkeypatch.setenv("REVAI_GHIDRA_CONTEXT_TIMEOUT_S", "1")
    assert cbmod._context_query_timeout() == 15       # floored


def test_one_wedged_query_returns_an_error_row_and_retries(monkeypatch):
    """The stall must surface as data, bounded, after exactly one retry."""
    srv, base_url = _stalling_server()
    monkeypatch.setenv("REVAI_GHIDRA_CONTEXT_TIMEOUT_S", "1")
    client = _Client(base_url)
    cb = cbmod.ContextBuilder(client, "s1")
    try:
        rows = cb._query("SELECT 1", max_rows=1)
    finally:
        srv.shutdown()
    assert len(rows) == 1 and "error" in rows[0], rows
    assert "timed out" in rows[0]["error"].lower(), rows[0]["error"]
    # the floor is 15s, so the bound passed down must be that, twice: one call
    # and exactly one retry -- not a retry storm
    assert client.calls == [15, 15], client.calls


def test_ghidra_query_names_the_timeout_in_its_error(monkeypatch, tmp_path):
    """A socket timeout must be readable in the error, not a bare OSError."""
    srv, base_url = _stalling_server()
    gpr = tmp_path / "p.gpr"
    gpr.write_text("x", encoding="utf-8")
    monkeypatch.setattr(gsql, "case_dir", lambda sha: tmp_path)
    monkeypatch.setattr(gsql, "_resolve_session",
                        lambda sid: {"session_id": sid, "gpr_path": str(gpr),
                                     "sha256": "b" * 64})
    client = gsql.GhidraSqlClient()
    monkeypatch.setattr(client, "_ensure_server", lambda s: base_url)
    try:
        try:
            client.ghidra_query("s1", "SELECT 1", timeout=1)
        except RuntimeError as exc:
            msg = str(exc)
        else:
            raise AssertionError("expected a RuntimeError")
    finally:
        srv.shutdown()
    assert "timed out after 1s" in msg, msg
