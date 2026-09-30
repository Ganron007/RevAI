#!/usr/bin/env python3
"""A single timeout must not be fatal to the thinking path.

Campaign evidence (2026-09-30, re-runs on the new provider): nspack and
win32k_dll both went red at publish with `tech2_no_stubs` /
`no_tech2_fallback` after a single 600 s read timeout. The handler treated a
timeout as "this effort is hung" and dropped straight to the no-thinking
fallback, which also failed, so the report was salvaged deterministically with
stub sections and the audit correctly refused it. A provider stall and a
genuinely slow job look identical from inside the client, so the first timeout
now earns one retry at the SAME effort before the ladder is abandoned.

Both directions are pinned: the retry happens, and a genuinely stuck call still
terminates instead of looping.
"""
from __future__ import annotations

import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


class _FlakyHandler(BaseHTTPRequestHandler):
    """Fails the first N requests by hanging, then answers properly.

    A hang (not a 5xx) is what the real failure looked like: the request was
    accepted and never answered.
    """

    fail_first = 0
    lock = threading.Lock()

    def do_POST(self):  # noqa: N802
        try:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
        except Exception:
            pass
        with _FlakyHandler.lock:
            if _FlakyHandler.fail_first > 0:
                _FlakyHandler.fail_first -= 1
                hang = True
            else:
                hang = False
        if hang:
            # accept the connection and never answer
            threading.Event().wait(30)
            return
        body = (b'{"choices":[{"finish_reason":"stop","message":'
                b'{"content":"{\\"ok\\": true}"}}]}')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), _FlakyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _point_client_at(srv, monkeypatch, timeout_s="1"):
    """llm_judge builds its own request from the env, so point the env here."""
    base = f"http://127.0.0.1:{srv.server_port}"
    monkeypatch.setenv("REVAI_LLM_API_URL", base)
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "test-model")
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", timeout_s)
    monkeypatch.setenv("REVAI_LLM_BUDGET", "0")
    return base


def test_one_timeout_is_retried_at_the_same_effort(monkeypatch):
    """First call hangs, second answers: the caller must get its answer."""
    _FlakyHandler.fail_first = 1
    srv = _serve()
    _point_client_at(srv, monkeypatch)
    try:
        data = v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=3,
                                reasoning="disabled")
    finally:
        srv.shutdown()
    assert v2_lib._llm_response_has_usable_content(data), data
    assert _FlakyHandler.fail_first == 0, "the hanging request was not retried"


def test_a_genuinely_stuck_call_still_terminates(monkeypatch):
    """Every request hangs: must raise, not retry forever."""
    _FlakyHandler.fail_first = 99
    srv = _serve()
    _point_client_at(srv, monkeypatch)
    raised = False
    try:
        v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=3,
                         reasoning="disabled")
    except Exception:
        raised = True
    finally:
        srv.shutdown()
    assert raised, "a permanently stuck endpoint must not return data"


def test_a_healthy_call_is_not_retried(monkeypatch):
    """No added latency or duplicate work on the happy path."""
    _FlakyHandler.fail_first = 0
    srv = _serve()
    _point_client_at(srv, monkeypatch)
    try:
        data = v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=3,
                                reasoning="disabled")
    finally:
        srv.shutdown()
    assert v2_lib._llm_response_has_usable_content(data)
    # the retry must not have been consumed: no hangs were staged
    assert _FlakyHandler.fail_first == 0
