#!/usr/bin/env python3
"""Streaming, caller-supplied timeouts, and retry-window budget clamping.

The problem these pin down, from 2026-09-30 to 2026-10-01:

  * A non-streaming request carries ZERO bytes until generation completes, so a
    socket that stays silent for the whole generation is indistinguishable from
    a dead one. Healthy-but-slow calls were logged as "timed out", retried, and
    blamed on the provider. Six such timeouts appeared across three runs and two
    samples, in five different stages -- not a sample-specific problem and not a
    provider hang (32768 non-streaming was later measured returning in 119s).

  * artifact_gen defined GEN_TIMEOUT_S=180 and never used it, and llm_judge had
    no timeout parameter, so the caller could not bound a call even in
    principle. The escalating retry then took 600s -> 1200s, which is EXACTLY
    artifact_gen's 1800s stage budget: the stage was killed by its own inner
    retry, rc=124.

The false-positive direction matters as much: a budget clamp must not silently
shrink a window that has room, and streaming must degrade cleanly when an
endpoint ignores stream=True rather than failing the call.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


# ------------------------------------------------------------ SSE reassembly

class _FakeResp:
    """Stands in for an HTTP response: iterable as SSE, readable as a body."""

    def __init__(self, lines, body: bytes | None = None):
        self._lines = lines
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        return iter(self._lines)

    def read(self):
        if self._body is not None:
            return self._body
        return b"".join(self._lines)


def _json_resp(payload: dict):
    return _FakeResp([], body=json.dumps(payload).encode())


def _sse(chunks, finish_reason: str = "stop"):
    out = []
    for c in chunks:
        out.append(b"data: " + json.dumps({
            "choices": [{"delta": {"content": c}, "finish_reason": None}]
        }).encode() + b"\n")
    out.append(b"data: " + json.dumps({
        "choices": [{"delta": {}, "finish_reason": finish_reason}]}).encode() + b"\n")
    out.append(b"data: [DONE]\n")
    return _FakeResp(out)


def _patch_urlopen(monkeypatch, handler):
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", handler)


def test_stream_is_reassembled_into_the_shape_callers_expect(monkeypatch):
    """Downstream reads choices[0].message.content and finish_reason."""
    _patch_urlopen(monkeypatch, lambda *a, **k: _sse(["Hello", " ", "world"]))
    data, metrics = v2_lib._post_llm_streaming(
        "http://x/v1/chat/completions", {}, {"model": "m"}, 60)
    assert data is not None
    ch = data["choices"][0]
    assert ch["message"]["content"] == "Hello world"
    assert ch["finish_reason"] == "stop", ch
    assert metrics["streamed"] is True
    assert metrics["chars"] == 11
    assert metrics["chunks"] == 4, "3 content chunks + the finish_reason chunk"


def test_role_and_usage_are_carried_through(monkeypatch):
    resp = _FakeResp([
        b'data: ' + json.dumps({"choices": [
            {"delta": {"role": "assistant", "content": "x"},
             "finish_reason": None}]}).encode() + b"\n",
        b'data: ' + json.dumps({
            "choices": [{"delta": {}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 1234}}).encode() + b"\n",
        b"data: [DONE]\n",
    ])
    _patch_urlopen(monkeypatch, lambda *a, **k: resp)
    data, _ = v2_lib._post_llm_streaming("http://x/v1", {}, {}, 60)
    assert data["choices"][0]["message"]["role"] == "assistant"
    assert data["usage"]["total_tokens"] == 1234, data


def test_malformed_sse_lines_are_skipped_not_fatal(monkeypatch):
    resp = _FakeResp([
        b"event: ping\n",
        b"data: {not json}\n",
        b'data: ' + json.dumps({"choices": [
            {"delta": {"content": "ok"}, "finish_reason": None}]}).encode() + b"\n",
        b"data: [DONE]\n",
    ])
    _patch_urlopen(monkeypatch, lambda *a, **k: resp)
    data, _ = v2_lib._post_llm_streaming("http://x/v1", {}, {}, 60)
    assert data["choices"][0]["message"]["content"] == "ok"


def test_endpoint_that_ignores_stream_returns_none_so_caller_falls_back(monkeypatch):
    """A JSON body instead of SSE must not be mistaken for an empty answer."""
    _patch_urlopen(monkeypatch, lambda *a, **k: _FakeResp([
        b'{"choices":[{"message":{"content":"hi"}}]}']))
    data, metrics = v2_lib._post_llm_streaming("http://x/v1", {}, {}, 60)
    assert data is None
    assert metrics["streamed"] is False


def test_empty_stream_returns_none(monkeypatch):
    _patch_urlopen(monkeypatch, lambda *a, **k: _FakeResp([b"data: [DONE]\n"]))
    data, _ = v2_lib._post_llm_streaming("http://x/v1", {}, {}, 60)
    assert data is None


def test_exception_during_stream_is_reported_not_raised(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection reset")
    _patch_urlopen(monkeypatch, boom)
    data, metrics = v2_lib._post_llm_streaming("http://x/v1", {}, {}, 60)
    assert data is None and metrics["streamed"] is False


def test_timing_log_says_where_the_time_went(monkeypatch, capsys):
    v2_lib._log_llm_timing(1, 3, "m", {
        "streamed": True, "ttft_s": 2.8, "elapsed_s": 119.3,
        "chars": 18393, "approx_tok_rate": 38.5, "finish_reason": "length"})
    out = capsys.readouterr().out
    assert "ttft=2.8s" in out and "total=119.3s" in out
    assert "tok/s=38.5" in out, out


def test_timing_log_silent_when_not_streamed(capsys):
    v2_lib._log_llm_timing(1, 3, "m", {"streamed": False})
    assert capsys.readouterr().out == ""


# ------------------------------------------------------------- stream toggle

def test_streaming_defaults_on_and_can_be_disabled(monkeypatch):
    monkeypatch.delenv("REVAI_LLM_STREAM", raising=False)
    assert v2_lib._llm_streaming_enabled() is True
    for val in ("0", "false", "no", "off", "OFF"):
        monkeypatch.setenv("REVAI_LLM_STREAM", val)
        assert v2_lib._llm_streaming_enabled() is False, val


# ------------------------------------------------- retry window vs stage budget

def test_escalation_is_clamped_to_the_callers_budget(monkeypatch):
    """The artifact_gen case: 600 + 1200 == 1800 == the stage budget."""
    seen = []

    def handler(req, timeout=None):
        seen.append(timeout)
        raise TimeoutError("The read operation timed out")

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "600")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_: None)

    # Every attempt timing out is llm_judge's existing terminal behaviour; the
    # assertion that matters is the window each attempt was given.
    with pytest.raises(Exception):
        v2_lib.llm_judge("p", timeout_s=600, budget_s=1800, max_retries=2)

    assert seen, "expected the HTTP path to be exercised"
    assert seen[0] == 600, seen
    # 600 + 1200 would be exactly 1800, leaving no margin for the stage.
    assert 600 + seen[1] <= 1800, f"budget overrun: {seen}"
    assert seen[1] > 600, "clamping must not make the retry pointless"


def test_escalation_still_doubles_when_there_is_room(monkeypatch):
    """A clamp must not shrink a window that legitimately fits."""
    seen = []
    n = {"i": 0}

    def handler(req, timeout=None):
        seen.append(timeout)
        if len(seen) == 1:
            raise TimeoutError("The read operation timed out")
        return _json_resp({"choices": [
            {"message": {"content": "{}"}, "finish_reason": "stop"}]})

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "600")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_: None)

    out = v2_lib.llm_judge("p", timeout_s=600, budget_s=3600, max_retries=2)
    assert out.get("choices"), out
    assert seen[0] == 600 and seen[1] == 1200, seen


def test_caller_timeout_beats_the_environment_default(monkeypatch):
    seen = []

    def handler(req, timeout=None):
        seen.append(timeout)
        raise TimeoutError("The read operation timed out")

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "600")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_: None)

    with pytest.raises(Exception):
        v2_lib.llm_judge("p", timeout_s=180, budget_s=1800, max_retries=1)
    assert seen and seen[0] == 180, seen


def test_env_timeout_still_used_when_no_caller_timeout(monkeypatch):
    seen = []

    def handler(req, timeout=None):
        seen.append(timeout)
        raise TimeoutError("The read operation timed out")

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "777")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_: None)

    with pytest.raises(Exception):
        v2_lib.llm_judge("p", max_retries=1)
    assert seen and seen[0] == 777, seen


def test_no_budget_means_no_clamping(monkeypatch):
    """budget_s is opt-in; existing callers must behave exactly as before."""
    seen = []

    def handler(req, timeout=None):
        seen.append(timeout)
        if len(seen) == 1:
            raise TimeoutError("The read operation timed out")
        return _json_resp({"choices": [
            {"message": {"content": "{}"}, "finish_reason": "stop"}]})

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "600")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_: None)

    v2_lib.llm_judge("p", max_retries=2)
    assert seen[:2] == [600, 1200], seen


def test_stream_reassembly_preserves_the_truncation_guard(monkeypatch):
    """Streaming must not weaken the hollow-response check.

    `_llm_response_has_usable_content` rejects finish_reason=length outright
    ("never accept a truncated response silently"). Reassembling a stream builds
    that field by hand, so the guard is only still intact if the reassembled
    dict carries the real finish_reason -- and this fails if it defaults to
    "stop", which would silently accept every truncated generation.
    """
    _patch_urlopen(monkeypatch,
                   lambda *a, **k: _sse(["partial report"], finish_reason="length"))
    data, _ = v2_lib._post_llm_streaming("http://x/v1", {}, {}, 60)
    assert data["choices"][0]["finish_reason"] == "length", data
    assert v2_lib._llm_response_has_usable_content(data) is False


def test_stream_reassembly_preserves_the_empty_content_guard(monkeypatch):
    """An empty stream must not become an accepted empty answer."""
    _patch_urlopen(monkeypatch, lambda *a, **k: _sse([]))
    data, metrics = v2_lib._post_llm_streaming("http://x/v1", {}, {}, 60)
    assert data is None and metrics["streamed"] is False


def test_streaming_path_is_used_by_default_end_to_end(monkeypatch):
    """llm_judge must actually go through the streaming helper."""
    calls = {"stream": 0}

    def handler(req, timeout=None):
        body = json.loads(req.data.decode())
        calls["stream"] += 1 if body.get("stream") else 0
        return _sse(['{"ok": true}'])

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.delenv("REVAI_LLM_STREAM", raising=False)
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    monkeypatch.setenv("REVAI_LLM_MAX_TOKENS", "4096")

    out = v2_lib.llm_judge("p", max_retries=1)
    assert calls["stream"] == 1, "expected a streaming request"
    assert out["choices"][0]["message"]["content"] == '{"ok": true}', out

# --------------------------------------------------------------------------
# 2026-10-03: the budget deadline fixes
# --------------------------------------------------------------------------

def test_no_room_for_a_second_window_skips_the_retry(monkeypatch):
    """budget_s < 2 * timeout_s must not overrun the caller's budget.

    The old clamp `max(base, min(base*2, b - base))` had a floor that
    reinstated the overrun: with timeout_s=180 and budget_s=180 the retry got
    another FULL 180s window (360s total) and the no-thinking fallback added a
    third. The budget is a deadline now -- the first attempt gets min(base,
    budget), and when nothing meaningful is left, both the same-effort retry
    and the fallback are skipped with a log line instead of pretended.

    The fake clock advances by each attempt's window, which is what makes the
    budget actually consumed (a real timeout burns wall time; an instant test
    handler does not).
    """
    seen = []
    clock = {"t": 1000.0}

    def handler(req, timeout=None):
        seen.append(timeout)
        clock["t"] += (timeout or 0)
        raise TimeoutError("The read operation timed out")

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.setattr(v2_lib.time, "monotonic", lambda: clock["t"])
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "600")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_: None)

    with pytest.raises(Exception):
        v2_lib.llm_judge("p", timeout_s=180, budget_s=180, max_retries=3)
    assert seen == [180], (
        f"exactly one attempt fits the budget; got windows {seen}")


def test_first_attempt_is_clamped_to_a_smaller_budget(monkeypatch):
    """A budget below the base window bounds the FIRST attempt too."""
    seen = []
    clock = {"t": 1000.0}

    def handler(req, timeout=None):
        seen.append(timeout)
        clock["t"] += (timeout or 0)
        raise TimeoutError("The read operation timed out")

    _patch_urlopen(monkeypatch, handler)
    monkeypatch.setattr(v2_lib.time, "monotonic", lambda: clock["t"])
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "600")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://x/v1/chat/completions")
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_: None)

    with pytest.raises(Exception):
        v2_lib.llm_judge("p", timeout_s=600, budget_s=120, max_retries=3)
    assert seen == [120], f"first window must be the budget, got {seen}"


def test_stream_ending_without_a_finish_reason_is_recorded_as_unknown(monkeypatch):
    """A clean EOF without a finish chunk is not a clean stop.

    Labelling it "stop" let arbitrarily truncated content pass the length
    guard. The response keeps the content (a provider that never sends finish
    chunks must still work) but records finish_reason None and says so.
    """
    lines = [b"data: " + json.dumps(
        {"choices": [{"delta": {"content": "partial"}, "finish_reason": None}]}
    ).encode() + b"\n"]
    resp = _FakeResp(lines)  # ends without [DONE] and without a finish chunk
    _patch_urlopen(monkeypatch, lambda *a, **k: resp)
    data, metrics = v2_lib._post_llm_streaming(
        "http://x/v1/chat/completions", {}, {"model": "m"}, 60)
    assert data is not None
    assert data["choices"][0]["finish_reason"] is None
    assert metrics["finish_reason"] is None
    assert metrics["chunks"] == 1


def test_stream_reader_stops_at_finish_reason_without_done(monkeypatch):
    """A provider that omits [DONE] must not turn a complete answer into a
    read timeout: once finish_reason arrived, the reader stops."""
    lines = [
        b"data: " + json.dumps(
            {"choices": [{"delta": {"content": "done"}, "finish_reason": None}]}
        ).encode() + b"\n\n",
        b"data: " + json.dumps(
            {"choices": [{"delta": {}, "finish_reason": "stop"}]}
        ).encode() + b"\n\n",
        # Nothing after this -- the fake response ends; a real stalled socket
        # would block here until the timeout, which is the bug.
    ]
    resp = _FakeResp(lines)
    _patch_urlopen(monkeypatch, lambda *a, **k: resp)
    data, metrics = v2_lib._post_llm_streaming(
        "http://x/v1/chat/completions", {}, {"model": "m"}, 60)
    assert data is not None
    assert data["choices"][0]["finish_reason"] == "stop"
    assert metrics["chunks"] == 2
