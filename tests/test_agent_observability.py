"""Tests for deep-dive observability: progress stream and the /api/graph endpoint."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import agentic_langgraph as alg  # noqa: E402


# --- #19a progress stream -------------------------------------------------


def test_progress_callback_writes_tool_and_llm_events(tmp_path):
    path = tmp_path / "deep-dive-progress.jsonl"
    cb = alg._UsageCallback("test-model", path)

    cb.on_tool_start({"name": "api_lookup"}, '{"api": "NtCreateFile"}', run_id="r1")
    cb.on_tool_end("[ok] docs", run_id="r1")

    class _Response:
        llm_output = {"token_usage": {"total_tokens": 42}}
        generations = []

    cb.on_llm_end(_Response())

    entries = [json.loads(line) for line in path.read_text().splitlines()]
    events = [e["event"] for e in entries]
    assert events == ["tool_start", "tool_end", "llm_end"]
    assert entries[0]["tool"] == "api_lookup"
    assert "NtCreateFile" in entries[0]["input"]
    # on_tool_end has no name of its own - it must be correlated by run_id.
    assert entries[1]["tool"] == "api_lookup"
    assert entries[1]["output_chars"] > 0
    assert entries[2]["tokens"]["total_tokens"] == 42
    assert all("ts" in e for e in entries)


def test_progress_callback_without_path_is_noop(tmp_path):
    cb = alg._UsageCallback("test-model", None)
    cb.on_tool_start({"name": "x"}, "{}", run_id="r")
    cb.on_tool_end("out", run_id="r")  # must not raise


def test_progress_write_failure_is_swallowed(tmp_path):
    """A broken progress path must never break a run."""
    cb = alg._UsageCallback("test-model", tmp_path / "missing-dir" / "p.jsonl")
    cb.on_tool_start({"name": "x"}, "{}", run_id="r")
    cb.on_tool_end("out", run_id="r")


# --- #19b graph endpoint --------------------------------------------------


def test_agent_graph_mermaid_shape():
    result = alg.agent_graph_mermaid()
    assert set(result) >= {"ok", "tools", "node_names", "caveat", "engine"}
    assert "api_lookup" in result["tools"]
    assert "compare_files" in result["tools"]
    assert result["caveat"]
    if result["ok"]:
        assert "graph" in result["mermaid"]
        assert "agent" in result["node_names"]


class _FakeRegistry:
    tools = {name: (lambda *a, **k: {"ok": True}) for name in alg.AGENT_TOOL_NAMES}


def test_langgraph_engine_exposes_lookup_and_compare():
    tools = alg._build_lc_tools(_FakeRegistry(), {"sample_path": "x"}, [], {}, 2000, {})
    by_name = {t.name: t for t in tools}
    assert "api_lookup" in by_name, "api_lookup must be reachable in the default engine"
    assert "compare_files" in by_name
    assert set(by_name["api_lookup"].args_schema.model_fields) == {"api", "query", "limit"}
    assert "b" in by_name["compare_files"].args_schema.model_fields
    # Model-facing description must explain the grounding tool, not just name it.
    assert "grounding" in by_name["api_lookup"].description.lower()


def test_api_graph_endpoint():
    try:
        import app as app_mod
    except Exception as exc:  # pragma: no cover - Flask/app import unavailable
        pytest.skip(f"app import unavailable: {exc}")
    client = app_mod.app.test_client()
    resp = client.get("/api/graph")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "tools" in data
    assert data.get("engine") == "langgraph"


# --- #19c stream mode + SSE -----------------------------------------------


def test_messages_from_stream_chunks_flattens_updates():
    from langchain_core.messages import AIMessage, ToolMessage

    tool_msg = ToolMessage(content="result", tool_call_id="1")
    ai_msg = AIMessage(content="done")
    chunks = [
        {"agent": {"messages": [ai_msg]}},
        {"tools": {"messages": [tool_msg]}},
        {"agent": {"messages": []}},
        "not-a-dict",
    ]
    messages = alg.messages_from_stream_chunks(chunks)
    assert messages == [ai_msg, tool_msg]


def test_messages_from_stream_chunks_handles_empty():
    assert alg.messages_from_stream_chunks([]) == []
    assert alg.messages_from_stream_chunks(None) == []


def test_progress_sse_endpoint_emits_existing_lines(tmp_path, monkeypatch):
    try:
        import app as app_mod
        import v2_lib
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"app/v2_lib import unavailable: {exc}")

    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path)
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    monkeypatch.setenv("REVAI_PROGRESS_STREAM_SECONDS", "1")
    sha = "c" * 64
    case = tmp_path / sha / "deep_dive"
    case.mkdir(parents=True)
    (case / "deep-dive-progress.jsonl").write_text(
        '{"event": "tool_start", "tool": "api_lookup"}\n'
        '{"event": "tool_end", "tool": "api_lookup", "output_chars": 12}\n')

    client = app_mod.app.test_client()
    resp = client.get(f"/api/orch/{sha}/progress/stream", buffered=False)
    assert resp.status_code == 200
    body = b"".join(resp.response).decode("utf-8", "replace")
    assert 'data: {"event": "tool_start", "tool": "api_lookup"}' in body
    assert body.count("data: ") >= 2
