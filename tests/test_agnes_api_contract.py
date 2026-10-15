"""Agnes 3.0 Flash requests stay within its published Chat Completions contract."""
from __future__ import annotations

import json
import sys
from pathlib import Path
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import add_module_dir  # noqa: E402
add_module_dir("revai/v2_lib.py")

import v2_lib


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({
            "choices": [{
                "message": {"role": "assistant", "content": '{"ok":true}'},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }).encode()


def test_agnes_reasoning_maps_to_documented_thinking_extension():
    endpoint = "https://apihub.agnes-ai.com/v1/chat/completions"

    assert v2_lib._build_reasoning_body("high", endpoint) == {
        "chat_template_kwargs": {"enable_thinking": True},
    }
    assert v2_lib._build_reasoning_body("disabled", endpoint) == {
        "chat_template_kwargs": {"enable_thinking": False},
    }
    assert v2_lib.get_llm_chat_options(4096, endpoint, "high") == {
        "extra_body": {"max_tokens": 4096,
                       "chat_template_kwargs": {"enable_thinking": True}}}


def test_non_agnes_reasoning_contract_is_unchanged():
    endpoint = "https://provider.example/v1/chat/completions"

    assert v2_lib._build_reasoning_body("high", endpoint) == {
        "thinking": {"type": "enabled"},
        "reasoning_effort": "high",
    }
    assert v2_lib.get_llm_chat_options(4096, endpoint, "high") == {
        "max_tokens": 4096}


def test_agnes_llm_judge_sends_only_documented_reasoning_and_output_cap(
        monkeypatch):
    bodies = []

    def fake_urlopen(request, timeout=None):
        assert isinstance(request, urllib.request.Request)
        bodies.append(json.loads(request.data.decode("utf-8")))
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_args, **_kw: 0)
    monkeypatch.setenv("REVAI_LLM_API_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "agnes-3.0-flash")
    monkeypatch.setenv("REVAI_LLM_REASONING", "high")
    monkeypatch.setenv("REVAI_LLM_MAX_TOKENS", "100000")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")

    result = v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=1)

    assert result["choices"][0]["message"]["content"] == '{"ok":true}'
    assert len(bodies) == 1
    body = bodies[0]
    assert body["model"] == "agnes-3.0-flash"
    assert body["max_tokens"] == 65536
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert "response_format" not in body
    assert "reasoning_effort" not in body
    assert "thinking" not in body


def test_agnes_output_cap_does_not_change_other_providers(monkeypatch):
    monkeypatch.setenv("REVAI_LLM_MAX_TOKENS", "100000")

    assert v2_lib._llm_max_tokens_for_url(
        "https://apihub.agnes-ai.com/v1") == 65536
    assert v2_lib._llm_max_tokens_for_url(
        "https://provider.example/v1") == 100000


def test_langchain_serializes_documented_fields_without_renaming_token_cap():
    httpx = pytest.importorskip("httpx")
    ChatOpenAI = pytest.importorskip("langchain_openai").ChatOpenAI
    bodies = []

    def handle(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "created": 0,
            "model": "configured-llm",
            "choices": [{"index": 0, "message": {
                "role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
        })

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        model = ChatOpenAI(
            model="configured-llm", api_key="test-key", http_client=client,
            base_url="https://apihub.agnes-ai.com/v1", temperature=0,
            **v2_lib.get_llm_chat_options(
                100000, "https://apihub.agnes-ai.com/v1", "high"),
        )
        model.bind_tools([{"type": "function", "function": {
            "name": "probe", "description": "Contract probe",
            "parameters": {"type": "object", "properties": {}},
        }}]).invoke("Contract probe")

    body = bodies[0]
    assert body["max_tokens"] == 65536
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert body["tools"]
    assert set(body) <= {
        "model", "messages", "temperature", "top_p", "max_tokens", "stream",
        "tools", "tool_choice", "chat_template_kwargs",
    }
