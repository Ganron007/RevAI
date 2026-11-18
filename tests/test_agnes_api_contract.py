"""Agnes 3.0 Flash requests stay within its published Chat Completions contract."""
from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
import urllib.error
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


class _PayloadResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def test_agnes_reasoning_maps_to_documented_thinking_extension():
    endpoint = "https://apihub.agnes-ai.com/v1/chat/completions"

    assert v2_lib._build_reasoning_body("high", endpoint) == {
        "chat_template_kwargs": {"enable_thinking": True},
    }
    assert v2_lib._build_reasoning_body("enabled", endpoint) == {
        "chat_template_kwargs": {"enable_thinking": True},
    }
    for legacy_level in ("low", "medium", "high", "max"):
        assert v2_lib._build_reasoning_body(legacy_level, endpoint) == {
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
    # RC-75 (2026-11-18): generic providers now receive their documented
    # reasoning field on the LangChain path too, merged through extra_body
    # exactly as the urllib path already sent it -- previously
    # REVAI_LLM_REASONING was silently inert on this path.
    assert v2_lib.get_llm_chat_options(4096, endpoint, "high") == {
        "max_tokens": 4096,
        "extra_body": {"thinking": {"type": "enabled"},
                       "reasoning_effort": "high"},
    }
    assert v2_lib._build_reasoning_body("enabled", endpoint) == {}
    # No configured reasoning -> no reasoning field at all (provider default).
    assert v2_lib.get_llm_chat_options(4096, endpoint, None) == {
        "max_tokens": 4096}


def test_stepfun_reasoning_contract_maps_to_documented_effort_only():
    endpoint = "https://api.stepfun.ai/step_plan/v1"

    # StepFun documents reasoning_effort low/medium/high on Chat Completions;
    # the undocumented generic `thinking` object must not be sent.
    for effort in ("low", "medium", "high"):
        assert v2_lib._build_reasoning_body(effort, endpoint) == {
            "reasoning_effort": effort}
    # `minimal` is not a documented StepFun value; the lowest documented
    # effort is the safe alias.
    assert v2_lib._build_reasoning_body("minimal", endpoint) == {
        "reasoning_effort": "low"}
    # No documented off switch (step-5-preview always thinks): the
    # enabled/disabled aliases keep the provider default.
    assert v2_lib._build_reasoning_body("enabled", endpoint) == {}
    assert v2_lib._build_reasoning_body("disabled", endpoint) == {}
    # The configured effort must reach the LangChain path -- step-5-preview
    # defaults to HIGH when the field is absent, so a dropped field would
    # silently burn the plan's TPM at maximum reasoning depth.
    assert v2_lib.get_llm_chat_options(4096, endpoint, "low") == {
        "max_tokens": 4096, "extra_body": {"reasoning_effort": "low"}}


def test_stepfun_llm_judge_honors_configured_effort_despite_flash_name(
        monkeypatch):
    """The provider match must beat the model-NAME heuristic.

    `step-3.7-flash` contains "flash", and the pre-fix branch sent
    reasoning=disabled for every such model -- which on StepFun maps to "no
    field at all" (provider default, high on some models). The operator's
    configured effort was inert and every judge call silently ran deeper
    than configured. Found live on the 2026-11-18 model switch.
    """
    bodies = []

    def fake_urlopen(request, timeout=None):
        bodies.append(json.loads(request.data.decode("utf-8")))
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_a, **_kw: 0)
    monkeypatch.setenv("REVAI_LLM_API_URL",
                       "https://api.stepfun.ai/step_plan/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "step-3.7-flash")
    monkeypatch.setenv("REVAI_LLM_REASONING", "low")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.delenv("REVAI_LLM_PLANNER_REASONING", raising=False)

    v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=1)

    assert len(bodies) == 1
    assert bodies[0]["model"] == "step-3.7-flash"
    assert bodies[0]["reasoning_effort"] == "low", (
        "the configured effort must reach the request body")
    # The undocumented generic `thinking` object must not be sent.
    assert "thinking" not in bodies[0]
    assert "chat_template_kwargs" not in bodies[0]

    # Second direction: nothing configured -> the documented default effort,
    # never the disabled-by-name branch.
    bodies.clear()
    monkeypatch.delenv("REVAI_LLM_REASONING", raising=False)
    v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=1)
    assert bodies[0]["reasoning_effort"] == "high", (
        "an unset effort falls back to the documented default, not disabled")


def test_non_stepfun_flash_provider_keeps_the_disabled_default(monkeypatch):
    """The name heuristic still governs providers we know expose no control."""
    bodies = []

    def fake_urlopen(request, timeout=None):
        bodies.append(json.loads(request.data.decode("utf-8")))
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_a, **_kw: 0)
    monkeypatch.setenv("REVAI_LLM_API_URL", "https://provider.example/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "some-flash-model")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.delenv("REVAI_LLM_PLANNER_REASONING", raising=False)
    monkeypatch.delenv("REVAI_LLM_REASONING", raising=False)

    v2_lib.llm_judge("Return only {\"ok\": true}", max_retries=1)

    # The disabled default keeps the pre-existing generic-provider shape
    # (no effort field; the generic thinking:disabled object) -- unchanged
    # by the StepFun branch, which only reorders WHICH rule fires.
    assert "reasoning_effort" not in bodies[0]
    assert bodies[0].get("thinking") == {"type": "disabled"}


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
    monkeypatch.setenv("REVAI_LLM_REASONING", "enabled")
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


def test_report_writer_uses_agnes_structured_tool_contract(monkeypatch):
    bodies = []
    response = {
        "model": "agnes-3.0-flash",
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{
                    "type": "function", "id": "call-report",
                    "function": {"name": "submit_report", "arguments": json.dumps({
                        "title": "Evidence-based report",
                        "sections": [{
                            "heading": "Executive Summary",
                            "blocks": [{
                                "kind": "observation",
                                "text": "Sample evidence.",
                                "source": "malcat",
                                "query_or_table": "quick_scan/00-tools-raw.json",
                                "row_or_rule": "$.malcat.file_summary.sha256",
                            }],
                        }],
                    })},
                }],
            },
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 12},
    }

    def fake_urlopen(request, timeout=None):
        bodies.append(json.loads(request.data.decode("utf-8")))
        return _PayloadResponse(response)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_args, **_kw: 0)
    monkeypatch.setenv("REVAI_LLM_API_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "agnes-3.0-flash")
    monkeypatch.setenv("REVAI_LLM_REASONING", "enabled")
    monkeypatch.setenv("REVAI_LLM_STREAM", "1")

    raw = v2_lib.llm_report("Write an evidence-based report")
    report = v2_lib.extract_llm_report(raw)

    assert len(bodies) == 1
    body = bodies[0]
    assert body["tools"] == [v2_lib.REPORT_WRITER_TOOL]
    assert body["tool_choice"] == {
        "type": "function", "function": {"name": "submit_report"}}
    assert "response_format" not in body
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert report["schema_used"] is True
    assert report["title"] == "Evidence-based report"
    assert report["source"] == "llm_judge"
    assert report["markdown"] == (
        "## Executive Summary\n\n"
        "- Sample evidence. (source: malcat, "
        "query_or_table: quick_scan/00-tools-raw.json, "
        "row_or_rule: $.malcat.file_summary.sha256)\n"
    )
    assert report["document"]["sections"][0]["heading"] == "Executive Summary"
    assert v2_lib.REPORT_WRITER_TOOL["function"]["parameters"]["required"] == [
        "sections"]


def test_report_writer_rejects_legacy_markdown_when_schema_is_required():
    response = {"choices": [{"finish_reason": "tool_calls", "message": {
        "tool_calls": [{"function": {"name": "submit_report", "arguments": json.dumps({
            "markdown": "## Executive Summary\n\nUncited prose.\n"})}}]}}]}
    legacy = v2_lib.extract_llm_report(response)
    assert legacy["schema_used"] is False
    with pytest.raises(v2_lib.ReportSchemaError, match="claim-level"):
        v2_lib.extract_llm_report(response, require_schema=True)


def test_report_writer_rejects_missing_or_multiple_tool_calls():
    empty = {"choices": [{"finish_reason": "tool_calls",
                          "message": {"tool_calls": []}}]}
    duplicate = {"choices": [{"finish_reason": "tool_calls", "message": {
        "tool_calls": [
            {"function": {"name": "submit_report", "arguments": "{}"}},
            {"function": {"name": "submit_report", "arguments": "{}"}},
        ]}}]}
    with pytest.raises(ValueError, match="exactly one"):
        v2_lib.extract_llm_report(empty)
    with pytest.raises(ValueError, match="exactly one"):
        v2_lib.extract_llm_report(duplicate)


def test_agnes_timeout_retry_never_disables_thinking(monkeypatch):
    bodies = []

    def timeout(request, timeout=None):
        bodies.append(json.loads(request.data.decode("utf-8")))
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", timeout)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_args, **_kw: 0)
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setenv("REVAI_LLM_API_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "agnes-3.0-flash")
    monkeypatch.setenv("REVAI_LLM_REASONING", "enabled")
    monkeypatch.setenv("REVAI_LLM_TIMEOUT", "1")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_BUDGET", "0")

    with pytest.raises(TimeoutError):
        v2_lib.llm_judge("prompt", max_retries=3)

    assert len(bodies) == 2
    assert all(body["chat_template_kwargs"] == {"enable_thinking": True}
               for body in bodies)


def test_payment_error_is_not_retried(monkeypatch):
    calls = []

    def payment_required(request, timeout=None):
        calls.append(request)
        raise urllib.error.HTTPError(
            request.full_url, 402, "Payment Required", {},
            io.BytesIO(b'{"error":"payment required"}'))

    monkeypatch.setattr(urllib.request, "urlopen", payment_required)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_args, **_kw: 0)
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: pytest.fail(
        "non-transient HTTP 402 must not sleep and retry"))
    monkeypatch.setenv("REVAI_LLM_API_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "agnes-3.0-flash")
    monkeypatch.setenv("REVAI_LLM_REASONING", "enabled")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")
    monkeypatch.setenv("REVAI_LLM_BUDGET", "0")

    with pytest.raises(urllib.error.HTTPError) as error:
        v2_lib.llm_judge("prompt", max_retries=5)

    assert error.value.code == 402
    assert len(calls) == 1


def test_agnes_agentic_completeness_retry_preserves_configured_thinking(
        monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "revai"))
    import deep_dive_agentic as agentic

    calls = []

    def fake_judge(_prompt, *, model=None, reasoning=None):
        calls.append(reasoning)
        return {"choices": [{"message": {"content": json.dumps({
            "verdict": "suspicious", "confidence": 50,
            "summary": "evidence-backed summary", "key_evidence": ["tool row"],
        })}}]}

    monkeypatch.setattr(agentic, "get_llm_api_url",
                        lambda: "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(agentic, "llm_judge", fake_judge)
    result = agentic._complete_final_answer_retry(
        {"verdict": "unknown"}, {"evidence": "tool row"},
        "agnes-3.0-flash", "contract-test")

    assert result["verdict"] == "suspicious"
    assert calls == [None]


def test_agnes_output_cap_does_not_change_other_providers(monkeypatch):
    monkeypatch.setenv("REVAI_LLM_MAX_TOKENS", "100000")

    assert v2_lib._llm_max_tokens_for_url(
        "https://apihub.agnes-ai.com/v1") == 65536
    assert v2_lib._llm_max_tokens_for_url(
        "https://provider.example/v1") == 100000


def test_agnes_claim_review_overrides_keep_thinking_and_bound_output(monkeypatch):
    bodies = []

    def fake_urlopen(request, timeout=None):
        bodies.append(json.loads(request.data.decode("utf-8")))
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(v2_lib, "llm_budget_acquire", lambda *_args, **_kw: 0)
    monkeypatch.setenv("REVAI_LLM_API_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_MODEL", "agnes-3.0-flash")
    monkeypatch.setenv("REVAI_LLM_REASONING", "enabled")
    monkeypatch.setenv("REVAI_LLM_STREAM", "0")

    v2_lib.llm_judge(
        "Return only {\"reviews\": []}", max_retries=1,
        max_tokens_override=4096, temperature_override=0.0,
    )

    body = bodies[0]
    assert body["max_tokens"] == 4096
    assert body["temperature"] == 0.0
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert "reasoning_effort" not in body


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
