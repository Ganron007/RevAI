#!/usr/bin/env python3
"""Regression: hollow LLM responses (valid JSON, no content) must be detected.

Deployment rehearsal 2026-09-21: the provider returned finish_reason=stop with
`{"Technical Malware Analysis Report v2 - <sha>":""}` — llm_judge accepted it and
the technical report came back empty (deterministic fallback + red quality).
llm_judge now retries such responses with thinking disabled instead of returning
them; these tests pin the shapes the detector must catch and must allow.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from v2_lib import _llm_response_has_usable_content  # noqa: E402


def _resp(content):
    return {
        "choices": [
            {"message": {"role": "assistant", "content": content},
             "finish_reason": "stop"}
        ]
    }


def test_hollow_single_key_object_is_not_usable():
    assert not _llm_response_has_usable_content(
        _resp('{"Technical Malware Analysis Report v2 - abc123":""}')
    )


def test_empty_content_is_not_usable():
    assert not _llm_response_has_usable_content(_resp(""))
    assert not _llm_response_has_usable_content(_resp("   \n"))
    assert not _llm_response_has_usable_content({"choices": [{"message": {}}]})


def test_markdown_object_is_usable():
    assert _llm_response_has_usable_content(
        _resp('{"markdown":"## Executive Summary\\nbody","source":"llm_judge"}')
    )


def test_corrupted_key_but_real_markdown_is_still_usable():
    # Observed master-report shape: a junk key "," with an empty value next to a
    # populated markdown field (valid JSON, salvageable).
    assert _llm_response_has_usable_content(
        _resp('{","  :"","markdown":"## Executive Summary\\nbody","source":"llm_judge"}')
    )


def test_raw_markdown_is_usable():
    assert _llm_response_has_usable_content(_resp("## Report\nbody text"))


def test_verdict_json_is_usable():
    assert _llm_response_has_usable_content(
        _resp('{"verdict":"malicious","score":80,"family_guess":"x"}')
    )


def test_json_list_usable_only_when_non_empty():
    assert _llm_response_has_usable_content(_resp('[{"name":"a"}]'))
    assert not _llm_response_has_usable_content(_resp("[]"))


def test_repeated_token_garbage_is_not_usable():
    """Rehearsal regression (2026-09-21): the provider returned ~275 KB of one
    repeated placeholder token at high reasoning effort."""
    assert not _llm_response_has_usable_content(_resp("final_placeholder " * 500))


def test_json_with_degenerate_markdown_is_not_usable():
    import json as _json
    garbage = _json.dumps({"markdown": "final_placeholder " * 500, "source": "llm_judge"})
    assert not _llm_response_has_usable_content(_resp(garbage))


def test_normally_repeated_prose_is_still_usable():
    prose = (
        "The sample resolves APIs dynamically (source: capa, top_rules), which "
        "indicates packed execution flow (source: pe_imports). "
    ) * 40
    assert _llm_response_has_usable_content(_resp(prose))


def test_whitespace_dominated_content_is_not_usable():
    """Rehearsal regression (2026-09-22): the model degenerated into 64k
    whitespace tokens after a '{"' prefix (finish_reason=length)."""
    assert not _llm_response_has_usable_content(_resp('{"' + " \t\n" * 3000))


def test_length_truncation_is_not_usable():
    payload = '{"markdown":"' + "long report text " * 200
    resp = _resp(payload)
    resp["choices"][0]["finish_reason"] = "length"
    assert not _llm_response_has_usable_content(resp)


def test_llm_judge_reasoning_override(monkeypatch):
    """llm_judge must honor an explicit reasoning override for one call."""
    import json as _json
    import urllib.request

    import v2_lib as _v2

    calls = []

    class _FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        calls.append(_json.loads(req.data.decode()))
        return _FakeResp(_json.dumps({
            "choices": [{"message": {"role": "assistant", "content": '{"verdict":"unknown"}'}}],
            "usage": {},
        }).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("REVAI_LLM_API_KEY", "k")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://localhost/v1/chat/completions")
    monkeypatch.setenv("REVAI_LLM_MODEL", "step-5-preview")
    monkeypatch.setenv("REVAI_LLM_REASONING", "high")

    _v2.llm_judge("probe", reasoning="disabled")
    assert calls[0]["thinking"] == {"type": "disabled"}


def test_json_with_empty_report_body_is_not_usable():
    """Rehearsal regression (2026-09-22): {"markdown":"", "sections_present":
    [...]} was accepted as usable because the section list is non-empty."""
    import json as _json
    payload = _json.dumps({
        "markdown": "",
        "sections_present": ["1. Executive Summary", "2. Sample Metadata"],
        "source": "llm_judge",
    })
    assert not _llm_response_has_usable_content(_resp(payload))


def test_json_with_real_body_is_usable():
    import json as _json
    payload = _json.dumps({
        "markdown": "## Executive Summary\nWe assess the sample as suspicious.",
        "sections_present": ["Executive Summary"],
        "source": "llm_judge",
    })
    assert _llm_response_has_usable_content(_resp(payload))


def test_timeout_skips_ladder_to_no_thinking(monkeypatch):
    """A hung thinking-path call must jump straight to the disabled attempt
    (each effort level would otherwise burn the full read window)."""
    import json as _json
    import urllib.request

    import v2_lib as _v2

    calls = []

    class _FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        body = _json.loads(req.data.decode())
        calls.append(body)
        if len(calls) == 1:
            raise TimeoutError("The read operation timed out")
        return _FakeResp(_json.dumps({
            "choices": [{"message": {
                "role": "assistant",
                "content": '{"verdict":"suspicious","score":45}',
            }}],
            "usage": {},
        }).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("REVAI_LLM_API_KEY", "test-key")
    monkeypatch.setenv("REVAI_LLM_API_URL", "http://localhost/v1/chat/completions")
    monkeypatch.setenv("REVAI_LLM_MODEL", "step-5-preview")
    monkeypatch.setenv("REVAI_LLM_REASONING", "high")

    out = _v2.llm_judge("probe")
    assert len(calls) == 2, f"expected one timeout then the fallback, got {len(calls)} calls"
    assert calls[1].get("thinking") == {"type": "disabled"}
    assert out["choices"][0]["message"]["content"]
