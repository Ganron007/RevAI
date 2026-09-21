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
