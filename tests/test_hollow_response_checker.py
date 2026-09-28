#!/usr/bin/env python3
"""The hollow-response checker must not reject scalar-valued JSON.

Found during the 2026-09-28 provider switch to agnes-3.0-flash. That model
answers a "return only this JSON: {"ok": true}" instruction with exactly
`{"ok": true}`, and `_llm_response_has_usable_content` returned False: its value
loop only accepted str >= 3 chars, non-empty list/dict, and report-shaped
bodies, so a bool fell through every clause. llm_judge then retried three times
and raised "llm_judge failed" on a perfectly good answer -- a false negative in
the guard that is supposed to catch *hollow* answers.

The guards that must still fire are pinned here too, because widening the
accepted types is exactly the kind of change that quietly disables a check.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


def resp(text, finish="stop"):
    return {"choices": [{"finish_reason": finish,
                         "message": {"content": text}}]}


def test_scalar_valued_json_is_usable():
    """The regression: these all used to be reported hollow."""
    for text in ('{"ok": true}', '{"ok": false}', '{"count": 3}',
                 '{"a": 1, "b": 2}', '{"score": 0.95}',
                 '{"verdict": true, "confidence": 0.9}'):
        assert v2_lib._llm_response_has_usable_content(resp(text)), text


def test_scalar_nested_in_container_is_usable():
    assert v2_lib._llm_response_has_usable_content(
        resp('{"findings": [{"malicious": true}]}'))


def test_genuinely_hollow_responses_still_rejected():
    """The check must keep catching what it was written for."""
    hollow = [
        ('{"markdown": ""}', "empty report body"),
        ('{"markdown": "x", "sections_present": ["a"]}', "empty body + list"),
        ('{"items": []}', "empty list"),
        ('{"flag": null}', "null only"),
        ('{"a": null, "b": null}', "all null"),
        ('{"name": ""}', "empty string only"),
        ('{}', "no values at all"),
        ('{"markdown": "placeholder"}', "stub body"),
    ]
    for text, why in hollow:
        assert not v2_lib._llm_response_has_usable_content(resp(text)), \
            f"{text!r} ({why}) should be hollow"


def test_truncated_responses_still_rejected():
    """Widening the value types must not accept a cut-off answer.

    Only `length` is this function's job: `abort` is handled by the caller
    (llm_judge downgrades reasoning and retries before ever asking the checker),
    so asserting it here would be asserting a contract that does not exist.
    """
    assert not v2_lib._llm_response_has_usable_content(
        resp('{"ok": true}', finish="length"))
    assert not v2_lib._llm_response_has_usable_content(
        resp('{"markdown": "' + "x" * 400 + '"}', finish="length"))
    # a stopped scalar reply is the case the fix is for
    assert v2_lib._llm_response_has_usable_content(
        resp('{"ok": true}', finish="stop"))


def test_empty_and_degenerate_content_still_rejected():
    assert not v2_lib._llm_response_has_usable_content(resp(""))
    assert not v2_lib._llm_response_has_usable_content(resp("   \n\t "))
    assert not v2_lib._llm_response_has_usable_content(
        resp("final_placeholder " * 200))


def test_real_content_still_accepted():
    for text in ('{"name": "abc"}', '{"items": [1, 2]}',
                 '{"markdown": "' + "x" * 250 + '"}',
                 "plain text answer"):
        assert v2_lib._llm_response_has_usable_content(resp(text)), text
