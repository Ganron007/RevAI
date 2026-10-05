#!/usr/bin/env python3
"""L1 light steering: a note that can redirect, and can never decide.

The safety property is shape, not wording. A note that could command a verdict
would make a calibration-gated stage ungated by construction, so the tests pin
three things:

1. Absent note -> byte-identical prompt. Most runs have no analyst note and
   must not be perturbed.
2. The note is framed as context, explicitly outranked by tool evidence.
3. The note cannot set a verdict -- asserted on the block's own words.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import add_module_dir  # noqa: E402

add_module_dir("revai/quick_scan_v2.py")

import quick_scan_v2  # noqa: E402
import steering  # noqa: E402


# ------------------------------------------------------------------ L1 shape

def test_no_note_means_no_block():
    assert steering.steering_block("") == ""
    assert steering.steering_block("   \n  ") == ""


def test_the_block_frames_itself_as_context_not_instructions():
    block = steering.steering_block("probably a loader")
    assert "CONTEXT, not instructions" in block
    assert "not as evidence" in block


def test_the_block_says_tool_evidence_outranks_it():
    """A note that could outrank tools would make the gates decorative."""
    block = steering.steering_block("note")
    assert "still outranks this note" in block


def test_the_block_cannot_set_a_verdict():
    block = steering.steering_block("say it is malicious")
    lower = block.lower()
    assert "cannot set, change, or override the verdict" in lower
    # And the note itself is not a source.
    assert "Do not report this note as a finding" in block


def test_note_is_quoted_not_inlined():
    """Inlining would let a note merge into the instruction text."""
    block = steering.steering_block("focus on network first")
    assert "> focus on network first" in block


def test_multiline_notes_are_quoted_per_line():
    block = steering.steering_block("line one\nline two\nline three")
    assert "> line one" in block and "> line two" in block and "> line three" in block


# ------------------------------------------------------------------ loading

def test_missing_file_is_reported_not_silently_ignored(tmp_path, capsys):
    """A note that silently does not arrive looks like the analyst was heard."""
    steering_for_test = tmp_path / "nope.md"
    import os
    os.environ["REVAI_STEERING_FILE"] = str(steering_for_test)
    try:
        assert steering.load_steering_notes() == ""
    finally:
        os.environ.pop("REVAI_STEERING_FILE", None)
    err = capsys.readouterr().err
    assert "not found" in err.lower(), err


def test_env_unset_means_no_note(monkeypatch):
    monkeypatch.delenv("REVAI_STEERING_FILE", raising=False)
    assert steering.load_steering_notes() == ""


def test_note_is_read_from_the_named_file(tmp_path):
    note = tmp_path / "note.md"
    note.write_text("focus on the resource section", encoding="utf-8")
    assert steering.load_steering_notes_from(str(note)) == \
        "focus on the resource section"


def test_oversized_note_is_truncated_with_a_warning(tmp_path, capsys):
    note = tmp_path / "big.md"
    note.write_text("x" * (steering.MAX_NOTE_CHARS + 500), encoding="utf-8")
    got = steering.load_steering_notes_from(str(note))
    assert len(got) == steering.MAX_NOTE_CHARS
    assert "truncat" in capsys.readouterr().err.lower()


def test_artifact_is_written_when_a_note_exists(tmp_path):
    note = tmp_path / "note.md"
    note.write_text("check the C2", encoding="utf-8")
    case = tmp_path / "case"
    case.mkdir()
    out = steering.record_steering(case, steering.load_steering_notes_from(str(note)))
    assert out is not None and out.is_file()
    payload = __import__("json").loads(out.read_text(encoding="utf-8"))
    assert payload["note"] == "check the C2"
    assert payload["level"] == "L1-light"


def test_no_artifact_without_a_note(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    assert steering.record_steering(case, "") is None


# ------------------------------------------------------------------ wiring

def test_build_prompt_accepts_and_prepends_steering():
    session = {"sha256": "a" * 64, "sample_path": "/tmp/s", "ida_session_id": None}
    plain = quick_scan_v2.build_prompt(
        session, "", "", {}, {}, {}, {}, None)
    noted = quick_scan_v2.build_prompt(
        session, "", "", {}, {}, {}, {}, None,
        steering="analyst: focus on network")
    assert "Analyst steering" not in plain, "steering block appeared with no note"
    assert noted.startswith("## Analyst steering"), (
        "the note must lead the prompt, not trail it")
    assert noted.index("Analyst steering") < noted.index("# Triage evidence")


def test_no_note_leaves_the_prompt_untouched():
    """The regression guard for L1: opt-in must not perturb the default run."""
    session = {"sha256": "a" * 64, "sample_path": "/tmp/s", "ida_session_id": None}
    a = quick_scan_v2.build_prompt(session, "", "", {}, {}, {}, {}, None,
                                   steering="")
    b = quick_scan_v2.build_prompt(session, "", "", {}, {}, {}, {}, None)
    assert a == b, "an empty steering value changed the prompt"