#!/usr/bin/env python3
"""L3 post-hoc steering: a note given AFTER a run must steer the NEXT one.

The operator's framing — an examiner finishes reading artifacts, disagrees with
where the analysis went, and wants to point the next pass somewhere. That only
works if the note survives the run that received it and reaches the next one.

The invariant that makes it safe: L1 and L3 merge in ONE place.
`effective_steering_note()` decides which direction applies. Two merge points
would drift, and drift here means an analyst is steered by a note they did not
write — the failure mode that would make the whole feature untrustworthy.

An explicit pre-run file wins over a recorded post-hoc note: the person writing a
file for THIS run is the more recent and more specific act.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

import steering  # noqa: E402
from steering import effective_steering_note  # noqa: E402
from steering_history import (  # noqa: E402
    append_steering_note,
    latest_steering_note,
    read_steering_history,
)


def test_empty_note_is_rejected_not_silently_accepted(tmp_path):
    """A UI that says ok to an empty note looks like it heard something."""
    import pytest
    with pytest.raises(ValueError):
        append_steering_note(tmp_path, "")
    with pytest.raises(ValueError):
        append_steering_note(tmp_path, "   \n  ")


def test_a_note_survives_and_can_be_read_back(tmp_path):
    rec = append_steering_note(tmp_path, "check the resource section")
    assert rec["note"] == "check the resource section"
    assert rec["level"] == "L3-post-hoc"
    history = read_steering_history(tmp_path)
    assert len(history) == 1 and history[0]["note"] == rec["note"]


def test_history_is_ordered_and_latest_wins(tmp_path):
    append_steering_note(tmp_path, "first")
    append_steering_note(tmp_path, "second")
    history = read_steering_history(tmp_path)
    assert [h["note"] for h in history] == ["first", "second"]
    assert latest_steering_note(tmp_path) == "second"


def test_no_history_means_no_note(tmp_path):
    assert read_steering_history(tmp_path) == []
    assert latest_steering_note(tmp_path) == ""


def test_unreadable_history_degrades_to_no_note(tmp_path):
    (tmp_path / "steering-history.json").write_text("{not json", encoding="utf-8")
    assert read_steering_history(tmp_path) == []
    assert latest_steering_note(tmp_path) == ""


def test_a_post_hoc_note_steers_the_next_run(tmp_path):
    """The whole point of L3: the note must reach the next analysis."""
    append_steering_note(tmp_path, "focus on network next")
    assert effective_steering_note(tmp_path) == "focus on network next"


def test_an_explicit_pre_run_file_wins_over_the_post_hoc_note(tmp_path, monkeypatch):
    """One merge point, deterministic precedence."""
    import steering
    note_file = tmp_path / "note.md"
    note_file.write_text("LOOK AT THE RESOURCE SECTION", encoding="utf-8")
    append_steering_note(tmp_path, "focus on network")
    monkeypatch.setenv("REVAI_STEERING_FILE", str(note_file))
    assert steering.effective_steering_note(tmp_path) == \
        "LOOK AT THE RESOURCE SECTION"


def test_pre_run_file_beats_post_hoc_only_when_present(tmp_path, monkeypatch):
    append_steering_note(tmp_path, "focus on network")
    monkeypatch.delenv("REVAI_STEERING_FILE", raising=False)
    assert steering.effective_steering_note(tmp_path) == "focus on network"


def test_no_case_dir_and_no_file_is_just_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("REVAI_STEERING_FILE", raising=False)
    assert steering.effective_steering_note(None) == ""
    assert steering.effective_steering_note(tmp_path) == ""


def test_l3_note_is_framed_as_context_when_it_reaches_the_prompt(tmp_path, monkeypatch):
    """The block is the safety property, whichever level supplied it."""
    import quick_scan_v2
    append_steering_note(tmp_path, "assume it is a loader")
    session = {"sha256": "a" * 64, "sample_path": "/tmp/s",
               "ida_session_id": None}
    monkeypatch.delenv("REVAI_STEERING_FILE", raising=False)
    prompt = quick_scan_v2.build_prompt(
        session, "", "", {}, {}, {}, {}, None,
        steering=effective_steering_note(tmp_path))
    assert "Analyst steering" in prompt
    assert "cannot set, change, or override the verdict" in prompt


def test_history_is_capped(tmp_path):
    """A note per keystroke must not become an unbounded artifact."""
    for i in range(60):
        append_steering_note(tmp_path, f"note {i}")
    history = read_steering_history(tmp_path)
    assert len(history) == 50, len(history)
    assert history[-1]["note"] == "note 59"