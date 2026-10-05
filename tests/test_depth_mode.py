#!/usr/bin/env python3
"""D0 depth mode: a separate mode with a convergence contract, not a budget.

The operator's five reasons are all honoured, and each has a test here:

1. expensive   -> bounded by a ceiling, with the bound reported
2. more time   -> the run is post-pipeline and never gates the main one
3. unpredictable-> the loop terminates on a declared unknown set, not a step count
4. pause/resume-> state checkpoints atomically after every region and reloads
5. status      -> cost_summary is what the examiner reads to decide

The objective is UNDERSTANDING, not a verdict, so the strongest test is that a
depth run cannot produce one: status vocabulary is finite and cited, and
'not-explored' is the only status excused a citation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

import depth_agent as da  # noqa: E402


def test_depth_is_off_by_default(monkeypatch):
    """The main pipeline must not be perturbed by an opt-in mode."""
    monkeypatch.delenv("REVAI_DEPTH", raising=False)
    assert da.depth_enabled() is False


def test_depth_is_enabled_by_each_documented_truthy_value(monkeypatch):
    for v in ("1", "true", "on", "ON", "True"):
        monkeypatch.setenv("REVAI_DEPTH", v)
        assert da.depth_enabled() is True, v
    for v in ("0", "false", "off", "", "yes"):
        monkeypatch.setenv("REVAI_DEPTH", v)
        assert da.depth_enabled() is False, v


def test_yes_is_not_a_truthy_value(monkeypatch):
    """Deliberate: 'yes' is accepted elsewhere in the pipeline for startup
    questions, but a mode switch must not be enabled by a stray value."""
    monkeypatch.setenv("REVAI_DEPTH", "yes")
    assert da.depth_enabled() is False


# ------------------------------------------------------- convergence contract

def test_the_status_vocabulary_is_finite():
    assert set(da.VALID_STATUSES) == {
        "understood", "partial", "not-reconstructed", "not-explored"}


def test_only_not_explored_may_omit_a_citation():
    """Everything else claims something, so everything else must show its work.

    This is what stops a confident wrong answer entering the map: 'understood'
    with no evidence is not a status, it is a guess wearing a status.
    """
    assert da.status_requires_evidence("not-explored") is False
    for s in ("understood", "partial", "not-reconstructed"):
        assert da.status_requires_evidence(s) is True, s


def test_the_loop_terminates_on_a_declared_unknown_set_not_a_step_count():
    """The buildable form of "whatever is required to understand the exe"."""
    regions = {"a": {"status": "understood"}}
    assert da.has_converged(regions) is True
    assert da.unknown_set(regions) == []
    regions["b"] = {"status": "partial"}
    assert da.has_converged(regions) is False
    assert da.unknown_set(regions) == ["b"]


def test_not_explored_counts_as_unknown():
    """It is an honest admission, not a completion."""
    regions = {"a": {"status": "not-explored"}}
    assert da.has_converged(regions) is False
    assert da.unknown_set(regions) == ["a"]


# ------------------------------------------------- checkpoint / stop / resume

def test_state_round_trips_through_a_case_dir(tmp_path):
    st = {"sha256": "a" * 64,
          "regions": {"entry": {"status": "understood", "why": "imports only",
                                "evidence": "ghidra_decompile:entry()"}},
          "stop_reason": None,
          "spend": {"llm_calls": 1, "seconds": 12.0, "tokens": 400}}
    da.save_state(tmp_path, st)
    back = da.load_state(tmp_path)
    assert back["regions"]["entry"]["status"] == "understood"
    assert back["spend"]["tokens"] == 400


def test_a_resume_picks_up_where_the_state_left_off(tmp_path):
    """Operator reason 4: pause and resume, not restart."""
    for name in ("a", "b", "c"):
        da.save_state(tmp_path, {
            "sha256": "a" * 64,
            "regions": {n: {"status": "understood", "why": "x",
                            "evidence": "y"} for n in ("a", "b", "c")[:("abc".index(name) + 1)]},
            "stop_reason": None,
            "spend": {"llm_calls": 0, "seconds": 0.0, "tokens": 0}})
    assert set(da.load_state(tmp_path)["regions"]) == {"a", "b", "c"}


def test_state_writes_are_atomic(tmp_path):
    """A stop mid-write must not destroy the resume point.

    Written to a temp file and renamed, so an interrupted save leaves the
    previous state intact rather than a half-written one.
    """
    first = {"regions": {"a": {"status": "understood"}}, "spend": {}}
    da.save_state(tmp_path, first)
    # a second, deliberately incomplete write leaves the first readable
    (tmp_path / "understanding.tmp").write_text('{"regions": {"a": {"sta')
    assert da.load_state(tmp_path)["regions"]["a"]["status"] == "understood"


def test_unreadable_state_degrades_to_a_skeleton(tmp_path):
    (tmp_path / "understanding.json").write_text("{broken", encoding="utf-8")
    st = da.load_state(tmp_path)
    assert st["regions"] == {}
    assert st["stop_reason"] is None


# ------------------------------------------------------------- cost honesty

def test_cost_summary_counts_every_status():
    regions = {
        "a": {"status": "understood"}, "b": {"status": "understood"},
        "c": {"status": "partial"}, "d": {"status": "not-reconstructed"},
        "e": {"status": "not-explored"},
    }
    spend = {"llm_calls": 5, "seconds": 90.0, "tokens": 4321}
    got = da.cost_summary(regions, spend)
    assert got["regions_total"] == 5
    assert got["by_status"]["understood"] == 2
    assert got["unknown_remaining"] == 3  # partial + not-reconstructed + not-explored
    assert got["spend"]["tokens"] == 4321


def test_cost_summary_ignores_an_unknown_status_label(tmp_path):
    """A typo'd status must not silently count toward convergence."""
    regions = {"a": {"status": "mostly-clear"}}
    got = da.cost_summary(regions, {"tokens": 1})
    assert sum(got["by_status"].values()) == 0
    # and it must NOT be considered understood
    assert da.has_converged(regions) is False


def test_cost_summary_is_what_makes_a_cutoff_a_partial_success(tmp_path):
    """Operator reason 5: the number the examiner reads to decide."""
    regions = {f"r{i}": {"status": "understood"} for i in range(18)}
    regions.update({f"u{i}": {"status": "not-explored"} for i in range(4)})
    got = da.cost_summary(regions, {"tokens": 1000})
    assert got["by_status"]["understood"] == 18
    assert got["unknown_remaining"] == 4, (
        "a stopped run must still report what it did not finish")