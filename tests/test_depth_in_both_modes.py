#!/usr/bin/env python3
"""Regressions for D53 (depth mode absent from the agentic spine) and D52.

D53: `REVAI_DEPTH=1` plus `--mode agentic` produced a green run with no
understanding.json and nothing in the trace saying depth was skipped.
stage_orchestrator.py had zero references to REVAI_DEPTH / depth_agent /
depth_understanding, so the env gate was honoured by the scripted spine and
silently ignored by the agentic one. Found by running BOTH modes on the same
sample (sha 18df68d) and diffing the artifacts:

  scripted  10 stages, understanding.json written
  agentic   10 stages, no depth stage, 'depth' absent from 31 events
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve, source  # noqa: E402


def test_the_agentic_spine_has_a_depth_stage():
    """The agentic driver must know depth exists, or the env gate is a lie."""
    src = source("revai/stage_orchestrator.py")
    assert "depth_understanding" in src, (
        "the agentic spine has no depth stage: REVAI_DEPTH=1 with "
        "--mode agentic is silently ignored and produces no understanding.json")
    assert "REVAI_DEPTH" in src or "depth_enabled" in src, (
        "the depth stage is not gated by the same helper the scripted spine uses")


def test_both_spines_gate_depth_the_same_way():
    """One gate, two drivers. Two copies is how they drift apart."""
    ps = source("revai/pipeline_single.py")
    so = source("revai/stage_orchestrator.py")
    assert "depth_enabled()" in ps, "the scripted spine lost the shared gate"
    assert "depth_enabled" in so, "the agentic spine must use the shared gate too"


def test_a_skipped_depth_stage_is_visible_not_silent():
    """With the gate off the trace must say so, not pretend the stage ran."""
    sys.modules.pop("stage_orchestrator", None)
    d = resolve("revai/stage_orchestrator.py").parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import stage_orchestrator as so  # noqa: PLC0415

    r = so.StageRunner.__new__(so.StageRunner)
    r.sha = "a" * 64
    r.events = []
    os.environ.pop("REVAI_DEPTH", None)
    try:
        out = r.run_depth()
    finally:
        os.environ.pop("REVAI_DEPTH", None)
    assert out.get("skipped") is True, out
    assert "REVAI_DEPTH" in out.get("reason", ""), (
        "the skip reason must name the gate, or a reader cannot tell why depth "
        "did not run")
    assert any(e.get("tool") == "depth_understanding" for e in r.events), (
        "the skip must land in the trace: a stage that never appears is "
        "indistinguishable from one that was never asked for")


def test_run_depth_never_gates_the_pipeline():
    """Depth's objective is understanding, so its failure must not fail the run."""
    src = source("revai/stage_orchestrator.py")
    i = src.find("def run_depth")
    assert i > 0
    body = src[i:i + 2600]
    # every failure path returns a dict; none raises
    assert "return {\"ok\": True, \"skipped\": True" in body, (
        "a depth failure must degrade to a recorded skip, not an exception")
    assert "TimeoutExpired" in body, (
        "the ceiling is a consolidate-and-declare, not a failed run")
