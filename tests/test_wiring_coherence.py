#!/usr/bin/env python3
"""Regression guard: the pipeline stays wired the way it was designed.

Runs the same checks as `revai/verify_pipeline.py` inside pytest, so registry
drift (a manifest tool without a callable, an agent tool with no description, a
LangGraph tool missing from the registry, undocumented env vars, doc count drift,
forbidden references) fails the test suite rather than being noticed in review.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import verify_pipeline as vp  # noqa: E402


def test_pipeline_wiring_is_coherent(capsys):
    results, failures, _warnings = vp.run_checks()
    capsys.readouterr()  # the harness prints; keep pytest output clean
    assert results, "verification harness produced no results"
    assert not failures, "wiring regressions: " + "; ".join(failures)


def test_registry_and_manifest_counts_are_expected(capsys):
    vp.run_checks()
    capsys.readouterr()
    counts = {r["check"]: r["detail"] for r in vp.RESULTS}
    # These two numbers appear in the public docs; pin them so a silent change
    # fails here first (update the docs in the same commit when they change).
    assert counts.get("manifest.fn", "").startswith("28 manifest tools")
    assert counts.get("registry.descriptions", "").startswith("25 agent tools")
