#!/usr/bin/env python3
"""Regressions for defects found by the FIRST full-pipeline sample run.

Sample: SmartApeSG client32.exe (sha 18df68d...), scripted mode, fresh boot,
all features enabled. Every stage rc=0, audit all_green=True -- and two deployed
features did not work.

DEFECT A (high) - the skills layer is bound on the default engine but never
advertised. The deep dive ran on LangGraph (the default), load_skill was in
AGENT_TOOL_NAMES and confirmed bound on the deployed file, yet across 42 agent
steps and 20 distinct tool calls there were ZERO load_skill references in the
470 KB artifact. Cause: the "procedures are loaded with the load_skill tool"
instruction lives only in deep_dive_agentic.build_messages() -- the CUSTOM
engine's prompt. agentic_langgraph builds its own system_prompt and never
imports build_messages, so on the default engine the model is never told the
procedures exist. Same class as the 2026-10-05 binding bug: the prompt names a
tool on one path while the path that runs is a different one.

DEFECT B (high) - depth_understanding reported a hollow green. The stage trace
recorded rc=0 ok=True in 0.1s, no understanding.json was produced, and stdout
showed regions_total=0 with spend.llm_calls=0. The CLI was correct; the stage
simply had no way to say "I did nothing".
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))

from _layout import resolve, source  # noqa: E402


def _load(modname: str):
    sys.modules.pop(modname, None)
    d = resolve(f"revai/{modname}.py").parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import importlib
    return importlib.import_module(modname)


# =========================== DEFECT A: skills advertised ====================

def test_both_engines_carry_the_procedure_grounding_instruction():
    """The instruction must exist on the path that actually runs.

    Asserted on the LangGraph system prompt as well as build_messages, because
    the engine that runs by default is LangGraph, and an instruction only the
    other engine sees is an instruction that is not sent.
    """
    lg = source("revai/agentic_langgraph.py")
    assert "skill_block" in lg, (
        "the LangGraph system prompt has no procedure-grounding block, so the "
        "model is never told load_skill exists -- the skills layer contributes "
        "nothing on the default engine")
    dd = source("revai/deep_dive_agentic.py")
    assert "PROCEDURE GROUNDING" in dd, (
        "the custom engine lost the instruction")


def test_the_grounding_block_has_one_definition():
    """Two copies of a prompt fragment is how this drifted in the first place."""
    sk = source("revai/skills.py")
    assert sk.count("SKILL_GROUNDING = ") == 1, (
        "more than one copy of the grounding block exists")
    lg = source("revai/agentic_langgraph.py")
    assert "skill_grounding_block as _skill_grounding_block" in lg, (
        "the LangGraph engine must import the shared block, not inline its own")


def test_the_grounding_block_renders_the_live_index():
    skills = _load("skills")
    block = skills.skill_grounding_block()
    names = sorted(skills.list_skills())
    assert names, "no skills on disk to advertise"
    for n in names:
        assert n in block, f"{n} is deployable but not advertised to the model"
    # the load-bearing wording, not decoration
    assert "load_skill" in block
    assert "BEFORE" in block or "before" in block, (
        "the block must say the procedure is loaded before the work, or the "
        "model will call it after it has already answered")
    assert "not evidence" in block, (
        "methodology must not be citable as a finding")
    assert "verdict-calibration" in block, (
        "the one skill whose absence directly degrades the verdict must be "
        "named explicitly")


def test_the_grounding_block_is_honest_when_no_skills_are_deployed(monkeypatch, tmp_path):
    skills = _load("skills")
    monkeypatch.setattr(skills, "SKILLS_DIR", tmp_path / "absent")
    block = skills.skill_grounding_block()
    assert "no reverse-engineering procedures are deployed" in block, (
        "an empty index must be reported, not rendered as an empty list that "
        "invites a call which cannot succeed")


def test_load_skill_and_api_lookup_are_both_bound_to_the_default_engine():
    """The 2026-10-05 fix, re-pinned from the sample run's vantage point."""
    lg = source("revai/agentic_langgraph.py")
    tree = ast.parse(lg)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "AGENT_TOOL_NAMES":
                    names |= {s.value for s in ast.walk(node.value)
                              if isinstance(s, ast.Constant)}
    for tool in ("load_skill", "api_lookup"):
        assert tool in names, (
            f"{tool} is not bound to the default engine: the prompt names it "
            "and the call cannot execute")


# =========================== DEFECT B: honest depth report =================

def test_a_depth_run_that_did_nothing_reports_itself(capsys, tmp_path):
    """rc=0 with an empty map must not read as a completed depth run."""
    da = _load("depth_agent")
    case = tmp_path / "case"
    case.mkdir()
    argv = sys.argv
    sys.argv = ["depth_agent.py", str(case)]
    try:
        rc = da._cli()
        out = capsys.readouterr()
    finally:
        sys.argv = argv
    payload = json.loads(out.out)
    assert rc == 0
    assert "no-depth-analysis-performed" in payload["stop_reason"], (
        "a stage that did no work must say so in the artifact")
    assert payload.get("understanding_json"), (
        "the stage must leave the artifact behind; an empty run that writes "
        "nothing is indistinguishable from one that found nothing")
    assert (case / "understanding.json").is_file()
    assert "WARNING" in out.err, "and say it on stderr where the watcher sees it"


def test_a_depth_run_with_regions_does_not_claim_deferral(capsys, tmp_path):
    """The deferral message must only fire when nothing actually ran."""
    da = _load("depth_agent")
    case = tmp_path / "case"
    case.mkdir()
    (case / "understanding.json").write_text(json.dumps({
        "sha256": "a" * 64,
        "regions": {"f1": {"status": "understood", "evidence": "x"}},
        "spend": {"llm_calls": 3},
    }), encoding="utf-8")
    argv = sys.argv
    sys.argv = ["depth_agent.py", str(case)]
    try:
        da._cli()
        out = capsys.readouterr()
    finally:
        sys.argv = argv
    payload = json.loads(out.out)
    assert "no-depth-analysis-performed" not in (payload["stop_reason"] or "")
    assert payload["regions_total"] == 1


# =========================== DEFECT C: panel reader blind to v3 ==============

def test_the_panel_reader_reads_both_report_formats():
    """The v3 inline panel must parse, or the cross-report check goes blind.

    Sample run sha 18df68d produced five reports, four of them v3, and the audit
    went red with `verdict.panels_unreadable: 5 report(s) present but only 1
    verdict panel(s) parseable`. The reports were complete (13/13 and 17/17,
    quality_ok=True) and every one stated its verdict in prose. `_TICKER_RE`
    matched only the v2 table row `| **Final** | *x* |`, so since #39 shipped a
    section-wise v3 report the cross-report agreement check had nothing to
    compare on -- a check that cannot see the format it is asked to check.

    The formats below are the ones the reports actually emit, taken from that
    run's artifacts.
    """
    sys.modules.pop("hollow_success", None)
    d = resolve("revai/hollow_success.py").parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import hollow_success as hs  # noqa: PLC0415

    real_formats = [
        # v2 table row, as REPORT-TECHNICAL-v2.md writes it
        "| **Final** | **suspicious** |",
        # v3 inline panel, as REPORT-MASTER-v3.md writes it
        "**Verdict: suspicious** (confidence: 70/100, source: deep_dive_agentic; "
        "agreement: llm_and_v1_agree).",
        # v3 technical, as REPORT-TECHNICAL-v3.md writes it
        "**Verdict:** `suspicious` (score 45), `family_guess = X`",
    ]
    for text in real_formats:
        m = hs._TICKER_RE.search(text)
        assert m, f"the panel reader cannot parse a format the reports emit: {text[:60]}"
        verdict = (m.group(1) or m.group(2) or "").strip().lower()
        assert verdict == "suspicious", f"{text[:50]} -> {verdict!r}"


def test_the_panel_reader_is_not_satisfied_by_prose_about_verdicts():
    """The v3 alternative must not become a loose 'verdict: <word>' match.

    A report that discusses verdicts in prose would otherwise satisfy the
    cross-report agreement check while saying nothing about its own verdict --
    which is how this check would stop meaning anything. The confidence clause
    is what anchors it.
    """
    sys.modules.pop("hollow_success", None)
    d = resolve("revai/hollow_success.py").parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import hollow_success as hs  # noqa: PLC0415

    prose = ("The verdict panel was repaired; see the verdict column. "
             "Why the verdict is suspicious rather than clean.")
    assert not hs._TICKER_RE.search(prose), (
        "the reader matched prose that merely discusses verdicts")
