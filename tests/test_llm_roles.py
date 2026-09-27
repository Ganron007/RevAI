#!/usr/bin/env python3
"""LLM role routing: default vs tool loop vs judgment.

RevAI resolves three independent roles from the env file:
- default   REVAI_LLM_MODEL          tool loop + triage + deep dive + reports
- tool loop REVAI_LLM_PLANNER_MODEL  the agentic planner bound to the ReAct loop
- judgment  REVAI_LLM_VERDICT_MODEL  the agentic final judge only

Regression (2026-09-27): get_llm_model() returned the judgment model, so pinning
REVAI_LLM_VERDICT_MODEL dragged every pipeline call onto it and REVAI_LLM_MODEL
became dead config. These tests pin the intended routing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402

_ROLES = ("REVAI_LLM_MODEL", "REVAI_LLM_PLANNER_MODEL", "REVAI_LLM_VERDICT_MODEL")


def _clear(monkeypatch) -> None:
    for var in _ROLES:
        monkeypatch.delenv(var, raising=False)


def test_operator_routing_fast_everywhere_but_the_judge(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("REVAI_LLM_MODEL", "fast-model")
    monkeypatch.setenv("REVAI_LLM_PLANNER_MODEL", "fast-model")
    monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", "heavy-model")

    assert v2_lib.get_default_model() == "fast-model"
    assert v2_lib.get_planner_model() == "fast-model"   # tool loop
    assert v2_lib.get_llm_model() == "fast-model"      # triage / deep dive / reports
    assert v2_lib.get_verdict_model() == "heavy-model"  # judgment role only


def test_a_judgment_pin_does_not_move_the_rest_of_the_pipeline(monkeypatch):
    """The 2026-09-27 bug in one assertion: pinning the judge used to move all."""
    _clear(monkeypatch)
    monkeypatch.setenv("REVAI_LLM_MODEL", "fast-model")
    monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", "heavy-model")

    assert v2_lib.get_llm_model() == "fast-model"
    assert v2_lib.get_planner_model() == "fast-model"
    assert v2_lib.get_verdict_model() == "heavy-model"


def test_planner_pin_falls_back_to_the_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("REVAI_LLM_MODEL", "fast-model")
    monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", "heavy-model")

    assert v2_lib.get_planner_model() == "fast-model"


def test_judgment_pin_falls_back_to_the_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("REVAI_LLM_MODEL", "quality-model")

    assert v2_lib.get_verdict_model() == "quality-model"


def test_a_judgment_pin_alone_still_gives_every_role_a_model(monkeypatch):
    """Operator pinned only the judge: no call may end up model-less."""
    _clear(monkeypatch)
    monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", "heavy-model")

    assert v2_lib.get_default_model() == "heavy-model"
    assert v2_lib.get_planner_model() == "heavy-model"
    assert v2_lib.get_llm_model() == "heavy-model"
    assert v2_lib.get_verdict_model() == "heavy-model"


def test_no_pins_is_a_no_op(monkeypatch):
    _clear(monkeypatch)
    for getter in (
        v2_lib.get_default_model,
        v2_lib.get_planner_model,
        v2_lib.get_llm_model,
        v2_lib.get_verdict_model,
    ):
        assert getter() == v2_lib._DEFAULT_MODEL


def test_console_role_pins_survive_a_console_default_model(monkeypatch):
    """Console-started runs: the default may be overridden, the roles may not.

    Pairs with tests/test_winre_ui_option.py::test_console_model_keeps_the_files_
    planner_and_verdict_pins (env mapping) - this asserts the resolution end.
    """
    import app as app_mod  # noqa: PLC0415

    monkeypatch.setattr(app_mod, "load_config", lambda: {"llm_model": "console-model"})
    monkeypatch.setenv("REVAI_LLM_PLANNER_MODEL", "file-planner")
    monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", "file-judge")
    env = app_mod.get_stage_env({})
    for key, value in env.items():
        if key.startswith("REVAI_LLM_"):
            monkeypatch.setenv(key, value)

    assert v2_lib.get_default_model() == "console-model"
    assert v2_lib.get_llm_model() == "console-model"
    assert v2_lib.get_planner_model() == "file-planner"
    assert v2_lib.get_verdict_model() == "file-judge"


# --- the scripted judgment sites must use the judgment model ---------------
#
# quick_scan's triage verdict and deep_dive_v2's judge are the scripted
# pipeline's judgments about the sample, so they take the judgment role's model
# (REVAI_LLM_VERDICT_MODEL). Checked structurally: the stages are full evidence
# pipelines, so the contract is the getter each `model = ...` assignment uses.


@pytest.mark.parametrize("module_name", ["quick_scan_v2", "deep_dive_v2"])
def test_scripted_judgment_sites_use_the_judgment_model(module_name):
    import ast

    source = (ROOT / "revai" / f"{module_name}.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    getters = {
        node.value.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id.endswith("_model")
        for target in node.targets
        if isinstance(target, ast.Name) and target.id == "model"
    }
    assert getters, f"{module_name}: no model getter assignment found"
    assert getters == {"get_verdict_model"}, (
        f"{module_name}: the scripted judgment must use the judgment role's "
        f"model, found {sorted(getters)}"
    )
