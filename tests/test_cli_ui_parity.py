#!/usr/bin/env python3
"""CLI/UI parity for FEATURE gates.

The first version scanned every env var the pipeline reads and flagged 55 --
almost all internal plumbing (tool binary paths, per-tool timeouts, LLM budget
and rate limits, test hooks, layout paths). Requiring a Console surface for
CADRE_CAPA_RULES is noise, and a test that cries wolf gets exempted wholesale,
which is how the real gaps survived the earlier audits.

So the scope is deliberate: gates an OPERATOR thinks of as a feature --
something they turn on to change what the analysis does. Everything else is
exempt BY CATEGORY with a reason, never a blanket pass.

The three real gaps this caught (depth_agent.py absent from app.py,
REVAI_TI_ENRICH and REVAI_DEPTH_CEILING_SECONDS in no settings key list) are all
feature-shaped, which is the point.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import code_files, resolve  # noqa: E402

#: Feature-shaped: a gate whose VALUE changes what the pipeline does, as opposed
#: to where a binary lives or how long a tool may run.
_FEATURE_RE = re.compile(
    r"^(?:REVAI_ENABLE_[A-Z_]+|REVAI_DEPTH|REVAI_DEPTH_[A-Z_]+|"
    r"REVAI_STEERING_[A-Z_]+|REVAI_WINRE_RUN|REVAI_TI_ENRICH|"
    r"REVAI_TECHNICAL_[A-Z_]+|REVAI_IOC_[A-Z_]+|REVAI_ALLOW_[A-Z_]+|"
    r"REVAI_DISABLE_[A-Z_]+)$")

#: Reachable from the Console under another name, or not a feature at all.
EXEMPT = {
    "REVAI_ENABLE_EMULATION_ORACLE": "run_config.emulation_oracle",
    "REVAI_ENABLE_UNPACK_PASS": "run_config.unpack_pass",
    "REVAI_ENABLE_ARTIFACT_GEN": "run_config.artifact_gen",
    "REVAI_ENABLE_AGENTIC_RECOVERY": "run_config.agentic_recovery",
    "REVAI_TECHNICAL_SECTIONWISE": "the Console always runs the v3 path",
    "REVAI_DISABLE_ANALYSIS_SCRIPTS": "operator-only; the script stage is opt-in",
    "REVAI_DISABLE_IOC_CONFIDENCE": "tier display, not an analysis behaviour",
    "REVAI_DEPTH_CEILING_SECONDS": "run_config.depth_ceiling_seconds",
    "REVAI_TI_ENRICH": "run_config.ti_enrich",
    "REVAI_STEERING_FILE": "the Console records a note instead (POST /api/steer)",
    "REVAI_DISABLE_DYNAMIC_CORROBORATION": "WinRE settings: winre_dynamic=off",
    "REVAI_DISABLE_DYNAMIC_SECTION": "WinRE settings: winre_dynamic=off",
    "REVAI_WINRE_RUN": "run_config.winre_run",
}


def _feature_gates() -> set[str]:
    """Feature-shaped env gates the pipeline reads, excluding app.py itself."""
    gates = set()
    for p in code_files():
        if p.name == "app.py":
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(
                r"os\.environ(?:\.get)?\s*[(\[]\s*[\"'](REVAI_[A-Z_]+)[\"']",
                txt):
            g = m.group(1)
            if _FEATURE_RE.match(g):
                gates.add(g)
    return gates


def test_every_feature_gate_is_reachable_from_the_console_or_exempt():
    app = resolve("revai/app.py").read_text(encoding="utf-8", errors="replace")
    run_cfg = set(re.findall(r'"([a-z_0-9]+)"', app))
    unreachable = []
    for gate in sorted(_feature_gates()):
        if gate in EXEMPT or gate in app:
            continue
        # a run_config key reaches the stage through get_stage_env, so the gate
        # is reachable from the Console under its rc name
        snake = re.sub(r"^REVAI_(ENABLE_)?", "", gate).lower()
        if snake in run_cfg:
            continue
        unreachable.append(gate)
    assert not unreachable, (
        "these FEATURE gates are read by the pipeline but the Console cannot "
        f"set them: {unreachable}\nWire them (run_config + get_stage_env), or "
        "add them to EXEMPT naming the surface they are reachable through.")


def test_depth_mode_is_runnable_from_the_console():
    """The specific defect: depth_agent.py appeared nowhere in app.py."""
    app = resolve("revai/app.py").read_text(encoding="utf-8", errors="replace")
    assert "depth_agent.py" in app, (
        "the Console has no depth stage: the CLI runs it and the UI silently "
        "cannot -- the exact parity gap this file exists for")
    assert '"depth": ["audit"]' in app, (
        "the depth stage must depend on the audit, as the scripted spine "
        "orders it")


def test_the_depth_button_sets_its_own_gate():
    app = resolve("revai/app.py").read_text(encoding="utf-8", errors="replace")
    assert "REVAI_DEPTH=1" in app, (
        "the Console's depth stage must set REVAI_DEPTH=1 itself; requiring the "
        "operator to also export it by hand is the parity gap")


def test_the_two_new_gates_round_trip_through_run_config():
    app = resolve("revai/app.py").read_text(encoding="utf-8", errors="replace")
    for key in ('"ti_enrich"', '"depth_ceiling_seconds"'):
        assert key in app, f"{key} is not persisted from the Console"
    assert "REVAI_TI_ENRICH" in app and "REVAI_DEPTH_CEILING_SECONDS" in app, (
        "the Console must translate run_config into the env vars a stage reads")
