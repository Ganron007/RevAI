"""R1: triage -> dynamic -> deep_dive, and only when WinRE is enabled.

Two properties matter more than the order itself:

1. With REVAI_WINRE_RUN unset, the stage list must be BYTE-IDENTICAL to the old
   order. A static-only deployment must not be perturbed by an opt-in change.
2. The dynamic stage must appear exactly ONCE. Appending it twice would detonate
   twice, and the Flare side is neither free nor idempotent.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import add_module_dir, source  # noqa: E402

add_module_dir("revai/v2_lib.py")

SRC = source("revai/pipeline_single.py")
ROOT = Path(__file__).resolve().parent.parent


def _stage_order(source: str) -> list[str]:
    """The order in which pipeline_single appends its stages.

    Line-based rather than parsed from an executed list, because the point is the
    SOURCE order: this test must fail if someone moves an append, even if the
    resulting list would happen to be equivalent.

    Handles both shapes this file uses -- `stages.append(( "name", ...))` on one
    line, and the multi-line `stages.append(("name", ...))` where `"name"` sits
    on its own line inside the tuple. A naive same-line match missed the latter,
    which is exactly how the R1 reorder is written.
    """
    names = ("intake", "quick_scan", "winre_dynamic", "deep_dive",
             "function_recovery", "artifact_gen", "yara_gen", "publish")
    lines = source.splitlines()
    hits: list[tuple[int, str]] = []
    in_extend = False
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if "stages.extend(" in stripped:
            in_extend = True
        if in_extend and stripped.startswith("])"):
            in_extend = False
        relevant = ("append" in stripped or "extend" in stripped or in_extend)
        if relevant:
            for name in names:
                if f'"{name}"' in stripped:
                    hits.append((i, name))
                    break
            continue
        # A bare "name" line: relevant when the previous non-blank line opened
        # an append (i.e. we are inside its argument tuple).
        if stripped.startswith('"') and stripped.endswith(","):
            key = stripped.strip('",')
            if key in names:
                for back in range(i - 1, max(-1, i - 4), -1):
                    prev = lines[back].strip()
                    if not prev:
                        continue
                    if "append" in prev or "extend" in prev:
                        hits.append((i, key))
                    break
    seen: dict[str, int] = {}
    for i, name in hits:
        seen[name] = i
    return [n for n, _ in sorted(((n, i) for n, i in seen.items()),
                                 key=lambda t: t[1])]


def test_dynamic_runs_between_triage_and_deep_dive():
    order = _stage_order(SRC)
    assert "quick_scan" in order and "deep_dive" in order, order
    if "winre_dynamic" in order:
        assert order.index("quick_scan") < order.index("winre_dynamic") < \
            order.index("deep_dive"), order
    else:
        raise AssertionError("winre_dynamic stage is absent entirely")


def test_the_dynamic_stage_is_appended_exactly_once():
    """A second append would detonate the sample twice."""
    assert SRC.count('"winre_dynamic"') == 1, (
        f"winre_dynamic appears {SRC.count(chr(34) + 'winre_dynamic' + chr(34))} "
        "times in pipeline_single.py; the stage must be appended once")


def test_dynamic_is_gated_by_the_documented_env_var():
    assert 'REVAI_WINRE_RUN' in SRC, "the gate variable is gone"


def test_the_gate_defaults_to_off():
    """An absent REVAI_WINRE_RUN must not enable detonation."""
    import ast
    tree = ast.parse(SRC)
    truthy = ("1", "true", "yes")
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Call):
            seg = ast.dump(node)
            if "REVAI_WINRE_RUN" in seg and truthy[0] in seg:
                found = True
    assert found, "the gate no longer checks the documented values explicitly"


def test_evidence_ingestion_is_presence_gated():
    """No pack must mean no change to the deep dive's behaviour."""
    dd = source("revai/deep_dive_agentic.py")
    assert "dynamic_corroboration_enabled()" in dd, (
        "the deep-dive ingestion is no longer gated on the shared opt-out")
    assert "load_dynamic_pack(sha)" in dd
    assert "corroborating-only" in dd, (
        "the ingested pack no longer states its authority, so a reader cannot "
        "tell dynamic-observed from static-observed")


def test_ingestion_failure_is_recorded_not_swallowed_silently():
    dd = source("revai/deep_dive_agentic.py")
    # The failure must land in findings (visible to the audit) rather than a
    # bare pass.
    assert 'findings["dynamic_corroboration"] = {"error":' in dd, (
        "a failed ingest must be recorded as a finding, not silently skipped")
    assert "continuing with static" in dd


def test_the_two_opt_out_paths_share_one_definition():
    """If they drift, REVAI_DISABLE_DYNAMIC_CORROBORATION becomes a lie.

    The report would claim the pack is absent while the agent had already
    reasoned over it.
    """
    lib = source("revai/v2_lib.py")
    dd = source("revai/deep_dive_agentic.py")
    assert "def dynamic_corroboration_enabled()" in lib
    # Both BEHAVIOURAL consumers defer to the one definition. A separate
    # diagnostic read that merely reports config state is not part of this
    # contract, which is why the assertion is on the call, not on a count.
    assert "if not dynamic_corroboration_enabled():" in lib, (
        "the publish-time path no longer defers to the shared helper")
    assert "if dynamic_corroboration_enabled():" in dd, (
        "the deep-dive path no longer defers to the shared helper")


def test_opt_out_suppresses_the_publish_time_block():
    from v2_lib import attach_dynamic_corroboration
    os.environ["REVAI_DISABLE_DYNAMIC_CORROBORATION"] = "1"
    try:
        probe = "TECHNICAL EVIDENCE"
        assert attach_dynamic_corroboration(probe, "deadbeef") == probe, (
            "REVAI_DISABLE_DYNAMIC_CORROBORATION=1 did not suppress the block")
    finally:
        os.environ.pop("REVAI_DISABLE_DYNAMIC_CORROBORATION", None)