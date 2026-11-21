"""RC-97/A3 (2026-11-21): the report itself states function-decompilation
coverage — the measurable answer to the operator's question ("are we even
deciphering every piece of code within the PE?").

Before this, no gate, no verdict, and no report ever stated how many
functions were decompiled — the RE-completeness blind spot. The appendix
now publishes a coverage table whose rows cite their own artifact, and the
assembler merges the sample-wide and payload coverage records the deep dive
wrote (RC-97/A1).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


def _tools(sample_cov=None, payload_cov=None):
    tools = {"malcat": {}}
    if sample_cov:
        tools["malcat"]["decompile_coverage"] = sample_cov
    if payload_cov:
        tools["payload_decompilation"] = {"decompile_coverage": payload_cov}
    return tools


def test_assembler_merges_sample_and_payload():
    cov = v2_lib.assemble_decompile_coverage(_tools(
        sample_cov={"enumerated": 42, "decompiled": 40, "failed": 1,
                    "skipped_budget": 0, "skipped_cap": 1},
        payload_cov={"enumerated": 30, "decompiled": 30, "failed": 0,
                     "skipped_budget": 0, "skipped_cap": 0}))
    assert cov["sample"]["decompiled"] == 40
    assert cov["payload"]["decompiled"] == 30
    assert cov["sample"]["locator"] == "$.malcat.decompile_coverage"
    assert cov["payload"]["locator"] == "$.payload_decompilation.decompile_coverage"


def test_assembler_is_empty_when_nothing_ran():
    assert v2_lib.assemble_decompile_coverage(_tools()) == {}


def test_appendix_publishes_the_coverage_table():
    tools = _tools(
        sample_cov={"enumerated": 42, "decompiled": 40, "failed": 1,
                    "skipped_budget": 0, "skipped_cap": 1},
        payload_cov={"enumerated": 30, "decompiled": 30, "failed": 0,
                     "skipped_budget": 0, "skipped_cap": 0})
    block = v2_lib.build_technical_evidence_block(
        {"sha256": "e" * 64}, None, None, None, tools, [])
    assert "## Function Decompilation Coverage" in block
    rows = [ln for ln in block.splitlines() if ln.startswith("| sample ")]
    assert rows and all("(source: deep_dive/01-tools-raw.json," in ln
                        for ln in rows), (
        "every coverage row cites its own artifact")
    assert "| 42 | 40 | 1 | 0 | 1 |" in rows[0]
