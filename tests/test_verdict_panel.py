"""The verdict PANEL beats the prose keyword heuristic.

The heuristic reads the first 2500 characters of a report and looks for
words like "benign" or "malicious". A master report whose executive summary
explains WHY a benign reading cannot stand ("a benign/legitimate tool cannot
stand") was read as a 'benign' report, while its own verdict panel said
'malicious'. The audit then reported a false
`cross_report:master_tech_verdict_mismatch(master=benign, technical=malicious)`.

The panel is the report's own structured verdict statement, so it is consulted
before the prose heuristic.
"""
from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402


MASTER = """# Executive Summary

- The binary masquerades as a Microsoft tool. A benign or legitimate reading
  cannot stand: the imports and the staged payload say otherwise.
- The pipeline-selected verdict for this sample is 'malicious'.

| Field | Value | Basis | Evidence |
| --- | --- | --- | --- |
| Verdict | malicious | Pipeline triage + deep-dive + agentic judge (score 91) | (source: verdict, query_or_table: verdict.json, row_or_rule: $.verdict) |
"""


def test_the_verdict_panel_wins_over_a_clearance_word_in_the_prose():
    assert v2_lib.infer_publish_verdict_from_markdown(MASTER) == "malicious"


def test_an_explicit_verdict_sentence_still_wins():
    md = "# Report\n\n**Verdict: SUSPICIOUS (score 30)**\n\n" + MASTER
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "suspicious"
