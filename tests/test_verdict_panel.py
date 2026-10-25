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


# --- RC-17: a QUOTED discrepancy is not the report's own verdict -------------
# Run 65be0144 (latent): the report contained "the same artifact's summary
# text reads 'Verdict: SUSPICIOUS (score 58)'" while its own verdict was
# malicious. The explicit-sentence regex can match the quoted text; only the
# accident of the own sentence appearing first kept the result correct.

QUOTED_DISCREPANCY = (
    "# Cross-Check\n\nThe same artifact's summary text reads "
    "'Verdict: SUSPICIOUS (score 58)', which differs from this analysis.\n\n"
)


def test_quoted_discrepancy_loses_to_the_reports_own_statement():
    md = QUOTED_DISCREPANCY + MASTER
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "malicious"


def test_quoted_discrepancy_after_the_own_statement_is_ignored():
    md = MASTER + "\n## Appendix\n\n" + QUOTED_DISCREPANCY
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "malicious"


def test_metalinguistic_prefix_classification():
    f = v2_lib._verdict_match_is_metalinguistic
    # Reported speech, quote opened before the verdict phrase.
    assert f("The same artifact's summary text reads 'Verdict: SUSPICIOUS'", 41)
    # Double-quoted variant.
    assert f('The summary states "Verdict: SUSPICIOUS"', 21)
    # Reporting verb with "the" between it and the phrase.
    assert f("The analyst's note says the verdict is suspicious", 28)
    # The RC-04 own-statement shape stays accepted (quote opens after "is").
    assert not f("The triage verdict for this sample is 'malicious'", 0)
    # A reporting verb followed by a comma is not immediately adjacent.
    assert not f("As the evidence shows, the verdict is malicious", 27)
    # An apostrophe inside a possessive is not a quote opener.
    assert not f("The analyst's note: the verdict is malicious", 25)
    # Empty prefix.
    assert not f("Verdict: malicious", 0)


def test_the_calibration_annotation_is_the_published_verdict():
    """RC-04b (option b): the annotation is the FIRST explicit verdict
    sentence, so re-derivation reads the calibrated label even when the body
    still narrates the raw triage verdict."""
    md = (
        "# REPORT-MASTER-v2\n\n"
        "> **[Verdict calibration]** The published verdict for this sample "
        "is **suspicious**. The raw publish-model claim (malicious) was "
        "calibrated to suspicious: protection/obfuscation signals present "
        "but no behavioral-intent evidence. The raw pipeline-selected label "
        "remains recorded in verdict.json and the publish record.\n\n"
        "## Executive Summary\n\n"
        "The triage verdict for this sample is 'malicious' with a score of 90.\n"
    )
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "suspicious"
