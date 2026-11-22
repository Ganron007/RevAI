"""RC-107 (re-run 27, 2026-11-22): the last publish red, in two parts.

Re-run 27 (marker `95fa8a6` = RC-106 live): the MASTER v2 finished fully
clean (0/0/0 -- the CLSID unverified-IoC class and the orphan class are
dead) and the technical failed on `uncited_claim_count: 3` ONLY:

* `[[redacted: not in evidence][8]] ea=80, summary=This program mus..`
* `[[redacted: not in evidence][10]] ea=80976, summary=This program mus..`
* `[payload_feedback.[redacted: not in evidence][8]] ea=68700, summary=Error: system co..`

Part 1 -- the scrub: the writer's own row labels render the tool locator in
its BARE dotted spelling (`[malcat.views.strings[8]]`,
`[payload_feedback.views.strings[8]]`). The domain-shape regex matches
those dotted identifiers (and can even match the substring after an
underscore, `feedback.views.strings`), the dotted spelling is never a
literal in the raw-JSON corpus, so the probe failed and the scrub mangled
the locator into `[redacted: not in evidence]`. RC-62 exempted the
`$`-prefixed spelling, citations, separators and file extensions -- the
bare JSONPath row label was the gap.

Part 2 -- the gate: malcat truncates its string summaries with an ellipsis
("This program mus.."). The sentence splitter treats the `..` as a
sentence end, orphaning the row-label fragment from the citation that
follows it on the same line. The splitter's own docstring says evidence
locators quote tool output containing periods OR ELLIPSES -- it handled
the citation-internal case only.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "revai"))

import report_quality as RQ  # noqa: E402
import section_publisher as SP  # noqa: E402

CIT = ("(source: deep_dive/01-tools-raw.json, query_or_table: "
       "deep_dive/01-tools-raw.json, row_or_rule: malcat.views.strings[8])")


@pytest.fixture
def scrub(monkeypatch):
    """The scrub pointed at a corpus that lacks the dotted JSONPath
    spelling -- exactly the raw-JSON situation."""
    monkeypatch.setattr(SP, "collect_evidence_text",
                        lambda root: ('{"malcat": {"views": {"strings": []}}}',
                                      ["synthetic"]))
    monkeypatch.setattr(SP, "case_dir", lambda sha: Path("/nonexistent"))


# ---------------------------------------------------------------------------
# Part 1 -- a JSONPath row label is a locator, not a domain
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label", [
    "malcat.views.strings",
    "payload_feedback.views.strings",
    "feedback.views.strings",       # the substring after the underscore
    "deep_dive.01-tools-raw",
], ids=["malcat", "payload", "underscore-substring", "deep-dive"])
def test_a_jsonpath_row_label_is_not_scrubbed(scrub, label):
    """A domain-shaped token immediately followed by a JSONPath bracket
    segment is an artifact path (RC-62 doctrine: a locator is not an
    indicator)."""
    line = f"- [{label}[8]] ea=80, summary=truncated.. {CIT}"
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "[redacted" not in out, f"{label} is a locator, not a domain"
    assert f"[{label}[8]]" in out


def test_a_real_domain_is_still_scrubbed(scrub):
    """The #42 fabrication class is untouched: a domain-shaped token that
    is NOT a locator and appears in no corpus variant is still redacted."""
    line = ("- The sample contacted evil-c2.example.com for tasking. "
            "(source: network, query_or_table: deep_dive/02-dynamic-pack.json, "
            "row_or_rule: $.network_intel.domains[0])")
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "[redacted: not in evidence]" in out
    assert "evil-c2.example.com" not in out


def test_a_corpus_carried_domain_is_kept(scrub):
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        SP, "collect_evidence_text",
        lambda root: ("beacon.evil-c2.example.com observed", ["synthetic"]))
    line = ("- The sample contacted evil-c2.example.com for tasking. "
            "(source: network, query_or_table: deep_dive/02-dynamic-pack.json, "
            "row_or_rule: $.network_intel.domains[0])")
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "evil-c2.example.com" in out
    assert "[redacted" not in out


# ---------------------------------------------------------------------------
# Part 2 -- an ellipsis is not a sentence terminator
# ---------------------------------------------------------------------------

def test_an_ellipsis_run_is_not_a_sentence_end():
    """Malcat truncates summaries with ".."; the splitter must not break
    the row label away from its citation."""
    line = ("- [malcat.views.strings[8]] ea=80, summary=This program mus.. "
            "under Win32$7 " + CIT)
    parts = RQ._split_report_sentences(line)
    assert len(parts) == 1, f"the ellipsis must not split: {parts}"
    assert "mus.." in parts[0] and "under Win32" in parts[0]


def test_a_single_terminal_period_still_splits():
    """The exemption is narrow: one period followed by whitespace is still
    a sentence end."""
    parts = RQ._split_report_sentences(
        "The sample is packed. It also writes to disk.")
    assert len(parts) == 2


def test_truncated_summary_rows_clear_the_uncited_gate(scrub):
    """End-to-end on the exact re-run 27 shapes: scrub + gate together."""
    lines = [
        "- [malcat.views.strings[8]] ea=80, summary=This program mus.. "
        "under Win32$7 " + CIT,
        "- [malcat.views.strings[10]] ea=80976, summary=This program mus.. "
        "under Win32$7 " + CIT,
        "- [payload_feedback.views.strings[8]] ea=68700, summary=Error: "
        "system co.. (source: payload_feedback, query_or_table: "
        "deep_dive/01-tools-raw.json, row_or_rule: "
        "$.payload_feedback.tools.malcat.views.strings[8])",
    ]
    for line in lines:
        scrubbed = SP._strip_unverified_indicators(line, "a" * 64)
        assert scrubbed == line, "the row label must survive the scrub"
        assert RQ.uncited_report_claims(scrubbed) == [], (
            f"the truncated-summary row must clear the gate: {line[:80]}")


def test_an_uncited_ellipsis_sentence_is_still_flagged(scrub):
    """Nothing is loosened: a sentence with no citation at all is still a
    claim, ellipsis or not."""
    line = "- [malcat.views.strings[8]] ea=80, summary=This program mus.."
    assert RQ.uncited_report_claims(line) != []
