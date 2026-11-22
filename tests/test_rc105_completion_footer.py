"""RC-105 (re-run 25, 2026-11-22): the deterministic completion footer
carries NO verdict statement and every footer line is declared layout.

Re-run 25's master_v3 failed quality on uncited_claim_count 4 -- the same
two sentences x two deterministically completed sections:

* "Deep-dive summary of record: PE32 UPX-packed sample with strong
  packer/structure anomalies."
* "Static evidence includes UPX signatures and LZMA/UPX version strings, ..."

Root cause: the deep-dive summary is MULTI-SENTENCE, the RC-100 collapse put
the citation at the END of the whole line, and the uncited gate's sentence
splitter flagged every sentence before it. RC-100 fixed the line break, not
the sentence split.

Second symptom, same root: the footer stated "Verdict of record for this
sample: **malicious**" -- the RAW verdict.json label. The publish calibration
fires AFTER the deterministic completions in the same flow (malicious ->
suspicious, "obfuscation is neutral"), so a footer rendered at completion
time can never state the verdict-of-record. check_quality's cross-report
comparison read the footers and flagged both v3 reports against both v2
reports (master_v2 suspicious vs technical_v3 malicious; master_v3 malicious
vs technical_v2 suspicious) even though all FOUR ensured verdict panels said
suspicious. RC-04b doctrine: the calibration is the verdict-of-record; the
raw label stays citable from verdict.json. The footer no longer restates it.
"""

import inspect
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "revai"))

import publish_report_v2 as PR  # noqa: E402
from report_quality import uncited_report_claims  # noqa: E402

# The exact re-run 25 shape: a multi-sentence deep-dive summary whose
# sentences the splitter flagged before the citation landed.
RERUN25_SUMMARY = (
    "PE32 UPX-packed sample with strong packer/structure anomalies. "
    "Static evidence includes UPX signatures and LZMA/UPX version strings, "
    "a Borland compiler marker, base64 and network-related strings, and a "
    "minimal dynamically-resolved import set (LoadLibraryA, GetProcAddress) "
    "often used for runtime API resolution in packed/obfuscated malware. "
    "Ghidra function metrics are empty in this session, indicating the "
    "session ended before code analysis."
)


def _session():
    return {"sha256": "b" * 64, "sample_path": "/opt/samples/x.bin"}


def _verdict():
    # The RAW label -- the footer must NOT restate it.
    return {"verdict": "malicious", "confidence": "high"}


def _deep():
    return {"summary": RERUN25_SUMMARY, "verdict": "malicious"}


def test_completion_footer_states_no_verdict():
    """The footer no longer carries a 'Verdict of record' line -- the ensured
    verdict panel is the single verdict-of-record per report."""
    for md in (
        PR._deterministic_master_section_md(
            "7. Capability Assessment", _session(), _verdict(), _deep(), {}, {},
            reason="LLM section unrecoverable; rendered deterministically",
            heading_level=1),
        PR._deterministic_technical_section_md(
            "1. Executive Summary", _session(), _verdict(), _deep(), "",
            reason="LLM section unrecoverable; rendered deterministically",
            heading_level=2),
    ):
        assert "Verdict of record" not in md, (
            "the completion footer must not state a verdict -- the ensured "
            "panel is the verdict-of-record (RC-04b)")


def test_no_raw_verdict_render_remains_in_the_builders():
    """Source-level pin: neither completion builder renders the raw
    verdict/confidence pair into the footer anymore."""
    src = inspect.getsource(PR._deterministic_master_section_md)
    tsrc = inspect.getsource(PR._deterministic_technical_section_md)
    for s in (src, tsrc):
        assert "Verdict of record" not in s
        assert "v.get('verdict'" not in s and 'v.get("verdict"' not in s


def test_footer_lines_are_declared_layout():
    """Every footer line (blank or **[Note]**-prefixed) from the completion
    marker onward -- the RC-59 exemption the uncited gate skips BEFORE the
    sentence splitter runs."""
    md = PR._deterministic_master_section_md(
        "7. Capability Assessment", _session(), _verdict(), _deep(), {}, {},
        reason="LLM section unrecoverable; rendered deterministically",
        heading_level=1)
    footer_started = False
    for ln in md.splitlines():
        s = ln.strip()
        if "Deterministic completion." in s:
            footer_started = True
        if not footer_started or not s:
            continue
        assert s.startswith("**[Note]**"), f"footer line not declared: {s[:80]}"


def test_multi_sentence_summary_is_one_declared_line():
    """The multi-sentence deep-dive summary renders as ONE **[Note]** line
    with the exact deep_dive citation at its end (RC-100 collapse kept)."""
    deep_cit = ("(source: deep_dive/05-deep-dive.json, "
                "query_or_table: deep_dive/05-deep-dive.json, "
                "row_or_rule: $.summary)")
    md = PR._deterministic_technical_section_md(
        "1. Executive Summary", _session(), _verdict(), _deep(), "",
        reason="LLM section unrecoverable; rendered deterministically",
        heading_level=2)
    hits = [ln for ln in md.splitlines() if "Deep-dive summary of record" in ln]
    assert len(hits) == 1, f"exactly one summary line expected: {len(hits)}"
    line = hits[0].strip()
    assert line.startswith("**[Note]**"), "the summary line must be declared"
    assert line.endswith(deep_cit), "the citation must land on the same line"
    # The whole summary survives on that one line (no sentence dropped).
    assert "Ghidra function metrics are empty" in line


@pytest.mark.parametrize("render", [
    lambda: PR._deterministic_master_section_md(
        "7. Capability Assessment", _session(), _verdict(), _deep(), {}, {},
        reason="LLM section unrecoverable; rendered deterministically",
        heading_level=1),
    lambda: PR._deterministic_technical_section_md(
        "1. Executive Summary", _session(), _verdict(), _deep(), "",
        reason="LLM section unrecoverable; rendered deterministically",
        heading_level=2),
], ids=["master", "technical"])
def test_completed_section_clears_the_uncited_gate(render):
    """End-to-end on the exact re-run 25 shape: the rendered completion has
    ZERO uncited claims -- the class that failed master_v3 is dead."""
    md = render()
    uncited = uncited_report_claims(md)
    assert uncited == [], (
        f"the completion must clear the uncited gate: {uncited[:3]}")


def test_rerun25_summary_sentence_class_is_dead():
    """The two flagged sentences from re-run 25, rendered verbatim inside a
    declared footer line, are not claims."""
    line = PR._as_layout_block(
        f"Deep-dive summary of record: {RERUN25_SUMMARY} "
        "(source: deep_dive/05-deep-dive.json, query_or_table: "
        "deep_dive/05-deep-dive.json, row_or_rule: $.summary)")
    assert uncited_report_claims(line) == []
