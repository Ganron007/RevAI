"""RC-94 (re-run 15, 2026-11-20): the deterministic completion's PUBLISHED
manifest embed carries no uncited line.

Re-run 15's publish failed on `uncited_claims:72` (master) + 2 (technical)
-- both from MY OWN RC-84 Fix 2 embed: the section row manifest was designed
for the WRITER PROMPT (instruction head, locator-bracketed row lines with no
citation parenthetical), and the completion embedded it verbatim into the
PUBLISHED report, where the citation gate counts every such line as an
uncited claim. The audit tail added the malcat Top Strings table (2-cell
rows, no citation) published through the technical completion.

Fix: `build_section_row_manifest(instructions=False)` renders the published
head (one non-factual **[Note]** line, the RC-59 convention);
`_cited_manifest_embed` cites every row line with its own exact locator and
marks the layout lines; `format_malcat_evidence`'s Top Strings table gains
the citation cell. Nothing is loosened: the cited locator is the very row
the manifest shows, and the writer-prompt call sites keep the instructions.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402
import publish_report_v2 as PR  # noqa: E402
import report_quality as RQ  # noqa: E402


@pytest.fixture()
def case_with_capa(tmp_path, monkeypatch):
    import v2_lib as VL
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setattr(VL, "LOGS_DIR", tmp_path / "logs")
    sha = "b" * 64
    case = tmp_path / "logs" / sha / "agentic"
    (case / "quick_scan").mkdir(parents=True)
    # The capability section's row manifest reads capa from the QUICK scan
    # artifact (its SECTION_ROW_SOURCES entry), plus the payload rows from
    # the deep artifact when a payload feedback pass ran.
    (case / "quick_scan" / "00-tools-raw.json").write_text(json.dumps({
        "capa": {"top_rules": [
            {"name": "create a service", "attack": [{"id": "T1543"}]},
            {"name": "acquire debug privileges"}] * 40,
        },
    }))
    (case / "deep_dive").mkdir()
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "payload_feedback": {"tools": {"capa": {"top_rules": [
            {"name": "payload rule zero"}]}}},
    }))
    return sha


def test_published_manifest_omits_writer_instructions(case_with_capa):
    manifest = v2_lib.build_section_row_manifest(
        case_with_capa, "7. Capability Assessment", instructions=False)
    assert manifest, "the rows must still be present"
    assert "EVIDENCE BOUNDARY" not in manifest
    assert "ANALYTICAL DISCIPLINE" not in manifest
    assert "Copy rows verbatim" not in manifest
    assert manifest.startswith("**[Note]**"), (
        "the published head is one non-factual marker line")


def test_writer_prompt_manifest_keeps_the_instructions(case_with_capa):
    manifest = v2_lib.build_section_row_manifest(
        case_with_capa, "7. Capability Assessment")
    assert "EVIDENCE BOUNDARY" in manifest, (
        "the writer-prompt form is unchanged (default instructions=True)")


def test_embed_cites_every_row_line(case_with_capa):
    manifest = v2_lib.build_section_row_manifest(
        case_with_capa, "7. Capability Assessment", instructions=False)
    embed = PR._cited_manifest_embed(manifest)
    uncited = [ln for ln in embed.splitlines()
               if ln.startswith("- [") and "(source:" not in ln]
    assert uncited == [], f"every manifest row must carry its citation: {uncited[:3]}"
    assert "(source: deep_dive/01-tools-raw.json, " \
           "query_or_table: deep_dive/01-tools-raw.json, " in embed
    assert embed.count("**[Note]**") >= 1, "layout lines are marked non-factual"


def test_embed_marks_block_headers_and_overflow_line(case_with_capa):
    manifest = v2_lib.build_section_row_manifest(
        case_with_capa, "7. Capability Assessment", instructions=False)
    embed = PR._cited_manifest_embed(manifest)
    for ln in embed.splitlines():
        s = ln.rstrip()
        if s.startswith("**") and s.endswith(":"):
            assert s.startswith("**[Note]**"), f"header must be marked: {s[:60]}"
        if "... and" in s and "more rows" in s:
            assert "(source:" in s, "the overflow line names its artifact"


def test_embed_passes_the_uncited_claim_gate_shape(case_with_capa):
    """End-to-end shape: no line of the published embed is a bare claim."""
    manifest = v2_lib.build_section_row_manifest(
        case_with_capa, "7. Capability Assessment", instructions=False)
    embed = PR._cited_manifest_embed(manifest)
    for ln in embed.splitlines():
        s = ln.strip()
        if not s or s.startswith("**[Note]**") or s.startswith("#"):
            continue
        if s.startswith("-"):
            assert "(source:" in s, f"uncited row line: {s[:70]}"
        elif s.startswith("|"):
            assert "(source:" in s or s.startswith("|---"), (
                f"uncited table line: {s[:70]}")


def test_malcat_top_strings_table_carries_citations(tmp_path):
    malcat = {"views": {"strings": [
        {"address": 93306, "string": "xU0>U"},
        {"address": 6547, "string": "td::bad_aAoc"}]}}
    text = v2_lib.format_malcat_evidence(malcat)
    rows = [ln for ln in text.splitlines() if ln.startswith("| 9")]
    assert rows and all("(source: malcat," in ln and
                        "$.malcat.views.strings[" in ln for ln in rows), (
        "each Top Strings row cites its exact locator")
    assert "| EA | String | Citation |" in text
