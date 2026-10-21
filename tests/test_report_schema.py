"""The claim-level report schema must make citation coverage structural."""
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/report_schema.py").parent))
from report_schema import (  # noqa: E402
    ReportSchemaError,
    is_non_factual_markdown_line,
    render_report_document,
    report_writer_tool_schema,
    validate_report_document,
)
from report_quality import uncited_report_claims  # noqa: E402


def _doc(*blocks, heading="1. Executive Summary"):
    return {"sections": [{"heading": heading, "blocks": list(blocks)}]}


def _observation(text="The file has one section.", source="malcat",
                 query="deep_dive/01-tools-raw.json",
                 row="$.malcat.file_summary.sections"):
    return {
        "kind": "observation",
        "text": text,
        "source": source,
        "query_or_table": query,
        "row_or_rule": row,
    }


def test_observation_requires_every_citation_field():
    errors = validate_report_document(_doc({
        "kind": "observation",
        "text": "The file has one section.",
        "source": "malcat",
        "query_or_table": "deep_dive/01-tools-raw.json",
    }))
    assert any("row_or_rule" in error for error in errors)


def test_each_observation_sentence_gets_the_citation():
    doc = _doc(_observation(
        "The file has one section. The section is readable."))
    markdown = render_report_document(doc, heading_level=1)
    assert markdown.count("(source: malcat,") == 2
    assert uncited_report_claims(markdown) == []


def test_table_row_citation_is_rendered_in_an_evidence_column():
    doc = _doc({
        "kind": "table",
        "columns": ["Field", "Value"],
        "rows": [
            {"cells": ["entropy", "7.2"], "source": "malcat",
             "query_or_table": "deep_dive/01-tools-raw.json",
             "row_or_rule": "$.malcat.file_summary.entropy"},
            {"cells": ["sections", "1"], "source": "malcat",
             "query_or_table": "deep_dive/01-tools-raw.json",
             "row_or_rule": "$.malcat.file_summary.sections"},
        ],
    })
    markdown = render_report_document(doc)
    assert "| Field | Value | Evidence |" in markdown
    assert markdown.count("(source: malcat,") == 2
    assert uncited_report_claims(markdown) == []


def test_assessment_and_recommendation_are_explicitly_non_factual():
    doc = _doc(
        _observation(),
        {"kind": "assessment", "text": "This is likely a loader."},
        {"kind": "recommendation", "text": "Submit the hash to TI."},
    )
    markdown = render_report_document(doc)
    assert "**[Assessment]**" in markdown
    assert "**[Recommendation]**" in markdown
    assert is_non_factual_markdown_line("- **[Assessment]** This is likely a loader.")
    assert uncited_report_claims(markdown) == []


def test_observation_text_citations_are_replaced_by_the_structured_locator():
    doc = _doc(_observation(
        "The file has one section (source: invented, row_or_rule: fake).",
        row="$.malcat.file_summary.sections"))
    markdown = render_report_document(doc)
    assert "invented" not in markdown
    assert markdown.count("(source: malcat,") == 1


def test_table_intro_is_rejected_so_it_must_be_a_cited_observation():
    errors = validate_report_document(_doc({
        "kind": "table",
        "intro": "The following imports were observed.",
        "columns": ["Field", "Value"],
        "rows": [{"cells": ["entropy", "7.2"], "source": "malcat",
                  "query_or_table": "x", "row_or_rule": "y"}],
    }))
    assert any("table intro is not supported" in error for error in errors)


def test_table_rejects_a_second_evidence_column():
    errors = validate_report_document(_doc({
        "kind": "table",
        "columns": ["Field", "Evidence"],
        "rows": [{"cells": ["a", "b"], "source": "malcat",
                  "query_or_table": "x", "row_or_rule": "y"}],
    }))
    assert any("Evidence" in error for error in errors)


def test_unbalanced_citation_value_fails_closed():
    errors = validate_report_document(_doc(_observation(
        row="$.malcat.file_summary.(")))
    assert any("unbalanced" in error for error in errors)


def test_table_cell_count_must_match_columns():
    errors = validate_report_document(_doc({
        "kind": "table",
        "columns": ["Field", "Value"],
        "rows": [{"cells": ["only one"], "source": "malcat",
                  "query_or_table": "x", "row_or_rule": "y"}],
    }))
    assert any("exactly 2" in error for error in errors)


def test_master_heading_level_is_one_and_technical_is_two():
    doc = _doc(_observation(), heading="Executive Summary")
    assert render_report_document(doc, heading_level=1).startswith(
        "# Executive Summary")
    assert render_report_document(doc, heading_level=2).startswith(
        "## Executive Summary")


def test_code_fence_is_longer_than_any_run_in_the_content():
    doc = _doc({"kind": "code", "language": "text", "text": "``` inner ```"})
    markdown = render_report_document(doc)
    assert "````text" in markdown
    assert markdown.rstrip().endswith("````")


def test_invalid_document_raises_with_the_path():
    try:
        render_report_document(_doc({"kind": "observation", "text": "x"}))
    except ReportSchemaError as exc:
        assert "sections[0].blocks[0]" in str(exc)
        assert "source" in str(exc)
    else:
        raise AssertionError("expected ReportSchemaError")


def test_tool_schema_requires_sections_and_citation_rows():
    schema = report_writer_tool_schema()["function"]["parameters"]
    assert schema["required"] == ["sections"]
    block = schema["properties"]["sections"]["items"]["properties"]["blocks"]
    assert "observation" in block["items"]["properties"]["kind"]["enum"]
    assert "intro" not in block["items"]["properties"]
    row = block["items"]["properties"]["rows"]["items"]
    assert set(row["required"]) == {
        "cells", "source", "query_or_table", "row_or_rule"}
