"""The claim-level report schema must make citation coverage structural."""
import json
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

def test_compound_and_prose_jsonpaths_are_rejected_at_the_schema_boundary():
    for row in (
        "$.malcat.views.imports and $.capa.top_rules",
        "$.malcat.views.imports, $.capa.top_rules",
        "$.malcat.views.imports; $.capa.top_rules",
        "$.malcat.views.imports (no WinInet entries)",
        "$.status.packet_capture.present=false, files=0",
    ):
        errors = validate_report_document(_doc(_observation(row=row)))
        assert any("row_or_rule must be one exact" in error for error in errors), (
            row, errors)


def test_exact_filter_range_assignment_and_named_bracket_locators_are_accepted():
    for row in (
        "$.malcat.views.imports[ea=1..3].name",
        "$.malcat.views.imports[ea=1,3].name",
        "$.malcat.views.imports[54..56].name",
        "$.malcat.file_summary.metadata[VersionInfo::OriginalFilename]",
        "$.packer.sections[UPX1]",
        "$.status.packet_capture.present=false",
        "$.function_results[?(@.function_address==\"5368798524\")].function_name",
        "$text",
    ):
        errors = validate_report_document(_doc(_observation(row=row)))
        assert not errors, (row, errors)


def test_sections_returned_as_a_json_string_are_recovered():
    """The provider sometimes returns `sections` as a JSON string.

    Measured 2026-10-21 on a real run: a master section was lost entirely
    because the container was a string even though the content was complete
    and correctly cited. The container is coerced; the CONTENT is still
    validated by exactly the same rules.
    """
    section = {
        "heading": "1. Sample Identification",
        "blocks": [_observation()],
    }
    doc = {"sections": json.dumps([section])}
    errors = validate_report_document(doc)
    assert not errors, errors
    markdown = render_report_document(doc, heading_level=1)
    assert "1. Sample Identification" in markdown


def test_sections_returned_double_wrapped_in_an_object_are_recovered():
    """`{"title": ..., "sections": [...]}` is the document nested one level deep."""
    section = {
        "heading": "1. Sample Identification",
        "blocks": [_observation()],
    }
    doc = {"sections": {"title": "RE Report", "sections": [section]}}
    errors = validate_report_document(doc)
    assert not errors, errors
    markdown = render_report_document(doc, heading_level=1)
    assert "1. Sample Identification" in markdown


def test_a_single_section_object_is_treated_as_a_one_section_document():
    section = {
        "heading": "1. Sample Identification",
        "blocks": [_observation()],
    }
    doc = {"sections": section}
    errors = validate_report_document(doc)
    assert not errors, errors
    assert "1. Sample Identification" in render_report_document(doc, heading_level=1)


def test_the_container_error_names_the_shape_that_was_actually_returned():
    """The correction pass can only fix what the error names."""
    errors = validate_report_document({"sections": "not-an-array"})
    assert errors
    assert "JSON STRING" in errors[0], errors
    errors = validate_report_document({"sections": {"heading": "x"}})
    assert errors
    assert "OBJECT" in errors[0], errors


def test_an_unrecoverable_container_is_still_rejected():
    errors = validate_report_document({"sections": 42})
    assert errors
    assert "non-empty array" in errors[0], errors


def test_complete_sections_survive_a_truncated_sections_string():
    """A truncated JSON array still contains complete sections worth keeping.

    Measured 2026-10-21: one master section was returned as a JSON string
    whose array was cut off mid-way, and the whole 9.7 KB of correctly cited
    content was lost to a parse error. The complete sections BEFORE the cut
    are recovered; the partial one is dropped, never guessed at.
    """
    good = {
        "heading": "1. Sample Identification",
        "blocks": [_observation()],
    }
    partial = '{"heading": "2. Broken", "blocks": [{"kind": "observ'
    text = json.dumps([good])[:-1] + "," + partial
    doc = {"sections": text}
    errors = validate_report_document(doc)
    assert not errors, errors
    markdown = render_report_document(doc, heading_level=1)
    assert "1. Sample Identification" in markdown
    assert "2. Broken" not in markdown


def test_a_repeated_section_heading_keeps_only_the_fullest_copy():
    """The writer sometimes answers one section request with that section twice.

    Measured 2026-10-21: a request for one section came back as a full
    21-block copy followed by a 1-block repeat, so the published report
    carried the same heading twice. The repeat is a strict subset and carries
    no new finding.
    """
    full = {
        "heading": "1. Sample Identification",
        "blocks": [_observation(), _observation(), _observation()],
    }
    repeat = {
        "heading": "1. Sample Identification",
        "blocks": [_observation()],
    }
    doc = {"sections": [full, repeat]}
    errors = validate_report_document(doc)
    assert not errors, errors
    markdown = render_report_document(doc, heading_level=1)
    assert markdown.count("# 1. Sample Identification") == 1, markdown[:400]


def test_a_truncated_first_copy_does_not_displace_a_fuller_later_one():
    thin = {
        "heading": "2. Classification",
        "blocks": [_observation()],
    }
    full = {
        "heading": "2. Classification",
        "blocks": [_observation(), _observation()],
    }
    doc = {"sections": [thin, full]}
    markdown = render_report_document(doc, heading_level=1)
    assert markdown.count("# 2. Classification") == 1, markdown[:400]


def _table(cells: list[str]) -> dict:
    return {
        "kind": "table",
        "columns": ["Field", "Value"],
        "rows": [{
            "cells": cells, "source": "malcat", "query_or_table": "x",
            "row_or_rule": "$.malcat.file_summary.type",
        }],
    }


def test_two_adjacent_tables_are_accepted_by_the_schema():
    """Layout is the quality gate's job, not the claim schema's.

    Reassessed 2026-10-26: rejecting adjacency here lost a whole master section
    when a REPAIR responded with two tables (run 7e51a300, section 4); the
    writer had no second chance and the report failed publication. The report
    quality gate still counts and caps orphan tables, so an over-tabled report
    is still red -- at the gate that owns style, not at the claim boundary.
    """
    doc = _doc(_table(["a", "b"]))
    doc["sections"][0]["blocks"].append(_table(["c", "d"]))
    errors = validate_report_document(doc)
    assert not errors, errors


def test_a_table_after_prose_is_accepted():
    doc = _doc(_table(["a", "b"]))
    doc["sections"][0]["blocks"].append(_observation())
    doc["sections"][0]["blocks"].append(_table(["c", "d"]))
    errors = validate_report_document(doc)
    assert not errors, errors


def test_a_table_at_the_end_of_a_section_is_accepted():
    """A section may legitimately end with a summary table."""
    doc = _doc(_observation())
    doc["sections"][0]["blocks"].append(_table(["a", "b"]))
    errors = validate_report_document(doc)
    assert not errors, errors


# --- RC-18: disassembly belongs in `code` blocks, and listing lines that leak
# outside a fence are source material, not uncited claims ---------------------

def _code_block(text, language="r2"):
    return {"kind": "code", "text": text, "language": language}


R2_LISTING = (
    "│ 0x0042419b 60 pushal\n"
    "│ 0x0042419c 61 popal\n"
    "┌ 37: entry0 ();\n"
)


def test_an_observation_cannot_carry_a_disassembly_listing():
    doc = _doc(_observation(
        "The unpacked entry point is 0x8320.\n" + R2_LISTING))
    errors = validate_report_document(doc)
    assert any("code" in error and "listing" in error.lower()
               for error in errors), errors


def test_the_same_listing_in_a_code_block_is_accepted():
    doc = _doc(
        _observation("The unpacked entry point is 0x8320."),
        _code_block(R2_LISTING),
    )
    assert validate_report_document(doc) == []


def test_plain_prose_with_an_address_is_not_rejected():
    doc = _doc(_observation(
        "0x401000 is the entry point; 0x8320 (33440) is the packed entry."))
    assert validate_report_document(doc) == []


def test_listing_lines_outside_a_fence_are_not_uncited_claims():
    markdown = (
        "## 6. Unpacking\n\n"
        "┌ 37: entry0 ();\n"
        "│ 0x0042419b 60 pushal\n"
        "0x0042419c 61 popal\n"
        "\n"
        "The unpacked entry point is 0x8320.\n"
    )
    claims = uncited_report_claims(markdown)
    assert claims == ["The unpacked entry point is 0x8320."], claims


def test_a_listing_inside_a_fence_is_still_excluded():
    markdown = (
        "## 6. Unpacking\n\n"
        "```\n" + R2_LISTING + "```\n"
        "\n"
        "The unpacked entry point is 0x8320.\n"
    )
    assert uncited_report_claims(markdown) == [
        "The unpacked entry point is 0x8320."]


# --- RC-19: a multi-cell row must cite the ROW locator, not a leaf field -----

def _row(cells, row_or_rule, source="yara", query="deep_dive/01-tools-raw.json"):
    return {"cells": cells, "source": source, "query_or_table": query,
            "row_or_rule": row_or_rule}


def test_a_multi_cell_row_citing_a_leaf_is_normalized_to_the_row():
    """RC-34 supersedes the RC-19 rejection: a leaf locator cannot bind every
    cell, but its PARENT ROW locator can -- so the schema normalizes the
    leaf to the row instead of killing the section (run 27799373 lost three
    master sections to this exact shape)."""
    doc = _doc(_table(["name", "note"]))
    doc["sections"][0]["blocks"] = [{
        "kind": "table",
        "columns": ["name", "note"],
        "rows": [{"cells": ["SEH", "handlers may exist"],
                  "source": "revai_tools_sec",
                  "query_or_table": "deep_dive/01-tools-raw.json",
                  "row_or_rule": "$.revai_tools_sec.findings[4].note"}],
    }]
    errors = validate_report_document(doc)
    assert not errors, errors
    row = doc["sections"][0]["blocks"][0]["rows"][0]
    assert row["row_or_rule"] == "$.revai_tools_sec.findings[4]"



def test_the_same_row_citing_the_row_locator_is_accepted():
    doc = _doc({
        "kind": "table",
        "columns": ["Rule", "String", "Offset", "Hits"],
        "rows": [_row(["keylogger", "$f1", "158640", "10"],
                      "$.yara.matches[10]")],
    })
    assert validate_report_document(doc) == []


def test_a_two_cell_row_citing_a_document_root_is_accepted():
    """verdict.json's row IS `$.verdict`; the rule targets indexed leaves."""
    doc = _doc({
        "kind": "table",
        "columns": ["Field", "Value"],
        "rows": [_row(["Report verdict", "malicious"], "$.verdict",
                      source="verdict", query="verdict.json")],
    })
    assert validate_report_document(doc) == []


def test_a_single_cell_row_may_still_cite_a_leaf():
    doc = _doc({
        "kind": "table",
        "columns": ["Matched string"],
        "rows": [_row(["$f1"], "$.yara.matches[10].strings[0]")],
    })
    assert validate_report_document(doc) == []


# --------------------------------------------------------------------------
# RC-34 (2026-10-30, run 27799373): a multi-cell table row citing a LEAF
# field is normalized to its parent ROW locator instead of killing the whole
# section. The row locator is strictly broader, so the citation is preserved
# and strengthened; every other rule still applies.
# --------------------------------------------------------------------------
def test_a_multi_cell_leaf_row_is_normalized_to_the_row_locator():
    doc = _doc(_table(["name", "note"]))
    doc["sections"][0]["blocks"] = [{
        "kind": "table",
        "columns": ["name", "note"],
        "rows": [{"cells": ["SEH", "handlers may exist"],
                  "source": "revai_tools_sec",
                  "query_or_table": "deep_dive/01-tools-raw.json",
                  "row_or_rule": "$.revai_tools_sec.findings[4].note"}],
    }]
    errors = validate_report_document(doc)
    assert not errors, errors
    row = doc["sections"][0]["blocks"][0]["rows"][0]
    assert row["row_or_rule"] == "$.revai_tools_sec.findings[4]"


def test_a_multi_cell_leaf_row_with_a_trailing_index_is_normalized():
    """The leaf AND any brackets after it are stripped, keeping the row
    index: strings[0].value -> strings[0]."""
    doc = _doc(_table(["name", "note"]))
    doc["sections"][0]["blocks"] = [{
        "kind": "table",
        "columns": ["name", "note"],
        "rows": [{"cells": ["only-value", "second cell"],
                  "source": "malcat",
                  "query_or_table": "deep_dive/01-tools-raw.json",
                  "row_or_rule": "$.malcat.views.strings[0].value"}],
    }]
    errors = validate_report_document(doc)
    assert not errors, errors
    row = doc["sections"][0]["blocks"][0]["rows"][0]
    assert row["row_or_rule"] == "$.malcat.views.strings[0]"


def test_a_one_non_empty_cell_row_keeps_its_leaf_locator():
    """A leaf locator binds a single non-empty cell fine; RC-34 only
    normalizes multi-cell rows."""
    doc = _doc(_table(["name", "note"]))
    doc["sections"][0]["blocks"] = [{
        "kind": "table",
        "columns": ["name", "note"],
        "rows": [{"cells": ["only-value", ""],
                  "source": "malcat",
                  "query_or_table": "deep_dive/01-tools-raw.json",
                  "row_or_rule": "$.malcat.views.strings[0].value"}],
    }]
    errors = validate_report_document(doc)
    assert not errors, errors
    row = doc["sections"][0]["blocks"][0]["rows"][0]
    assert row["row_or_rule"] == "$.malcat.views.strings[0].value"


def test_a_compound_locator_is_still_rejected():
    doc = _doc(_table(["name", "note"]))
    doc["sections"][0]["blocks"] = [{
        "kind": "table",
        "columns": ["name", "note"],
        "rows": [{"cells": ["a", "b"],
                  "source": "x",
                  "query_or_table": "y.json",
                  "row_or_rule": "$.a[0].f and $.b[1]"}],
    }]
    errors = validate_report_document(doc)
    assert any("one exact JSONPath" in e for e in errors), errors
