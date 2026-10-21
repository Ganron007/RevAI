"""Citation parsing must accept labels before ``source:`` but not prose labels."""
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/citation_syntax.py").parent))
from citation_syntax import (  # noqa: E402
    has_citation_locator,
    parse_citation_annotations,
    strip_citation_annotations,
)


def test_leading_label_before_source_is_a_citation():
    """The 2026-10-20 verdict citation starts with a label, not ``source:``."""
    text = (
        "**Verdict: SUSPICIOUS** (locked pipeline verdict; score 35, "
        "source: verdict.json, query_or_table: verdict.json, "
        "row_or_rule: $.verdict)"
    )
    citations = parse_citation_annotations(text)
    assert len(citations) == 1
    assert citations[0]["source"] == "verdict.json"
    assert citations[0]["query_or_table"] == "verdict.json"
    assert citations[0]["row_or_rule"] == "$.verdict"
    assert has_citation_locator(text)


def test_prose_source_label_is_not_a_citation():
    assert parse_citation_annotations("The source: field is metadata.") == []
    assert parse_citation_annotations("The tool (see docs) reports source: foo.") == []
    assert not has_citation_locator("The source: field is metadata.")


def test_nested_parentheses_and_commas_stay_in_the_locator():
    text = (
        "See (source: malcat, query_or_table: Imports (5), "
        "row_or_rule: kernel32.LoadLibraryA, kernel32.CreateFileW)."
    )
    citations = parse_citation_annotations(text)
    assert len(citations) == 1
    assert citations[0]["query_or_table"] == "Imports (5)"
    assert citations[0]["row_or_rule"] == (
        "kernel32.LoadLibraryA, kernel32.CreateFileW"
    )


def test_leading_label_with_nested_brackets_is_a_citation():
    text = (
        "Observation (static note [reviewed]; source: procmon, "
        "query_or_table: procmon.csv, row_or_rule: 42)"
    )
    citations = parse_citation_annotations(text)
    assert len(citations) == 1
    assert citations[0]["source"] == "procmon"
    assert citations[0]["row_or_rule"] == "42"


def test_source_only_annotation_is_parsed_without_a_locator():
    text = "Observed (source: malcat)."
    citations = parse_citation_annotations(text)
    assert len(citations) == 1
    assert citations[0]["source"] == "malcat"
    assert not has_citation_locator(text)


def test_strip_removes_the_whole_labelled_annotation():
    text = (
        "Verdict (locked; source: verdict.json, query_or_table: verdict.json, "
        "row_or_rule: $.verdict) stands."
    )
    stripped = strip_citation_annotations(text)
    assert "source:" not in stripped
    assert stripped.startswith("Verdict")
    assert stripped.endswith("stands.")


def test_table_cell_citation_still_parses():
    text = "| source: procmon, query_or_table: procmon.csv, row_or_rule: 42 |"
    citations = parse_citation_annotations(text)
    assert len(citations) == 1
    assert citations[0]["row_or_rule"] == "42"


def test_malformed_nesting_is_rejected():
    """A mismatched inner bracket must fail closed, not invent a citation."""
    text = "(outer [source: malcat, query_or_table: x, row_or_rule: y)"
    assert parse_citation_annotations(text) == []


def test_closed_parenthesis_before_source_is_not_a_citation():
    """The fast enclosing map must not resurrect a bracket closed earlier."""
    assert parse_citation_annotations("(see docs) source: foo") == []
