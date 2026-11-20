"""RC-92 (re-run 13, 2026-11-20): the payload second pass and the bare
procmon-filter locators resolve at audit time.

Re-run 13's audit carried 60 unresolved-rows. Two of them were RESOLVER
gaps, both found by classifying every row against the run's own artifacts:

- ``payload_feedback.tools.<engine>...`` / ``payload_decompilation...``
  rows are CITABLE by the section row manifest (RC-90b) but every one came
  back unresolved: the 01-tools-raw branch filter only skipped the
  ``$.upx_second_pass`` wrapper, so a row naming the payload wrapper was
  filtered down to a top-level engine branch -- a DIFFERENT document.
- ``procmon_sample_events[?(@.row==N)].path``: the strict JSONPath parser
  only accepted the parenthesized filter atom, and a bare locator carrying
  a bracket segment never received its ``$.`` prefix, so the writer's
  unparenthesized spelling (``[?@.row==94805]``) parsed to nothing.

Everything else in the 60 was classified as a WRITER INVENTION against the
run's own artifacts (``frida_summary.apis_fired``, ``window.gate_fired``,
``malcat.views.carved_files``, ``qs $.xor_search``, ...) and stays
unresolved -- RC-89's discipline: no aliases for paths that do not exist.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import entailment as E  # noqa: E402


def _tools_raw(tmp_path):
    """A deep_dive 01-tools-raw.json carrying a payload second pass."""
    data = {
        "_cadre_provenance": {"sha256": "x" * 64},
        "yara": {"matches": [{"rule": "Top", "strings": []}]},
        "capa": {"top_rules": [{"rule": "topcapa"}]},
        "malcat": {"functions": [], "views": {"strings": ["s"]}},
        "payload_feedback": {
            "path": "/tmp/payload.vir",
            "engine": "unpack_oracle",
            "tools": {
                "yara": {"matches": [{"rule": "PayloadRule", "strings": [
                    {"id": "$a1", "offset": 54432}]}]},
                "capa": {"top_rules": [{"rule": "payloadcapa"}]},
                # Mirror the real artifact: the payload's own malcat document
                # carries `functions` at the top level AND under `views`
                # (the malcat generator's shape; the resolver's view alias
                # rewrite needs both, exactly as in the top-level document).
                "malcat": {"functions": [
                    {"address": 1, "name": "sub_401000"}],
                    "views": {"functions": [
                        {"address": 1, "name": "sub_401000"}],
                        "strings": ["s"]}},
            },
        },
        "payload_decompilation": {
            "engine": "malcat",
            "decompilations": [
                {"address": 1, "body": "int sub_401000() { ... }"}],
        },
    }
    path = tmp_path / "01-tools-raw.json"
    path.write_text(json.dumps(data))
    return path


def test_payload_nested_rows_resolve_their_own_document(tmp_path):
    path = _tools_raw(tmp_path)
    for row in (
            "$.payload_feedback.tools.yara.matches[0]",
            "payload_feedback.tools.yara.matches[0]",
            "$.payload_feedback.tools.capa.top_rules[0]",
            "payload_feedback.tools.malcat.functions[0]",
            "$.payload_decompilation.decompilations[0]",
            "payload_decompilation.decompilations[0]"):
        located = E._locate_cited_row(
            path, row, "deep_dive/01-tools-raw.json", "yara")
        assert located is not None, f"{row} must resolve"
    # The values are the PAYLOAD document's rows, not the top-level ones.
    hit = E._locate_cited_row(
        path, "$.payload_feedback.tools.yara.matches[0]",
        "deep_dive/01-tools-raw.json", "yara")
    assert hit["value"]["rule"] == "PayloadRule"


def test_payload_row_cited_as_top_level_engine_stays_unresolved(tmp_path):
    """Fail closed: dropping the wrapper names the TOP-LEVEL document."""
    path = _tools_raw(tmp_path)
    for source, row in (
            ("payload yara", "yara.matches[0]"),
            ("payload capa", "capa.top_rules[0]"),
            ("payload capa", "capa.top_rules[0]")):
        located = E._locate_cited_row(
            path, row, "deep_dive/01-tools-raw.json", source)
        assert located is None, (
            f"{row!r} with source {source!r} would certify the top-level "
            "engine document instead of the payload document -- must fail")


def test_upx_second_pass_rows_still_resolve(tmp_path):
    """The RC-27-era nested document keeps its own resolution path."""
    data = json.loads(_tools_raw(tmp_path).read_text())
    data["upx_second_pass"] = {
        "tools": {"yara": {"matches": [{"rule": "SecondPass"}]}}}
    path = tmp_path / "01-tools-raw.json"
    path.write_text(json.dumps(data))
    located = E._locate_cited_row(
        path, "$.upx_second_pass.tools.yara.matches[0]",
        "deep_dive/01-tools-raw.json", "yara")
    assert located is not None and located["value"]["rule"] == "SecondPass"


def _pack(tmp_path):
    data = {
        "_cadre_provenance": {"sha256": "x" * 64},
        "procmon_sample_events": [
            {"row": 100, "pid": 6504, "operation": "CreateFile",
             "path": "C:\\Windows\\test"},
            {"row": 200, "pid": 6504, "operation": "RegCreateKey",
             "path": "HKLM\\SOFTWARE"},
        ],
    }
    path = tmp_path / "02-dynamic-pack.json"
    path.write_text(json.dumps(data))
    return path


def test_procmon_filter_rows_resolve_their_exact_row(tmp_path):
    path = _pack(tmp_path)
    for spelling in (
            "procmon_sample_events[?(@.row==100)].path",
            "procmon_sample_events[?@.row==100].path",
            "$.procmon_sample_events[?(@.row==100)].path",
            "$.procmon_sample_events[?@.row==100].path"):
        located = E._locate_cited_row(
            path, spelling, "deep_dive/02-dynamic-pack.json", "winre")
        assert located is not None, f"{spelling} must resolve"
        assert located["value"] == "C:\\Windows\\test"


def test_procmon_filter_row_absent_stays_unresolved(tmp_path):
    path = _pack(tmp_path)
    located = E._locate_cited_row(
        path, "procmon_sample_events[?(@.row==99999)].path",
        "deep_dive/02-dynamic-pack.json", "winre")
    assert located is None


def test_table_key_locator_keeps_its_own_path(tmp_path):
    """The ``table: key`` locator is a different grammar -- untouched."""
    path = _pack(tmp_path)
    located = E._locate_cited_row(
        path, "procmon: data row 100", "deep_dive/02-dynamic-pack.json",
        "procmon")
    # The CSV data-row locator (row=100) still resolves through its own
    # branch, which proves the new bare-bracket normalization did not
    # swallow the table-key grammar. The CSV branch returns the row object
    # in its excerpt.
    assert located is not None
    assert "100" in located["excerpt"]


def test_plain_numeric_index_normalization_unchanged(tmp_path):
    path = _pack(tmp_path)
    located = E._locate_cited_row(
        path, "procmon_sample_events[0]",
        "deep_dive/02-dynamic-pack.json", "procmon")
    assert located is not None and located["value"]["row"] == 100
