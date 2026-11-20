"""RC-93 (re-run 14, 2026-11-20): the v3 finalizers fix every orphan-table
pair and scrub hash-shaped values that appear nowhere in the evidence.

Re-run 14's technical_v3 failed section_publish on exactly two quality
issues after a fully green publish (0 missing / 0 stubs / 0 uncited / lock
ok):

1. ``table_orphans: 4`` — ``_fix_orphan_tables`` carried an arbitrary
   ``inserted < 2`` bound that left adjacent-table pairs unrepaired when
   the writer produced more than two. The bound was never the gate's: the
   gate counts orphans, not repairs, and every pair the gate can count
   gets exactly one non-factual separator, so the post-transform count is 0.
2. ``unverified_iocs: 1`` — the writer transcribed the pack's
   ``pcap_sha256`` with ONE character dropped (a 63-char hex run that
   matches nothing). ``_strip_unverified_indicators`` scrubbed registry
   paths, domains and URLs but had no hash-shape pattern. The checker
   honestly refused the typo; the scrub now redacts hash-shaped maximal hex
   runs (MD5/SHA1/SHA256 range) that appear NOWHERE in the corpus, and
   keeps values the corpus carries (the correct 64-char pcap_sha256 appears
   twice elsewhere in the same report and survives).
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import section_publisher as SP  # noqa: E402
import report_quality as RQ  # noqa: E402
import entailment as E  # noqa: E402


# ------------------------------------------------------- orphan tables

def _pair_block():
    return "| a | b |\n| --- | --- |\n| 1 | 2 |\n"


def test_every_adjacent_table_pair_gets_its_separator():
    """Five adjacent pairs: the old `inserted < 2` bound left 2 orphans."""
    md = ""
    for idx in range(5):
        md += f"pre {idx}\n\n" + _pair_block() + "\n" + _pair_block() + "\n"
    md += "closing prose so the last table is not an EOF orphan\n"
    fixed = SP._fix_orphan_tables(md)
    assert RQ.count_table_orphans(fixed) == 0, (
        "every pair the gate can count must be repaired, not just two")
    assert fixed.count("**[Note]**") == 5


def test_trailing_table_at_eof_gets_the_closing_note():
    """The gate's second orphan shape: table rows followed only by blanks
    before end-of-text. The same non-factual marker closes it."""
    md = "intro\n\n" + _pair_block() + "\n"
    assert RQ.count_table_orphans(md) == 1, (
        "fixture must reproduce the gate's EOF-orphan shape")
    fixed = SP._fix_orphan_tables(md)
    assert RQ.count_table_orphans(fixed) == 0
    assert fixed.count("**[Note]**") == 1


def test_report_ending_exactly_on_a_table_row_stays_clean():
    """A table whose last row IS the final line is not counted by the gate
    (no table-end event fires); the note appended there is harmless."""
    md = "intro\n\n" + _pair_block() + "| x | y |\n"
    fixed = SP._fix_orphan_tables(md)
    assert RQ.count_table_orphans(fixed) == 0


def test_contiguous_table_rows_are_one_table_and_untouched():
    """No blank line between rows = one table; the transform must not
    split it (the gate counts contiguous rows as a single table too)."""
    md = _pair_block() + "| c | d |\n| --- | --- |\n| 3 | 4 |\n"
    fixed = SP._fix_orphan_tables(md)
    assert fixed == md
    assert RQ.count_table_orphans(fixed) == 0


def test_single_pair_still_gets_the_note_marker():
    md = "intro\n\n" + _pair_block() + "\n" + _pair_block() + "\n"
    fixed = SP._fix_orphan_tables(md)
    assert RQ.count_table_orphans(fixed) == 0
    assert fixed.count("**[Note]**") == 2


# ------------------------------------------------- hash-shaped scrub

CORRECT_SHA = ("85fc082d7a119a7f5406d2c71d883189b"
               "894437d6f2cfe16d8208a00c36da85f")
# The writer's transcription: one character (`f`) dropped.
TYPO_SHA = CORRECT_SHA.replace("cfe16", "ce16")
assert len(CORRECT_SHA) == 64 and len(TYPO_SHA) == 63
assert TYPO_SHA not in CORRECT_SHA


@pytest.fixture()
def case_with_pcap_hash(tmp_path, monkeypatch):
    """A case whose status artifact carries the CORRECT pcap sha256."""
    import v2_lib
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    sha = "a" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "dynamic-analysis-status.json").write_text(json.dumps({
        "status": {
            "packet_capture": {"present": True, "files": 2,
                               "pcap_sha256": CORRECT_SHA}}}))
    return sha, case


def test_typo_hash_redacted_correct_hash_kept(case_with_pcap_hash):
    sha, _case = case_with_pcap_hash
    md = (f"- PCAP SHA256: {CORRECT_SHA}. (source: external_capture)\n"
          f"- packet capture sha256 {TYPO_SHA} in the off-box capture\n")
    out = SP._strip_unverified_indicators(md, sha)
    assert CORRECT_SHA in out, "the corpus-carried value must survive"
    assert TYPO_SHA not in out, "the 63-char typo must be redacted"
    assert "[redacted: not in evidence]" in out


def test_md5_and_sha1_shapes_get_the_same_treatment(case_with_pcap_hash):
    sha, _case = case_with_pcap_hash
    ghost_md5 = "d" * 32
    md = f"- md5 {ghost_md5} observed in the sandbox\n"
    out = SP._strip_unverified_indicators(md, sha)
    assert ghost_md5 not in out


def test_corpus_hash_present_in_evidence_is_never_touched(
        case_with_pcap_hash):
    sha, _case = case_with_pcap_hash
    md = f"- packet capture sha256 {CORRECT_SHA} (off-box)\n"
    out = SP._strip_unverified_indicators(md, sha)
    assert out == md


def test_hex_inside_a_citation_is_protected(case_with_pcap_hash):
    """RC-62: `(source: ...)` parentheticals are masked before scrubbing."""
    sha, _case = case_with_pcap_hash
    md = ("- row payload (source: deep_dive/01-tools-raw.json, "
          f"row: {TYPO_SHA})\n")
    out = SP._strip_unverified_indicators(md, sha)
    assert TYPO_SHA in out, "citation content must never be scrubbed"


def test_short_and_overlong_hex_runs_are_ignored(case_with_pcap_hash):
    sha, _case = case_with_pcap_hash
    short = "f" * 16
    long = "f" * 100
    md = f"- token {short} and blob {long}\n"
    out = SP._strip_unverified_indicators(md, sha)
    assert short in out and long in out, (
        "only MD5/SHA1/SHA256-range runs are in scope")


# ------------------------------------------------- resolver (RC-93)

def test_short_engine_lookup_unions_all_word_matching_aliases(tmp_path):
    """source "yara" must not collapse into the longest alias containing it
    ("yara_generator" -> rule.yara.json ONLY): both yara artifacts are
    candidates, and the one carrying the row resolves it."""
    root = tmp_path
    (root / "rule.yara.json").write_text(json.dumps({"rules": []}))
    (root / "deep_dive").mkdir()
    (root / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "yara": {"matches": [{"rule": "UPX"}, {"rule": "IsPacked"},
                             {"rule": "HasOverlay"}, {"rule": "Dropper"}]}}))
    paths = E._source_artifact_candidates("yara", "yara.matches[3]", root)
    names = sorted(p.name for p in paths)
    assert names == ["01-tools-raw.json", "rule.yara.json"], (
        "the union of word-matching aliases, not one collapsed file")
    hit = E._locate_cited_row(
        root / "deep_dive" / "01-tools-raw.json",
        "$.yara.matches[3].rule", "yara.matches[3]", "yara")
    assert hit is not None and hit["value"] == "Dropper"


def test_pe_imports_lookup_reaches_the_deep_branch(tmp_path):
    (root := tmp_path / "c").mkdir(parents=True)
    (root / "quick_scan").mkdir()
    (root / "quick_scan" / "pe-imports.json").write_text(json.dumps({
        "engine": "pe_imports", "signals": [{"label": "quick-label"}]}))
    (root / "deep_dive").mkdir()
    (root / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "pe_imports": {"signals": [{"label": "deep-label"}]}}))
    hit = E._locate_cited_row(
        root / "deep_dive" / "01-tools-raw.json",
        "$.pe_imports.signals[0].label", "quick_scan/pe-imports.json",
        "pe_imports")
    assert hit is not None and hit["value"] == "deep-label"


def _tools_raw(tmp_path):
    """Minimal deep_dive 01-tools-raw.json with a payload second pass."""
    path = tmp_path / "01-tools-raw.json"
    path.write_text(json.dumps({
        "yara": {"matches": [{"rule": "Top"}]},
        "capa": {"top_rules": [{"rule": "topcapa"}]},
        "payload_feedback": {"tools": {
            "yara": {"matches": [{"rule": "PayloadRule"}]},
            "capa": {"top_rules": [{"rule": "payloadcapa"}]}}},
    }))
    return path


def test_payload_locator_split_across_query_and_row_resolves(tmp_path):
    """The RC-82 swap shape: the full payload path in `query`, the bare
    index in `row`. The wrapper is named by the QUERY -- the skip must
    honor it, and the joined path must resolve the payload document."""
    path = _tools_raw(tmp_path)
    hit = E._locate_cited_row(
        path, "[0]", "$.payload_feedback.tools.capa.top_rules",
        "deep_dive/01-tools-raw.json")
    assert hit is not None, "the joined payload path must resolve"
    assert hit["value"]["rule"] == "payloadcapa"


def test_payload_source_with_dropped_wrapper_still_fails_closed(tmp_path):
    """The laundering guard is untouched: a payload SOURCE whose row names
    a top-level engine branch is still rejected."""
    path = _tools_raw(tmp_path)
    assert E._locate_cited_row(
        path, "yara.matches[0]", "deep_dive/01-tools-raw.json",
        "payload yara") is None
