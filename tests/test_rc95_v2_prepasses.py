"""RC-95 (re-run 16, 2026-11-21): the v2 path runs the deterministic
pre-passes before the bounded LLM retries, and the registry scrub matches
ABBREVIATED paths.

Re-run 16 (publish rc=1): the v2 master carried 5 adjacent-table pairs in
the WinRE dynamic block (the LLM orphan retry was retained; RC-93's
deterministic transform lived only in the v3 section_publisher path) and
the v2 technical carried 6 abbreviated registry paths
(`HKLM\\...\\Winlogon\\Notify\\wlogon\\Asynchronous` -- the writer's
ellipsis compression, honestly refused by the checker; the scrub's old
`[\\w\\\\]+` token stopped at the first dot and never matched them).

Fix: publish_report_v2 runs `_fix_orphan_tables` + `_strip_unverified_
indicators` on both reports BEFORE the LLM retries (which then only fire
for whatever the transforms cannot fix), and the scrub's registry token
runs to the usual delimiters with a de-punctuated corpus probe. Nothing is
loosened: corpus-carried values are kept, corpus-absent ones redacted.
"""
import inspect
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import section_publisher as SP  # noqa: E402
import publish_report_v2 as PR  # noqa: E402
import v2_lib  # noqa: E402

FULL_PATH = ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
             "\\Winlogon\\Notify\\wlogon")
ABBREV = "HKLM\\...\\Winlogon\\Notify\\wlogon\\Asynchronous"


@pytest.fixture()
def case_with_winlogon_path(tmp_path, monkeypatch):
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    sha = "c" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "deep_dive").mkdir()
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "payload_feedback": {"tools": {"yara": {"matches": []}}},
        "persistence": {"file_effects": [
            {"path": FULL_PATH, "effect": "RegCreateKey"}]}}))
    # Mirror the real flow: the observed registry key is attested in
    # iocs.json, whose RENDERED values (single backslashes, the RC-38
    # rendered-evidence corpus) are what the scrub's corpus check compares.
    (case / "iocs.json").write_text(json.dumps({
        "registry_keys": [FULL_PATH]}))
    return sha, case


def test_abbreviated_registry_path_is_redacted(case_with_winlogon_path):
    sha, _ = case_with_winlogon_path
    md = (f"- Winlogon Notify values written: {ABBREV}, plus the DLLName "
          "and Logon values.\n")
    out = SP._strip_unverified_indicators(md, sha)
    assert ABBREV not in out, "the ellipsis abbreviation must be redacted"
    assert "[redacted: not in evidence]" in out


def test_corpus_carried_full_path_is_kept(case_with_winlogon_path):
    sha, _ = case_with_winlogon_path
    md = f"- Persistence key created: {FULL_PATH}\n"
    out = SP._strip_unverified_indicators(md, sha)
    assert FULL_PATH in out, "the evidence-carried path must survive"
    assert "[redacted" not in out


def test_trailing_sentence_punctuation_survives(case_with_winlogon_path):
    sha, _ = case_with_winlogon_path
    md = f"- The key {ABBREV} was created by the dropper.\n"
    out = SP._strip_unverified_indicators(md, sha)
    assert ABBREV not in out
    assert out.rstrip().endswith("dropper.") or ".\n" in out, (
        "the redaction must not eat the sentence's period")


def test_the_v2_finalize_runs_both_pre_passes():
    """Wiring pin: the technical and master finalizes call the deterministic
    transforms BEFORE the bounded retries (re-run 16: the retries were
    retained and the gates still failed; the deterministic pass fixes the
    shapes without a single LLM call)."""
    src = inspect.getsource(PR)
    assert "markdown = _fix_orphan_tables(markdown)" in src
    assert "markdown = _strip_unverified_indicators(" in src
    assert "master_md = _fix_orphan_tables(master_md)" in src
    assert "master_md = _strip_unverified_indicators(" in src
    # the pre-passes precede the retry blocks in the source
    assert src.index("_fix_orphan_tables(markdown)") < src.index(
        "retry_orphan_table_sections(\n            markdown")


def test_pre_pass_removes_every_adjacent_pair():
    """The exact re-run 16 master shape: five evidence tables back to back
    in the dynamic block; after the pre-pass the orphan gate passes with no
    LLM retry."""
    block = ("| API | Fired | Evidence |\n|---|---|---|\n"
             "| CreateFileW | yes | (source: frida, query_or_table: "
             "deep_dive/02-dynamic-pack.json, row_or_rule: "
             "$.frida_trace.invocations[0]) |\n")
    md = "## Dynamic Analysis (WinRE detonation)\n\n"
    for _ in range(5):
        md += block + "\n" + block + "\n"
    fixed = PR._fix_orphan_tables(md)
    import report_quality as RQ
    assert RQ.count_table_orphans(fixed) == 0
