#!/usr/bin/env python3
"""The small hardening items from the 2026-10-03 review, each pinned.

#28 the pe_imports map became a real artifact; the audit's standard-path
checks stopped crying wolf on green agentic runs; docs.counts can no longer
pass by having its subject matter deleted.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import source  # noqa: E402


# --------------------------------------------------------------------------
# Plan #28: the high-signal import map is a real artifact
# --------------------------------------------------------------------------

def test_quick_scan_writes_the_pe_imports_map_as_its_own_artifact():
    """The map must exist at a known path, not only inside 00-tools-raw.json.

    On the live .43 case the behaviour cross-check found no pe-imports.txt
    and silently fell back to the deep-dive tools JSON, which is how the
    #14d calibration saw 0/27 behaviour APIs 'present' on a real Win32 GUI
    sample. The writer must guard on a REAL map: a failed pe_imports run
    persisted as an empty artifact would read as evidence of absence.
    """
    src = source("revai/quick_scan_v2.py")
    assert '"pe-imports.json"' in src, (
        "quick_scan no longer writes quick_scan/pe-imports.json")
    writer = src[src.find('"pe-imports.json"') - 400:src.find('"pe-imports.json"') + 200]
    assert '.get("signals")' in writer and '.get("error")' in writer, (
        "the pe-imports.json write must require signals and no error -- "
        "a failed tool run must never look like evidence of absence")


def test_the_behaviour_check_reads_the_new_artifact_first():
    from report_quality import _load_high_signal_map

    case = Path(__import__("tempfile").mkdtemp())
    qs = case / "quick_scan"
    qs.mkdir(parents=True)
    (qs / "pe-imports.json").write_text(json.dumps({
        "engine": "pe_imports", "signal_count": 2,
        "signals": [{"api_match": "RegSetValueExW", "label": "registry-write"},
                    {"api_match": "VirtualAllocEx", "label": "alloc"}],
    }), encoding="utf-8")
    names, used, meta = _load_high_signal_map(case)
    assert {"regsetvalueexw", "virtualallocex"} <= names, names
    assert used == ["quick_scan/pe-imports.json"], used
    assert meta.get("signal_count") == 2, meta


def test_a_failed_pe_imports_map_is_not_evidence_of_absence():
    from report_quality import _load_high_signal_map

    case = Path(__import__("tempfile").mkdtemp())
    qs = case / "quick_scan"
    qs.mkdir(parents=True)
    (qs / "pe-imports.json").write_text(json.dumps({
        "engine": "pe_imports", "error": "pe_import_signals failed: boom",
        "signal_count": 0, "signals": []}), encoding="utf-8")
    names, used, meta = _load_high_signal_map(case)
    # The reader's contract is shape-based: an empty map contributes no
    # names and is not recorded as used, so the surface falls through to the
    # structured/evidence fallbacks instead of silently "verifying" against
    # nothing.
    assert not names and not used, (names, used)


# --------------------------------------------------------------------------
# Audit: standard-path checks are not applicable on the agentic path
# --------------------------------------------------------------------------

def test_audit_deep_large_marks_standard_path_checks_not_applicable():
    src = source("revai/audit_pipeline.py")
    assert '"engine_path": "agentic"' in src, (
        "audit_deep_large does not mark its engine path")
    for key in ("00_sql_evidence", "03_prompt", "04_llm", "llm_source"):
        assert f'for _std_only in (' in src or key in src, key
    assert "checks[_std_only] = None" in src, (
        "the four standard-path checks must be None (not False) on the "
        "agentic path: False on green runs trains readers to discount the "
        "audit table")


def test_capa_salvage_is_none_when_capa_passed():
    """False on a green run read as a failure; None reads as not applicable."""
    src = source("revai/audit_pipeline.py")
    assert '"capa_salvage_used": (None if tool_status["capa"]["ok"] else capa_salvage)' in src, (
        "capa_salvage_used must be None when capa passed, False only when "
        "capa failed without a salvage")


# --------------------------------------------------------------------------
# verify_pipeline: docs.counts cannot pass on deletion
# --------------------------------------------------------------------------

def test_docs_counts_fails_when_a_doc_carries_no_counts(tmp_path, monkeypatch):
    """Deleting the counts used to make the check pass silently."""
    import verify_pipeline as vp

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "tool-stack.md").write_text(
        "# Tool stack\n\nNo numbers here on purpose.\n", encoding="utf-8")
    monkeypatch.setattr(vp, "REPO", tmp_path)
    seen: list[tuple[str, bool, str]] = []
    original = vp.check

    def spy(name, ok=True, detail="", *a, **kw):
        seen.append((name, bool(ok), str(detail)))

    vp.check = spy
    try:
        vp.check_docs_counts()
    finally:
        vp.check = original
    flagged = [d for n, ok, d in seen if n == "docs.counts" and not ok]
    # Each family is asserted on its own (MEDIUM-3): a doc missing only the
    # manifest count is flagged for exactly that, not only when both are gone.
    assert flagged and "manifest tool count" in flagged[0], seen


def test_docs_counts_fails_when_only_the_manifest_count_is_missing(
        tmp_path, monkeypatch):
    """MEDIUM-3: the omission guard was conjunctive, so this used to pass."""
    import verify_pipeline as vp

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "tool-stack.md").write_text(
        "# Tool stack\n\n26 agent-callable tools, no manifest count.\n",
        encoding="utf-8")
    monkeypatch.setattr(vp, "REPO", tmp_path)
    seen: list[tuple[str, bool, str]] = []
    original = vp.check

    def spy(name, ok=True, detail="", *a, **kw):
        seen.append((name, bool(ok), str(detail)))

    vp.check = spy
    try:
        vp.check_docs_counts()
    finally:
        vp.check = original
    flagged = [d for n, ok, d in seen if n == "docs.counts" and not ok]
    assert flagged and "manifest tool count" in flagged[0], seen


def test_docs_counts_still_passes_on_a_correct_doc(tmp_path, monkeypatch):
    """The other direction: the new rule must not flag a real doc.

    The doc carries a phrasing the patterns actually recognise for BOTH
    families: the phrasing the previous fixture used ("A 28-tool manifest")
    does not match the manifest pattern, so that fixture was never a correct
    doc in the first place.
    """
    import verify_pipeline as vp

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "tool-stack.md").write_text(
        "# Tool stack\n\nThe pipeline runs 28 tools automatically, with 26 "
        "agent-callable tools.\n", encoding="utf-8")
    monkeypatch.setattr(vp, "REPO", tmp_path)
    seen: list[tuple[str, bool, str]] = []
    original = vp.check

    def spy(name, ok=True, detail="", *a, **kw):
        seen.append((name, bool(ok), str(detail)))

    vp.check = spy
    try:
        vp.check_docs_counts()
    finally:
        vp.check = original
    assert all(ok for n, ok, _ in seen if n == "docs.counts"), seen
