#!/usr/bin/env python3
"""Two guards, both learned from a real mistake.

REVAI_RUN_MODE guard (2026-09-30/10-01): running a mode-keyed stage by hand
without REVAI_RUN_MODE writes artifacts into the legacy flat directory
(logs/<sha>/) while the audit reads logs/<sha>/<mode>/. That happened three
times: two publish_report_v2 runs wrote 207K reports into the flat dir, and an
audit run read a stale pipeline-audit.json back and reported failures that were
not real. case_dir() fell back silently every time.

Per-chunk split retry: a failed report chunk is retried one section at a time
rather than dropped, because the provider serves the same content reliably when
asked for less at a time.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402
import publish_report_v2 as pub  # noqa: E402


# ---------------------------------------------------------------- run-mode guard

def test_require_run_mode_rejects_unset(monkeypatch):
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    try:
        v2_lib.require_run_mode("publish_report_v2")
    except RuntimeError as exc:
        assert "REVAI_RUN_MODE is not set" in str(exc)
        assert "publish_report_v2" in str(exc), "the stage name must be in the error"
    else:
        raise AssertionError("an unset REVAI_RUN_MODE must raise")


def test_require_run_mode_accepts_the_three_modes(monkeypatch):
    for mode in ("scripted", "agentic", "ui"):
        monkeypatch.setenv("REVAI_RUN_MODE", mode)
        assert v2_lib.require_run_mode("stage") == mode


def test_require_run_mode_rejects_an_unknown_mode(monkeypatch):
    monkeypatch.setenv("REVAI_RUN_MODE", "typo")
    try:
        v2_lib.require_run_mode("audit_pipeline")
    except RuntimeError as exc:
        assert "not a known mode" in str(exc)
    else:
        raise AssertionError("an unknown mode must raise, not silently misfile")


def test_case_dir_warns_once_when_falling_back_to_flat(monkeypatch, capsys):
    """The silent fallback is the root cause; it must at least be loud."""
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    v2_lib._FLAT_CASE_DIR_WARNED.clear()
    monkeypatch.setattr(v2_lib, "LOGS_DIR", ROOT / "_t_logs")

    v2_lib.case_dir("a" * 64)
    first = capsys.readouterr().err
    assert "REVAI_RUN_MODE is not set" in first, first
    assert "LEGACY FLAT" in first, first

    v2_lib.case_dir("a" * 64)          # same sha -> no repeat
    assert capsys.readouterr().err == "", "must warn once per sha, not per call"

    v2_lib.case_dir("b" * 64)          # different sha -> warns again
    assert "REVAI_RUN_MODE is not set" in capsys.readouterr().err


def test_case_dir_does_not_warn_when_a_mode_is_set(monkeypatch, capsys):
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")
    v2_lib._FLAT_CASE_DIR_WARNED.clear()
    monkeypatch.setattr(v2_lib, "LOGS_DIR", ROOT / "_t_logs")
    d = v2_lib.case_dir("c" * 64)
    assert d.name == "scripted", d
    assert capsys.readouterr().err == ""


def test_explicit_mode_argument_also_avoids_the_warning(monkeypatch, capsys):
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    v2_lib._FLAT_CASE_DIR_WARNED.clear()
    monkeypatch.setattr(v2_lib, "LOGS_DIR", ROOT / "_t_logs")
    d = v2_lib.case_dir("d" * 64, mode="agentic")
    assert d.name == "agentic"
    assert capsys.readouterr().err == ""


# ------------------------------------------------------- per-chunk split retry

def _session() -> dict:
    return {"sha256": "e" * 64, "sample_path": "/x", "project_name": "p"}


def test_a_failed_chunk_is_retried_one_section_at_a_time(monkeypatch):
    """A group that returns nothing must not take its sections down with it."""
    asked: list[list[str]] = []

    def fake_llm(prompt):
        head = prompt.split("Rules", 1)[0]
        wanted = [t for t in v2_lib.TECHNICAL_REPORT_SECTIONS if f"- {t}" in head]
        asked.append(wanted)
        if len(wanted) > 1:
            return {"choices": [{"message": {"content": "{}"}}]}   # empty
        body = "\n\n".join(f"# {t}\n\ncontent for {t}" for t in wanted)
        import json
        return {"choices": [{"message": {"content": json.dumps(
            {"markdown": body})}}]}

    monkeypatch.setattr(pub, "llm_judge", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        _session(), {}, {}, {}, [], "EVIDENCE")

    # every section must still be present despite the group failures
    for t in v2_lib.TECHNICAL_REPORT_SECTIONS:
        assert f"# {t}" in md, f"{t} lost after its group failed"
    assert any(len(w) == 1 for w in asked), (
        "no single-section retry was attempted")
    assert any(len(w) > 1 for w in asked), "the grouped call was never tried"


def test_split_retry_does_not_run_when_every_group_succeeds(monkeypatch):
    """One call per configured group, and no extras.

    Note single-section groups are NORMAL now (the tiling splits the dense
    sections), so "no 1-section call" is not the invariant -- the invariant is
    that the call set equals the configured group set.
    """
    asked: list[tuple[str, ...]] = []

    def fake_llm(prompt):
        head = prompt.split("Rules", 1)[0]
        wanted = tuple(t for t in v2_lib.TECHNICAL_REPORT_SECTIONS
                       if f"- {t}" in head)
        asked.append(wanted)
        import json
        body = "\n\n".join(f"# {t}\n\ncontent" for t in wanted)
        return {"choices": [{"message": {"content": json.dumps(
            {"markdown": body})}}]}

    monkeypatch.setattr(pub, "llm_judge", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        _session(), {}, {}, {}, [], "EVIDENCE")
    assert not errors, errors

    T = v2_lib.TECHNICAL_REPORT_SECTIONS
    expected = {tuple(T[a:b]) for a, b in pub.TECHNICAL_BODY_GROUPS}
    expected |= {tuple(T[slice(*pub.TECHNICAL_WRAP_RANGE)]),
                 tuple(T[slice(*pub.TECHNICAL_TAIL_RANGE)])}
    assert len(asked) == len(expected), (
        f"expected one call per group ({len(expected)}), got {len(asked)}: "
        f"{[len(a) for a in asked]}")
    assert set(asked) == expected, (
        "calls did not match the configured groups -- a split retry must not "
        f"run when every group succeeds: {set(asked) ^ expected}")


def test_a_section_that_fails_alone_is_recorded_exactly_once(monkeypatch):
    """Whatever layer notices the failure, the section is reported one time."""
    def fake_llm(prompt):
        head = prompt.split("Rules", 1)[0]
        wanted = [t for t in v2_lib.TECHNICAL_REPORT_SECTIONS if f"- {t}" in head]
        if any("5. Behavioral" in t for t in wanted):
            return {"choices": [{"message": {"content": "{}"}}]}
        import json
        body = "\n\n".join(f"# {t}\n\ncontent" for t in wanted)
        return {"choices": [{"message": {"content": json.dumps(
            {"markdown": body})}}]}

    monkeypatch.setattr(pub, "llm_judge", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        _session(), {}, {}, {}, [], "EVIDENCE")
    assert "# 5. Behavioral & Dynamic Analysis" not in md
    # section 5 is its own group (4,5), so the split layer is not involved --
    # the group caller records it. Either message is fine; twice is not.
    mentioning = [e for e in errors if "Behavioral" in e]
    assert len(mentioning) == 1, (
        f"the failing section must be reported exactly once: {errors}")
    # and the rest of the report still landed
    assert "# 1. Executive Summary" in md
    assert "# 13. Appendix B: Analysis Environment" in md
