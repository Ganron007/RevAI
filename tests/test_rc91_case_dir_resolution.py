#!/usr/bin/env python3
"""RC-91: the case directory resolves deterministically, and an empty result
always says WHY it is empty.

The defect this closes is not a documentation gap. Measured live on S2
`f18d3493ba43` 2026-11-20: the unpacked payload's rows were present and
citable in `deep_dive/01-tools-raw.json`, and a probe without
`REVAI_RUN_MODE` resolved to the LEGACY FLAT directory, found nothing, and
returned an EMPTY manifest. "No rows exist" and "I read the wrong directory"
were the same observable outcome, and the second one looked exactly like a
missing-evidence bug.

Three changes, each pinned here:
  1. `case_dir` infers the mode from disk when exactly one mode directory
     exists -- the probe above now resolves to `agentic/` and finds the rows.
  2. An AMBIGUOUS mode (several mode directories) never guesses; it warns on
     every call and names the candidates.
  3. `build_section_row_manifest` / `build_section_frontier` name the failure
     when the case directory or its artifacts are absent, instead of
     returning empty in silence.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


SHA = "f" * 64


@pytest.fixture(autouse=True)
def _logs_dir(tmp_path, monkeypatch):
    """Point LOGS_DIR at a temp tree and clear REVAI_RUN_MODE."""
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    return tmp_path / "logs"


def _tools_raw(logs_dir: Path, mode: str) -> None:
    case = logs_dir / SHA / mode / "deep_dive"
    case.mkdir(parents=True, exist_ok=True)
    (case / "01-tools-raw.json").write_text(json.dumps({
        "payload_feedback": {
            "ok": True,
            "tools": {
                "capa": {"top_rules": [{"name": "acquire debug privileges"}]},
                "floss": {"strings": ["C:\\unm0ve.txt"]},
                "malcat": {"views": {"strings": [{"ea": 56442,
                                                  "summary": "Advapi32.dll"}]},
                           "functions": [{"ea": 6440, "name": "sub_401728"}]},
                "yara": {"matches": [{"rule": "UPX"}]},
            },
        },
        "payload_decompilation": {"decompilations": {
            "6440": {"name": "sub_401728", "decompilation": "void f(void){}"}}},
    }), encoding="utf-8")


# ---------------------------------------------------------------- 1. inference
def test_the_mode_is_inferred_when_exactly_one_exists(_logs_dir):
    """The live failure: a probe with no REVAI_RUN_MODE found nothing."""
    _tools_raw(_logs_dir, "agentic")
    resolved = v2_lib.case_dir(SHA)
    assert resolved == _logs_dir / SHA / "agentic", resolved
    # And the manifest is no longer empty.
    md = v2_lib.build_section_row_manifest(SHA, "4. Static Code Analysis")
    assert "payload_decompilation" in md, md[:400]


def test_an_explicit_mode_wins_over_inference(_logs_dir):
    _tools_raw(_logs_dir, "agentic")
    assert v2_lib.case_dir(SHA, "scripted") == _logs_dir / SHA / "scripted"


def test_the_env_var_wins_over_inference(_logs_dir, monkeypatch):
    _tools_raw(_logs_dir, "agentic")
    (_logs_dir / SHA / "ui" / "deep_dive").mkdir(parents=True)
    monkeypatch.setenv("REVAI_RUN_MODE", "ui")
    assert v2_lib.case_dir(SHA) == _logs_dir / SHA / "ui"


# -------------------------------------------------------------- 2. ambiguity
def test_an_ambiguous_mode_never_guesses(_logs_dir, capsys):
    """Several mode dirs -> the caller must say which run it means."""
    for mode in ("agentic", "scripted"):
        (_logs_dir / SHA / mode).mkdir(parents=True)
    resolved = v2_lib.case_dir(SHA)
    # Falls back to flat (the legacy answer) but SAYS so, every call.
    assert resolved == _logs_dir / SHA
    err = capsys.readouterr().err
    assert "cannot be inferred" in err, err
    assert "agentic" in err and "scripted" in err, err
    # Not once-per-process: a second call warns again.
    v2_lib.case_dir(SHA)
    assert "cannot be inferred" in capsys.readouterr().err


def test_no_mode_dirs_at_all_still_uses_the_flat_dir(_logs_dir):
    """A genuinely legacy flat layout is the one correct flat answer."""
    assert v2_lib.case_dir(SHA) == _logs_dir / SHA


# ------------------------------------------------------- 3. loud empty results
def test_a_missing_case_dir_is_named_not_silent(_logs_dir, capsys):
    md = v2_lib.build_section_row_manifest(SHA, "4. Static Code Analysis")
    assert md == "", md
    err = capsys.readouterr().err
    assert "case directory does not exist" in err, err
    # No mode directory exists, so the flat path is what was read -- and the
    # message names exactly that, which is the point.
    assert str(_logs_dir / SHA) in err, err


def test_absent_artifacts_are_named_not_silent(_logs_dir, capsys):
    """The case dir exists but the artifacts do not: still not a bare empty."""
    (_logs_dir / SHA / "agentic").mkdir(parents=True)
    md = v2_lib.build_section_row_manifest(SHA, "4. Static Code Analysis")
    assert md == "", md
    err = capsys.readouterr().err
    assert "none were found" in err, err
    assert "artifacts are absent" in err, err


def test_the_frontier_names_the_same_failures(_logs_dir, capsys):
    """The frontier had the identical silent-empty defect."""
    (_logs_dir / SHA / "agentic").mkdir(parents=True)
    out = v2_lib.build_section_frontier(
        SHA, "4. Static Code Analysis", "## 4. Static Code Analysis\n")
    assert out == "", out
    err = capsys.readouterr().err
    assert "none were found" in err, err


def test_a_section_with_no_sources_is_silent_and_empty(_logs_dir, capsys):
    """Deterministic sections (5 and 8) legitimately have no manifest."""
    _tools_raw(_logs_dir, "agentic")
    md = v2_lib.build_section_row_manifest(SHA, "8. Attribution")
    assert md == "", md
    assert capsys.readouterr().err == ""
