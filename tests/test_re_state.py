#!/usr/bin/env python3
"""Phase 0 - the RE state stream's contracts, pinned.

The stream is the substrate #26 (full depth) and #13-L2 (mid-run steering)
consume. These tests pin the properties that make it safe to build both on:
schema-bound consumers, append-only history, a truncated tail that is dropped
AND counted, and a vocabulary that cannot fork away from depth_agent's.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import resolve  # noqa: E402

import re_state  # noqa: E402


def _case(tmp_path: Path, name: str = "case") -> Path:
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_new_state_leads_with_the_schema():
    """A reader must be able to reject a state that is not ours.

    Schema-first is what makes 'bind consumers to the schema' mechanical
    rather than a convention: the first key a consumer checks is the one that
    identifies the format.
    """
    st = re_state.new_state("abc123", "run-1")
    assert list(st.keys())[0] == "schema", st
    assert st["schema"] == re_state.SCHEMA
    assert st["regions"] == {}
    assert st["spend"] == {
        "llm_calls": 0, "seconds": 0.0, "tokens": 0,
        "domain_investigations": 0, "token_usage_complete": None,
    }


def test_append_only_history_folds_deterministically(tmp_path):
    """The log is the truth; the same events always fold to the same state."""
    case = _case(tmp_path)
    log = case / re_state.EVENT_FILE
    re_state.append_event(log, "init", sample_sha256="abc", run_id="r1")
    re_state.append_event(log, "phase", phase="investigate")
    ev = re_state.region_event({}, "persistence", "partial",
                               reason="imports only",
                               citations=["deep_dive/05-deep-dive.json"])
    re_state.append_event(log, **ev)
    re_state.append_event(log, "spend", llm_calls=2, seconds=3.5, tokens=900,
                          domain_investigations=4,
                          token_usage_complete=True)

    events, dropped = re_state.load_log(log)
    assert dropped == 0
    st1 = re_state.fold_events(events)
    st2 = re_state.fold_events(events)
    assert st1 == st2, "the fold must be deterministic"
    assert st1["phase"] == "investigate"
    assert st1["regions"]["persistence"]["status"] == "partial"
    assert st1["spend"] == {
        "llm_calls": 2, "seconds": 3.5, "tokens": 900,
        "domain_investigations": 4, "token_usage_complete": True,
    }

    # The log itself still holds every event - history is not collapsed.
    lines = [l for l in log.read_text().splitlines() if l.strip()]
    assert len(lines) == 4, "append_event must never rewrite or collapse"


def test_later_status_wins_but_history_survives(tmp_path):
    """A region re-statused keeps its history in the log and its latest
    status in the fold - which is what makes a re-run auditable."""
    case = _case(tmp_path)
    log = case / re_state.EVENT_FILE
    re_state.append_event(
        log, **re_state.region_event({}, "c2_network", "partial",
                                     reason="domains only"))
    re_state.append_event(
        log, **re_state.region_event({}, "c2_network", "understood",
                                     reason="DGA enumerated",
                                     citations=["deep_dive/05-deep-dive.json"]))
    st, _ = re_state.load_state(case)
    assert st["regions"]["c2_network"]["status"] == "understood"
    events, _ = re_state.load_log(log)
    assert len(events) == 2


def test_truncated_tail_is_dropped_and_counted(tmp_path):
    """A kill mid-append can only corrupt the last line - and a silently
    truncated log is indistinguishable from a shorter run."""
    case = _case(tmp_path)
    log = case / re_state.EVENT_FILE
    re_state.append_event(log, "init", sample_sha256="abc")
    re_state.append_event(log, "phase", phase="investigate")
    with open(log, "a", encoding="utf-8") as fh:
        fh.write('{"t": 123, "kind": "spend", "llm_c')  # killed mid-write
    events, dropped = re_state.load_log(log)
    assert dropped == 1, "a corrupt line must be counted, not swallowed"
    assert len(events) == 2
    st, dropped2 = re_state.load_state(case)
    assert dropped2 == 1
    assert st["phase"] == "investigate", "the good events still fold"


def test_unrecognised_status_is_a_defect_not_a_synonym(tmp_path):
    """depth_agent's lesson, carried into the shared substrate: a typo'd
    status used to be excluded from the unknown set (the loop terminated with
    the region never understood) and from the cost counts."""
    case = _case(tmp_path)
    log = case / re_state.EVENT_FILE
    re_state.append_event(
        log, **re_state.region_event({}, "evasion", "understod",
                                     reason="typo", citations=["x"]))
    st, _ = re_state.load_state(case)
    assert st["regions"]["evasion"]["defect"] == "unrecognised_status"
    assert "evasion" in re_state.unknown_regions(st), (
        "a malformed status must count as unknown, or the loop terminates "
        "with the region never understood")
    assert re_state.has_converged(st) is False
    counts = re_state.cost_summary(st)["by_status"]
    assert counts["defects"] == 1
    assert counts.get("understod", 0) == 1, "the raw label is preserved"


def test_overstated_status_without_evidence_is_flagged(tmp_path):
    """'understood' with no citation is recorded WITH the claim, plus the
    defect - an overstated status is worse than an admitted unknown."""
    case = _case(tmp_path)
    log = case / re_state.EVENT_FILE
    re_state.append_event(
        log, **re_state.region_event({}, "evasion", "understood",
                                     reason="trust me"))
    st, _ = re_state.load_state(case)
    assert st["regions"]["evasion"]["defect"] == "status_without_evidence"

    # not-explored is the ONLY citation-excused status.
    re_state.append_event(
        log, **re_state.region_event({}, "imports", "not-explored"))
    st, _ = re_state.load_state(case)
    assert st["regions"]["imports"]["defect"] == ""


def test_checkpoint_is_atomic_and_the_log_stays_the_truth(tmp_path):
    """The snapshot is a convenience; the log is the source of truth. A kill
    mid-write can never leave a half-read snapshot."""
    case = _case(tmp_path)
    log = case / re_state.EVENT_FILE
    re_state.append_event(
        log, **re_state.region_event({}, "surface", "understood",
                                     reason="entry mapped",
                                     citations=["deep_dive/05-deep-dive.json"]))
    st, _ = re_state.load_state(case)
    re_state.save_checkpoint(case, st)
    snap = json.loads((case / re_state.STATE_SNAPSHOT).read_text())
    assert snap == st
    assert not (case / (re_state.STATE_SNAPSHOT + ".tmp")).exists()


def test_unknown_kinds_do_not_corrupt_the_fold(tmp_path):
    """Forward compatibility is the schema binding: a future producer's new
    event kinds are ignored by today's consumer instead of folding garbage
    into the state (and instead of crashing it)."""
    case = _case(tmp_path)
    log = case / re_state.EVENT_FILE
    re_state.append_event(log, "init", sample_sha256="abc")
    re_state.append_event(log, "future_kind_we_do_not_know", payload={"x": 1})
    st, dropped = re_state.load_state(case)
    assert dropped == 0
    assert st["sample_sha256"] == "abc"
    assert st["regions"] == {}


def test_the_vocabulary_cannot_fork_from_depth_agent():
    """The local mirror and depth_agent's owner must agree - a fork is a
    future termination bug, and this is the cheapest place to catch it."""
    assert re_state.verify_vocabulary_agreement(), (
        "re_state's vocabulary or citation rule drifted from depth_agent's")


def test_module_imports_from_the_repo_layout():
    """The layout tripwire's counterpart: this module must sit in revai/ flat,
    because that is what deploys."""
    assert resolve("revai/re_state.py").exists()
