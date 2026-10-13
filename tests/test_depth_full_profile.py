#!/usr/bin/env python3
"""Plan #26 - the full depth profile: the domain-node substrate.

The full profile is NOT a truthy alias for "on". It is a different
investigation: every capability domain is deepened by its own bounded
tool-calling node (the #20 substrate), under a raised ceiling, with
emulation/unpack/solver forced on, emitting the Phase 0 state stream, and
producing a map whose gap section is required rather than optional.

These tests pin the profile's contract without an LLM: the parsing, the
budget levers, the fold's honesty rules (the substrate changes, the honesty
rule does not), the quarantine that keeps the main pipeline's record, and a
driven `_run_full_profile` with the substrate monkeypatched.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import source  # noqa: E402

import depth_agent as DA  # noqa: E402


# ------------------------------------------------------------- the profile gate
def test_profile_parsing_keeps_full_distinct_from_on(monkeypatch):
    """`full` is a profile, not a truthy alias -- the contract the vocabulary
    was built to reserve (tests/test_depth_mode.py pins the narrow set)."""
    for val, expected in (("full", "full"), ("FULL", "full"),
                          (" full ", "full"), ("1", "d0"), ("true", "d0"),
                          ("on", "d0"), ("", ""), ("yes", ""),
                          ("fullest", "")):
        monkeypatch.setenv("REVAI_DEPTH", val)
        assert DA.depth_profile() == expected, val
        assert DA.depth_requested() is bool(expected), val
        # depth_enabled keeps its narrow meaning: "full" is NOT "on".
        assert DA.depth_enabled() is (expected == "d0"), val


def test_full_ceiling_defaults_far_above_d0(monkeypatch):
    """Long runtimes are expected by design for the full profile; an explicit
    env value still wins for both."""
    monkeypatch.delenv("REVAI_DEPTH_CEILING_SECONDS", raising=False)
    monkeypatch.setenv("REVAI_DEPTH", "full")
    full_default = DA.ceiling_seconds()
    monkeypatch.setenv("REVAI_DEPTH", "1")
    d0_default = DA.ceiling_seconds()
    assert full_default > d0_default >= 7200, (full_default, d0_default)
    monkeypatch.setenv("REVAI_DEPTH_CEILING_SECONDS", "600")
    assert DA.ceiling_seconds() == 600, "the explicit env must win"
    monkeypatch.setenv("REVAI_DEPTH_CEILING_SECONDS", "not-a-number")
    assert DA.ceiling_seconds() == d0_default, "non-numeric falls back"


def test_forced_features_use_setdefault_semantics(monkeypatch):
    """An operator's explicit value wins; what was forced is recorded so the
    run states what it enabled."""
    for key in ("REVAI_DOMAIN_GRAPH", "REVAI_DOMAIN_STEP_BUDGET",
                "REVAI_ENABLE_EMULATION_ORACLE", "REVAI_ENABLE_UNPACK_PASS",
                "ENABLE_DEOBFUSCATION_PASS"):
        monkeypatch.delenv(key, raising=False)
    forced = DA._force_full_profile_features()
    assert len(forced) == 5, forced
    assert any(f.startswith("REVAI_DOMAIN_GRAPH=1") for f in forced)
    # An explicit operator value is not overwritten and is not reported as forced.
    monkeypatch.setenv("REVAI_ENABLE_UNPACK_PASS", "0")
    forced2 = DA._force_full_profile_features()
    assert not any("UNPACK" in f for f in forced2), forced2


# ------------------------------------------------------------- the fold's rules
def _dom_result(domains: dict) -> dict:
    return {"findings": {"domain_graph": {"domains": domains},
                         "domain_findings": "- **persistence**: ..."}}


def test_fold_maps_domains_under_the_shared_vocabulary():
    dom = _dom_result({
        "persistence": {"status": "understood", "answer": "run key",
                        "evidence": ["iocs.json"], "reason": "cited",
                        "tool_calls_used": 4},
        "c2_network": {"status": "not-explored", "answer": "",
                       "evidence": [], "reason": "packed"},
    })
    folded = DA._fold_domain_results({}, dom)
    assert folded["persistence"]["status"] == "understood"
    assert folded["persistence"]["evidence"] == ["iocs.json"]
    assert folded["persistence"]["substrate"] == "domain-graph"
    # not-explored is citation-excused and stays as claimed.
    assert folded["c2_network"]["status"] == "not-explored"
    assert "defect" not in folded["c2_network"] or \
        not folded["c2_network"].get("defect")


def test_fold_grades_conservatively_exactly_like_d0():
    """The substrate changes; the honesty rule does not."""
    dom = _dom_result({
        "evasion": {"status": "understood", "answer": "anti-debug",
                    "evidence": [], "reason": "trust me"},
        "surface": {"status": "understod", "answer": "typo",
                    "evidence": ["x"], "reason": "typo"},
        "exfiltration": {"status": "understood", "answer": "archive",
                         "evidence": ["deep_dive/05-deep-dive.json"]},
    })
    folded = DA._fold_domain_results({}, dom)
    # understood with no evidence is downgraded, as investigate_region does.
    assert folded["evasion"]["status"] == "partial"
    assert folded["evasion"]["downgraded_for_no_evidence"] is True
    # a status outside the vocabulary is a defect, preserved verbatim.
    assert folded["surface"]["status"] == "partial"
    assert folded["surface"]["model_status"] == "understod"
    assert folded["surface"]["status_contradicts_answer"] is True
    # a properly cited claim survives.
    assert folded["exfiltration"]["status"] == "understood"


# ------------------------------------------------------------- the quarantine
def test_quarantine_keeps_the_main_pipelines_record(tmp_path):
    """The full pass overwrites agentic_deep_dive.json; the published reports
    cite the original, so it is moved aside rather than erased."""
    dd = tmp_path / "deep_dive"
    dd.mkdir()
    (dd / "agentic_deep_dive.json").write_text('{"original": true}')
    (dd / "05-deep-dive.json").write_text("{}")
    moved = DA._quarantine_deep_dive_artifacts(tmp_path)
    assert len(moved) == 2, moved
    assert not (dd / "agentic_deep_dive.json").exists()
    kept = list(dd.glob("agentic_deep_dive.json.pre-depth-full-*"))
    assert kept and json.loads(kept[0].read_text())["original"] is True


# ------------------------------------------------------------- the driven loop
def _seeded_case(tmp_path: Path) -> Path:
    case = tmp_path / ("a" * 64) / "agentic"
    case.mkdir(parents=True)
    (case / "understanding.json").write_text(json.dumps({
        "regions": {
            "persistence": {"status": "partial", "reason": "imports only",
                            "attempts": 0},
            "c2_network": {"status": "not-explored", "reason": "packed",
                           "attempts": 0},
        },
        "spend": {"llm_calls": 0, "seconds": 0.0, "tokens": 0},
    }))
    return case


def test_run_depth_loop_full_profile_drives_the_substrate(tmp_path, monkeypatch):
    """The full loop, driven with the substrate monkeypatched: regions folded,
    the Phase 0 stream emitted, the snapshot written, the gap section
    required, and the profile recorded in the artifact."""
    monkeypatch.setenv("REVAI_DEPTH", "full")
    monkeypatch.delenv("REVAI_DEPTH_CEILING_SECONDS", raising=False)
    case = _seeded_case(tmp_path)
    calls = []

    def fake_pass(sha, case_dir):
        calls.append(sha)
        return _dom_result({
            "persistence": {"status": "understood", "answer": "run key",
                            "evidence": ["iocs.json"], "reason": "cited"},
            "c2_network": {"status": "partial", "answer": "domains only",
                           "evidence": ["strings.txt"]},
        })

    monkeypatch.setattr(DA, "run_domain_depth_pass", fake_pass)
    st = DA.run_depth_loop(case)

    assert calls, "the domain-node substrate must be the investigation path"
    assert st["profile"] == "full"
    assert st["substrate"] == "domain-graph (#20)"
    assert st["regions"]["persistence"]["status"] == "understood"
    assert st["regions"]["persistence"]["evidence"] == ["iocs.json"]
    assert st["regions"]["c2_network"]["status"] == "partial"
    assert st["spend"]["llm_calls"] == 2
    # The gap section is REQUIRED for the full profile.
    assert st["gap_section"]["unknown_regions"] == ["c2_network"]
    assert st["gap_section"]["regions_total"] == 2
    assert st["stop_reason"] and "costed" in st["stop_reason"]
    # The Phase 0 stream: events appended and the snapshot folded beside them.
    import re_state
    events, dropped = re_state.load_log(case / re_state.EVENT_FILE)
    assert dropped == 0
    kinds = [e.get("kind") for e in events]
    assert kinds[0] == "init" and "phase" in kinds
    assert kinds.count("region_status") == 2
    assert kinds.count("spend") == 2
    snap = json.loads((case / re_state.STATE_SNAPSHOT).read_text())
    assert snap["schema"] == re_state.SCHEMA
    assert snap["regions"]["persistence"]["status"] == "understood"
    # The forced features are recorded.
    assert st["forced_features"]


def test_full_profile_does_not_paper_over_a_failed_substrate(tmp_path, monkeypatch):
    """A substrate that produced nothing is a STATED failure; the flat
    evidence-only investigation is not substituted for it."""
    monkeypatch.setenv("REVAI_DEPTH", "full")
    case = _seeded_case(tmp_path)
    monkeypatch.setattr(DA, "run_domain_depth_pass", lambda sha, c: {})
    st = DA.run_depth_loop(case)
    assert "no usable result" in st["stop_reason"]
    assert st["regions"]["persistence"]["status"] == "partial", (
        "a failed pass must not invent determinations")


# ------------------------------------------------------------- the stage gates
def test_the_stage_gates_accept_the_profile():
    """Both drivers must run the depth stage for REVAI_DEPTH=full, and the
    orchestrator must pass the PROFILE through rather than flattening it."""
    single = source("revai/pipeline_single.py")
    assert "depth_requested()" in single, (
        "pipeline_single must gate on depth_requested, or REVAI_DEPTH=full "
        "never reaches the stage")
    orch = source("revai/stage_orchestrator.py")
    assert "depth_requested()" in orch
    assert 'env["REVAI_DEPTH"] = depth_profile() or "1"' in orch, (
        "the orchestrator must forward the profile; flattening to 1 would "
        "silently run the D0 substrate")
    app = source("revai/app.py")
    # The Console's depth button must not flatten an exported profile either.
    assert 'if not (os.environ.get("REVAI_DEPTH") or "").strip():' in app
    assert '"REVAI_DEPTH=1"' in app, "the button's own opt-in stays"
    # The run-config carries the profile and maps it to the env.
    assert '"depth_profile"' in app
    assert 'env["REVAI_DEPTH"] = _dp' in app
