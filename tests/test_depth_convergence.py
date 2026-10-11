"""#26: the depth convergence loop.

The module had the vocabulary, the state store, the cost accounting and the stop
triggers -- and no loop. These pin the loop that was missing: it deepens the
capability domains the main pipeline could not establish, enforces the honesty
rule locally, checkpoints after every region, and consolidates on any exit.
"""
import json
import sys
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/depth_agent.py").parent))
import depth_agent as D  # noqa: E402
import v2_lib  # noqa: E402

SHA = "a" * 64

DOMAINS = {"surface": "understood", "persistence": "partial",
           "c2_network": "partial", "evasion": "partial",
           "execution_injection": "partial", "credential_access": "partial",
           "exfiltration": "partial", "defense_impairment": "partial",
           "crypto": "partial"}


def _case(tmp_path, domains=DOMAINS, answers=None):
    """A case whose capability ledger says: 1 observed, 8 not."""
    logs = tmp_path / "logs"
    case = logs / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    hist = []
    for k, st in domains.items():
        ev = ["e1"] if st == "understood" else []
        hist.append({"tool": f"domain:{k}",
                     "result": {"status": st,
                                "answer": (answers or {}).get(k, f"{k} answer"),
                                "evidence": ev,
                                "tool_calls_used": 3,
                                "format": "json"}})
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": domains}},
         "history": hist}), encoding="utf-8")
    return case, logs


def _fake_judge(reply):
    def _j(prompt, **kw):
        return reply if isinstance(reply, str) else json.dumps(reply)
    return _j


# ---------------------------------------------------------------- seeding
def test_only_unestablished_domains_become_regions(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    regions = D.seed_regions(case)
    assert set(regions) == set(DOMAINS) - {"surface"}, (
        "a domain the pipeline already established must not be re-deepened")
    for name, r in regions.items():
        assert r["status"] == D.STATUS_NOT_EXPLORED
        assert r["seeded_from_provenance"] == "inferred"
        assert r["question"], "a region with no question cannot be investigated"


def test_no_ledger_seeds_nothing_and_says_so(tmp_path, monkeypatch):
    case = tmp_path / "logs" / SHA / "scripted"
    case.mkdir(parents=True)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(tmp_path / "logs"))
    assert D.seed_regions(case) == {}


# ---------------------------------------------------------------- the loop
def test_the_loop_converges_when_the_model_answers(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    monkeypatch.setattr(D, "investigate_region",
                        lambda c, n, r: {**r, "status": D.STATUS_UNDERSTOOD,
                                         "answer": "closed", "evidence": ["e"]})
    st = D.run_depth_loop(case, ceiling=600)
    assert st["converged"] is True
    assert st["stop_reason"].startswith("converged")
    assert st["cost"]["by_status"]["understood"] == 8
    assert st["cost"]["unknown_remaining"] == 0
    assert (case / "understanding.json").is_file()


def test_the_loop_checkpoints_after_every_region(tmp_path, monkeypatch):
    """A pause must be a resume, not a restart."""
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    saves = []
    real_save = D.save_state

    def _spy(c, st):
        saves.append(len(st.get("regions") or {}))
        return real_save(c, st)

    monkeypatch.setattr(D, "save_state", _spy)
    monkeypatch.setattr(D, "investigate_region",
                        lambda c, n, r: {**r, "status": D.STATUS_UNDERSTOOD,
                                         "answer": "x", "evidence": ["e"]})
    D.run_depth_loop(case, ceiling=600)
    assert len(saves) >= 9, f"checkpointed only {len(saves)} times"


def test_resume_keeps_finished_regions(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    monkeypatch.setattr(D, "investigate_region",
                        lambda c, n, r: {**r, "status": D.STATUS_UNDERSTOOD,
                                         "answer": "x", "evidence": ["e"]})
    D.run_depth_loop(case, ceiling=600)
    # a second run re-seeds but must not re-investigate the understood ones
    calls = []
    monkeypatch.setattr(D, "investigate_region",
                        lambda c, n, r: (calls.append(n),
                                         {**r, "status": D.STATUS_UNDERSTOOD,
                                          "answer": "x", "evidence": ["e"]})[1])
    st = D.run_depth_loop(case, ceiling=600)
    assert calls == [], f"re-investigated already-understood regions: {calls}"
    assert st["converged"] is True


# ---------------------------------------------------------------- honesty
def test_understood_without_evidence_is_downgraded(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    monkeypatch.setattr(v2_lib, "llm_judge", _fake_judge({
        "status": "understood", "answer": "definitely persistence",
        "evidence": [], "reason": ""}))
    r = D.investigate_region(case, "persistence",
                             D.seed_regions(case)["persistence"])
    assert r["status"] == D.STATUS_PARTIAL, (
        "'understood' with no citation must not enter the map")
    assert r["downgraded_for_no_evidence"] is True
    assert "no evidence cited" in r["reason"]


def test_a_status_outside_the_vocabulary_is_recorded_not_accepted(tmp_path,
                                                                 monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    monkeypatch.setattr(v2_lib, "llm_judge", _fake_judge({
        "status": "totally-clear", "answer": "a", "evidence": ["e"]}))
    r = D.investigate_region(case, "persistence",
                             D.seed_regions(case)["persistence"])
    assert r["status"] == D.STATUS_PARTIAL
    assert r["model_status"] == "totally-clear"
    assert r["status_contradicts_answer"] is True


def test_not_explored_while_answering_is_a_contradiction(tmp_path, monkeypatch):
    """The #62 class: a node that says it never looked while giving an answer."""
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    monkeypatch.setattr(v2_lib, "llm_judge", _fake_judge({
        "status": "not-explored", "answer": "no persistence found",
        "evidence": ["e"]}))
    r = D.investigate_region(case, "persistence",
                             D.seed_regions(case)["persistence"])
    assert r["status"] == D.STATUS_PARTIAL
    assert r["status_contradicts_answer"] is True


def test_a_failed_call_is_not_reconstructed_not_understood(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))

    def _boom(prompt, **kw):
        raise RuntimeError("provider down")

    monkeypatch.setattr(v2_lib, "llm_judge", _boom)
    r = D.investigate_region(case, "persistence",
                             D.seed_regions(case)["persistence"])
    assert r["status"] == D.STATUS_NOT_RECONSTRUCTED
    assert "provider down" in r["reason"]


# ---------------------------------------------------------------- stop triggers
def test_the_ceiling_consolidates_rather_than_truncating(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    monkeypatch.setattr(D, "investigate_region",
                        lambda c, n, r: {**r, "status": D.STATUS_PARTIAL,
                                         "answer": "inconclusive",
                                         "evidence": ["e"]})
    st = D.run_depth_loop(case, ceiling=0)      # already past the ceiling
    assert st["converged"] is False
    assert "ceiling reached" in st["stop_reason"]
    assert "consolidated, not truncated" in st["stop_reason"]
    assert st["cost"]["unknown_remaining"] == 8, (
        "a cutoff must still report what is unknown")


def test_the_examiner_stop_file_ends_the_loop(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    (case / "depth.stop").write_text("", encoding="utf-8")
    monkeypatch.setattr(D, "investigate_region",
                        lambda c, n, r: {**r, "status": D.STATUS_UNDERSTOOD,
                                         "answer": "x", "evidence": ["e"]})
    st = D.run_depth_loop(case, ceiling=600)
    assert "stopped by examiner" in st["stop_reason"]
    assert st["cost"]["unknown_remaining"] == 8


def test_the_stop_file_is_checked_every_iteration(tmp_path, monkeypatch):
    """A stop written mid-run must be honoured, not only at the start."""
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    seen = {"n": 0}

    def _inv(c, n, r):
        seen["n"] += 1
        if seen["n"] == 3:
            (Path(c) / "depth.stop").write_text("", encoding="utf-8")
        return {**r, "status": D.STATUS_PARTIAL, "answer": "x",
                "evidence": ["e"]}

    monkeypatch.setattr(D, "investigate_region", _inv)
    st = D.run_depth_loop(case, ceiling=600)
    assert "stopped by examiner" in st["stop_reason"]
    assert seen["n"] == 3, f"kept going after the stop: {seen['n']}"


def test_no_regions_is_reported_not_silently_empty(tmp_path, monkeypatch):
    case, logs = _case(tmp_path, domains={k: "understood" for k in DOMAINS})
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    st = D.run_depth_loop(case, ceiling=600)
    assert st["regions"] == {}
    assert "no-regions-to-deepen" in st["stop_reason"]


def test_a_region_that_stays_unknown_is_costed_not_retried(tmp_path, monkeypatch):
    """THE defect the unit tests missed and the first live run found.

    A region that comes back unknown used to be picked again forever: measured
    on packed_rook_native at 27,162,541 llm_calls for three regions, because
    `unknown_set()` kept returning the same name and nothing tracked attempts.
    The tests passed because they mocked investigate_region to CONVERGE, so the
    non-converging path -- the only one that can spin -- was never exercised.
    """
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    calls = []

    def _never_converges(c, n, r):
        calls.append(n)
        return {**r, "status": D.STATUS_PARTIAL, "answer": "inconclusive",
                "evidence": ["e"]}

    monkeypatch.setattr(D, "investigate_region", _never_converges)
    st = D.run_depth_loop(case, ceiling=600)

    assert len(calls) == 8, (
        f"each of the 8 regions must be investigated ONCE; got {len(calls)} "
        f"calls -- a non-converging region is being retried, which is the spin "
        "that cost 27M llm_calls")
    assert len(set(calls)) == 8, "no region may be attempted twice by default"
    assert st["converged"] is False
    assert st["stop_reason"].startswith("costed:")
    assert "declared, not retried" in st["stop_reason"]
    assert st["spend"]["llm_calls"] == 8
    assert st["cost"]["unknown_remaining"] == 8


def test_attempts_are_bounded_and_settable(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    calls = []

    def _never_converges(c, n, r):
        calls.append(n)
        return {**r, "status": D.STATUS_PARTIAL, "answer": "x",
                "evidence": ["e"]}

    monkeypatch.setattr(D, "investigate_region", _never_converges)
    monkeypatch.setenv("REVAI_DEPTH_MAX_ATTEMPTS", "2")
    st = D.run_depth_loop(case, ceiling=600)
    assert len(calls) == 16, f"8 regions x 2 attempts; got {len(calls)}"
    assert st["attempts_allowed"] == 2

    for bad in ("abc", "0", "-3", ""):
        monkeypatch.setenv("REVAI_DEPTH_MAX_ATTEMPTS", bad)
        assert D._max_attempts() == 1, (
            f"a bad attempts value {bad!r} must fall back to 1, not disable "
            "the bound")


def test_a_stop_mid_run_is_honoured_with_attempt_tracking(tmp_path, monkeypatch):
    case, logs = _case(tmp_path)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(logs))
    seen = {"n": 0}

    def _inv(c, n, r):
        seen["n"] += 1
        if seen["n"] == 3:
            (Path(c) / "depth.stop").write_text("", encoding="utf-8")
        return {**r, "status": D.STATUS_PARTIAL, "answer": "x",
                "evidence": ["e"]}

    monkeypatch.setattr(D, "investigate_region", _inv)
    st = D.run_depth_loop(case, ceiling=600)
    assert "stopped by examiner" in st["stop_reason"]
    assert seen["n"] == 3
    assert st["spend"]["llm_calls"] == 3


def test_the_region_prompt_carries_the_pipelines_cited_evidence(tmp_path, monkeypatch):
    """A region handed only the CONCLUSION cannot re-derive or challenge it.

    Measured on packed_rook_native: the evasion region reported "no sample was
    provided, no strings/imports/disassembly output was available" while the
    pipeline had plainly examined one -- because it was given the conclusion and
    a count, not the citations.
    """
    import v2_lib
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    hist = []
    for k, st in DOMAINS.items():
        # surface is observed (understood + evidence). The rest are `inferred`
        # because they CONTRADICT themselves -- which is the packed_rook shape,
        # and the one case where a seeded region still has evidence to carry.
        if st == "understood":
            ev = [f"{k}: import_table row 1", f"{k}: strings row 2"]
            contra = False
        else:
            ev = [f"{k}: import_table row 1", f"{k}: strings row 2"]
            contra = True
        hist.append({"tool": f"domain:{k}",
                     "result": {"status": st, "answer": f"{k} answer",
                                "evidence": ev,
                                "status_contradicts_answer": contra,
                                "tool_calls_used": 3, "format": "json"}})
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": DOMAINS}},
         "history": hist}), encoding="utf-8")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")

    regions = D.seed_regions(case)
    r = regions["persistence"]
    assert r["pipeline_evidence"], (
        "the seeded region must carry what the pipeline CITED")
    assert any("import_table" in e for e in r["pipeline_evidence"])

    seen = {}

    def _cap(prompt, **kw):
        seen["prompt"] = prompt
        return {"choices": [{"message": {"content": json.dumps(
            {"status": "understood", "answer": "a", "evidence": ["e"]})}}]}

    monkeypatch.setattr(v2_lib, "llm_judge", _cap)
    D.investigate_region(case, "persistence", r)
    p = seen["prompt"]
    assert "Evidence the pipeline cited for it" in p
    assert "import_table row 1" in p, (
        "the region must see the citations, not just the conclusion")
    assert "persistence answer" in p


def test_a_region_with_no_citations_says_so(tmp_path, monkeypatch):
    """An absent evidence list must be stated, not silently omitted."""
    import v2_lib
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": DOMAINS}},
         "history": [{"tool": f"domain:{k}",
                      "result": {"status": "partial", "answer": "a",
                                 "evidence": [], "tool_calls_used": 1,
                                 "format": "json"}}
                     for k in DOMAINS]}), encoding="utf-8")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")

    seen = {}

    def _cap(prompt, **kw):
        seen["prompt"] = prompt
        return {"choices": [{"message": {"content": json.dumps(
            {"status": "understood", "answer": "a", "evidence": ["e"]})}}]}

    monkeypatch.setattr(v2_lib, "llm_judge", _cap)
    r = D.seed_regions(case)["persistence"]
    D.investigate_region(case, "persistence", r)
    assert "cited nothing" in seen["prompt"]
