"""revai/depth_agent.py — the depth mode: understand HOW the sample works.

A separate mode because the operator's five reasons all hold: expensive, long,
unpredictable (it loops until the picture is complete), needs pause/resume, and
needs status the examiner can act on. This is NOT the main pipeline and must
never gate it. It runs AFTER the main pipeline and reads that pipeline's
artifacts as its starting context.

The objective is UNDERSTANDING, not a verdict. A depth run that produces a
verdict has failed its own objective — this stage produces a function map, not a
judgment.

What makes it buildable is the convergence contract, not the budget. "Whatever is
required to understand the exe" cannot be a stopping rule. Every function or
region gets a status from a fixed vocabulary, each with a reason and an evidence
citation, and the loop terminates when the unknown set is empty or explicitly
costed.

Two honest boundaries are structural here, not aspirational:

* An OVERSTATED status is worse than an admitted unknown. 'understood' with no
  citation is not accepted, so a confident wrong answer cannot enter the map.
* A cutoff is not a failure. Hitting the ceiling forces a consolidate-and-declare
  phase, so the run always yields a partial-but-honest map rather than nothing —
  which is what makes an unpredictable run acceptable.

Stop triggers: BOTH, per the operator. An examiner can stop at any time, and a
wall-clock/token ceiling stops it unattended. Either way the run consolidates
before it exits.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

#: The env knob. Operator requirement: a separate mode with an ON/OFF switch.
DEPTH_ENV = "REVAI_DEPTH"

#: Statuses a region can carry. This vocabulary is the convergence contract --
#: "whatever is required to understand the exe" becomes checkable only once
# "not understood" has a small number of named, distinguishable shapes.
STATUS_UNDERSTOOD = "understood"
STATUS_PARTIAL = "partial"
STATUS_NOT_RECONSTRUCTED = "not-reconstructed"
STATUS_NOT_EXPLORED = "not-explored"
VALID_STATUSES = (STATUS_UNDERSTOOD, STATUS_PARTIAL,
                 STATUS_NOT_RECONSTRUCTED, STATUS_NOT_EXPLORED)

#: Statuses that count as "still unknown" for the termination check.
UNKNOWN_STATUSES = (STATUS_PARTIAL, STATUS_NOT_RECONSTRUCTED,
                   STATUS_NOT_EXPLORED)

#: The state file the loop checkpoints after every region. This is what makes
#: pause and resume real rather than a restart, and what a stop consolidates.
STATE_FILE = "understanding.json"

#: Default ceiling. Deliberately generous but NOT open: an unbounded loop is how
#: a token budget burns without converging. The operator asked for a very-high
#: budget AND a ceiling, and both are true here -- the ceiling is high and its
#: effect is consolidation, not truncation.
DEFAULT_CEILING_SECONDS = 7200


def depth_enabled() -> bool:
    """Whether depth mode is on. Off by default — the main pipeline is unaffected.

    The vocabulary is deliberately 1/true/on and NOT the wider "yes" accepted by
    other startup gates: `REVAI_DEPTH` also carries the historical
    `REVAI_DEPTH=full` spelling from plan #26, which means a *depth profile*
    rather than "on". Widening the truthy set here would make R2's future
    `full` profile indistinguishable from "on". tests/test_depth_mode.py pins
    this; a change here is a change to the documented contract, not a fix.
    """
    return os.environ.get(DEPTH_ENV, "").strip().lower() in ("1", "true", "on")


def status_requires_evidence(status: str) -> bool:
    """Whether a status must carry a citation.

    ONLY 'not-explored' is excused: it asserts nothing beyond that the region was
    not looked at, and forcing a citation there would force a fabrication. Every
    other status claims something and must show its work.
    """
    return status != STATUS_NOT_EXPLORED


def unrecognised_statuses(regions: dict) -> list[str]:
    """Names carrying a status outside the vocabulary.

    An unrecognised label is NOT 'unknown' and NOT 'understood' -- it is a defect
    in the state itself, and it must be visible rather than silently dropped from
    both sets. `unknown_set` used to test membership in UNKNOWN_STATUSES, so a
    typo'd status was excluded from the unknown set (the loop would terminate with
    the region never understood) AND from cost_summary's counts (regions_total
    under-counted by one). Only has_converged noticed, and nothing called it.
    """
    known = set(VALID_STATUSES)
    return sorted(name for name, r in (regions or {}).items()
                  if str((r or {}).get("status")) not in known)


def unknown_set(regions: dict) -> list[str]:
    """Names still unknown, PLUS anything with a malformed status.

    Defensive because this is the set a loop's termination depends on: treating an
    unrecognised status as 'not unknown' would end the run with a region never
    understood and reported as such.
    """
    return sorted(set(unknown_set_known(regions)) | set(unrecognised_statuses(regions)))


def unknown_set_known(regions: dict) -> list[str]:
    """Names carrying one of the recognised UNKNOWN statuses."""
    return sorted(name for name, r in (regions or {}).items()
                  if str((r or {}).get("status")) in UNKNOWN_STATUSES)


def has_converged(regions: dict) -> bool:
    """True when EVERY region carries a fully understood status.

    Explicitly NOT "nothing is unknown": a status label outside the vocabulary
    must not count toward completion. Treating an unrecognised value as
    understood means a typo silently marks the run finished, which is the same
    failure as an unverified claim being counted as verified.
    """
    return bool(regions) and all(
        str((r or {}).get("status")) == STATUS_UNDERSTOOD
        for r in (regions or {}).values())


def load_state(case_dir: Path) -> dict:
    """The depth state for a case, or an empty skeleton when there is none."""
    p = Path(case_dir) / STATE_FILE
    if not p.is_file():
        return {"sha256": None, "regions": {}, "stop_reason": None,
                "spend": {"llm_calls": 0, "seconds": 0.0, "tokens": 0}}
    try:
        d = json.loads(p.read_text(errors="replace"))
        d.setdefault("regions", {})
        d.setdefault("stop_reason", None)
        d.setdefault("spend", {"llm_calls": 0, "seconds": 0.0, "tokens": 0})
        return d
    except Exception:
        return {"regions": {}, "stop_reason": None,
                "spend": {"llm_calls": 0, "seconds": 0.0, "tokens": 0}}


def save_state(case_dir: Path, state: dict) -> None:
    """Checkpoint the state. Called after every region so a stop is cheap."""
    p = Path(case_dir) / STATE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)  # atomic: a stop mid-write must not corrupt the resume


def ceiling_seconds() -> int:
    raw = os.environ.get("REVAI_DEPTH_CEILING_SECONDS", "") or str(
        DEFAULT_CEILING_SECONDS)
    try:
        return max(60, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_CEILING_SECONDS


def cost_summary(regions: dict, spend: dict) -> dict:
    """The number that makes a cutoff a partial success rather than a failure.

    Reported by every depth run: N regions understood / partial / not
    reconstructed / not explored, plus what it cost. Without this the operator
    cannot tell a run that finished from one that was stopped, and cannot set
    budgets by measurement.
    """
    counts = {s: 0 for s in VALID_STATUSES}
    malformed = 0
    for r in (regions or {}).values():
        s = str((r or {}).get("status"))
        if s in counts:
            counts[s] += 1
        else:
            malformed += 1
    unknown = sum(counts[s] for s in UNKNOWN_STATUSES)
    return {"regions_total": sum(counts.values()) + malformed,
             "by_status": counts,
             "malformed_status": malformed,
             # A region with an unrecognised status is not accounted 'unknown',
             # but it is certainly not understood -- report both so the number
             # reconciles and cannot be read as a clean completion.
             "unknown_remaining": unknown + malformed,
             "spend": spend}


def _domain_questions() -> dict[str, dict]:
    """The capability domains, from the vocabulary the pipeline already enforces."""
    try:
        import domain_graph as dg
        return {d["key"]: d for d in dg.DOMAINS}
    except Exception:
        return {}


def seed_regions(case: Path) -> dict[str, dict]:
    """The regions this depth run must deepen, seeded from the capability ledger.

    A region is a capability domain the main pipeline could NOT establish to an
    evidence-backed determination -- provenance `inferred` or `unknown` (#56).
    A domain already `observed` needs no depth: the evidence is already cited.
    That is what makes this loop converge on something measurable rather than
    re-deriving what the deep dive already established.

    Returns the seeded region map; a case with no ledger (flat engine, or
    REVAI_DOMAIN_GRAPH off) seeds nothing and the caller says so rather than
    inventing regions.
    """
    regions: dict[str, dict] = {}
    try:
        from v2_lib import build_capability_coverage, LOGS_DIR
        _logs = Path(os.environ.get("REVAI_LOGS_DIR") or LOGS_DIR)
        # case is <logs>/<sha>[/<mode>]; build_capability_coverage wants <logs>+<sha>
        sha = case.name if len(case.name) == 64 else case.parent.name
        cov = build_capability_coverage(sha, logs_dir=_logs)
    except Exception:
        return regions
    if not cov or not cov.get("domains"):
        return regions

    questions = _domain_questions()
    for key, entry in (cov.get("domains") or {}).items():
        prov = entry.get("provenance") or "unknown"
        if prov == "observed":
            continue
        d = questions.get(key) or {}
        regions[key] = {
            "status": STATUS_NOT_EXPLORED,
            "reason": "",
            "evidence": [],
            "title": d.get("title", key),
            "question": d.get("question", ""),
            "seeded_from_provenance": prov,
            "pipeline_determination": str(entry.get("answer") or "")[:400],
            "pipeline_evidence_count": entry.get("evidence") or 0,
        }
    return regions


def _stop_requested(case: Path) -> bool:
    """The examiner's stop switch. Touching <case>/depth.stop ends the loop."""
    return (Path(case) / "depth.stop").exists()


def investigate_region(case: Path, name: str, region: dict) -> dict:
    """One bounded investigation of one region. Returns the updated region.

    The honesty rule is enforced HERE, not trusted: a status that claims
    something must cite evidence, and a status outside the vocabulary is not
    silently accepted. 'understood' with no citation is downgraded to 'partial'
    with the reason recorded -- a confident wrong answer must not enter the map.
    """
    from v2_lib import llm_judge
    title = region.get("title") or name
    question = region.get("question") or f"What does this sample do for {title}?"
    prior = str(region.get("pipeline_determination") or "")
    prompt = (
        "You are deepening ONE capability domain of a malware reverse-engineering "
        "analysis. The main pipeline already examined it and could NOT establish "
        "an evidence-backed determination. Your job is to close that gap or say "
        "honestly that it cannot be closed from the available evidence.\n\n"
        f"## Domain: {title}\n{question}\n\n"
        f"## What the main pipeline concluded (provenance: "
        f"{region.get('seeded_from_provenance')})\n{prior or '(nothing recorded)'}\n\n"
        "## Rules\n"
        "- Cite CONCRETE evidence for every claim: a tool, a SQL query, a "
        "function name, an offset, a string. 'understood' with no citation is "
        "not accepted and will be downgraded.\n"
        "- If the evidence does not establish the behaviour, say 'not observed' "
        "and name what you checked. 'not observed' with the checks named IS a "
        "determination.\n"
        "- Never infer a capability from the sample's family or filename.\n"
        "- Reply with ONE JSON object: "
        '{"status": "understood|partial|not-reconstructed", '
        '"answer": "...", "evidence": ["...", "..."], "reason": "..."}\n'
        "- 'not-reconstructed' means the available tools could not reach the "
        "answer (packed, unsupported format, no SQL server).\n"
    )
    try:
        raw = llm_judge(prompt)
    except Exception as exc:
        region["status"] = STATUS_NOT_RECONSTRUCTED
        region["reason"] = f"investigation call failed: {type(exc).__name__}: {exc}"
        region["evidence"] = []
        return region

    text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    parsed = {}
    try:
        from v2_lib import normalize_llm_json
        parsed = normalize_llm_json(text) or {}
        if not isinstance(parsed, dict):
            parsed = {}
    except Exception:
        parsed = {}

    status = str(parsed.get("status") or "").strip().lower()
    evidence = [str(e)[:160] for e in (parsed.get("evidence") or [])[:8]]
    answer = str(parsed.get("answer") or "")[:1200]
    reason = str(parsed.get("reason") or "")[:400]

    if status not in VALID_STATUSES or status == STATUS_NOT_EXPLORED:
        # Not in the vocabulary, or claiming "I never looked" while answering:
        # both are the model over- or under-stating. Record what it said and
        # take the conservative grade.
        region["model_status"] = status or "(none)"
        region["status"] = STATUS_PARTIAL
        region["reason"] = reason or (
            f"model returned status {status!r}, outside the vocabulary or "
            "contradicting its own answer")
        region["status_contradicts_answer"] = True
    else:
        region["status"] = status
        region["reason"] = reason

    # THE rule: a claim needs a citation. Enforced here so a confident wrong
    # answer cannot enter the map.
    if status_requires_evidence(region["status"]) and not evidence:
        if region["status"] == STATUS_UNDERSTOOD:
            region["status"] = STATUS_PARTIAL
            region["reason"] = (
                (region.get("reason") or "")
                + " | downgraded from understood: no evidence cited")
            region["downgraded_for_no_evidence"] = True

    region["answer"] = answer
    region["evidence"] = evidence
    region["investigated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return region


def run_depth_loop(case: Path, ceiling: int | None = None) -> dict:
    """The convergence loop: deepen every seeded region until understood or costed.

    Terminates on ANY of: every region understood, the wall-clock ceiling, or the
    examiner's stop file. Every exit consolidates -- a cutoff yields a
    partial-but-honest map, never nothing.

    Checkpoints after EVERY region, so a pause is a resume rather than a restart.
    """
    case = Path(case)
    ceiling = ceiling if ceiling is not None else ceiling_seconds()
    t0 = time.time()
    st = load_state(case)
    st.setdefault("regions", {})
    st.setdefault("spend", {"llm_calls": 0, "seconds": 0.0, "tokens": 0})

    # Resume: regions already carried keep their status; only re-seed the ones
    # that were never investigated.
    seeded = seed_regions(case)
    for name, region in seeded.items():
        st["regions"].setdefault(name, region)
    if not st["regions"]:
        st["stop_reason"] = (
            "no-regions-to-deepen: every capability domain the main pipeline "
            "examined already carries an evidence-backed determination, or the "
            "run produced no capability ledger. Nothing to converge on.")
        save_state(case, st)
        return st

    stop_reason = None
    while True:
        pending = unknown_set(st["regions"])
        if not pending:
            stop_reason = "converged: every region understood"
            break
        if _stop_requested(case):
            stop_reason = (f"stopped by examiner (depth.stop); "
                           f"{len(pending)} region(s) still unknown")
            break
        elapsed = time.time() - t0
        if elapsed >= ceiling:
            stop_reason = (
                f"ceiling reached after {int(elapsed)}s; "
                f"{len(pending)} region(s) still unknown -- consolidated, "
                "not truncated")
            break

        name = pending[0]
        before = time.time()
        st["regions"][name] = investigate_region(case, name, st["regions"][name])
        st["spend"]["llm_calls"] = int(st["spend"].get("llm_calls", 0)) + 1
        st["spend"]["seconds"] = round(
            float(st["spend"].get("seconds", 0.0)) + (time.time() - before), 1)
        # Checkpoint after EVERY region: a pause is a resume.
        save_state(case, st)

    st["stop_reason"] = stop_reason
    st["converged"] = has_converged(st["regions"])
    st["cost"] = cost_summary(st["regions"], st["spend"])
    save_state(case, st)
    return st


def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="depth mode")
    ap.add_argument("target", nargs="?",
                    help="case directory (default: read REVAI_CASE_DIR)")
    ap.add_argument("--status", action="store_true",
                    help="report the depth state as JSON and exit")
    ap.add_argument("--run", action="store_true",
                    help="run the convergence loop (deepen every region the "
                         "main pipeline could not establish)")
    args = ap.parse_args()

    # Resolve the case dir the SAME way the other stages do. The first version
    # took a bare path and pipeline_single passed a sha, so the stage read
    # /opt/samples/logs/<sha>/understanding.json -- a path that never exists --
    # and reported an empty map with rc=0. That is indistinguishable in the trace
    # from 'the sample has no functions', which is exactly the hollow-success
    # failure the rest of the pipeline gates against.
    case = None
    target = args.target or os.environ.get("REVAI_CASE_DIR", "")
    if target:
        p = Path(target)
        if p.is_dir():
            case = p
        else:
            # A sha resolves through case_dir() -- but case_dir() CREATES the
            # directory, so `is_dir()` is always True afterwards and the
            # "fail loudly when the case does not exist" branch below could
            # never fire. The stage would resolve a sha that was never run,
            # report an empty map and exit 0 -- the hollow green this whole
            # path exists to prevent. Check whether the case existed BEFORE
            # resolving, which is the only thing that distinguishes "a sample
            # that was run" from "a sha nobody has analysed".
            from v2_lib import LOGS_DIR
            _logs = Path(os.environ.get("REVAI_LOGS_DIR") or LOGS_DIR)
            _pre_existing = _logs.is_dir() and (_logs / target).exists()
            try:
                from v2_lib import case_dir
                case = case_dir(target)
            except Exception:
                case = p
            if not _pre_existing:
                print(f"[depth] case for {target[:16]}... does not exist under "
                      f"{_logs}: the sample has not been run, so there is nothing "
                      "to deepen. Run the pipeline first.",
                      file=sys.stderr, flush=True)
                return 3

    if case is None:
        print(f"depth enabled: {depth_enabled()}  "
              f"ceiling: {ceiling_seconds()}s")
        return 0

    if args.run:
        if case is None:
            print("[depth] --run needs a case directory or a run sha",
                  file=sys.stderr, flush=True)
            return 2
        st = run_depth_loop(case)
        summary = cost_summary(st.get("regions"), st.get("spend") or {})
        summary["case_dir"] = str(case)
        summary["converged"] = st.get("converged")
        summary["stop_reason"] = st.get("stop_reason")
        print(json.dumps(summary, indent=2))
        # rc=0 only when the loop actually ran. An empty region set is an honest
        # outcome, not a failure, but it is reported on stderr so a hollow run
        # cannot look like a converged one.
        if not st.get("regions"):
            print(f"[depth] {st.get('stop_reason')}", file=sys.stderr, flush=True)
        return 0

    st = load_state(case)
    summary = cost_summary(st["regions"], st["spend"])
    summary["case_dir"] = str(case)
    summary["converged"] = has_converged(st["regions"])
    summary["stop_reason"] = st.get("stop_reason")

    # A depth run that has done nothing must not read as a depth run that
    # finished. This invocation REPORTED state; it did not investigate anything
    # (no regions, no spend). The convergence loop exists and is driven by
    # --run; an empty map here means no depth run has been performed on this
    # case, which is exactly the hollow-success shape the rest of the pipeline
    # gates against.
    spend = st.get("spend") or {}
    if not st.get("regions") and not spend.get("llm_calls"):
        summary["stop_reason"] = (
            "no-depth-analysis-performed: this invocation reported the case's "
            "depth state and investigated nothing. The convergence loop exists "
            "and is driven by `depth_agent.py <case> --run`; no depth run has "
            "been performed on this case. regions_total=0 means nothing was "
            "looked at, not that the sample has no functions."
        )
        summary["depth_run_with"] = "depth_agent.py <case> --run"
        print("[depth] WARNING: no depth analysis has been performed on this "
              "case. Run `depth_agent.py <case> --run` to deepen the capability "
              "domains the main pipeline could not establish.",
              file=sys.stderr, flush=True)
        # Write the artifact with that reason inside it. A stage that produced
        # nothing and left no trace is indistinguishable in the trace from one
        # that legitimately found nothing.
        try:
            out = case / "understanding.json"
            out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            summary["understanding_json"] = str(out)
        except OSError as exc:
            print(f"[depth] could not write understanding.json: {exc}",
                  file=sys.stderr, flush=True)

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())