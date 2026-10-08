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


def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="depth mode")
    ap.add_argument("target", nargs="?",
                    help="case directory (default: read REVAI_CASE_DIR)")
    ap.add_argument("--status", action="store_true",
                    help="report the depth state as JSON and exit")
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

    st = load_state(case)
    summary = cost_summary(st["regions"], st["spend"])
    summary["case_dir"] = str(case)
    summary["converged"] = has_converged(st["regions"])
    summary["stop_reason"] = st.get("stop_reason")

    # A depth run that has done nothing must not read as a depth run that
    # finished. Plan #20 landed the capability-domain substrate the convergence
    # loop runs on, but NOT the loop itself -- a domain node answers once, with
    # no re-examination -- so this stage still has no investigation to perform.
    # The honest report is an explicit one, not rc=0 with an empty map and no
    # artifact, which is exactly the hollow-success shape the rest of the
    # pipeline gates against.
    spend = st.get("spend") or {}
    if not st.get("regions") and not spend.get("llm_calls"):
        summary["stop_reason"] = (
            "no-depth-analysis-performed: the deep dive's capability-domain "
            "nodes (plan #20) answer each domain once and do not re-examine it; "
            "the convergence loop that would drive them is still open. This run "
            "reported the case's depth state; it did not investigate anything. "
            "regions_total=0 means nothing was looked at, not that the sample "
            "has no functions."
        )
        summary["depth_deferred_to"] = (
            "the convergence loop over plan #20's domain nodes")
        print("[depth] WARNING: no depth analysis ran. The convergence loop "
              "over the domain nodes is still open; this invocation only "
              "reports state.",
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