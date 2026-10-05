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
    """Whether depth mode is on. Off by default — the main pipeline is unaffected."""
    return os.environ.get(DEPTH_ENV, "").strip().lower() in ("1", "true", "on")


def status_requires_evidence(status: str) -> bool:
    """Whether a status must carry a citation.

    ONLY 'not-explored' is excused: it asserts nothing beyond that the region was
    not looked at, and forcing a citation there would force a fabrication. Every
    other status claims something and must show its work.
    """
    return status != STATUS_NOT_EXPLORED


def unknown_set(regions: dict) -> list[str]:
    """Names of the regions still unknown, for the termination check."""
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
    for r in (regions or {}).values():
        s = str((r or {}).get("status"))
        if s in counts:
            counts[s] += 1
    return {"regions_total": sum(counts.values()), "by_status": counts,
             "unknown_remaining": sum(counts[s] for s in UNKNOWN_STATUSES),
             "spend": spend}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="depth mode")
    ap.add_argument("case", nargs="?", help="case dir to inspect")
    args = ap.parse_args()
    if args.case:
        st = load_state(Path(args.case))
        print(json.dumps(cost_summary(st["regions"], st["spend"]), indent=2))
    else:
        print(f"depth enabled: {depth_enabled()}  "
              f"ceiling: {ceiling_seconds()}s")
    raise SystemExit(0)