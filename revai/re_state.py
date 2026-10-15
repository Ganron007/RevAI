#!/usr/bin/env python3
"""Phase 0 - the RE state stream: a versioned, append-only record of where a
reverse-engineering effort stands.

This is the substrate #26 (full depth profile) and #13-L2 (mid-run steering)
both consume. The design rule from the plan is load-bearing: **bind consumers
to the SCHEMA, never to the producer.** The stream is a fold of an append-only
event log, so:

* the history is the audit trail - a consumer reads `re-state.jsonl` and gets
  every transition, not just the latest snapshot;
* a kill mid-write can corrupt at most the last line, and a corrupted last
  line is DROPPED AND REPORTED, never silently (a silently truncated log
  looks exactly like a shorter run);
* swapping the producer (D0 depth today, the domain-node graph tomorrow) is a
  producer change with zero consumer churn, because consumers bind to
  `SCHEMA`.

The four-status vocabulary is NOT redefined here - it is re-exported from
`depth_agent`, which owns it. Two vocabularies would drift, and drift here
means a loop terminates on a status nobody validates.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Iterable

# Bind consumers to this string. A state that does not carry it is not ours to
# read: half-reading a foreign schema is how a consumer inherits a producer's
# bug silently.
SCHEMA = "revai-re-state/v1"

#: The event log. Append-only; the state is a fold of it.
EVENT_FILE = "re-state.jsonl"

#: The atomic snapshot written beside the log (a convenience for readers, and
#: what a stop consolidates into). Never the source of truth.
STATE_SNAPSHOT = "re-state.json"

STATUS_UNDERSTOOD = "understood"
STATUS_PARTIAL = "partial"
STATUS_NOT_RECONSTRUCTED = "not-reconstructed"
STATUS_NOT_EXPLORED = "not-explored"
VALID_STATUSES = (STATUS_UNDERSTOOD, STATUS_PARTIAL,
                  STATUS_NOT_RECONSTRUCTED, STATUS_NOT_EXPLORED)
UNKNOWN_STATUSES = (STATUS_PARTIAL, STATUS_NOT_RECONSTRUCTED,
                    STATUS_NOT_EXPLORED)

# Re-export the vocabulary's helpers from their owner rather than copying them.
from depth_agent import (  # noqa: E402
    status_requires_evidence,
    unrecognised_statuses,
)


def status_requires_evidence_local(status: str) -> bool:
    """Local mirror of depth_agent's rule, pinned so this module can be tested
    without importing the depth loop. The two must agree; a test asserts the
    imported helper matches this one."""
    return status != STATUS_NOT_EXPLORED


def new_state(sample_sha256: str = "", run_id: str = "") -> dict:
    """A fresh state: schema first (a reader must be able to reject it), empty
    regions, zero spend."""
    return {
        "schema": SCHEMA,
        "sample_sha256": sample_sha256,
        "run_id": run_id,
        "phase": "init",
        "hypothesis": "",
        "regions": {},
        "spend": {"llm_calls": 0, "seconds": 0.0, "tokens": 0,
                  "domain_investigations": 0,
                  "token_usage_complete": None},
        "started_at": time.time(),
    }


def _now() -> float:
    return time.time()


def append_event(path: Path, kind: str, **fields: Any) -> dict:
    """Append one event to the log. Never rewrites, never truncates.

    The write is a single line with a trailing newline: a kill mid-write can
    then only ever corrupt the LAST line, which `fold_events` drops and
    reports. Anything more clever (buffering, in-place updates) breaks that
    guarantee.
    """
    event = {"t": _now(), "kind": kind}
    event.update(fields)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, default=str) + "\n")
    return event


def region_event(state: dict, name: str, status: str, reason: str = "",
                 citations: Iterable[str] = ()) -> dict:
    """Build (not append) a region-status event with the honesty rules applied.

    * a status outside the vocabulary is recorded AS THAT STATUS plus
      `defect: "unrecognised_status"` - it is not normalised into a valid one,
      because a typo'd status is a defect in the state, not a synonym;
    * a citation-requiring status with no citation is recorded plus
      `defect: "status_without_evidence"` (depth's rule: an OVERSTATED status
      is worse than an admitted unknown).
    """
    event = {
        "kind": "region_status",
        "region": name,
        "status": str(status),
        "reason": reason,
        "citations": list(citations),
    }
    if status not in VALID_STATUSES:
        event["defect"] = "unrecognised_status"
    elif status_requires_evidence_local(status) and not list(citations):
        event["defect"] = "status_without_evidence"
    return event


def fold_events(events: Iterable[dict]) -> dict:
    """Fold an event list into the current state. Deterministic: the same
    events in the same order always produce the same state."""
    state = new_state()
    for ev in events:
        kind = ev.get("kind")
        if kind == "init":
            state["sample_sha256"] = ev.get("sample_sha256", "")
            state["run_id"] = ev.get("run_id", "")
            state["started_at"] = ev.get("t", state["started_at"])
        elif kind == "phase":
            state["phase"] = ev.get("phase", state["phase"])
        elif kind == "hypothesis":
            state["hypothesis"] = ev.get("hypothesis", "")
        elif kind == "region_status":
            state["regions"][ev.get("region", "?")] = {
                "status": ev.get("status", ""),
                "reason": ev.get("reason", ""),
                "citations": ev.get("citations", []),
                "defect": ev.get("defect", ""),
                "updated_at": ev.get("t", 0),
            }
        elif kind == "spend":
            sp = state["spend"]
            calls = int(ev.get("llm_calls", 0) or 0)
            sp["llm_calls"] += calls
            sp["seconds"] = round(float(sp.get("seconds", 0.0))
                                  + float(ev.get("seconds", 0.0) or 0.0), 1)
            sp["tokens"] += int(ev.get("tokens", 0) or 0)
            sp["domain_investigations"] += int(
                ev.get("domain_investigations", 0) or 0)
            if "token_usage_complete" in ev:
                reported = bool(ev.get("token_usage_complete"))
                prior = sp.get("token_usage_complete")
                sp["token_usage_complete"] = (
                    reported if prior is None else bool(prior) and reported)
            elif calls:
                # A stage that does not emit measured token usage cannot claim
                # that the accumulated token total is complete.
                sp["token_usage_complete"] = False
    return state


def load_log(path: Path) -> tuple[list[dict], int]:
    """Read the event log, tolerating a truncated last line.

    Returns (events, dropped_tail). A partial last line is dropped AND
    COUNTED - a silently truncated log is indistinguishable from a shorter
    run, which is the failure this whole design exists to prevent.
    """
    if not path.exists():
        return [], 0
    events: list[dict] = []
    dropped = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except (ValueError, TypeError):
                dropped += 1
    return events, dropped


def load_state(case_dir: Path) -> tuple[dict, int]:
    """Fold the log in `case_dir`. Returns (state, dropped_tail)."""
    events, dropped = load_log(Path(case_dir) / EVENT_FILE)
    return fold_events(events), dropped


def save_checkpoint(case_dir: Path, state: dict) -> None:
    """Atomically write the snapshot beside the log (tmp + replace).

    The snapshot is a convenience for readers; the LOG is the truth. A kill
    mid-write can never leave a half-read snapshot.
    """
    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    tmp = case_dir / (STATE_SNAPSHOT + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str),
                   encoding="utf-8")
    os.replace(tmp, case_dir / STATE_SNAPSHOT)


def unknown_regions(state: dict) -> list[str]:
    """Regions still unknown, PLUS any with a malformed status.

    Defensive because this is the set a loop's termination depends on
    (depth_agent's lesson, carried into the shared substrate): treating an
    unrecognised status as 'not unknown' ends the run with a region never
    understood and reported as understood.
    """
    regions = state.get("regions") or {}
    known = {n for n, r in regions.items()
             if str((r or {}).get("status")) in UNKNOWN_STATUSES}
    return sorted(known | set(unrecognised_statuses(regions)))


def has_converged(state: dict) -> bool:
    """Convergence = no unknown regions AND no malformed statuses."""
    return not unknown_regions(state)


def cost_summary(state: dict) -> dict:
    """Cost honesty as a first-class output: the four counts plus spend, so a
    budget is set by measurement rather than by feel."""
    regions = state.get("regions") or {}
    counts = {s: 0 for s in VALID_STATUSES}
    for r in regions.values():
        st = str((r or {}).get("status"))
        counts[st] = counts.get(st, 0) + 1
    counts["defects"] = sum(
        1 for r in regions.values() if (r or {}).get("defect"))
    return {
        "regions_total": len(regions),
        "by_status": counts,
        "spend": state.get("spend") or {},
        "converged": has_converged(state),
    }


def verify_vocabulary_agreement() -> bool:
    """The local mirror and depth_agent's owner must agree. Called by tests;
    a disagreement is a fork, and a fork is a future termination bug."""
    return (VALID_STATUSES
            == tuple(__import__("depth_agent").VALID_STATUSES)
            and status_requires_evidence_local(STATUS_UNDERSTOOD)
            == status_requires_evidence(STATUS_UNDERSTOOD)
            and status_requires_evidence_local(STATUS_NOT_EXPLORED)
            == status_requires_evidence(STATUS_NOT_EXPLORED))
