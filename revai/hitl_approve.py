#!/usr/bin/env python3
"""
hitl_approve.py — Approve or reject a pending v2 HITL checkpoint.

Usage:
  python3 /opt/scripts/hitl_approve.py approve deep_dive_v2 pre_sql
  python3 /opt/scripts/hitl_approve.py reject  deep_dive_v2 pre_sql --reason "missing decompile target"
  python3 /opt/scripts/hitl_approve.py list
  python3 /opt/scripts/hitl_approve.py show  deep_dive_v2 pre_sql

Reads the state file written by `v2_lib.hitl_checkpoint()` at
`$CADRE_HITL_DIR/<agent>-<step>.json` (default `/tmp/cadre-hitl/<agent>-<step>.json`)
and flips `approved` accordingly.

Reject exits with rc=2 so a wrapper script can branch on the outcome.
The agent's `hitl_checkpoint()` reads `approved` from the same state file -
it observes the flip on its next 2s poll and either returns (approved=True)
or raises TimeoutError (approved=False, after deadline).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HITL_DIR = Path(os.environ.get("CADRE_HITL_DIR", "/tmp/cadre-hitl"))
HITL_DIR.mkdir(parents=True, exist_ok=True)


def _load(agent: str, step: str) -> dict | None:
    p = HITL_DIR / f"{agent}-{step}.json"
    if not p.is_file():
        return None
    return json.loads(p.read_text())


def _atomic_write(path: Path, payload: str) -> None:
    """Write payload atomically via a temp file + rename.

    This reduces (does not eliminate) the chance of a concurrent `hitl_approve.py`
    reader seeing a half-written JSON. Two concurrent `hitl_approve.py` writers
    (e.g. one `approve`, one `reject`) are still last-writer-wins — for stronger
    serialization use file-locking on `HITL_DIR` (future).
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload)
    tmp.replace(path)


def cmd_approve(agent: str, step: str, reviewer: str) -> dict:
    rec = _load(agent, step)
    if rec is None:
        sys.exit(f"no checkpoint at {HITL_DIR}/{agent}-{step}.json")
    rec["approved"] = True
    rec["reviewer"] = reviewer
    rec["review_ts"] = time.time()
    _atomic_write(HITL_DIR / f"{agent}-{step}.json", json.dumps(rec, indent=2))
    return rec


def cmd_reject(agent: str, step: str, reviewer: str, reason: str) -> dict:
    rec = _load(agent, step)
    if rec is None:
        sys.exit(f"no checkpoint at {HITL_DIR}/{agent}-{step}.json")
    rec["approved"] = False
    rec["rejected"] = True
    rec["reject_reason"] = reason
    rec["reviewer"] = reviewer
    rec["review_ts"] = time.time()
    _atomic_write(HITL_DIR / f"{agent}-{step}.json", json.dumps(rec, indent=2))
    return rec


def cmd_list() -> list:
    pending: list[dict] = []
    for f in sorted(HITL_DIR.glob("*.json")):
        rec = json.loads(f.read_text())
        pending.append({
            "file": f.name,
            "agent": rec.get("agent"),
            "step": rec.get("step"),
            "ts": rec.get("ts"),
            "approved": rec.get("approved"),
            "wait_mode": rec.get("wait_mode"),
            "payload_keys": sorted((rec.get("payload") or {}).keys()),
        })
    return pending


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("approve", help="mark a checkpoint approved")
    p1.add_argument("agent")
    p1.add_argument("step")
    p1.add_argument("--reviewer", default="manual")

    p2 = sub.add_parser("reject", help="mark a checkpoint rejected (rc=2 to caller)")
    p2.add_argument("agent")
    p2.add_argument("step")
    p2.add_argument("--reviewer", default="manual")
    p2.add_argument("--reason", required=True)

    p3 = sub.add_parser("list", help="list all checkpoint state files")

    p4 = sub.add_parser("show", help="show one checkpoint")
    p4.add_argument("agent")
    p4.add_argument("step")

    args = ap.parse_args()

    if args.cmd == "approve":
        result = cmd_approve(args.agent, args.step, args.reviewer)
        print(json.dumps(result, indent=2))
        print(f"APPROVED {args.agent} {args.step}")
    elif args.cmd == "reject":
        result = cmd_reject(args.agent, args.step, args.reviewer, args.reason)
        print(json.dumps(result, indent=2))
        print(f"REJECTED  {args.agent} {args.step}")
        sys.exit(2)
    elif args.cmd == "list":
        for entry in cmd_list():
            print(json.dumps(entry))
    elif args.cmd == "show":
        rec = _load(args.agent, args.step)
        if rec is None:
            sys.exit(f"no checkpoint at {HITL_DIR}/{args.agent}-{args.step}.json")
        print(json.dumps(rec, indent=2))


if __name__ == "__main__":
    main()
