#!/usr/bin/env python3
"""
intake_watcher.py — Watch /opt/samples/incoming/ and trigger v2 intake.

Does NOT pull from main CADRE VR/DFIR/Campaign — use manual drop or future opt-in bridge.

Usage:
  python3 intake_watcher.py --once
  python3 intake_watcher.py --daemon --interval 30
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

INCOMING = Path("/opt/samples/incoming/manual-drop")
STATE = Path("/opt/samples/staging/intake-watcher-state.json")
SKIP = {".gitkeep", "README.md"}


def load_state() -> dict:
    if STATE.is_file():
        return json.loads(STATE.read_text())
    return {"processed": []}


def save_state(state: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2))


def process_file(path: Path, family: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "/opt/scripts/intake_v2.py", str(path), "--project-name", family],
        capture_output=True,
        text=True,
        timeout=900,
    )
    return {
        "path": str(path),
        "family": family,
        "ok": proc.returncode == 0,
        "stdout_tail": (proc.stdout or "")[-500:],
        "stderr_tail": (proc.stderr or "")[-500:],
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def scan_once(state: dict) -> list[dict]:
    INCOMING.mkdir(parents=True, exist_ok=True)
    results = []
    for p in sorted(INCOMING.iterdir()):
        if not p.is_file() or p.name in SKIP:
            continue
        key = f"{p.name}:{p.stat().st_mtime_ns}"
        if key in state["processed"]:
            continue
        family = p.stem.split("_")[0] if "_" in p.stem else "incoming"
        results.append(process_file(p, family))
        state["processed"].append(key)
        if len(state["processed"]) > 500:
            state["processed"] = state["processed"][-200:]
    save_state(state)
    return results


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--daemon", action="store_true")
    ap.add_argument("--interval", type=int, default=60)
    args = ap.parse_args()

    state = load_state()
    if args.daemon:
        while True:
            r = scan_once(state)
            if r:
                print(json.dumps(r, indent=2))
            time.sleep(args.interval)
    else:
        r = scan_once(state)
        print(json.dumps(r, indent=2))
        print("INTAKE_WATCHER_OK")


if __name__ == "__main__":
    main()
