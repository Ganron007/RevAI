#!/usr/bin/env python3
"""
pipeline_single_v63.py — V6.3 Single-mode agentic RE pipeline.

One mode for all sample sizes:
  intake → quick_scan → deep_dive_agentic → [optional dynamic] → yara → publish → section → audit

Goal/state-aware enough for V6.3 MVP:
  - Deterministic stage order with abort-on-fail for early stages
  - Always agentic deep dive (no size-based standard/large deep fork)
  - Writes pipeline_mode=single + replayable stage_trace.json
  - Optional HITL pause via REVENG_HITL_VERDICT=1 (stops before publish if quick≠deep)

Usage:
  python3 /opt/scripts/pipeline_single_v63.py /path/to/sample.exe
  python3 /opt/scripts/pipeline_single_v63.py --sha <sha256>   # resume from session
  REVENG_DYNAMIC=1 python3 /opt/scripts/pipeline_single_v63.py /path/to/sample.exe
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    LOGS_DIR,
    SESSIONS_DIR,
    ensure_pipeline_runtime_env,
    load_session,
    update_session,
)

SCRIPTS = Path("/opt/scripts")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha_of(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(cmd: list[str], log_path: Path, timeout: int) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[pipeline_single] exec: {' '.join(cmd)}", flush=True)
    with log_path.open("a", encoding="utf-8") as lf:
        lf.write(f"\n===== {_utc()} CMD {' '.join(cmd)}\n")
        lf.flush()
        try:
            p = subprocess.run(
                cmd,
                stdout=lf,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                env=os.environ.copy(),
            )
            lf.write(f"===== rc={p.returncode}\n")
            return int(p.returncode)
        except subprocess.TimeoutExpired:
            lf.write("===== TIMEOUT\n")
            return 124


def _quick_verdict(sha: str) -> str:
    p = LOGS_DIR / sha / "verdict.json"
    if not p.exists():
        return ""
    try:
        return str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        return ""


def _deep_verdict(sha: str) -> str:
    p = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    if not p.exists():
        return ""
    try:
        return str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        return ""


def run_single(sample: Path | None, sha: str | None, *, with_dynamic: bool) -> dict:
    ensure_pipeline_runtime_env()
    if sample is None and not sha:
        raise SystemExit("need sample path or --sha")

    if sample is not None:
        sample = sample.resolve()
        if not sample.is_file():
            raise SystemExit(f"sample not found: {sample}")
        sha = _sha_of(sample)
        project = sample.parent.parent.name if sample.parent.parent else "single"
        intake_cmd = [
            sys.executable, str(SCRIPTS / "intake_v2.py"), str(sample),
            "--project-name", project[:64], "--mode", "large",
        ]
    else:
        assert sha
        sess = load_session(sha)
        sample_path = sess.get("sample_path")
        if not sample_path:
            raise SystemExit("session missing sample_path")
        sample = Path(sample_path)
        intake_cmd = None  # already intaken

    # Mark single mode in session after intake (or now if resume)
    run_log = LOGS_DIR / sha / "pipeline_single.log"
    trace_path = LOGS_DIR / sha / "stage_trace.json"
    stages = []
    if intake_cmd:
        stages.append(("intake", intake_cmd, 7200))
    stages.extend([
        ("quick_scan", [sys.executable, str(SCRIPTS / "quick_scan_v2.py"), sha], 7200),
        ("deep_dive", [sys.executable, str(SCRIPTS / "deep_dive_agentic.py"), sha], 14400),
    ])
    if with_dynamic and (SCRIPTS / "dynamic_run_v2.py").exists():
        stages.append(
            ("dynamic", [sys.executable, str(SCRIPTS / "dynamic_run_v2.py"), sha, "--max-seconds", "45"], 900)
        )
    stages.extend([
        ("yara_gen", [sys.executable, str(SCRIPTS / "yara_gen_v2.py"), sha], 1800),
        ("publish_v2", [sys.executable, str(SCRIPTS / "publish_report_v2.py"), sha, "--template", "full"], 3600),
        ("publish_v3", [sys.executable, str(SCRIPTS / "section_publisher.py"), sha], 3600),
        ("audit", [sys.executable, str(SCRIPTS / "audit_pipeline.py"), sha, "--mode", "single"], 600),
    ])

    trace = {
        "schema": "v6.3.single",
        "sha256": sha,
        "started_at": _utc(),
        "pipeline_mode": "single",
        "with_dynamic": with_dynamic,
        "stages": [],
    }
    abort_on = {"intake", "quick_scan", "deep_dive"}
    t0 = time.time()
    for name, cmd, timeout in stages:
        # HITL gate before publish
        if name.startswith("publish") and os.environ.get("REVENG_HITL_VERDICT", "").strip() in ("1", "true", "yes"):
            qv, dv = _quick_verdict(sha), _deep_verdict(sha)
            if qv and dv and qv != dv:
                entry = {
                    "stage": name,
                    "ok": False,
                    "skipped": True,
                    "reason": f"HITL: quick_verdict={qv} deep_verdict={dv}",
                    "ts": _utc(),
                }
                trace["stages"].append(entry)
                trace["hitl_stop"] = entry
                print(f"[pipeline_single] HITL stop before {name}: {entry['reason']}", flush=True)
                break

        st = time.time()
        rc = _run(cmd, run_log, timeout)
        entry = {
            "stage": name,
            "cmd": cmd,
            "rc": rc,
            "ok": rc == 0,
            "elapsed_s": round(time.time() - st, 1),
            "ts": _utc(),
        }
        trace["stages"].append(entry)
        print(f"[pipeline_single] {name} rc={rc} {entry['elapsed_s']}s", flush=True)

        # After intake, stamp single mode
        if name == "intake" and rc == 0:
            try:
                update_session(sha, {
                    "pipeline_mode": "single",
                    "pipeline_mode_source": "pipeline_single_v63",
                    "pipeline_mode_reasons": ["v6.3_single_mode"],
                })
            except Exception as e:
                print(f"[pipeline_single] session update warn: {e}", flush=True)

        if rc != 0 and name in abort_on:
            print(f"[pipeline_single] ABORT remaining (failed={name})", flush=True)
            break

    # Resume path: ensure session mode stamped
    try:
        if (SESSIONS_DIR / f"{sha}.json").exists():
            update_session(sha, {
                "pipeline_mode": "single",
                "pipeline_mode_source": "pipeline_single_v63",
            })
    except Exception:
        pass

    trace["finished_at"] = _utc()
    trace["elapsed_s"] = round(time.time() - t0, 1)
    audit = {}
    aj = LOGS_DIR / sha / "pipeline-audit.json"
    if aj.exists():
        try:
            audit = json.loads(aj.read_text())
        except Exception:
            pass
    trace["all_green"] = bool(audit.get("all_green"))
    trace["stage_ok"] = audit.get("stage_ok")
    (LOGS_DIR / sha).mkdir(parents=True, exist_ok=True)
    trace_path.write_text(json.dumps(trace, indent=2, default=str))
    print(f"[pipeline_single] trace -> {trace_path} all_green={trace['all_green']}", flush=True)
    return trace


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sample", nargs="?", help="path to sample")
    ap.add_argument("--sha", default=None)
    ap.add_argument("--dynamic", action="store_true", help="run Flare dynamic stage")
    ap.add_argument("--no-dynamic", action="store_true")
    args = ap.parse_args()
    with_dyn = bool(args.dynamic or os.environ.get("REVENG_DYNAMIC", "").strip() in ("1", "true", "yes"))
    if args.no_dynamic:
        with_dyn = False
    sample = Path(args.sample) if args.sample else None
    trace = run_single(sample, args.sha, with_dynamic=with_dyn)
    return 0 if trace.get("all_green") else 1


if __name__ == "__main__":
    raise SystemExit(main())
