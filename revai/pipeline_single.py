#!/usr/bin/env python3
"""
pipeline_single.py — deterministic single-mode spine (no Flare).

  intake → quick_scan → deep_dive_agentic → yara → publish → section → audit

Prefer stage_orchestrator.py for LangGraph plan/act/observe + HITL.
This script remains the non-agent fallback (same artifacts).

Usage:
  python3 /opt/scripts/pipeline_single.py /path/to/sample.exe
  python3 /opt/scripts/pipeline_single.py --sha <sha256>
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
    case_dir,
    ensure_pipeline_runtime_env,
    load_session,
    revai_provenance,
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
    p = case_dir(sha) / "verdict.json"
    if not p.exists():
        return ""
    try:
        return str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        return ""


def _deep_verdict(sha: str) -> str:
    p = case_dir(sha) / "deep_dive" / "05-deep-dive.json"
    if not p.exists():
        return ""
    try:
        return str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        return ""


def run_single(sample: Path | None, sha: str | None, mode: str = "standard") -> dict:
    ensure_pipeline_runtime_env()
    # CLI default = scripted; an explicit REVAI_RUN_MODE from the caller wins
    # (mode-keyed storage contract — see v2_lib.case_dir).
    os.environ.setdefault("REVAI_RUN_MODE", "scripted")
    # Scripted spine is deterministic: zero retries everywhere (stage + tool
    # level). Explicit user env (REVAI_STAGE_RETRIES=..., REVAI_TOOL_RETRIES=...)
    # still wins.
    os.environ.setdefault("REVAI_STAGE_RETRIES", "0")
    os.environ.setdefault("REVAI_TOOL_RETRIES", "0")
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
            "--project-name", project[:64], "--mode", mode,
        ]
    else:
        assert sha
        sess = load_session(sha)
        sample_path = sess.get("sample_path")
        if not sample_path:
            raise SystemExit("session missing sample_path")
        sample = Path(sample_path)
        intake_cmd = None

    run_log = case_dir(sha) / "pipeline_single.log"
    trace_path = case_dir(sha) / "stage_trace.json"
    stages = []
    if intake_cmd:
        stages.append(("intake", intake_cmd, 7200))
    stages.extend([
        ("quick_scan", [sys.executable, str(SCRIPTS / "quick_scan_v2.py"), sha], 7200),
        ("deep_dive", [sys.executable, str(SCRIPTS / "deep_dive_agentic.py"), sha], 14400),
    ])
    # Optional v4 function-recovery stage (opt-in, between deep dive and yara).
    # Gated by REVAI_ENABLE_AGENTIC_RECOVERY=1 (legacy ENABLE_AGENTIC_RECOVERY
    # honored). Never required for green — recovery output feeds the reports.
    _rec_enabled = (
        os.environ.get("REVAI_ENABLE_AGENTIC_RECOVERY")
        or os.environ.get("ENABLE_AGENTIC_RECOVERY", "0")
    ).strip().lower() in ("1", "true", "yes")
    if _rec_enabled:
        stages.append((
            "function_recovery",
            [sys.executable, str(SCRIPTS / "agentic_recover_v4.py"), sha],
            3600,
        ))
    # Optional WinRE detonation stage (opt-in, between deep dive and publish).
    # Gated by REVAI_WINRE_RUN=1; the runner skips itself when WinRE is not
    # installed/configured (Console Settings -> Dynamic analysis (WinRE)).
    # A Flare-side failure is recorded and never blocks the static run.
    if os.environ.get("REVAI_WINRE_RUN", "").strip().lower() in ("1", "true", "yes"):
        stages.append((
            "winre_dynamic",
            [sys.executable, str(SCRIPTS / "winre_runner.py"), sha],
            7200,
        ))
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
        "with_dynamic": False,
        "provenance": revai_provenance(),
        "stages": [],
    }
    abort_on = {"intake", "quick_scan", "deep_dive"}
    t0 = time.time()
    for name, cmd, timeout in stages:
        if name.startswith("publish") and os.environ.get("REVAI_HITL_VERDICT", "").strip() in ("1", "true", "yes"):
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

        if name == "intake" and rc == 0:
            try:
                update_session(sha, {
                    "pipeline_mode": "single",
                    "pipeline_mode_source": "pipeline_single",
                    "pipeline_mode_reasons": ["v6.3_single_mode"],
                })
            except Exception as e:
                print(f"[pipeline_single] session update warn: {e}", flush=True)

        if rc != 0 and name in abort_on:
            print(f"[pipeline_single] ABORT remaining (failed={name})", flush=True)
            break

    try:
        if (SESSIONS_DIR / f"{sha}.json").exists():
            update_session(sha, {
                "pipeline_mode": "single",
                "pipeline_mode_source": "pipeline_single",
            })
    except Exception:
        pass

    trace["finished_at"] = _utc()
    trace["elapsed_s"] = round(time.time() - t0, 1)
    trace = finalize_trace(trace)
    case_dir(sha).mkdir(parents=True, exist_ok=True)
    trace_path.write_text(json.dumps(trace, indent=2, default=str))
    print(f"[pipeline_single] trace -> {trace_path} all_green={trace['all_green']}", flush=True)
    return trace


def finalize_trace(trace: dict, audit_path: Path | None = None) -> dict:
    """Set all_green/stage_ok from THIS run's audit stage only.

    Never trust artifacts left by a previous run: a run that aborts before its
    audit stage must be reported red even when a stale pipeline-audit.json
    exists on disk (rehearsal 2026-09-22: an aborted run reported
    all_green=True and exited 0 while reading the previous run's audit).
    """
    audit_entry = next(
        (s for s in trace.get("stages", []) if s.get("stage") == "audit"), None
    )
    audit_ok = audit_entry is not None and audit_entry.get("ok")
    audit: dict = {}
    if audit_ok:
        if audit_path is None:
            sha = trace.get("sha256") or ""
            audit_path = case_dir(sha) / "pipeline-audit.json"
        try:
            if audit_path.exists():
                audit = json.loads(audit_path.read_text())
        except Exception:
            audit = {}
    if audit_ok and audit:
        trace["all_green"] = bool(audit.get("all_green"))
        trace["stage_ok"] = audit.get("stage_ok")
        return trace
    trace["all_green"] = False
    trace["stage_ok"] = {
        s.get("stage"): bool(s.get("ok")) for s in trace.get("stages", [])
    }
    if audit_entry is None:
        failed = [
            s.get("stage") for s in trace.get("stages", []) if not s.get("ok")
        ]
        trace["aborted"] = True
        trace["aborted_reason"] = (
            f"stage failed: {failed[0]}" if failed else "audit stage did not run"
        )
    else:
        trace["aborted"] = True
        trace["aborted_reason"] = f"audit stage rc={audit_entry.get('rc')}"
    return trace


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sample", nargs="?", help="path to sample")
    ap.add_argument("--sha", default=None)
    ap.add_argument("--mode", default="standard",
                    help="intake mode: standard (auto-analysis) or large (import-only); default standard")
    args = ap.parse_args()
    sample = Path(args.sample) if args.sample else None
    trace = run_single(sample, args.sha, mode=args.mode)
    return 0 if trace.get("all_green") else 1


if __name__ == "__main__":
    raise SystemExit(main())
