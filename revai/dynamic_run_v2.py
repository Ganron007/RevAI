#!/usr/bin/env python3
"""
dynamic_run_v2.py — V6.2 optional Flare-VM detonation stage (Remnux orchestrator).

Copies the sample to Flare (.42), runs Frida API trace (V1.9 script), pulls
artifacts into logs/<sha>/dynamic/. Remnux never executes the PE.

Usage:
  python3 /opt/scripts/dynamic_run_v2.py <sha256>
  python3 /opt/scripts/dynamic_run_v2.py <sha256> --max-seconds 45 --dry-run

Env:
  FLARE_HOST       default 192.168.77.42
  FLARE_USER       default FLARE-VM
  FLARE_SSH_KEY    default /home/remnux/.ssh/cadre-77.42-key (or host path)
  FLARE_SSH_PORT   default 22
  REVENG_DYNAMIC_SKIP=1  → write META skip and exit 0
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
try:
    from v2_lib import LOGS_DIR, SESSIONS_DIR, load_session, high_signal_yara_matches
except Exception:  # local/dev fallback
    LOGS_DIR = Path(os.environ.get("REVENG_LOGS_DIR", "/opt/samples/logs"))
    SESSIONS_DIR = Path(os.environ.get("REVENG_SESSIONS_DIR", "/opt/samples/sessions"))

    def load_session(sha: str) -> dict:
        return json.loads((SESSIONS_DIR / f"{sha}.json").read_text())

    def high_signal_yara_matches(yara: dict | None) -> list:
        return []


DEFAULT_APIS = (
    "CreateFileW,WriteFile,ReadFile,DeleteFileW,"
    "RegOpenKeyExW,RegSetValueExW,"
    "VirtualAlloc,VirtualProtect,WriteProcessMemory,CreateRemoteThread,"
    "WinHttpOpen,InternetOpenW,connect,send,recv,"
    "LoadLibraryW,GetProcAddress,CreateProcessW"
)

SCHEMA_VERSION = "v6.2.1"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _flare_cfg() -> dict:
    return {
        "host": os.environ.get("FLARE_HOST", "192.168.77.42"),
        "user": os.environ.get("FLARE_USER", "FLARE-VM"),
        "key": os.environ.get(
            "FLARE_SSH_KEY",
            str(Path.home() / ".ssh" / "cadre-77.42-key"),
        ),
        "port": int(os.environ.get("FLARE_SSH_PORT", "22")),
        "remote_root": os.environ.get("FLARE_SAMPLES_ROOT", r"C:\samples"),
        "frida_script": os.environ.get(
            "FLARE_FRIDA_SCRIPT",
            r"C:\tools\flarevm-deploy\dynamic\frida_api_trace.py",
        ),
        "python": os.environ.get("FLARE_PYTHON", "python"),
    }


def _ssh_base(cfg: dict) -> list[str]:
    return [
        "ssh",
        "-i", cfg["key"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-o", "BatchMode=yes",
        "-p", str(cfg["port"]),
        f"{cfg['user']}@{cfg['host']}",
    ]


def _scp_to(cfg: dict, local: Path, remote: str) -> None:
    cmd = [
        "scp",
        "-i", cfg["key"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-P", str(cfg["port"]),
        str(local),
        f"{cfg['user']}@{cfg['host']}:{remote}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"scp to flare failed: {r.stderr[:400]}")


def _scp_from(cfg: dict, remote: str, local: Path) -> None:
    cmd = [
        "scp",
        "-i", cfg["key"],
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-P", str(cfg["port"]),
        f"{cfg['user']}@{cfg['host']}:{remote}",
        str(local),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"scp from flare failed: {r.stderr[:400]}")


def _ssh_run(cfg: dict, remote_cmd: str, timeout: int = 300) -> subprocess.CompletedProcess:
    cmd = _ssh_base(cfg) + [remote_cmd]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _yara_lock(sha: str) -> dict:
    """V6.2.6 — dynamic must not clear high-signal YARA."""
    out = {"high_signal": [], "policy": "sandbox_cannot_clear_high_signal_yara"}
    for path in (
        LOGS_DIR / sha / "quick_scan" / "00-tools-raw.json",
        LOGS_DIR / sha / "verdict.json",
        LOGS_DIR / sha / "deep_dive" / "01-tools-raw.json",
    ):
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        yara = data.get("yara") if isinstance(data, dict) else None
        if not yara and isinstance(data, dict) and "matches" in data:
            yara = data
        hits = high_signal_yara_matches(yara if isinstance(yara, dict) else {})
        if hits:
            out["high_signal"] = hits
            break
        # verdict may store yara_family_hits
        if isinstance(data, dict) and data.get("yara_family_hits"):
            out["high_signal"] = list(data.get("yara_family_hits") or [])
            break
    return out


def _write_meta(dyn_dir: Path, meta: dict) -> None:
    dyn_dir.mkdir(parents=True, exist_ok=True)
    (dyn_dir / "META.json").write_text(json.dumps(meta, indent=2, default=str))
    (dyn_dir / "SCHEMA.md").write_text(
        "# Dynamic evidence schema (V6.2)\n\n"
        "- `META.json` — run status, host, timings, yara_lock\n"
        "- `frida_trace.json` — JSONL API calls from Flare Frida\n"
        "- `network.json` — optional sink summary (stub until FakeNet wired)\n"
        "- `procmon.csv` — optional (when headless procmon available)\n"
    )


def run_dynamic(sha: str, *, max_seconds: int = 60, dry_run: bool = False, apis: str | None = None) -> dict:
    cfg = _flare_cfg()
    dyn_dir = LOGS_DIR / sha / "dynamic"
    dyn_dir.mkdir(parents=True, exist_ok=True)
    yara_lock = _yara_lock(sha)

    meta = {
        "schema_version": SCHEMA_VERSION,
        "sha256": sha,
        "started_at": _utc(),
        "flare_host": cfg["host"],
        "ok": False,
        "skipped": False,
        "error": None,
        "yara_lock": yara_lock,
        "artifacts": {},
    }

    if str(os.environ.get("REVENG_DYNAMIC_SKIP") or "").strip().lower() in ("1", "true", "yes", "on"):
        meta["skipped"] = True
        meta["ok"] = True
        meta["error"] = "REVENG_DYNAMIC_SKIP=1"
        meta["finished_at"] = _utc()
        _write_meta(dyn_dir, meta)
        print(f"[dynamic_run_v2] skipped REVENG_DYNAMIC_SKIP -> {dyn_dir}", flush=True)
        return meta

    try:
        session = load_session(sha)
    except Exception as e:
        meta["error"] = f"session load failed: {e}"
        meta["finished_at"] = _utc()
        _write_meta(dyn_dir, meta)
        return meta

    sample = session.get("sample_path") or ""
    if not sample or not Path(sample).is_file():
        meta["error"] = f"sample missing: {sample!r}"
        meta["finished_at"] = _utc()
        _write_meta(dyn_dir, meta)
        return meta

    # Forward slashes for OpenSSH scp. Never rf"...\frida..." — \f is form-feed.
    root = str(cfg["remote_root"]).replace("\\", "/").rstrip("/")
    remote_dir = f"{root}/{sha}"
    remote_sample = f"{remote_dir}/sample.exe"
    remote_trace = f"{remote_dir}/frida_trace.jsonl"
    remote_dir_win = remote_dir.replace("/", "\\")
    api_list = apis or DEFAULT_APIS

    if dry_run:
        meta["ok"] = True
        meta["skipped"] = True
        meta["error"] = "dry_run"
        meta["plan"] = {
            "sample": sample,
            "remote_sample": remote_sample,
            "apis": api_list,
            "max_seconds": max_seconds,
        }
        meta["finished_at"] = _utc()
        _write_meta(dyn_dir, meta)
        # still emit network stub for schema completeness
        (dyn_dir / "network.json").write_text(json.dumps({
            "status": "not_collected",
            "reason": "dry_run / FakeNet deferred",
        }, indent=2))
        print(f"[dynamic_run_v2] dry_run ok -> {dyn_dir}", flush=True)
        return meta

    t0 = time.time()
    try:
        if not Path(cfg["key"]).is_file():
            raise FileNotFoundError(f"FLARE_SSH_KEY not found: {cfg['key']}")

        # Probe SSH
        probe = _ssh_run(cfg, "echo FLARE_OK", timeout=30)
        if probe.returncode != 0 or "FLARE_OK" not in (probe.stdout or ""):
            raise RuntimeError(f"flare ssh probe failed: {probe.stderr[:300]}")

        # Best-effort cleanup (prior hung Frida/malware)
        _ssh_run(
            cfg,
            'taskkill /F /IM sample.exe /T 2>nul & '
            'taskkill /F /IM frida-helper-64.exe /T 2>nul & exit /b 0',
            timeout=30,
        )

        _ssh_run(cfg, f'cmd /c "if not exist {remote_dir_win} mkdir {remote_dir_win}"', timeout=60)
        print(f"[dynamic_run_v2] scp sample -> {remote_sample}", flush=True)
        _scp_to(cfg, Path(sample), remote_sample)

        # Frida detonation. Local SSH timeout = max_seconds + watchdog slack.
        frida_cmd = (
            f'{cfg["python"]} "{cfg["frida_script"]}" '
            f'--target "{remote_sample}" '
            f'--apis "{api_list}" '
            f'--out "{remote_trace}" '
            f'--max-seconds {int(max_seconds)} '
            f'--max-calls 5000'
        )
        print(f"[dynamic_run_v2] frida max_seconds={max_seconds}", flush=True)
        ssh_budget = int(max_seconds) + 30
        try:
            fr = _ssh_run(cfg, frida_cmd, timeout=ssh_budget)
        except subprocess.TimeoutExpired as te:
            meta["frida_timeout"] = True
            meta["frida_rc"] = -1
            meta["frida_stderr_tail"] = f"ssh timeout after {ssh_budget}s: {te}"
            fr = subprocess.CompletedProcess(args=[], returncode=-1, stdout="", stderr=str(te))
            _ssh_run(
                cfg,
                'taskkill /F /IM sample.exe /T 2>nul & '
                'taskkill /F /IM python.exe /FI "WINDOWTITLE eq *frida*" /T 2>nul & '
                'taskkill /F /IM frida-helper-64.exe /T 2>nul & exit /b 0',
                timeout=30,
            )
        meta["frida_rc"] = fr.returncode
        meta["frida_stdout_tail"] = (fr.stdout or "")[-500:]
        meta["frida_stderr_tail"] = (fr.stderr or "")[-500:]

        local_trace = dyn_dir / "frida_trace.json"
        try:
            _scp_from(cfg, remote_trace, local_trace)
            meta["artifacts"]["frida_trace.json"] = str(local_trace)
            # count lines
            n = sum(1 for _ in local_trace.open("r", encoding="utf-8", errors="replace"))
            meta["frida_events"] = n
        except Exception as e:
            meta["frida_pull_error"] = str(e)
            # write empty placeholder so schema exists
            local_trace.write_text("")
            meta["artifacts"]["frida_trace.json"] = str(local_trace)
            meta["frida_events"] = 0

        (dyn_dir / "network.json").write_text(json.dumps({
            "status": "not_collected",
            "reason": "FakeNet/INetSim sink deferred (V6.2.4 stub)",
            "policy": "lab_sink_only_no_open_internet",
        }, indent=2))
        meta["artifacts"]["network.json"] = str(dyn_dir / "network.json")

        # Accuracy: never let dynamic flip high-signal YARA off
        meta["verdict_policy"] = {
            "static_yara_wins": True,
            "high_signal_yara": yara_lock.get("high_signal") or [],
            "note": "Dynamic corroboration only; cannot clear CADRE_*/family YARA",
        }
        meta["ok"] = True
        meta["elapsed_s"] = round(time.time() - t0, 1)
    except Exception as e:
        meta["error"] = str(e)
        meta["ok"] = False
        meta["elapsed_s"] = round(time.time() - t0, 1)
        (dyn_dir / "network.json").write_text(json.dumps({
            "status": "not_collected",
            "reason": f"run_failed:{e}",
        }, indent=2))

    meta["finished_at"] = _utc()
    _write_meta(dyn_dir, meta)
    print(
        f"[dynamic_run_v2] ok={meta['ok']} events={meta.get('frida_events')} "
        f"err={meta.get('error')} -> {dyn_dir}",
        flush=True,
    )
    return meta


def main() -> int:
    ap = argparse.ArgumentParser(description="V6.2 Flare dynamic detonation (Remnux orchestrator)")
    ap.add_argument("sha256")
    ap.add_argument("--max-seconds", type=int, default=60)
    ap.add_argument("--apis", default=None, help="comma-separated API list override")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    meta = run_dynamic(
        args.sha256.strip().lower(),
        max_seconds=args.max_seconds,
        dry_run=args.dry_run,
        apis=args.apis,
    )
    # soft-fail: pipeline can continue; audit records dynamic presence
    if meta.get("skipped") or meta.get("ok"):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
