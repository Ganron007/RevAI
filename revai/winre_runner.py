#!/usr/bin/env python3
"""winre_runner.py — optional WinRE (FlareVM) dynamic detonation driver for RevAI.

RevAI is static-first. This module runs ONLY when the operator opts in (the
Console's "Dynamic analysis (WinRE)" panel / `REVAI_WINRE_ENABLED=1`) and WinRE
is installed at ``/opt/winre`` (see docs/WINRE-REMOTE.md). It builds the WinRE
remote-driver command, exports the FlareVM settings WinRE reads (`FLARE_*`),
streams the run to a log, then verifies the detonation pack so publish can
attach the presence-gated dynamic-corroboration block.

Settings resolution — non-secret values live in the Console config
(``/opt/samples/pipeline-config.json``) and are overridable by env / CLI:

  winre_enabled        REVAI_WINRE_ENABLED        0         master switch
  flare_host           FLARE_HOST                 ""        FlareVM IP/host
  flare_user           FLARE_USER                 FLARE-VM
  flare_ssh_port       FLARE_SSH_PORT             22
  flare_ssh_key        FLARE_SSH_KEY              ~/.ssh/winre-flare (path only)
  winre_logs           REVAI_WINRE_LOGS           /opt/winre/logs
  winre_mode           REVAI_WINRE_MODE           agentic   static|agentic
  winre_window         REVAI_WINRE_WINDOW         150       --max-seconds
  winre_adaptive       REVAI_WINRE_ADAPTIVE       1         --adaptive
  winre_pesieve        REVAI_WINRE_PESIEVE        1         --pesieve
  winre_agentic_dbg    REVAI_WINRE_AGENTIC_DBG    0         --agentic-dbg
  winre_snapshot_gate  REVAI_WINRE_SNAPSHOT_GATE  observe   observe|enforce|off
                       REVAI_WINRE_ROOT           /opt/winre
                       REVAI_WINRE_PY             <root>/venv/bin/python
                       REVAI_WINRE_TIMEOUT        3600      subprocess seconds

Every failure is recorded (``winre-run.json``), never raised into the pipeline:
a missing FlareVM or key leaves the static run untouched — reports stay
presence-gated and byte-identical to a WinRE-less install.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(os.environ.get("REVAI_PIPELINE_CONFIG", "/opt/samples/pipeline-config.json"))
DEFAULT_ROOT = Path("/opt/winre")
DEFAULT_LOGS = Path("/opt/winre/logs")

# Config JSON keys (non-secret; the Console Settings panel writes these).
_CONFIG_KEYS = {
    "enabled": "winre_enabled",
    "flare_host": "flare_host",
    "flare_user": "flare_user",
    "flare_ssh_port": "flare_ssh_port",
    "flare_ssh_key": "flare_ssh_key",
    "logs_root": "winre_logs",
    "mode": "winre_mode",
    "window": "winre_window",
    "adaptive": "winre_adaptive",
    "pesieve": "winre_pesieve",
    "agentic_dbg": "winre_agentic_dbg",
    "snapshot_gate": "winre_snapshot_gate",
    "timeout": "winre_timeout",
}

# Environment overrides (CLI / per-run).
_ENV_KEYS = {
    "enabled": "REVAI_WINRE_ENABLED",
    "flare_host": "FLARE_HOST",
    "flare_user": "FLARE_USER",
    "flare_ssh_port": "FLARE_SSH_PORT",
    "flare_ssh_key": "FLARE_SSH_KEY",
    "logs_root": "REVAI_WINRE_LOGS",
    "mode": "REVAI_WINRE_MODE",
    "window": "REVAI_WINRE_WINDOW",
    "adaptive": "REVAI_WINRE_ADAPTIVE",
    "pesieve": "REVAI_WINRE_PESIEVE",
    "agentic_dbg": "REVAI_WINRE_AGENTIC_DBG",
    "snapshot_gate": "REVAI_WINRE_SNAPSHOT_GATE",
    "timeout": "REVAI_WINRE_TIMEOUT",
}

_BOOL_TRUE = ("1", "true", "yes", "on")
_BOOL_FALSE = ("0", "false", "no", "off")


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value if value is not None else "").strip().lower()
    if s in _BOOL_TRUE:
        return True
    if s in _BOOL_FALSE:
        return False
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def settings() -> dict:
    """Resolved WinRE settings: Console config < environment."""
    cfg = _load_config()

    def pick(name: str, default: Any) -> Any:
        env = os.environ.get(_ENV_KEYS[name])
        if env is not None and str(env).strip() != "":
            return env
        val = cfg.get(_CONFIG_KEYS[name])
        if val is None or (isinstance(val, str) and not val.strip()):
            return default
        return val

    root = Path(str(os.environ.get("REVAI_WINRE_ROOT") or DEFAULT_ROOT))
    py = Path(str(os.environ.get("REVAI_WINRE_PY") or (root / "venv" / "bin" / "python")))
    key = str(pick("flare_ssh_key", "~/.ssh/winre-flare"))
    return {
        "enabled": _as_bool(pick("enabled", "0")),
        "flare_host": str(pick("flare_host", "")).strip(),
        "flare_user": str(pick("flare_user", "FLARE-VM")).strip() or "FLARE-VM",
        "flare_ssh_port": _as_int(pick("flare_ssh_port", 22), 22),
        "flare_ssh_key": str(Path(key).expanduser()),
        "root": root,
        "python": py,
        "logs_root": Path(str(pick("logs_root", str(DEFAULT_LOGS)))),
        "mode": (str(pick("mode", "agentic")).strip().lower() or "agentic"),
        "window": _as_int(pick("window", 150), 150),
        "adaptive": _as_bool(pick("adaptive", "1"), True),
        "pesieve": _as_bool(pick("pesieve", "1"), True),
        "agentic_dbg": _as_bool(pick("agentic_dbg", "0"), False),
        "snapshot_gate": (str(pick("snapshot_gate", "observe")).strip().lower() or "observe"),
        "timeout": _as_int(pick("timeout", 3600), 3600),
    }


def availability(s: dict | None = None) -> tuple[bool, str]:
    """(ok, reason) — can a detonation be started right now?"""
    cfg = s or settings()
    if not cfg["enabled"]:
        return False, "winre_disabled: enable Dynamic analysis (WinRE) in Settings or set REVAI_WINRE_ENABLED=1"
    if not Path(cfg["root"]).is_dir():
        return False, f"winre_not_installed: {cfg['root']} missing (optional setup step, see docs/WINRE-REMOTE.md)"
    if not (Path(cfg["root"]) / "winre" / "pipeline.py").is_file():
        return False, f"winre_package_missing: {cfg['root']}/winre/pipeline.py not found"
    if not Path(cfg["python"]).is_file():
        return False, f"winre_venv_missing: {cfg['python']} not found (python3 -m venv {cfg['root']}/venv)"
    if not cfg["flare_host"]:
        return False, "flare_host_unset: set the FlareVM address in Settings or FLARE_HOST"
    if not Path(cfg["flare_ssh_key"]).is_file():
        return False, f"flare_key_missing: {cfg['flare_ssh_key']} not found (path only; key stays on disk)"
    if cfg["mode"] not in ("agentic", "static"):
        return False, f"winre_mode_invalid: {cfg['mode']}"
    if cfg["snapshot_gate"] not in ("observe", "enforce", "off"):
        return False, f"winre_snapshot_gate_invalid: {cfg['snapshot_gate']}"
    return True, "ok"


def _ssh_base(cfg: dict) -> list[str]:
    return [
        "ssh", "-i", cfg["flare_ssh_key"], "-p", str(cfg["flare_ssh_port"]),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=6",
        f"{cfg['flare_user']}@{cfg['flare_host']}",
    ]


def probe(timeout: int = 15, s: dict | None = None) -> dict:
    """Test the FlareVM connection (no detonation). Used by the Console button."""
    cfg = s or settings()
    out: dict[str, Any] = {
        "ok": False,
        "host": cfg["flare_host"],
        "user": cfg["flare_user"],
        "port": cfg["flare_ssh_port"],
        "key": cfg["flare_ssh_key"],
        "root": str(cfg["root"]),
        "logs_root": str(cfg["logs_root"]),
        "enabled": cfg["enabled"],
    }
    if not cfg["flare_host"]:
        out["error"] = "flare_host_unset"
        return out
    if not Path(cfg["flare_ssh_key"]).is_file():
        out["error"] = f"flare_key_missing: {cfg['flare_ssh_key']}"
        return out
    try:
        r = subprocess.run(
            _ssh_base(cfg) + ["echo WINRE_SSH_OK"],
            capture_output=True, text=True, timeout=timeout,
        )
        detail = (r.stdout or "").strip() or (r.stderr or "").strip()
        out["ssh_ok"] = r.returncode == 0 and "WINRE_SSH_OK" in (r.stdout or "")
        out["detail"] = detail[:400]
        out["rc"] = r.returncode
        if not out["ssh_ok"]:
            out["error"] = f"ssh_failed: rc={r.returncode} {detail[:200]}"
        else:
            out["ok"] = True
    except Exception as e:
        out["error"] = f"ssh_error: {type(e).__name__}: {e}"
    return out


def build_command(sample_path: str | Path, cfg: dict) -> list[str]:
    """The WinRE CLI invocation (remote driver) for this configuration."""
    cmd = [
        str(cfg["python"]), "-m", "winre.pipeline", str(sample_path),
        "--driver", "remote",
        "--mode", cfg["mode"],
        "--dynamic",
        "--max-seconds", str(cfg["window"]),
    ]
    if cfg["adaptive"]:
        cmd.append("--adaptive")
    if cfg["pesieve"]:
        cmd.append("--pesieve")
    if cfg["agentic_dbg"]:
        cmd.append("--agentic-dbg")
    return cmd


def _child_env(cfg: dict) -> dict:
    env = os.environ.copy()
    # WinRE's envfile.py gives process env precedence over /opt/winre/.env.
    env["FLARE_HOST"] = cfg["flare_host"]
    env["FLARE_USER"] = cfg["flare_user"]
    env["FLARE_SSH_PORT"] = str(cfg["flare_ssh_port"])
    env["FLARE_SSH_KEY"] = cfg["flare_ssh_key"]
    env["WINRE_SNAPSHOT_GATE"] = cfg["snapshot_gate"]
    # Keep WinRE's evidence root in sync with the root RevAI reads packs from
    # (default /opt/winre/logs); a Console override must land where we look.
    env["WINRE_PIPELINE_LOGS"] = str(cfg["logs_root"])
    return env


def _case_dir(sha: str) -> Path:
    try:
        from v2_lib import case_dir  # flat runtime / repo sibling

        return case_dir(sha)
    except Exception:
        return Path("/opt/samples/logs") / sha


def run_status_path(sha: str) -> Path:
    return _case_dir(sha) / "winre-run.json"


def read_run_status(sha: str) -> dict | None:
    p = run_status_path(sha)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_status(sha: str, payload: dict) -> None:
    p = run_status_path(sha)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass


def sample_path_for(sha: str) -> str | None:
    try:
        from v2_lib import load_session

        sp = (load_session(sha) or {}).get("sample_path")
        return str(sp) if sp else None
    except Exception:
        return None


def summarize_pack(sha: str, logs_root: Path | str) -> dict:
    """What the pack for this case contributes (counts mirror the report block).

    Uses v2_lib's shared counter so winre-run.json, the Console chip and the
    published corroboration block can never disagree. Fail-open.
    """
    try:
        from v2_lib import dynamic_pack_counts, load_dynamic_pack

        pack = load_dynamic_pack(sha, winre_root=Path(logs_root))
        if not pack:
            return {"pack_present": False, "pack": {}}
        counts = dynamic_pack_counts(pack)
        return {
            "pack_present": True,
            "pack": {
                "window": pack.get("window"),
                "dns": counts["dns"],
                "http": counts["http"],
                "sni": counts["sni"],
                "dropped": counts["dropped"],
                "dumps": counts["dumps"],
                "unpack_artifact": counts["unpack_artifact"],
            },
        }
    except Exception as e:
        return {"pack_present": False, "pack": {"pack_error": f"{type(e).__name__}: {e}"}}


def run_dynamic(
    sha: str,
    *,
    sample_path: str | None = None,
    s: dict | None = None,
    timeout: int | None = None,
    force: bool = False,
) -> dict:
    """Run the WinRE remote detonation. Soft-fails with a recorded reason."""
    cfg = s or settings()
    ok, reason = availability(cfg)
    if not ok and not force:
        payload = {
            "state": "skipped",
            "reason": reason,
            "host": cfg["flare_host"],
            "mode": cfg["mode"],
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        _write_status(sha, payload)
        print(f"[winre_runner] skipped: {reason}", flush=True)
        return {"ok": True, "skipped": True, "reason": reason, **payload}

    sp = sample_path or sample_path_for(sha)
    if not sp or not Path(sp).is_file():
        payload = {
            "state": "failed",
            "error": f"sample_missing: {sp}",
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        _write_status(sha, payload)
        print(f"[winre_runner] failed: {payload['error']}", flush=True)
        return {"ok": False, "error": payload["error"], **payload}

    cmd = build_command(sp, cfg)
    case = _case_dir(sha)
    log_path = case / "winre-run.log"
    limit = int(timeout or cfg["timeout"])
    started = datetime.now(timezone.utc)
    _write_status(sha, {
        "state": "running",
        "host": cfg["flare_host"],
        "user": cfg["flare_user"],
        "key": cfg["flare_ssh_key"],
        "mode": cfg["mode"],
        "window": cfg["window"],
        "adaptive": cfg["adaptive"],
        "agentic_dbg": cfg["agentic_dbg"],
        "started_at": started.isoformat(),
        "log": str(log_path),
        "sample": sp,
    })
    print(f"[winre_runner] detonation -> {' '.join(cmd)}", flush=True)
    t0 = time.time()
    rc: int | None = None
    error = ""
    try:
        case.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as lf:
            lf.write(f"\n===== {started.isoformat()} CMD {' '.join(cmd)}\n")
            lf.flush()
            p = subprocess.run(
                cmd, cwd=str(cfg["root"]), env=_child_env(cfg),
                stdout=lf, stderr=subprocess.STDOUT, timeout=limit,
            )
            rc = int(p.returncode)
            lf.write(f"===== rc={rc}\n")
        if rc != 0:
            error = f"winre_rc={rc} (see {log_path})"
    except subprocess.TimeoutExpired:
        rc = 124
        error = f"winre_timeout after {limit}s (see {log_path})"
    except Exception as e:
        rc = -1
        error = f"winre_error: {type(e).__name__}: {e}"

    duration = round(time.time() - t0, 1)
    summary = summarize_pack(sha, cfg["logs_root"])
    pack_present = bool(summary["pack_present"])
    pack_info: dict[str, Any] = summary["pack"] or {}

    payload = {
        "state": "ok" if rc == 0 and pack_present else ("ok_no_pack" if rc == 0 else "failed"),
        "rc": rc,
        "duration_s": duration,
        "host": cfg["flare_host"],
        "mode": cfg["mode"],
        "window": cfg["window"],
        "adaptive": cfg["adaptive"],
        "agentic_dbg": cfg["agentic_dbg"],
        "log": str(log_path),
        "pack_present": pack_present,
        "pack": pack_info,
        "error": error,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_status(sha, payload)
    print(
        f"[winre_runner] state={payload['state']} rc={rc} {duration}s "
        f"pack={pack_present} {error}",
        flush=True,
    )
    return {"ok": rc == 0, **payload}


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Run the optional WinRE detonation for a sample")
    ap.add_argument("sha", help="sample sha256 (session must exist)")
    ap.add_argument("--sample", default=None, help="sample path (defaults to the session's)")
    ap.add_argument("--mode", default=None, choices=["agentic", "static"])
    ap.add_argument("--window", type=int, default=None, help="--max-seconds")
    ap.add_argument("--timeout", type=int, default=None, help="subprocess timeout seconds")
    ap.add_argument("--force", action="store_true", help="run even when the availability check fails")
    args = ap.parse_args()

    cfg = settings()
    if args.mode:
        cfg["mode"] = args.mode
    if args.window:
        cfg["window"] = args.window
    out = run_dynamic(
        args.sha, sample_path=args.sample, s=cfg, timeout=args.timeout, force=args.force,
    )
    print(json.dumps(out, indent=2, default=str))
    return 0 if out.get("ok") or out.get("skipped") else 1


if __name__ == "__main__":
    raise SystemExit(main())
