#!/usr/bin/env python3
"""WinRE's LLM variables, resolved from the one shared place.

WinRE's own CLI (`python -m winre.pipeline ...`) is not spawned by RevAI, so it
cannot inherit RevAI's LLM config by itself. This resolves the same four
variables with the same precedence the runner uses - process environment >
WinRE's own `.env` > RevAI's shared `llm.env` - and either prints shell exports
or runs a command with them, so an operator running WinRE directly still
configures the model in exactly one place.

    python3 winre_llm_env.py --check
    eval "$(python3 winre_llm_env.py)"
    python3 winre_llm_env.py --run python3 -m winre.pipeline <sample> --mode agentic
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from winre_runner import SHARED_LLM_ENV, resolve_winre_llm, settings  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Resolve WinRE LLM variables from RevAI's shared config.")
    ap.add_argument("--check", action="store_true",
                    help="print the resolution state only (no exports)")
    ap.add_argument("--run", nargs=argparse.REMAINDER, default=[],
                    help="run a command with the resolved environment")
    args = ap.parse_args()

    cfg = settings()
    values, meta = resolve_winre_llm(cfg)
    if args.check or not args.run:
        print(f"# source={meta['source']} configured={meta['configured']} "
              f"model={meta['model']} mode={cfg.get('mode')}")
    if not meta.get("configured"):
        print(f"# no LLM configured: set {SHARED_LLM_ENV}, or WINRE_LLM_* in "
              f"{_winre_env(cfg)}", file=sys.stderr)
        return 1
    if args.check:
        return 0
    for key, val in values.items():
        print(f"export {key}={shlex.quote(val)}")
    if args.run:
        cmd = args.run[1:] if args.run and args.run[0] == "--" else args.run
        env = os.environ.copy()
        env.update(values)
        return subprocess.run(cmd, env=env).returncode
    return 0


def _winre_env(cfg: dict) -> str:
    override = os.environ.get("WINRE_ENV", "").strip()
    return override or str(Path(cfg["root"]) / ".env")


if __name__ == "__main__":
    raise SystemExit(main())
