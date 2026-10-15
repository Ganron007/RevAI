#!/usr/bin/env python3
"""WinRE's LLM variables, resolved from its own control-plane config.

WinRE's own CLI (`python -m winre.pipeline ...`) is not spawned by RevAI, so it
uses its own WINRE_LLM_* exports or env file. This applies the same resolver
as the RevAI bridge; neither path borrows RevAI's provider, model or key.

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
from winre_runner import resolve_winre_llm, settings  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Resolve WinRE LLM variables from its own config.")
    ap.add_argument("--check", action="store_true",
                    help="print the resolution state only (no exports)")
    ap.add_argument("--run", nargs=argparse.REMAINDER, default=[],
                    help="run a command with the resolved environment")
    args = ap.parse_args()

    cfg = settings()
    values, meta = resolve_winre_llm(cfg)
    running = bool(args.run)
    if args.check or not running:
        print(f"# source={meta['source']} configured={meta['configured']} "
              f"model={meta['model']} mode={cfg.get('mode')}")
    if not meta.get("configured"):
        print("# no LLM configured: set WINRE_LLM_* exports or configure "
              f"{_winre_env(cfg)}", file=sys.stderr)
        return 1
    if args.check:
        return 0
    if running:
        # Never print exports on the exec path: the key would land in the caller's
        # stdout, a log file, or a terminal scrollback.
        cmd = args.run[1:] if args.run[0] == "--" else args.run
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("REVAI_LLM_")}
        env.update(values)
        return subprocess.run(cmd, env=env).returncode
    # Eval path: the whole point is to hand the variables to the shell.
    for key, val in values.items():
        print(f"export {key}={shlex.quote(val)}")
    return 0


def _winre_env(cfg: dict) -> str:
    override = os.environ.get("WINRE_ENV", "").strip()
    return override or str(Path(cfg["root"]) / ".env")


if __name__ == "__main__":
    raise SystemExit(main())
