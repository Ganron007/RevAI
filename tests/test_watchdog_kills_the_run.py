#!/usr/bin/env python3
"""The watchdog must kill the whole run, not just its own child.

Verified defects from the 2026-10-03 review, pinned here because each one was
invisible in normal operation:

B1  `kill_run` signalled only `$RUN_PID`. `pipeline_single.py` runs every stage
    with `subprocess.run`, so a stage is a GRANDCHILD of the watcher and
    survived -- the watcher printed exit 2 "run killed" over a live Ghidra
    process still burning tokens. The run is now started with `setsid` (its own
    process group) and killed by negative PGID.

B2  A failed `sudo reboot` exited 0, which the script's own header defines as
    "every stage rc=0". The reboot rule is mandatory, so its failure must not
    look like success to a caller doing `run-watched.sh … && deploy`.

B3  A trailing `--sha` with no value aborted under `set -u` with exit 1, which a
    caller reads as "a stage failed"; 3 is the documented usage error.

B4  `--timeout-minutes 1.5` reached arithmetic inside `watch_loop` -- after the
    run was launched -- so the arithmetic error orphaned it, the same
    "watcher dies, run survives" shape as B1.

B1 is asserted on the SCRIPT rather than by running it, because the real proof
needs a sample and a 45-minute pipeline; the shape (setsid + negative PGID +
direct child) is what makes the grandchild die, and it is asserted directly.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import resolve  # noqa: E402

# scripts/run-watched.sh in the repo; /opt/scripts/run-watched.sh once deployed.
WATCHER = resolve("scripts/run-watched.sh")
# The directory to run from: the repo root in the repo layout, the scripts dir
# in the flat VM layout. The script path is then relative either way.
ROOT = WATCHER.parent.parent if WATCHER.parent.name == "scripts" else WATCHER.parent


def _run_watcher(*args: str) -> subprocess.CompletedProcess:
    """Invoke the watcher from bash, whatever host runs the suite.

    `bash` here may be git-bash (C: at ``/c/``) or WSL (``/mnt/c/``), and the
    two mounts are not interchangeable -- a hardcoded prefix fails on one of
    them. Passing a RELATIVE path with ``cwd`` sidesteps the mount question
    entirely, and it is what a caller would type anyway.
    """
    return subprocess.run(
        ["bash", "scripts/run-watched.sh", *args],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT))


def _src() -> str:
    return WATCHER.read_text(encoding="utf-8", errors="replace")


def test_run_is_started_in_its_own_process_group():
    """Without setsid there is no group to signal, so B1 cannot be fixed."""
    src = _src()
    start = re.search(r"^\s*setsid\s+python3\s+pipeline_single\.py", src, re.M)
    assert start, "the run must be launched with setsid so it leads a group"


def test_kill_run_signals_the_negative_pgid():
    """The negative PID is what reaches the grandchildren."""
    src = _src()
    assert 'kill -TERM "-$pgid"' in src, "TERM must go to the process group"
    assert 'kill -KILL "-$pgid"' in src, "KILL must go to the process group"
    # And it must derive the pgid from the live process, not assume it.
    assert "ps -o pgid= -p" in src, "pgid must be read from the running process"


def test_kill_run_still_signals_the_direct_child():
    """The group may be gone already; `wait` is blocked on the child."""
    src = _src()
    assert 'kill -TERM "$RUN_PID"' in src
    assert 'kill -KILL "$RUN_PID"' in src


def test_kill_run_does_not_use_a_pattern_kill():
    """`pkill -f` also kills the invoking shell (documented in AGENTS.md)."""
    src = _src()
    assert "pkill" not in src, (
        "a pattern kill can signal this script itself; use the process group")


def test_a_failed_reboot_does_not_exit_zero():
    """B2: 0 means 'every stage rc=0', so it must not mean 'reboot failed'."""
    src = _src()
    assert "if ! sudo reboot; then" in src, "the reboot's status must be tested"
    assert "exit 1" in src.split("if ! sudo reboot; then")[1][:400], (
        "a failed reboot must exit non-zero, not fall through to exit 0")


def test_missing_option_values_exit_with_the_usage_code():
    """B3: exit 3 is the documented usage/environment error."""
    for opt in ("--sha", "--mode", "--timeout-minutes"):
        proc = _run_watcher("/tmp/no-such-sample.bin", opt)
        assert proc.returncode == 3, (
            f"{opt} with no value exited {proc.returncode}, expected 3")


def test_non_integer_timeout_is_rejected_before_launch():
    """B4: validating inside watch_loop orphans the run.

    The validator sits before the sample-existence check on purpose, so a
    nonexistent sample still reaches it — which is what lets this test run
    without a real, writable sample path on either host (a Windows temp path is
    mangled by the bash that invokes the watcher, and the deployed runtime dir
    is root-owned).
    """
    proc = _run_watcher("/tmp/no-such-sample.bin", "--timeout-minutes", "1.5")
    assert proc.returncode == 3, proc.returncode
    assert "whole number" in proc.stderr, proc.stderr


def test_a_valid_timeout_is_not_rejected_by_the_validator():
    """The guard must not fail a legitimate invocation.

    30 with a non-existent sample still exits 3 -- that is the sample check,
    which is the correct reason; what must not happen is a *validator* error.
    """
    proc = _run_watcher("/tmp/no-such-sample.bin", "--timeout-minutes", "30")
    assert proc.returncode == 3
    assert "whole number" not in proc.stderr, proc.stderr


if __name__ == "__main__":
    sys.exit(0)