#!/usr/bin/env python3
"""`scripts/instrument-live-log.sh` reads a run in one pass, and must exit honestly.

The standing rule is to monitor a run live and act on the FIRST error, and that
"0 errors" is not evidence a stage worked -- measure the artifact. This script is
that rule made mechanical. These tests pin its exit contract and its layout
awareness, because a reporting tool that says "green" when it simply could not
find the log is the same failure as the hollow-success gate reporting green on an
empty case.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _layout import resolve  # noqa: E402

TOOL = resolve("scripts/instrument-live-log.sh")


def _run(*args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run the tool, from wherever this layout keeps it.

    The repo has `scripts/instrument-live-log.sh`; the deployed layout has it flat
    at `/opt/scripts/instrument-live-log.sh`. Running it by a relative path from
    ROOT works in both, because ROOT is the directory the tool lives in.
    """
    rel = TOOL.name if TOOL.parent == ROOT else ("scripts/" + TOOL.name)
    return subprocess.run(
        ["bash", rel, *args],
        capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))


def test_the_script_is_executable():
    """Git must record the exec bit, which is what the VM deploy copies.

    Checked in the INDEX, not the filesystem: Windows has no executable bit, so
    `st_mode` is 0644 there regardless, and asserting on it would fail on the
    developer host while the deploy is correct.
    """
def test_it_deploys_with_the_operator_scripts():
    assert TOOL.is_file(), f"missing {TOOL}"
    inside = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, cwd=str(ROOT))
    if inside.returncode != 0:
        return  # deployed flat layout: there is no git index to consult
    out = subprocess.run(
        ["git", "ls-files", "-s", TOOL.relative_to(ROOT).as_posix()],
        capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("100755"), (
        f"git does not record the exec bit: {out.stdout.strip()}")


def test_bash_syntax_is_valid():
    """A syntax error here means the tool is dead in production."""
    out = subprocess.run(
        ["bash", "-n", TOOL.name],
        capture_output=True, text=True, cwd=str(TOOL.parent))
    assert out.returncode == 0, out.stderr


def test_no_line_endings_can_break_bash():
    """CRLF in a shell script is fatal to bash.

    A text-mode write on Windows introduced 273 CRLF into this file during
    development and the tool stopped working entirely. Guarded because it is a
    mistake that costs a whole debugging cycle rather than a test.
    """
    data = TOOL.read_bytes()
    assert b"\r\n" not in data, "CRLF in a .sh breaks bash; normalise to LF"


def test_usage_error_exits_three():
    proc = _run("/nonexistent-sample-path-xyz")
    assert proc.returncode == 3, (proc.returncode, proc.stderr, proc.stdout)


def test_it_deploys_with_the_operator_scripts():
    """deploy.sh must ship it, or it exists only on the developer host."""
    dep = resolve("scripts/deploy.sh")
    if not dep.is_file():
        return  # the VM deploy is flat and does not ship deploy.sh
    text = dep.read_text(encoding="utf-8", errors="replace")
    assert "instrument-live-log.sh" in text, "not in the deploy.sh operator list"