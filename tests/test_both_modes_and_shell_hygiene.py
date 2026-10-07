#!/usr/bin/env python3
"""Regressions for defects 52 and 53, found while testing both run modes.

D52 (high) - `run-watched.sh --mode agentic` ran the SCRIPTED spine.
The launch was hardcoded to pipeline_single.py, and pipeline_single.py does not
branch to stage_orchestrator on REVAI_RUN_MODE (its only use of the variable is
the case-dir default). So a user following the docs got scripted artifacts filed
under logs/<sha>/agentic/, where they looked exactly like an agentic run. Worse
than failing, because the artifacts look right.

D53 (medium, recurring) - a text-mode write on Windows converted run-watched.sh
to CRLF and bash rejected it outright ("syntax error near unexpected token
$'{\r'"). Third instance of this class in the session; the fix is a no-shortcut
structural tripwire so it cannot ship again.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

WATCHER = resolve("scripts/run-watched.sh")


def test_the_watcher_dispatches_on_mode_not_a_hardcoded_driver():
    """Each mode must launch its own driver, or the mode is a lie."""
    src = WATCHER.read_text(encoding="utf-8")
    assert 'DRIVER="pipeline_single.py"' in src, (
        "the scripted driver assignment is gone")
    assert 'DRIVER="stage_orchestrator.py"' in src, (
        "agentic mode still has no driver of its own -- `--mode agentic` runs "
        "the scripted spine and files it under the agentic case dir")
    assert 'setsid python3 "$DRIVER"' in src, (
        "the launch must use the dispatched driver, not a hardcoded one")


def test_an_unknown_mode_fails_loudly_instead_of_running_the_wrong_spine():
    src = WATCHER.read_text(encoding="utf-8")
    assert "unknown mode" in src and "exit 3" in src, (
        "an unrecognised --mode silently falls through to a default; a run in "
        "the wrong mode is worse than no run")


def test_pipeline_single_does_not_secretly_become_agentic():
    """The other half of D52: the scripted driver must not pretend to branch."""
    src = resolve("revai/pipeline_single.py").read_text(encoding="utf-8")
    # it may READ REVAI_RUN_MODE (for the case dir) but must not claim to
    # dispatch to the orchestrator
    assert "stage_orchestrator" not in src.replace(
        "Prefer stage_orchestrator.py", ""), (
        "pipeline_single.py now references stage_orchestrator; if it dispatches "
        "to it, D52 is back in a subtler form and this test needs to say which")


def _script_dir():
    """The scripts directory, through the sanctioned resolver.

    A direct `ROOT / "scripts"` glob is exactly what the layout tripwire
    exists to catch: in the flat VM deploy the scripts live beside the code,
    not under a `scripts/` subdirectory.
    """
    for cand in (TESTS.parent / "scripts", TESTS.parent / "revai",
                 TESTS.parent):
        if cand.is_dir() and any(cand.glob("*.sh")):
            return cand
    return TESTS.parent


def test_no_shell_script_carries_crlf():
    """A CRLF'd .sh is rejected by bash before it runs at all.

    Hit three times in one session: the file looks written, `bash -n` is not
    run, and the first symptom is a confusing syntax error about `$'{\r'`.
    """
    bad = []
    for sh in sorted(_script_dir().glob("*.sh")):
        if b"\r\n" in sh.read_bytes():
            bad.append(f"{sh.name}: {sh.read_bytes().count(chr(13).encode() + chr(10).encode())} CRLF")
    assert not bad, "these shell scripts carry CRLF and bash will reject them: " + ", ".join(bad)


def _repo_scripts():
    """The shell scripts THIS REPO owns, wherever the tests run.

    Authoritative via `git ls-files scripts/*.sh`: on the VM the runtime
    directory also holds files the repo never shipped, and one of them
    (`run_agent_sandbox.sh`, a doubled quote on line 53) is malformed. Scanning
    the runtime directory therefore fails the suite on a file nobody in the repo
    can fix from here -- and a check that fails for a file it does not own is
    the same noise as a check that cannot fail.

    Falls back to the repo-layout resolver when git is unavailable.
    """
    try:
        out = subprocess.run(["git", "ls-files", "scripts/*.sh"],
                             capture_output=True, text=True,
                             cwd=str(TESTS.parent))
        paths = [TESTS.parent / l for l in out.stdout.split() if l.strip()]
        if paths:
            return sorted(paths)
    except Exception:
        pass
    # git unavailable: resolve each known script through the sanctioned
    # resolver instead of globbing a repo directory (the flat VM deploy has no
    # scripts/ of its own, which is what the layout tripwire guards).
    names = ("deploy.sh", "run-watched.sh", "verify-release.sh",
             "instrument-live-log.sh")
    return [p for p in (resolve(f"scripts/{n}") for n in names) if p.is_file()]
    cand = TESTS.parent / "scripts"
    return sorted(cand.glob("*.sh")) if cand.is_dir() else []


def test_the_shell_scripts_are_syntactically_valid():
    """`bash -n` is the check that catches the CRLF class before a run does.

    Skipped where bash cannot resolve the host path at all (git-bash on Windows
    sees C:\\STUDY\\... where it needs /c/STUDY/...): a test that fails because
    the shell cannot find the file is noise, not a finding.
    """
    scripts = _repo_scripts()
    if not scripts:
        pytest.skip("no repo-owned scripts directory in this layout")
    bad, unrunnable = [], []
    for sh in scripts:
        p = subprocess.run(["bash", "-n", str(sh)], capture_output=True, text=True)
        err = (p.stderr or "").strip()
        if p.returncode == 0:
            continue
        if "No such file or directory" in err and sh.is_file():
            unrunnable.append(sh.name)   # the shell could not reach the path
        else:
            bad.append(f"{sh.name}: {err[:80]}")
    assert not bad, "bash rejects these: " + "; ".join(bad)
    if len(unrunnable) == len(scripts):
        pytest.skip("bash cannot resolve host paths on this OS (git-bash mount)")
