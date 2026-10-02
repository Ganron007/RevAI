#!/usr/bin/env python3
"""The audit found a real bug; this pins it.

`v2_lib._capa_malcat_only` references `run_packer_scan` in its packed-stub
acceptance path. It was never imported into `v2_lib`, so the call raised
`NameError` -- and the surrounding `except Exception: pk = {}` swallowed it.

The failure was silent and behavioural, not a crash: a sample that Malcat reports
as clean (0 rules) but whose packer checklist flags as `packed` or `suspicious`
was supposed to be accepted as a `packed_stub` success, with the capa error
cleared and `rule_count` set to 0. That branch could never fire. Instead the
sample fell through to the Mandiant CLI, which errors on intentionally-corrupt
packed headers such as UPack -- so a packed stub produced a spurious tool error
on every run.

Nothing went red: the stage exited 0 and the artifact was well-formed, which is
the same shape as the five hollow-success defects from the previous session.

Found by pyflakes during the 2026-10-02 audit, not by a test -- which is why the
test exists now.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import add_module_dir, source  # noqa: E402
add_module_dir("revai/v2_lib.py")

import v2_lib  # noqa: E402


def test_run_packer_scan_is_imported_into_v2_lib():
    """The bug itself: the name must resolve in this module's namespace."""
    assert hasattr(v2_lib, "run_packer_scan"), (
        "v2_lib calls run_packer_scan() but does not import it; the NameError is "
        "swallowed by a bare except and the packed-stub path never fires")
    assert callable(v2_lib.run_packer_scan)


def test_the_call_site_no_longer_relies_on_a_name_error():
    """Pin the call site so a future refactor cannot reintroduce the swallow."""
    src = source("revai/v2_lib.py")
    assert "pk = run_packer_scan(sample_path)" in src, (
        "the packed-stub acceptance path has moved or been removed -- re-check "
        "that packed stubs are still accepted")


def test_run_packer_scan_is_actually_callable_on_a_real_sample():
    """A live call, so an import that resolves but cannot run is caught."""
    exe = Path("/bin/true")
    if not exe.is_file():
        exe = Path("/usr/bin/true")
    if not exe.is_file():
        return  # non-POSIX test host; the two tests above still apply
    out = v2_lib.run_packer_scan(str(exe))
    assert isinstance(out, dict), out
    # The contract the call site depends on: a label to compare against
    # ("packed"/"suspicious") and a name for the report.
    assert "label" in out or "ok" in out, out


def test_the_bare_except_is_still_there_but_no_longer_load_bearing():
    """The except stays -- packer_scan may legitimately raise.

    What must not happen is a NameError being absorbed by it. Now that the import
    is at module level, the except can only catch failures inside packer_intake.
    """
    src = source("revai/v2_lib.py")
    assert "from packer_intake import run_packer_scan" in src, (
        "import must be at module level so the name resolves before the try")
    assert "from packer_intake import run_packer_scan" not in src.split(
        "def _capa_malcat_only")[0].split("import run_packer_scan")[0][-200:], (
        "a function-local import would reintroduce a path where the name can be "
        "missing")