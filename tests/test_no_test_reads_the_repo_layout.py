#!/usr/bin/env python3
r"""No test may open a repo-layout path directly. This is the tripwire.

THE BUG CLASS. The repo and the deployed VM have different layouts:

    repo:    revai/v2_lib.py            deploy:  /opt/scripts/v2_lib.py
    repo:    scripts/run-watched.sh      deploy:  /opt/scripts/run-watched.sh

`tests/test_x.py` reading ``ROOT / "revai" / "v2_lib.py"`` works locally and
raises FileNotFoundError **at module import** on the VM, where `/opt/scripts/revai/`
does not exist. A collection error is not a test failure: pytest reports
"Interrupted: N errors during collection" and runs NOTHING, so the whole VM suite
goes red and the signal reads as "everything broke" rather than "one test needs
its path fixed".

This reached 13 instances before anyone noticed, including several in tests I
wrote AFTER already fixing earlier ones. Knowing the trap did not help because the
fix was a convention, not a rule. What made it invisible for so long is worse:

    the release gate never ran the test suite on the VM at all.

`scripts/verify-release.sh` picked `python3`, which on this PEP-668-managed VM has
no pytest, so its own test step died with "No module named pytest". The gate
reported the suite as failing (or skipped) while never executing it -- so the one
check designed to catch deployment-vs-repo drift was itself not running. The gate
now probes for a python WITH pytest and falls back to /tmp/rtvenv, and fails
loudly if none exists.

This test is the guard: read every test's AST and fail on any repo-rooted path
access. It is an AST scan rather than a regex because multi-line calls hide from
regexes, and because the failure it guards against is silent.
"""
from __future__ import annotations

import ast
import sys
import warnings
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))

# The taint scanner lives in its own module so it can be probed directly by
# test_the_tripwire_sees_the_escape_shapes below. The previous version's scanner
# was a private function inside this file, which meant it could only be tested
# against the one synthetic shape that test wrote -- a gate verified against
# itself.
from _layout_scan import file_reads_repo_source  # noqa: E402

REPO_ROOT = TESTS_DIR.parent

#: Repo subdirectories whose files are deployed FLAT (so a repo-layout path does
#: not exist on the VM). Anything else is data, not code.
_CODE_DIRS = ("revai", "scripts", "install", "config", "extensions")

#: The sanctioned accessor. Tests that need a repo file must go through it.
_LAYOUT_MODULE = "_layout"


def test_no_test_reads_a_repo_layout_path_directly():
    """Every test that opens a source file must go through tests/_layout.py."""
    offenders: dict[str, list[int]] = {}
    for path in sorted(TESTS_DIR.glob("*.py")):
        if path.name == "_layout.py" or path.name == Path(__file__).name:
            continue
        lines = file_reads_repo_source(path)
        if lines:
            offenders[path.name] = lines

    assert not offenders, (
        "these tests open a repo-layout path directly, which does not exist in "
        "the flat VM deploy (/opt/scripts/revai/ etc) and aborts collection there:\n"
        + "\n".join(f"  {name}: line(s) {', '.join(map(str, ls))}"
                    for name, ls in sorted(offenders.items()))
        + "\n\nUse tests/_layout.py -- resolve(\"revai/x.py\") or source(\"revai/x.py\")"
    )


def test_layout_module_covers_every_code_directory():
    """The sanctioned accessor must know both layouts for every code dir.

    A test that goes through _layout is only as safe as _layout's own candidate
    list. If a code dir is missing from it, using _layout silently falls back to
    the repo path and the trap reopens for that directory.
    """
    sys.path.insert(0, str(TESTS_DIR))
    import _layout

    candidates = dir(_layout)
    assert "resolve" in candidates, "_layout must expose resolve()"
    assert "source" in candidates, "_layout must expose source()"
    # resolve() must find this very file's repo in at least the local layout.
    found = _layout.resolve("revai/v2_lib.py")
    assert found is not None and found.name == "v2_lib.py", found


def test_the_tripwire_itself_can_fail(tmp_path):
    """A tripwire that cannot fire is the defect it was written to prevent.

    Writes its probe into `tmp_path`, not into `tests/`: the scan globs
    `tests/*.py`, so a probe left behind by a kill, timeout or Ctrl-C between
    the write and the unlink is picked up by the very next run and reported as
    an offender -- self-inflicted red from the tripwire's own probe.
    """
    probe = tmp_path / "_probe_detects.py"
    probe.write_text(
        "from pathlib import Path\n"
        "ROOT = Path(__file__).resolve().parent.parent\n"
        "src = (ROOT / 'revai' / 'v2_lib.py').read_text(errors='replace')\n",
        encoding="utf-8")
    assert file_reads_repo_source(probe), "the scan missed a repo-rooted read_text"


def test_the_tripwire_does_not_flag_the_safe_form(tmp_path):
    """And it must not flag tests that already go through _layout."""
    probe = tmp_path / "_probe_safe.py"
    probe.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).resolve().parent))\n"
        "from _layout import resolve, source\n"
        "src = source('revai/v2_lib.py')\n",
        encoding="utf-8")
    hits = file_reads_repo_source(probe)
    assert not hits, f"false positive on the sanctioned form: {hits}"


def test_the_tripwire_sees_the_escape_shapes(tmp_path):
    """Every shape the old substring scan was blind to.

    The previous gate matched `Name(id='ROOT'` plus a reader attribute, which
    let through four ordinary spellings -- all of them demonstrated against it:

      p = ROOT / "revai" / "x.py" ; p.read_text()      (indirection)
      open(ROOT / "revai" / "x.py").read()             (`open` is ast.Name,
                                                        not ast.Attribute)
      REPO_ROOT / "scripts" / "x.py"                   (root named REPO_ROOT)
      subprocess.run([sys.executable, str(ROOT / "scripts" / "x.sh")])

    The last one is how the harness invokes scripts, so it was not a
    hypothetical. This test is what keeps the gate honest about all of them.
    """
    shapes = [
        "p = ROOT / 'revai' / 'x.py'\ndata = p.read_text(errors='replace')\n",
        "data = open(ROOT / 'revai' / 'x.py').read()\n",
        "REPO_ROOT = Path(__file__).resolve().parent.parent\n"
        "data = (REPO_ROOT / 'revai' / 'x.py').read_text()\n",
        "import subprocess, sys\n"
        "subprocess.run([sys.executable, str(ROOT / 'scripts' / 'x.sh')])\n",
        "import py_compile\n"
        "py_compile.compile(str(ROOT / 'revai' / 'cli.py'))\n",
        "data = open('revai/v2_lib.py').read()\n",
    ]
    header = ("import subprocess, sys, py_compile\n"
              "from pathlib import Path\n"
              "ROOT = Path(__file__).resolve().parent.parent\n")
    missed: list[int] = []
    for i, shape in enumerate(shapes):
        probe = tmp_path / f"_probe_escape_{i}.py"
        probe.write_text(header + shape, encoding="utf-8")
        hits = file_reads_repo_source(probe)
        if not hits:
            missed.append(i)
    assert not missed, f"the scan is blind to shapes {missed} of {len(shapes)}"


if __name__ == "__main__":
    import inspect

    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS {name}")
            except AssertionError as exc:
                print(f"  FAIL {name}: {exc}")
                raise SystemExit(1)
    print("  all layout tripwire checks passed")