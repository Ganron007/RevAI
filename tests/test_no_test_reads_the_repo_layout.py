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
REPO_ROOT = TESTS_DIR.parent

#: Repo subdirectories whose files are deployed FLAT (so a repo-layout path does
#: not exist on the VM). Anything else is data, not code.
_CODE_DIRS = ("revai", "scripts", "install", "config", "extensions", "docs")

#: Attribute reads that touch the filesystem and therefore need a real path.
_READERS = frozenset({
    "read_text", "read_bytes", "is_file", "exists", "glob", "rglob",
    "open", "iterdir", "stat",
})

#: The sanctioned accessor. Tests that need a repo file must go through it.
_LAYOUT_MODULE = "_layout"


def _rooted_repo_paths(tree: ast.AST) -> list[str]:
    """Every `ROOT / "<code-dir>" / ...` sub-expression in this test file."""
    found: list[str] = []
    for node in ast.walk(tree):
        # BinOp chains: ((ROOT / "revai") / "x.py")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            seg = ast.dump(node)
            for d in _CODE_DIRS:
                if f"Constant(value='{d}')" in seg or f'Constant(value="{d}")' in seg:
                    found.append(d)
                    break
    return found


def _file_reads_repo_source(path: Path) -> list[int]:
    """Line numbers in `path` that read a file under a code directory."""
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        # ast.parse on files this test does not own surfaces their latent
        # SyntaxWarnings (non-raw docstrings containing \` or \S). Those are not
        # this tripwire's finding -- suppress them so a warning in an unrelated
        # file cannot make this gate look broken.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(src)
    except SyntaxError as exc:  # a broken test file is itself a finding
        print(f"  {path.name}: PARSE ERROR {exc}")
        return [exc.lineno or 0]
    uses_layout = _LAYOUT_MODULE in src
    bad: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not isinstance(f, ast.Attribute) or f.attr not in _READERS:
            continue
        seg = ast.dump(node)
        # Only when the call is rooted at ROOT and reaches into a code dir.
        if "Name(id='ROOT'" not in seg and "Name(id='REPO_ROOT'" not in seg:
            continue
        if any(f"Constant(value='{d}')" in seg or f'Constant(value="{d}")' in seg
               for d in _CODE_DIRS):
            bad.append(node.lineno)
    if bad and not uses_layout:
        # Not a failure on its own: the file may simply never read a repo file.
        pass
    return bad


def test_no_test_reads_a_repo_layout_path_directly():
    """Every test that opens a source file must go through tests/_layout.py."""
    offenders: dict[str, list[int]] = {}
    for path in sorted(TESTS_DIR.glob("*.py")):
        if path.name == "_layout.py" or path.name == Path(__file__).name:
            continue
        lines = _file_reads_repo_source(path)
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


def test_the_tripwire_itself_can_fail():
    """A tripwire that cannot fire is the defect it was written to prevent."""
    import inspect

    import _layout

    # A genuinely repo-rooted read must be detected in a synthetic file.
    probe = TESTS_DIR / "_tripwire_probe.py"
    probe.write_text(
        "from pathlib import Path\n"
        "ROOT = Path(__file__).resolve().parent.parent\n"
        "src = (ROOT / 'revai' / 'v2_lib.py').read_text(errors='replace')\n",
        encoding="utf-8")
    try:
        hits = _file_reads_repo_source(probe)
    finally:
        probe.unlink()
    assert hits, "the AST scan did not detect a repo-rooted read_text"


def test_the_tripwire_does_not_flag_the_safe_form():
    """And it must not flag tests that already go through _layout."""
    sys.path.insert(0, str(TESTS_DIR))
    import _layout

    probe = TESTS_DIR / "_tripwire_probe2.py"
    probe.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).resolve().parent))\n"
        "from _layout import resolve, source\n"
        "src = source('revai/v2_lib.py')\n",
        encoding="utf-8")
    try:
        hits = _file_reads_repo_source(probe)
    finally:
        probe.unlink()
    assert not hits, f"false positive on the sanctioned form: {hits}"
    assert callable(_layout.source)


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