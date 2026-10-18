"""Publisher no-rewrite invariant and documentation count mutation guards."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _layout import resolve  # noqa: E402

def test_publishers_do_not_mutate_generated_claims():
    for rel in ("revai/publish_report_v2.py", "revai/section_publisher.py"):
        src = resolve(rel).read_text(encoding="utf-8", errors="replace")
        assert "scrub_report_indicators(" not in src, rel
        assert "repair_verdict_panel(" not in src, rel
        assert "align_publish_markdown_to_upstream(" not in src, rel
        assert "surface_verdict_sources_panel(" not in src, rel


# ------------------------------------------------------------------ MEDIUM-3

def _run_harness(root: Path | None = None) -> str:
    """Run the real harness, wherever it lives.

    `revai/verify_pipeline.py` in the repo, `/opt/scripts/verify_pipeline.py`
    once deployed -- the twelfth layout trap, where a hardcoded path passes
    locally and fails on the VM.

    `root` points the harness at a different docs tree. The mutation tests pass
    a copy, so probing the guard never touches a tracked file.
    """
    harness = resolve("revai/verify_pipeline.py")
    cmd = [sys.executable, str(harness)]
    if root is not None:
        cmd += ["--root", str(root)]
    out = subprocess.run(
        cmd,
        capture_output=True, text=True,
        cwd=str(harness.parent), timeout=900)
    return out.stdout + out.stderr


def _probe_docs_tree(mutate) -> str:
    """Run the harness against a COPY of the docs tree, mutated by `mutate`.

    Mutating the tracked README.md directly is a defect in itself, not a
    shortcut:

    * every concurrent harness run in the same tree sees the mutation and
      reports a spurious `docs.counts` FAIL -- observed live as
      `test_docs_counts_passes_on_the_untouched_tree` failing because a
      *sibling test's* write was visible mid-run;
    * a kill, timeout or Ctrl-C between the write and the `finally` restore
      leaves the tracked file permanently mutated;
    * `write_text` is not atomic on Windows, so a reader can observe a
      truncated README.

    Copying into tmp_path also makes the probes runnable in both a source
    checkout and the deployed flat layout, which carries README.md and docs/
    alongside the test files.

    On the flat VM layout there is genuinely nothing to probe, so this SKIPS
    rather than failing: a test that fails for an absent artefact is the same
    noise as a check that cannot fail.
    """
    files = [
        ROOT / "README.md",
        ROOT / "docs" / "tool-stack.md",
        ROOT / "docs" / "architecture.md",
        ROOT / "docs" / "img" / "architecture_v2.svg",
        ROOT / "assets" / "revai-architecture.svg",
    ]
    present = [p for p in files if p.is_file()]
    if not present:
        import pytest
        pytest.skip("no source checkout on this host (flat VM layout) - "
                    "there is no docs tree to probe")
    tmp = Path(tempfile.mkdtemp(prefix="verify-probe-"))
    try:
        for src in present:
            dst = tmp / src.relative_to(ROOT)
            dst.parent.mkdir(parents=True, exist_ok=True)
            text = mutate(src.read_text(encoding="utf-8"), src.name)
            if text != src.read_text(encoding="utf-8"):
                dst.write_text(text, encoding="utf-8")
            else:
                shutil.copyfile(src, dst)
        return _run_harness(root=tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _drop_manifest_counts(text: str, _name: str) -> str:
    return (text
            .replace("(28 tools)", "(a handful of tools)")
            .replace("28 format-aware manifest tools",
                     "format-aware manifest tools"))


def _drop_agent_counts(text: str, _name: str) -> str:
    return text.replace("26 agent-callable", "agent-callable")


def test_docs_counts_fails_when_the_manifest_count_alone_is_removed():
    out = _probe_docs_tree(_drop_manifest_counts)
    assert "FAIL" in out and "docs.counts" in out, out[-500:]


def test_docs_counts_fails_when_the_agent_count_alone_is_removed():
    out = _probe_docs_tree(_drop_agent_counts)
    assert "FAIL" in out and "docs.counts" in out, out[-500:]


def test_the_probe_actually_mutates_a_documented_count():
    """A probe that changes nothing cannot prove the guard fires."""
    tmp = Path(tempfile.mkdtemp(prefix="verify-noop-"))
    try:
        (tmp / "README.md").write_text("nothing here to mutate", encoding="utf-8")
        out = _run_harness(root=tmp)
        assert "FAIL" in out and "docs.counts" in out, (
            "a tree with no counts at all should fail the omission guard")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_docs_counts_passes_on_the_untouched_tree():
    """The real tree, unmutated, still passes -- and nothing in this session has
    written to it, which is what makes the assertion meaningful.

    On the flat VM layout the harness warns that docs.counts is skipped, so the
    harness's own documentation is what is being asserted here; a FAIL would
    mean something else regressed.
    """
    out = _run_harness()
    assert "docs.counts" in out, out[-500:]
    assert "FAIL" not in out, out[-500:]
    readme = ROOT / "README.md"
    if readme.is_file():
        assert "a handful of tools" not in readme.read_text(
            encoding="utf-8"), "a mutated README was left behind by a probe"
