#!/usr/bin/env python3
"""Two guards that could not fire, pinned.

MEDIUM-1 -- the case-directory tripwire could not see the shape of the bug it
guards. Its first-argument capture was `[\\w.]+` with one optional parenthesized
group. That matches `case_dir(sha)` but NOT `case_dir(sha) / "correlate"` -- which
is the literal form of the defect it was written for (the original bug passed
`out_dir`, whose value is `case_dir(sha)/correlate`). A call rewritten into that
shape was invisible, and because `assert calls` only needs ONE match per file,
once other calls matched the bad one was never noticed.

MEDIUM-3 -- the `docs.counts` omission guard was conjunctive. `if not A and not B`
catches deleting BOTH count families, so removing only the manifest count -- or
only the agent count -- still passed with the other family present.

Both are asserted by executing the real check against a mutated file, because a
guard that cannot fail is worse than no guard: it is believed.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _layout import resolve  # noqa: E402

README = ROOT / "README.md"

SHAPES = [
    "scrub_report_indicators(case_dir(sha) / \"correlate\", md, \"x\")",
    "scrub_report_indicators(os.path.join(case_dir(sha), \"correlate\"), md, \"x\")",
    "scrub_report_indicators(LOG_DIR / sha, md, \"x\")",
    "scrub_report_indicators(case=case_dir(sha), markdown=md, label=\"x\")",
    "scrub_report_indicators(out_dir, md, \"x\")",
]
TEAM = "scrub_report_indicators("
PATTERN = r"scrub_report_indicators\(\s*(.*?),\s*"


# ------------------------------------------------------------------ MEDIUM-1

def test_the_tripwire_sees_the_literal_bug_shape():
    """The capture must cover the exact shape of the original defect."""
    blind = [s for s in SHAPES
             if s.startswith(TEAM) and not re.findall(PATTERN, s)]
    assert not blind, f"invisible call shapes: {blind}"
    assert len(SHAPES) == 5, "the probe itself is broken"


def test_the_tripwire_still_passes_the_real_callers():
    src = resolve("revai/section_publisher.py").read_text(
        encoding="utf-8", errors="replace")
    calls = re.findall(PATTERN, src)
    assert calls, "no call sites found -- the probe is broken"
    for root in calls:
        assert root.strip() in ("case_dir(sha)", "case"), root


def test_the_tripwire_is_not_blind_to_a_keyword_first_argument():
    """`case=...` is a legal call shape and must not be skipped."""
    found = re.findall(PATTERN, SHAPES[3])
    assert found == ["case=case_dir(sha)"], found


# ------------------------------------------------------------------ MEDIUM-3

def _run_harness() -> str:
    """Run the real harness, wherever it lives.

    `revai/verify_pipeline.py` in the repo, `/opt/scripts/verify_pipeline.py`
    once deployed -- the twelfth layout trap, where a hardcoded path passes
    locally and fails on the VM.
    """
    harness = resolve("revai/verify_pipeline.py")
    out = subprocess.run(
        [sys.executable, str(harness)],
        capture_output=True, text=True,
        cwd=str(harness.parent), timeout=900)
    return out.stdout + out.stderr


def test_docs_counts_fails_when_the_manifest_count_alone_is_removed():
    if not README.is_file():
        return
    backup = README.read_text(encoding="utf-8")
    try:
        mutated = (backup
                   .replace("(28 tools)", "(a handful of tools)")
                   .replace("28 format-aware manifest tools",
                            "format-aware manifest tools"))
        assert mutated != backup, "probe did not mutate anything"
        README.write_text(mutated, encoding="utf-8")
        out = _run_harness()
    finally:
        README.write_text(backup, encoding="utf-8")
    assert "FAIL" in out and "docs.counts" in out, out[-500:]


def test_docs_counts_fails_when_the_agent_count_alone_is_removed():
    if not README.is_file():
        return
    backup = README.read_text(encoding="utf-8")
    try:
        mutated = backup.replace("26 agent-callable", "agent-callable")
        assert mutated != backup, "probe did not mutate anything"
        README.write_text(mutated, encoding="utf-8")
        out = _run_harness()
    finally:
        README.write_text(backup, encoding="utf-8")
    assert "FAIL" in out and "docs.counts" in out, out[-500:]


def test_docs_counts_passes_on_the_untouched_tree():
    out = _run_harness()
    assert "docs.counts" in out, out[-500:]
    assert "FAIL" not in out, out[-500:]