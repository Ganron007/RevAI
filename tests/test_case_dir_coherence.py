#!/usr/bin/env python3
"""quick_scan's tool cache was written where deep_dive does not read it.

Found 2026-10-01 while auditing tool coverage across modes. Both files handled
every OTHER artifact mode-keyed, which is why this survived for so long:

    quick_scan_v2.py:598        qs_dir = LOGS_DIR / sha / "quick_scan"
    deep_dive_agentic.py:829    reads case_dir(sha) / "quick_scan" / "00-tools-raw.json"

The writer went to the flat path, the reader looked in the mode-keyed path, and
so the cache NEVER hit. The comment above the writer -- "deep_dive reuses this
cache (no second capa/FLOSS run)" -- was silently false: every run re-ran capa
and FLOSS, and the mode-keyed audit saw no quick_scan tool evidence at all.

Neither side raised. Writes and reads were both individually correct, so no test
failed and no run went red -- the failure was only visible as duplicated work
and a missing artifact. Which is why this is pinned as a *pairing* invariant
(the writer's path must equal the reader's path) rather than as two independent
assertions about each file.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import add_module_dir, source  # noqa: E402

add_module_dir("revai/quick_scan_v2.py")

QS = source("revai/quick_scan_v2.py")
DD = source("revai/deep_dive_agentic.py")

# The cache both sides care about.
CACHE = "00-tools-raw.json"


def _flat_constructions(src: str) -> list[str]:
    """Every place a file builds a path as LOGS_DIR / <something>.

    `LOGS_DIR / sha` as a *read fallback* is legitimate -- v2_lib.case_dir()
    falls back to it on purpose, and the Console appends a flat candidate after
    the mode-keyed ones. Constructing one to WRITE an artifact is the defect.
    """
    out = []
    for m in re.finditer(r"^\s*\w+\s*=\s*LOGS_DIR\s*/\s*[^\n]+", src, re.M):
        out.append(m.group(0).strip())
    return out


def test_quick_scan_writes_no_artifact_to_the_flat_path():
    """All three flat writes are gone: the cache, ti-enrich, goodware verdict."""
    flat = _flat_constructions(QS)
    assert flat == [], (
        "quick_scan_v2.py builds artifact paths from LOGS_DIR directly: "
        f"{flat}. Use case_dir(sha) so the artifact lands where the "
        "mode-keyed audit and deep_dive look for it.")


def test_cache_write_and_read_agree():
    """The invariant that was actually broken: one path, two files."""
    assert f'case_dir(args.sha256) / "quick_scan"' in QS, (
        "quick_scan must build its cache dir from case_dir(args.sha256)")
    assert f'case_dir(sha) / "quick_scan" / "{CACHE}"' in DD, (
        "deep_dive must read the cache from case_dir(sha)/quick_scan")


def test_goodware_early_return_writes_mode_keyed_verdict():
    """The goodware branch returns before the main path runs.

    Easy to miss because it only fires on benign samples, so a broken verdict
    path there would never show up on a malware corpus.
    """
    block = QS.split("GOODWARE_FINGERPRINT match")[0]
    tail = block[-1200:]
    assert "log_dir = case_dir(args.sha256)" in tail, (
        "the goodware early-return writes verdict.json; it must be "
        "mode-keyed like every other verdict")


def test_deep_dive_cache_read_is_not_guarded_into_silence():
    """A missing cache must degrade, not silently skip the reuse.

    The read is in a try/except. If the cache is absent that is legitimate (a
    deep dive may run standalone), but the reuse claim in the writer's comment
    should not be asserted by a test that cannot see the file.
    """
    idx = DD.find(f'case_dir(sha) / "quick_scan" / "{CACHE}"')
    assert idx != -1
    window = DD[max(0, idx - 400):idx + 200]
    assert "except" in window, (
        "the cache read must be guarded: a standalone deep_dive has no cache")


def test_case_dir_is_the_only_supported_artifact_root():
    """v2_lib keeps LOGS_DIR as the base constant -- that is correct.

    What must not exist is a *second* way to address artifacts. This test is the
    tripwire for a future stage reintroducing one.
    """
    import v2_lib
    assert v2_lib.LOGS_DIR == Path("/opt/samples/logs")
    # case_dir must land inside a mode segment, not directly on the sha dir.
    import os
    os.environ["REVAI_RUN_MODE"] = "scripted"
    try:
        d = v2_lib.case_dir("a" * 64)
        assert d.name == "scripted", d
        assert d.parent.name == "a" * 64, d
    finally:
        os.environ.pop("REVAI_RUN_MODE", None)