#!/usr/bin/env python3
"""Locate a module that lives in two different layouts.

The repository keeps its Python modules under `revai/`; the VM deploys the same
files FLAT into `/opt/scripts` (see AGENTS.md section 2, the deploy contract).
`scripts/deploy.sh` copies files but never deletes, so both spellings can exist
at once and the repo layout must win -- a stale flat leftover should never
shadow the file under test.

Without this, `tests/test_case_dir_coherence.py` and `tests/test_cff_detector.py`
raised FileNotFoundError at COLLECTION time on the VM, so the two tripwires
guarding the mode-keyed-path and deobfuscation defects could not run in the one
environment where those defects actually bite. A test that only runs in half the
supported layouts is not a tripwire.

Used at module import time, so it must not import anything from `revai`.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def resolve(relpath: str) -> Path:
    """Return the first existing candidate for `relpath`, repo layout first.

    `relpath` is relative to the repo root, e.g. "revai/quick_scan_v2.py".
    Candidates are the repo path itself, then the same path with a leading
    "revai/" stripped (the flat VM layout), then the bare basename under the
    root (how `extensions/` content lands).
    """
    rel = Path(relpath)
    parts = rel.parts
    candidates = [ROOT / rel]
    if parts and parts[0] == "revai":
        candidates.append(ROOT.joinpath(*parts[1:]))
    candidates.append(ROOT / rel.name)
    for cand in candidates:
        if cand.is_file():
            return cand
    return candidates[0]  # let the caller raise with the canonical path


def source(relpath: str) -> str:
    """Read a module's text through :func:`resolve`."""
    return resolve(relpath).read_text(errors="replace")


def add_module_dir(relpath: str) -> None:
    """Put a module's directory on sys.path so `import <name>` resolves.

    The flat VM layout is found because pytest runs with cwd=/opt/scripts, which
    python -m pytest places on sys.path; the repo layout is added explicitly.
    """
    d = resolve(relpath).parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))