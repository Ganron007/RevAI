#!/usr/bin/env python3
"""The verdict-panel reader must survive a report layout it has not seen.

Third failure of the same check: `verdict.panels_unreadable` fired on WannaCry
after two earlier rounds of "add the format the reports actually emit". Five
layouts exist across the two publishers and a punctuation-anchored regex is a
treadmill -- the same enumerated-vs-discovered class this project already fixed
for artifacts and tools.

The fix anchors on the VERDICT VOCABULARY (drawn from calibrate_verdict's
accepted verdicts) rather than on the punctuation around it, and accepts both
row labels the publishers use (`Verdict` and `Final`). These tests pin every
layout observed on a real run, plus the prose shapes that must NOT match -- a
reader that matches prose would make the cross-report agreement check meaningless.
"""
from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402


def _reader():
    sys.modules.pop("hollow_success", None)
    d = resolve("revai/hollow_success.py").parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import hollow_success as hs  # noqa: PLC0415
    return hs


#: Every verdict layout seen on a real run, with the verdict it carries.
#: WannaCry's `**Verdict: MALICIOUS** | **Family: ...** | **Score: 97/100** |`
#: and `| **Verdict** | Malicious | ...` are the two that broke the last reader.
REAL_LAYOUTS = [
    ("v2 table row", "| **Final** | **suspicious** |", "suspicious"),
    ("v2 table row italic", "| **Final** | *unknown* |", "unknown"),
    ("v3 inline panel",
     "**Verdict: suspicious** (confidence: 70/100, source: deep_dive_agentic).",
     "suspicious"),
    ("v3 technical",
     "**Verdict:** `suspicious` (score 45), `family_guess = X`", "suspicious"),
    ("v2 body uppercase",
     "**Verdict: SUSPICIOUS (score 45/100)** - a legitimately coded tool",
     "suspicious"),
    ("v2 header with family and score",
     "**Verdict: MALICIOUS** | **Family: WannaCry (WannaCrypt0r)** | "
     "**Score: 97/100** |", "malicious"),
    ("v3 table row",
     "| **Verdict** | Malicious | YARA 28 rule hits + Capa 32 rules |",
     "malicious"),
    ("v3 table row with source",
     "| Verdict | **Malicious** | (source: cross-section:verdict_agreement) |",
     "malicious"),
    ("benign inline", "**Verdict: benign** (confidence: 12/100)", "benign"),
]


def test_every_real_verdict_layout_parses():
    hs = _reader()
    for label, text, expected in REAL_LAYOUTS:
        m = hs._PANEL_RE.search(text)
        assert m, f"{label}: the reader cannot parse a layout the reports emit"
        got = (m.group(1) or "").strip().lower().replace(" ", "_")
        assert got == expected, f"{label}: got {got!r}, want {expected!r}"


def test_the_reader_does_not_match_prose_about_verdicts():
    """A reader satisfied by prose would make the agreement check meaningless."""
    hs = _reader()
    prose = [
        "The verdict panel was repaired; see the verdict column. Why the "
        "verdict is suspicious rather than clean.",
        "The verdict is suspicious, scored on a scale of one to ten.",
        "YARA 28 rule hits and Capa 32 capability rules fired on this sample.",
        "| Source | Verdict |\n|---|---|\n| yara | malicious |",
    ]
    for text in prose:
        assert not hs._PANEL_RE.search(text), (
            f"matched prose that does not state its own verdict: {text[:70]}")


def test_the_verdict_vocabulary_matches_the_verdict_engine():
    """Two lists of what a verdict can be is how they drift apart."""
    hs = _reader()
    src = resolve("revai/v2_lib.py").read_text(encoding="utf-8", errors="replace")
    # calibrate_verdict's accepted set, read from the engine rather than restated
    for word in ("malicious", "suspicious", "benign", "unknown"):
        assert word in src, (
            f"{word} is not a verdict the engine accepts, so the panel reader "
            "must not treat it as one either")
    for word in hs._VERDICT_VOCAB:
        assert word.replace("_", " ") in src or word in src, (
            f"{word} is in the reader's vocabulary but not the engine's")
