#!/usr/bin/env python3
"""#14d calibration regression: the three real false-positive classes.

Every sentence in MD below is lifted from a published, human-reviewed case study in
docs/case-studies/. Each one flagged under some earlier version of the check; the
fixed classifier must record none of them as a contradiction.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from report_quality import (  # noqa: E402
    _classify_sentence,
    verify_behavior_prerequisites,
)

# Real sentences, with the case they came from.
CORPUS_SENTENCES = [
    # agentic/pool-large-darkgate - denial of specificity while claiming the behaviour
    ("While `RegSetValue` is imported, the exact registry key path and value written "
     "for persistence was not extracted from static analysis.", "detail"),
    # agentic/lumma-stealer - same shape
    ("While registry manipulation capabilities are confirmed, no specific registry "
     "keys, values, or autostart locations were identified in static analysis.", "detail"),
    # agentic/pool-mid-vidar
    ("Registry access is confirmed, but no specific persistence keys, values, or "
     "scheduled tasks were extracted without unpacking.", "detail"),
    # agentic/pool-mid-quasar - dynamic-observation denial, not an existence denial
    ("No runtime network traffic, process injection, or persistence actions were "
     "observed.", "detail"),
    # scripted/space1-flawedammyy - hypothetical affirmation, not a denial
    ("In a real-world scenario without analysis tools, it would likely proceed to "
     "decrypt its payload, inject code, and establish persistence.", "claim"),
    # scripted/ghyte - the report denying a behaviour the evidence confirms absent
    ("| Persistence (Run keys, services) | No | No registry or service imports | High |",
     "negated"),
    # scripted/ghyte - catalogue vocabulary
    ("- **note**: Per-family persistence catalog (Maldev/Mandiant cheat sheet); "
     "spoof suspects need memory-cmdline confirmation (post_mortem)", "catalogue"),
    # scripted/ghyte - explicit "no mapping for" list (legend, not a claim)
    ("There is no mapping for C2 (T1071, T1105, T1195, etc.), persistence (T1547, "
     "T1053, etc.), credential access (T1003, T1555, etc.).", "catalogue"),
]

# The ghyte import map: `pe_imports` reported signal_count 0, so the report's
# "no registry or service imports" denial is corroborated by the evidence. Only
# injection APIs are present here, which is what makes the denial legitimate.
SURFACE = "createremotethread\nwriteprocessmemory"


def test_every_corpus_sentence_classifies_as_recorded():
    for sentence, expected in CORPUS_SENTENCES:
        got = _classify_sentence(sentence)
        assert got == expected, f"{expected} expected, got {got}: {sentence[:70]}"


def test_no_corpus_sentence_produces_a_contradiction():
    md = "\n".join(s for s, _ in CORPUS_SENTENCES)
    result = verify_behavior_prerequisites(md, SURFACE)
    assert result["unsupported"] == 0, result["unsupported_items"]
    assert result["contradictions"] == []
    # the denials are still *counted*, so the reader can see the work happened
    assert result["negated_mentions"] >= 1
    assert result["catalogue_mentions"] >= 1
    assert result["detail_mentions"] >= 3


def test_real_claim_against_a_real_map_stays_advisory():
    """Uncorroborated is recorded, never a gate failure (absence != proof)."""
    md = ("Static analysis confirms process injection, downloader, persistence, "
          "keylogging, and sandbox evasion capabilities.")
    result = verify_behavior_prerequisites(md, SURFACE)
    assert result["unsupported"] == 0
    assert result["uncorroborated"] >= 1
    assert result["advisory"] is True
