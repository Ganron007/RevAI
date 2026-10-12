#!/usr/bin/env python3
"""The Frida static probe must be impossible to narrate as a runtime execution.

Found 2026-10-12 on msil_crypt_dotnet (scripted): the technical report claimed
"Frida probing (version 17.18.0) with a hook on `mscoree.dll!_CorExeMain` ran
but observed no runtime events" — a dynamic execution that never happened. The
tool that produced the cited rows is `frida_static_probe`: Frida availability
plus PE import-derived hook CANDIDATES, no injection, no execution. The
cross-report gate caught it (correctly — the run went red); this pins the
structural fix so the evidence itself cannot invite the misreading again.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import resolve, source  # noqa: E402

import v2_lib  # noqa: E402


def test_frida_static_probe_output_labels_itself_static():
    """Both exit paths (frida-tools present or absent) must carry the labels.

    The labels are the fix: the report author cites this dict, so the dict has
    to say, in its own keys, that nothing was executed. A reader who cites
    `probe_kind`/`executed` cannot honestly write "ran".
    """
    out = v2_lib.frida_static_probe(str(resolve("README.md")))
    assert out.get("probe_kind") == "static", out
    assert out.get("executed") is False, out
    assert out.get("runtime_events") is None, out
    note = str(out.get("note", "")).lower()
    assert "no injection" in note and "was executed" in note, out
    assert "no runtime events" in note, out
    assert "candidates" in note, out


def test_behavioral_evidence_renders_the_static_probe_honestly():
    """The evidence-pack line must not read like a runtime probe report.

    The old line rendered `Frida probe: N hooked calls` — from a key the
    static probe never produces, so it always printed 0, which reads as "a
    probe ran and hooked nothing". That sentence is what the model turned
    into "Frida probing ... ran but observed no runtime events".
    """
    payload = {
        "deep": {
            "behavioral": {
                "speakeasy": {"total_api_calls": 3,
                              "api_calls": [{"dll": "kernel32", "name": "x",
                                             "count": 3}]},
                "frida_probe": {
                    "frida_available": True,
                    "frida_version": "17.18.0",
                    "pe_probe": {"hook_candidates": ["mscoree.dll!_CorExeMain"]},
                    "probe_kind": "static",
                    "executed": False,
                    "runtime_events": None,
                },
            }
        }
    }
    text = v2_lib._sec_behavioral_evidence(payload)
    assert "hooked calls" not in text, (
        "the Frida line still reads like a runtime probe report: " + text)
    assert "static analysis only" in text, text
    assert "no execution" in text, text
    assert "1 hook candidate" in text, text
    # The Speakeasy half of the same section must keep rendering.
    assert "Speakeasy: 3 API calls" in text, text


def test_registry_description_says_the_probe_never_runs_the_sample():
    """The deep-dive agent's own tool description must say it too."""
    src = source("revai/deep_dive_agentic.py")
    marker = '"frida_static_probe": "Run Frida STATIC probe'
    assert marker in src, (
        "the frida_static_probe registry description lost its STATIC/no-"
        "execution wording")
    line = src.split(marker, 1)[1].split('",', 1)[0]
    assert "no execution" in line.lower(), line
