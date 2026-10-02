#!/usr/bin/env python3
"""The v3 technical report is generated one section per call, not one call total.

Measured 2026-10-01 on win32k_dll. The technical report asked a single
llm_judge call for all 13 sections. That request cannot fit one response -- the
largest successful call that run was 46,415 chars against a 16,384-token cap --
so it returned finish_reason=length after section 1, and every completeness
figure downstream described a stub:

    report-technical-v2.json  source=llm_judge               13/13
    report-technical-v3.json  source=deterministic_fallback   1/13

v2 was already section-wise, which is the entire difference between those rows.

What these tests protect, in priority order:

  1. ROUTING. Evidence is filtered per section. If routing is wrong the failure
     is silent and well-formed: a section gets the wrong evidence, or none, and
     the report still looks complete. So routing is asserted against the real
     34-heading evidence pack structure, not a happy-path stub.
  2. The per-section response stays SMALL. That is the whole point; a regression
     to one big prompt reintroduces the original truncation.
  3. The monolithic path remains reachable as a rollback lever.
  4. One failed section does not cost the other twelve.

Evidence blocks below are copied from the real EVIDENCE-BUNDLE.md headings.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import add_module_dir, source  # noqa: E402
add_module_dir("revai/section_publisher.py")

import section_publisher as sp  # noqa: E402

# Real headings from the win32k_dll EVIDENCE-BUNDLE.md, in order.
REAL_HEADINGS = [
    "## Verdict",
    "## Deep-Dive Summary Evidence",
    "## Malcat Structured Analysis",
    "### Malcat File Summary",
    "### File Layout (sections/regions)",
    "### Malcat YARA / Signatures (12)",
    "### Anomalies (10)",
    "### High-Signal Strings (21 matched keywords; engine=malcat)",
    "### Top Strings (300 extracted; showing 80)",
    "### Imports (192)",
    "### Functions (30)",
    "### Decompilations (top 6)",
    "### Virtual Files (8)",
    "### Structures (67)",
    "## capa Capability Rules",
    "## PE Imports / Signals",
    "## YARA Matches (pipeline)",
    "## Generated YARA Meta",
    "## FLOSS Strings",
]

REAL_EVIDENCE = "\n".join(
    f"{h}\nbody content for {h.lstrip('# ').strip()}\n" for h in REAL_HEADINGS)


def _blocks():
    return sp._split_evidence_blocks(REAL_EVIDENCE)


# ------------------------------------------------------------------ splitting

def test_split_preserves_every_heading_and_its_body():
    blocks = _blocks()
    heads = [h for h, _ in blocks]
    for h in REAL_HEADINGS:
        assert h in heads, f"lost heading {h}"
    for h, body in blocks:
        assert h in body, f"heading {h} not at top of its own block"
        assert "body content for" in body, h


def test_split_handles_empty_and_headless_input():
    assert sp._split_evidence_blocks("") == []
    assert sp._split_evidence_blocks("no headings at all") != []
    assert len(sp._split_evidence_blocks("no headings at all")) == 1


# -------------------------------------------------------------------- routing

def test_verdict_reaches_every_section():
    """A section written without the verdict is written blind."""
    for name in sp.TECHNICAL_REPORT_SECTIONS:
        ev = sp._technical_section_evidence(name, _blocks())
        assert "Verdict" in ev or "verdict" in ev.lower(), (
            f"{name} received no verdict evidence")


def test_static_analysis_gets_decompilation_and_imports():
    ev = sp._technical_section_evidence("4. Static Code Analysis", _blocks())
    assert "Decompilations" in ev
    assert "Imports (192)" in ev


def test_network_section_gets_network_evidence_not_decompilation():
    """Routing must actually exclude, not just include."""
    ev = sp._technical_section_evidence("6. Network Indicators & C2", _blocks())
    assert "Decompilations" not in ev, (
        "network section received decompilation evidence; routing is not "
        "filtering")


def test_detection_section_gets_yara():
    ev = sp._technical_section_evidence("9. Detection Engineering", _blocks())
    assert "YARA" in ev


def test_capabilities_section_gets_capa():
    ev = sp._technical_section_evidence("7. Capabilities Assessment", _blocks())
    assert "capa Capability Rules" in ev


def test_layout_section_gets_layout_and_structures():
    ev = sp._technical_section_evidence(
        "3. File Layout & Structural Analysis", _blocks())
    assert "File Layout" in ev
    assert "Structures (67)" in ev


def test_no_section_is_starved_of_all_evidence():
    """Every section gets something beyond the always-set verdict block."""
    for name in sp.TECHNICAL_REPORT_SECTIONS:
        ev = sp._technical_section_evidence(name, _blocks())
        body_lines = [ln for ln in ev.splitlines() if ln.strip()]
        assert len(body_lines) > 2, f"{name} received essentially no evidence"


def test_every_required_section_has_a_spec_and_description():
    for name in sp.TECHNICAL_REPORT_SECTIONS:
        assert name in sp.TECHNICAL_SECTION_EVIDENCE, f"no evidence spec: {name}"
        assert name in sp.TECHNICAL_SECTION_DESCRIPTIONS, f"no description: {name}"


def test_evidence_cap_is_enforced():
    """Without a cap, one section's gather could recreate the original bug."""
    huge = "\n".join(f"{h}\n{'x' * 5000}" for h in REAL_HEADINGS * 6)
    ev = sp._technical_section_evidence("4. Static Code Analysis",
                                       sp._split_evidence_blocks(huge))
    assert len(ev) <= sp._TECHNICAL_EVIDENCE_CAP + 500, len(ev)
    assert "truncated" in ev.lower(), "the cap must be disclosed, not silent"


# --------------------------------------------------------------------- prompt

def test_prompt_asks_for_one_section_and_carries_the_house_rules():
    p = sp._technical_section_prompt(
        "6. Network Indicators & C2", "desc", "evidence here", "a" * 64)
    assert "6. Network Indicators & C2" in p
    assert "Write ONLY" in p
    for rule in ("source:", "not observed", "EXPLAIN, DON'T DUMP",
                 "ASCII apostrophes only"):
        assert rule in p, f"lost rule: {rule}"
    assert "the rest" not in p.lower()


def test_prompt_forbids_abbreviated_indicators():
    """The winservices audit failure was an abbreviated registry path. The
    prompt must carry the rule that prevents it recurring."""
    p = sp._technical_section_prompt("8. Indicators of Compromise", "d", "e",
                                     "s" * 64)
    assert "FULL" in p and "..." in p


def test_prompt_records_absence_rather_than_inventing():
    p = sp._technical_section_prompt("5. Behavioral & Dynamic Analysis", "d",
                                     "", "s" * 64)
    assert "no evidence routed" in p
    assert "not observed" in p


# ------------------------------------------------------------------ behaviour

class _Resp:
    def __init__(self, content):
        self._c = content

    def __getitem__(self, k):
        msg = {"role": "assistant", "content": self._c}
        return [{"message": msg, "finish_reason": "stop"}]


def test_one_failing_section_does_not_lose_the_others(monkeypatch):
    # Section 8 is rendered deterministically from iocs.json and never reaches
    # the LLM, so the simulated failure has to be a different section.
    failing = "6. Network Indicators & C2"

    def fake(prompt, *a, **kw):
        # Take the title from the header line, not from the "Write ONLY the '...'"
        # sentence: "11. What We Don't Know" contains an apostrophe, so splitting
        # on quotes silently truncates the name and the fixture proves nothing.
        title = prompt.split("# Technical Report Section: ", 1)[1].splitlines()[0]
        if title == failing:
            raise RuntimeError("simulated section failure")
        return _Resp(json.dumps({"title": title,
                                "markdown": f"## {title}\n\nsubstantive body",
                                "source": "llm_judge"}))

    monkeypatch.setattr(sp, "llm_judge", fake)
    monkeypatch.setattr(sp, "llm_call_metadata", lambda r: {})
    monkeypatch.setattr(sp, "get_llm_model", lambda: "m")

    results, md = sp.generate_technical_sectionwise("b" * 64, REAL_EVIDENCE,
                                                    parallel=False)
    assert len(results) == len(sp.TECHNICAL_REPORT_SECTIONS)
    failed = [r["name"] for r in results if not r["llm_ok"]]
    assert failed == [failing], failed
    # The other twelve are still real sections in the output.
    for name in sp.TECHNICAL_REPORT_SECTIONS:
        if name not in failed:
            assert f"## {name}" in md, f"{name} absent from assembled markdown"


def test_section_8_never_calls_the_llm(monkeypatch):
    """The whole point: an indicator no engine produced cannot be authored."""
    def explode(*a, **kw):
        raise AssertionError("section 8 must not reach the LLM")

    monkeypatch.setattr(sp, "llm_judge", explode)
    blocks = sp._split_evidence_blocks(REAL_EVIDENCE)
    r = sp._generate_technical_section("8. Indicators of Compromise", blocks,
                                       "", "a" * 64)
    assert r["llm_ok"] is True
    assert r.get("deterministic") is True
    assert r.get("error") is None
    assert "## 8. Indicators of Compromise" in r["markdown"]


def test_section_8_is_included_in_the_assembled_report(monkeypatch):
    monkeypatch.setattr(sp, "llm_judge", lambda *a, **k: _Resp(
        json.dumps({"title": "t", "markdown": "## t\n\nbody"})))
    monkeypatch.setattr(sp, "llm_call_metadata", lambda r: {})
    monkeypatch.setattr(sp, "get_llm_model", lambda: "m")
    _results, md = sp.generate_technical_sectionwise("b" * 64, REAL_EVIDENCE,
                                                     parallel=False)
    assert "## 8. Indicators of Compromise" in md


def test_sectionwise_is_the_default_and_the_rollback_flag_works(monkeypatch):
    monkeypatch.delenv("REVAI_TECHNICAL_SECTIONWISE", raising=False)
    assert sp._technical_sectionwise_enabled() is True
    for val in ("0", "false", "no", "off", "OFF"):
        monkeypatch.setenv("REVAI_TECHNICAL_SECTIONWISE", val)
        assert sp._technical_sectionwise_enabled() is False, val


def test_results_are_returned_in_report_order():
    assert list(sp.TECHNICAL_SECTION_EVIDENCE) == sp.TECHNICAL_REPORT_SECTIONS, \
        "spec order must match report order so assembly is deterministic"
    assert list(sp.TECHNICAL_SECTION_DESCRIPTIONS) == \
        sp.TECHNICAL_REPORT_SECTIONS


def test_monolithic_block_is_still_present_as_rollback():
    """The rollback lever must not rot into a broken reference."""
    src = (ROOT / "revai" / "section_publisher.py").read_text(errors="replace")
    assert "You MUST produce markdown with ALL of these level-2 headings" in src
    assert "technical_assembly_retried" in src, (
        "the monolithic completeness retry must remain intact")