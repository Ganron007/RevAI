#!/usr/bin/env python3
"""The skills layer: cited procedures the agent LOADS, never recalls.

These tests pin the property that makes skills different from prompt prose. Prompt
prose is re-summarised by the model and the summary drifts — that is the exact
mechanism behind #42 (indicators no tool observed) and #35 (report prose drifting
from the check). A skill is a file with a version and cited sources, so a gate can
check it and a report can cite it.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

import skills  # noqa: E402

EXPECTED = ("re-methodology", "unpack-and-verify", "obfuscation-recognition",
            "ghidra-sql-recipes", "verdict-calibration")


def test_the_five_approved_skills_all_exist():
    assert sorted(skills.list_skills()) == sorted(EXPECTED), skills.list_skills()


def test_the_index_carries_exactly_one_line_per_skill():
    text = skills.skill_index_text()
    for name in EXPECTED:
        assert f"`{name}`" in text, f"{name} missing from the prompt index"
    assert text.count("\n") + 1 == len(EXPECTED)


def test_every_skill_has_a_manifest_with_coverage_accounting():
    """A skill must say what it does NOT cover.

    Without that, "the skill was silent" is indistinguishable from "no source
    existed" — the coverage-accounting principle, and the same shape as the
    evidence-pack gap that produced #42.
    """
    for name in EXPECTED:
        s = skills.load_skill(name)
        assert s["covers"], f"{name}: no covers declared"
        assert s["does_not_cover"], f"{name}: no does_not_cover declared"
        assert s["body"].strip(), f"{name}: empty body"
        assert s["version"], f"{name}: no version"


def test_every_skill_ships_sources_and_states_their_status():
    """Provenance always — and the citation status is declared, not implied.

    A repo-derived skill honestly records that it has no external citations;
    a KB-derived one records the ranges. Either way the reader must not mistake
    a citation for a resolvable link in a public repo.
    """
    for name in EXPECTED:
        s = skills.load_skill(name)
        assert s["sources"], f"{name}: no sources.jsonl"
        assert s["attribution"], f"{name}: no attribution note"
        for src in s["sources"]:
            assert "rel_path" in src or "files" in src, src


def test_every_skill_body_states_its_attribution_note():
    """The "not resolvable in this repo" caveat must be in the skill, not only
    in the loader — a reader who opens SKILL.md directly is the one most likely
    to treat a citation as a link.

    Whitespace-normalised before matching: the note is prose and wraps, so an
    exact single-line match would fail on a wrapped paragraph and pass on a
    single-line one — which is a test bug, not a skill defect.
    """
    for name in EXPECTED:
        body = " ".join(skills.load_skill(name)["body"].split())
        states_unresolvable = ("not resolvable in this public repository"
                              in body)
        states_repo_derived = ("no external citations" in body
                               or "this skill is derived from" in body.lower())
        assert states_unresolvable or states_repo_derived, (
            f"{name}: the body does not declare whether its citations resolve here")


def test_unknown_skill_raises_rather_than_falling_back():
    """A silent empty skill is how a hollow-success run happens here too."""
    try:
        skills.load_skill("definitely-not-a-skill")
    except KeyError:
        return
    raise AssertionError("an unknown skill must raise, not return empty")


def test_citation_is_emittable_and_honest_about_being_unresolvable():
    for name in EXPECTED:
        cite = skills.skill_citation(name)
        assert name in cite and "provenance" in cite, cite


def test_citation_for_an_unknown_skill_is_empty_not_broken():
    """A report must omit a citation rather than emit a broken one."""
    assert skills.skill_citation("nope") == ""


def test_name_is_sanitised_so_a_path_cannot_escaped():
    """`../../etc/passwd` must not become a path."""
    assert skills._read_skill_file("../../etc/passwd") is None
    assert skills._read_skill_file("..%2f..%2fetc") is None


def test_the_calibration_skill_restates_the_neutral_rule():
    """The contract is load-bearing and must survive extraction verbatim."""
    body = skills.load_skill("verdict-calibration")["body"]
    assert "NEUTRAL" in body
    assert "behavioural-intent evidence" in body


def test_the_unpack_skill_restates_the_honesty_rule():
    body = skills.load_skill("unpack-and-verify")["body"]
    assert "CLAIM, not an artifact" in body or "claim, not an artifact" in body.lower()


def test_the_skill_index_is_loaded_by_the_tool_registry():
    """S0's actual deliverable: the agent can load a skill on demand."""
    from deep_dive_agentic import TOOL_DESCRIPTIONS, ToolRegistry
    assert "load_skill" in TOOL_DESCRIPTIONS, (
        "load_skill has no description, so the agent cannot know it exists")
    assert "load_skill" in ToolRegistry().tools


def test_load_skill_returns_a_tool_shaped_result():
    from deep_dive_agentic import ToolRegistry
    reg = ToolRegistry()
    out = reg.tools["load_skill"]({"skill": "re-methodology"}, {})
    assert out["skill"] == "re-methodology"
    assert out["body"], "the tool returned no procedure"
    assert out["citation"], "the tool returned no citation"


def test_load_skill_error_paths_are_explicit():
    from deep_dive_agentic import ToolRegistry
    reg = ToolRegistry()
    bad = reg.tools["load_skill"]({"skill": "nope"}, {})
    assert "error" in bad and bad.get("available"), bad
    empty = reg.tools["load_skill"]({}, {})
    assert "error" in empty, empty