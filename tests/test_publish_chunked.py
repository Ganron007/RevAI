#!/usr/bin/env python3
"""The chunked technical report must tile, order and fail safely.

Motivation (2026-10-01): one monolithic technical-report call cannot serve every
sample. The configured provider never returns a response that would exceed ~16K
output tokens -- it hangs until the socket timeout -- so win32k_dll's report
burned 600 s, then 1200 s, and still landed on stubs. The fix generates the
report as several bounded calls, which is the pattern publish v3 already uses.

Two bugs were found by writing these tests rather than by reading the code:
  - the first group boundaries were (2,5),(5,8),(7,11), so section 8 was in two
    groups and would have been written twice;
  - the first assembly appended the body before the wrap, which would have
    emitted the Executive Summary after the findings it summarises.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import publish_report_v2 as pub  # noqa: E402
from v2_lib import TECHNICAL_REPORT_SECTIONS as SECTIONS  # noqa: E402


def test_groups_tile_every_section_exactly_once():
    """No section may be written twice, and none may be dropped."""
    covered: list[int] = []
    for a, b in pub.TECHNICAL_BODY_GROUPS:
        covered += list(range(a, b))
    covered += list(range(*pub.TECHNICAL_WRAP_RANGE))
    covered += list(range(*pub.TECHNICAL_TAIL_RANGE))

    assert len(covered) == len(SECTIONS), (
        f"covered {len(covered)} of {len(SECTIONS)} sections")
    dupes = sorted({i for i in covered if covered.count(i) > 1})
    assert not dupes, f"sections written more than once: {dupes}"
    missing = sorted(set(range(len(SECTIONS))) - set(covered))
    assert not missing, f"sections never written: {missing}"


def test_body_groups_are_contiguous_and_in_order():
    body = list(pub.TECHNICAL_BODY_GROUPS)
    assert body[0][0] == 2, "body should start at the first analytical section"
    for (_, prev_end), (next_start, _) in zip(body, body[1:]):
        assert next_start == prev_end, (
            f"body groups must tile without a gap or overlap: {body}")
    assert body[-1][1] <= pub.TECHNICAL_TAIL_RANGE[0], (
        "the body must stop before the tail groups start")


def test_evidence_dense_sections_each_get_their_own_call():
    """Sections 3-5 overflowed when grouped together on win32k_dll.

    That group returned nothing at all while its neighbours produced ~29K chars
    each, so the density is per-section, not a general size problem. Asserted so
    a future "simplify the grouping" change cannot silently reintroduce it.
    """
    singles = {a for a, b in pub.TECHNICAL_BODY_GROUPS if b - a == 1}
    for idx in (2, 3, 4):          # File Layout, Static Code Analysis, Behavioural
        assert idx in singles, (
            f"section {SECTIONS[idx]!r} must have its own call; got "
            f"{pub.TECHNICAL_BODY_GROUPS}")


def test_prompt_for_a_subset_asks_only_for_that_subset(monkeypatch):
    """A chunk call must not ask for headings it is not going to write."""
    titles = SECTIONS[2:5]
    prompt = pub.build_prompt_technical(
        {"sha256": "a" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", sections=titles)
    head = prompt.split("Rules", 1)[0]
    for t in titles:
        assert t in head, f"{t} missing from the chunk heading list"
    for t in SECTIONS[5:]:
        assert t not in head, f"{t} must not be requested by this chunk"
    assert "ONE PART of a larger report" in prompt


def test_full_prompt_still_requests_every_section():
    prompt = pub.build_prompt_technical(
        {"sha256": "a" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE")
    head = prompt.split("Rules", 1)[0]
    for t in SECTIONS:
        assert t in head, f"{t} missing from the monolithic heading list"
    assert "ONE PART of a larger report" not in prompt


def test_prior_sections_context_is_included_when_supplied():
    prompt = pub.build_prompt_technical(
        {"sha256": "a" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE", sections=SECTIONS[0:2],
        prior_sections_md="## 5. Behavioral\nreal body text")
    assert "real body text" in prompt
    assert "Earlier sections of THIS report" in prompt


def test_chunked_generation_orders_document_and_records_audits(monkeypatch):
    """Front matter leads, appendices trail, and every call is audited."""
    calls: list[tuple[list[str], dict]] = []

    def fake_llm(prompt):
        # figure out which headings this chunk was asked for
        head = prompt.split("Rules", 1)[0]
        wanted = [t for t in SECTIONS if f"- {t}" in head]
        calls.append((wanted, {"prompt": prompt}))
        body = "\n\n".join(f"# {t}\n\ncontent for {t}" for t in wanted)
        return {"choices": [{"message": {"content": json.dumps(
            {"markdown": body})}}]}

    monkeypatch.setattr(pub, "llm_judge", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": "b" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE")

    assert not errors, errors
    assert len(audits) == len(pub.TECHNICAL_BODY_GROUPS) + 2, (
        f"expected one audit per call, got {len(audits)}")

    # document order: section 1 before section 3, section 13 last
    pos = {t: md.find(f"# {t}") for t in SECTIONS}
    assert all(v >= 0 for v in pos.values()), f"missing sections: {pos}"
    order = [pos[t] for t in SECTIONS]
    assert order == sorted(order), (
        "sections are not in document order -- the Executive Summary must lead "
        f"and the appendices must trail: {order}")

    # the wrap call must have seen the body it summarises
    assert any("Earlier sections of THIS report" in d["prompt"]
               for _, d in calls), (
        "no call received prior-section context; the summary would be guessed")


def test_a_failed_group_is_recorded_and_omits_its_sections(monkeypatch):
    """Fail-open per group: record the error, do not invent filler text."""
    def fake_llm(prompt):
        head = prompt.split("Rules", 1)[0]
        if "- 5. Behavioral & Dynamic Analysis" in head:
            raise RuntimeError("provider exploded")
        wanted = [t for t in SECTIONS if f"- {t}" in head]
        body = "\n\n".join(f"# {t}\n\ncontent for {t}" for t in wanted)
        return {"choices": [{"message": {"content": json.dumps(
            {"markdown": body})}}]}

    monkeypatch.setattr(pub, "llm_judge", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": "c" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE")

    assert errors, "a failed group must be recorded"
    assert "provider exploded" in errors[0]
    assert "# 5. Behavioral & Dynamic Analysis" not in md
    # the other sections still landed
    assert "# 1. Executive Summary" in md
    assert "# 13. Appendix B: Analysis Environment" in md


def test_total_failure_raises_so_the_caller_can_fall_back(monkeypatch):
    """If every call fails the caller must get an exception, not a stub report."""
    def fake_llm(prompt):
        raise RuntimeError("all calls fail")

    monkeypatch.setattr(pub, "llm_judge", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": "d" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE")
    # Every section must be accounted for. The exact error count depends on the
    # split-retry layer -- a group that fails is retried per section, so one
    # group can log several entries -- so assert coverage, not a total.
    for title in SECTIONS:
        assert any(title in e for e in errors), (
            f"no error names {title!r}: {errors}")
    assert any("all calls fail" in e for e in errors), errors
    assert not md.strip(), "no content should be produced when all calls fail"
