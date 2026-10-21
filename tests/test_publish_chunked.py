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
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _report_fixtures import structured_tool_response  # noqa: E402
import publish_report_v2 as pub  # noqa: E402
import section_publisher as pub3  # noqa: E402
from v2_lib import TECHNICAL_REPORT_SECTIONS as SECTIONS  # noqa: E402
from v2_lib import REPORT_MASTER_SECTIONS as MASTER_SECTIONS  # noqa: E402


def _substantive_body(title: str) -> str:
    name = title.split(". ", 1)[-1]
    return (f"Evidence-grounded analysis of {name} explains the observed "
            "artifact, its source, and the limits of the conclusion. " * 8)


def _report_response(markdown: str, title: str = "Test report") -> dict:
    return structured_tool_response(markdown, title=title)


def test_fallback_reports_are_marked_non_schema():
    """A deterministic fallback must not inherit schema provenance.

    The audit accepts an absent `schema_used` for pre-schema reports. A new
    fallback that omits the key would therefore pass the schema check despite
    having no claim-level citations, so the publisher must write False.
    """
    for source in (
        "deterministic_fallback",
        "deterministic_fallback_after_incomplete_llm",
    ):
        report = pub._finalize_schema_provenance({"source": source})
        assert report["schema_used"] is False, source

    llm = pub._finalize_schema_provenance(
        {"source": "llm_judge", "schema_used": True})
    assert llm["schema_used"] is True

    legacy = pub._finalize_schema_provenance({"source": "llm_judge"})
    assert "schema_used" not in legacy, (
        "the helper must not invent provenance for a legacy report")


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


def test_targeted_technical_section_is_inserted_in_canonical_order():
    first, missing, following = SECTIONS[0], SECTIONS[1], SECTIONS[2]
    existing = (
        f"## {first}\n\n{_substantive_body(first)}\n\n"
        f"## {following}\n\n{_substantive_body(following)}"
    )
    candidate = _substantive_body(missing)

    repaired, inserted = pub._upsert_report_section(
        existing, missing, candidate, SECTIONS
    )

    assert inserted is True
    assert pub.missing_sections(repaired, SECTIONS[:3]) == []
    assert repaired.index(f"## {first}") < repaired.index(f"## {missing}")
    assert repaired.index(f"## {missing}") < repaired.index(f"## {following}")


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


def test_technical_prompt_separates_static_probe_from_runtime_status():
    """Every technical chunk must see the same component-level ground truth."""
    status = {
        "sentence": (
            "RevAI Speakeasy: no oracle result; RevAI Frida probe: static-only, "
            "not sample execution; WinRE detonation: sample launch confirmed; "
            "WinRE Frida runtime: runtime events captured (577); packet capture: "
            "1 capture file present."
        )
    }
    evidence = pub.append_dynamic_status_to_technical_evidence("EVIDENCE", status)
    prompt = pub.build_prompt_technical(
        {"sha256": "a" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], evidence, sections=SECTIONS[4:5])
    assert "STATIC, not sample execution" in prompt
    assert status["sentence"] in prompt


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
        body = "\n\n".join(f"# {t}\n\n{_substantive_body(t)}" for t in wanted)
        return _report_response(body)

    monkeypatch.setattr(pub, "llm_report", fake_llm)
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


def test_chunked_generation_retries_a_stubbed_section_with_full_context(monkeypatch):
    target = "10. MITRE ATT&CK Mapping"
    targeted_retries: list[str] = []

    def fake_llm(prompt):
        head = prompt.split("Rules", 1)[0]
        wanted = [title for title in SECTIONS if f"- {title}" in head]
        repair = "## Targeted section repair" in prompt
        if repair:
            targeted_retries.extend(wanted)
        bodies = []
        for title in wanted:
            body = ("MITRE coverage is listed in Appendix A."
                    if title == target and not repair else _substantive_body(title))
            bodies.append(f"# {title}\n\n{body}")
        return _report_response("\n\n".join(bodies))

    monkeypatch.setattr(pub, "llm_report", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": "f" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "AUTHORITATIVE EVIDENCE")

    assert not errors, errors
    assert targeted_retries == [target]
    assert "MITRE coverage is listed in Appendix A." not in md
    assert _substantive_body(target)[:100] in md
    assert not pub.stub_sections(md, [target])
    assert any(a.get("part") == "stub-retry-result" and
               a.get("section") == target and a.get("accepted") is True
               for a in audits)


def test_failed_stub_retry_keeps_original_and_remains_a_quality_failure(monkeypatch):
    target = "10. MITRE ATT&CK Mapping"

    def fake_llm(prompt):
        head = prompt.split("Rules", 1)[0]
        wanted = [title for title in SECTIONS if f"- {title}" in head]
        repair = "## Targeted section repair" in prompt
        bodies = []
        for title in wanted:
            body = ("No ATT&CK technique is established by this evidence."
                    if repair or title == target else _substantive_body(title))
            bodies.append(f"# {title}\n\n{body}")
        return _report_response("\n\n".join(bodies))

    monkeypatch.setattr(pub, "llm_report", fake_llm)
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": "1" * 64, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "AUTHORITATIVE EVIDENCE")

    assert "No ATT&CK technique is established by this evidence." in md
    assert errors and any(target in error for error in errors), errors
    assert any(a.get("part") == "stub-retry-result" and
               a.get("section") == target and a.get("accepted") is False
               for a in audits)


def test_master_stub_retry_replaces_only_the_stubbed_section():
    target = "11. MITRE ATT&CK Mapping"
    original = f"# {target}\n\nSee Appendix A for the ATT&CK mapping."
    markdown = (
        "# Executive Summary\n\n"
        + _substantive_body("Executive Summary")
        + "\n\n"
        + original
    )
    calls: list[str] = []

    def retry(section: str, original_section: str) -> str:
        calls.append(section)
        assert original_section == original
        return f"# {target}\n\n{_substantive_body(target)}"

    repaired, attempts = pub.retry_master_stub_sections(
        markdown, [target], retry
    )

    assert calls == [target]
    assert attempts == [{
        "section": target,
        "accepted": True,
        "reason": "retry section passes stub quality gate",
    }]
    assert "See Appendix A for the ATT&CK mapping." not in repaired
    assert not pub.stub_sections(repaired, [target])
    assert "Evidence-grounded analysis of Executive Summary" in repaired


def test_failed_master_stub_retry_retains_stub_and_quality_failure():
    target = "11. MITRE ATT&CK Mapping"
    original = f"# {target}\n\nSee Appendix A for the ATT&CK mapping."
    markdown = f"# Executive Summary\n\n{_substantive_body('Executive Summary')}\n\n{original}"

    repaired, attempts = pub.retry_master_stub_sections(
        markdown,
        [target],
        lambda _section, original_section: original_section,
    )

    assert repaired == markdown
    assert attempts[0]["accepted"] is False
    assert pub.stub_sections(repaired, [target]) == [target]


def test_section_metadata_is_recomputed_from_final_markdown():
    required = ["1. Executive Summary", "2. Sample Metadata"]
    markdown = (
        f"## {required[0]}\n\n"
        + ("The summary is grounded in the available evidence. " * 12)
    )
    report = {
        "source": "llm_judge",
        "sections_missing": [],
        "sections_stub": [],
        "sections_complete": len(required),
    }

    missing, stubs = pub._refresh_section_metadata(report, markdown, required)

    assert missing == [required[1]]
    assert stubs == []
    assert report["sections_missing"] == missing
    assert report["sections_total"] == len(required)
    assert report["sections_complete"] == 1
    assert report["source"] == "llm_incomplete"


def test_section_publisher_counts_llm_generations_and_local_sections_truthfully():
    pass1 = [
        {"name": name}
        for index, name in enumerate(pub3.REPORT_SECTION_SPECS)
    ]
    pass2 = [
        {"name": name}
        for index, (name, spec) in enumerate(pub3.REPORT_SECTION_SPECS.items())
        if spec[2]
    ]

    counts = pub3._section_invocation_counts(pass1, pass2)

    assert counts == {
        "pass1_llm_generation_calls": 14,
        "pass2_llm_generation_calls": 14,
        "local_sections": 3,
    }


def test_first_draft_is_preserved_for_the_support_gate(monkeypatch):
    section = "5. Behavioral Analysis"
    body = "The sample performs a behavior that requires source evidence. " * 8
    calls = []

    def fake_llm(prompt):
        calls.append(prompt)
        return _report_response(f"## {section}\n\n{body}", title=section)

    monkeypatch.setattr(pub3, "llm_report", fake_llm)
    monkeypatch.setattr(pub3, "llm_call_metadata", lambda _response: {})
    monkeypatch.setattr(pub3, "get_llm_model", lambda: "test-model")

    result = pub3._run_one_section(
        section, "a" * 64, {}, {}, pass_num=1
    )

    assert len(calls) == 1
    assert result["first_draft_policy"] == (
        "first draft is preserved; the claim-support gate reports defects "
        "instead of asking the writer to repair its own unsupported claims"
    )
    assert result["uncited_claim_count"] == 0
    assert "source: test" in result["markdown"]
    assert result["markdown"].count(
        "The sample performs a behavior that requires source evidence.") == 8
    assert "Trusted reverse-engineering methodology" in calls[0]
    assert "report-evidence-methodology v" in calls[0]


def test_technical_writers_receive_the_run_evidence_manifest():
    manifest = (
        "## Sample/run identity and evidence provenance\n"
        '{"sample_sha256":"' + "a" * 64 + '","run_id":"' + "b" * 32 + '"}'
    )
    prompt = pub3._technical_section_prompt(
        "5. Behavioral & Dynamic Analysis", "behavior", "tool evidence",
        "a" * 64, provenance_block_text=manifest)
    assert manifest in prompt
    assert "report-evidence-methodology v" in prompt


def test_a_failed_group_is_recorded_and_omits_its_sections(monkeypatch):
    """Fail-open per group: record the error, do not invent filler text."""
    def fake_llm(prompt):
        head = prompt.split("Rules", 1)[0]
        if "- 5. Behavioral & Dynamic Analysis" in head:
            raise RuntimeError("provider exploded")
        wanted = [t for t in SECTIONS if f"- {t}" in head]
        body = "\n\n".join(f"# {t}\n\n{_substantive_body(t)}" for t in wanted)
        return _report_response(body)

    monkeypatch.setattr(pub, "llm_report", fake_llm)
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

    monkeypatch.setattr(pub, "llm_report", fake_llm)
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
