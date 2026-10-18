"""The report quality gate must fail closed when claim review cannot run."""
from __future__ import annotations

import sys
import json
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import add_module_dir  # noqa: E402

add_module_dir("revai/report_quality.py")
add_module_dir("revai/entailment.py")

import entailment  # noqa: E402
import report_quality  # noqa: E402


def test_entailment_checker_exception_is_a_quality_failure(tmp_path, monkeypatch):
    sha = "c" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "REPORT-MASTER-v2.md").write_text(
        "# Executive Summary\n\n" + "A sufficiently long sample summary. " * 100,
        encoding="utf-8",
    )

    def unavailable(*_args, **_kwargs):
        raise TimeoutError("claim review timed out")

    monkeypatch.setattr(entailment, "check_report_entailment", unavailable)
    result = report_quality.evaluate_sha_publish_quality(
        tmp_path / "logs", sha, case_root=case)

    claim_check = result["checks"]["claim_entailment"]
    assert claim_check["ok"] is False
    assert claim_check["status"] == "error"
    assert "claim_entailment:error" in result["issues"]


def test_short_factual_assertion_is_not_exempt_from_citation():
    assert report_quality.uncited_report_claims("No C2 observed.") == [
        "No C2 observed."]


def test_table_source_cell_alone_does_not_ground_a_row():
    markdown = (
        "| Behavior | Evidence |\n|---|---|\n"
        "| Sample started a process | Procmon |"
    )
    assert report_quality.uncited_report_claims(markdown) == [
        "| Sample started a process | Procmon |"]


def test_ioc_gate_checks_the_generated_draft_without_rewriting_it(tmp_path):
    evidence = tmp_path / "case"
    evidence.mkdir()
    (evidence / "iocs.json").write_text(
        '{"domains":["observed.example.com"]}', encoding="utf-8")
    draft = (
        "# Sample Findings\n\n"
        "The sample contacted http://invented.example.org/gate.\n"
    )

    result = report_quality.evaluate_report_markdown(
        draft,
        required_sections=[],
        source="llm_judge",
        min_total_chars=0,
        label="master_v2",
        evidence_root=evidence,
    )

    verification = result["claimed_ioc_verification"]
    assert verification["claims"] >= 1
    assert verification["unverified"] >= 1
    assert any("report:unverified_iocs:" in issue for issue in result["issues"])
    assert "invented.example.org" in draft
    assert result["ok"] is False


def test_ioc_gate_fails_closed_when_the_case_has_no_raw_evidence(tmp_path):
    result = report_quality.evaluate_report_markdown(
        "# Empty evidence\n\nNo indicators are claimed.",
        required_sections=[],
        source="llm_judge",
        min_total_chars=0,
        label="master_v3",
        evidence_root=tmp_path,
    )
    assert result["ok"] is False
    assert "master_v3:evidence_corpus_missing" in result["issues"]


def test_final_quality_checks_literal_iocs_in_all_four_report_files(
    tmp_path, monkeypatch
):
    sha = "d" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    (case / "iocs.json").write_text(
        '{"domains":["observed.example.com"]}', encoding="utf-8")
    files = {
        "REPORT-MASTER-v2.md": "http://master-v2-claim.evil.com/path",
        "REPORT-MASTER-v3.md": "http://master-v3-claim.evil.com/path",
        "REPORT-TECHNICAL-v2.md": "http://technical-v2-claim.evil.com/path",
        "REPORT-TECHNICAL-v3.md": "http://technical-v3-claim.evil.com/path",
    }
    for filename, claim in files.items():
        (case / filename).write_text(
            f"# Report\n\nObserved indicator: {claim}.", encoding="utf-8")
    for filename, payload in (
        ("report-v2.json", {"source": "llm_judge"}),
        ("report-technical-v2.json", {"source": "llm_judge"}),
        ("report-technical-v3.json", {"source": "llm_judge"}),
        ("section-results-v3.json", {"master_v3_quality": {"ok": True}}),
    ):
        (case / filename).write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(
        entailment, "check_report_entailment",
        lambda *_args, **_kwargs: {"ok": True, "status": "ok", "violations": []})
    result = report_quality.evaluate_sha_publish_quality(
        tmp_path / "logs", sha, case_root=case)

    verification = result["checks"]["claimed_ioc_verification"]
    assert set(verification) == {
        "master_v2", "master_v3", "technical_v2", "technical_v3"}
    for name in verification:
        assert verification[name]["unverified"] >= 1, name
    assert sum("report:unverified_iocs:" in issue for issue in result["issues"]) >= 4
