"""Regression tests for RC-112 prompt/artifact parity and deterministic builders."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "revai"))

import publish_report_v2 as P  # noqa: E402
import report_quality as Q  # noqa: E402
import v2_lib as V  # noqa: E402


def test_summarize_row_prevents_mid_description_sentence_split():
    row = {
        "name": "HugeFunctionGapAtSectionBoundary",
        "desc": (
            "There is a huge gap between start/end of executable section "
            "(which is not a know structure). It often means that data is stored there"
        ),
        "dll": "mscoreei.dll",
        "ver": "v4.0.30319",
        "ip": "192.168.77.43",
        "entropy": "7.51",
    }
    summary = V._summarize_row(row, limit=500)
    assert "). It " not in summary
    assert "structure); It often" in summary
    assert "mscoreei.dll" in summary
    assert "v4.0.30319" in summary
    assert "192.168.77.43" in summary
    assert "7.51" in summary

    manifest = (
        "**Anomalies** — `deep_dive/01-tools-raw.json` at `payload_feedback.tools.malcat.views.anomalies`:\n"
        f"- [`payload_feedback.tools.malcat.views.anomalies[6]`] {summary}\n"
    )
    embedded = P._cited_manifest_embed(manifest)
    assert Q.uncited_report_claims(embedded) == []


def test_deterministic_master_key_evidence_cites_deep_dive_when_present():
    session = {"sha256": "a" * 64, "sample_path": "/tmp/s.vir", "file_type": {}}
    verdict = {
        "verdict": "Suspicious",
        "key_evidence": [{"source": "malcat", "row_or_rule": "UPX"}],
    }
    deep = {
        "summary": "Packed sample.",
        "confidence": 90,
        "key_evidence": [{"source": "yara_scan", "row_or_rule": "domain"}],
    }
    sec = P._master_deterministic_sections_map(
        session, verdict, deep, {}, {}, reason="test"
    )
    static_md = sec["4. Static Analysis"]
    assert "deep_dive/05-deep-dive.json" in static_md
    assert "query_or_table: verdict.json" not in static_md

    # Fallback to verdict.json when deep has no key_evidence.
    sec_fb = P._master_deterministic_sections_map(
        session, verdict, {"summary": "Only summary."}, {}, {}, reason="test"
    )
    assert "query_or_table: verdict.json" in sec_fb["4. Static Analysis"]


def test_build_prompt_preserves_status_wrapper_and_exact_paths():
    prompt = P.build_prompt_full(
        {"sha256": "b" * 64, "sample_path": "/tmp/s.vir", "project_name": "p"},
        verdict={"verdict": "Suspicious", "summary": "ok"},
        deep={"verdict": "malicious", "summary": "deep"},
        yara_meta={},
        audit=[],
        upx={"upx_ok": True, "unpacked_path": "/tmp/u"},
        xor_hits={"candidates": ["abc"]},
        dotnet_result={"is_dotnet": False},
        dynamic_status={"emulation": {"present": True}, "winre": {"detonation_ran": True}},
        sections=["Executive Summary"],
    )
    assert "## Evidence — deep_dive/05-deep-dive.json" in prompt
    assert "## Evidence — deep-dive.json" not in prompt
    assert "deep_dive/01-tools-raw.json, cite exact fields under $.upx.*" in prompt
    assert "deep_dive/01-tools-raw.json, cite exact fields under $.xor.*" in prompt
    assert "deep_dive/01-tools-raw.json, cite fields under $.dotnet.*" in prompt
    # dynamic_status JSON block in prompt must preserve the outer `"status"` wrapper
    assert '"status": {' in prompt


def test_build_deterministic_technical_no_name_error():
    md = P.build_deterministic_technical(
        {"sha256": "c" * 64, "sample_path": "/tmp/s.vir", "project_name": "p"},
        verdict={"verdict": "Suspicious", "score": 50, "family_guess": "unknown"},
        deep={"summary": "summary"},
        technical_evidence="INLINE_TECH_EV",
        reason="test",
    )
    assert "INLINE_TECH_EV" in md
    assert "deep_dive/05-deep-dive.json" in md


def test_dynamic_analysis_section_no_nonexistent_hook_count_fields():
    pack = {
        "present": True,
        "dynamic_stage": {"ran": True},
        "frida_summary": {
            "status": "ok",
            "hook_coverage": {
                "state": "partial",
                "requested": ["CreateFileW"],
                "installed": ["CreateFileW"],
                "unavailable": [],
                "calls_observed": 10,
                "max_calls": 100,
                "call_limit_reached": False,
                "process_coverage_complete": False,
                "process_count": 1,
            },
        },
        "frida_trace": {"status": "valid", "record_count": 10, "attributed_call_count": 10, "invocations": []},
    }
    rendered = V.format_dynamic_analysis_section(pack)
    assert "requested_count" not in rendered
    assert "installed_count" not in rendered
    assert "unavailable_count" not in rendered
    assert "status.frida_runtime.hook_coverage.installed" in rendered
