"""Regression pins for RC-110, audit-tail routing, verdict panel calibration,
and static-probe-scoped Frida absence checks."""
from __future__ import annotations

import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/entailment.py").parent))
import entailment as E  # noqa: E402
import report_quality as RQ  # noqa: E402
import v2_lib  # noqa: E402


SHA = "f" * 64


def test_rc110_tools_raw_container_citation_resolves_malcat_and_bare_paths(tmp_path):
    case = tmp_path / "logs" / SHA / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "malcat": {
            "views": {
                "strings": [
                    {"ea": 38117, "summary": "ADVAPI32.DLL"},
                    {"ea": 38104, "summary": "KERNEL32.DLL"},
                ],
                "anomalies": [
                    {"name": "CrossSectionJump", "category": "cfg"},
                ],
            },
            "carved_files": [
                {"ea": 80896, "offset": 73728, "size": 34816, "type": "PE"},
            ],
        },
        "capa": {"top_rules": [{"name": "packed with UPX"}]},
        "payload_sql": {"functions": [{"addr": "4316832", "name": "start"}]},
    }), encoding="utf-8")

    for row in (
        "malcat.views.strings[0]",
        "malcat.views.anomalies[0]",
        "malcat.views.strings",
        "$.malcat.views.strings[1]",
    ):
        located, check = E._ground_citation({
            "source": "deep_dive/01-tools-raw.json",
            "query": "deep_dive/01-tools-raw.json",
            "row": row,
        }, case)
        assert located is not None, (row, check)
        assert check["status"] == "traceable-row", (row, check)

    # malcat.views.carved_files -> malcat.carved_files alias
    located_carved, check_carved = E._ground_citation({
        "source": "malcat",
        "query": "deep_dive/01-tools-raw.json",
        "row": "$.malcat.views.carved_files[0]",
    }, case)
    assert located_carved is not None, check_carved
    assert check_carved["status"] == "traceable-row", check_carved

    # deep_dive_agentic citing payload_sql inside 01-tools-raw.json
    located_psql, check_psql = E._ground_citation({
        "source": "deep_dive_agentic",
        "query": "deep_dive/01-tools-raw.json",
        "row": "$.payload_sql.functions[0].addr",
    }, case)
    assert located_psql is not None, check_psql
    assert check_psql["status"] == "traceable-row", check_psql

    # Negative bounds: cross-engine mismatch & unknown source must stay rejected
    cross_loc, cross_chk = E._ground_citation({
        "source": "capa",
        "query": "deep_dive/01-tools-raw.json",
        "row": "malcat.views.strings[0]",
    }, case)
    assert cross_loc is None, cross_loc
    assert cross_chk["status"] == "unresolved-row", cross_chk

    unk_loc, unk_chk = E._ground_citation({
        "source": "not_an_engine",
        "query": "deep_dive/01-tools-raw.json",
        "row": "malcat.views.strings[0]",
    }, case)
    assert unk_loc is None, unk_loc
    assert unk_chk["status"] == "unresolved-row", unk_chk

    abs_loc, abs_chk = E._ground_citation({
        "source": "deep_dive/01-tools-raw.json",
        "query": "deep_dive/01-tools-raw.json",
        "row": "malcat.views.strings[99]",
    }, case)
    assert abs_loc is None, abs_loc
    assert abs_chk["status"] == "unresolved-row", abs_chk


def test_audit_tail_manifest_and_dynamic_pack_routing(tmp_path):
    case = tmp_path / "logs" / SHA / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    (case / "publish").mkdir(parents=True)

    (case / "publish" / "report-input-manifest.json").write_text(json.dumps({
        "schema": "revai-report-input-manifest/v1",
        "sample_sha256": SHA,
        "run_id": "1" * 32,
        "artifacts": [
            {"path": "rule.yara.json", "status": "attested"},
        ],
    }), encoding="utf-8")

    (case / "deep_dive" / "02-dynamic-pack.json").write_text(json.dumps({
        "job_meta": {"sha256": SHA, "sample_pid": 432},
        "network": {"status": "ok", "pcaps": ["packets.pcap"]},
        "external_capture": {"pcap_sha256": "abc123", "packets_captured": 56},
        "network_intel": {
            "captures": [{"dns_queries": ["example.test"], "tls_sni": ["example.test"]}],
        },
        "procmon_summary": {"status": "ok", "rows_scanned": 1000},
        "procmon_sample_event_rows_selected": 1,
        "procmon_sample_events": [
            {"row": 658928, "operation": "RegSetValue", "pid": 432},
        ],
        "procmon_created_written_files_total": 1,
        "procmon_created_written_files": [{"path": "C:\\temp\\drop.exe"}],
        "dynamic_stage": {
            "detonation_ran": True,
            "findings": {
                "findings": {
                    "network": {"leads": [{"host": "example.test"}]},
                },
            },
        },
    }), encoding="utf-8")

    for src, q, row in (
        ("manifest", "revai-report-input-manifest/v1", "$.sample_sha256"),
        ("manifest", "revai-report-input-manifest/v1", "$.run_id"),
        ("manifest", "revai-report-input-manifest/v1", "$.artifacts[?(@.path=='rule.yara.json')]"),
        ("procmon", "deep_dive/02-dynamic-pack.json", "$.procmon_sample_event_rows_selected[?(@.row==658928)]"),
        ("winre_frida", "deep_dive/02-dynamic-pack.json", "$.procmon_sample_event_rows_selected[0]"),
        ("procmon", "deep_dive/02-dynamic-pack.json", "$.procmon_summary.procmon_created_written_files_total"),
        ("procmon", "deep_dive/02-dynamic-pack.json", "$.procmon_summary.procmon_created_written_files[0]"),
        ("winre:dynamic", "deep_dive/02-dynamic-pack.json", "$.network.external_capture.pcap_sha256"),
        ("winre:dynamic", "deep_dive/02-dynamic-pack.json", "$.network.network_intel.captures[0].dns_queries"),
        ("winre:dynamic", "deep_dive/02-dynamic-pack.json", "$.network.findings.leads[0]"),
        ("winre", "deep_dive/02-dynamic-pack.json", "$.job_meta.detonation_ran"),
    ):
        located, check = E._ground_citation({"source": src, "query": q, "row": row}, case)
        assert located is not None, (src, row, check)
        assert check["status"] == "traceable-row", (src, row, check)

    # Absent rows must still fail closed
    miss_loc, miss_chk = E._ground_citation({
        "source": "manifest",
        "query": "revai-report-input-manifest/v1",
        "row": "$.nonexistent_field",
    }, case)
    assert miss_loc is None
    assert miss_chk["status"] == "unresolved-row"

    miss_pm, miss_pm_chk = E._ground_citation({
        "source": "procmon",
        "query": "deep_dive/02-dynamic-pack.json",
        "row": "$.procmon_sample_event_rows_selected[?(@.row==999999)]",
    }, case)
    assert miss_pm is None
    assert miss_pm_chk["status"] == "unresolved-row"


def test_raw_automated_verdict_metalinguistic_and_calibration_note():
    md = (
        "<!-- execution: sha256=" + SHA + " -->\n"
        "# REPORT-TECHNICAL-v3\n\n"
        "The raw automated verdict is 'malicious', but the pipeline verdict control "
        "locks the report label to 'suspicious'. The dynamic verdict is unknown with "
        "low confidence.\n\n"
        "| Field | Value |\n| --- | --- |\n| Verdict | suspicious |\n"
    )
    assert v2_lib.infer_publish_verdict_from_markdown(md) == "suspicious"

    cal = {"from": "malicious", "to": "suspicious", "reason": "obfuscation only."}
    with_note = v2_lib.prepend_verdict_calibration_note(md, cal)
    assert "> **[Verdict calibration]** The published verdict for this sample is **suspicious**" in with_note
    assert v2_lib.prepend_verdict_calibration_note(with_note, cal) == with_note
    assert v2_lib.infer_publish_verdict_from_markdown(with_note) == "suspicious"

    # Non-raw explicit statement shape remains recognized
    assert not v2_lib._verdict_match_is_metalinguistic(
        "The triage verdict for this sample is 'malicious'", 0
    )


def test_frida_static_probe_absence_exempt_while_runtime_denial_flagged():
    dyn_status = {
        "any_dynamic_performed": True,
        "emulation": {"ok": True},
        "winre": {"detonation_ran": True},
        "frida_runtime": {"observed_runtime_events": True, "trace_artifact_present": True},
        "packet_capture": {"present": True},
    }
    truthful = (
        "Speakeasy and Frida static probes ran but recorded no runtime events, "
        "which is a coverage finding rather than evidence of anti-analysis."
    )
    assert RQ._dynamic_absence_claim(truthful, dyn_status) is None

    false_runtime_denial = "WinRE Frida runtime trace recorded no runtime events."
    assert RQ._dynamic_absence_claim(false_runtime_denial, dyn_status) is not None

    blanket_frida_denial = "Frida recorded no runtime events during execution."
    assert RQ._dynamic_absence_claim(blanket_frida_denial, dyn_status) is not None
