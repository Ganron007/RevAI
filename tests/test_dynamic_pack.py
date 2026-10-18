#!/usr/bin/env python3
"""Regression: WinRE dynamic-pack ingestion + presence-gated corroboration.

Covers the RevAI side of the WinRE integration:
- mode-aware pack discovery (WinRE section layout) with window + unpack artifact
- dynamic-corroboration block content (window, coverage caveat, network IoCs,
  static_yara_wins, unpack artifact honesty) and lab-IP hygiene
- presence gating: no pack -> evidence unchanged (users without WinRE)
- opt-out env switch
"""
from __future__ import annotations

import json
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from v2_lib import (  # noqa: E402
    attach_dynamic_corroboration,
    dynamic_pack_counts,
    format_flare_dynamic_evidence,
    load_dynamic_pack,
)
from report_quality import _dynamic_pack_evidence_text  # noqa: E402

SHA = "a" * 64


def _make_pack(root: Path, sha: str = SHA, *, with_artifact: bool = True,
               with_dumps: bool = True) -> Path:
    dyn = root / sha / "agentic" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "META.json").write_text(json.dumps({
        "ok": True,
        "schema_version": "v6.2.4",
        "max_seconds": 150,
        "verdict_policy": {"static_yara_wins": True},
        "flare_host": "192.168.77.42",  # must never leak into reports
    }))
    (dyn / "META.job.json").write_text(json.dumps({
        "window": {"requested_s": 150, "effective_s": 6, "adaptive": True,
                   "idle_stop_s": 5, "stop_reason": "idle"},
    }))
    (dyn / "network_intel.json").write_text(json.dumps({
        "captures": [{
            "dns_queries": ["pywolwnvd.biz", "update.googleapis.com"],
            "tls_sni": ["talks.vg"],
            "http_requests": ["pywolwnvd.biz\tPOST\t/elbdrbyvil"],
        }],
    }))
    (dyn / "frida_summary.json").write_text(json.dumps({
        "decoded_paths": ["C:\\Users\\FLARE-VM\\AppData\\Roaming\\3cf8b057.bin",
                          "C:\\Windows\\System32\\ntdll.dll"],
    }))
    mem = dyn / "memory"
    mem.mkdir()
    (mem / "pe_sieve.stdout.txt").write_text("pe-sieve output")
    (mem / "pe_sieve_report.json").write_text(json.dumps({"ok": False}))
    if with_dumps:
        (mem / "6604_ghyte.dmp").write_bytes(b"dump")
    if with_artifact:
        deep = root / sha / "agentic" / "deep"
        (deep / "x64dbg").mkdir(parents=True)
        (deep / "x64dbg" / "x64_demo_unpacked.exe").write_bytes(b"not-a-real-pe")
        (deep / "deep.json").write_text(json.dumps({
            "agent": {"unpack_prepass": {
                "ok": True, "dump_kind": "heap", "dump_source": "pesieve_imp",
                "rebuild_hint": None, "artifact": {"parses": False, "imports": 0},
            }},
        }))
    return dyn


def test_load_pack_winre_section(tmp_path):
    _make_pack(tmp_path)
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    assert pack and pack["present"]
    assert pack["source"] == "winre:agentic"
    assert pack["window"]["requested_s"] == 150
    assert pack["window"]["effective_s"] == 6
    assert pack["window"]["adaptive"] is True
    assert pack["verdict_policy"]["static_yara_wins"] is True
    art = pack["unpack_artifact"]
    assert art and art["name"] == "x64_demo_unpacked.exe"
    assert art["dump_kind"] == "heap"
    assert art["dump_source"] == "pesieve_imp"
    assert Path(pack["section_root"]).name == "agentic"


def test_load_pack_absent(tmp_path):
    assert load_dynamic_pack(SHA, winre_root=tmp_path) is None


def test_static_only_run_marker_is_not_a_pack(tmp_path):
    """A WinRE static-only run's skip marker must not read as a pack."""
    dyn = tmp_path / SHA / "static" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "STAGE.json").write_text(json.dumps({
        "stage": "dynamic", "ok": True, "ran": False,
        "skipped": "not requested", "summary": "dynamic not requested (static-only run)"}))
    assert load_dynamic_pack(SHA, winre_root=tmp_path) is None
    # With a real pack in another mode section, that one is selected instead.
    real = tmp_path / SHA / "agentic" / "dynamic"
    real.mkdir(parents=True)
    (real / "META.json").write_text(json.dumps({"ok": True}))
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    assert pack and pack["source"] == "winre:agentic"


def test_dynamic_pack_counts(tmp_path):
    """Shared counter (Console chip / winre-run.json / report) mirrors the pack."""
    _make_pack(tmp_path)
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    counts = dynamic_pack_counts(pack)
    assert counts["present"] is True
    assert counts["dns"] == 2 and counts["http"] == 1 and counts["sni"] == 1
    assert counts["dropped"] == 0            # decoded strings do not prove a file drop
    assert counts["frida_decoded_paths"] == 1  # only the AppData path is retained
    assert counts["files_created_written"] == 0
    assert counts["dumps"] == 1              # .dmp only, not the pe-sieve logs
    assert counts["unpack_artifact"] == "x64_demo_unpacked.exe"
    # absent pack -> all zeros, never raises
    assert dynamic_pack_counts(None) == {
        "present": False, "dns": 0, "http": 0, "sni": 0, "dropped": 0,
        "files_created_written": 0, "frida_decoded_paths": 0,
        "dumps": 0, "unpack_artifact": None}


def test_sample_process_tree_file_creation_is_kept_with_exact_rows(tmp_path, monkeypatch):
    """Only sample-tree CreateFile+WriteFile pairs count as file writes."""
    dyn = _make_pack(tmp_path, with_artifact=False, with_dumps=False)
    (dyn / "META.job.json").write_text(json.dumps({
        "detonation_ran": True,
        "sample_pid": 123,
        "window": {"requested_s": 150, "effective_s": 20},
    }))
    with (dyn / "procmon.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(("Time of Day", "Process Name", "PID", "Operation",
                         "Path", "Result", "Detail"))
        writer.writerows((
            ("10:00:00", "sample.exe", "123", "Process Create",
             r"C:\Windows\System32\cmd.exe", "SUCCESS", "PID: 456"),
            ("10:00:01", "cmd.exe", "456", "CreateFile",
             r"C:\ProgramData\Upkeep\payload.bin", "SUCCESS", "OpenResult: Created"),
            ("10:00:02", "cmd.exe", "456", "WriteFile",
             r"C:\ProgramData\Upkeep\payload.bin", "SUCCESS", "Offset: 0, Length: 4"),
            ("10:00:03", "sample.exe", "123", "WriteFile",
             r"C:\Users\Flare-VM\AppData\Local\Temp\frida-123\x86_64-frida-agent.dll",
             "SUCCESS", "Offset: 0"),
            ("10:00:04", "sample.exe", "123", "RegSetValue",
             r"HKLM\System\CurrentControlSet\Services\BAM\State\UserSettings\S-1-5-21",
             "SUCCESS", "Data: 1"),
        ))

    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    assert pack and pack["procmon_sample_pid"] == 123
    assert len(pack["procmon_created_written_files"]) == 1
    record = pack["procmon_created_written_files"][0]
    assert record["create"]["row"] == 3
    assert record["write"]["row"] == 4
    assert record["create"]["pid"] == record["write"]["pid"] == 456
    assert pack["procmon_instrumentation_exclusions"][0]["count"] == 1
    assert all("BAM" not in event.get("path", "")
               for event in pack["procmon_sample_events"])

    counts = dynamic_pack_counts(pack)
    assert counts["files_created_written"] == 1
    assert counts["dropped"] == 0
    md = format_flare_dynamic_evidence(pack)
    assert "Created and written during the sample process tree" in md
    assert "data row 3; PID 456; operation CreateFile" in md
    assert "data row 4; PID 456; operation WriteFile" in md
    assert "do not prove that the sample created or wrote those files" in md
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path))
    monkeypatch.delenv("REVAI_DISABLE_DYNAMIC_CORROBORATION", raising=False)
    evidence_text, _used = _dynamic_pack_evidence_text(tmp_path / SHA)
    assert "Procmon data row 3; PID 456; operation CreateFile" in evidence_text
    assert "Procmon data row 4; PID 456; operation WriteFile" in evidence_text


def test_passive_tcpdump_pcap_in_off_box_layout_is_loaded_and_attributed(tmp_path):
    """The off-box sensor capture and its provenance reach RevAI reporting."""
    dyn = _make_pack(tmp_path)
    off_box = dyn / "off_box"
    (off_box / "network_raw").mkdir(parents=True)
    (off_box / "network_raw" / "vmnet2.pcap").write_bytes(b"pcap")
    (off_box / "capture.json").write_text(json.dumps({
        "requested": True, "status": "collected", "mode": "passive",
        "interface": "ens32", "guest_ip": "192.168.77.42",
        "capture_filter": "host 192.168.77.42", "packets_captured": 37,
        "pcap_sha256": "a" * 64,
        "path": "off_box/network_raw/vmnet2.pcap", "elapsed_s": 129.7,
    }))

    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    assert pack and pack["pcaps"] == ["off_box/network_raw/vmnet2.pcap"]
    assert pack["external_capture"]["status"] == "collected"
    assert dynamic_pack_counts(pack)["present"] is True
    md = format_flare_dynamic_evidence(pack)
    assert "1 pcap(s)" in md
    assert "passive off-box packet capture" in md
    assert "packets_captured=37" in md
    assert "off_box/network_raw/vmnet2.pcap" not in md  # private lab path stays internal


def test_no_dump_run_is_reported_honestly(tmp_path):
    """A pe-sieve report without dumps must not read as captured memory."""
    _make_pack(tmp_path, with_dumps=False)
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    assert dynamic_pack_counts(pack)["dumps"] == 0
    md = format_flare_dynamic_evidence(pack)
    assert "pe-sieve output only (no dumps)" in md
    assert "memory dump" not in md


def test_block_content_and_hygiene(tmp_path):
    _make_pack(tmp_path)
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    md = format_flare_dynamic_evidence(pack)
    assert "## Dynamic Corroboration (WinRE detonation)" in md
    assert "requested=150s" in md and "effective=6s" in md
    assert "adaptive=True" in md and "stop_reason=idle" in md
    assert "coverage caveat" in md
    assert "static_yara_wins" in md
    assert "pywolwnvd.biz" in md and ".biz" in md        # DGA-shaped IoCs surfaced
    assert "3cf8b057.bin" in md                          # decoded path surfaced
    assert "x64_demo_unpacked.exe" in md                 # artifact surfaced
    assert "1 memory dump(s)" in md                       # dumps counted (.dmp only)
    assert "not PE-parsable" in md                       # honest raw-blob path
    assert "supplementary to static evidence" in md
    assert "192.168." not in md                          # lab IP never printed


def test_attach_is_presence_gated(tmp_path):
    evidence = "# Technical Evidence Pack\n\nstatic stuff\n"
    # no pack -> unchanged
    assert attach_dynamic_corroboration(evidence, SHA, winre_root=tmp_path) == evidence
    # pack present -> block appended
    _make_pack(tmp_path)
    out = attach_dynamic_corroboration(evidence, SHA, winre_root=tmp_path)
    assert out.startswith(evidence.rstrip())
    assert "Dynamic Corroboration" in out


def test_attach_opt_out(tmp_path, monkeypatch):
    _make_pack(tmp_path)
    evidence = "evidence\n"
    monkeypatch.setenv("REVAI_DISABLE_DYNAMIC_CORROBORATION", "1")
    assert attach_dynamic_corroboration(evidence, SHA, winre_root=tmp_path) == evidence
