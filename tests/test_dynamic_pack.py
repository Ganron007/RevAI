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


def test_dynamic_pack_counts(tmp_path):
    """Shared counter (Console chip / winre-run.json / report) mirrors the pack."""
    _make_pack(tmp_path)
    pack = load_dynamic_pack(SHA, winre_root=tmp_path)
    counts = dynamic_pack_counts(pack)
    assert counts["present"] is True
    assert counts["dns"] == 2 and counts["http"] == 1 and counts["sni"] == 1
    assert counts["dropped"] == 1            # only the AppData path counts
    assert counts["dumps"] == 1              # .dmp only, not the pe-sieve logs
    assert counts["unpack_artifact"] == "x64_demo_unpacked.exe"
    # absent pack -> all zeros, never raises
    assert dynamic_pack_counts(None) == {
        "present": False, "dns": 0, "http": 0, "sni": 0, "dropped": 0,
        "dumps": 0, "unpack_artifact": None}


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
    assert "3cf8b057.bin" in md                          # dropped path surfaced
    assert "x64_demo_unpacked.exe" in md                 # artifact surfaced
    assert "1 memory dump(s)" in md                       # dumps counted (.dmp only)
    assert "not PE-parsable" in md                       # honest raw-blob path
    assert "Corroboration only" in md
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
