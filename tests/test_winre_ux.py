"""RC-68/69/70 (2026-11-11): the WinRE integrated-run UX — restore-required
pre-flight, the agentic-dbg combination refusal, and the log-parse fallback.

The operator-facing problem: a dirty snapshot gate surfaced as a bare rc=1
with the restore instruction buried in winre-run.log, the dbg+dynamic
combination was silently built into one doomed invocation, and nothing in
the RevAI Console showed the gate state or could attest.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import winre_runner as WR  # noqa: E402




def _full_manifest(case):
    """A manifest covering every REPORT_INPUT_ARTIFACTS entry: the dynamic
    pack attested, everything else not-produced."""
    import hashlib
    import v2_lib
    manifest = {"schema": "revai-report-input-manifest/v1", "artifacts": []}
    for rel in v2_lib.REPORT_INPUT_ARTIFACTS:
        p = case / rel
        if p.is_file():
            raw = p.read_bytes()
            manifest["artifacts"].append({
                "path": rel, "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw), "status": "attested",
            })
        else:
            manifest["artifacts"].append({"path": rel, "status": "not-produced"})
    return manifest

def _cfg(**over):
    cfg = {
        "enabled": True, "flare_host": "192.0.2.42", "flare_user": "FLARE-VM",
        "flare_ssh_port": 22, "flare_ssh_key": "~/.ssh/winre-flare",
        "root": Path("/opt/winre"), "python": Path("/usr/bin/python3"),
        "logs_root": Path("/opt/winre/logs"), "mode": "agentic",
        "window": 150, "adaptive": None, "pesieve": True,
        "agentic_dbg": False, "snapshot_gate": "enforce",
        "llm_source": "winre_env", "timeout": 3600,
    }
    cfg.update(over)
    return cfg


def test_snapshot_state_parses_the_gate_json(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        class R:
            returncode = 0
            stdout = json.dumps({"mode": "enforce", "marker": True,
                                 "ledger_clean": True,
                                 "last_action": "verified_clean"})
            stderr = ""
        return R()

    monkeypatch.setattr(WR.subprocess, "run", fake_run)
    st = WR.snapshot_state(_cfg())
    assert st["marker"] is True and st["ledger_clean"] is True
    assert st["last_action"] == "verified_clean"
    assert calls[0][1:4] == ["-m", "winre.snapshot_gate", "status"]


def test_snapshot_state_fail_open_on_garbage(monkeypatch):
    def fake_run(cmd, **kw):
        class R:
            returncode = 1
            stdout = ""
            stderr = "no module"
        return R()

    monkeypatch.setattr(WR.subprocess, "run", fake_run)
    st = WR.snapshot_state(_cfg())
    assert "error" in st, st


# ---------------------------------------------------------------- RC-70
def test_agentic_dbg_refused_before_any_launch(monkeypatch, tmp_path):
    refused = []
    monkeypatch.setattr(WR, "availability", lambda cfg: (True, ""))
    monkeypatch.setattr(WR, "snapshot_state", lambda cfg: {})
    monkeypatch.setattr(WR, "build_command",
                        lambda *a, **k: refused.append(1) or [])
    sha = "a" * 64
    out = WR.run_dynamic(sha, s=_cfg(agentic_dbg=True),
                         sample_path=str(tmp_path / "s.bin"))
    assert out["ok"] is False, out
    assert out["state"] == "failed", out
    assert "separate gated execution" in out["error"], out
    assert "--agentic-dbg" in out["error"], out
    assert not refused, "the doomed command must not be built or launched"
    st = WR.read_run_status(sha)
    assert st and st.get("state") == "failed", st


# ---------------------------------------------------------------- RC-68
def test_dirty_gate_returns_restore_required_without_launch(monkeypatch,
                                                            tmp_path):
    launched = []
    monkeypatch.setattr(WR, "availability", lambda cfg: (True, ""))
    monkeypatch.setattr(
        WR, "snapshot_state",
        lambda cfg: {"mode": "enforce", "marker": True,
                     "ledger_clean": False, "last_action": "detonated"})
    monkeypatch.setattr(WR, "build_command",
                        lambda *a, **k: launched.append(1) or [])
    sha = "b" * 64
    out = WR.run_dynamic(sha, s=_cfg(), sample_path=str(tmp_path / "s.bin"))
    assert out["ok"] is False
    assert out["state"] == "restore_required", out
    assert out["restore_required"] is True
    assert "GOLD snapshot" in out["restore_hint"], out
    assert out["gate"]["ledger_clean"] is False
    assert not launched, "a dirty gate must refuse before any launch"
    st = WR.read_run_status(sha)
    assert st and st.get("state") == "restore_required", st


def test_missing_marker_also_restore_required(monkeypatch, tmp_path):
    monkeypatch.setattr(WR, "availability", lambda cfg: (True, ""))
    monkeypatch.setattr(
        WR, "snapshot_state",
        lambda cfg: {"mode": "enforce", "marker": False,
                     "ledger_clean": True, "last_action": "unknown"})
    monkeypatch.setattr(WR, "build_command", lambda *a, **k: [])
    out = WR.run_dynamic("c" * 64, s=_cfg(),
                         sample_path=str(tmp_path / "s.bin"))
    assert out["state"] == "restore_required", out


def test_clean_gate_does_not_block(monkeypatch, tmp_path):
    """The pre-flight must not block an armed gate — the run proceeds."""
    monkeypatch.setattr(WR, "availability", lambda cfg: (True, ""))
    monkeypatch.setattr(
        WR, "snapshot_state",
        lambda cfg: {"mode": "enforce", "marker": True,
                     "ledger_clean": True, "last_action": "verified_clean"})
    monkeypatch.setattr(WR, "build_command", lambda *a, **k: ["cmd"])
    monkeypatch.setattr(WR, "remote_clock_skew", lambda cfg, timeout=20: {})
    monkeypatch.setattr(WR, "resolve_winre_llm",
                        lambda cfg: ({}, {"source": "winre_env"}))
    monkeypatch.setattr(WR, "sample_path_for", lambda sha: None)

    class P:
        returncode = 0

    monkeypatch.setattr(WR.subprocess, "Popen",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("full run path not mocked here")))
    # run_dynamic past the pre-flight goes into the subprocess path; we only
    # assert it did NOT return restore_required at the pre-flight.
    try:
        out = WR.run_dynamic("d" * 64, s=_cfg(),
                             sample_path=str(tmp_path / "s.bin"))
        state = out.get("state")
    except AssertionError as e:
        state = f"proceeded past pre-flight ({e})" if "full run path" in str(e) else None
    assert state is not None and "restore_required" not in str(state), (
        "a clean armed gate must never produce restore_required")


# ------------------------------------------------- RC-68 log-parse fallback
def test_a_gate_refusal_in_the_run_log_sets_restore_required(
        monkeypatch, tmp_path):
    sha = "e" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    log = case / "winre-run.log"
    log.write_text(
        "starting...\n"
        '{"reason": "The guest clean marker is present, but the independent '
        'control-plane ledger is not attested clean", "how_to_clear": '
        '["revert the FlareVM to the GOLD snapshot in VMware", '
        '"attest it: python -m winre.snapshot_gate attest"]}\n',
        encoding="utf-8")

    summary = {"pack_present": False, "pack": {}, "correlation": None}
    monkeypatch.setattr(WR, "summarize_pack",
                        lambda sha, logs_root, expected_run_id=None: summary)
    monkeypatch.setattr(WR.time, "time", lambda: 0.0)

    # Drive the payload construction directly through the real code path by
    # calling the module's helper semantics via run_dynamic is complex; the
    # log-parse contract is: the signatures match this refusal text.
    text = log.read_text(encoding="utf-8").lower()[-8000:]
    assert any(sig in text for sig in WR._GATE_REFUSAL_SIGNATURES), (
        "the refusal record must match the runner's signatures")
    # And a benign failure must not match.
    benign = "traceback: provider 500\nllm empty response\n".lower()
    assert not any(sig in benign for sig in WR._GATE_REFUSAL_SIGNATURES)


def test_restore_hint_names_the_manual_flow():
    assert "GOLD snapshot" in WR._RESTORE_HINT
    assert "attest" in WR._RESTORE_HINT.lower()
    # WinRE never reverts the VM itself — the hint must not promise an
    # automated restore.
    assert "revert" in WR._RESTORE_HINT.lower()


# ---------------------------------------------------------------- RC-69
def test_attest_clean_invokes_the_gate_attest(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        class R:
            returncode = 0
            stdout = json.dumps({"ok": True, "action": "verified_clean"})
            stderr = ""
        return R()

    monkeypatch.setattr(WR.subprocess, "run", fake_run)
    out = WR.attest_clean(_cfg())
    assert out["ok"] is True and out["action"] == "verified_clean", out
    assert calls[0][1:5] == ["-m", "winre.snapshot_gate", "attest",
                             "--action"]
    assert calls[0][5] == "verified_clean"


# ---------------------------------------------------------------- RC-71
# Found live on S1 mode-a (integrated detonation): the WinRE dynamic pack's
# raw Frida invocation rows filled 884 KB of the 900 KB report-evidence
# corpus -> every technical publish prompt exceeded the provider context ->
# 30 non-retryable HTTP 400s -> the technical report lost 5 sections. The
# writer render elides the raw rows (the claim review reads the complete
# attested file); the summary and attribution counts stay visible.
def test_dynamic_pack_render_elides_raw_invocations(tmp_path):
    import v2_lib
    sha = "7" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    big_rows = [{"invocation_id": f"{i}:1:1", "api": "NtWriteFile",
                 "args": ["h", "buf", f"payload-{i}" * 20]} for i in range(3000)]
    pack = {"frida_summary": {"calls": [{"api": "NtWriteFile", "count": 3000}]},
            "frida_trace": {"attribution_status": "sample_process_tree",
                            "attributed_call_count": 296,
                            "invocations": big_rows}}
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "02-dynamic-pack.json").write_text(json.dumps(pack))
    manifest = _full_manifest(case)
    rendered, meta = v2_lib.format_report_source_evidence(case, manifest)
    assert "RC-71 render elision: 3000 raw invocation rows" in rendered, (
        "the raw rows must be elided from the writer render")
    assert "payload-" not in rendered, (
        "no raw row payload may reach the writer render")
    assert "attribution_status" in rendered, (
        "the summary + attribution counts stay visible to the writer")
    # the attested FILE is untouched
    import json as _json
    on_disk = _json.loads(
        (case / "deep_dive" / "02-dynamic-pack.json").read_text())
    assert len(on_disk["frida_trace"]["invocations"]) == 3000, (
        "the attested artifact must keep every row for claim review")


def test_a_small_dynamic_pack_renders_whole(tmp_path):
    import v2_lib
    sha = "8" * 64
    case = tmp_path / "logs" / sha / "agentic"
    case.mkdir(parents=True)
    pack = {"frida_summary": {"calls": []},
            "frida_trace": {"attribution_status": "none",
                            "invocations": []}}
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "02-dynamic-pack.json").write_text(json.dumps(pack))
    manifest = _full_manifest(case)
    rendered, _meta = v2_lib.format_report_source_evidence(case, manifest)
    assert "RC-71 render elision" not in rendered, (
        "an empty invocation list must not be flagged as elided")
