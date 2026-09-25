#!/usr/bin/env python3
"""Unit tests for the optional WinRE integration (revai/winre_runner.py).

Covers settings resolution (Console config < env), availability reasons, the
command builder, the soft-skip path and the child-env mapping — no FlareVM
required.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import winre_runner as wr  # noqa: E402


def _write_cfg(tmp_path: Path, cfg: dict) -> Path:
    p = tmp_path / "pipeline-config.json"
    p.write_text(json.dumps(cfg))
    return p


def test_settings_defaults_and_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setattr(
        wr, "CONFIG_PATH",
        _write_cfg(tmp_path, {"winre_enabled": True, "flare_host": "10.0.0.5", "winre_window": 60}),
    )
    monkeypatch.delenv("FLARE_HOST", raising=False)
    monkeypatch.delenv("REVAI_WINRE_WINDOW", raising=False)
    s = wr.settings()
    assert s["enabled"] is True
    assert s["flare_host"] == "10.0.0.5"
    assert s["window"] == 60
    assert s["flare_user"] == "FLARE-VM"
    assert s["mode"] == "agentic"
    # Environment wins over the Console config.
    monkeypatch.setenv("FLARE_HOST", "192.168.77.42")
    monkeypatch.setenv("REVAI_WINRE_WINDOW", "150")
    s2 = wr.settings()
    assert s2["flare_host"] == "192.168.77.42"
    assert s2["window"] == 150


def test_availability_reasons(tmp_path, monkeypatch):
    monkeypatch.setattr(wr, "CONFIG_PATH", _write_cfg(tmp_path, {}))
    ok, reason = wr.availability(wr.settings())
    assert not ok and "winre_disabled" in reason

    cfg = {
        "winre_enabled": True,
        "flare_host": "10.0.0.1",
        "flare_ssh_key": str(tmp_path / "k"),
    }
    monkeypatch.setattr(wr, "CONFIG_PATH", _write_cfg(tmp_path, cfg))
    s = wr.settings()
    s["root"] = tmp_path / "nope"
    ok, reason = wr.availability(s)
    assert not ok and "winre_not_installed" in reason

    root = tmp_path / "winre"
    (root / "winre").mkdir(parents=True)
    (root / "winre" / "pipeline.py").write_text("")
    venv_bin = root / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("")
    s["root"] = root
    s["python"] = venv_bin / "python"
    ok, reason = wr.availability(s)
    assert not ok and "flare_key_missing" in reason

    key = tmp_path / "k"
    key.write_text("k")
    s["flare_ssh_key"] = str(key)
    s["mode"] = "static"   # agentic additionally needs an LLM (own test below)
    ok, reason = wr.availability(s)
    assert ok, reason


def test_availability_rejects_invalid_knobs(tmp_path, monkeypatch):
    root = tmp_path / "winre"
    (root / "winre").mkdir(parents=True)
    (root / "winre" / "pipeline.py").write_text("")
    (root / "venv" / "bin").mkdir(parents=True)
    (root / "venv" / "bin" / "python").write_text("")
    key = tmp_path / "k"
    key.write_text("k")
    s = {
        "enabled": True, "root": root, "python": root / "venv" / "bin" / "python",
        "flare_host": "10.0.0.1", "flare_ssh_key": str(key),
        "mode": "bogus", "snapshot_gate": "observe",
    }
    ok, reason = wr.availability(s)
    assert not ok and "winre_mode_invalid" in reason
    s["mode"] = "agentic"
    s["snapshot_gate"] = "bogus"
    ok, reason = wr.availability(s)
    assert not ok and "winre_snapshot_gate_invalid" in reason


def test_build_command_flags():
    cfg = {
        "python": "/opt/winre/venv/bin/python", "mode": "agentic", "window": 150,
        "adaptive": True, "pesieve": True, "agentic_dbg": False,
    }
    cmd = wr.build_command("/tmp/sample.exe", cfg)
    assert cmd[0] == "/opt/winre/venv/bin/python"
    assert cmd[1:3] == ["-m", "winre.pipeline"]
    assert "--driver" in cmd and "remote" in cmd
    assert "--dynamic" in cmd
    assert "--max-seconds" in cmd and "150" in cmd
    assert "--adaptive" in cmd and "--pesieve" in cmd
    assert "--agentic-dbg" not in cmd
    cfg["agentic_dbg"] = True
    cfg["adaptive"] = False
    cfg["mode"] = "static"
    cmd2 = wr.build_command("/tmp/sample.exe", cfg)
    assert "--agentic-dbg" in cmd2
    assert "--adaptive" not in cmd2
    assert "static" in cmd2


def test_run_dynamic_soft_skip_writes_status(tmp_path, monkeypatch):
    monkeypatch.setattr(wr, "CONFIG_PATH", _write_cfg(tmp_path, {}))  # disabled
    monkeypatch.setattr(wr, "_case_dir", lambda sha: tmp_path / "case")
    out = wr.run_dynamic("a" * 64)
    assert out["ok"] is True and out["skipped"] is True
    st = wr.read_run_status("a" * 64)
    assert st and st["state"] == "skipped"
    assert "winre_disabled" in (st.get("reason") or "")


def test_child_env_mapping():
    cfg = {
        "flare_host": "10.0.0.9", "flare_user": "FLARE-VM", "flare_ssh_port": 2222,
        "flare_ssh_key": "/tmp/k", "snapshot_gate": "enforce",
        "logs_root": "/data/winre-logs",
    }
    env = wr._child_env(cfg)
    assert env["FLARE_HOST"] == "10.0.0.9"
    assert env["FLARE_USER"] == "FLARE-VM"
    assert env["FLARE_SSH_PORT"] == "2222"
    assert env["FLARE_SSH_KEY"] == "/tmp/k"
    assert env["WINRE_SNAPSHOT_GATE"] == "enforce"
    # WinRE must write its evidence where RevAI reads packs from.
    assert env["WINRE_PIPELINE_LOGS"] == "/data/winre-logs"


def _llm_env(tmp_path, monkeypatch, shared: dict, winre: dict | None = None):
    shared_path = tmp_path / "llm.env"
    shared_path.write_text("\n".join(f"{k}={v}" for k, v in shared.items()))
    monkeypatch.setattr(wr, "SHARED_LLM_ENV", shared_path)
    root = tmp_path / "winre"
    (root / "winre").mkdir(parents=True, exist_ok=True)
    (root / ".env").write_text("\n".join(f"{k}={v}" for k, v in (winre or {}).items()))
    return {"root": root, "mode": "agentic", "llm_source": "inherit"}


def test_llm_inherits_from_the_shared_config(tmp_path, monkeypatch):
    """One place: RevAI's llm.env supplies WinRE's four variables."""
    for key in ("WINRE_LLM_BASE_URL", "WINRE_LLM_MODEL", "WINRE_LLM_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    cfg = _llm_env(tmp_path, monkeypatch, {
        "REVAI_LLM_API_URL": "https://provider/v1", "REVAI_LLM_MODEL": "m-1",
        "REVAI_LLM_API_KEY": "k-1", "REVAI_LLM_REASONING": "high",
    })
    values, meta = wr.resolve_winre_llm(cfg)
    assert values["WINRE_LLM_BASE_URL"] == "https://provider/v1"
    assert values["WINRE_LLM_MODEL"] == "m-1"
    assert values["WINRE_LLM_API_KEY"] == "k-1"
    assert values["WINRE_LLM_REASONING"] == "high"
    assert meta["source"] == "shared" and meta["configured"] is True
    # The key never leaves the resolver: meta is what the Console sees.
    assert "k-1" not in json.dumps(meta)
    env = wr._child_env({**cfg, "flare_host": "h", "flare_user": "u",
                         "flare_ssh_port": 22, "flare_ssh_key": "/tmp/k",
                         "snapshot_gate": "observe", "logs_root": "/opt/winre/logs"})
    assert env["WINRE_LLM_MODEL"] == "m-1"


def test_winre_own_env_wins_over_the_shared_config(tmp_path, monkeypatch):
    for key in ("WINRE_LLM_BASE_URL", "WINRE_LLM_MODEL", "WINRE_LLM_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    cfg = _llm_env(tmp_path, monkeypatch,
                   {"REVAI_LLM_MODEL": "shared-model", "REVAI_LLM_API_KEY": "sk",
                    "REVAI_LLM_API_URL": "https://shared/v1"},
                   winre={"WINRE_LLM_MODEL": "winre-model", "WINRE_LLM_API_KEY": "wk",
                          "WINRE_LLM_BASE_URL": "https://winre/v1"})
    values, meta = wr.resolve_winre_llm(cfg)
    assert values["WINRE_LLM_MODEL"] == "winre-model"
    assert values["WINRE_LLM_API_KEY"] == "wk"
    assert meta["source"] == "winre_env"


def test_llm_source_winre_env_disables_inheritance(tmp_path, monkeypatch):
    for key in ("WINRE_LLM_BASE_URL", "WINRE_LLM_MODEL", "WINRE_LLM_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    cfg = _llm_env(tmp_path, monkeypatch, {
        "REVAI_LLM_MODEL": "shared-model", "REVAI_LLM_API_KEY": "sk",
        "REVAI_LLM_API_URL": "https://shared/v1"})
    cfg["llm_source"] = "winre_env"
    values, meta = wr.resolve_winre_llm(cfg)
    assert values == {} and meta["configured"] is False
    env = wr._child_env({**cfg, "flare_host": "h", "flare_user": "u",
                         "flare_ssh_port": 22, "flare_ssh_key": "/tmp/k",
                         "snapshot_gate": "observe", "logs_root": "/opt/winre/logs"})
    assert "WINRE_LLM_MODEL" not in env


def test_availability_refuses_agentic_without_an_llm(tmp_path, monkeypatch):
    for key in ("WINRE_LLM_BASE_URL", "WINRE_LLM_MODEL", "WINRE_LLM_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    root = tmp_path / "winre"
    (root / "winre").mkdir(parents=True)
    (root / "winre" / "pipeline.py").write_text("")
    (root / "venv" / "bin").mkdir(parents=True)
    (root / "venv" / "bin" / "python").write_text("")
    key_file = tmp_path / "k"
    key_file.write_text("k")
    (root / ".env").write_text("")
    cfg = {
        "enabled": True, "root": root, "python": root / "venv" / "bin" / "python",
        "flare_host": "10.0.0.1", "flare_ssh_key": str(key_file),
        "mode": "agentic", "snapshot_gate": "observe", "llm_source": "inherit",
    }
    monkeypatch.setattr(wr, "SHARED_LLM_ENV", tmp_path / "absent.env")
    ok, reason = wr.availability(cfg)
    assert not ok and "winre_llm_unset" in reason
    # static mode needs no LLM at all
    ok2, reason2 = wr.availability({**cfg, "mode": "static"})
    assert ok2, reason2
    # ... and a bad knob is rejected by name
    ok3, reason3 = wr.availability({**cfg, "mode": "static", "llm_source": "bogus"})
    assert not ok3 and "winre_llm_source_invalid" in reason3


def test_helper_exec_path_never_prints_the_key(tmp_path, monkeypatch, capsys):
    """Regression: --run must put the key in the child env, never on stdout."""
    import sys

    import winre_llm_env as envmod

    shared = tmp_path / "llm.env"
    shared.write_text("REVAI_LLM_API_URL=https://p/v1\nREVAI_LLM_MODEL=m-1\n"
                      "REVAI_LLM_API_KEY=secret-key\n")
    root = tmp_path / "winre"
    (root / "winre").mkdir(parents=True)
    (root / ".env").write_text("")
    monkeypatch.setattr(wr, "SHARED_LLM_ENV", shared)
    monkeypatch.setattr(envmod, "settings", lambda: {
        "root": root, "mode": "agentic", "llm_source": "inherit"})
    seen: dict = {}

    def _fake_run(cmd, env=None):
        seen["cmd"] = cmd
        seen["env"] = env
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(envmod.subprocess, "run", _fake_run)
    monkeypatch.setattr(sys, "argv", ["winre_llm_env.py", "--run", "true"])
    assert envmod.main() == 0
    assert "secret-key" not in capsys.readouterr().out
    assert seen["env"]["WINRE_LLM_API_KEY"] == "secret-key"
    assert seen["cmd"] == ["true"]

    # The eval path still hands the variables to the shell - that is its purpose.
    monkeypatch.setattr(sys, "argv", ["winre_llm_env.py"])
    assert envmod.main() == 0
    assert "export WINRE_LLM_MODEL=m-1" in capsys.readouterr().out


def test_clock_skew_check_flags_a_skewed_control_plane(monkeypatch):
    """A fast control plane must be reported (advisory) before a detonation."""
    from datetime import datetime, timedelta, timezone

    cfg = {"flare_host": "10.0.0.1", "flare_user": "FLARE-VM", "flare_ssh_port": 22,
           "flare_ssh_key": "/tmp/k"}

    def _fake(cmd, **kwargs):
        stamp = (datetime.now(timezone.utc) - timedelta(hours=5))
        return type("R", (), {"returncode": 0, "stdout": stamp.isoformat(timespec="microseconds") + "\n",
                              "stderr": ""})()

    monkeypatch.setattr(wr.subprocess, "run", _fake)
    out = wr.remote_clock_skew(cfg)
    assert out["ok"] is True
    assert abs(out["skew_s"] + 18000) < 30      # control plane ~5h ahead
    assert out["warn"] is True                   # > CLOCK_SKEW_WARN_S

    def _ok(cmd, **kwargs):
        stamp = datetime.now(timezone.utc)
        return type("R", (), {"returncode": 0, "stdout": stamp.isoformat(timespec="microseconds") + "\n",
                              "stderr": ""})()

    monkeypatch.setattr(wr.subprocess, "run", _ok)
    out2 = wr.remote_clock_skew(cfg)
    assert out2["ok"] is True and abs(out2["skew_s"]) < 5 and out2["warn"] is False

    def _fail(cmd, **kwargs):
        return type("R", (), {"returncode": 255, "stdout": "", "stderr": "connection refused"})()

    monkeypatch.setattr(wr.subprocess, "run", _fail)
    out3 = wr.remote_clock_skew(cfg)
    assert out3["ok"] is False and out3["warn"] is False   # fail-open, never blocks


def test_read_run_status_sees_pipeline_triggered_runs(tmp_path, monkeypatch):
    """A pipeline (mode-dir) status must be visible from the Console (flat)."""
    import v2_lib

    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.delenv("REVAI_RUN_MODE", raising=False)
    sha = "d" * 64
    base = tmp_path / "logs" / sha
    scripted = base / "scripted"
    scripted.mkdir(parents=True)
    (scripted / "winre-run.json").write_text(json.dumps(
        {"state": "ok", "finished_at": "2026-09-23T18:46:17+00:00"}))
    (base / "winre-run.json").write_text(json.dumps(
        {"state": "skipped", "finished_at": "2026-09-23T17:00:00+00:00"}))
    st = wr.read_run_status(sha)
    assert st and st["state"] == "ok"
    # A newer Console-triggered run still wins over an older pipeline one.
    (base / "winre-run.json").write_text(json.dumps(
        {"state": "ok", "finished_at": "2026-09-24T09:00:00+00:00"}))
    assert wr.read_run_status(sha)["finished_at"] == "2026-09-24T09:00:00+00:00"


def test_summarize_pack_counts(tmp_path):
    """winre-run.json's pack summary uses the same counts as the report block."""
    sha = "b" * 64
    dyn = tmp_path / sha / "static" / "dynamic"
    dyn.mkdir(parents=True)
    (dyn / "META.json").write_text(json.dumps({"ok": True}))
    (dyn / "META.job.json").write_text(json.dumps({
        "window": {"requested_s": 150, "effective_s": 10.5, "stop_reason": "idle"}}))
    (dyn / "network_intel.json").write_text(json.dumps({
        "captures": [{"dns_queries": ["a.example", "b.example"],
                      "http_requests": ["a.example\tGET\t/"], "tls_sni": []}]}))
    (dyn / "frida_summary.json").write_text(json.dumps({
        "decoded_paths": ["C:\\Users\\FLARE-VM\\AppData\\Local\\Temp\\x.bin"]}))
    mem = dyn / "memory"
    mem.mkdir()
    (mem / "pe_sieve.stdout.txt").write_text("out")
    (mem / "dump.dmp").write_bytes(b"d")
    s = wr.summarize_pack(sha, tmp_path)
    assert s["pack_present"] is True
    p = s["pack"]
    assert p["dns"] == 2 and p["http"] == 1 and p["sni"] == 0
    assert p["dropped"] == 1 and p["dumps"] == 1
    assert p["window"]["effective_s"] == 10.5
    # absent pack -> not present, no exception
    assert wr.summarize_pack("c" * 64, tmp_path)["pack_present"] is False
