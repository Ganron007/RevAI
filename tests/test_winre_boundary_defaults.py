"""R1: the bridge must not weaken an execution-plane default.

WinRE owns the restore gate (`enforce`) and the idle policy. RevAI's bridge
drives WinRE; it does not get to decide for it. These tests pin that the ABSENT
case reaches WinRE as absent, and that an explicit operator choice is still
honoured -- including a bad one being rejected rather than silently coerced.

The defects: `snapshot_gate` hard-defaulted to `observe` and was exported into
the child environment, so opting into RevAI-driven dynamic analysis disabled
WinRE's restore gate (process env beats WinRE's env file, so WinRE's `enforce`
could never reassert); and `adaptive` defaulted to true, which makes
flare_dynamic_job.ps1 restore the 10-second early-idle cutoff, so a 150-second
window was not 150 seconds of observation.
"""
import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/winre_runner.py").parent))
import winre_runner as W  # noqa: E402


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    for k in list(os.environ):
        if k.startswith("REVAI_WINRE"):
            monkeypatch.delenv(k, raising=False)
    # CONFIG_PATH is bound at import time, so the env var cannot redirect it.
    # Without this the suite inherits the machine's real settings: on the lab VM
    # /opt/samples/pipeline-config.json sets winre_snapshot_gate=enforce and
    # winre_adaptive=true, and every "unset" assertion below would be testing the
    # machine rather than the default path. These tests are ABOUT the default.
    monkeypatch.setattr(W, "CONFIG_PATH", tmp_path / "no-such-config.json")


def _write_config(monkeypatch, tmp_path, **winre):
    """Point the settings loader at a config that makes explicit choices.

    Keys are FLAT at the top level (`_load_config` reads `cfg.get(key)`), which
    is the shape the Console Settings panel writes.
    """
    import json as _json
    path = tmp_path / "pipeline-config.json"
    path.write_text(_json.dumps(winre), encoding="utf-8")
    monkeypatch.setattr(W, "CONFIG_PATH", path)


def _cfg(**over):
    cfg = {"enabled": False, "flare_host": "", "flare_user": "FLARE-VM",
           "flare_ssh_port": 22, "flare_ssh_key": "~/.ssh/winre-flare",
           "root": "/opt/winre", "python": "/opt/winre/venv/bin/python",
           "logs_root": Path("/opt/winre/logs"), "mode": "static",
           "window": 150, "adaptive": None, "pesieve": True,
           "agentic_dbg": False, "snapshot_gate": None,
           "llm_source": "inherit", "timeout": 3600}
    cfg.update(over)
    return cfg


# ------------------------------------------------------------------ the defaults
def test_unset_gate_stays_unset_and_is_not_exported():
    """The core defect. WinRE must see NO gate and apply its own `enforce`."""
    cfg = W.settings()
    assert cfg["snapshot_gate"] is None, (
        f"the bridge invented a gate: {cfg['snapshot_gate']!r}")
    assert "WINRE_SNAPSHOT_GATE" not in W._child_env(cfg), (
        "exporting a default the execution plane did not choose is how the gate "
        "got disabled")


def test_unset_adaptive_does_not_opt_into_the_early_idle_cutoff():
    cfg = W.settings()
    assert cfg["adaptive"] is None
    assert "--adaptive" not in W.build_command("/tmp/x.exe", cfg), (
        "--adaptive reinstates the 10s early-idle stop for sleeping samples; "
        "unset must not pass it")


def test_an_explicit_gate_is_honoured(monkeypatch):
    monkeypatch.setenv("REVAI_WINRE_SNAPSHOT_GATE", "observe")
    cfg = W.settings()
    assert cfg["snapshot_gate"] == "observe"
    assert W._child_env(cfg)["WINRE_SNAPSHOT_GATE"] == "observe"


def test_an_explicit_adaptive_is_honoured(monkeypatch):
    monkeypatch.setenv("REVAI_WINRE_ADAPTIVE", "1")
    assert "--adaptive" in W.build_command("/tmp/x.exe", W.settings())


def test_an_explicit_off_gate_is_honoured(monkeypatch):
    monkeypatch.setenv("REVAI_WINRE_SNAPSHOT_GATE", "off")
    assert W._child_env(W.settings())["WINRE_SNAPSHOT_GATE"] == "off"


def test_an_inherited_gate_from_the_process_is_still_dropped_when_unset(monkeypatch):
    """A stale WINRE_SNAPSHOT_GATE in our own environment must not leak through.

    `_child_env` copies os.environ, so a leftover export would defeat the fix.
    """
    monkeypatch.setenv("WINRE_SNAPSHOT_GATE", "observe")
    cfg = W.settings()
    assert cfg["snapshot_gate"] is None
    assert "WINRE_SNAPSHOT_GATE" not in W._child_env(cfg)


# ------------------------------------------------------------------ validation
def test_a_bogus_explicit_gate_is_rejected(monkeypatch, tmp_path):
    """Not silently coerced to a default -- a typo must be reported."""
    root = tmp_path / "winre"
    (root / "winre").mkdir(parents=True)
    (root / "winre" / "pipeline.py").write_text("", encoding="utf-8")
    py = tmp_path / "venv" / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.write_text("", encoding="utf-8")
    key = tmp_path / "k"
    key.write_text("", encoding="utf-8")
    base = dict(root=str(root), python=str(py), flare_host="192.168.77.42",
                flare_ssh_key=str(key), enabled=True, mode="static")

    monkeypatch.setenv("REVAI_WINRE_SNAPSHOT_GATE", "bogus")
    ok, why = W.availability(_cfg(**base, snapshot_gate="bogus"))
    assert ok is False and "snapshot_gate_invalid" in why, why

    for good in ("observe", "enforce", "off"):
        ok, why = W.availability(_cfg(**base, snapshot_gate=good))
        assert "snapshot_gate_invalid" not in why, f"{good} rejected: {why}"

    # Unset must pass the gate check (it is a legitimate choice: WinRE decides).
    ok, why = W.availability(_cfg(**base, snapshot_gate=None))
    assert "snapshot_gate_invalid" not in why, why


# ------------------------------------------------------- the recorded settings
def test_settings_report_null_rather_than_a_default():
    """The Console shows this value; null is honest, `observe` was a fiction."""
    cfg = W.settings()
    assert cfg["adaptive"] is None and cfg["snapshot_gate"] is None
    probe = W.probe(timeout=1, s=cfg)
    assert isinstance(probe, dict)


# ------------------------------------------------- an explicit choice still wins
def test_the_config_files_explicit_gate_is_honoured(monkeypatch, tmp_path):
    """The lab VM's pipeline-config.json sets `enforce` explicitly.

    That is an operator choice and must be forwarded, not second-guessed. R1 was
    a defect in the DEFAULT path -- this pins that fixing it did not start
    overriding a deliberate setting.
    """
    _write_config(monkeypatch, tmp_path, winre_snapshot_gate="enforce",
                  winre_adaptive=True)
    cfg = W.settings()
    assert cfg["snapshot_gate"] == "enforce"
    assert cfg["adaptive"] is True
    assert W._child_env(cfg)["WINRE_SNAPSHOT_GATE"] == "enforce"
    assert "--adaptive" in W.build_command("/tmp/x.exe", cfg)


def test_the_config_files_explicit_observe_is_still_honoured(monkeypatch, tmp_path):
    """Weakening the gate remains possible -- but only when asked for."""
    _write_config(monkeypatch, tmp_path, winre_snapshot_gate="observe")
    cfg = W.settings()
    assert cfg["snapshot_gate"] == "observe"
    assert W._child_env(cfg)["WINRE_SNAPSHOT_GATE"] == "observe"


def test_the_environment_overrides_the_config_file(monkeypatch, tmp_path):
    _write_config(monkeypatch, tmp_path, winre_snapshot_gate="enforce")
    monkeypatch.setenv("REVAI_WINRE_SNAPSHOT_GATE", "off")
    assert W.settings()["snapshot_gate"] == "off"
