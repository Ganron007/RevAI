#!/usr/bin/env python3
"""Tests for the WinRE dynamic-corroboration UI option (plan: WinRE optional).

Covers the status helper used by the Console, the run-config -> env mapping, and
the status endpoint. The Console toggle must control both halves of the
corroboration (evidence-pack block + deterministic report section) together.
"""

import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_DIR.parent / "revai"))

from test_dynamic_pack import SHA, _make_pack  # noqa: E402

import v2_lib  # noqa: E402
from v2_lib import winre_dynamic_status  # noqa: E402


def test_status_with_pack(tmp_path, monkeypatch):
    _make_pack(tmp_path)
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path))
    monkeypatch.delenv("REVAI_DISABLE_DYNAMIC_CORROBORATION", raising=False)
    monkeypatch.delenv("REVAI_DISABLE_DYNAMIC_SECTION", raising=False)

    status = winre_dynamic_status(SHA, "agentic")
    assert status["root_present"] is True
    assert status["pack_present"] is True
    assert status["source"] == "winre:agentic"
    assert status["dns"] == 2            # synthetic pack carries 2 DNS names
    assert status["sni"] == 1
    assert status["http"] == 1
    assert status["dropped"] >= 1        # %APPDATA% payload path
    assert status["unpack_artifact"] == "x64_demo_unpacked.exe"
    assert status["corroboration_enabled"] is True
    assert status["section_renders"] is True


def test_status_without_pack(tmp_path, monkeypatch):
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path))
    status = winre_dynamic_status(SHA, "agentic")
    assert status["root_present"] is True
    assert status["pack_present"] is False
    assert status["dns"] == 0
    assert status["section_renders"] is False


def test_status_reports_disabled_toggle(tmp_path, monkeypatch):
    _make_pack(tmp_path)
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path))
    monkeypatch.setenv("REVAI_DISABLE_DYNAMIC_CORROBORATION", "1")
    monkeypatch.setenv("REVAI_DISABLE_DYNAMIC_SECTION", "1")
    status = winre_dynamic_status(SHA, "agentic")
    assert status["pack_present"] is True       # the pack exists …
    assert status["corroboration_enabled"] is False
    assert status["section_renders"] is False   # … but it will not reach reports


# --- run-config -> env mapping --------------------------------------------


def _app():
    try:
        import app as app_mod
    except Exception as exc:  # pragma: no cover - Flask/app unavailable
        pytest.skip(f"app import unavailable: {exc}")
    return app_mod


def test_run_config_maps_toggle_to_both_envs(monkeypatch):
    app_mod = _app()
    monkeypatch.delenv("REVAI_DISABLE_DYNAMIC_CORROBORATION", raising=False)
    monkeypatch.delenv("REVAI_DISABLE_DYNAMIC_SECTION", raising=False)

    off = app_mod.get_stage_env({"winre_dynamic": False})
    assert off["REVAI_DISABLE_DYNAMIC_CORROBORATION"] == "1"
    assert off["REVAI_DISABLE_DYNAMIC_SECTION"] == "1"

    on = app_mod.get_stage_env({"winre_dynamic": True})
    assert on["REVAI_DISABLE_DYNAMIC_CORROBORATION"] == "0"
    assert on["REVAI_DISABLE_DYNAMIC_SECTION"] == "0"


def test_run_config_logs_root_override(monkeypatch):
    app_mod = _app()
    env = app_mod.get_stage_env({"winre_logs": "/tmp/other-packs"})
    assert env["REVAI_WINRE_LOGS"] == "/tmp/other-packs"


def test_winre_status_endpoint(tmp_path, monkeypatch):
    app_mod = _app()
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(tmp_path))
    client = app_mod.app.test_client()
    resp = client.get(f"/api/winre/status/{SHA}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "pack_present" in data and "section_renders" in data
    assert data["pack_present"] is False

    _make_pack(tmp_path)
    resp = client.get(f"/api/winre/status/{SHA}?mode=agentic")
    assert resp.status_code == 200
    assert resp.get_json()["pack_present"] is True
