"""R2: the dynamic pack reader must see WinRE's newer producer roots.

WinRE writes dynamic-mode evidence at `<sha>/dynamic/dynamic/` with producer
metadata at `<sha>/dynamic/META.json`, and has a separate `<sha>/dbg/` root.
The reader searched only `agentic, static, ui` plus the legacy flat root, so it
matched the mode ROOT as `winre:flat`, found its META.json, reported
"pack present" -- and returned null for every piece of runtime evidence. A pack
that looks present with its contents gone is worse than an absent pack, because
nothing downstream can tell the difference.

These build the layouts on disk and drive the REAL resolver and loader. The
fixtures are written in the shapes WinRE writes, and every layout is checked for
the thing that matters: the runtime evidence actually arrives.
"""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402

SHA = "a" * 64


def _w(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _detonation(stage: Path, *, events: int = 17) -> None:
    """The contents a real detonation stage carries."""
    _w(stage / "META.json", {"elapsed_s": 150,
                             "window": {"requested_s": 150, "effective_s": 150}})
    _w(stage / "frida_summary.json", {"events": events, "kind": "frida"})
    _w(stage / "network.json", {"hosts": ["evil.example.biz"]})
    _w(stage / "process_snapshot.json", {"processes": 12})


def _winre_root(tmp_path: Path) -> Path:
    root = tmp_path / "winre" / "logs"
    root.mkdir(parents=True)
    return root


# ------------------------------------------------------------- the new layouts
def test_the_nested_dynamic_stage_is_found_and_its_evidence_reads(tmp_path):
    """The layout that produced a present-but-empty pack."""
    root = _winre_root(tmp_path)
    mode = root / SHA / "dynamic"
    stage = mode / "dynamic"
    stage.mkdir(parents=True)
    _w(mode / "META.json", {"producer": "mode", "mode": "dynamic"})
    _detonation(stage)

    dyn, info = v2_lib._resolve_dynamic_dir(SHA, winre_root=root)
    assert dyn == stage, f"resolved {dyn}, expected the nested stage {stage}"
    assert info["source"] == "winre:dynamic"

    pack = v2_lib.load_dynamic_pack(SHA, winre_root=root)
    assert pack["present"] is True
    assert pack["frida_summary"] == {"events": 17, "kind": "frida"}, (
        "the pack was reported present with its runtime evidence missing -- "
        "the exact defect")
    assert pack["network"] == {"hosts": ["evil.example.biz"]}
    assert pack["process_snapshot"] == {"processes": 12}


def test_producer_metadata_is_not_mistaken_for_detonation_metadata(tmp_path):
    """The mode root's META.json describes the MODE, not the detonation."""
    root = _winre_root(tmp_path)
    mode = root / SHA / "dynamic"
    stage = mode / "dynamic"
    stage.mkdir(parents=True)
    _w(mode / "META.json", {"producer": "mode", "mode": "dynamic"})
    _detonation(stage, events=17)

    pack = v2_lib.load_dynamic_pack(SHA, winre_root=root)
    assert pack["meta"].get("elapsed_s") == 150, (
        f"read producer metadata as the pack: {pack['meta']}")
    assert pack["meta"].get("producer") is None
    assert pack["window"]["effective_s"] == 150


def test_the_section_root_is_the_mode_root_not_the_stage(tmp_path):
    """deep/x64dbg lives at the mode root, so the section root must be it."""
    root = _winre_root(tmp_path)
    mode = root / SHA / "dynamic"
    stage = mode / "dynamic"
    stage.mkdir(parents=True)
    _detonation(stage)
    _w(mode / "deep" / "deep.json",
       {"agent": {"unpack_prepass": {"dump_source": "x64dbg",
                                     "dump_kind": "rwx-heap"}}})
    (mode / "deep" / "x64dbg").mkdir(parents=True)
    (mode / "deep" / "x64dbg" / "unpacked.exe").write_bytes(b"MZ" + b"\0" * 64)

    pack = v2_lib.load_dynamic_pack(SHA, winre_root=root)
    assert Path(pack["section_root"]) == mode, (
        f"section_root {pack['section_root']} != mode root {mode}; the unpack "
        "artifact lookup would search the wrong tree")
    art = pack.get("unpack_artifact")
    assert art and art["name"] == "unpacked.exe", (
        "the mode-wide unpack artifact was not reachable from the section root")
    assert art["dump_source"] == "x64dbg"


def test_the_dbg_root_is_discovered(tmp_path):
    root = _winre_root(tmp_path)
    dbg = root / SHA / "dbg"
    dbg.mkdir(parents=True)
    _detonation(dbg, events=5)
    dyn, info = v2_lib._resolve_dynamic_dir(SHA, winre_root=root)
    assert info["source"] == "winre:dbg" and dyn == dbg
    assert v2_lib.load_dynamic_pack(SHA, winre_root=root)["frida_summary"]


def test_a_nested_dbg_stage_is_preferred_over_the_dbg_root(tmp_path):
    root = _winre_root(tmp_path)
    dbg = root / SHA / "dbg"
    stage = dbg / "dynamic"
    stage.mkdir(parents=True)
    _w(dbg / "META.json", {"producer": "dbg-mode"})
    _detonation(stage, events=9)
    dyn, info = v2_lib._resolve_dynamic_dir(SHA, winre_root=root)
    assert dyn == stage and info["source"] == "winre:dbg"
    assert v2_lib.load_dynamic_pack(SHA, winre_root=root)["frida_summary"][
        "events"] == 9


# ------------------------------------------------------------- no regressions
@pytest.mark.parametrize("layout", ["flat", "agentic", "static", "ui"])
def test_the_existing_layouts_still_resolve(tmp_path, layout):
    """Appending the new roots must not change what already worked."""
    root = _winre_root(tmp_path)
    stage = (root / SHA if layout == "flat" else root / SHA / layout) / "dynamic"
    stage.mkdir(parents=True)
    _detonation(stage, events=3)
    pack = v2_lib.load_dynamic_pack(SHA, winre_root=root)
    assert pack["present"] is True
    assert pack["frida_summary"]["events"] == 3, (
        f"{layout} layout lost its evidence (source={pack['source']})")


def test_a_legacy_flat_pack_is_not_relabelled(tmp_path):
    """No nested stage means this is the flat pack, and must keep its name."""
    root = _winre_root(tmp_path)
    stage = root / SHA / "dynamic"
    stage.mkdir(parents=True)
    _detonation(stage)
    _, info = v2_lib._resolve_dynamic_dir(SHA, winre_root=root)
    assert info["source"] == "winre:flat", (
        f"a flat pack was relabelled {info['source']}")


def test_a_static_only_skip_marker_is_still_not_a_pack(tmp_path):
    """The 2026-09-24 regression must survive the reordering."""
    root = _winre_root(tmp_path)
    stage = root / SHA / "static" / "dynamic"
    stage.mkdir(parents=True)
    _w(stage / "STAGE.json", {"skipped": True, "ran": False})
    assert v2_lib._resolve_dynamic_dir(SHA, winre_root=root)[0] is None


def test_the_revai_side_is_unaffected(tmp_path):
    logs = tmp_path / "revai" / "logs"
    stage = logs / SHA / "scripted" / "dynamic"
    stage.mkdir(parents=True)
    _detonation(stage, events=11)
    pack = v2_lib.load_dynamic_pack(SHA, logs_dir=logs, winre_root=None)
    assert pack["frida_summary"]["events"] == 11
    assert pack["source"].startswith("revai:")


def test_the_winre_logs_env_var_is_honoured(tmp_path, monkeypatch):
    root = _winre_root(tmp_path)
    stage = root / SHA / "dynamic" / "dynamic"
    stage.mkdir(parents=True)
    _detonation(stage)
    monkeypatch.setenv("REVAI_WINRE_LOGS", str(root))
    pack = v2_lib.load_dynamic_pack(SHA, logs_dir=tmp_path / "empty")
    assert pack["present"] and pack["frida_summary"]["events"] == 17


def test_an_absent_pack_is_still_absent(tmp_path):
    """Absent means falsy. It must never become a present-but-empty pack."""
    root = _winre_root(tmp_path)
    pack = v2_lib.load_dynamic_pack(SHA, winre_root=root)
    assert not pack, f"an absent pack became {pack!r}"
    assert v2_lib._resolve_dynamic_dir(SHA, winre_root=root)[0] is None


def test_a_mode_root_with_metadata_but_no_stage_is_not_a_pack(tmp_path):
    """The dangerous middle case: producer metadata present, evidence absent.

    If this ever reports present, the reader is back to calling a mode root a
    pack -- the defect R2 describes.
    """
    root = _winre_root(tmp_path)
    mode = root / SHA / "dynamic"
    mode.mkdir(parents=True)
    _w(mode / "META.json", {"producer": "mode", "mode": "dynamic"})
    pack = v2_lib.load_dynamic_pack(SHA, winre_root=root)
    assert not pack or not pack.get("frida_summary"), (
        "a bare mode root was read as a pack with runtime evidence")
