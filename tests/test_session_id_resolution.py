"""Session IDs emitted by intake must resolve to their canonical registry."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


def test_type_tagged_ghidra_session_ids_resolve_to_sha_registry(tmp_path, monkeypatch):
    sha = "a" * 64
    expected = {"sha256": sha, "sample_path": "/opt/samples/example.exe"}
    (tmp_path / f"{sha}.json").write_text(json.dumps(expected), encoding="utf-8")
    monkeypatch.setattr(v2_lib, "SESSIONS_DIR", tmp_path)

    for session_id in (
        sha,
        f"ghidra-pe-{sha}",
        f"ghidra-elf-{sha}",
        f"ghidra-macho-{sha}",
        f"ghidra-dotnet-{sha}",
    ):
        assert v2_lib.load_session_for_id(session_id) == expected
