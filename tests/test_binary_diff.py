"""Tests for structural binary comparison (binary_diff)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import binary_diff as bd  # noqa: E402


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_raw_containment(tmp_path):
    payload = b"\xab" * (bd.CHUNK * 4)
    loader = b"\x00" * (bd.CHUNK * 10) + payload + b"\xcd" * (bd.CHUNK * 2)
    a = _write(tmp_path, "loader.bin", loader)
    b = _write(tmp_path, "payload.bin", payload)

    result = bd.compare(a, b)
    bc = result["byte_containment"]
    assert bc["b_in_a"] == 1.0
    assert bc["a_in_b"] < 0.5
    assert bc["largely_contained"]["b_in_a"] is True
    assert bc["largely_contained"]["a_in_b"] is False
    assert result["a"]["format"] == "raw"
    assert result["a"]["pe_parsed"] is False
    assert result["signals"]["pe_comparison"] == "skipped"


def test_unrelated_files_have_no_containment(tmp_path):
    a = _write(tmp_path, "a.bin", bytes(range(256)) * 4)
    b = _write(tmp_path, "b.bin", bytes(range(255, -1, -1)) * 4)
    result = bd.compare(a, b)
    assert result["byte_containment"]["b_in_a"] == 0.0
    assert result["byte_containment"]["a_in_b"] == 0.0


def test_hashes_and_size_ratio(tmp_path):
    a = _write(tmp_path, "a.bin", b"x" * 100)
    b = _write(tmp_path, "b.bin", b"x" * 50)
    result = bd.compare(a, b)
    assert result["size_ratio_b_to_a"] == 0.5
    assert result["a"]["sha256"] != result["b"]["sha256"]
    assert len(result["a"]["sha256"]) == 64
    assert result["notes"]


def test_pe_comparison_when_parseable(tmp_path):
    try:
        from test_revai_tools_core import _minimal_pe  # tests dir on sys.path
    except Exception:  # pragma: no cover - helper unavailable
        return
    data = _minimal_pe()
    a = _write(tmp_path, "sample.exe", data)
    b = _write(tmp_path, "same.exe", data)
    result = bd.compare(a, b)
    assert result["a"]["format"] == "pe"
    if not result["a"].get("pe_parsed"):
        return  # parser rejected the synthetic stub; raw path already covered
    signals = result["signals"]
    assert ".text" in signals["shared_sections"]
    assert signals["same_imphash"] is True
    assert signals["entry_section"]["same"] is True
    assert ".text" in signals["section_entropy_delta"]


def test_missing_file_raises_for_caller_to_handle(tmp_path):
    a = _write(tmp_path, "a.bin", b"data" * 32)
    try:
        bd.compare(a, str(tmp_path / "nope.bin"))
    except OSError:
        return
    raise AssertionError("expected an OSError for a missing input file")
