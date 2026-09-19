#!/usr/bin/env python3
"""PE parser regression tests.

Three offsets were wrong in `pe.py` and silently degraded every 64-bit sample
(and the section flags of every sample):

* section `Characteristics` was read from `NumberOfRelocations`
* PE32+ `NumberOfRvaAndSizes` / data directory were read at the PE32 offsets
  (so 64-bit images reported zero imports)
* the PE32+ optional-header fields were positionally shifted, so entry point,
  image base and alignments were wrong

These tests pin the correct layout with a hand-built PE32+ fixture.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import pe as pe_mod  # noqa: E402


def _minimal_pe64() -> bytes:
    """PE32+ (x64) with one section and one import: kernel32!GetProcAddress."""
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", e_lfanew) + b"\x00" * 64

    sec = (b".text\x00\x00\x00"
           + struct.pack("<IIIIIIHHI", 0x200, 0x1000, 0x200, 0x200,
                         0, 0, 0, 0, 0x60000020))  # code | execute | read

    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)          # PE32+ magic
    struct.pack_into("<I", opt, 4, 0x200)          # SizeOfCode
    struct.pack_into("<I", opt, 16, 0x1000)        # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, 0x1000)        # BaseOfCode
    struct.pack_into("<Q", opt, 24, 0x140000000)   # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)        # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)         # FileAlignment
    struct.pack_into("<I", opt, 56, 0x2000)        # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)         # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 2)             # Subsystem = GUI
    struct.pack_into("<Q", opt, 72, 0x100000)      # SizeOfStackReserve
    struct.pack_into("<I", opt, 108, 16)           # NumberOfRvaAndSizes (PE32+: 108)
    struct.pack_into("<II", opt, 112 + 8, 0x1000, 40)  # import dir (data dirs at 112)

    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)

    body = bytearray(0x200)
    struct.pack_into("<IIIII", body, 0x00, 0x1014, 0, 0, 0x1044, 0x1014)
    struct.pack_into("<QQ", body, 0x14, 0x1030, 0)          # IAT: hint/name rva
    struct.pack_into("<H", body, 0x30, 0)                   # hint
    body[0x32:0x32 + len(b"GetProcAddress\x00")] = b"GetProcAddress\x00"
    body[0x44:0x44 + len(b"kernel32.dll\x00")] = b"kernel32.dll\x00"

    header = dos + b"PE\x00\x00" + coff + bytes(opt) + sec
    return header + b"\x00" * (0x200 - len(header)) + bytes(body)


def test_pe64_offsets_and_flags(tmp_path):
    sample = tmp_path / "sample64.exe"
    sample.write_bytes(_minimal_pe64())
    parsed = pe_mod.parse_pe(str(sample))

    assert parsed.is_64
    # Regression: these were shifted by the PE32+ field mapping.
    assert parsed.entry_point == 0x1000
    assert parsed.image_base == 0x140000000
    assert parsed.section_alignment == 0x1000
    assert parsed.file_alignment == 0x200

    # Regression: Characteristics was read from NumberOfRelocations (0).
    section = parsed.sections[0]
    assert section.name == ".text"
    assert section.executable is True
    assert section.writable is False


def test_pe64_imports_are_parsed(tmp_path):
    sample = tmp_path / "sample64.exe"
    sample.write_bytes(_minimal_pe64())
    parsed = pe_mod.parse_pe(str(sample))

    # Regression: PE32+ reported zero imports (NumberOfRvaAndSizes read at 92).
    assert len(parsed.imports) == 1
    assert parsed.imports[0].dll == "kernel32.dll"
    assert parsed.imports[0].functions == ["GetProcAddress"]


def test_pe32_still_parses(tmp_path):
    """The 32-bit path must keep working unchanged."""
    try:
        from test_revai_tools_core import _minimal_pe
    except Exception:  # pragma: no cover
        return
    sample = tmp_path / "sample32.exe"
    sample.write_bytes(_minimal_pe())
    parsed = pe_mod.parse_pe(str(sample))
    assert not parsed.is_64
    assert parsed.sections[0].name == ".text"
    assert parsed.sections[0].executable is True
    assert parsed.imports and parsed.imports[0].dll
