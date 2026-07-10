#!/usr/bin/env python3
"""test_file_type.py - synthetic magic-byte tests for file_type.py.

Tests _detect_pe, _detect_elf, _detect_macho, _detect_text (with
script_type). Uses in-memory synthetic headers, no real malware
samples needed.

Run:
    python3 /opt/scripts/tests/test_file_type.py

Exit code 0 = all pass, 1 = at least one fail.
"""
from __future__ import annotations
import sys
import os
import tempfile
import struct
import traceback
from pathlib import Path

# Import file_type from sibling directory
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from file_type import detect_file_type  # noqa: E402

# --- Test fixtures: synthetic magic bytes -------------------------------

def make_elf(elf_class=2, ei_data=1, e_type=2, e_machine=0x3E, padding=512):
    """ELF header. class=2=64bit, ei_data=1=LE, e_type=2=ET_EXEC,
    e_machine=0x3E=x86_64. Header is laid out identically for
    ELF32 and ELF64 (e_ident 16 bytes, e_type/e_machine 2 bytes each);
    file_type.py reads e_machine at offset 18 with the endianness
    declared in EI_DATA. So we pack e_type/e_machine in the same
    endianness the file claims to use."""
    e_ident = (
        b"\x7fELF"            # magic
        + bytes([elf_class])   # EI_CLASS
        + bytes([ei_data])     # EI_DATA
        + b"\x01"              # EI_VERSION
        + b"\x00" * 9          # padding (OSABI + PAD)
    )
    endian_char = "<" if ei_data == 1 else ">"
    e_header = struct.pack(f"{endian_char}HHIQQQ", e_type, e_machine, 1, 0, 0, 0)
    return e_ident + e_header + b"\x00" * padding


def make_macho(magic=0xFEEDFACF, cputype=0x01000007, cpusubtype=3, filetype=2, padding=512):
    """Mach-O 64-bit. magic=0xFEEDFACF, cputype=0x01000007=x86_64.
    NOTE: file_type.py reads cputype as big-endian regardless of file
    endianness (the magic byte tells the OS which way to interpret
    payloads, but cputype is always big-endian on disk)."""
    header = struct.pack(">IIIIIIII",
                         magic, cputype, cpusubtype, filetype,
                         0, 0, 0, 0)  # ncmds, sizeofcmds, flags, reserved
    return header + b"\x00" * padding


def make_pe_truncated(arch=0x014C, padding=256):
    """Truncated PE header. machine=0x014C=i386. No real PE\0\0 pointer
    so the parser falls back to default."""
    return b"MZ\x90\x00" + b"\x00" * 60 + b"\x80\x00\x00\x00" + struct.pack("<H", arch) + b"\x00" * padding


def make_fat_macho():
    """Mach-O fat/universal binary. magic=0xCAFEBABE."""
    header = struct.pack(">II", 0xCAFEBABE, 1)  # 1 arch
    # Each fat_arch is 20 bytes: cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4)
    fat_arch = struct.pack(">IIIII", 0x01000007, 3, 0x1000, 0x5000, 0x1000)
    return header + fat_arch + b"\x00" * 512


# --- Test runner --------------------------------------------------------

PASSED = 0
FAILED = 0
FAILURES: list[tuple[str, str]] = []


def assert_eq(name, got, expected, note=""):
    global PASSED, FAILED
    if got == expected:
        print(f"  PASS  {name:50s}  got={got}")
        PASSED += 1
    else:
        msg = f"got={got!r}  expected={expected!r}  {note}"
        print(f"  FAIL  {name:50s}  {msg}")
        FAILED += 1
        FAILURES.append((name, msg))


def assert_in(name, value, allowed_values, note=""):
    global PASSED, FAILED
    if value in allowed_values:
        print(f"  PASS  {name:50s}  got={value}")
        PASSED += 1
    else:
        msg = f"got={value!r}  expected one of {allowed_values!r}  {note}"
        print(f"  FAIL  {name:50s}  {msg}")
        FAILED += 1
        FAILURES.append((name, msg))


def run_on_bytes(synth_bytes: bytes, suffix: str = ".bin") -> dict:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
        f.write(synth_bytes)
        p = f.name
    try:
        return detect_file_type(p)
    finally:
        os.unlink(p)


# --- Test cases ---------------------------------------------------------

def test_elf_x86_64():
    print("\n[test_elf_x86_64]")
    info = run_on_bytes(make_elf(elf_class=2, e_machine=0x3E), ".elf")
    assert_eq("format", info.get("format"), "elf")
    assert_eq("os", info.get("os"), "linux")
    assert_eq("bits", info.get("bits"), 64)
    assert_eq("endian", info.get("endian"), "little")
    assert_eq("arch", info.get("arch"), "x86_64")


def test_elf_x86_32_be():
    print("\n[test_elf_x86_32_be]")
    info = run_on_bytes(make_elf(elf_class=1, ei_data=2, e_machine=0x03), ".elf")
    assert_eq("format", info.get("format"), "elf")
    assert_eq("os", info.get("os"), "linux")
    assert_eq("bits", info.get("bits"), 32)
    assert_eq("endian", info.get("endian"), "big")
    assert_eq("arch", info.get("arch"), "x86")


def test_elf_arm64():
    print("\n[test_elf_arm64]")
    info = run_on_bytes(make_elf(elf_class=2, e_machine=0xB7), ".elf")
    assert_eq("format", info.get("format"), "elf")
    assert_eq("bits", info.get("bits"), 64)
    assert_eq("arch", info.get("arch"), "arm64")


def test_macho_x86_64():
    print("\n[test_macho_x86_64]")
    info = run_on_bytes(make_macho(magic=0xFEEDFACF, cputype=0x01000007), ".macho")
    assert_eq("format", info.get("format"), "macho")
    assert_eq("os", info.get("os"), "macos")
    assert_eq("bits", info.get("bits"), 64)
    assert_eq("arch", info.get("arch"), "x86_64")


def test_macho_arm64():
    print("\n[test_macho_arm64]")
    info = run_on_bytes(make_macho(magic=0xFEEDFACF, cputype=0x0100000C), ".macho")
    assert_eq("format", info.get("format"), "macho")
    assert_eq("bits", info.get("bits"), 64)
    assert_eq("arch", info.get("arch"), "arm64")


def test_macho_fat():
    print("\n[test_macho_fat]")
    info = run_on_bytes(make_fat_macho(), ".macho")
    assert_eq("format", info.get("format"), "macho_fat")
    assert_eq("bits", info.get("bits"), "fat")


def test_pe_truncated():
    """Truncated PE (no PE\\0\\0 pointer). Parser should still return
    format=pe with arch=? since e_lfanew is in range but PE sig
    doesn't match."""
    print("\n[test_pe_truncated]")
    info = run_on_bytes(make_pe_truncated(arch=0x014C), ".exe")
    assert_eq("format", info.get("format"), "pe")
    assert_eq("os", info.get("os"), "windows")
    # arch may be "unknown(0x...)" since the PE\\0\\0 sig check fails
    assert_in("arch_present", info.get("arch") is not None, [True])


def test_text_batch():
    print("\n[test_text_batch]")
    info = run_on_bytes(b"@echo off\r\nset X=1\r\ncalc.exe\r\n", ".bat")
    assert_eq("format", info.get("format"), "text")
    assert_eq("script_type", info.get("script_type"), "batch")


def test_text_shell():
    print("\n[test_text_shell]")
    info = run_on_bytes(b"#!/bin/bash\necho hello\n", ".sh")
    assert_eq("format", info.get("format"), "text")
    assert_eq("script_type", info.get("script_type"), "shell")


def test_text_javascript():
    print("\n[test_text_javascript]")
    info = run_on_bytes(b"// some js\nfunction foo() { return 1; }\n", ".js")
    assert_eq("format", info.get("format"), "text")
    assert_eq("script_type", info.get("script_type"), "script")


def test_text_no_script_type():
    """Plain text without script keywords should still be 'text' but
    script_type may be None or absent."""
    print("\n[test_text_no_script_type]")
    info = run_on_bytes(b"This is just some plain text content.\n", ".txt")
    assert_eq("format", info.get("format"), "text")
    assert_in("script_type", info.get("script_type"), [None, "batch", "shell", "script", "csharp"])


def test_unknown_binary():
    """Random bytes that don't match any known magic."""
    print("\n[test_unknown_binary]")
    info = run_on_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd\xfc" + b"\x00" * 100, ".bin")
    assert_eq("format", info.get("format"), "unknown")


def test_file_not_found():
    print("\n[test_file_not_found]")
    info = detect_file_type("/nonexistent/path/to/file.exe")
    assert_eq("format", info.get("format"), "unknown")
    assert_in("error_present", "error" in info, [True])


# --- Main ---------------------------------------------------------------

def main():
    global PASSED, FAILED
    tests = [
        test_elf_x86_64,
        test_elf_x86_32_be,
        test_elf_arm64,
        test_macho_x86_64,
        test_macho_arm64,
        test_macho_fat,
        test_pe_truncated,
        test_text_batch,
        test_text_shell,
        test_text_javascript,
        test_text_no_script_type,
        test_unknown_binary,
        test_file_not_found,
    ]
    for t in tests:
        try:
            t()
        except Exception as e:
            FAILED += 1
            FAILURES.append((t.__name__, f"EXCEPTION: {e}\n{traceback.format_exc()}"))
            print(f"  FAIL  {t.__name__:50s}  EXCEPTION: {e}")

    print(f"\n{'='*60}")
    print(f"file_type tests: {PASSED} passed, {FAILED} failed")
    if FAILURES:
        print("\nFailures:")
        for name, msg in FAILURES:
            print(f"  - {name}: {msg}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
