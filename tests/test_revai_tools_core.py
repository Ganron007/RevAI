"""Smoke tests for the stdlib core: hashes, strings, iocs, PE parser."""

import hashlib
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import hashes as hashes_mod  # noqa: E402
import iocs as iocs_mod  # noqa: E402
import strings as strings_mod  # noqa: E402
import pe as pe_mod  # noqa: E402


def _minimal_pe() -> bytes:
    """Hand-built 32-bit PE with one section + one import (kernel32.GetProcAddress)."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0x100, 0xE0, 0x100)
    opt32 = struct.pack("<HBB", 0x10B, 0, 0)                       # 0x00 magic/linker
    opt32 += struct.pack("<III", 0x1000, 0, 0)                    # 0x04 code/init/uninit sizes
    opt32 += struct.pack("<IIIIII", 0x1000, 0x1000, 0x1000, 0x400000,
                         0x1000, 0x200)                           # 0x10 entry..filealign
    opt32 += struct.pack("<HHHHHH", 6, 0, 0, 0, 4, 0)             # 0x28 versions
    opt32 += struct.pack("<IIII", 0, 0x1000, 0x200, 0)            # 0x34 win32ver/image/headers/checksum
    opt32 += struct.pack("<HH", 2, 0x8140)                        # 0x44 subsystem=gui, dllchars
    opt32 += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # 0x48 stacks/heaps
    opt32 += struct.pack("<II", 0, 16)                            # 0x58 loaderflags/numdirs
    opt32 += struct.pack("<IIII", 0, 0, 0x1000, 40)               # 0x60 export(0,0) + import dir
    opt32 += b"\x00" * (0xE0 - len(opt32))
    sec = b".text\x00\x00\x00" + struct.pack("<IIIIIIHHI", 0x100, 0x1000, 0x200,
                                             0x200, 0, 0, 0, 0, 0x60000020)
    pe_bytes = dos + struct.pack("<I", 0x4550) + coff + opt32 + sec
    def rva(off: int) -> int:
        return 0x1000 + (off - 0x200)
    # import directory at file offset 0x200 (rva 0x1000)
    desc = struct.pack("<IIIII", 0, 0, 0, rva(0x218), rva(0x214))  # name @0x218, iat @0x214
    iat = struct.pack("<I", rva(0x225))                            # 0x214 -> hint/name @0x225
    name = b"kernel32.dll\x00"                                     # 0x218 .. 0x225
    hint_name = b"\x00\x00" + b"GetProcAddress\x00"                # 0x225 ..
    terminator = b"\x00" * 20
    pe_bytes += b"\x00" * max(0, 0x200 - len(pe_bytes))
    pe_bytes += desc + iat + name + hint_name + terminator
    return pe_bytes


def test_file_hashes():
    data = b"hello world"
    h = hashes_mod.file_hashes(data)
    assert h["md5"] == hashlib.md5(data).hexdigest()
    assert len(h["sha256"]) == 64


def test_imphash():
    imports = [{"dll": "KERNEL32.dll", "functions": ["GetProcAddress"]}]
    assert hashes_mod.imphash(imports) == hashlib.md5(
        b"kernel32.getprocaddress").hexdigest()


def test_strings_ascii():
    data = b"prefix\x00TheQuickBrownFox\x00suffix"
    found = [s["string"] for s in strings_mod.extract_strings(data, min_len=4)]
    assert "TheQuickBrownFox" in found


def test_iocs_defang():
    data = b"c2.evil.example.com http://1.2.3.4/x bc1qxyz"
    iocs = iocs_mod.extract_iocs(data)
    assert any(u.startswith("http[:]//") for u in iocs["urls"])
    assert any("1[.]2[.]3[.]4" in i for i in iocs["ips"])
    assert any("c2[.]evil[.]example[.]com" in d for d in iocs["domains"])


def test_pe_parse_minimal():
    data = _minimal_pe()
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        pe = pe_mod.parse_pe(path)
        assert pe.machine == 0x14C
        assert not pe.is_64
        assert pe.entry_point == 0x1000
        assert pe.subsystem_name == "windows_gui"
        assert len(pe.sections) == 1
        assert any(i.dll.lower() == "kernel32.dll" and
                   "GetProcAddress" in i.functions for i in pe.imports)
    finally:
        os.unlink(path)


def test_pe_rejects_non_pe():
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"not a pe at all")
        path = f.name
    try:
        with pytest.raises(pe_mod.PEParseError):
            pe_mod.parse_pe(path)
    finally:
        os.unlink(path)
