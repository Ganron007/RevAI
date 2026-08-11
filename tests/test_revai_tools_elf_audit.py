"""ELF parser + audit provenance tests (mock backend for the walk)."""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import sinkcat  # noqa: E402
import elf as elf_mod  # noqa: E402
from backend import DisasmBackend, Function, Instruction  # noqa: E402


def _minimal_elf64() -> bytes:
    """Hand-built ELF64: PT_LOAD, PT_GNU_STACK non-exec, PT_GNU_RELRO,
    dynamic with DT_NEEDED + DT_BIND_NOW, dynsym with __stack_chk_fail."""
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    phoff = 64
    dyn_off = phoff + 4 * 56
    dynstr_off = dyn_off + 96          # 6 dynamic entries (96 bytes)
    shoff = dynstr_off + 27            # "libc.so.6\0" + "__stack_chk_fail\0"
    dynsym_off = shoff + 3 * 64
    ehdr += struct.pack("<HHIQQQIHHHHHH", 3, 0x3E, 1, 0x400000, phoff, shoff,
                        0, 64, 56, 4, 64, 3, 1)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000)
    phdrs += struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 0)
    phdrs += struct.pack("<IIQQQQQQ", 0x6474E552, 4, 0, 0, 0, 0, 0, 0)
    phdrs += struct.pack("<IIQQQQQQ", 2, 7, dyn_off, dyn_off, 0x60, dyn_off, 0x60, 0x1000)
    dyn = struct.pack("<qQ", 5, dynstr_off) + struct.pack("<qQ", 6, dynsym_off) + \
          struct.pack("<qQ", 1, 0) + struct.pack("<qQ", 24, 0) + \
          struct.pack("<qQ", 30, 8) + struct.pack("<qQ", 0, 0)
    dynstr = b"libc.so.6\x00__stack_chk_fail\x00"
    shdrs = b"\x00" * 64
    shdrs += struct.pack("<IIQQQQIIQQ", 1, 3, 0, dynstr_off, len(dynstr), 0, 0, 0, 0, 0)
    shdrs += struct.pack("<IIQQQQIIQQ", 7, 11, 0, dynsym_off, 48, 0, 0, 0, 24, 16)
    dynsym = b"\x00" * 24
    dynsym += struct.pack("<IBBHQQ", 10, 2, 0, 0, 0, 0)  # __stack_chk_fail @ idx 10
    return ehdr + phdrs + dyn + dynstr + shdrs + dynsym


class MockBackend(DisasmBackend):

    def __init__(self, funcs, xrefs, disasm):
        self._funcs = funcs
        self._xrefs = xrefs
        self._disasm = disasm

    def linear_disasm(self, path, vaddr, count=8):
        return self._disasm.get(vaddr, [])[:count]

    def functions(self, path):
        return self._funcs

    def xrefs(self, path, target):
        t = int(target, 16) if isinstance(target, str) else target
        return self._xrefs.get(t, [])

    def calls(self, path, fn):
        return []

    def analyze(self, path, xref_targets):
        return {"functions": self._funcs, "imports": [], "xrefs": self._xrefs}

    def disasm(self, path, sites, window=24):
        return {s: self._disasm.get(s, []) for s in sites}


def test_elf_parse_minimal():
    import tempfile, os
    data = _minimal_elf64()
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        e = elf_mod.parse_elf(path)
        assert e.is_64
        assert e.is_pie
        assert e.has_gnu_stack and e.has_gnu_relro
        assert "libc.so.6" in e.needed
        assert any("__stack_chk_fail" in s for s in e.dyn_imports)
    finally:
        os.unlink(path)


def test_elf_rejects_non_elf():
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"plain text")
        path = f.name
    try:
        with pytest.raises(elf_mod.ELFParseError):
            elf_mod.parse_elf(path)
    finally:
        os.unlink(path)


def test_audit_subtraction_pattern():
    entry = 0x401000
    f_entry = Function(entry, 64, "entry", [], [])
    f_sink = Function(0x401200, 64, "fcn.00401200", [], [])
    # memcpy at 0x401210; rdx (len) set by sub rdx, [ebp-4]
    site = 0x401210
    insns = [
        Instruction(0x401208, 4, "mov", "eax, [ebp-4]", b""),
        Instruction(0x40120C, 3, "sub", "rdx, eax", b""),
        Instruction(site, 6, "call", "sym.imp.KERNEL32.dll_memcpy", b""),
    ]
    bk = MockBackend(
        funcs=[f_entry, f_sink],
        xrefs={0x401300: [site]},
        disasm={site: insns},
    )
    sites = [{"api": "memcpy", "dll": "KERNEL32.dll", "class": "unbounded_copy",
              "address": site, "function": "fcn.00401200"}]
    findings = sinkcat.audit_sites("x", bk, sites, [entry])
    assert len(findings) == 1
    assert "subtraction" in findings[0]["patterns"]


def test_audit_no_pattern():
    entry = 0x401000
    f_entry = Function(entry, 64, "entry", [], [])
    f_sink = Function(0x401200, 64, "fcn.00401200", [], [])
    # safe memcpy: rdx from a constant, sink not reachable from entry
    site = 0x401210
    insns = [
        Instruction(0x40120C, 6, "mov", "rdx, 0x100", b""),
        Instruction(site, 6, "call", "sym.imp.KERNEL32.dll_memcpy", b""),
    ]
    bk = MockBackend(funcs=[f_entry, f_sink], xrefs={0x401300: [site]},
                     disasm={site: insns})
    sites = [{"api": "memcpy", "dll": "KERNEL32.dll", "class": "unbounded_copy",
              "address": site, "function": "fcn.00401200"}]
    findings = sinkcat.audit_sites("x", bk, sites, [entry])
    assert len(findings) == 0
