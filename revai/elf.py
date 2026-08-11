"""ELF32/ELF64 parsing — own implementation on the C structures.

Covers: ELF header, program headers (PT_LOAD / PT_GNU_STACK / PT_GNU_RELRO /
PT_DYNAMIC), dynamic section (DT_NEEDED, DT_FLAGS/DT_FLAGS_1, DT_BIND_NOW,
DT_TEXTREL, DT_RPATH), and dynamic symbols (imports incl. __stack_chk_fail —
the stack-canary signal). Enough to drive mitigations analysis (sec) and the
triage surface without any third-party library.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
DT_NEEDED = 1
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_BIND_NOW = 24
DT_TEXTREL = 22
DT_RPATH = 15
DF_BIND_NOW = 0x8
DF_TEXTREL = 0x4
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000
DT_SYMTAB = 6
DT_STRTAB = 5
DT_HASH = 4
DT_GNU_HASH = 0x6FFFFEF5
SHT_DYNSYM = 11
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4


class ELFParseError(ValueError):
    pass


@dataclass
class ELFSection:
    name: str
    offset: int
    size: int
    flags: int
    type: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    @property
    def writable(self) -> bool:
        return bool(self.flags & SHF_WRITE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "offset": self.offset, "size": self.size,
            "type": self.type, "executable": self.executable,
            "writable": self.writable,
        }


@dataclass
class ELF:
    path: str
    data: bytes
    is_64: bool
    e_type: int
    machine: int
    entry_point: int
    program_headers: list[dict[str, Any]]
    sections: list[ELFSection]
    needed: list[str]
    dyn_imports: list[str]
    flags: int
    flags1: int
    has_gnu_stack: bool
    has_gnu_relro: bool

    @property
    def is_pie(self) -> bool:
        return self.e_type == ET_DYN

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "class": "64" if self.is_64 else "32",
            "type": "pie" if self.is_pie else "executable",
            "machine": hex(self.machine),
            "entry_point": hex(self.entry_point),
            "needed": self.needed,
            "dyn_imports": self.dyn_imports,
            "sections": [s.to_dict() for s in self.sections],
        }


def _read_cstr(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    return data[off:end if end != -1 else len(data)].decode("latin-1", errors="replace")


def parse_elf(path: str | Path) -> ELF:
    path = str(path)
    data = Path(path).read_bytes()
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ELFParseError("not an ELF")
    is_64 = data[4] == ELFCLASS64
    if data[5] != ELFDATA2LSB:
        raise ELFParseError("big-endian ELF unsupported")

    if is_64:
        e_type, machine, entry = struct.unpack_from("<HHI", data, 16)
        phoff, shoff = struct.unpack_from("<QQ", data, 32)
        _, _, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(
            "<IHHHHHH", data, 48)
    else:
        e_type, machine, entry = struct.unpack_from("<HHI", data, 16)
        phoff, shoff = struct.unpack_from("<II", data, 28)
        _, _, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(
            "<IHHHHHH", data, 36)

    program_headers: list[dict[str, Any]] = []
    has_stack = has_relro = False
    dyn_off = dyn_size = 0
    for i in range(phnum):
        off = phoff + i * phentsize
        if is_64:
            p_type, p_flags = struct.unpack_from("<II", data, off)
            p_offset = struct.unpack_from("<Q", data, off + 8)[0]
            p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        else:
            p_type, p_offset, p_flags = struct.unpack_from("<III", data, off)
            p_filesz = struct.unpack_from("<I", data, off + 16)[0]
        program_headers.append({"type": p_type, "flags": p_flags,
                                "offset": p_offset, "filesz": p_filesz})
        if p_type == PT_GNU_STACK:
            has_stack = True
        elif p_type == PT_GNU_RELRO:
            has_relro = True
        elif p_type == PT_DYNAMIC:
            dyn_off, dyn_size = p_offset, p_filesz

    sections: list[ELFSection] = []
    shstr = b""
    if shoff and shnum and shstrndx < shnum:
        shstr_off = struct.unpack_from("<Q" if is_64 else "<I",
                                       data, shoff + shstrndx * shentsize + (24 if is_64 else 16))[0]
        shstr_size = struct.unpack_from("<Q" if is_64 else "<I",
                                        data, shoff + shstrndx * shentsize + (32 if is_64 else 20))[0]
        shstr = data[shstr_off:shstr_off + shstr_size]
    for i in range(shnum):
        off = shoff + i * shentsize
        name_off = struct.unpack_from("<I", data, off)[0]
        if is_64:
            sh_type, sh_flags = struct.unpack_from("<IQ", data, off + 4)
            sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
            sh_size = struct.unpack_from("<Q", data, off + 32)[0]
        else:
            sh_type, sh_flags = struct.unpack_from("<II", data, off + 4)
            sh_offset = struct.unpack_from("<I", data, off + 16)[0]
            sh_size = struct.unpack_from("<I", data, off + 20)[0]
        sections.append(ELFSection(
            _read_cstr(shstr, name_off), sh_offset, sh_size, sh_flags, sh_type))

    needed: list[str] = []
    flags = flags1 = 0
    dyn_imports: list[str] = []
    if dyn_off:
        ent_size = 16 if is_64 else 8
        strtab_off = symtab_off = 0
        for i in range(dyn_size // ent_size):
            off = dyn_off + i * ent_size
            if is_64:
                d_tag, d_val = struct.unpack_from("<qQ", data, off)
            else:
                d_tag, d_val = struct.unpack_from("<iI", data, off)
            if d_tag == DT_NEEDED and strtab_off:
                needed.append(_read_cstr(data, strtab_off + d_val))
            elif d_tag == DT_FLAGS:
                flags = d_val
            elif d_tag == DT_FLAGS_1:
                flags1 = d_val
            elif d_tag == DT_STRTAB:
                strtab_off = d_val
            elif d_tag == DT_SYMTAB:
                symtab_off = d_val
            elif d_tag == 0:
                break
        if symtab_off and strtab_off:
            dyn_imports = _read_dynsym(data, symtab_off, strtab_off, is_64)

    return ELF(path=path, data=data, is_64=is_64, e_type=e_type,
               machine=machine, entry_point=entry,
               program_headers=program_headers, sections=sections,
               needed=needed, dyn_imports=dyn_imports, flags=flags,
               flags1=flags1, has_gnu_stack=has_stack, has_gnu_relro=has_relro)


def _read_dynsym(data: bytes, symtab_off: int, strtab_off: int,
                 is_64: bool) -> list[str]:
    """Read symbol names from a dynsym table (imports incl. canary)."""
    ent = 24 if is_64 else 16
    names: list[str] = []
    if symtab_off + ent > len(data):
        return names
    for off in range(symtab_off, len(data) - ent + 1, ent):
        st_name = struct.unpack_from("<I", data, off)[0]
        if st_name == 0:
            if off > symtab_off:
                break
            continue
        names.append(_read_cstr(data, strtab_off + st_name))
    return names
