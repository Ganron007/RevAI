"""PE32/PE32+ parsing — implemented from scratch on the C structures.

stdlib `struct` only. Covers: DOS/PE headers, COFF header, optional header,
section table, data directories, and a lazy import-table walk (IAT descriptors
→ DLL names + function names, honoring the original-first-thunk fallback).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

IMAGE_DOS_SIGNATURE = 0x5A4D          # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550        # "PE\0\0"
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_IAT = 12

IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664


class PEParseError(ValueError):
    pass


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_pointer: int
    characteristics: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    @property
    def memory_only(self) -> bool:
        return self.raw_size == 0 and self.virtual_size > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "virtual_address": self.virtual_address,
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "raw_pointer": self.raw_pointer,
            "characteristics": self.characteristics,
            "executable": self.executable,
            "writable": self.writable,
            "memory_only": self.memory_only,
            "entropy": round(self.entropy, 3),
        }


@dataclass
class Import:
    dll: str
    functions: list[str] = field(default_factory=list)


@dataclass
class PE:
    path: str
    data: bytes
    machine: int
    is_64: bool
    image_base: int
    entry_point: int
    section_alignment: int
    file_alignment: int
    dll_characteristics: int
    subsystem: int
    checksum: int
    sections: list[Section]
    imports: list[Import]
    guard_cf_table_rva: int = 0
    guard_cf_table_size: int = 0

    @property
    def subsystem_name(self) -> str:
        return {1: "native", 2: "windows_gui", 3: "windows_cui", 9: "windows_ce"}.get(
            self.subsystem, f"unknown_{self.subsystem}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "machine": hex(self.machine),
            "architecture": "x64" if self.is_64 else "x86",
            "image_base": hex(self.image_base),
            "entry_point": hex(self.entry_point),
            "subsystem": self.subsystem_name,
            "checksum": self.checksum,
            "dll_characteristics": self.dll_characteristics,
            "sections": [s.to_dict() for s in self.sections],
            "imports": [
                {"dll": i.dll, "functions": i.functions} for i in self.imports
            ],
        }


def _read_cstr(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    if end == -1:
        end = len(data)
    return data[off:end].decode("latin-1", errors="replace")


def _rva_to_offset(data: bytes, sections: list[Section], rva: int) -> int | None:
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            delta = rva - s.virtual_address
            if delta < s.raw_size:
                return s.raw_pointer + delta
            return None
    return None


def parse_pe(path: str | Path) -> PE:
    path = str(path)
    data = Path(path).read_bytes()
    if len(data) < 0x40 or struct.unpack_from("<H", data, 0)[0] != IMAGE_DOS_SIGNATURE:
        raise PEParseError("not a PE: missing DOS header")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or struct.unpack_from("<I", data, e_lfanew)[0] != IMAGE_NT_SIGNATURE:
        raise PEParseError("not a PE: missing PE signature")

    coff = e_lfanew + 4
    machine, num_sections, _, _, _ = struct.unpack_from("<HHIII", data, coff)
    opt_off = coff + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    if not is_64 and magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        raise PEParseError(f"unknown optional-header magic 0x{magic:x}")

    if is_64:
        # +16: entry(4) baseofcode(4) imagebase(8) sectalign(4) filealign(4)
        #      versions(6x2) win32ver(4) sizeimage(4) sizeheaders(4)
        #      checksum(4) subsystem(2) dllchars(2)
        (
            _, entry_point, _, image_base, section_alignment,
            file_alignment, _, _, _, _, _, _, _, _, _, subsystem,
            dll_characteristics,
        ) = struct.unpack_from("<IIQIIHHHHHHIIIIHH", data, opt_off + 16)
    else:
        # +16: entry(4) baseofcode(4) basedata(4) imagebase(4) sectalign(4)
        #      filealign(4) versions(6x2) win32ver(4) sizeimage(4)
        #      sizeheaders(4) checksum(4) subsystem(2) dllchars(2)
        (
            _, entry_point, _, _, image_base, section_alignment,
            file_alignment, _, _, _, _, _, _, _, _, _, subsystem,
            dll_characteristics,
        ) = struct.unpack_from("<IIIIIIHHHHHHIIIIHH", data, opt_off + 16)
    checksum = struct.unpack_from("<I", data, opt_off + 64)[0]
    num_dirs = struct.unpack_from("<I", data, opt_off + 92)[0]

    size_of_opt = struct.unpack_from("<H", data, coff + 16)[0]
    sec_off = opt_off + size_of_opt
    if sec_off + num_sections * 40 > len(data):
        raise PEParseError("truncated section table")

    sections: list[Section] = []
    for i in range(num_sections):
        off = sec_off + i * 40
        raw_name = data[off:off + IMAGE_SIZEOF_SHORT_NAME].rstrip(b"\x00")
        name = raw_name.decode("latin-1", errors="replace")
        vsize, vaddr, rsize, rptr, _, _, chars = struct.unpack_from("<IIIIIIH", data, off + 8)
        sections.append(Section(name, vaddr, vsize, rsize, rptr, chars))

    imports: list[Import] = []
    dirs_off = opt_off + 96
    if num_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT:
        import_rva, import_size = struct.unpack_from("<II", data, dirs_off + IMAGE_DIRECTORY_ENTRY_IMPORT * 8)
        guard_cf_rva = guard_cf_size = 0
        if num_dirs > 13:
            guard_cf_rva, guard_cf_size = struct.unpack_from("<II", data, dirs_off + 13 * 8)
        off = _rva_to_offset(data, sections, import_rva)
        seen_dlls: set[str] = set()
        for _ in range(4096):
            if off is None or off + 20 > len(data):
                break
            oft_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", data, off)
            if name_rva == 0:
                break
            name_off = _rva_to_offset(data, sections, name_rva)
            if name_off is None:
                break
            dll = _read_cstr(data, name_off)
            funcs: list[str] = []
            thunk_rva = oft_rva or iat_rva
            thunk_off = _rva_to_offset(data, sections, thunk_rva) if thunk_rva else None
            while thunk_off is not None and thunk_off + (8 if is_64 else 4) <= len(data):
                thunk = struct.unpack_from("<Q" if is_64 else "<I", data, thunk_off)[0]
                if thunk == 0:
                    break
                if thunk & (0x8000000000000000 if is_64 else 0x80000000):
                    funcs.append(f"ordinal_{thunk & 0xFFFF}")
                else:
                    hint_name = _rva_to_offset(data, sections, thunk & 0x7FFFFFFF)
                    if hint_name is not None and hint_name + 2 <= len(data):
                        funcs.append(_read_cstr(data, hint_name + 2))
                    else:
                        funcs.append(f"0x{thunk:x}")
                thunk_off += 8 if is_64 else 4
            if dll and dll not in seen_dlls:
                seen_dlls.add(dll)
                imports.append(Import(dll, funcs))
            off += 20
    else:
        guard_cf_rva = guard_cf_size = 0

    return PE(
        path=path, data=data, machine=machine, is_64=is_64,
        image_base=image_base, entry_point=entry_point,
        section_alignment=section_alignment, file_alignment=file_alignment,
        dll_characteristics=dll_characteristics, subsystem=subsystem,
        checksum=checksum, sections=sections, imports=imports,
        guard_cf_table_rva=guard_cf_rva, guard_cf_table_size=guard_cf_size,
    )
