"""file_type.py — detect binary format from magic bytes.

Supports: PE (Windows), .NET (PE+CLR), ELF (Linux), Mach-O (macOS),
PDF / OLE / OOXML (document triage — MAP L1 §6).

Returns dict: {"format": "pe"|"elf"|"macho"|"dotnet"|"pdf"|"ole"|"ooxml"|"unknown", ...}

Usage:
    from file_type import detect_file_type
    info = detect_file_type("/path/to/sample")
    if info["format"] == "elf":
        # use ELF-specific analyzers
    elif info["format"] == "pe" and info["arch"] == "x86":
        # use PE-specific
"""
from pathlib import Path
import zipfile


def detect_file_type(path: str) -> dict:
    """Read first 64 bytes + return detected format + metadata."""
    p = Path(path)
    if not p.exists():
        return {"format": "unknown", "error": f"file not found: {path}"}
    # Read 512 bytes — enough for PE (e_lfanew+24) and ELF (52 bytes for e_type/e_machine)
    with open(p, "rb") as f:
        head = f.read(512)
    if len(head) < 4:
        return {"format": "unknown", "error": "file too small"}
    # PDF
    if head.startswith(b"%PDF"):
        return {
            "format": "pdf",
            "os": "document",
            "arch": "n/a",
            "bits": 0,
            "endian": "n/a",
            "magic": "PDF",
            "doc_triage": True,
        }
    # OLE Compound File (legacy Office .doc/.xls/.ppt)
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return {
            "format": "ole",
            "os": "document",
            "arch": "n/a",
            "bits": 0,
            "endian": "n/a",
            "magic": "OLE",
            "doc_triage": True,
        }
    # ZIP / OOXML (.docx/.xlsx/.pptx) — distinguish from generic zip later if needed
    if head[:2] == b"PK":
        try:
            with zipfile.ZipFile(p) as zf:
                names = set(zf.namelist())
            if any(n.startswith("word/") for n in names) or "[Content_Types].xml" in names:
                kind = "ooxml"
                if any(n.startswith("xl/") for n in names):
                    kind = "ooxml_xlsx"
                elif any(n.startswith("ppt/") for n in names):
                    kind = "ooxml_pptx"
                elif any(n.startswith("word/") for n in names):
                    kind = "ooxml_docx"
                return {
                    "format": "ooxml",
                    "ooxml_kind": kind,
                    "os": "document",
                    "arch": "n/a",
                    "bits": 0,
                    "endian": "n/a",
                    "magic": "PK/OOXML",
                    "doc_triage": True,
                }
        except zipfile.BadZipFile:
            pass
    # PE: 0x4D 0x5A 0x90 0x00 ('MZ\x90\x00')
    if head[:2] == b"MZ":
        info = _detect_pe(head, p)
        # Compound / binder check: scan whole file for additional MZ headers
        # (binders concatenate multiple PEs to drop at runtime). Use chunked
        # read so we don't miss MZ headers that fall between step boundaries.
        try:
            size = p.stat().st_size
            if size > 4096:
                with open(p, "rb") as f:
                    mz_count = 1
                    emb_offsets = [0]
                    CHUNK = 65536  # 64KB scan blocks
                    overlap = 2     # re-read 2 bytes at chunk boundary
                    f.seek(0)
                    buf = f.read(CHUNK + overlap)
                    last_off = 0
                    while buf:
                        # Find MZ in buffer (note: MZ is 2 bytes; we accept
                        # any MZ\? because we just want rough count)
                        i = 0
                        while i < len(buf) - 1:
                            if buf[i] == 0x4D and buf[i + 1] == 0x5A:
                                # Skip the MZ at offset 0 (counted already)
                                if last_off + i > 0:
                                    # Avoid double-counting same offset
                                    if not emb_offsets or last_off + i - emb_offsets[-1] > 1:
                                        mz_count += 1
                                        emb_offsets.append(last_off + i)
                                        if len(emb_offsets) >= 8:
                                            break
                                i += 2
                            else:
                                i += 1
                        if len(emb_offsets) >= 8:
                            break
                        last_off += CHUNK
                        if last_off >= size:
                            break
                        f.seek(last_off)
                        buf = f.read(CHUNK + overlap)
                if mz_count > 1:
                    info["compound"] = "binder"
                    info["embedded_pe_count"] = mz_count
                    info["embedded_pe_offsets"] = emb_offsets[:8]
        except OSError:
            pass
        return info
    # ELF: 0x7F 'E' 'L' 'F'
    if head[:4] == b"\x7fELF":
        return _detect_elf(head)
    # Mach-O
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return _detect_macho(head)
    # Script / text? (only if first 512 bytes decode as text — PE is excluded)
    try:
        head.decode("utf-8")
        text = head[:512].decode("utf-8", errors="replace")
        # Detect common script types by content (not extension)
        lower = text.lstrip().lower()
        script_format = None
        if lower.startswith("@echo off") or lower.startswith("rem ") or "set " in lower[:200]:
            script_format = "batch"
        elif lower.startswith("#!/") or lower.startswith("#!/"):
            script_format = "shell"
        elif lower.startswith("<script") or lower.startswith("//") or "function " in lower[:200]:
            script_format = "script"
        elif lower.startswith("using ") and ";" in lower[:200]:
            script_format = "csharp"  # fallback for .NET source
        return {
            "format": "text",
            "os": "?",
            "arch": "?",
            "bits": 0,
            "script_type": script_format,
            "magic": text[:16],
        }
    except Exception:
        pass
    return {"format": "unknown", "magic": head[:8].hex()}


def _detect_pe(head: bytes, p: Path) -> dict:
    """PE parsing: find PE\0\0 signature at e_lfanew offset, check for .NET CLR header."""
    info = {"format": "pe", "os": "windows", "arch": "?", "bits": 32,
            "endian": "little", "magic": "MZ"}
    e_lfanew = int.from_bytes(head[0x3c:0x40], "little")
    if e_lfanew + 6 > len(head):
        return info
    if head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return info
    machine = int.from_bytes(head[e_lfanew + 4:e_lfanew + 6], "little")
    # Machine constants from winnt.h (full 16-bit values)
    PE_ARCH = {
        0x014c: ("x86", 32), 0x8664: ("x86_64", 64), 0x01c0: ("arm", 32),
        0xaa64: ("arm64", 64), 0x01c4: ("armnt", 32), 0x0200: ("ia64", 64),
    }
    # Check both full 16-bit and short 12-bit (some files have just low bits)
    if machine in PE_ARCH:
        info["arch"], info["bits"] = PE_ARCH[machine]
    elif (machine & 0xFFFF) in PE_ARCH:
        info["arch"], info["bits"] = PE_ARCH[machine & 0xFFFF]
    else:
        info["arch"] = f"unknown(0x{machine:04x})"
    # .NET detection: 14th data directory entry = COM descriptor (CLR runtime header)
    # At e_lfanew + 24 (PE sig + COFF header) + optional_header + 14*8
    # Optional header size: PE32=224, PE32+=240
    opt_magic = int.from_bytes(head[e_lfanew + 24:e_lfanew + 26], "little") if e_lfanew + 26 <= len(head) else 0x10b
    if opt_magic == 0x20b:  # PE32+
        opt_data_dir_offset = 112
    else:
        opt_data_dir_offset = 96
    clr_dir_offset = e_lfanew + 24 + opt_data_dir_offset + 14 * 8
    if clr_dir_offset + 8 <= len(head):
        rva = int.from_bytes(head[clr_dir_offset:clr_dir_offset + 4], "little")
        if rva != 0:
            info["format"] = "dotnet"
            info["dotnet"] = True
    return info


def _detect_elf(head: bytes) -> dict:
    """ELF parsing: class (32/64), endian, e_machine, OS via EI_OSABI."""
    info = {"format": "elf", "os": "linux", "arch": "?", "bits": 32,
            "endian": "little", "magic": "ELF"}
    if len(head) < 20:
        return info
    # EI_CLASS: byte 4 (1=32bit, 2=64bit)
    info["bits"] = 64 if head[4] == 2 else 32
    # EI_DATA: byte 5 (1=LE, 2=BE)
    info["endian"] = "little" if head[5] == 1 else "big"
    # e_machine at offset 18 (2 bytes)
    e_machine = int.from_bytes(head[18:20], info["endian"])
    ELF_ARCH = {
        0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "arm64",
        0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0x16: "s390",
        0x32: "ia64", 0xF3: "riscv", 0xEB: "avr",
    }
    if e_machine in ELF_ARCH:
        info["arch"] = ELF_ARCH[e_machine]
    # EI_OSABI: byte 7
    OSABI = {
        0x03: "linux", 0x09: "freebsd", 0x0C: "openbsd",
    }
    if head[7] in OSABI:
        info["os"] = OSABI[head[7]]
    return info


def _detect_macho(head: bytes) -> dict:
    """Mach-O parsing: magic + cputype."""
    info = {"format": "macho", "os": "macos", "arch": "?", "bits": 32,
            "endian": "little", "magic": "Mach-O"}
    magic = head[:4]
    # 0xCAFEBABE = fat/universal, 0xFEEDFACE = 32-bit, 0xFEEDFACF = 64-bit
    if magic == b"\xca\xfe\xba\xbe":
        info["format"] = "macho_fat"
        info["bits"] = "fat"
        return info
    if magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        info["bits"] = 32
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        info["bits"] = 64
    # cputype at offset 4 (4 bytes)
    cputype = int.from_bytes(head[4:8], "big")
    MACHO_ARCH = {
        0x07: ("i386", 32), 0x01000007: ("x86_64", 64),
        0x0C: ("arm", 32), 0x0100000C: ("arm64", 64),
        0x12: ("ppc", 32), 0x01000012: ("ppc64", 64),
    }
    if cputype in MACHO_ARCH:
        info["arch"], info["bits"] = MACHO_ARCH[cputype]
    return info


if __name__ == "__main__":
    import sys, json
    for p in sys.argv[1:]:
        info = detect_file_type(p)
        print(f"{p}\n  {json.dumps(info, indent=2)}")
