"""revai-tools CLI.

Implemented: triage, hashes, strings, sections, sec, iocs, scan, map, sinks
(import-level). Disassembly-backed commands (audit, paths, xrefs, funcs, dis)
are planned — see docs/PLAN.md.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import hashes as hashes_mod
import iocs as iocs_mod
import map as map_mod
import mitigations
import scan as scan_mod
import sections as sections_mod
import sinkcat
import strings as strings_mod
import r2backend
import elf as elf_mod
import elf_macho
import pe as pe_mod
from output import render

PLANNED = ("paths", "xrefs", "funcs", "dis")


def _load_pe(path: str) -> pe_mod.PE:
    return pe_mod.parse_pe(path)


def _load_elf(path: str) -> elf_mod.ELF:
    return elf_mod.parse_elf(path)


def _load_format(path: str):
    fmt = _detect_format(path)
    if fmt == "pe":
        return "pe", _load_pe(path)
    if fmt == "elf":
        return "elf", _load_elf(path)
    raise elf_macho.FormatNotImplemented(f"{fmt} parsing planned (milestone 2)")


def _detect_format(path: str) -> str:
    data = Path(path).read_bytes()[:4]
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"):
        return "macho"
    return "unknown"


def _cmd_triage(args) -> dict:
    fmt = _detect_format(args.file)
    if fmt != "pe":
        raise elf_macho.FormatNotImplemented(f"{fmt} parsing planned (milestone 2)")
    pe = _load_pe(args.file)
    data = pe.data
    h = hashes_mod.file_hashes(data)
    imp = hashes_mod.imphash([i.__dict__ for i in pe.imports])
    iocs = iocs_mod.extract_iocs(data)
    for s in pe.sections:
        raw = data[s.raw_pointer:s.raw_pointer + s.raw_size]
        s.entropy = sections_mod.shannon_entropy(raw)
    return {
        "file": pe.path,
        "format": "pe",
        "architecture": pe.to_dict()["architecture"],
        "hashes": {**h, "imphash": imp},
        "entry_point": hex(pe.entry_point),
        "subsystem": pe.subsystem_name,
        "sections": [s.to_dict() for s in pe.sections],
        "imports": [{"dll": i.dll, "count": len(i.functions)} for i in pe.imports],
        "iocs": {k: v[:50] for k, v in iocs.items()},
        "mitigations": mitigations.analyze_mitigations(pe),
        "scan": scan_mod.scan_file(data),
        "entropy": map_mod.entropy_map(data),
    }


def _cmd_hashes(args) -> dict:
    data = Path(args.file).read_bytes()
    out = hashes_mod.file_hashes(data)
    if args.imphash:
        fmt = _detect_format(args.file)
        if fmt == "pe":
            pe = _load_pe(args.file)
            out["imphash"] = hashes_mod.imphash([i.__dict__ for i in pe.imports])
        else:
            out["imphash"] = "n/a"
    return out


def _cmd_strings(args) -> dict:
    data = Path(args.file).read_bytes()
    return {"strings": strings_mod.extract_strings(data, min_len=args.min)}


def _cmd_sections(args) -> dict:
    pe = _load_pe(args.file)
    out = []
    for s in pe.sections:
        raw = pe.data[s.raw_pointer:s.raw_pointer + s.raw_size]
        s.entropy = sections_mod.shannon_entropy(raw)
        out.append(s.to_dict())
    return {"sections": out}


def _cmd_sec(args) -> dict:
    fmt, obj = _load_format(args.file)
    return mitigations.analyze_mitigations(obj)


def _backend() -> r2backend.R2Backend:
    return r2backend.R2Backend()


def _cmd_sinks(args) -> dict:
    fmt, obj = _load_format(args.file)
    if fmt == "pe":
        imports = [{"vaddr": 0, "lib": i.dll, "name": fn}
                   for i in getattr(obj, "imports", []) for fn in i.functions]
        entry = obj.entry_point
    else:
        imports = []
        entry = obj.entry_point
    backend = _backend()
    analysis = backend.analyze(args.file, [])
    imports = analysis["imports"] or imports
    sites = sinkcat.resolve_sinks(args.file, backend, imports, sinkcat.SINK_CATALOGUE)
    return {"format": fmt, "entry_point": hex(entry),
            "sink_count": len(sites),
            "sinks": [{"api": s["api"], "dll": s["dll"], "class": s["class"],
                       "address": hex(s["address"]), "function": s["function"]}
                      for s in sites]}


def _cmd_audit(args) -> dict:
    fmt, obj = _load_format(args.file)
    if fmt == "pe":
        imports = [{"vaddr": 0, "lib": i.dll, "name": fn}
                   for i in getattr(obj, "imports", []) for fn in i.functions]
        entry = obj.entry_point
    else:
        imports = []
        entry = obj.entry_point
    backend = _backend()
    analysis = backend.analyze(args.file, [])
    imports = analysis["imports"] or imports
    sites = sinkcat.resolve_sinks(args.file, backend, imports, sinkcat.SINK_CATALOGUE)
    entries = [entry]
    findings = sinkcat.audit_sites(args.file, backend, sites, entries)
    return {"format": fmt,
            "findings": [{"api": f["api"], "class": f["class"],
                          "address": hex(f["address"]), "function": f["function"],
                          "patterns": f["patterns"], "provenance": f["provenance"]}
                         for f in findings]}


def _cmd_iocs(args) -> dict:
    data = Path(args.file).read_bytes()
    return iocs_mod.extract_iocs(data)


def _cmd_scan(args) -> dict:
    data = Path(args.file).read_bytes()
    return scan_mod.scan_file(data)


def _cmd_map(args) -> dict:
    data = Path(args.file).read_bytes()
    return map_mod.entropy_map(data)


def _add_json(parser) -> None:
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="revai-tools",
                                 description="RevAI internal binary-analysis toolchain")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("triage", help="full static triage")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_triage)

    p = sub.add_parser("hashes", help="md5/sha1/sha256[/imphash]")
    p.add_argument("file")
    p.add_argument("--imphash", action="store_true")
    _add_json(p)
    p.set_defaults(func=_cmd_hashes)

    p = sub.add_parser("strings", help="ASCII/UTF-16 strings")
    p.add_argument("file")
    p.add_argument("--min", type=int, default=4)
    _add_json(p)
    p.set_defaults(func=_cmd_strings)

    p = sub.add_parser("sections", help="sections with entropy + flags")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_sections)

    p = sub.add_parser("sec", help="exploit mitigations with consequences")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_sec)

    p = sub.add_parser("iocs", help="IOC extraction (defanged)")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_iocs)

    p = sub.add_parser("scan", help="crypto constants + packer markers")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("map", help="entropy profile")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_map)

    p = sub.add_parser("sinks", help="dangerous-API call sites (r2-backed)")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_sinks)

    p = sub.add_parser("audit", help="sink sites with exploitable arg provenance (r2-backed)")
    p.add_argument("file")
    _add_json(p)
    p.set_defaults(func=_cmd_audit)

    for name in PLANNED:
        p = sub.add_parser(name, help="planned — requires disasm backend (milestone 2)")
        p.add_argument("file", nargs="?")
        p.set_defaults(func=None, planned=name)

    args = ap.parse_args(argv)
    if getattr(args, "planned", None):
        print(f"revai-tools: '{args.planned}' is planned — requires the disasm "
              f"backend (milestone 2). See docs/PLAN.md.")
        return 2
    try:
        result = args.func(args)
    except elf_macho.FormatNotImplemented as e:
        print(f"revai-tools: {e}", file=sys.stderr)
        return 2
    except pe_mod.PEParseError as e:
        print(f"revai-tools: parse error: {e}", file=sys.stderr)
        return 1
    print(render(result, args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
