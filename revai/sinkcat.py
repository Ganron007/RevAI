"""Sink call-site resolution + audit provenance walk (x86/x64).

`resolve_sinks` maps the catalogue to concrete call sites via import-vaddr
xrefs (imports are the 90% case for the Windows API catalogue).
`audit_sites` walks each site's argument provenance backward over linear
disassembly and flags only sites whose provenance matches a bug pattern —
a memcpy whose length was just computed by a subtraction (underflow), an
allocation sized by a multiply (integer overflow), a printf whose format
string is loaded from memory rather than a constant, an unbounded copy
reachable from an export.
"""

from __future__ import annotations

import re
from typing import Any

from backend import DisasmBackend, Function, Instruction

# x86-32: args on stack [esp+N] pushed before call; fastcall uses ecx/edx.
# x64: rcx, rdx, r8, r9.
ARG_REGS_64 = ("rcx", "rdx", "r8", "r9")
ARG_REGS_32 = ("ecx", "edx", "esi")

# API name -> bug class. One entry per API family; the catalogue is ours.
SINK_CATALOGUE: dict[str, str] = {
    "memcpy": "unbounded_copy",
    "memmove": "unbounded_copy",
    "strcpy": "unbounded_copy",
    "strcat": "unbounded_copy",
    "wcscpy": "unbounded_copy",
    "wcscat": "unbounded_copy",
    "sprintf": "format_string",
    "vsprintf": "format_string",
    "swprintf": "format_string",
    "wsprintfa": "format_string",
    "wsprintfw": "format_string",
    "printf": "format_string",
    "fprintf": "format_string",
    "gets": "unbounded_input",
    "scanf": "unbounded_input",
    "alloca": "input_sized_stack",
    "_alloca": "input_sized_stack",
    "malloc": "integer_overflow_size",
    "calloc": "integer_overflow_size",
    "realloc": "integer_overflow_size",
    "heapalloc": "integer_overflow_size",
    "virtualalloc": "integer_overflow_size",
    "system": "command_execution",
    "popen": "command_execution",
    "winexec": "command_execution",
    "shellexecutea": "command_execution",
    "shellexecutew": "command_execution",
    "createprocessa": "command_execution",
    "createprocessw": "command_execution",
    "tmpfile": "temp_file_race",
    "tmpnam": "temp_file_race",
    "rand": "weak_randomness",
    "srand": "weak_randomness",
    "cryptgenrandom": "strong_randomness",
}

_MOV_RE = re.compile(r"^(mov|lea|movzx|movsx|and|or|xor|sub|add|imul|shl|shr|sar|inc|dec)\s+([re]?[abcds]x|[re]?[sd]i|[r]?[0-9]+)\s*,\s*(.+)$")
_PUSH_RE = re.compile(r"^push\s+(.+)$")
_CALL_RE = re.compile(r"^call\s+(.+)$")

PROVENANCE_WINDOW = 20


def resolve_sinks(path: str, backend: DisasmBackend,
                  imports: list[dict[str, Any]],
                  catalogue: dict[str, str]) -> list[dict[str, Any]]:
    """Catalogue hits at concrete call sites (import-vaddr xrefs)."""
    by_name: dict[str, dict[str, Any]] = {}
    for imp in imports:
        base = (imp.get("name") or "").lower()
        if base in catalogue:
            by_name[base] = imp
    targets = [v["vaddr"] for v in by_name.values()]
    if not targets:
        return []
    analysis = backend.analyze(path, targets)
    xrefs = analysis["xrefs"]
    func_by_addr = {f.address: f for f in analysis["functions"]}

    def _containing(addr: int) -> str:
        for f in analysis["functions"]:
            if f.address <= addr < f.address + max(f.size, 1):
                return f.name
        return ""

    sites: list[dict[str, Any]] = []
    for base, imp in by_name.items():
        for addr in xrefs.get(imp["vaddr"], []):
            sites.append({
                "api": base,
                "dll": imp.get("lib"),
                "class": catalogue[base],
                "address": addr,
                "function": _containing(addr),
            })
    return sites


def audit_sites(path: str, backend: DisasmBackend, sites: list[dict[str, Any]],
                entries: list[int]) -> list[dict[str, Any]]:
    """Keep only sites whose provenance matches a bug pattern."""
    if not sites:
        return []
    windows = backend.disasm(path, [s["address"] for s in sites])
    funcs = backend.functions(path)
    func_map = {f.address: f for f in funcs}
    call_graph = _build_call_graph(path, backend, funcs)
    reachable = _reachable_from(entries, call_graph, func_map)

    findings: list[dict[str, Any]] = []
    for s in sites:
        insns = windows.get(s["address"], [])
        args = _collect_args(insns, s["address"])
        pats = _match_patterns(s["class"], args)
        if s["class"] in ("unbounded_copy", "command_execution") and \
                _function_reachable(s["function"], func_map, reachable):
            pats.append("export_reachable")
        if pats:
            findings.append({**s, "patterns": sorted(set(pats)),
                             "provenance": args})
    return findings


def _build_call_graph(path: str, backend: DisasmBackend,
                      funcs: list[Function]) -> dict[int, set[int]]:
    graph: dict[int, set[int]] = {}
    for f in funcs:
        graph.setdefault(f.address, set())
    for f in funcs:
        for caller_addr in backend.xrefs(path, f.address):
            caller = _addr_in_func(caller_addr, funcs)
            if caller is not None:
                graph.setdefault(caller, set()).add(f.address)
    return graph


def _reachable_from(entries: list[int], graph: dict[int, set[int]],
                    func_map: dict[int, Function]) -> set[int]:
    seen: set[int] = set()
    stack = [e for e in entries if e in func_map]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for nxt in graph.get(cur, set()):
            if nxt not in seen:
                stack.append(nxt)
    return seen


def _function_reachable(name: str, func_map: dict[int, Function],
                        reachable: set[int]) -> bool:
    if not name:
        return False
    for addr, f in func_map.items():
        if f.name == name:
            return addr in reachable
    return False


def _addr_in_func(addr: int, funcs: list[Function]) -> int | None:
    for f in funcs:
        if f.address <= addr < f.address + max(f.size, 1):
            return f.address
    return None


def _collect_args(insns: list[Instruction], site: int) -> dict[str, str]:
    """Backward walk: last assignment per argument register, plus x86-32
    stack pushes (cdecl right-to-left: last push before the call = arg1).
    Stops at the previous call/ret — provenance never crosses a call
    boundary. Pushed register values resolve to their last assignment."""
    pushes: list[str] = []
    regs_last: dict[str, str] = {}
    for insn in insns:
        if insn.address >= site:
            break
        line = f"{insn.mnemonic} {insn.operands}".strip()
        if insn.mnemonic in ("call", "ret", "jmp", "jz", "jnz", "je", "jne"):
            pushes = []
            regs_last = {}
            continue
        m = _PUSH_RE.match(line)
        if m:
            pushes.append(m.group(1))
        else:
            m = _MOV_RE.match(line)
            if m:
                regs_last[m.group(2)] = f"{m.group(1)} {m.group(3)}"

    def _resolve(v: str) -> str:
        if v.lower() in regs_last:
            return f"{v} <- {regs_last[v.lower()]}"
        return v

    args: dict[str, str] = {}
    n = 0
    for v in reversed(pushes):
        n += 1
        args[f"arg{n}"] = _resolve(v)
        if n >= 4:
            break
    for reg in ARG_REGS_64:
        if reg in regs_last:
            args[reg] = regs_last[reg]
    return args


def _match_patterns(sink_class: str, args: dict[str, str]) -> list[str]:
    pats: list[str] = []
    vals = " ".join(args.values()).lower()
    fmt = args.get("arg2") or args.get("rcx") or ""
    if sink_class == "unbounded_copy":
        if "sub " in vals or "- 0x" in vals:
            pats.append("subtraction")
        if "lea " in vals and "[" in vals:
            pats.append("direct_string")
    elif sink_class == "format_string":
        if fmt and "lea " not in fmt.lower() and not fmt.lower().startswith("0x"):
            pats.append("format_from_memory")
    elif sink_class in ("integer_overflow_size", "input_sized_stack"):
        if "imul" in vals or "mul " in vals or "shl" in vals:
            pats.append("multiply")
    elif sink_class == "command_execution":
        if "lea " in vals or "add " in vals:
            pats.append("concat_built")
    return pats
