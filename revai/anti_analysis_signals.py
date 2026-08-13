#!/usr/bin/env python3
"""
anti_analysis_signals.py — deterministic anti-analysis signal extractor (Ghidra SQL).

Signals (2026-08-09):
  - breakpoints on "high-value Windows/Native API calls that suggest logic,
    evasion, or communication"; TLS callbacks run BEFORE the entry point;
    timing-check anti-debug (GetTickCount64 + NtDelayExecution).
  - PEB BeingDebugged (FS:[0x30]), IsDebuggerPresent,
    SetUnhandledExceptionFilter, process/artifact checks, CPUID/VM artifact
    strings; the "self-defending malware" stage.

No `instructions.func_addr` column exists in ghidrasql (verified 2026-08-09),
so instruction-level findings are mapped to functions via the funcs address
range in Python. Every query is lightweight and failure-safe: the extractor
never raises — on any error it returns {"error": ...} so the pipeline cannot
break.

Output shape:
    {
      "engine": "anti_analysis_signals",
      "signals": [ {category, weight, func_addr, func_name, evidence, note} ],
      "functions": { "<addr>": {"name", "score", "signals": [...], "evidence": [...]} },
      "summary": {"categories": {...}, "total_signals": N, "functions_with_signals": N},
    }
"""
from __future__ import annotations

import re
import time
from typing import Any

# Anti-debug / anti-analysis APIs (callers are prime LLM-analysis candidates)
DEBUGGER_APIS = (
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugString", "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
    "DebugActiveProcess", "NtSetInformationThread", "GetThreadContext", "SetThreadContext",
    "FindWindowA", "FindWindowW", "GetWindowThreadProcessId",
)
# Timing APIs — two distinct calls in one function => timing check heuristic
TIMING_APIS = (
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    "NtQueryPerformanceCounter", "timeGetTime", "GetSystemTimeAsFileTime",
    "GetLocalTime", "NtGetSystemTime", "NtDelayExecution", "SleepEx", "Sleep",
)
# Process/tool-enumeration APIs (anti-analysis process scans)
PROCESS_SCAN_APIS = (
    "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW", "Process32First",
    "Process32Next", "EnumProcesses", "NtQuerySystemInformation",
    "EnumProcessModulesEx", "GetModuleFileNameExW", "GetModuleBaseNameW",
)

# VM / sandbox / analysis-tool artifacts embedded in strings.
# len >= 5 tokens: case-insensitive substring match (catches "VMwareTools",
# "vmtoolsd.exe", "x64dbg.exe"). Short tokens: word-boundary match only
# ("frida" must not match "Friday" — observed false positive 2026-08-09).
VM_ARTIFACT_SUBSTR = (
    "vmware", "vmtoolsd", "vboxguest", "vboxservice", "virtualbox", "qemu",
    "xenpci", "xenservice", "vmsrvc", "vmmouse", "sandboxie", "procmon",
    "wireshark", "ollydbg", "x64dbg", "x32dbg", "windbg", "dbgview",
    "apimonitor", "idaq", "radare", "ghidra", "immunity", "syser", "hiew",
    "ollyice", "mhook", "pestudio", "pe-bear",
)
VM_ARTIFACT_WORD = ("frida", "gdb", "ida", "upx", "sbie", "x64", "x32", "nmap", "tcpdump")

DEBUGGER_STRINGS = VM_ARTIFACT_SUBSTR + VM_ARTIFACT_WORD  # same artifact pool, single category

# Category -> weight (distinct signals per function, summed)
CATEGORY_WEIGHTS = {
    "tls_callback": 3,       # pre-EP code (TLS callbacks run before entry)
    "peb_access": 2,         # PEB BeingDebugged read (FS:[0x30] / GS:[0x60])
    "debugger_api": 2,       # IsDebuggerPresent / NtQueryInformationProcess etc.
    "seh_anti_debug": 2,     # SetUnhandledExceptionFilter / UnhandledExceptionFilter
    "timing_pair": 2,        # >=2 distinct timing APIs in one function
    "timing_single": 1,      # 1 timing API call (informational)
    "process_scan": 1,       # toolhelp/EnumProcesses process scans
    "vm_artifact": 2,        # VM/sandbox/analysis-tool artifact string referenced
    "debugger_string": 1,    # debugger/tool-name string referenced
}

_FS_PEB_RE = re.compile(r"[FG]S:\s*\[?0x[36]0", re.IGNORECASE)
_MODULE_WALK_RE = re.compile(r"[FG]S:\s*\[?0x(?:0c|14|1c|20|24|28)", re.IGNORECASE)
_WORD_RE_CACHE: dict[str, re.Pattern] = {}


def _word_re(token: str) -> re.Pattern:
    p = _WORD_RE_CACHE.get(token)
    if p is None:
        p = re.compile(rf"\b{re.escape(token)}\b", re.IGNORECASE)
        _WORD_RE_CACHE[token] = p
    return p


def _addr_key(addr: Any) -> str:
    return str(int(addr)) if addr is not None else ""


def _containing_func(addr: int, func_ranges: list[tuple[int, int, dict]]) -> dict | None:
    """Find the function whose [address, address+size) contains `addr` (binary search)."""
    lo, hi = 0, len(func_ranges)
    while lo < hi:
        mid = (lo + hi) // 2
        start, end, f = func_ranges[mid]
        if addr < start:
            hi = mid
        elif addr >= end:
            lo = mid + 1
        else:
            return f
    return None


def extract_anti_analysis(client, session_id: str) -> dict:
    """Deterministic anti-analysis signal extraction over ghidrasql. Never raises."""
    t0 = time.time()
    out: dict[str, Any] = {
        "engine": "anti_analysis_signals",
        "signals": [],
        "functions": {},
        "summary": {},
    }
    try:
        funcs = client.ghidra_query(
            session_id, "SELECT addr AS address, name, size FROM funcs", max_rows=100000
        ).get("rows", [])
        func_ranges = sorted(
            (int(f.get("address") or 0), int(f.get("address") or 0) + int(f.get("size") or 0), f)
            for f in funcs
            if f.get("address") is not None
        )
        func_meta = {_addr_key(f.get("address")): f for f in funcs}

        def _emit(category: str, func: dict | None, evidence: str, note: str) -> None:
            addr = _addr_key(func.get("address")) if func else ""
            weight = CATEGORY_WEIGHTS.get(category, 1)
            sig = {
                "category": category, "weight": weight,
                "func_addr": addr,
                "func_name": (func or {}).get("name", "") if func else "",
                "evidence": evidence, "note": note,
            }
            out["signals"].append(sig)
            if func:
                rec = out["functions"].setdefault(addr, {
                    "name": (func or {}).get("name", ""),
                    "score": 0, "signals": [], "evidence": [],
                })
                if category not in rec["signals"]:
                    rec["signals"].append(category)
                    rec["score"] += weight
                if evidence not in rec["evidence"]:
                    rec["evidence"].append(evidence)

        # ---- 1) TLS callbacks: code xrefs into .tls memory block ----
        tls_blocks = [
            b for b in client.ghidra_query(
                session_id, "SELECT start_addr, end_addr, name FROM memory_blocks", max_rows=5000
            ).get("rows", [])
            if "tls" in str(b.get("name") or "").lower()
        ]
        for block in tls_blocks:
            s, e = int(block.get("start_addr") or 0), int(block.get("end_addr") or 0)
            refs = client.ghidra_query(
                session_id,
                f"SELECT from_addr, to_addr, is_code FROM xrefs WHERE to_addr >= {s} AND to_addr < {e} "
                f"AND is_code = 1 LIMIT 50",
                max_rows=50,
            ).get("rows", [])
            for r in refs:
                f = _containing_func(int(r.get("from_addr") or 0), func_ranges)
                _emit("tls_callback", f,
                      f"code xref {r.get('from_addr')} -> {block.get('name')} at {r.get('to_addr')}",
                      "TLS callback candidate (runs before entry point)")

        # ---- 2) PEB access via segment-offset instructions ----
        inst_rows = client.ghidra_query(
            session_id,
            "SELECT addr, mnemonic, operands FROM instructions "
            "WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'",
            max_rows=20000,
        ).get("rows", [])
        for r in inst_rows:
            ops = str(r.get("operands") or "")
            addr = int(r.get("addr") or 0)
            f = _containing_func(addr, func_ranges)
            if _FS_PEB_RE.search(ops):
                _emit("peb_access", f, f"{r.get('mnemonic')} {ops} @ {addr}",
                      "PEB read via FS:[0x30]/GS:[0x60] (BeingDebugged/ProcessHeap)")

        # ---- 3) API-based signals via callgraph ----
        # ghidrasql v0.0.4: the callgraph_edges VIEW materializes per-row
        # through COALESCE joins (100s+ hangs on full scans; LIKE cannot push
        # down). Rebuild the view in Python from the fast underlying tables:
        # call_edges + names (+ funcs already loaded above).
        names_map: dict[str, str] = {}
        for r in client.ghidra_query(
            session_id, "SELECT addr, name FROM names", max_rows=200000
        ).get("rows", []):
            names_map[_addr_key(r.get("addr"))] = str(r.get("name") or "")
        edge_rows = client.ghidra_query(
            session_id, "SELECT src_func_addr, dst_func_addr FROM call_edges",
            max_rows=200000,
        ).get("rows", [])

        def _dst_name(dst: Any) -> str:
            dk = _addr_key(dst)
            f = func_meta.get(dk)
            if f and f.get("name"):
                return str(f["name"])
            nm = names_map.get(dk)
            return nm or f"sub_{int(dst or 0):X}"

        def _api_callers(apis: tuple[str, ...]) -> list[dict]:
            out = []
            for e in edge_rows:
                dn = _dst_name(e.get("dst_func_addr"))
                if any(dn.startswith(a) for a in apis):
                    src_f = func_meta.get(_addr_key(e.get("src_func_addr"))) or {}
                    out.append({
                        "src_func_addr": e.get("src_func_addr"),
                        "src_func_name": str(src_f.get("name") or ""),
                        "dst_func_name": dn,
                    })
            return out

        for cat, apis, note in (
            ("debugger_api", DEBUGGER_APIS, "debugger-detection API"),
            ("seh_anti_debug", ("SetUnhandledExceptionFilter", "UnhandledExceptionFilter"),
             "SEH-based anti-debug"),
            ("process_scan", PROCESS_SCAN_APIS, "process/tool enumeration"),
        ):
            for r in _api_callers(apis):
                f = func_meta.get(_addr_key(r.get("src_func_addr")))
                _emit(cat, f, f"calls {r.get('dst_func_name')}", note)

        # timing: single vs pair
        timing_calls: dict[str, set[str]] = {}
        for r in _api_callers(TIMING_APIS):
            src = _addr_key(r.get("src_func_addr"))
            if src:
                timing_calls.setdefault(src, set()).add(str(r.get("dst_func_name") or ""))
        for src, names in timing_calls.items():
            f = func_meta.get(src)
            _emit("timing_pair" if len(names) >= 2 else "timing_single", f,
                  "timing APIs: " + ", ".join(sorted(names)),
                  ">=2 distinct timing APIs => timing check heuristic")

        # ---- 4) VM / debugger artifact strings referenced by functions ----
        str_rows = client.ghidra_query(
            session_id, "SELECT addr, content FROM strings WHERE length < 300",
            max_rows=100000,
        ).get("rows", [])
        matched_addrs: dict[int, list[tuple[str, str]]] = {}  # addr -> [(token, kind)]
        for r in str_rows:
            content = str(r.get("content") or "")
            addr = int(r.get("addr") or 0)
            lower = content.lower()
            for token in VM_ARTIFACT_SUBSTR:
                if token in lower:
                    matched_addrs.setdefault(addr, []).append((token, "vm_artifact"))
                    break
            for token in VM_ARTIFACT_WORD:
                if _word_re(token).search(content):
                    matched_addrs.setdefault(addr, []).append((token, "debugger_string"))
        if matched_addrs:
            sr_rows = client.ghidra_query(
                session_id, "SELECT func_addr, ref_addr, string_addr FROM string_refs",
                max_rows=100000,
            ).get("rows", [])
            for r in sr_rows:
                saddr = int(r.get("string_addr") or 0)
                hits = matched_addrs.get(saddr)
                if not hits:
                    continue
                f = (func_meta.get(_addr_key(r.get("func_addr")))
                     or _containing_func(int(r.get("ref_addr") or 0), func_ranges))
                for token, kind in hits:
                    _emit(kind, f, f"refs artifact string '{token}' @ {saddr}",
                          "VM/sandbox/analysis-tool artifact string")

        # ---- summary ----
        cats: dict[str, int] = {}
        for sig in out["signals"]:
            cats[sig["category"]] = cats.get(sig["category"], 0) + 1
        out["summary"] = {
            "categories": cats,
            "total_signals": len(out["signals"]),
            "functions_with_signals": len(out["functions"]),
            "elapsed_s": round(time.time() - t0, 2),
            "note": "Deterministic; TLS callbacks are pre-entry-point candidates.",
        }
    except Exception as e:  # never break the pipeline
        out["error"] = f"{type(e).__name__}: {e}"
    return out


if __name__ == "__main__":
    import json
    import sys

    sys.path.insert(0, "/opt/scripts")
    from ghidra_sql_client import get_ghidra_sql_client
    from v2_lib import load_session

    sha = sys.argv[1]
    sid = load_session(sha)["session_id"]
    result = extract_anti_analysis(get_ghidra_sql_client(), sid)
    print(json.dumps(result, indent=2, default=str))
