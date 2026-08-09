#!/usr/bin/env python3
"""
dynamic_resolve_detect.py — deterministic dynamic-API-resolve detector (Ghidra SQL).

Signals (2026-08-09):
  - hash-based resolver doing LoadLibrary then GetProcAddress; the
    IAT-rebuild trigger is "no further resolve calls". Resolve loops call the
    resolver function repeatedly with per-call hash/name arguments.
  - shellcode resolves LoadLibrary+GetProcAddress first; PEB walk
    (TEB+0x30 -> PEB -> Ldr -> InMemoryOrderModuleList) for export walking.
  - import-by-hash handling.

Sites flagged here are the "core logic" of packed/stripped samples — the static
import directory is empty for them, so pe_import_signals sees 0 imports.

Signals:
  1. resolver_funcs  — functions that call GetProcAddress* (the resolver itself)
  2. resolve_sites   — functions calling GetProcAddress or a resolver function
                       >= 2 times (resolve loops / hash-dispatch tables)
  3. peb_module_walk — functions with FS:[0x30]/GS:[0x60] PEB access AND offsets
                       in {0x0c,0x14,0x1c,0x20,0x24,0x28} (LDR/module-list walk)
  4. ordinal_imports — imports named Ordinal_* (dynamically resolved exports)

Deterministic and failure-safe: never raises; returns {"error": ...} on failure.
"""
from __future__ import annotations

import re
import time
from typing import Any

RESOLVER_APIS = (
    "GetProcAddress", "LdrGetProcedureAddress", "LdrGetProcedureAddressForCaller",
)
LOADER_APIS = (
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "LdrLoadDll", "GetModuleHandleA", "GetModuleHandleW",
    "GetModuleHandleExA", "GetModuleHandleExW",
)

MIN_RESOLVE_CALLS = 2  # resolve-loop threshold (calls to GPA/resolver per site)

_FS_PEB_RE = re.compile(r"[FG]S:\s*\[?0x[36]0", re.IGNORECASE)
_MODULE_WALK_RE = re.compile(r"[FG]S:\s*\[?0x(?:0c|14|1c|20|24|28)", re.IGNORECASE)


def _addr_key(addr: Any) -> str:
    return str(int(addr)) if addr is not None else ""


def _containing_func(addr: int, func_ranges: list[tuple[int, int, dict]]) -> dict | None:
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


def extract_dynamic_resolve(client, session_id: str) -> dict:
    """Deterministic dynamic-import-resolution detection over ghidrasql. Never raises."""
    t0 = time.time()
    out: dict[str, Any] = {"engine": "dynamic_resolve_detect", "summary": {}}
    try:
        funcs = client.ghidra_query(
            session_id, "SELECT address, name, size FROM funcs", max_rows=100000
        ).get("rows", [])
        func_ranges = sorted(
            (int(f.get("address") or 0), int(f.get("address") or 0) + int(f.get("size") or 0), f)
            for f in funcs
            if f.get("address") is not None
        )
        func_meta = {_addr_key(f.get("address")): f for f in funcs}

        def _like(apis: tuple[str, ...]) -> str:
            return " OR ".join(f"dst_func_name LIKE '{a}%'" for a in apis)

        # ---- 1) resolver functions (direct GetProcAddress callers) ----
        gpa_rows = client.ghidra_query(
            session_id,
            f"SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges "
            f"WHERE {_like(RESOLVER_APIS)}",
            max_rows=50000,
        ).get("rows", [])
        gpa_counts: dict[str, int] = {}
        for r in gpa_rows:
            src = _addr_key(r.get("src_func_addr"))
            if src:
                gpa_counts[src] = gpa_counts.get(src, 0) + 1
        resolver_addrs = {a for a, n in gpa_counts.items() if n >= 1}
        resolver_funcs = sorted(
            ({**func_meta.get(a, {}), "gpa_calls": gpa_counts.get(a, 0)} for a in resolver_addrs),
            key=lambda f: -int(f.get("gpa_calls") or 0),
        )

        # ---- 2) resolve sites: callers of resolver functions / GPA, >= 2 calls ----
        edges = client.ghidra_query(
            session_id,
            f"SELECT src_func_addr, dst_func_addr FROM call_edges",
            max_rows=200000,
        ).get("rows", [])
        resolve_calls: dict[str, int] = {}
        loader_calls: dict[str, int] = {}
        for e in edges:
            src = _addr_key(e.get("src_func_addr"))
            dst = _addr_key(e.get("dst_func_addr"))
            if not src or not dst:
                continue
            if dst in resolver_addrs:
                resolve_calls[src] = resolve_calls.get(src, 0) + 1
        # direct GPA callers also count (they are themselves resolver funcs)
        for a, n in gpa_counts.items():
            resolve_calls[a] = resolve_calls.get(a, 0) + n

        load_rows = client.ghidra_query(
            session_id,
            f"SELECT src_func_addr FROM callgraph_edges WHERE {_like(LOADER_APIS)}",
            max_rows=50000,
        ).get("rows", [])
        for r in load_rows:
            src = _addr_key(r.get("src_func_addr"))
            if src:
                loader_calls[src] = loader_calls.get(src, 0) + 1

        resolve_sites = []
        for a, n in resolve_calls.items():
            if n < MIN_RESOLVE_CALLS:
                continue
            f = func_meta.get(a, {})
            resolve_sites.append({
                "func_addr": a,
                "func_name": f.get("name", ""),
                "resolve_calls": n,
                "gpa_direct_calls": gpa_counts.get(a, 0),
                "loader_calls": loader_calls.get(a, 0),
                "score": n + loader_calls.get(a, 0) * 2,
            })
        resolve_sites.sort(key=lambda s: -s["score"])

        # ---- 3) PEB module walk (export walkers / shellcode loaders) ----
        inst_rows = client.ghidra_query(
            session_id,
            "SELECT address, mnemonic, operands FROM instructions "
            "WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'",
            max_rows=20000,
        ).get("rows", [])
        peb_funcs: dict[str, dict] = {}
        for r in inst_rows:
            addr = int(r.get("address") or 0)
            ops = str(r.get("operands") or "")
            f = _containing_func(addr, func_ranges)
            if not f:
                continue
            fa = _addr_key(f.get("address"))
            rec = peb_funcs.setdefault(fa, {"func": f, "peb": False, "walk": False})
            if _FS_PEB_RE.search(ops):
                rec["peb"] = True
            if _MODULE_WALK_RE.search(ops):
                rec["walk"] = True
        peb_walkers = [
            {"func_addr": fa, "func_name": rec["func"].get("name", ""),
             "peb_read": rec["peb"], "module_walk_offsets": rec["walk"]}
            for fa, rec in peb_funcs.items() if rec["peb"] and rec["walk"]
        ]

        # ---- 4) ordinal imports (dynamic exports) ----
        ordinal_rows = client.ghidra_query(
            session_id,
            "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'",
            max_rows=1000,
        ).get("rows", [])
        ordinal_imports = [
            {"name": r.get("name"), "module": r.get("module")} for r in ordinal_rows
        ]

        out.update({
            "resolver_funcs": resolver_funcs[:50],
            "resolve_sites": resolve_sites[:50],
            "peb_module_walkers": peb_walkers[:50],
            "ordinal_imports": ordinal_imports[:50],
            "summary": {
                "resolver_funcs": len(resolver_funcs),
                "resolve_sites": len(resolve_sites),
                "peb_module_walkers": len(peb_walkers),
                "ordinal_imports": len(ordinal_imports),
                "min_resolve_calls": MIN_RESOLVE_CALLS,
                "elapsed_s": round(time.time() - t0, 2),
                "note": "Resolve sites are core logic of packed/stripped samples "
                        "(static import dir empty).",
            },
        })
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
    result = extract_dynamic_resolve(get_ghidra_sql_client(), sid)
    print(json.dumps(result, indent=2, default=str))
