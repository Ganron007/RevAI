#!/usr/bin/env python3
"""Validate RevAI's deep-dive SQL against the running ghidrasql stack.

Runs the pipeline's complete fixed query set (agentic_recover_v4 +
recovery/context_builder + the writeback-adjacent reads) against one real
project and records per-query status, row counts and timings to JSON. Run it
BEFORE and AFTER a ghidrasql/libghidra upgrade and diff the two JSONs for
behavioral regressions (row counts and sample values must match; only
unordered LIMIT probes may legitimately differ).

Deployed layout: copy to the VM and run from /opt/scripts with that
interpreter, e.g.

    cd /opt/scripts && python3 validate-ghidrasql-sql.py <sha256> /tmp/sql_after.json

The run spawns a ghidrasql server through the normal client path (so it also
exercises server start + /health/deep) and tears it down via close_all().
Used for the v0.0.6 -> v0.0.7 upgrade (2026-10-03): 21/21 queries OK,
20/21 identical, and both real signal extractors byte-identical against
their stored artifacts.
"""
import json
import sys
import time

sys.path.insert(0, "/opt/scripts")
from v2_lib import load_session  # noqa: E402
from ghidra_sql_client import GhidraSqlClient  # noqa: E402

sha = sys.argv[1]
out_path = sys.argv[2]
sess = load_session(sha)
sid = sess["session_id"]
print(f"session={sid} gpr={sess.get('gpr_path')}", flush=True)
client = GhidraSqlClient()

results: dict[str, dict] = {}


def run(name: str, sql: str, max_rows: int = 200) -> dict:
    t0 = time.time()
    try:
        r = client.ghidra_query(sid, sql, max_rows=max_rows)
        rows = r.get("rows") or []
        err = r.get("error")
        results[name] = {
            "ok": err is None,
            "error": err,
            "n": len(rows),
            "elapsed_s": round(time.time() - t0, 1),
            "sample": rows[:3],
        }
    except Exception as e:  # noqa: BLE001
        results[name] = {"ok": False, "error": f"{type(e).__name__}: {e}",
                         "n": None, "elapsed_s": round(time.time() - t0, 1)}
    v = results[name]
    print(f"  {name:22s} {'ok ' if v['ok'] else 'FAIL'} n={v['n']} "
          f"{v['elapsed_s']}s {str(v.get('error') or '')[:100]}", flush=True)
    return v


# --- the pipeline's fixed query set -----------------------------------------
run("funcs_count", "SELECT count(*) AS c FROM funcs", 1)
run("funcs_nameless",
    "SELECT addr AS address, name, size FROM funcs "
    "WHERE name LIKE 'FUN_%' OR name LIKE 'func_%' OR name = ''", 100000)
run("metrics_slim",
    "SELECT func_addr, call_in_count, string_ref_count FROM function_metrics",
    50000)
run("metrics_full",
    "SELECT func_addr, cyclomatic_complexity, call_in_count, call_out_count, "
    "instruction_count, block_count FROM function_metrics", 50000)
run("string_refs_group",
    "SELECT func_addr, COUNT(*) AS c FROM string_refs GROUP BY func_addr",
    100000)
run("call_edges", "SELECT src_func_addr, dst_func_addr FROM call_edges", 200000)
run("callgraph_view_hv",
    "SELECT src_func_addr, dst_func_name FROM callgraph_edges "
    "WHERE dst_func_name LIKE 'RegSetValue%' OR dst_func_name LIKE 'VirtualAlloc%'",
    100000)
run("names_sample", "SELECT addr, name FROM names LIMIT 5", 5)
run("strings_len", "SELECT addr, content FROM strings WHERE length > 2 LIMIT 5", 5)
run("xrefs_kinds", "SELECT DISTINCT kind FROM xrefs LIMIT 20", 20)
run("imports_sample", "SELECT addr, name FROM imports LIMIT 5", 5)
run("capabilities_check", "SELECT name FROM sqlite_master WHERE type='table' "
    "AND name IN ('analysis_passes','program_options','live_meta',"
    "'parity_findings','perf_benchmarks')", 10)

# --- per-function queries (context_builder's exact shapes) -------------------
frow = client.ghidra_query(
    sid, "SELECT addr, size FROM funcs ORDER BY size DESC LIMIT 1",
    max_rows=1).get("rows") or []
if frow:
    addr = str(frow[0].get("addr"))
    size = int(frow[0].get("size") or 0)
    start, end = int(addr), int(addr) + max(size, 1)
    run("pseudocode_point",
        f"SELECT text FROM pseudocode WHERE func_addr = '{addr}' "
        "AND is_stale = '0' LIMIT 1", 1)
    xr = run("xrefs_range",
             "SELECT DISTINCT x.to_addr FROM xrefs x "
             f"WHERE x.from_addr >= '{start}' AND x.from_addr <= '{end}' "
             "LIMIT 60", 60)
    addrs = [str(r.get("to_addr")) for r in (xr.get("sample") or [])
             if isinstance(r, dict) and r.get("to_addr")]
    if addrs:
        lit = ",".join(f"'{a}'" for a in addrs[:20])
        run("strings_in_list",
            f"SELECT content FROM strings WHERE addr IN ({lit}) "
            "AND length > 2 LIMIT 20", 20)
    run("callers_join",
        "SELECT DISTINCT f.addr AS address, f.name, f.size "
        "FROM call_edges c JOIN funcs f ON f.addr = c.src_func_addr "
        f"WHERE c.dst_func_addr = '{addr}' AND c.src_func_addr != '0' LIMIT 25",
        25)
    run("callees_join",
        "SELECT DISTINCT f.addr AS address, f.name, f.size "
        "FROM call_edges c JOIN funcs f ON f.addr = c.dst_func_addr "
        f"WHERE c.src_func_addr = '{addr}' AND c.dst_func_addr != '0' LIMIT 25",
        25)
    run("neighbors",
        "SELECT addr AS address, name, size FROM funcs "
        f"WHERE addr >= '{start - 0x2000}' AND addr <= '{start + 0x2000}' "
        f"ORDER BY ABS(CAST(addr AS INTEGER) - {start}) ASC LIMIT 7", 7)
    run("metrics_one",
        "SELECT func_addr, cyclomatic_complexity, call_in_count, call_out_count, "
        "instruction_count, block_count FROM function_metrics "
        f"WHERE func_addr = '{addr}' LIMIT 1", 1)

# --- writeback-adjacent read paths -------------------------------------------
run("bookmarks_read", "SELECT addr, category, comment FROM bookmarks LIMIT 5", 5)
run("comments_read", "SELECT addr, comment FROM comments LIMIT 5", 5)

json.dump(results, open(out_path, "w"), indent=2, default=str)
failed = [k for k, v in results.items() if not v["ok"]]
print(f"\nqueries: {len(results)} | failed: {failed or 'none'}", flush=True)
client.close_all()
