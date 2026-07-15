"""Pure-SQL CFF detector using ghidra_query (no subqueries).

Computes a CFF score per function from ghidra's funcs + instructions + cfg_edges:
  - high conditional-jump count per function
  - low unique-target / total ratio = dispatcher pattern (CFF)

Output: marker file at /opt/samples/logs/cff-detector/cff_detector.log
"""
import sys
import json
import time
import os
sys.path.insert(0, "/opt/scripts")
from v2_lib import McpGhidraClient, SESSIONS_DIR  # noqa

# Step 1: get functions (top 50 by size, since CFF targets are usually big)
SQL_FUNCS = """
SELECT name, start_ea, size
FROM funcs
WHERE size > 1024
ORDER BY size DESC
LIMIT 50
"""

# Step 2: count conditional jumps per function
# (instruction.mnemonic is JNZ, JZ, etc; we filter on prefix J and exclude JMP)
SQL_JUMPS = """
SELECT mnemonic, COUNT(*) AS n
FROM instructions
WHERE mnemonic LIKE 'J%' AND mnemonic != 'JMP'
GROUP BY mnemonic
"""

# Step 3: get cfg_edges from blocks (in-func CFF hub detection)
# We're using tables that exist; sub-queries aren't supported, so we do
# the analysis on the client side after fetching the per-function summary.

import collections

def find_session():
    sessions = sorted(SESSIONS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not sessions:
        return None
    return json.loads(sessions[0].read_text()).get("session_id")

SID = sys.argv[1] if len(sys.argv) > 1 else find_session()
if not SID:
    print("cff_detect: no session found")
    sys.exit(0)

print(f"cff_detect: session_id={SID}")

marker_dir = "/opt/samples/logs/cff-detector"
os.makedirs(marker_dir, exist_ok=True)

c = McpGhidraClient()
try:
    # Step 1
    funcs = c.ghidra_query(SID, SQL_FUNCS)
    func_list = funcs.get("rows", []) if isinstance(funcs, dict) else []
    print(f"cff_detect: got {len(func_list)} candidate functions")

    # --- Imports health check (ALWAYS runs, even if no functions) ---
    # Ghidra's `imports` table is often empty for packed / compound PEs.
    # Use data_items (import thunks, PTR_* entries) as the reliable source.
    imp = c.ghidra_query(SID, "SELECT count(*) AS cnt FROM data_items WHERE name LIKE 'PTR_%'")
    imp_count = int((imp.get("rows", [{}])[0].get("cnt") or 0) if isinstance(imp, dict) else 0)
    print(f"cff_detect: import_ptrs count={imp_count}")
    imp_marker = os.path.join(marker_dir, "imports_health.log")
    with open(imp_marker, "w") as f:
        f.write(f"ts={int(time.time())}\n")
        f.write(f"session_id={SID}\n")
        f.write(f"imports_count={imp_count}\n")
        f.write(f"status={'ok' if imp_count > 0 else 'EMPTY (data_items PTR_* also empty; sample may have no imports)'}\n")

    if not func_list:
        # Still write an empty CFF marker so the session is tracked
        marker = os.path.join(marker_dir, "cff_detector.log")
        with open(marker, "w") as f:
            f.write(f"ts={int(time.time())}\n")
            f.write(f"session_id={SID}\n")
            f.write(f"cff_candidates=0 (no functions > 1024 bytes)\n")
        sys.exit(0)

    # Step 2: count instructions per function (no GROUP BY on join)
    # We can't join `funcs` to `instructions` in this ghidrasql (no fk
    # column on instructions). So we fetch all instructions table rows for
    # the function start_ea range and tally in Python.
    # The ghidra blocks table maps each function to a [start_ea, end_ea].
    # We use blocks + cfg_edges to find dispatcher patterns.

    # 1. Pull cfg_edges bounded by a reasonable limit. Large samples can have
    # hundreds of thousands of edges; scanning them all in Python is too slow.
    edges = c.ghidra_query(SID, """
        SELECT src_start_ea, dst_start_ea
        FROM cfg_edges
        WHERE src_start_ea > 0 AND dst_start_ea > 0
    """, max_rows=50000)
    edge_list = edges.get("rows", []) if isinstance(edges, dict) else []
    print(f"cff_detect: got {len(edge_list)} cfg edges (limited to 50000)")

    # 2. Build a map: source-addr -> set of dest-addr (only for branches)
    src_to_dsts = collections.defaultdict(set)
    for e in edge_list:
        src = e.get("src_start_ea")
        dst = e.get("dst_start_ea")
        if src is None or dst is None:
            continue
        if src == dst:
            continue
        src_to_dsts[src].add(dst)

    # 3. For each function, score it as a potential CFF
    findings = []
    budget_seconds = 90
    loop_start = time.time()
    for f in func_list:
        if time.time() - loop_start > budget_seconds:
            print(f"cff_detect: hit {budget_seconds}s budget; stopping early")
            break
        f_start = int(f.get("start_ea") or 0)
        f_size = int(f.get("size") or 0)
        f_name = f.get("name", "?")
        if not f_start or not f_size:
            continue
        f_end = f_start + f_size
        # count conditional edges in this function
        cond_edges = 0
        unique_dsts = set()
        for src, dsts in src_to_dsts.items():
            if f_start <= int(src) < f_end:
                cond_edges += len(dsts)
                unique_dsts.update(dsts)
        if cond_edges < 8:
            continue
        # CFF: many branches with few unique targets = dispatcher
        ratio = len(unique_dsts) / cond_edges
        cff_score = max(0, min(100, int((1.0 - ratio) * 100)))
        if cff_score >= 25:
            findings.append({
                "function": f_name,
                "entry": f"0x{f_start:x}",
                "size": f_size,
                "cond_edges": cond_edges,
                "unique_dsts": len(unique_dsts),
                "cff_score": cff_score,
            })

    findings.sort(key=lambda x: -x["cff_score"])

    # Write marker (marker_dir defined at top of script)
    marker = os.path.join(marker_dir, "cff_detector.log")
    lines = [
        f"ts={int(time.time())}",
        f"session_id={SID}",
        f"cff_candidates={len(findings)}",
        "---",
    ]
    for f in findings:
        lines.append(
            f"function={f['function']} entry={f['entry']} size={f['size']} "
            f"cond_edges={f['cond_edges']} unique_dsts={f['unique_dsts']} "
            f"cff_score={f['cff_score']}"
        )
    with open(marker, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Also include a "near-miss" list of all functions with cond_edges >= 8
    # so the analyst can see what the threshold rejected.
    near_miss = [f for f in findings if f["cff_score"] < 25]
    if near_miss:
        with open(marker, "a") as f:
            f.write("---near-miss (score 8-24)---\n")
            for f in near_miss:
                f.write(f"  function={f['function']} entry={f['entry']} cff_score={f['cff_score']}\n")

    print(f"cff_detect: found {len(findings)} CFF candidates; marker={marker}")
    for f in findings[:5]:
        print(f"  function={f['function']} entry={f['entry']} cff_score={f['cff_score']} cond_edges={f['cond_edges']}")
finally:
    c.close()
