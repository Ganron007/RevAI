#!/usr/bin/env python3
"""idasql_remnux.py — Direct IDA database queries via idapro on Remnux.

Replaces the old SSH-to-Windows-IDA approach. Uses the idapro Python
library (installed at /opt/ida/idalib/python/idapro-0.0.9-py3-none-any.whl)
to load IDA databases and run SQL queries locally.

The key difference from a remote idasql.exe: we import
idaapi and use the idapro API directly, not an HTTP server.

Prerequisites:
  pip3 install /opt/ida/idalib/python/idapro-0.0.9-py3-none-any.whl
  (already installed on Remnux)

Usage:
  python3 /opt/scripts/idasql_remnux.py 85a4ea1b... 'SELECT count(*) FROM funcs'
  python3 /opt/scripts/idasql_remnux.py 85a4ea1b... 'SELECT name, address FROM funcs LIMIT 5'
"""
import sys
import os
import json
import time

# Force IDADIR so idapro knows where to load from
os.environ["IDADIR"] = "/opt/ida"

import idapro  # provides open_database, close_database
import idaapi  # core IDA API (funcs, strings, segments, xrefs, etc.)
import ida_funcs
import ida_segment
import ida_bytes
import ida_nalt
import idautils
import ida_auto

# NOTE: ida_strings is NOT available as a standalone module on
# Remnux's Python 3.12. get_strlist_qty/get_strlist_item live in
# idaapi. get_strlit_contents lives in ida_bytes.

# IDA stores data in a flat file (.i64). Queries go through
# the Python API, not SQL. We emulate a SQL-like interface
# for consistency with the ghidra_sql_client pattern.
#
# NOTE: open_database / close_database live in `idapro` (the wrapper),
# NOT in `idaapi` (the core). This is the #1 gotcha.


def open_db(path_or_sha: str) -> str:
    """Open the IDA database. Accepts either:
      - a direct .i64 path: "/tmp/ls_bin.i64"
      - a SHA256 prefix: "85a4ea1b..." (looks up /opt/ida-sessions/<sha>/)
    """
    if path_or_sha.endswith(".i64"):
        db_path = path_or_sha
    else:
        # SHA lookup — finds .i64 under /opt/ida-sessions/<sha>/
        db_dir = f"/opt/ida-sessions/{path_or_sha}"
        matches = [f for f in os.listdir(db_dir) if f.endswith(".i64")]
        if not matches:
            raise FileNotFoundError(f"no .i64 in {db_dir}")
        db_path = os.path.join(db_dir, matches[0])
    # open_database(path, run_auto_analysis=False)
    # We open WITHOUT auto-analysis (the .i64 is already analyzed).
    # auto_wait() is called separately to let any residual analysis
    # finish gracefully.
    err = idapro.open_database(db_path, False)
    if err:
        raise RuntimeError(f"failed to open {db_path}: error {err}")
    ida_auto.auto_wait()
    return db_path


def close_db():
    idapro.close_database(0)


def query_funcs(limit: int = 20) -> list[dict]:
    """Return top functions by size."""
    import warnings
    out = []
    for i, fea in enumerate(idautils.Functions()):
        if i >= limit:
            break
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fn = ida_funcs.get_func(fea)
        if fn:
            out.append({
                "name": ida_funcs.get_func_name(fea),
                "address": str(fea),
                "size": fn.size() if hasattr(fn, "size") else str(fn.end_ea - fn.start_ea),
            })
    return out


def query_imports(limit: int = 50) -> list[dict]:
    """Return top imports."""
    out = []
    count = 0
    for i in range(ida_nalt.get_import_module_qty()):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = f"module_{i}"
        def cb(dll, func_name, ord_, data):
            nonlocal count
            if count >= limit:
                return False
            data.append({
                "module": dll,
                "name": func_name,
                "address": str(ord_) if ord_ else "",
            })
            count += 1
            return True
        result = []
        ida_nalt.enum_import_names(i, cb, result)
        out.extend(result)
        if count >= limit:
            break
    return out


def query_strings(limit: int = 50) -> list[dict]:
    """Return top strings."""
    out = []
    # ida_strings is not importable standalone on Remnux Python 3.12.
    # get_strlist_qty / get_strlist_item live in idaapi directly.
    sl = idaapi.get_strlist_qty()
    for i in range(min(sl, limit)):
        s = idaapi.get_strlist_item(i)
        content = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)
        if content:
            out.append({
                "address": str(s.ea),
                "content": content.decode("utf-8", errors="replace")[:200],
                "length": s.length,
            })
    return out


def query_segments() -> list[dict]:
    """Return all segments."""
    out = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        name = ida_segment.get_segm_name(seg)
        out.append({
            "name": name,
            "start_ea": hex(seg.start_ea),
            "end_ea": hex(seg.end_ea),
            "size": seg.size(),
        })
    return out


def query_xrefs(address: str, limit: int = 20) -> list[dict]:
    """Return xrefs to an address."""
    out = []
    addr = int(address, 16) if address.startswith("0x") else int(address)
    for x in idautils.XrefsTo(addr):
        if len(out) >= limit:
            break
        src_func = ida_funcs.get_func(x.frm)
        out.append({
            "from": hex(x.frm),
            "to": hex(x.to),
            "type": str(x.type),
            "from_func": ida_funcs.get_func_name(x.frm) if src_func else "",
        })
    return out


def query_direct(sql: str, max_rows: int = 200) -> dict:
    """Execute a simple SQL-like query against the IDA database.

    Supported queries:
      SELECT count(*) FROM funcs
      SELECT name, size FROM funcs ORDER BY size DESC LIMIT N
      SELECT name, address FROM funcs LIMIT N
      SELECT address, content FROM strings LIMIT N
      SELECT name, module FROM imports LIMIT N
      SELECT name, start_ea, size FROM segments
      SELECT from_address, to_address FROM xrefs WHERE to_address = 0xABC LIMIT N
    """
    sql_lower = sql.strip().lower().rstrip(";")

    # Parse simple queries
    if "from funcs" in sql_lower:
        if "count(*)" in sql_lower:
            funcs = idautils.Functions()
            return {"columns": ["count"], "rows": [{"count": str(len(list(funcs)))}], "row_count": 1}
        else:
            funcs = query_funcs(max_rows)
            return {"columns": ["name", "address", "size"], "rows": funcs, "row_count": len(funcs)}

    elif "from strings" in sql_lower:
        strings = query_strings(max_rows)
        return {"columns": ["address", "content"], "rows": strings, "row_count": len(strings)}

    elif "from imports" in sql_lower:
        imports = query_imports(max_rows)
        return {"columns": ["module", "name", "address"], "rows": imports, "row_count": len(imports)}

    elif "from segments" in sql_lower:
        segs = query_segments()
        return {"columns": ["name", "start_ea", "end_ea", "size"], "rows": segs, "row_count": len(segs)}

    elif "from xrefs" in sql_lower:
        # Extract WHERE to_address = 0xABC
        import re
        m = re.search(r"where\s+to_address\s*=\s*(0x[0-9a-f]+|\d+)", sql_lower)
        addr = m.group(1) if m else "0"
        xrefs = query_xrefs(addr, max_rows)
        return {"columns": ["from", "to", "type", "from_func"], "rows": xrefs, "row_count": len(xrefs)}

    else:
        return {"columns": [], "rows": [], "row_count": 0, "error": f"unsupported query: {sql}"}


def main():
    if len(sys.argv) < 3:
        print("usage: idasql_remnux.py <sha256|session_id> <sql>")
        sys.exit(1)

    session_id = sys.argv[1]
    sql = sys.argv[2]

    # Strip ida- prefix
    sha = session_id.replace("ida-", "")

    try:
        db_path = open_db(sha)
        result = query_direct(sql)
        result["source"] = "idasql_remnux"
        result["session_id"] = session_id
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(json.dumps({"error": str(e), "session_id": session_id}, indent=2))
        sys.exit(1)
    finally:
        try:
            close_db()
        except Exception:
            pass


if __name__ == "__main__":
    main()
