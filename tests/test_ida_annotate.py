#!/usr/bin/env python3
"""test_ida_annotate.py - test IDA write-back + snapshot/rollback locally on Remnux.

Mirrors test_ghidra_annotate.py but for IDA via local idasql
(v0.0.17 at /usr/local/bin/idasql). No SSH to a Windows IDA host.

What it verifies (8 steps):
  1. baseline:        original function name is `sub_100129F6`
  2. snapshot:        copies the raw binary to a backup dir
  3. update:          renames the function via UPDATE funcs SET name=...
                      with the -w flag (creates .i64 next to raw binary)
  4. verify_rename:   new name appears in subsequent query
  5. insert:          adds a bookmark + a comment
  6. verify_*:        both rows visible in subsequent queries
  7. rollback:        deletes .i64 + siblings, restores raw binary
  8. verify_rollback: original name is back (re-analysis from scratch)

Run:
    python3 /opt/scripts/tests/test_ida_annotate.py
"""
from __future__ import annotations
import json
import sys
import time
from pathlib import Path

# Add /opt/scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ida_sql_client import get_ida_sql_client

SHA = "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966"
TEST_ADDR = 0x100129F6
TEST_RENAME = "complex_dispatcher_IDA_TEST"
TEST_BM_DESC = "IDA write-back test bookmark"
TEST_CM = "IDA test comment"

PASSED = 0
FAILED = 0
FAILURES: list[tuple[str, str]] = []


def check(name: str, ok: bool, msg: str = ""):
    global PASSED, FAILED
    if ok:
        print(f"  PASS  {name}")
        PASSED += 1
    else:
        print(f"  FAIL  {name}  {msg}")
        FAILED += 1
        FAILURES.append((name, msg))


def run(sha: str) -> int:
    global PASSED, FAILED
    print(f"\n=== test_ida_annotate (sha={sha[:16]}...) ===\n")

    c = get_ida_sql_client()

    # 0. Cleanup any stale idasql processes
    c._kill_any_idasql()
    time.sleep(1)

    # 1. Baseline
    print("[1. baseline]")
    r = c.ida_query(sha, "SELECT name FROM funcs WHERE address = 268511734")
    baseline_name = r["rows"][0]["name"] if r["rows"] else None
    check("baseline name is sub_100129F6",
          baseline_name == "sub_100129F6",
          f"got: {baseline_name!r}")

    # 2. Snapshot
    print("\n[2. snapshot]")
    snap = c.snapshot(sha)
    check("snapshot created", snap.get("size_bytes", 0) > 0,
          f"snap: {snap}")
    check("snapshot id present", bool(snap.get("snapshot_id")))

    # 3. Update (rename)
    print("\n[3. update rename]")
    result = c.annotate(
        sha,
        renames=[{"address": TEST_ADDR, "new_name": TEST_RENAME}],
        bookmarks=[{"address": TEST_ADDR, "comment": TEST_BM_DESC}],
        dry_run=False,
    )
    check("annotate ok", result["ok"], f"result: {result}")
    check("rename applied", len(result.get("applied", [])) >= 2)
    check("no failures", len(result.get("failed", [])) == 0)

    # 4. Verify rename
    print("\n[4. verify rename]")
    r = c.ida_query(sha, "SELECT name FROM funcs WHERE address = 268511734")
    new_name = r["rows"][0]["name"] if r["rows"] else None
    check("name is now complex_dispatcher_IDA_TEST",
          new_name == TEST_RENAME,
          f"got: {new_name!r}")

    # 5. Verify bookmark visible
    print("\n[5. verify bookmark]")
    r = c.ida_query(sha, "SELECT description FROM bookmarks WHERE address = 268511734")
    bm_descs = [row.get("description", "") for row in r["rows"]]
    check("bookmark visible", any(TEST_BM_DESC in d for d in bm_descs),
          f"got: {bm_descs}")

    # 6. Verify comment visible
    print("\n[6. verify comment]")
    r = c.ida_query(sha, "SELECT comment FROM comments WHERE address = 268511734")
    comments = [row.get("comment", "") for row in r["rows"]]
    check("comment visible", any(TEST_BM_DESC in cm for cm in comments),
          f"got: {comments}")

    # 7. Rollback
    print("\n[7. rollback]")
    rb = c.rollback(sha)
    check("rollback ok", rb.get("ok") is True, f"result: {rb}")

    # 8. Verify rollback
    print("\n[8. verify rollback]")
    r = c.ida_query(sha, "SELECT name FROM funcs WHERE address = 268511734")
    rb_name = r["rows"][0]["name"] if r["rows"] else None
    check("name reverted to sub_100129F6",
          rb_name == "sub_100129F6",
          f"got: {rb_name!r}")

    print(f"\n{'='*60}")
    print(f"test_ida_annotate: {PASSED} passed, {FAILED} failed")
    if FAILURES:
        for n, m in FAILURES:
            print(f"  - {n}: {m}")
        return 1
    return 0


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--sha", default=SHA)
    args = ap.parse_args()
    return run(args.sha)


if __name__ == "__main__":
    sys.exit(main())
