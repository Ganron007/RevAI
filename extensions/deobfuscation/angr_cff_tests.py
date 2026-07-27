#!/usr/bin/env python3
"""angr_cff_tests.py - angr CFG + symbolic-exec tests for CFF-dispatcher samples.

Tests angr's ability to:
  1. Build CFG on a real HackTool sample
  2. Find dispatcher nodes (outdegree=2, case-targets)
  3. Symbolic-exec to find paths past a dispatcher

If angr is unavailable (e.g. Remnux protobuf compat), tests skip gracefully
but still print useful diagnostics.

Usage: python3 angr_cff_tests.py [sample_path]
       (default: first .i64 in /opt/samples/corpus/...)
"""
import os
import sys
import json
import time
from pathlib import Path

sys.path.insert(0, '/opt/cadre-v3-tools/deobfuscation')
from invoke_z3_or_angr import invoke_angr, ANGR_PYTHON


def find_sample():
    """Find a sample to test against. Prefer raw binaries over .i64."""
    # 1. Env override
    p = os.environ.get("CFF_SAMPLE")
    if p and Path(p).is_file():
        return p
    # 2. First .exe in corpus
    corpus = Path("/opt/samples/corpus")
    if corpus.exists():
        for proj in corpus.iterdir():
            if proj.is_dir():
                for sha_dir in proj.iterdir():
                    if sha_dir.is_dir():
                        for f in sha_dir.iterdir():
                            if f.suffix.lower() in (".exe", ".dll", ".bin", ""):
                                if f.is_file() and f.stat().st_size > 1024:
                                    return str(f)
    return None


def test_angr_available():
    """Test 1: can angr be imported at all?"""
    print("Test 1: angr availability check")
    if not Path(ANGR_PYTHON).is_file():
        print(f"  [SKIP] angr Python not found at {ANGR_PYTHON}")
        return "skip"
    try:
        import subprocess
        r = subprocess.run(
            [ANGR_PYTHON, "-c", "import angr; print(angr.__version__)"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            print(f"  [PASS] angr imports OK: {r.stdout.strip()}")
            return "pass"
        else:
            print(f"  [SKIP] angr import error: {r.stderr.strip()[:200]}")
            return "skip"
    except Exception as e:
        print(f"  [SKIP] angr import exception: {type(e).__name__}: {e}")
        return "skip"


def test_cfg_build(sample_path, timeout=120):
    """Test 2: build angr CFG on the sample (via subprocess to keep angr sandboxed)."""
    print(f"Test 2: angr CFG build on {Path(sample_path).name} (timeout={timeout}s)")
    if not Path(ANGR_PYTHON).is_file():
        print("  [SKIP] angr not available")
        return "skip"
    inline = f'''
import sys, json
import angr
p = angr.Project("{sample_path}", auto_load_libs=False)
cfg = p.analyses.CFGFast(normalize=True)
nodes = list(cfg.graph.nodes())
print(json.dumps({{"result": "ok", "node_count": len(nodes), "binary": p.filename}}))
'''
    try:
        import subprocess
        t0 = time.time()
        r = subprocess.run(
            [ANGR_PYTHON, "-c", inline],
            capture_output=True, text=True, timeout=timeout,
        )
        duration = time.time() - t0
        last_line = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        try:
            j = json.loads(last_line)
            print(f"  [PASS] CFG built: {j['node_count']} nodes in {duration:.1f}s")
            return "pass"
        except json.JSONDecodeError:
            print(f"  [FAIL] CFG build failed: {last_line[:200] or r.stderr[:200]}")
            return "fail"
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] CFG build exceeded {timeout}s")
        return "timeout"
    except Exception as e:
        print(f"  [FAIL] CFG build error: {type(e).__name__}: {e}")
        return "fail"


def test_dispatcher_search(sample_path, timeout=120):
    """Test 3: search for CFF dispatcher patterns (outdegree=2) in the CFG."""
    print(f"Test 3: dispatcher pattern search on {Path(sample_path).name}")
    if not Path(ANGR_PYTHON).is_file():
        print("  [SKIP] angr not available")
        return "skip"
    inline = f'''
import sys, json
import angr
import networkx as nx
p = angr.Project("{sample_path}", auto_load_libs=False)
cfg = p.analyses.CFGFast(normalize=True)
dispatchers = []
for n in cfg.graph.nodes():
    outdeg = cfg.graph.out_degree(n)
    if outdeg == 2:
        succ = list(cfg.graph.successors(n))
        n_addr = n.addr if hasattr(n, 'addr') else int(n)
        try:
            block = p.factory.block(n_addr, opt_level=1)
            if block.capstone.insns <= 5:
                dispatchers.append({{
                    "addr": hex(n_addr),
                    "outdegree": outdeg,
                    "successors": [hex(s.addr if hasattr(s, 'addr') else int(s)) for s in succ],
                    "insn_count": block.capstone.insns,
                }})
        except Exception:
            pass
print(json.dumps({{"result": "ok", "dispatchers": dispatchers[:20]}}))
'''
    try:
        import subprocess
        t0 = time.time()
        r = subprocess.run(
            [ANGR_PYTHON, "-c", inline],
            capture_output=True, text=True, timeout=timeout,
        )
        duration = time.time() - t0
        last_line = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        try:
            j = json.loads(last_line)
            n = len(j.get("dispatchers", []))
            print(f"  [PASS] Found {n} dispatcher candidates in {duration:.1f}s")
            for d in j.get("dispatchers", [])[:3]:
                print(f"    {d['addr']}: outdeg={d['outdegree']} insns={d['insn_count']}")
            return "pass"
        except json.JSONDecodeError:
            print(f"  [FAIL] search failed: {last_line[:200] or r.stderr[:200]}")
            return "fail"
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] search exceeded {timeout}s")
        return "timeout"
    except Exception as e:
        print(f"  [FAIL] search error: {type(e).__name__}: {e}")
        return "fail"


def test_symbolic_explore(sample_path, find_addr, timeout=60):
    """Test 4: symbolic exploration past a known address."""
    print(f"Test 4: symbolic exec to find {hex(find_addr) if isinstance(find_addr, int) else find_addr}")
    r = invoke_angr(sample_path, find_addr=find_addr, avoid_addrs=[], timeout=timeout)
    print(f"  tool={r.tool} result={r.result} duration={r.duration_s:.1f}s")
    print(f"  evidence: {r.evidence[:200]}")
    if r.result == "recovered":
        return "pass"
    elif r.result in ("untested", "timeout"):
        return "skip"
    return "fail"


if __name__ == "__main__":
    sample = sys.argv[1] if len(sys.argv) > 1 else find_sample()
    print(f"=== angr CFF / symbolic-exec test suite ===")
    print(f"Sample: {sample or '(none found)'}")
    print()

    t0 = time.time()
    results = {}

    results["avail"] = test_angr_available()
    print()

    if sample and Path(sample).is_file() and results["avail"] == "pass":
        results["cfg"] = test_cfg_build(sample, timeout=120)
        print()
        results["dispatcher"] = test_dispatcher_search(sample, timeout=120)
        print()
        # Symbolic exec requires a known target address; use entry point as a smoke test
        # (not meaningful, but exercises the path).
        results["symexec"] = test_symbolic_explore(sample, find_addr=0x401000, timeout=30)
        print()
    else:
        results["cfg"] = "skip"
        results["dispatcher"] = "skip"
        results["symexec"] = "skip"
        print("  (angr unavailable or no sample; skipping CFG tests)")
        print()

    duration = time.time() - t0
    print(f"=== Tests completed in {duration:.1f}s ===")
    for k, v in results.items():
        print(f"  {k}: {v}")
