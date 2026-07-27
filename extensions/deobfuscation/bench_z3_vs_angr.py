#!/usr/bin/env python3
"""bench_z3_vs_angr.py - Benchmark Z3 vs angr vs cff_deflatten on v3 corpus.

Runs each tool against a sample of MBA/control-flow patterns and reports
timing + outcome. Useful for choosing which tool to invoke for which claim.

Usage: python3 bench_z3_vs_angr.py [iterations]
       (default: 5 iterations of each test)
"""
import sys
import time
import json
import statistics
from pathlib import Path

sys.path.insert(0, '/opt/cadre-v3-tools/deobfuscation')
from invoke_z3_or_angr import invoke_z3, invoke_angr, invoke_cff_deflatten


# Z3 test claims (math identities, must all return unsat)
Z3_CLAIMS = [
    ("mba_1", "(x ^ y) + 2 * (x & y) == x + y"),
    ("mba_2", "(x | y) - (x & y) == x ^ y"),
    ("mba_3", "(x | y) + (x & y) == x + y"),
    ("opaque_1", "((x * (x + 1)) & 1) == 0"),
    ("complex_1", "(x | y) + (x & y) == x + y"),
]


def bench_z3(iterations=5):
    """Benchmark Z3 on MBA identities."""
    print(f"=== Z3 benchmark ({iterations} iterations x {len(Z3_CLAIMS)} claims) ===")
    durations = []
    outcomes = []
    for i in range(iterations):
        for name, claim in Z3_CLAIMS:
            t0 = time.time()
            r = invoke_z3(claim, timeout=10)
            d = time.time() - t0
            durations.append(d)
            outcomes.append(r.result)
            print(f"  iter {i+1} {name}: {r.result} in {d*1000:.1f}ms")
    print()
    if durations:
        print(f"  Z3 stats: min={min(durations)*1000:.1f}ms median={statistics.median(durations)*1000:.1f}ms max={max(durations)*1000:.1f}ms")
        print(f"  Outcomes: {dict((o, outcomes.count(o)) for o in set(outcomes))}")
    return durations, outcomes


def bench_cff_deflatten(sample_path, iterations=1, timeout=60):
    """Benchmark cff_deflatten on a real sample."""
    print(f"=== cff_deflatten benchmark ({iterations} iterations on {Path(sample_path).name}, timeout={timeout}s) ===")
    durations = []
    candidates = []
    for i in range(iterations):
        t0 = time.time()
        r = invoke_cff_deflatten(sample_path, timeout=timeout)
        d = time.time() - t0
        durations.append(d)
        cands = r.raw.get("candidates", []) if hasattr(r, 'raw') and r.raw else []
        candidates.append(len(cands))
        print(f"  iter {i+1}: result={r.result} in {d:.1f}s, {len(cands)} CFF candidates")
    print()
    if durations:
        print(f"  cff_deflatten stats: avg={statistics.mean(durations):.1f}s, candidates per run: {candidates}")
    return durations, candidates


def bench_angr_path(sample_path, find_addr=0x401000, timeout=30):
    """Benchmark angr path-execution (single run, but report timing)."""
    print(f"=== angr symbolic exec benchmark (find={hex(find_addr)}, timeout={timeout}s) ===")
    t0 = time.time()
    r = invoke_angr(sample_path, find_addr=find_addr, avoid_addrs=[], timeout=timeout)
    d = time.time() - t0
    print(f"  result={r.result} in {d:.1f}s")
    print(f"  evidence: {r.evidence[:200]}")
    return d, r.result


if __name__ == "__main__":
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    print(f"=== Tool benchmark: Z3 vs angr vs cff_deflatten ===")
    print(f"  iterations: {iterations}")
    print()

    # 1. Z3 (always works, no sample needed)
    z3_durs, z3_out = bench_z3(iterations=iterations)
    print()

    # 2. cff_deflatten (needs a sample)
    sample = Path("/opt/samples/corpus/SmartApeSG-2026-05-27/18df68d1581c11130c139fa52abb74dfd098a9af698a250645d6a4a65efcbf2d/client32.exe")
    if not sample.is_file():
        # Try other corpus locations
        corpus = Path("/opt/samples/corpus")
        for proj in corpus.iterdir():
            if proj.is_dir():
                for sha in proj.iterdir():
                    if sha.is_dir():
                        for f in sha.iterdir():
                            if f.suffix.lower() in (".exe", ".dll"):
                                sample = f
                                break
                        if sample.exists():
                            break
                if sample.exists():
                    break

    if sample and sample.is_file():
        cff_durs, cff_cands = bench_cff_deflatten(str(sample), iterations=1, timeout=60)
        print()
        angr_dur, angr_res = bench_angr_path(str(sample), find_addr=0x401000, timeout=30)
        print()
    else:
        print("  (no sample found; skipping cff_deflatten + angr benchmarks)")
        print()
        cff_durs, cff_cands = [], []
        angr_dur, angr_res = None, None

    # Summary
    print("=== Summary ===")
    print(f"  Z3:               {len(z3_durs)} runs, median={statistics.median(z3_durs)*1000:.1f}ms, outcomes={dict((o, z3_out.count(o)) for o in set(z3_out))}")
    if cff_durs:
        print(f"  cff_deflatten:    {len(cff_durs)} runs, avg={statistics.mean(cff_durs):.1f}s, candidates={cff_cands}")
    if angr_dur is not None:
        print(f"  angr (sym exec):  1 run, {angr_dur:.1f}s, result={angr_res}")
    print()
    print("  Tool selection guidance:")
    print("    mba_identity / opaque_predicate -> Z3 (sub-second, exact)")
    print("    cff_dispatcher                   -> cff_deflatten (heuristic, seconds)")
    print("    path_constraint                  -> angr (symbolic exec, seconds-minutes)")
