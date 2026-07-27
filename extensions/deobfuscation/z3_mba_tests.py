#!/usr/bin/env python3
"""z3_mba_tests.py - Extended Z3 test suite for MBA identity verification.

Tests Z3's ability to verify known MBA (Mixed Boolean-Arithmetic)
identities used in deobfuscation. Also tests opaque predicate
verification and performance timing.

Usage: python3 z3_mba_tests.py
"""
import sys
import time
import json
from pathlib import Path

sys.path.insert(0, '/opt/cadre-v3-tools/deobfuscation')
from invoke_z3_or_angr import invoke_z3


TESTS = [
    # (name, claim, expected_result, description)
    # === Classic MBA identities (x^y) + 2*(x&y) == x+y variants ===
    ("mba_1", "(x ^ y) + 2 * (x & y) == x + y", "unsat",
     "Classic MBA identity: XOR + AND decomposition"),
    ("mba_2", "(x | y) - (x & y) == x ^ y", "unsat",
     "OR minus AND equals XOR"),
    ("mba_3", "(x | y) + (x & y) == x + y", "unsat",
     "OR plus AND equals sum"),

    # === Distributive/associative laws ===
    ("law_1", "x * (y + z) == (x * y) + (x * z)", "unsat",
     "Distributive law: multiplication over addition"),
    ("law_2", "(x + y) * z == (x * z) + (y * z)", "unsat",
     "Distributive law (right-side)"),
    ("law_3", "x + y == y + x", "unsat", "Commutativity of addition"),
    ("law_4", "x * y == y * x", "unsat", "Commutativity of multiplication"),

    # === Opaque predicates (expressions that are always true/false) ===
    ("opaque_1", "((x * (x + 1)) & 1) == 0", "unsat",
     "x*(x+1) is always even"),
    # NOTE: %, / not supported on Z3 BitVecs in Python eval.
    # "Product of 3 consecutive ints is divisible by 6" requires modular arithmetic
    # not available with BitVec +/. Skipped.
    ("opaque_3", "((x * x) - x) & 1 == 0", "unsat",
     "x^2 - x is always even (bitwise)"),

    # === Disproving (should be SAT - has counterexample) ===
    ("sat_1", "x == y", "sat", "x==y is not a tautology"),
    ("sat_2", "x + y == x * y", "sat", "x+y != x*y always"),
    ("sat_3", "x & y == x | y", "sat", "AND != OR"),

    # === Complex MBA (from real obfuscators) ===
    # NOTE: x|y = x^y + (x&y) -- only ONE (x&y), not two.
    # So (x^y) + 2*(x&y) is WRONG: it equals x|y + (x&y) = x + y, not x|y.
    ("complex_1", "(x | y) + (x & y) == x + y", "unsat",
     "OR + AND == sum (correct identity)"),
    ("complex_2", "(x | y) - (x & y) == x ^ y", "unsat",
     "OR - AND == XOR (correct identity)"),
]


def run_all_tests(timeout=10):
    results = []
    for name, claim, expected, desc in TESTS:
        t0 = time.time()
        r = invoke_z3(claim, timeout=timeout)
        duration = time.time() - t0
        passed = (r.result == expected)
        results.append({
            "name": name,
            "claim": claim,
            "expected": expected,
            "actual": r.result,
            "passed": passed,
            "duration_s": round(duration, 3),
            "tool": r.tool,
            "description": desc,
        })
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}: {r.result} (expected {expected}) [{duration:.3f}s] {desc}")
    return results


if __name__ == "__main__":
    print("=== Z3 MBA / opaque-predicate test suite ===")
    print(f"  Running {len(TESTS)} tests...")
    print()
    results = run_all_tests()
    print()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    total_time = sum(r["duration_s"] for r in results)
    print(f"=== {passed}/{total} passed in {total_time:.2f}s ===")
    if passed < total:
        print("FAILED:")
        for r in results:
            if not r["passed"]:
                print(f"  {r['name']}: expected {r['expected']}, got {r['actual']}")
        sys.exit(1)