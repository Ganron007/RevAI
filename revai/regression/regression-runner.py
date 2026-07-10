#!/usr/bin/env python3
"""regression-runner.py — run the current v2/v3 pipeline against the 4 baseline samples.

Calls v2_validate.py --pipeline --sample for each baseline sample. This exercises
the current 5-agent flow: intake_v2.py → quick_scan_v2.py → deep_dive_v2.py →
yara_gen_v2.py → publish_report_v2.py, with RAG/hybrid enabled.

When --v3 is passed, also runs lightweight v3 smoke tests:
  - FastAPI server health check (with retries)
  - RAG smoke test (hybrid backend, a few representative queries)
  - angr/Z3 self-test

The full RAG benchmark is intentionally not part of the regression gate; it is
a standalone performance measurement. Run it separately with rag_benchmark.py.

Usage:
  python3 /opt/cadre-v3-tools/regression/regression-runner.py
  python3 /opt/cadre-v3-tools/regression/regression-runner.py --only apt29,busybox
  python3 /opt/cadre-v3-tools/regression/regression-runner.py --v3

Report saved to: /opt/cadre-v3-tools/regression/v3-pipeline-regression-<DATE>.md
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from v2_validate import SAMPLES, verdict_ok  # noqa: E402

SCRIPTS = Path("/opt/scripts")
V3_TOOLS = Path("/opt/cadre-v3-tools")
RAG_BENCH = V3_TOOLS / "rag" / "tests" / "rag_benchmark.py"
DEOB_SMOKES = V3_TOOLS / "deobfuscation" / "invoke_z3_or_angr.py"
FASTAPI_URL = "http://localhost:8000"
LOG_DIR = V3_TOOLS / "regression" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR = V3_TOOLS / "regression"


def run_sample(name: str, info: dict) -> dict:
    print(f"\n=== {name} ===")
    print(f"  path:   {info['path']}")
    print(f"  expect: {info['expect']}")
    t0 = time.time()
    proc = subprocess.run(
        ["python3", str(SCRIPTS / "v2_validate.py"), "--pipeline", "--sample", name],
        capture_output=True, text=True, timeout=14400,
    )
    elapsed = time.time() - t0
    out = proc.stdout + "\n" + proc.stderr
    # Save log
    log_file = LOG_DIR / f"{name}-{int(t0)}.log"
    log_file.write_text(out)
    print(f"  exit:   {proc.returncode}  time: {elapsed:.1f}s  log: {log_file.name}")

    # Parse the FINAL JSON block from v2_validate.py output.
    # v2_validate.py prints multiple JSONs (intake, quick_scan, then the final triage).
    # The final one is the verdict block with 'expect', 'got', 'agreement', 'status'.
    # Use raw_decode to handle nested JSON properly.
    verdict = "unknown"
    agreement = "unknown"
    family = "unknown"
    status = "unknown"
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(out):
        # Skip whitespace to find next '{'
        while pos < len(out) and out[pos] != "{":
            pos += 1
        if pos >= len(out):
            break
        try:
            j, end = decoder.raw_decode(out, pos)
            pos = end
            if "sample" in j and "expect" in j and "got" in j:
                # This is the verdict block (intake/quick_scan don't have all 3)
                verdict = j.get("got", "unknown")
                agreement = j.get("agreement", "unknown")
                family = j.get("family_guess", "unknown")
                status = j.get("status", "unknown")
        except json.JSONDecodeError:
            pos += 1
    pass_ = verdict_ok(info["expect"], verdict) and proc.returncode in (0, 1)
    # Per v2 plan section 15.5 acceptance: smartape PASS at status NEEDS_HUMAN_REVIEW
    # (agreement mechanism correctly surfaces the LLM-vs-v1 disagreement to human).
    # v2_validate.py exits 1 for NEEDS_HUMAN_REVIEW; exit 0 for clean PASS.
    # Both are valid outcomes (no regression). Re-baseline PASS = verdict_ok(expect, got).
    is_human_review = status == "NEEDS_HUMAN_REVIEW"
    return {
        "name": name,
        "expect": info["expect"],
        "got": verdict,
        "agreement": agreement,
        "family": family,
        "exit": proc.returncode,
        "elapsed_s": elapsed,
        "pass": pass_,
        "is_human_review": is_human_review,
    }


def check_fastapi(retries: int = 3, timeout: int = 30) -> dict:
    """Health check the CADRE FastAPI inference gateway with retries."""
    t0 = time.time()
    result = {"name": "fastapi_health", "pass": False, "elapsed_s": 0.0, "detail": ""}
    last_err = ""
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(f"{FASTAPI_URL}/health", timeout=timeout) as resp:
                body = resp.read().decode()
                result["pass"] = resp.status == 200
                result["detail"] = body
                result["elapsed_s"] = time.time() - t0
                return result
        except urllib.error.URLError as e:
            last_err = str(e)
        except Exception as e:
            last_err = f"exception: {e}"
        if attempt < retries:
            time.sleep(2 ** attempt)
    result["detail"] = last_err
    result["elapsed_s"] = time.time() - t0
    return result


def run_rag_smoke() -> dict:
    """Lightweight RAG smoke test: verify hybrid backend returns hits."""
    import sys as _sys

    t0 = time.time()
    result = {
        "name": "rag_smoke",
        "pass": False,
        "elapsed_s": 0.0,
        "detail": "",
    }
    env = {
        **dict(os.environ),
        "REVENG_RAG": "1",
        "REVENG_RAG_HYBRID": "1",
        "REVENG_RAG_BACKEND": "remote",
        "REVENG_RAG_ANN": "0",
        "REVENG_RAG_RERANKER": "0",
    }
    smoke_queries = [
        "APT29 CozyBear backdoor",
        "Cobalt Strike Malleable C2",
        "T1059.001 PowerShell execution",
    ]
    try:
        _sys.path.insert(0, str(V3_TOOLS / "rag"))
        from rag_hybrid import HybridSearcher

        searcher = HybridSearcher()
        for q in smoke_queries:
            hits = searcher.search(q, top_k=3)
            if not hits:
                raise RuntimeError(f"no RAG hits for query: {q}")
        result["pass"] = True
        result["detail"] = f"{len(smoke_queries)} smoke queries returned hits"
    except Exception as e:
        result["detail"] = f"RAG smoke failed: {e}"
    finally:
        # Avoid leaking our private import into the global sys.modules if it
        # would conflict with later stages.
        for mod in ("rag_hybrid", "reveng_rag", "faiss_searcher", "remote_embedder", "reranker"):
            if mod in sys.modules:
                del sys.modules[mod]
    result["elapsed_s"] = time.time() - t0
    log_file = LOG_DIR / f"rag-smoke-{int(t0)}.log"
    log_file.write_text(result["detail"])
    return result


def run_rag_benchmark() -> dict:
    """Run the full v3 RAG benchmark across all configured backends.

    This is intentionally NOT part of the default --v3 smoke path because it
    can saturate the host GPU server for many minutes. Use it for performance
    measurement, not as a regression gate.
    """
    t0 = time.time()
    result = {
        "name": "rag_benchmark",
        "pass": False,
        "elapsed_s": 0.0,
        "detail": "",
    }
    env = {
        **dict(os.environ),
        "REVENG_RAG": "1",
        "REVENG_RAG_HYBRID": "1",
        "REVENG_RAG_ANN": "1",
        "REVENG_RAG_RERANKER": "1",
    }
    cmd = [
        "python3", str(RAG_BENCH),
        "--backends", "dense,hybrid,ann,reranker",
        "--queries", str(V3_TOOLS / "rag" / "tests" / "queries.jsonl"),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=env)
    log_file = LOG_DIR / f"rag-benchmark-{int(t0)}.log"
    log_file.write_text(proc.stdout + "\n" + proc.stderr)
    result["pass"] = proc.returncode == 0
    result["detail"] = f"exit={proc.returncode}; log={log_file}"
    result["elapsed_s"] = time.time() - t0
    return result


def run_deobfuscation_smoke() -> dict:
    """Run the angr/Z3 self-test."""
    t0 = time.time()
    result = {
        "name": "deobfuscation_smoke",
        "pass": False,
        "elapsed_s": 0.0,
        "detail": "",
    }
    proc = subprocess.run(
        ["python3", str(DEOB_SMOKES), "--test"],
        capture_output=True, text=True, timeout=600,
    )
    log_file = LOG_DIR / f"deobfuscation-smoke-{int(t0)}.log"
    log_file.write_text(proc.stdout + "\n" + proc.stderr)
    result["pass"] = proc.returncode == 0
    result["detail"] = f"exit={proc.returncode}; log={log_file}"
    result["elapsed_s"] = time.time() - t0
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated sample names (default: all 4)")
    ap.add_argument("--v3", action="store_true", help="also run v3 RAG/deobfuscation smoke tests")
    ap.add_argument("--full-benchmark", action="store_true", help="run full RAG benchmark instead of smoke (saturates GPU; not for CI)")
    args = ap.parse_args()
    if args.only:
        wanted = set(s.strip() for s in args.only.split(","))
        samples = {k: v for k, v in SAMPLES.items() if k in wanted}
    else:
        samples = SAMPLES

    today = date.today().isoformat()
    print(f"regression-runner.py — {today}")
    print(f"samples: {list(samples)}")
    print(f"--v3: {args.v3}")
    print(f"--full-benchmark: {args.full_benchmark}")

    results = []
    for name in ["apt29", "wannacry", "smartape", "busybox"]:
        if name in samples:
            results.append(run_sample(name, samples[name]))

    v3_results = []
    if args.v3:
        v3_results.append(check_fastapi())
        if args.full_benchmark:
            v3_results.append(run_rag_benchmark())
        else:
            v3_results.append(run_rag_smoke())
        v3_results.append(run_deobfuscation_smoke())

    # Summary table - pipeline
    print("\n\n" + "=" * 78)
    print(f"{'Sample':<10} {'Expect':<12} {'Got':<12} {'Agreement':<18} {'Exit':<6} {'Time':<8} {'Pass':<6}")
    print("=" * 78)
    for r in results:
        marker = "PASS*" if r.get("is_human_review") else ("PASS" if r["pass"] else "FAIL")
        print(f"{r['name']:<10} {r['expect']:<12} {r['got']:<12} {r['agreement']:<18} {r['exit']:<6} {r['elapsed_s']:<8.1f} {marker:<6}")
    print("=" * 78)
    print("(* = NEEDS_HUMAN_REVIEW; this IS the correct outcome for smartape per v2 section 15.5)")
    passed = sum(1 for r in results if r["pass"])
    print(f"\n{passed}/{len(results)} PASS v2/v3 pipeline\n")

    if args.v3:
        print("=" * 78)
        print(f"{'V3 Smoke':<24} {'Pass':<6} {'Time':<8} {'Detail'}")
        print("=" * 78)
        for r in v3_results:
            marker = "PASS" if r["pass"] else "FAIL"
            print(f"{r['name']:<24} {marker:<6} {r['elapsed_s']:<8.1f} {r['detail']}")
        print("=" * 78)
        v3_passed = sum(1 for r in v3_results if r["pass"])
        print(f"\n{v3_passed}/{len(v3_results)} PASS v3 smoke tests\n")

    # Save report
    report_name = f"v3-pipeline-regression-{today}.md" if args.v3 else f"v3-pipeline-regression-{today}.md"
    report_path = REPORT_DIR / report_name
    table_lines = [
        f"| {'Sample':<10} | {'Expect':<12} | {'Got':<12} | {'Agreement':<18} | {'Exit':<6} | {'Time':<8} | {'Pass':<6} |",
        f"|{'-'*12}|{'-'*14}|{'-'*14}|{'-'*20}|{'-'*8}|{'-'*10}|{'-'*8}|",
    ]
    for r in results:
        table_lines.append(
            f"| {r['name']:<10} | {r['expect']:<12} | {r['got']:<12} | {r['agreement']:<18} | {r['exit']:<6} | {r['elapsed_s']:<8.1f} | {'PASS' if r['pass'] else 'FAIL':<6} |"
        )
    table = "\n".join(table_lines)

    v3_table = ""
    if args.v3:
        v3_table_lines = [
            f"| {'Smoke test':<24} | {'Pass':<6} | {'Time':<8} | {'Detail'} |",
            f"|{'-'*26}|{'-'*8}|{'-'*10}|{'-'*50}|",
        ]
        for r in v3_results:
            v3_table_lines.append(
                f"| {r['name']:<24} | {'PASS' if r['pass'] else 'FAIL':<6} | {r['elapsed_s']:<8.1f} | {r['detail']:<50} |"
            )
        v3_table = "\n".join(v3_table_lines)

    report_title = f"v3 pipeline regression - {today} (5-agent + RAG/deobfuscation smoke)"
    report = f"""# {report_title}

> **Status:** {passed}/{len(results)} PASS v2/v3 pipeline - {'REGRESSION CLEAN' if passed == len(results) else 'REGRESSION FAILED - v3 work BLOCKED'}

## Summary

| Sample | Expect | Got | Agreement | Exit | Time | Pass |
|--------|--------|-----|-----------|------|------|------|
{table}

## Acceptance check (5-agent pipeline)

- [{'x' if passed == len(results) else ' '}] intake_v2.py runs
- [{'x' if passed == len(results) else ' '}] quick_scan_v2.py runs with RAG/hybrid
- [{'x' if passed == len(results) else ' '}] deep_dive_v2.py runs with RAG/hybrid
- [{'x' if passed == len(results) else ' '}] yara_gen_v2.py runs
- [{'x' if passed == len(results) else ' '}] publish_report_v2.py runs with RAG/hybrid
- [{'x' if passed == len(results) else ' '}] {passed}/{len(results)} PASS on baseline sample set
- [{'x' if any('disagree' in r['agreement'].lower() for r in results) else ' '}] agreement mechanism lets smartape PASS at NEEDS_HUMAN_REVIEW
"""
    if args.v3:
        report += f"""
## V3 smoke tests

| Smoke test | Pass | Time | Detail |
|------------|------|------|--------|
{v3_table}

- [{'x' if v3_results[0]['pass'] else ' '}] FastAPI inference gateway health check
- [{'x' if v3_results[1]['pass'] else ' '}] {'Full RAG benchmark across dense/hybrid/ann/reranker backends' if args.full_benchmark else 'Lightweight RAG smoke test (hybrid backend)'}
- [{'x' if v3_results[2]['pass'] else ' '}] angr/Z3 deobfuscation self-test
"""

    report += f"""
## Per-sample detail

"""
    for r in results:
        report += f"### {r['name']}\n"
        report += f"- Expect: `{r['expect']}`\n"
        report += f"- Got: `{r['got']}` (family: `{r['family']}`)\n"
        report += f"- Agreement: `{r['agreement']}`\n"
        report += f"- Exit code: {r['exit']}\n"
        report += f"- Time: {r['elapsed_s']:.1f}s\n"
        report += f"- Log: {LOG_DIR}/{r['name']}-*.log\n\n"

    report += f"""## Notes

- This runner validates the current 5-agent pipeline (intake → quick_scan → deep_dive → yara_gen → publish_report).
- IDA is local on Remnux via /opt/ida; no SSH bridge is used.
- RAG/hybrid requires the FastAPI server on the configured RAG URL.
- Logs at: {LOG_DIR}/
"""
    report_path.write_text(report)
    print(f"Report: {report_path}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
