#!/usr/bin/env python3
"""test_pipeline.py - smoke tests for the v2 pipeline.

Verifies that on a known sample, each stage:
  - runs to completion (rc=0)
  - writes its expected artifacts
  - produces a valid JSON verdict with required fields

NO content-equality assertions - those would require analyst-labeled
ground truth, which we don't have at scale yet. This is a "did the
pipeline produce a coherent answer" smoke test, not a "did the
answer match yesterday's answer" regression test.

Run:
    python3 /opt/scripts/tests/test_pipeline.py
    python3 /opt/scripts/tests/test_pipeline.py --sha <sha256>
    python3 /opt/scripts/tests/test_pipeline.py --sha <sha256> --strict

Exit 0 on pass, 1 on fail.
"""
from __future__ import annotations
import sys
import os
import json
import argparse
import subprocess
import time
from pathlib import Path

LOGS_DIR = Path("/opt/samples/logs")
SESSIONS_DIR = Path("/opt/samples/sessions")
SCRIPTS_DIR = Path("/opt/scripts")

# Default sample: Farfli (verified end-to-end on 2026-07-03)
DEFAULT_SHA = "85a4ea1b8db25c259fc6c208954ebb3c3a939bddb4856a942fd844be5ac16966"

STAGES = [
    ("intake",     "intake_v2.py",     []),
    ("quick_scan", "quick_scan_v2.py", []),
    ("deep_dive",  "deep_dive_v2.py",  ["--no-speakeasy"]),
    ("publish",    "publish_report_v2.py", ["--template", "full"]),
    ("correlate",  "section_publisher.py", []),
]

# Required evidence files per stage (relative to LOGS_DIR/<sha>/<stage>/)
STAGE_ARTIFACTS = {
    "intake":     [],   # intake_v2.py writes to /opt/samples/sessions/, not <stage>/
    "quick_scan": ["00-tools-raw.json", "01-sql-evidence.json", "02-prompt.txt",
                   "03-llm-raw.json", "04-verdict.json"],
    "deep_dive":  ["00-sql-evidence.json", "01-tools-raw.json", "02-cff-findings.json",
                   "03-prompt.txt", "04-llm-raw.json", "05-deep-dive.json"],
    "publish":    ["00-prompt.txt", "01-llm-raw.json", "02-REPORT-MASTER-v2.md"],
    "correlate":  ["00-tools-raw.json", "01-section-results.json", "02-REPORT-MASTER-v3.md"],
}

# Required fields in root verdict.json
VERDICT_REQUIRED_FIELDS = ["verdict", "family_guess", "numeric_score", "llm_audit"]

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


def run_stage(sha: str, stage: str, script: str, args: list) -> tuple[int, float]:
    """Re-run a single stage. Returns (rc, runtime_sec)."""
    t0 = time.time()
    proc = subprocess.run(
        ["python3", str(SCRIPTS_DIR / script), sha] + args,
        capture_output=True, text=True, timeout=900,
    )
    return proc.returncode, time.time() - t0


def test_session_exists(sha: str):
    print("\n[test_session_exists]")
    p = SESSIONS_DIR / f"{sha}.json"
    check("session.json exists", p.exists(), f"missing: {p}")
    if p.exists():
        s = json.loads(p.read_text())
        check("session.session_id present", "session_id" in s)
        check("session.file_type present", "file_type" in s)
        if "file_type" in s:
            ft = s["file_type"]
            check("file_type.format present", "format" in ft)


def test_stage_artifacts(sha: str, stage: str):
    print(f"\n[test_stage_artifacts:{stage}]")
    artifacts = STAGE_ARTIFACTS.get(stage, [])
    if not artifacts:
        check(f"{stage}: no required artifacts (intake stage)", True)
        return
    stage_dir = LOGS_DIR / sha / stage
    check(f"{stage}: directory exists", stage_dir.exists(), f"missing: {stage_dir}")
    if not stage_dir.exists():
        return
    for art in artifacts:
        p = stage_dir / art
        check(f"{stage}: {art} exists", p.exists(), f"missing: {p}")
        if p.exists():
            size = p.stat().st_size
            check(f"{stage}: {art} non-empty", size > 0, f"size={size}")


def test_verdict(sha: str):
    print("\n[test_verdict]")
    p = LOGS_DIR / sha / "verdict.json"
    check("verdict.json exists", p.exists(), f"missing: {p}")
    if not p.exists():
        return
    v = json.loads(p.read_text())
    for field in VERDICT_REQUIRED_FIELDS:
        check(f"verdict.{field} present", field in v)
    if "verdict" in v:
        # LLM judge uses "malicious"; the early-return v1 fallback uses "malware".
        # Accept both as valid positive verdicts.
        check("verdict.verdict in {malicious, malware, suspicious, clean}",
              v["verdict"] in ("malicious", "malware", "suspicious", "clean"),
              f"got: {v['verdict']!r}")
    if "numeric_score" in v:
        check("verdict.numeric_score is int", isinstance(v["numeric_score"], int))
        check("verdict.numeric_score >= 0", v["numeric_score"] >= 0)
    if "llm_audit" in v:
        audit = v["llm_audit"]
        check("verdict.llm_audit.response_model present", "response_model" in audit)
        check("verdict.llm_audit.is_reasoning_model is bool",
              isinstance(audit.get("is_reasoning_model"), bool))


def test_deep_dive(sha: str):
    print("\n[test_deep_dive]")
    p = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    check("deep_dive.json exists", p.exists())
    if not p.exists():
        return
    d = json.loads(p.read_text())
    check("deep_dive.confidence present", "confidence" in d)
    if "confidence" in d:
        check("deep_dive.confidence is number", isinstance(d["confidence"], (int, float)))
    check("deep_dive.summary non-empty", bool(d.get("summary")))


def test_publish_report(sha: str):
    print("\n[test_publish_report]")
    p = LOGS_DIR / sha / "REPORT-MASTER-v2.md"
    check("REPORT-MASTER-v2.md exists", p.exists())
    if not p.exists():
        return
    text = p.read_text()
    check("v2 report has > 50 lines", text.count("\n") > 50)
    check("v2 report has Executive Summary", "Executive Summary" in text)
    check("v2 report has Classification", "Classification" in text)


def test_correlate(sha: str):
    print("\n[test_correlate]")
    p = LOGS_DIR / sha / "REPORT-MASTER-v3.md"
    check("REPORT-MASTER-v3.md exists", p.exists())
    if not p.exists():
        return
    text = p.read_text()
    check("v3 report has > 100 lines", text.count("\n") > 100)
    check("v3 report has 17 sections", text.count("## ") >= 17)


def test_session_to_evidence_consistency(sha: str):
    print("\n[test_session_to_evidence_consistency]")
    sess_p = SESSIONS_DIR / f"{sha}.json"
    ev_p = LOGS_DIR / sha
    check("session.json exists", sess_p.exists())
    check("evidence dir exists", ev_p.exists())
    if not sess_p.exists() or not ev_p.exists():
        return
    sess = json.loads(sess_p.read_text())
    sid = sess.get("session_id", "")
    check("session.session_id non-empty", bool(sid))


def main():
    global PASSED, FAILED
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha", default=DEFAULT_SHA,
                        help="sha256 of sample to test (default: Farfli)")
    parser.add_argument("--strict", action="store_true",
                        help="Re-run all stages before asserting (slow)")
    parser.add_argument("--skip-rerun", action="store_true",
                        help="Don't re-run; just check existing artifacts")
    args = parser.parse_args()
    sha = args.sha

    print(f"Testing pipeline artifacts for sha={sha}")
    print(f"  --strict={args.strict}  --skip-rerun={args.skip_rerun}")

    if args.strict and not args.skip_rerun:
        print("\n[re-run stages]")
        for stage, script, sargs in STAGES:
            print(f"  re-running {stage}...")
            rc, rt = run_stage(sha, stage, script, sargs)
            check(f"stage {stage} rc=0", rc == 0, f"rc={rc}, runtime={rt:.1f}s")

    test_session_exists(sha)
    test_session_to_evidence_consistency(sha)
    test_verdict(sha)
    test_deep_dive(sha)
    test_publish_report(sha)
    test_correlate(sha)
    for stage, _, _ in STAGES:
        test_stage_artifacts(sha, stage)

    print(f"\n{'='*60}")
    print(f"pipeline smoke tests: {PASSED} passed, {FAILED} failed")
    if FAILURES:
        print("\nFailures:")
        for name, msg in FAILURES:
            print(f"  - {name}: {msg}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
