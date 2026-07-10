#!/usr/bin/env python3
"""
intake_v2.py — Phase 1a intake helper.

Loads a sample into a per-sha Ghidra project and writes a session registry
JSON at /opt/samples/sessions/<sha256>.json. Does NOT touch the 5-agent
v1 pipeline — this is a focused helper for the v2 proof slice.

Usage:
  python3 /opt/scripts/intake_v2.py <sample_path> [--project-name <name>]

Behavior:
  - Computes sha256
  - Stages sample to /opt/samples/corpus/<project-name>/<sha256>/<basename>
  - If /home/remnux/ghidra-projects/<sha256>.gpr missing:
      runs Ghidra analyzeHeadless to import + analyze
  - Writes /opt/samples/sessions/<sha256>.json with:
      {sha256, sample_path, session_id, gpr_path, program_name, staged_at, intake_version=2}
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from file_type import detect_file_type

GHIDRA_HOME = Path("/opt/ghidra")
GPR_ROOT = Path("/home/remnux/ghidra-projects")
CORPUS_ROOT = Path("/opt/samples/corpus")
SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")

ANALYZE_HEADLESS = GHIDRA_HOME / "support" / "analyzeHeadless"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stage_sample(sample: Path, project_name: str, sha: str) -> Path:
    dest_dir = CORPUS_ROOT / project_name / sha
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / sample.name
    if not dest.exists() or dest.stat().st_size != sample.stat().st_size:
        shutil.copy2(sample, dest)
    return dest


def import_into_ghidra(sample: Path, sha: str, file_type_info: dict | None = None) -> Path:
    """
    Run analyzeHeadless to import + analyze. Returns the .gpr path.
    Per-sha project dir at /home/remnux/ghidra-projects/<sha>/

    Supports PE (Windows), .NET (PE+CLR), ELF (Linux), Mach-O (macOS).
    Ghidra auto-detects the format; we just pick the right processor.
    """
    proj_dir = GPR_ROOT / sha
    proj_dir.mkdir(parents=True, exist_ok=True)
    proj_name = sha
    gpr = proj_dir / f"{sha}.gpr"
    rep = proj_dir / f"{sha}.rep"
    if gpr.exists() and gpr.stat().st_size > 0 and rep.exists():
        # already imported successfully
        return gpr

    log_path = LOGS_DIR / sha / "intake-analyzeHeadless.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Wipe any partial state from a previous failed import
    for stale in (gpr, rep, proj_dir / f"{sha}.lock", proj_dir / f"{sha}.lock~"):
        if stale.exists():
            if stale.is_dir():
                shutil.rmtree(stale, ignore_errors=True)
            else:
                try:
                    stale.unlink()
                except OSError:
                    pass

    # Choose the right Ghidra processor based on file type
    fmt = (file_type_info or {}).get("format", "pe")
    arch = (file_type_info or {}).get("arch", "x86")
    bits = (file_type_info or {}).get("bits", 32)
    # Ghidra processor selection
    if fmt == "macho":
        # Mach-O: Ghidra's "Macho" loader handles all Mac archs
        processor = "Macho"  # wait — Ghidra's loader is "Mach-O" / "AARCH64" / "x86:LE:64:default"
        # Ghidra 11+ uses language IDs; for Mach-O x86_64 the loader handles it
        # Without -processor/-language, Ghidra auto-detects from the file
        # For safety: don't specify, let it auto-detect
        processor = None
    elif fmt == "elf":
        # ELF: Ghidra auto-detects. Linux-specific processor modules include
        # x86:LE:32:default (32-bit), x86:LE:64:default (64-bit),
        # AARCH64:LE:64:v8A (ARM64), ARM:LE:32:v7 (ARM 32)
        # For now let it auto-detect
        processor = None
    elif fmt in ("pe", "dotnet"):
        # Windows PE/.NET: Ghidra uses "x86:LE:32:default" (32-bit) or
        # "x86:LE:64:default" (64-bit). Auto-detect works.
        processor = None
    else:
        processor = None  # unknown — let Ghidra figure it out or fail gracefully

    cmd = [
        str(ANALYZE_HEADLESS),
        str(proj_dir),
        proj_name,
        "-import", str(sample),
        # No -postScript. Equivalent work runs as Python post-analysis
        # (cff_detect.py, etc.) for portability across Ghidra versions.
    ]
    if processor:
        cmd += ["-processor", processor]

    print(f"[intake_v2] analyzeHeadless -> {sample.name} (fmt={fmt}, arch={arch}, bits={bits})", flush=True)
    with log_path.open("wb") as logf:
        rc = subprocess.call(cmd, stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=3600)
    if rc != 0:
        raise RuntimeError(f"analyzeHeadless failed rc={rc}; see {log_path}")
    if not gpr.exists():
        raise RuntimeError(f"analyzeHeadless returned 0 but {gpr} missing; see {log_path}")

    # NOTE: CFF detector is NOT called here. It runs from main()
    # AFTER write_session(), because cff_detect.py needs the session
    # JSON to look up the Ghidra project. Calling it here caused a
    # race condition where session.json didn't exist yet.

    return gpr


def import_into_ida(sample: Path, sha: str) -> Path | None:
    """Run idasql -s <sample> -w -q to create .i64 next to sample.

    Returns the .i64 path (or None if idasql is unavailable).
    The .i64 is created in the same dir as the staged sample so
    ida_sql_client can find it via the sample_path fallback.
    """
    if not shutil.which("idasql"):
        print("[intake_v2] idasql not found in PATH", flush=True)
        return None
    log_path = LOGS_DIR / sha / "intake-idasql.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # Clean stale .i64 siblings from a previous failed run
    for ext in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        p = sample.parent / (sample.name + ext)
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass
    i64 = sample.parent / (sample.name + ".i64")
    cmd = ["idasql", "-s", str(sample), "-w", "-q", "SELECT COUNT(*) AS cnt FROM funcs;"]
    print(f"[intake_v2] idasql bootstrap -> {sample.name}", flush=True)
    with log_path.open("wb") as logf:
        rc = subprocess.call(cmd, stdout=logf, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, timeout=1800)
    if rc != 0 or not i64.exists():
        tail = log_path.read_text(errors="replace")[-500:]
        print(f"[intake_v2] idasql bootstrap warning: rc={rc}, see {log_path}\n{tail}",
              flush=True)
        return None
    return i64


def write_session(sha: str, sample: Path, gpr: Path, project_name: str,
                file_type_info: dict | None = None,
                ida_session_id: str | None = None,
                ida_db_path: str | None = None) -> Path:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    program_name = sample.name
    fmt = (file_type_info or {}).get("format", "pe")
    arch = (file_type_info or {}).get("arch", "?")
    bits = (file_type_info or {}).get("bits", 0)
    os_name = (file_type_info or {}).get("os", "?")
    # Session ID is type-tagged so deep_dive/quick_scan can adapt queries
    if fmt == "elf":
        session_id = f"ghidra-elf-{sha}"
    elif fmt == "macho":
        session_id = f"ghidra-macho-{sha}"
    elif fmt == "dotnet":
        session_id = f"ghidra-dotnet-{sha}"
    else:
        session_id = f"ghidra-pe-{sha}"
    session = {
        "sha256": sha,
        "sample_path": str(sample),
        "session_id": session_id,
        "gpr_path": str(gpr),
        "program_name": program_name,
        "gpr_dir": str(gpr.parent),
        "ida_session_id": ida_session_id,
        "ida_db_path": ida_db_path,
        "malcat_analysis_id": None,
        "project_name": project_name,
        "staged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "intake_version": 2,
        "file_type": {
            "format": fmt,
            "os": os_name,
            "arch": arch,
            "bits": bits,
            # Pass through compound/binder info (file_type.py may set these)
            **({"compound": file_type_info["compound"],
                "embedded_pe_count": file_type_info["embedded_pe_count"],
                "embedded_pe_offsets": file_type_info["embedded_pe_offsets"]}
               if file_type_info and file_type_info.get("compound") else {}),
        },
    }
    out = SESSIONS_DIR / f"{sha}.json"
    out.write_text(json.dumps(session, indent=2))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_path")
    ap.add_argument("--project-name", default="malware-sample-library")
    ap.add_argument("--skip-ida", action="store_true",
                    help="Skip local IDA bootstrap (idasql)")
    args = ap.parse_args()

    sample = Path(args.sample_path).resolve()
    if not sample.exists():
        print(f"missing: {sample}", file=sys.stderr)
        sys.exit(2)

    # Detect file type (PE / ELF / Mach-O / .NET) for multi-platform support
    file_type_info = detect_file_type(str(sample))
    fmt = file_type_info.get("format", "unknown")
    arch = file_type_info.get("arch", "?")
    bits = file_type_info.get("bits", 0)
    os_name = file_type_info.get("os", "?")
    print(f"[intake_v2] file_type: {fmt} ({os_name} {arch}-{bits})", flush=True)
    if fmt == "unknown":
        print(f"[intake_v2] WARNING: unknown file type (magic={file_type_info.get('magic','')})", flush=True)

    print(f"[intake_v2] hashing {sample}", flush=True)
    sha = sha256_of(sample)
    print(f"[intake_v2] sha256={sha}", flush=True)

    staged = stage_sample(sample, args.project_name, sha)
    print(f"[intake_v2] staged -> {staged}", flush=True)

    gpr = import_into_ghidra(staged, sha, file_type_info=file_type_info)
    print(f"[intake_v2] gpr -> {gpr}", flush=True)

    # Local IDA bootstrap: run idasql -w -q to create .i64 + persist.
    # Without this, quick_scan/deep_dive IDA evidence is empty.
    ida_db_path = None
    if not args.skip_ida:
        ida_db_path = import_into_ida(staged, sha)
        if ida_db_path:
            print(f"[intake_v2] ida_db -> {ida_db_path}", flush=True)
        else:
            print("[intake_v2] ida_db skipped (idasql unavailable)", flush=True)

    session_path = write_session(
        sha, staged, gpr, args.project_name, file_type_info,
        ida_session_id=f"ida-{sha}",
        ida_db_path=str(ida_db_path) if ida_db_path else None,
    )
    print(f"[intake_v2] session -> {session_path}", flush=True)

    # CFF detector — runs AFTER write_session so the session JSON
    # exists and cff_detect.py can look up the Ghidra project.
    if fmt in ("pe", "dotnet"):
        cff_session_id = f"ghidra-{fmt}-{sha}"
        try:
            cff_result = subprocess.run(
                ["python3", "/opt/scripts/cff_detect.py", cff_session_id],
                check=False, timeout=120,
            )
            if cff_result.returncode != 0:
                print(f"[intake_v2] cff_detect rc={cff_result.returncode} (non-fatal)", flush=True)
        except Exception as e:
            print(f"[intake_v2] cff_detect warning: {e}", flush=True)

    session_data = json.loads(session_path.read_text())
    print(json.dumps({
        "sha256": sha,
        "session_id": session_data["session_id"],
        "sample_path": str(staged),
        "gpr_path": str(gpr),
        "ida_session_id": session_data.get("ida_session_id"),
        "ida_db_path": session_data.get("ida_db_path"),
        "file_type": session_data.get("file_type"),
    }, indent=2))


if __name__ == "__main__":
    main()
