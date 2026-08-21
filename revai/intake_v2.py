#!/usr/bin/env python3
"""
intake_v2.py — Phase 1a intake helper (plan v2.0).

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
from ghidra_sql_client import get_ghidra_sql_client
from ida_sql_client import get_ida_sql_client
from v2_lib import (  # noqa: E402
    case_dir,
    malcat_analyze,
    llm_judge,
    resolve_pipeline_mode,
    update_session,
)

GHIDRA_HOME = Path("/opt/ghidra")
GPR_ROOT = Path("/home/remnux/ghidra-projects")
CORPUS_ROOT = Path("/opt/samples/corpus")
SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")
# LLM config — clean RevAI runtime home only.
LLM_ENV = Path("/opt/revai/config/llm.env")
CADRE_ENV = Path("/opt/secrets/cadre.env")

DOC_FORMATS = frozenset({"pdf", "ole", "ooxml"})

ANALYZE_HEADLESS = GHIDRA_HOME / "support" / "analyzeHeadless"


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_doc_triage_script() -> Path | None:
    here = Path(__file__).resolve().parent
    for cand in (
        Path("/opt/scripts/doc_triage_v2.py"),
        here / "doc_triage_v2.py",
        here.parent / "doc_triage_v2.py",
    ):
        if cand.is_file():
            return cand
    return None


def run_doc_triage(sample: Path, sha: str) -> dict:
    """PDF/OLE/OOXML first-look before PE deep RE."""
    out_json = case_dir(sha) / "doc_triage.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    script = _find_doc_triage_script()
    if not script:
        stub = {
            "schema": "v6.2.1-doc-triage",
            "sha256": sha,
            "path": str(sample),
            "ok": False,
            "error": "doc_triage_v2.py not found",
            "analyst_next": [
                "Install/deploy doc_triage_v2.py to /opt/scripts/",
                "Re-run intake on this document sample",
            ],
        }
        out_json.write_text(json.dumps(stub, indent=2) + "\n", encoding="utf-8")
        print(f"[intake_v2] doc_triage MISSING script -> {out_json}", flush=True)
        return stub
    cmd = [
        sys.executable,
        str(script),
        str(sample),
        "--out",
        str(out_json),
        "--logs-root",
        str(LOGS_DIR),
    ]
    print(f"[intake_v2] doc_triage -> {script.name}", flush=True)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=180, errors="replace")
    except subprocess.TimeoutExpired:
        stub = {"ok": False, "error": "doc_triage timeout", "sha256": sha}
        out_json.write_text(json.dumps(stub, indent=2) + "\n", encoding="utf-8")
        return stub
    if out_json.is_file():
        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {"ok": False, "error": "invalid doc_triage.json"}
    else:
        data = {"ok": False, "error": "doc_triage produced no output", "stderr": (cp.stderr or "")[:500]}
        out_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    data["intake_hook"] = True
    data["doc_triage_rc"] = cp.returncode
    out_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"[intake_v2] doc_triage wrote {out_json} rc={cp.returncode}", flush=True)
    return data


def stage_sample(sample: Path, project_name: str, sha: str) -> Path:
    dest_dir = CORPUS_ROOT / project_name / sha
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / sample.name
    if not dest.exists() or dest.stat().st_size != sample.stat().st_size:
        shutil.copy2(sample, dest)
    return dest


def _ghidra_project_ready(gpr: Path, rep: Path) -> bool:
    """True if Ghidra project exists. .gpr may be 0 bytes; real data lives in .rep."""
    if not gpr.exists() or not rep.exists() or not rep.is_dir():
        return False
    if (rep / "project.prp").exists():
        return True
    idata = rep / "idata"
    try:
        return idata.exists() and any(idata.rglob("*"))
    except OSError:
        return False


def import_into_ghidra(
    sample: Path,
    sha: str,
    file_type_info: dict | None = None,
    *,
    no_analysis: bool = False,
) -> Path:
    """
    Run analyzeHeadless to import (+ optionally full AutoAnalysis). Returns .gpr path.

    Large / agentic mode MUST use no_analysis=True:
      - Import only (fast, no 3600s AutoAnalysis wall)
      - Agentic deep_dive then drives segmented SQL / decompile / tool work
      - That is the point of large mode — never one monolithic analysis timeout

    Standard mode keeps full AutoAnalysis with -analysisTimeoutPerFile 3600.
    """
    proj_dir = GPR_ROOT / sha
    proj_dir.mkdir(parents=True, exist_ok=True)
    proj_name = sha
    gpr = proj_dir / f"{sha}.gpr"
    rep = proj_dir / f"{sha}.rep"
    if _ghidra_project_ready(gpr, rep):
        # already imported successfully (.gpr may be empty; .rep holds data)
        return gpr

    log_path = case_dir(sha) / "intake-analyzeHeadless.log"
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
        "-max-cpu", "8",
    ]
    if no_analysis:
        # Large mode: import only. Agentic loop segments analysis later.
        cmd.append("-noanalysis")
    else:
        cmd += ["-analysisTimeoutPerFile", "3600"]
    if processor:
        cmd += ["-processor", processor]

    mode_label = "import-only/-noanalysis" if no_analysis else "import+AutoAnalysis/3600s"
    print(
        f"[intake_v2] analyzeHeadless -> {sample.name} "
        f"(fmt={fmt}, arch={arch}, bits={bits}, {mode_label})",
        flush=True,
    )
    # Import-only should finish quickly; full analysis may take hours.
    proc_timeout = 1800 if no_analysis else 10800
    with log_path.open("wb") as logf:
        rc = subprocess.call(
            cmd, stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            timeout=proc_timeout,
        )
    if rc != 0:
        raise RuntimeError(f"analyzeHeadless failed rc={rc}; see {log_path}")
    if not gpr.exists() and not _ghidra_project_ready(gpr, rep):
        raise RuntimeError(f"analyzeHeadless returned 0 but project missing; see {log_path}")

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
    log_path = case_dir(sha) / "intake-idasql.log"
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


def run_malcat_triage(sample: Path, sha: str) -> dict:
    """Run a fast Malcat triage pass and persist the raw profile.

    Malcat is the fastest static profiler we have (triage takes ~1-8 s on
    50 MB PEs). It gives us file type, architecture, packer hints, .NET bundle
    detection, import counts, anomalies, and YARA hits before we spend time
    loading Ghidra/IDA. Downstream stages can use this as both a validator
    and a fallback.
    """
    print(f"[intake_v2] malcat triage -> {sample.name}", flush=True)
    try:
        result = malcat_analyze(str(sample), profile="triage")
        profile_path = case_dir(sha) / "malcat-triage.json"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(json.dumps(result, indent=2, default=str))
        print(f"[intake_v2] malcat triage profile -> {profile_path}", flush=True)
        return result
    except Exception as e:
        print(f"[intake_v2] malcat triage error: {e}", flush=True)
        return {"error": str(e)}


def write_session(sha: str, sample: Path, gpr: Path | None, project_name: str,
                file_type_info: dict | None = None,
                ida_session_id: str | None = None,
                ida_db_path: str | None = None,
                malcat_profile_path: str | None = None,
                malcat_analysis_id: int | None = None) -> Path:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    program_name = sample.name
    fmt = (file_type_info or {}).get("format", "pe")
    arch = (file_type_info or {}).get("arch", "?")
    bits = (file_type_info or {}).get("bits", 0)
    os_name = (file_type_info or {}).get("os", "?")
    gpr_ok = bool(gpr) and str(gpr).strip() not in ("", ".", "/")
    # Session ID is type-tagged so deep_dive/quick_scan can adapt queries
    if fmt == "elf":
        session_id = f"ghidra-elf-{sha}"
    elif fmt == "macho":
        session_id = f"ghidra-macho-{sha}"
    elif fmt == "dotnet":
        session_id = f"ghidra-dotnet-{sha}"
    elif fmt in DOC_FORMATS:
        session_id = f"doc-{fmt}-{sha}"
    else:
        session_id = f"ghidra-pe-{sha}"
    session = {
        "sha256": sha,
        "sample_path": str(sample),
        "session_id": session_id,
        "gpr_path": str(gpr) if gpr_ok else None,
        "program_name": program_name,
        "gpr_dir": str(gpr.parent) if gpr_ok else None,
        "ida_session_id": ida_session_id,
        "ida_db_path": ida_db_path,
        "malcat_profile_path": malcat_profile_path,
        "malcat_analysis_id": malcat_analysis_id,
        "project_name": project_name,
        "staged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "intake_version": 2,
        "file_type": {
            "format": fmt,
            "os": os_name,
            "arch": arch,
            "bits": bits,
            **({"doc_triage": True} if fmt in DOC_FORMATS else {}),
            **({"ooxml_kind": file_type_info.get("ooxml_kind")}
               if file_type_info and file_type_info.get("ooxml_kind") else {}),
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


def _malcat_summary(malcat: dict | None) -> dict:
    """Extract a compact, comparable summary from a Malcat triage result."""
    if not malcat or malcat.get("error"):
        return {"error": malcat.get("error", "not run") if malcat else "not run"}
    fs = malcat.get("file_summary") or {}
    metadata = fs.get("metadata") or {}
    views = malcat.get("views") or {}
    return {
        "type": fs.get("type"),
        "arch": fs.get("architecture"),
        "file_size": fs.get("file_size"),
        "entropy": fs.get("entropy"),
        "sha256": fs.get("sha256"),
        "dotnet_bundle": bool(metadata.get(".NET Bundle::BundleID")),
        "imports_count": len(views.get("imports", [])),
        "strings_count": len(views.get("strings", [])),
        "functions_count": len(views.get("functions", [])),
        "constants_count": len(malcat.get("constants", [])),
        "anomalies_count": len(malcat.get("anomalies", [])),
        "yara_hits_count": len(views.get("yara_hits", [])),
        "errors": malcat.get("errors", []),
    }


def validate_engine_outputs(sha: str, session: dict, malcat_summary: dict | None = None) -> dict:
    """Cross-validate Malcat, Ghidra, and IDA outputs after intake.

    Returns a tool-summary report. The final intake-validation.json is written
    by decide_sources after it adds LLM/rule-based source decisions.
    """
    report = {
        "sha256": sha,
        "tool_summaries": {
            "malcat": _malcat_summary(malcat_summary),
            "ghidra": {},
            "ida": {},
        },
        "warnings": [],
    }
    ghidra_session_id = session["session_id"]
    ida_session_id = session.get("ida_session_id")

    try:
        gh = get_ghidra_sql_client()
        for label, sql in [
            ("imports", "SELECT COUNT(1) AS cnt FROM imports"),
            ("import_ptrs", "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'"),
            ("funcs", "SELECT COUNT(1) AS cnt FROM funcs"),
            ("strings", "SELECT COUNT(1) AS cnt FROM strings"),
        ]:
            r = gh.ghidra_query(ghidra_session_id, sql)
            rows = r.get("rows", [{}])
            report["tool_summaries"]["ghidra"][label] = int(rows[0].get("cnt", 0)) if rows else 0
        gh.close(ghidra_session_id)
    except Exception as e:
        report["warnings"].append(f"Ghidra validation failed: {e}")

    if ida_session_id:
        try:
            ida = get_ida_sql_client()
            for label, sql in [
                ("imports", "SELECT COUNT(1) AS cnt FROM imports"),
                ("funcs", "SELECT COUNT(1) AS cnt FROM funcs"),
                ("strings", "SELECT COUNT(1) AS cnt FROM strings"),
            ]:
                r = ida.ida_query(ida_session_id, sql)
                rows = r.get("rows", [{}])
                report["tool_summaries"]["ida"][label] = int(rows[0].get("cnt", 0)) if rows else 0
            ida.close(ida_session_id)
        except Exception as e:
            report["warnings"].append(f"IDA validation failed: {e}")

    # Keep flat ghidra/ida keys for backward compatibility
    report["ghidra"] = report["tool_summaries"]["ghidra"]
    report["ida"] = report["tool_summaries"]["ida"]

    # Cross-check imports
    gh_imp = report["ghidra"].get("imports")
    ida_imp = report["ida"].get("imports")
    gh_ptrs = report["ghidra"].get("import_ptrs")
    if gh_imp is not None and ida_imp is not None:
        if gh_imp == 0 and ida_imp > 0:
            report["warnings"].append(
                f"Ghidra imports is 0 but IDA has {ida_imp} imports; "
                "likely a packed/binder PE with imports in embedded sub-PEs."
            )
        elif ida_imp > 0 and abs(gh_imp - ida_imp) > max(ida_imp * 0.2, 10):
            report["warnings"].append(
                f"Import count divergence: Ghidra imports={gh_imp}, IDA imports={ida_imp}."
            )

    if gh_imp is not None and gh_ptrs is not None and gh_ptrs > 0 and gh_imp == 0:
        report["warnings"].append(
            f"Ghidra has {gh_ptrs} PTR_* entries but 0 imports table entries; "
            "the custom loader did not populate the imports table."
        )

    # Cross-check function counts
    gh_f = report["ghidra"].get("funcs")
    ida_f = report["ida"].get("funcs")
    if gh_f is not None and ida_f is not None and ida_f > 0:
        ratio = gh_f / ida_f
        if ratio < 0.5 or ratio > 2.0:
            report["warnings"].append(
                f"Function count divergence: Ghidra={gh_f}, IDA={ida_f} (ratio {ratio:.2f})."
            )

    # Cross-check Malcat vs Ghidra/IDA
    mc = report["tool_summaries"]["malcat"]
    if "error" not in mc and isinstance(mc.get("imports_count"), int) and ida_imp is not None:
        if ida_imp > 0 and abs(mc["imports_count"] - ida_imp) > max(ida_imp * 0.3, 10):
            report["warnings"].append(
                f"Malcat imports ({mc['imports_count']}) diverge from IDA imports ({ida_imp})."
            )

    return report


def _build_source_decision_prompt(tool_summaries: dict, rule_decisions: dict, warnings: list) -> str:
    return f"""You are a malware-analysis source-selection engine.

Given the tool summaries below, choose the best source for each category:
imports, functions, strings, decompilation, cff, static_profile.

Possible sources: ghidra, ida, malcat, both, none.
Assign confidence: high, medium, low.

Tool summaries:
{json.dumps(tool_summaries, indent=2, default=str)}

Existing rule-based decisions:
{json.dumps(rule_decisions, indent=2, default=str)}

Warnings:
{json.dumps(warnings, indent=2)}

Return JSON with one entry per category:
{{"imports": {{"source": "...", "confidence": "...", "reason": "..."}}, ...}}
"""


def decide_sources(sha: str, session: dict, validation: dict, use_llm: bool = True) -> dict:
    """Decide which engine is authoritative per evidence category.

    Writes /opt/samples/logs/<sha>/intake-validation.json with tool summaries,
    warnings, and source decisions. Also writes /opt/samples/logs/<sha>/source-decisions.json
    as a flat copy for backward compatibility.
    """
    _ = session  # reserved for future per-sample overrides
    ghidra = validation.get("ghidra", {})
    ida = validation.get("ida", {})
    malcat = validation.get("tool_summaries", {}).get("malcat", {})

    rule_decisions = {
        "sha256": sha,
        "imports": {"source": None, "confidence": "medium", "reason": ""},
        "functions": {"source": None, "confidence": "medium", "reason": ""},
        "strings": {"source": "both", "confidence": "high", "reason": "use both engines"},
        "decompilation": {"source": "ghidra", "confidence": "medium", "reason": "default to Ghidra"},
        "cff": {"source": "ghidra", "confidence": "medium", "reason": "default to Ghidra"},
        "static_profile": {"source": "malcat", "confidence": "medium", "reason": "default to Malcat"},
    }

    gh_imp = ghidra.get("imports", 0)
    ida_imp = ida.get("imports", 0)

    # Imports
    if gh_imp > 0 and ida_imp > 0:
        if max(gh_imp, ida_imp) / min(gh_imp, ida_imp) <= 1.2:
            rule_decisions["imports"]["source"] = "ghidra"
            rule_decisions["imports"]["reason"] = f"Ghidra={gh_imp}, IDA={ida_imp}; within 20%."
        else:
            rule_decisions["imports"]["source"] = "ida"
            rule_decisions["imports"]["reason"] = f"IDA={ida_imp}, Ghidra={gh_imp}; divergence > 20%."
    elif gh_imp > 0:
        rule_decisions["imports"]["source"] = "ghidra"
        rule_decisions["imports"]["reason"] = f"IDA has 0 imports; Ghidra has {gh_imp}."
    elif ida_imp > 0:
        rule_decisions["imports"]["source"] = "ida"
        rule_decisions["imports"]["reason"] = f"Ghidra has 0 imports; IDA has {ida_imp}."
    else:
        rule_decisions["imports"]["source"] = "none"
        rule_decisions["imports"]["reason"] = "No imports from either engine."

    # Fallback to Malcat imports if both SQL engines are missing imports
    if rule_decisions["imports"]["source"] == "none" and isinstance(malcat.get("imports_count"), int) and malcat["imports_count"] > 0:
        rule_decisions["imports"]["source"] = "malcat"
        rule_decisions["imports"]["reason"] = f"Ghidra/IDA imports missing; Malcat has {malcat['imports_count']} imports."

    # Functions
    gh_f = ghidra.get("funcs", 0)
    ida_f = ida.get("funcs", 0)
    if gh_f > 0 and ida_f > 0:
        if max(gh_f, ida_f) / min(gh_f, ida_f) <= 2.0:
            rule_decisions["functions"]["source"] = "ghidra"
            rule_decisions["functions"]["reason"] = f"Ghidra={gh_f}, IDA={ida_f}; within 2x."
        else:
            rule_decisions["functions"]["source"] = "review"
            rule_decisions["functions"]["reason"] = f"Ghidra={gh_f}, IDA={ida_f}; divergence > 2x."
    elif gh_f > 0:
        rule_decisions["functions"]["source"] = "ghidra"
        rule_decisions["functions"]["reason"] = f"IDA has 0 functions; Ghidra has {gh_f}."
    elif ida_f > 0:
        rule_decisions["functions"]["source"] = "ida"
        rule_decisions["functions"]["reason"] = f"Ghidra has 0 functions; IDA has {ida_f}."
    else:
        rule_decisions["functions"]["source"] = "none"
        rule_decisions["functions"]["reason"] = "No functions from either engine."

    # If function coverage is unreliable, decompilation/CFF are off
    if rule_decisions["functions"]["source"] in ("none", "review"):
        rule_decisions["decompilation"]["source"] = "none"
        rule_decisions["decompilation"]["reason"] = "Function coverage is unreliable."
        rule_decisions["cff"]["source"] = "none"
        rule_decisions["cff"]["reason"] = "Function coverage is unreliable."

    # Static profile
    if "error" in malcat:
        rule_decisions["static_profile"]["source"] = "none"
        rule_decisions["static_profile"]["reason"] = "Malcat triage failed."
    else:
        rule_decisions["static_profile"]["confidence"] = "high"
        rule_decisions["static_profile"]["reason"] = (
            f"Malcat provides fast file summary, anomalies ({malcat.get('anomalies_count')}), "
            f"imports ({malcat.get('imports_count')}), and strings."
        )

    # Use LLM to refine decisions when available
    decisions = dict(rule_decisions)
    if use_llm:
        try:
            prompt = _build_source_decision_prompt(validation["tool_summaries"], rule_decisions, validation["warnings"])
            resp = llm_judge(prompt)
            llm_decisions = json.loads(resp["choices"][0]["message"]["content"])
            for cat in list(rule_decisions.keys()):
                if cat != "sha256" and cat in llm_decisions:
                    decisions[cat] = llm_decisions[cat]
            decisions["llm_revised"] = True
        except Exception as e:
            print(f"[intake_v2] LLM source decision failed: {e}; using rule-based", flush=True)
            decisions["llm_revised"] = False

    # Persist full intake-validation.json
    full_report = {
        "sha256": sha,
        "tool_summaries": validation["tool_summaries"],
        "warnings": validation["warnings"],
        "source_decisions": decisions,
    }
    val_path = case_dir(sha) / "intake-validation.json"
    val_path.parent.mkdir(parents=True, exist_ok=True)
    val_path.write_text(json.dumps(full_report, indent=2, default=str))

    # Persist flat source-decisions.json for backward compatibility
    flat = {k: v for k, v in decisions.items() if k != "llm_revised"}
    flat_path = case_dir(sha) / "source-decisions.json"
    flat_path.write_text(json.dumps(flat, indent=2, default=str))

    return decisions


def main():
    load_env_file(LLM_ENV)
    load_env_file(CADRE_ENV)
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_path")
    ap.add_argument("--project-name", default="malware-sample-library")
    ap.add_argument("--skip-ida", action="store_true",
                    help="Skip local IDA bootstrap (idasql)")
    ap.add_argument(
        "--mode",
        choices=("auto", "standard", "large"),
        default="auto",
        help="Pipeline mode: auto-classify (default), or force standard/large "
             "(see docs/PIPELINE-MODES.md)",
    )
    ap.add_argument(
        "--resume-after-ghidra",
        action="store_true",
        help="Skip analyzeHeadless; continue from an already-finished .gpr "
             "(use when intake parent died but Ghidra completed).",
    )
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

    # --- Document path: triage first, skip Ghidra/IDA ---
    if fmt in DOC_FORMATS:
        doc = run_doc_triage(staged, sha)
        session_path = write_session(
            sha, staged, None, args.project_name, file_type_info,
            ida_session_id=None,
            ida_db_path=None,
            malcat_profile_path=None,
            malcat_analysis_id=None,
        )
        session_data = json.loads(session_path.read_text())
        session_data = update_session(sha, {
            "doc_triage_path": str(case_dir(sha) / "doc_triage.json"),
            "doc_triage": doc,
            "pipeline_mode": "document",
            "pipeline_mode_reasons": ["file_type_document_triage"],
            "gpr_path": None,
            "skip_ghidra": True,
            "skip_ida": True,
        })
        # Audit parity: document samples get neutral intake-validation.json +
        # source-decisions.json so the intake gate and downstream prompt
        # assembly keep the same evidence contract (doc_triage carries the
        # evidence; ghidra/ida are explicitly not-applicable).
        try:
            _flags = (doc.get("triage") or {}).get("flags") or {}
            _iv = {
                "sha256": sha,
                "format": fmt,
                "mode": "document",
                "tool_summaries": {
                    "malcat": {},
                    "ghidra": {},
                    "ida": {},
                    "doc_triage": {
                        "ok": bool(doc.get("ok", doc.get("doc_triage_rc") == 0)),
                        "kind": doc.get("kind"),
                        "flags": _flags,
                        "analyst_next": doc.get("analyst_next") or [],
                    },
                },
                "ghidra": {},
                "ida": {},
                "warnings": [
                    "document format: ghidra/ida skipped (doc_triage used)",
                ],
            }
            (case_dir(sha) / "intake-validation.json").write_text(
                json.dumps(_iv, indent=2, default=str)
            )
            _sd = {
                "sha256": sha,
                "format": fmt,
                "imports": {
                    "source": "none",
                    "confidence": "high",
                    "reason": "document format: no PE imports (doc_triage used)",
                },
                "functions": {
                    "source": "none",
                    "confidence": "high",
                    "reason": "document format: no functions (doc_triage used)",
                },
                "strings": {
                    "source": "doc_triage",
                    "confidence": "medium",
                    "reason": "doc_triage string/flag extraction",
                },
                "decompilation": {
                    "source": "none",
                    "confidence": "high",
                    "reason": "document format: no decompilation (doc_triage used)",
                },
            }
            (case_dir(sha) / "source-decisions.json").write_text(
                json.dumps(_sd, indent=2, default=str)
            )
        except Exception as e:
            print(f"[intake_v2] document validation stub error: {e}", flush=True)
        print(
            f"[intake_v2] document intake complete kind={fmt} "
            f"doc_triage={case_dir(sha) / 'doc_triage.json'}",
            flush=True,
        )
        print(json.dumps({
            "sha256": sha,
            "session_id": session_data.get("session_id"),
            "sample_path": str(staged),
            "file_type": session_data.get("file_type"),
            "pipeline_mode": "document",
            "doc_triage_path": str(case_dir(sha) / "doc_triage.json"),
            "doc_triage_flags": (doc.get("triage") or {}).get("flags"),
            "analyst_next": doc.get("analyst_next") or [],
        }, indent=2, default=str))
        return

    # Fast Malcat triage first: gives us file type, packer hints, .NET bundle
    # detection, import count, and anomalies before we spend time on Ghidra/IDA.
    malcat_profile_path = str(case_dir(sha) / "malcat-triage.json")
    if Path(malcat_profile_path).exists() and args.resume_after_ghidra:
        malcat_summary = json.loads(Path(malcat_profile_path).read_text(encoding="utf-8", errors="replace"))
        print(f"[intake_v2] resume: reusing malcat triage -> {malcat_profile_path}", flush=True)
    else:
        malcat_summary = run_malcat_triage(staged, sha)
        malcat_profile_path = str(case_dir(sha) / "malcat-triage.json") if isinstance(malcat_summary, dict) else None
    malcat_analysis_id = malcat_summary.get("analysis_id") if isinstance(malcat_summary, dict) else None

    # Early mode decision BEFORE Ghidra: large → import-only (-noanalysis);
    # agentic deep_dive segments analysis. Standard → full AutoAnalysis.
    pre_session = {"sample_path": str(staged), "file_type": file_type_info}
    pre_mode = resolve_pipeline_mode(
        pre_session,
        intake_validation={
            "tool_summaries": {"malcat": _malcat_summary(malcat_summary)},
        },
        override=None if args.mode == "auto" else args.mode,
    )
    no_analysis = pre_mode.get("mode") == "large"
    print(
        f"[intake_v2] pre_mode={pre_mode.get('mode')} "
        f"ghidra_no_analysis={no_analysis} reasons={pre_mode.get('reasons')}",
        flush=True,
    )

    if args.resume_after_ghidra:
        gpr = GPR_ROOT / sha / f"{sha}.gpr"
        rep = GPR_ROOT / sha / f"{sha}.rep"
        if not _ghidra_project_ready(gpr, rep):
            print(
                f"[intake_v2] resume-after-ghidra failed: project not ready "
                f"(gpr={gpr} exists={gpr.exists()} size={gpr.stat().st_size if gpr.exists() else 0}; "
                f"rep={rep} exists={rep.exists()})",
                file=sys.stderr,
            )
            sys.exit(3)
        print(
            f"[intake_v2] resume: using existing project -> {gpr} "
            f"(gpr_bytes={gpr.stat().st_size}, rep_ok=True)",
            flush=True,
        )
    else:
        gpr = import_into_ghidra(
            staged, sha, file_type_info=file_type_info, no_analysis=no_analysis,
        )
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
        malcat_profile_path=malcat_profile_path,
        malcat_analysis_id=malcat_analysis_id,
    )
    print(f"[intake_v2] session -> {session_path}", flush=True)

    # CFF detector — AFTER write_session (needs session JSON → Ghidra project).
    # LARGE mode: skip. The agentic pipeline owns CFF analysis as a segmented
    # step — never a monolithic intake hang on binders.
    if fmt in ("pe", "dotnet") and not no_analysis:
        cff_session_id = f"ghidra-{fmt}-{sha}"
        try:
            cff_result = subprocess.run(
                ["python3", "/opt/scripts/cff_detect.py", cff_session_id],
                check=False, timeout=1200,
            )
            if cff_result.returncode != 0:
                print(f"[intake_v2] cff_detect rc={cff_result.returncode} (non-fatal)", flush=True)
        except Exception as e:
            print(f"[intake_v2] cff_detect warning: {e}", flush=True)
    elif no_analysis:
        print(
            "[intake_v2] large mode: skipping intake cff_detect "
            "(agentic pipeline owns segmented CFF analysis)",
            flush=True,
        )

    session_data = json.loads(session_path.read_text())

    # Cross-validate Ghidra and IDA SQL outputs so downstream stages know
    # which data sources are reliable for this sample.
    try:
        validation = validate_engine_outputs(sha, session_data, malcat_summary)
        if validation.get("warnings"):
            for w in validation["warnings"]:
                print(f"[intake_v2] validation warning: {w}", flush=True)
        else:
            print("[intake_v2] engine validation passed", flush=True)
    except Exception as e:
        print(f"[intake_v2] engine validation error: {e}", flush=True)
        validation = {
            "sha256": sha,
            "tool_summaries": {"malcat": _malcat_summary(malcat_summary), "ghidra": {}, "ida": {}},
            "ghidra": {},
            "ida": {},
            "warnings": [str(e)],
        }

    try:
        decisions = decide_sources(sha, session_data, validation)
        print(f"[intake_v2] source decisions -> {case_dir(sha) / 'source-decisions.json'}", flush=True)
    except Exception as e:
        print(f"[intake_v2] source decisions error: {e}", flush=True)
        decisions = {"sha256": sha, "error": str(e)}

    # Classify standard vs large after we have size + binder + func counts.
    mode_override = None if args.mode == "auto" else args.mode
    mode_info = resolve_pipeline_mode(
        session_data,
        intake_validation={
            "tool_summaries": validation.get("tool_summaries") or {},
            "ghidra": validation.get("ghidra") or {},
            "ida": validation.get("ida") or {},
        },
        override=mode_override,
    )
    session_data = update_session(sha, {
        "pipeline_mode": mode_info["mode"],
        "pipeline_mode_reasons": mode_info.get("reasons") or [],
        "pipeline_mode_signals": mode_info.get("signals") or {},
        "pipeline_mode_source": mode_info.get("source") or "auto",
        "pipeline_mode_locked": bool(mode_override),
    })
    print(
        f"[intake_v2] pipeline_mode={mode_info['mode']} "
        f"source={mode_info.get('source')} reasons={mode_info.get('reasons')}",
        flush=True,
    )

    print(json.dumps({
        "sha256": sha,
        "session_id": session_data["session_id"],
        "sample_path": str(staged),
        "gpr_path": str(gpr),
        "ida_session_id": session_data.get("ida_session_id"),
        "ida_db_path": session_data.get("ida_db_path"),
        "file_type": session_data.get("file_type"),
        "pipeline_mode": session_data.get("pipeline_mode"),
        "pipeline_mode_reasons": session_data.get("pipeline_mode_reasons"),
        "validation": validation,
        "source_decisions": decisions,
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
