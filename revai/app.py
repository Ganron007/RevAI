"""app.py — professional web UI for the CADRE-RevAI malware pipeline.

Workflow:
  1. STAGE  — pick a file + family, click Stage
  2. RUN    — per-stage buttons (intake → quick_scan → deep_dive → yara_gen → publish → correlate)
  3. REVIEW — Evidence tree, rendered reports, RAG context, raw tool output, live log

State persisted to /opt/samples/logs/<sha>/pipeline-status.json.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, Response, send_from_directory, redirect

SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")
SCRIPTS_DIR = Path("/opt/scripts")
CONFIG_PATH = Path("/opt/samples/pipeline-config.json")
# P0.3: LLM API key lives ONLY in this chmod-600 env file — never in pipeline-config.json.
SECRETS_PATH = Path(os.environ.get("CADRE_UI_SECRETS", "/opt/secrets/cadre-ui.env"))
# P0.2: HTTP staging/orch only accepts samples under these roots (realpath-checked).
STAGE_ALLOWED_ROOTS = (
    Path("/opt/samples/incoming"),
    Path("/opt/samples/mta-routing"),
)
# SPA build (deployed to /opt/scripts/ui/). Fallback: sibling of app.py.
UI_DIST = Path(os.environ.get("CADRE_UI_DIST", str(SCRIPTS_DIR / "ui")))
if not (UI_DIST / "index.html").is_file():
    _local = Path(__file__).resolve().parent / "ui"
    if (_local / "index.html").is_file():
        UI_DIST = _local

# Hard timeout for any single stage in the Flask UI.  The deep-analysis
# stages can take 1–2 hours on large samples, so cap at 4 hours.
STAGE_TIMEOUT_S = int(os.environ.get("STAGE_TIMEOUT_S", "14400"))

DEFAULT_CONFIG = {
    # LLM backend is configured by the user at runtime (env or UI settings).
    # No hardcoded model, API key, endpoint, or reasoning level in code.
    "llm_model": "",
    "llm_api_url": "",
    "llm_api_key": "",
    "llm_reasoning": "",
    "product_mode": "LLM-only · static RE · LangGraph orch",
}

# Settings keys exposed to SPA (no RAG URLs / toggles on the wire).
LLM_SETTINGS_KEYS = ("llm_model", "llm_api_url", "llm_api_key", "llm_reasoning", "product_mode")

# Core spine (static RE + LLM). Dynamic analysis is analyst-optional only.
# CLI: pipeline_single.py / stage_orchestrator.py (no Flare in spine).
STAGES = [
    ("intake",     "intake",     str(SCRIPTS_DIR / "intake_v2.py"),        []),
    ("quick_scan", "quick_scan", str(SCRIPTS_DIR / "quick_scan_v2.py"),   []),
    ("deep_dive",  "deep_dive",  str(SCRIPTS_DIR / "deep_dive_agentic.py"), []),
    ("yara_gen",   "yara_gen",   str(SCRIPTS_DIR / "yara_gen_v2.py"),     []),
    ("publish",    "publish",    str(SCRIPTS_DIR / "publish_report_v2.py"), ["--template", "full"]),
    ("correlate",  "correlate",  str(SCRIPTS_DIR / "section_publisher.py"), []),
    ("audit",      "audit",      str(SCRIPTS_DIR / "audit_pipeline.py"),   []),
]
STAGE_INFO = {sid: (label, script, args) for sid, label, script, args in STAGES}

STAGE_ORDER = [s[0] for s in STAGES]
STAGE_DEPS = {
    "intake": [],
    "quick_scan": ["intake"],
    "deep_dive": ["quick_scan"],
    "yara_gen": ["deep_dive"],
    "publish": ["yara_gen"],
    "correlate": ["publish"],
    "audit": ["correlate"],
}

STAGE_DETAILS = {
    "intake": {
        "num": 1, "title": "Intake",
        "desc": "Load sample into Ghidra + IDA, create session registry",
        "long_desc": "Runs Ghidra analyzeHeadless to import + analyze the binary, runs idasql bootstrap to create the .i64, and writes the session JSON that all downstream stages use.",
        "artifacts": ["session.json", "intake-analyzeHeadless.log"],
        "dir": None,
    },
    "quick_scan": {
        "num": 2, "title": "Quick Scan",
        "desc": "Run all triage tools → RAG → one LLM call → verdict",
        "long_desc": "Executes capa, YARA, FLOSS, r2, upx, xorsearch, and more in parallel. Assembles signal-prioritized evidence cards and asks the LLM for a triage verdict.",
        "artifacts": ["00-tools-raw.json", "01-sql-evidence.json", "02-prompt.txt", "03-llm-raw.json", "04-verdict.json"],
        "dir": "quick_scan",
    },
    "deep_dive": {
        "num": 3, "title": "Deep Dive (agentic)",
        "desc": "LangGraph/agentic deep RE for all samples",
        "long_desc": (
            "Always runs deep_dive_agentic.py (SQL-first checklist + agent loop). "
            "Stage orchestration: stage_orchestrator.py / pipeline_single.py. "
            "Flare dynamic is NOT in the core spine (analyst-optional)."
        ),
        "artifacts": [
            "00-sql-evidence.json", "01-tools-raw.json", "02-cff-findings.json",
            "03-prompt.txt", "04-llm-raw.json", "05-deep-dive.json",
            "agentic_deep_dive.json",
        ],
        "dir": "deep_dive",
    },
    "yara_gen": {
        "num": 4, "title": "YARA Gen",
        "desc": "Generate YARA + Sigma detection rules",
        "long_desc": "Collects strings from Ghidra/IDA, verdict IOCs, and hex signatures, then builds a YARA rule and a Sigma rule. Optionally validates the YARA rule against the sample.",
        "artifacts": ["rule.yar", "rule.yara.json", "rule.yml"],
        "dir": None,
    },
    "publish": {
        "num": 5, "title": "Publish",
        "desc": "Generate REPORT-MASTER v2 from all evidence",
        "long_desc": "Collects verdict, deep-dive, YARA, audit trail and raw tool packs, adds optional RAG context, and asks the LLM to write the 16-section REPORT-MASTER markdown.",
        "artifacts": ["00-prompt.txt", "01-llm-raw.json", "02-REPORT-MASTER-v2.md"],
        "dir": "publish",
    },
    "correlate": {
        "num": 6, "title": "Correlate",
        "desc": "Section-based Map-Reduce report with cross-references",
        "long_desc": "Pass 1 generates 17 report sections independently with focused evidence + targeted RAG. Pass 2 re-generates sections with cross-section context so each section can cite findings from the others. Produces REPORT-MASTER-v3.md.",
        "artifacts": ["00-tools-raw.json", "01-section-results.json", "02-REPORT-MASTER-v3.md"],
        "dir": "correlate",
    },
    "audit": {
        "num": 7, "title": "Audit",
        "desc": "Strict full-stage audit (standard|large) → pipeline-audit.json",
        "long_desc": (
            "Runs audit_pipeline.py with session pipeline_mode. "
            "Pass = all_green in pipeline-audit.json + AUDIT-REPORT.md. "
            "Required gate for S1/S3 evidence and S4 UI calibration."
        ),
        "artifacts": ["pipeline-audit.json", "AUDIT-REPORT.md"],
        "dir": None,
    },
}

# Root-level files that are not stored in a stage sub-directory but conceptually
# belong to one pipeline stage. Used by /api/evidence to avoid a confusing "root"
# bucket in the evidence tree.
ROOT_FILE_STAGE_MAP = {
    "verdict.json": "quick_scan",
    "prompt.txt": "quick_scan",
    "audit.jsonl": "session",
    "ghidrasql-server.log": "intake",
    "idasql-server.log": "intake",
    "intake-analyzeHeadless.log": "intake",
    "intake-idasql.log": "intake",
    "pipeline-status.json": "session",
    "pipeline-audit.json": "audit",
    "AUDIT-REPORT.md": "audit",
}

# in-memory task registry
tasks: dict = {}
tasks_lock = threading.Lock()

app = Flask(__name__)


# ============== filesystem helpers ==============

def _sample_display_name(sample_path: str, project_name: str, sha: str) -> str:
    base = Path(sample_path or "").name
    if base:
        return base
    if project_name:
        return project_name
    return sha[:12] + "…"


def _sample_group_name(sample_path: str, project_name: str) -> str:
    """Corpus family folder or project_name — navigation group key."""
    try:
        p = Path(sample_path or "")
        # /opt/samples/corpus/<family>/<sha>/<file>
        parts = p.parts
        if "corpus" in parts:
            i = parts.index("corpus")
            if i + 1 < len(parts):
                fam = parts[i + 1]
                if fam and fam.lower() not in ("corpus",):
                    return fam
    except Exception:
        pass
    return project_name or "ungrouped"


def _date_bucket(staged_at: str) -> str:
    if not staged_at:
        return "Older"
    try:
        # support Z / offset
        ts = staged_at.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = (now.date() - dt.astimezone(timezone.utc).date()).days
        if days <= 0:
            return "Today"
        if days == 1:
            return "Yesterday"
        if days < 7:
            return "This week"
        if days < 30:
            return "This month"
        return "Older"
    except Exception:
        return "Older"


def _verdict_fields(sha: str) -> dict:
    """Lazy join verdict.json for case-card badges (best-effort)."""
    out = {
        "verdict": "",
        "family_guess": "",
        "score": None,
    }
    vp = LOGS_DIR / sha / "verdict.json"
    if not vp.exists():
        return out
    try:
        v = json.loads(vp.read_text(encoding="utf-8", errors="replace"))
        out["verdict"] = (v.get("verdict") or "")[:40]
        out["family_guess"] = (v.get("family_guess") or "")[:60]
        sc = v.get("score", v.get("numeric_score"))
        out["score"] = sc
    except Exception:
        pass
    return out


def list_samples() -> list:
    out = []
    if not SESSIONS_DIR.exists():
        return out
    for sf in sorted(SESSIONS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(sf.read_text())
            sha = data.get("sha256", sf.stem)
            ft = data.get("file_type", {})
            sample_path = data.get("sample_path", "")
            project_name = data.get("project_name", "")
            staged_at = data.get("staged_at", "")
            vf = _verdict_fields(sha)
            out.append({
                "sha256": sha,
                "sha_short": sha[:12],
                "session_id": data.get("session_id", ""),
                "project_name": project_name,
                "display_name": _sample_display_name(sample_path, project_name, sha),
                "group": _sample_group_name(sample_path, project_name),
                "date_bucket": _date_bucket(staged_at),
                "file_type": ft.get("format", "?"),
                "os": ft.get("os", "?"),
                "arch": ft.get("arch", "?"),
                "bits": ft.get("bits", 0),
                "gpr_path": data.get("gpr_path", ""),
                "staged_at": staged_at,
                "sample_path": sample_path,
                "pipeline_mode": data.get("pipeline_mode") or "",
                "pipeline_mode_reasons": data.get("pipeline_mode_reasons") or [],
                "verdict": vf["verdict"],
                "family_guess": vf["family_guess"],
                "score": vf["score"],
            })
        except Exception as e:
            out.append({"sha256": sf.stem, "sha_short": sf.stem[:12], "display_name": sf.stem[:12],
                        "group": "error", "date_bucket": "Older", "error": str(e)})
    return out


# Preset jq-like paths for Raw Audit pane (V5.17) — mirrors RAW-AUDIT-CHEATSHEET
JSON_QUERY_PRESETS = [
    {"id": "verdict_surface", "label": "Verdict surface", "path": "verdict.json",
     "expr": "verdict,score,family_guess,agreement,source,model"},
    {"id": "capa_rules", "label": "capa top rules", "path": "quick_scan/00-tools-raw.json",
     "expr": "capa.engine,capa.rule_count,capa.top_rules"},
    {"id": "yara_matches", "label": "YARA matches", "path": "quick_scan/00-tools-raw.json",
     "expr": "yara.matches"},
    {"id": "malcat_sections", "label": "Malcat sections", "path": "quick_scan/00-tools-raw.json",
     "expr": "malcat.file_summary"},
    {"id": "malcat_high_strings", "label": "Malcat strings (all)", "path": "quick_scan/00-tools-raw.json",
     "expr": "malcat.views.strings"},
    {"id": "pe_imports", "label": "PE imports/signals", "path": "quick_scan/00-tools-raw.json",
     "expr": "pe_imports"},
    {"id": "upx", "label": "UPX unpack", "path": "deep_dive/01-tools-raw.json",
     "expr": "upx"},
    {"id": "r2_entry", "label": "r2 disassembly map keys", "path": "deep_dive/01-tools-raw.json",
     "expr": "r2_decomp"},
    {"id": "speakeasy", "label": "Speakeasy summary", "path": "deep_dive/01-tools-raw.json",
     "expr": "speakeasy"},
    {"id": "lief", "label": "LIEF binary structure", "path": "deep_dive/01-tools-raw.json",
     "expr": "lief"},
    {"id": "diec", "label": "Packer/compiler/language (DIE)", "path": "deep_dive/01-tools-raw.json",
     "expr": "diec"},
    {"id": "findcrypt", "label": "Crypto constants (FindCrypt)", "path": "deep_dive/01-tools-raw.json",
     "expr": "findcrypt"},
    {"id": "goresym", "label": "Go symbol recovery", "path": "deep_dive/01-tools-raw.json",
     "expr": "goresym"},
    {"id": "rift", "label": "Rust metadata", "path": "deep_dive/01-tools-raw.json",
     "expr": "rift"},
    {"id": "ilspy", "label": ".NET C# decompile", "path": "deep_dive/01-tools-raw.json",
     "expr": "ilspy"},
    {"id": "pdfid", "label": "PDF structure", "path": "deep_dive/01-tools-raw.json",
     "expr": "pdfid"},
    {"id": "shellcode", "label": "Shellcode extraction", "path": "deep_dive/01-tools-raw.json",
     "expr": "shellcode"},
    {"id": "elf", "label": "ELF structure", "path": "deep_dive/01-tools-raw.json",
     "expr": "elf"},
    {"id": "deep_key_evidence", "label": "Deep key_evidence", "path": "deep_dive/05-deep-dive.json",
     "expr": "key_evidence,summary,behaviors,iocs"},
    {"id": "sql_labels", "label": "SQL evidence labels", "path": "deep_dive/00-sql-evidence.json",
     "expr": ""},
]


def _json_path_get(data, expr: str):
    """Safe dotted-path extractor. Comma = multi-key object. Empty = whole doc."""
    expr = (expr or "").strip()
    if not expr:
        return data
    if "," in expr:
        out = {}
        for part in expr.split(","):
            part = part.strip()
            if not part:
                continue
            out[part.split(".")[-1] if "." not in part else part] = _json_path_get(data, part)
        return out
    cur = data
    for key in expr.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def list_json_artifacts(sha: str) -> list:
    """JSON files under logs/<sha> suitable for Raw Audit."""
    base = LOGS_DIR / sha
    out = []
    if not base.exists():
        return out
    for item in sorted(base.rglob("*.json")):
        if not item.is_file() or item.name.startswith("."):
            continue
        rel = str(item.relative_to(base)).replace("\\", "/")
        out.append({
            "path": rel,
            "size": item.stat().st_size,
            "mtime": item.stat().st_mtime,
        })
    return out


def list_browser_dirs() -> list:
    # Browser shows only incoming / drop directories for staging.
    # Staged samples already live in /opt/samples/corpus but are managed via
    # /opt/samples/sessions/*.json; exposing corpus here creates a conflict
    # because users try to stage already-copied files instead of using the dropbox.
    candidates = [
        Path("/opt/samples/incoming/user-drop"),
        Path("/opt/samples/incoming/manual-drop"),
        Path("/opt/samples/incoming/cadre-push"),
        Path("/opt/samples/incoming/vr-hunt-pull"),
        Path("/opt/samples/sources/mta"),
        Path("/home/remnux/Desktop"),
        Path("/tmp"),
    ]
    out = []
    for d in candidates:
        if d.exists() and d.is_dir():
            try:
                files = sorted(d.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))[:80]
                out.append({
                    "path": str(d),
                    "n_files": sum(1 for _ in d.iterdir()),
                    "files": [
                        {"name": f.name, "is_dir": f.is_dir(),
                         "size": f.stat().st_size if f.is_file() else 0}
                        for f in files
                    ],
                })
            except Exception:
                pass
    return out


def get_upload_instructions() -> dict:
    return {
        "dropbox": "/opt/samples/incoming/user-drop",
        "commands": {
            "windows_powershell": "scp -i $env:USERPROFILE\\.ssh\\remnux-lab-key C:\\path\\to\\sample.exe remnux@<remnux-ip>:/opt/samples/incoming/user-drop/",
            "windows_cmd": "scp -i %USERPROFILE%\\.ssh\\remnux-lab-key C:\\path\\to\\sample.exe remnux@<remnux-ip>:/opt/samples/incoming/user-drop/",
            "linux_mac": "scp -i ~/.ssh/remnux-lab-key /path/to/sample.exe remnux@<remnux-ip>:/opt/samples/incoming/user-drop/",
        },
        "note": "Upload malware via SCP to the dropbox, then click Stage in this UI. No browser upload is supported for safety.",
    }


def stage_sample(src_path: str, family: str = "unknown") -> dict:
    """Stage a file: copy to /opt/samples/corpus/<family>/<sha>/ + run intake.

    Delegates to intake_v2.py so the session.json gets a real
    gpr_path and ida_db_path (not stubs). Runs synchronously
    because the UI expects to see a fully-staged sample.

    timeout=1800s (30 min): analyzeHeadless + idasql -w can take
    a long time on large samples. The timeout prevents the HTTP
    request from hanging forever if intake hangs. Progress is
    written to /opt/samples/logs/<sha>/intake-progress.json so
    the UI can poll it via /api/intake-progress/<sha>.
    """
    if not stage_path_allowed(src_path):
        allowed = ", ".join(str(r) for r in STAGE_ALLOWED_ROOTS)
        return {"ok": False, "error": f"src_path outside allowed staging roots ({allowed})"}
    src = Path(src_path)
    if not src.exists() or not src.is_file():
        return {"ok": False, "error": f"file not found: {src_path}"}
    family_clean = "".join(c for c in family if c.isalnum() or c in "._-") or "unknown"
    # Compute SHA first so we know the progress file path
    h = hashlib.sha256()
    with open(src, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    sha = h.hexdigest()
    # Initialize progress file
    prog_dir = LOGS_DIR / sha
    prog_dir.mkdir(parents=True, exist_ok=True)
    prog_path = prog_dir / "intake-progress.json"
    prog_path.write_text(json.dumps({
        "sha": sha, "stage": "starting", "pct": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "msg": "launching intake_v2.py",
    }))
    # Delegate to intake_v2.py so Ghidra + IDA bootstrap actually runs.
    try:
        proc = subprocess.run(
            ["python3", str(SCRIPTS_DIR / "intake_v2.py"),
             str(src), "--project-name", family_clean],
            capture_output=True, text=True, timeout=1800,
            cwd="/opt/scripts",
        )
    except subprocess.TimeoutExpired:
        prog_path.write_text(json.dumps({
            "sha": sha, "stage": "timeout", "pct": 100,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "msg": "intake_v2.py exceeded 1800s timeout",
        }))
        return {"ok": False, "error": "intake_v2.py exceeded 1800s timeout"}
    prog_path.write_text(json.dumps({
        "sha": sha, "stage": "done" if proc.returncode == 0 else "failed",
        "pct": 100, "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-500:],
        "stderr_tail": proc.stderr[-500:],
    }))
    if proc.returncode != 0:
        return {"ok": False, "error": f"intake_v2.py failed rc={proc.returncode}",
                "stderr": proc.stderr[-500:], "stdout": proc.stdout[-500:]}
    sess_path = SESSIONS_DIR / f"{sha}.json"
    if not sess_path.exists():
        return {"ok": False, "error": f"intake_v2.py succeeded but session.json missing: {sess_path}"}
    sess = json.loads(sess_path.read_text())
    return {"ok": True, "sha256": sha, "family": family_clean,
            "project_name": family_clean, "sample_path": sess.get("sample_path", ""),
            "file_type": sess.get("file_type", {}),
            "session_id": sess.get("session_id", ""),
            "gpr_path": sess.get("gpr_path", ""),
            "ida_db_path": sess.get("ida_db_path", "")}


@app.route("/api/intake-progress/<sha>")
def api_intake_progress(sha):
    """Return the latest intake progress for a sample (UI polling endpoint)."""
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    p = LOGS_DIR / sha / "intake-progress.json"
    if not p.exists():
        return jsonify({"stage": "none", "pct": 0, "msg": "no intake started"})
    try:
        return jsonify(json.loads(p.read_text()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== state persistence ==============

def get_status_path(sha: str) -> Path:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return LOGS_DIR / sha / "pipeline-status.json"


def load_pipeline_state(sha: str) -> dict:
    p = get_status_path(sha)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"sha": sha, "stages": {}}


def infer_pipeline_state(sha: str) -> dict:
    """Merge pipeline-status.json with artifact existence.

    Returns per-stage:
      - status: done / done-inferred / pending / error
      - source: 'pipeline-status' or 'artifact-inference'
      - started_at / finished_at from pipeline-status if available
    """
    state = load_pipeline_state(sha)
    stages = state.get("stages", {})
    out = {"sha": sha, "stages": {}}
    for s in STAGE_ORDER:
        info = stages.get(s) or {}
        status = info.get("status")
        if status in ("done", "error", "running"):
            out["stages"][s] = {**info, "source": "pipeline-status"}
            continue
        # infer from artifacts
        d = STAGE_DETAILS[s]
        artifacts = d.get("artifacts") or []
        if s == "intake":
            artifacts = ["intake-analyzeHeadless.log"]
        dir_name = d.get("dir")
        all_present = True
        for art in artifacts:
            if dir_name:
                p = LOGS_DIR / sha / dir_name / art
            else:
                if art == "session.json":
                    p = SESSIONS_DIR / f"{sha}.json"
                else:
                    p = LOGS_DIR / sha / art
            if not p.exists():
                all_present = False
                break
        if all_present and artifacts:
            out["stages"][s] = {"status": "done-inferred", "source": "artifact-inference"}
        else:
            out["stages"][s] = {"status": "pending", "source": "artifact-inference"}
    return out


def save_pipeline_state(sha: str, state: dict):
    p = get_status_path(sha)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2, default=str))


_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_FILE_READ_MAX = 50 * 1024 * 1024  # 50 MB


def require_sha(sha: str | None) -> str | None:
    """Return lowercased 64-hex SHA or None if invalid (blocks path traversal)."""
    if not sha or not _SHA_RE.fullmatch(sha):
        return None
    return sha.lower()


@app.before_request
def _validate_sha_url_vars():
    """P0.4: reject any non-64-hex <sha> URL variable on every route.

    Edge-level guard so no route (present or future) can join an
    unvalidated sha into a filesystem path. Hex-only = no traversal.
    """
    if request.view_args and "sha" in request.view_args:
        sha = request.view_args["sha"]
        if not sha or not _SHA_RE.fullmatch(sha):
            return jsonify({"error": "invalid sha"}), 400
    return None


def resolve_file_path(sha: str, rel_path: str) -> Path | None:
    """Resolve a relative path safely, allowing session.json as a special case."""
    sha_ok = require_sha(sha)
    if not sha_ok:
        return None
    if not rel_path or ".." in rel_path.replace("\\", "/") or rel_path.startswith(("/", "\\")):
        return None
    if rel_path == "session.json":
        sess = SESSIONS_DIR / f"{sha_ok}.json"
        return sess if sess.exists() else None
    base = (LOGS_DIR / sha_ok).resolve()
    full = (base / rel_path).resolve()
    try:
        full.relative_to(base)
    except ValueError:
        return None
    return full if full.exists() and full.is_file() else None


def stage_path_allowed(src_path: str) -> bool:
    """P0.2: True only if src_path resolves under an allowed staging root."""
    if not src_path:
        return False
    try:
        real = Path(src_path).resolve(strict=False)
    except Exception:
        return False
    for root in STAGE_ALLOWED_ROOTS:
        try:
            real.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def _read_llm_key() -> str:
    """P0.3: Read the LLM API key from the chmod-600 secrets env file."""
    try:
        for line in SECRETS_PATH.read_text().splitlines():
            line = line.strip()
            if line.startswith("REVAI_LLM_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return ""


def _write_llm_key(key: str) -> None:
    """P0.3: Persist the LLM API key to the secrets file with 0600 perms."""
    SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    if SECRETS_PATH.exists():
        try:
            lines = [l for l in SECRETS_PATH.read_text().splitlines()
                     if not l.strip().startswith("REVAI_LLM_API_KEY=")]
        except Exception:
            lines = []
    lines.append(f"REVAI_LLM_API_KEY={key}")
    SECRETS_PATH.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(SECRETS_PATH, 0o600)
    except Exception:
        pass


def load_config() -> dict:
    """Load pipeline UI settings from persistent JSON, merging with defaults.

    P0.3 migration: if an older config still carries a plaintext llm_api_key,
    move it to the secrets file and rewrite the config without it.
    """
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text()))
        except Exception:
            pass
    legacy_key = (cfg.get("llm_api_key") or "").strip()
    if legacy_key and legacy_key != "***":
        _write_llm_key(legacy_key)
        cfg["llm_api_key"] = ""
        try:
            scrubbed = {k: v for k, v in cfg.items() if k != "llm_api_key"}
            CONFIG_PATH.write_text(json.dumps({**scrubbed, "llm_api_key": ""}, indent=2))
        except Exception:
            pass
    cfg["llm_api_key"] = _read_llm_key()
    return cfg


def save_config(cfg: dict) -> None:
    """Persist pipeline UI settings — never persists the LLM API key (P0.3)."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    safe = dict(cfg)
    safe["llm_api_key"] = ""
    CONFIG_PATH.write_text(json.dumps(safe, indent=2))


def get_stage_env() -> dict[str, str]:
    """Build the environment variables passed to every spawned stage.

    LLM settings are injected only when the UI has explicitly set them,
    otherwise the stage scripts inherit them from the system environment.
    """
    cfg = load_config()
    env: dict[str, str] = {
        # Post-opt standard defaults (S1/S4) — match CLI rebench / S2 ui_default
        "CADRE_FLOSS_PROFILE": os.environ.get("CADRE_FLOSS_PROFILE", "auto"),
        "CADRE_CAPA_ENGINE": os.environ.get("CADRE_CAPA_ENGINE", "auto"),
    }
    # LLM backend: reads model names from env (REVAI_LLM_MODEL, REVAI_LLM_PLANNER_MODEL,
    # REVAI_LLM_VERDICT_MODEL). The env file is the single source of truth for model choice.
    llm_model = (cfg.get("llm_model") or "").strip()
    if llm_model:
        env["REVAI_LLM_MODEL"] = llm_model
        env["REVAI_LLM_VERDICT_MODEL"] = llm_model
        env["REVAI_LLM_MODEL_REQUESTED"] = llm_model
    llm_api_url = cfg.get("llm_api_url", "").strip()
    if llm_api_url:
        env["REVAI_LLM_API_URL"] = llm_api_url
    llm_reasoning = cfg.get("llm_reasoning", "").strip()
    if llm_reasoning:
        env["REVAI_LLM_REASONING"] = llm_reasoning
    else:
        env.setdefault("REVAI_LLM_REASONING", "max")
    llm_api_key = cfg.get("llm_api_key", "").strip()
    if llm_api_key:
        env["REVAI_LLM_API_KEY"] = llm_api_key
    return env



# ============== stage runner ==============

def _session_pipeline_mode(sha: str) -> str:
    """Return single|standard|large from session (orchestrator prefers single)."""
    try:
        sess = json.loads((SESSIONS_DIR / f"{sha}.json").read_text())
        mode = (sess.get("pipeline_mode") or "").strip().lower()
        if mode in ("single", "standard", "large"):
            return mode
        from v2_lib import resolve_pipeline_mode
        info = resolve_pipeline_mode(sess)
        return info.get("mode") or "single"
    except Exception:
        return "single"


def build_stage_command(stage: str, sha: str, sample_path: str) -> list:
    label, script, extra_args = STAGE_INFO[stage]
    if stage == "intake":
        override = (os.environ.get("CADRE_PIPELINE_MODE") or "single").strip().lower()
        cmd = ["python3", script] + list(extra_args) + [sample_path]
        if override == "single":
            cmd.extend(["--mode", "large"])  # agentic-friendly bootstrap
        elif override in ("standard", "large"):
            cmd.extend(["--mode", override])
        return cmd
    if stage == "yara_gen":
        try:
            family = Path(sample_path).parent.parent.name
            if not family or family.lower() in ("corpus", "incoming"):
                family = "unknown"
        except Exception:
            family = "unknown"
        return ["python3", script, "--family", family, sha]
    if stage == "deep_dive":
        return ["python3", script, sha]  # deep_dive_agentic — no --mode
    if stage == "audit":
        mode = _session_pipeline_mode(sha)
        audit_mode = "large" if mode in ("single", "large") else "standard"
        return ["python3", script, "--mode", audit_mode, sha]
    return ["python3", script] + list(extra_args) + [sha]


def run_stage(sha: str, stage: str, sample_path: str) -> str:
    """Spawn one stage, stream stdout to in-memory + on-disk log."""
    task_id = uuid.uuid4().hex[:12]
    cmd = build_stage_command(stage, sha, sample_path)
    now = datetime.now(timezone.utc).isoformat()
    with tasks_lock:
        tasks[task_id] = {
            "task_id": task_id, "sha": sha, "stage": stage,
            "status": "running", "started_at": now, "finished_at": None,
            "returncode": None, "command": " ".join(cmd),
            "log": [f"[{now}] $ {' '.join(cmd)}"],
        }
    state = load_pipeline_state(sha)
    state.setdefault("stages", {})[stage] = {
        "status": "running", "started_at": now, "returncode": None,
        "log_tail": tasks[task_id]["log"][-50:],
    }
    save_pipeline_state(sha, state)

    # persistent stage log file
    stage_log_dir = LOGS_DIR / sha / stage
    stage_log_dir.mkdir(parents=True, exist_ok=True)
    stage_log_path = stage_log_dir / "stage.log"

    def _run():
        proc = None
        timed_out = False

        def _kill():
            nonlocal timed_out
            timed_out = True
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass

        timer = threading.Timer(STAGE_TIMEOUT_S, _kill)
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=False, bufsize=1,
                cwd="/opt/scripts",
                env={**os.environ, **get_stage_env()},
            )
            timer.start()
            with open(stage_log_path, "w", encoding="utf-8", errors="replace") as logf:
                for chunk in iter(proc.stdout.readline, b""):
                    if not chunk:
                        continue
                    line = chunk.decode("utf-8", errors="replace").rstrip()
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    tagged = f"[{ts}] {line}"
                    logf.write(tagged + "\n")
                    logf.flush()
                    with tasks_lock:
                        tasks[task_id]["log"].append(tagged)
                        if len(tasks[task_id]["log"]) > 2000:
                            tasks[task_id]["log"] = tasks[task_id]["log"][-2000:]
                    state = load_pipeline_state(sha)
                    state.setdefault("stages", {}).setdefault(stage, {})
                    state["stages"][stage]["log_tail"] = tasks[task_id]["log"][-50:]
                    save_pipeline_state(sha, state)
            try:
                rc = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    rc = proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    rc = -9
            if timed_out:
                rc = -9
                ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                with tasks_lock:
                    tasks[task_id]["log"].append(f"[{ts}] STAGE TIMEOUT after {STAGE_TIMEOUT_S}s")
        except Exception as e:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            with tasks_lock:
                tasks[task_id]["log"].append(f"[{ts}] EXCEPTION: {e}")
            rc = -1
        finally:
            timer.cancel()
        now = datetime.now(timezone.utc).isoformat()
        with tasks_lock:
            tasks[task_id]["status"] = "done" if rc == 0 else "error"
            tasks[task_id]["finished_at"] = now
            tasks[task_id]["returncode"] = rc
            if rc == 0:
                tasks[task_id]["log"].append(f"[{now}] {stage} DONE rc=0")
            else:
                tasks[task_id]["log"].append(f"[{now}] {stage} FAILED rc={rc}")
        state = load_pipeline_state(sha)
        state.setdefault("stages", {}).setdefault(stage, {})
        state["stages"][stage]["status"] = "done" if rc == 0 else "error"
        state["stages"][stage]["finished_at"] = now
        state["stages"][stage]["returncode"] = rc
        save_pipeline_state(sha, state)
    threading.Thread(target=_run, daemon=True).start()
    return task_id


def run_all_stages(sha: str, sample_path: str) -> str:
    """Run all pipeline stages in sequence. Halts on first failure."""
    master_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    with tasks_lock:
        tasks[master_id] = {
            "task_id": master_id, "sha": sha, "stage": "all",
            "status": "running", "started_at": now, "finished_at": None,
            "returncode": None, "command": f"Run All on {sha[:12]}",
            "log": [f"[{now}] === starting Run All on {sha[:12]} ==="],
        }
    def _seq():
        for stage, _, _, _ in STAGES:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            with tasks_lock:
                tasks[master_id]["log"].append(f"[{ts}] ---> starting stage: {stage}")
            subtask_id = run_stage(sha, stage, sample_path)
            while True:
                with tasks_lock:
                    st = tasks[subtask_id]["status"]
                if st in ("done", "error"):
                    break
                time.sleep(0.5)
            with tasks_lock:
                rc = tasks[subtask_id]["returncode"]
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            with tasks_lock:
                if rc == 0:
                    tasks[master_id]["log"].append(f"[{ts}] <--- {stage} OK")
                else:
                    tasks[master_id]["log"].append(f"[{ts}] <--- {stage} FAILED rc={rc} -- halting")
                    tasks[master_id]["status"] = "error"
                    tasks[master_id]["returncode"] = rc
                    tasks[master_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
                    return
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        with tasks_lock:
            tasks[master_id]["log"].append(f"[{ts}] === all pipeline stages complete ===")
            tasks[master_id]["status"] = "done"
            tasks[master_id]["returncode"] = 0
            tasks[master_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
    threading.Thread(target=_seq, daemon=True).start()
    return master_id


# ============== routes ==============

def _spa_index():
    """Serve React SPA index.html when built; else fall back to legacy Jinja."""
    idx = UI_DIST / "index.html"
    if idx.is_file():
        return send_from_directory(UI_DIST, "index.html")
    return render_template(
        "index.html",
        stages=[s[0] for s in STAGES],
        stage_labels={s[0]: s[1] for s in STAGES},
        stage_details=STAGE_DETAILS,
    )


@app.route("/")
def index():
    return _spa_index()


@app.route("/legacy")
def legacy_ui():
    """Jinja UI retired — redirect to the RevAI Console."""
    return redirect("/", code=302)


@app.route("/assets/<path:filename>")
def spa_assets(filename):
    assets = UI_DIST / "assets"
    if not assets.is_dir():
        return jsonify({"error": "SPA not deployed"}), 404
    return send_from_directory(assets, filename)


@app.route("/api/samples")
def api_samples():
    return jsonify(list_samples())


@app.route("/api/json-presets")
def api_json_presets():
    """Preset queries for Raw Audit pane (V5.17)."""
    return jsonify(JSON_QUERY_PRESETS)


@app.route("/api/json-files/<sha>")
def api_json_files(sha):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""):
        return jsonify({"error": "invalid sha"}), 400
    return jsonify(list_json_artifacts(sha))


@app.route("/api/json-query/<sha>", methods=["POST"])
def api_json_query(sha):
    """Run a sandboxed dotted-path query against a stage JSON file (V5.17)."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""):
        return jsonify({"error": "invalid sha"}), 400
    data = request.get_json(force=True, silent=True) or {}
    rel = (data.get("path") or "").strip().replace("\\", "/")
    expr = (data.get("expr") or "").strip()
    if not rel or ".." in rel or rel.startswith("/"):
        return jsonify({"error": "invalid path"}), 400
    p = resolve_file_path(sha, rel)
    if not p or not p.exists():
        return jsonify({"error": f"file not found: {rel}"}), 404
    if p.suffix.lower() != ".json":
        return jsonify({"error": "only .json files supported"}), 400
    # Size cap ~25 MB
    if p.stat().st_size > 25 * 1024 * 1024:
        return jsonify({"error": "file too large (>25MB)"}), 413
    try:
        blob = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return jsonify({"error": f"json parse failed: {e}"}), 400
    try:
        result = _json_path_get(blob, expr)
    except Exception as e:
        return jsonify({"error": f"query failed: {e}"}), 400
    text = json.dumps(result, indent=2, default=str)
    # Truncate huge results for UI
    truncated = False
    if len(text) > 2_000_000:
        text = text[:2_000_000] + "\n… [truncated]"
        truncated = True
    return jsonify({
        "ok": True,
        "path": rel,
        "expr": expr,
        "truncated": truncated,
        "result": result if not truncated else None,
        "result_text": text,
        "keys": list(blob.keys())[:80] if isinstance(blob, dict) else [],
    })


@app.route("/api/pipeline-map")
def api_pipeline_map():
    """Describe the pipeline for the Console help/landing screens (SSoT: STAGES)."""
    cfg = load_config()
    return jsonify({
        "stages": [
            {
                "id": sid,
                "label": STAGE_INFO[sid][0],
                "script": Path(STAGE_INFO[sid][1]).name,
                "deps": STAGE_DEPS.get(sid, []),
                **(STAGE_DETAILS.get(sid) or {}),
            }
            for sid in STAGE_ORDER
        ],
        "gates": {
            "all_green": "audit_pipeline.py — every stage green in pipeline-audit.json",
            "quality_green": "report_quality.py — no deterministic fallbacks / narrative stubs",
            "truly_green": "all_green + quality_green + zero failed tools (the quality bar)",
        },
        "product_mode": cfg.get("product_mode") or DEFAULT_CONFIG["product_mode"],
        "planner_model": cfg.get("llm_model") or os.environ.get("REVAI_LLM_PLANNER_MODEL", ""),
        "dropbox": "/opt/samples/incoming/user-drop",
    })


@app.route("/api/browse")
def api_browse():
    return jsonify({"dirs": list_browser_dirs(), "upload": get_upload_instructions()})


def _settings_public(cfg: dict) -> dict:
    """LLM-only surface for SPA."""
    out = {k: cfg.get(k, DEFAULT_CONFIG.get(k, "")) for k in LLM_SETTINGS_KEYS}
    out["product_mode"] = cfg.get("product_mode") or DEFAULT_CONFIG["product_mode"]
    # Never echo API key to browser (mask if set)
    key = out.get("llm_api_key") or ""
    out["llm_api_key"] = ("***" if key and key != "***" else "") if key else ""
    out["llm_api_key_set"] = bool(key and key != "***")
    return out


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    """Return LLM settings for the SPA."""
    return jsonify(_settings_public(load_config()))


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    """Persist LLM settings only."""
    data = request.get_json(force=True, silent=True) or {}
    cfg = load_config()
    for key in LLM_SETTINGS_KEYS:
        if key not in data:
            continue
        if key == "llm_api_key":
            # P0.3: key goes to chmod-600 secrets file only, never pipeline-config.json
            if data[key] not in ("", "***"):
                _write_llm_key(str(data[key]).strip())
            continue
        cfg[key] = data[key]
    cfg["product_mode"] = DEFAULT_CONFIG["product_mode"]
    save_config(cfg)
    return jsonify({"ok": True, "config": _settings_public(load_config())})


@app.route("/api/status/<sha>")
def api_status(sha):
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    return jsonify(infer_pipeline_state(sha))


@app.route("/api/deps/<sha>")
def api_deps(sha):
    """Return stage dependency readiness for a sample."""
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    state = load_pipeline_state(sha)
    done = {
        s: ((state.get("stages") or {}).get(s) or {}).get("status") in ("done", "done-inferred")
        for s in STAGE_ORDER
    }
    out = {}
    for s in STAGE_ORDER:
        missing = [d for d in STAGE_DEPS[s] if not done.get(d)]
        out[s] = {"ready": not missing, "missing": missing, "done": done.get(s, False)}
    return jsonify(out)


@app.route("/api/task/<task_id>")
def api_task(task_id):
    with tasks_lock:
        t = tasks.get(task_id)
    if t:
        out = dict(t)
        # SPA expects log_tail; keep log for legacy compatibility
        log = list(out.get("log") or [])
        out["log_tail"] = log[-120:]
        return jsonify(out)
    return jsonify({"error": "task not found"}), 404


@app.route("/api/stage", methods=["POST"])
def api_stage():
    data = request.get_json(force=True, silent=True) or {}
    src = data.get("src_path", "").strip()
    family = data.get("family", "unknown").strip() or "unknown"
    if not src:
        return jsonify({"ok": False, "error": "src_path required"}), 400
    result = stage_sample(src, family=family)
    return jsonify(result) if result.get("ok") else (jsonify(result), 400)


@app.route("/api/run/<sha>/<stage>", methods=["POST"])
def api_run(sha, stage):
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    if stage not in STAGE_INFO:
        return jsonify({"error": f"unknown stage: {stage}"}), 400
    samples = list_samples()
    s = next((x for x in samples if x.get("sha256") == sha), None)
    if not s:
        return jsonify({"error": f"sample not found: {sha}"}), 404
    sample_path = s.get("sample_path", "")
    task_id = run_stage(sha, stage, sample_path)
    return jsonify({"task_id": task_id, "sha": sha, "stage": stage,
                    "command": build_stage_command(stage, sha, sample_path)})


@app.route("/api/run_all/<sha>", methods=["POST"])
def api_run_all(sha):
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    samples = list_samples()
    s = next((x for x in samples if x.get("sha256") == sha), None)
    if not s:
        return jsonify({"error": f"sample not found: {sha}"}), 404
    task_id = run_all_stages(sha, s.get("sample_path", ""))
    return jsonify({"task_id": task_id, "sha": sha})


@app.route("/api/reset/<sha>", methods=["POST"])
def api_reset(sha):
    """Delete all stage outputs and logs for a sample, but keep the staged
    corpus file and session.json so the user can re-run from scratch.
    """
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    samples = list_samples()
    s = next((x for x in samples if x.get("sha256") == sha), None)
    if not s:
        return jsonify({"error": f"sample not found: {sha}"}), 404

    deleted: list[str] = []
    errors: list[str] = []

    # Remove the per-sample logs directory (stage outputs, reports, stage.logs).
    logs_root = LOGS_DIR.resolve()
    log_dir = (LOGS_DIR / sha).resolve()
    try:
        log_dir.relative_to(logs_root)
    except ValueError:
        return jsonify({"error": "refusing reset outside logs root"}), 400
    if log_dir.exists() and log_dir != logs_root:
        try:
            shutil.rmtree(log_dir)
            deleted.append(str(log_dir))
        except Exception as e:
            errors.append(f"could not remove {log_dir}: {e}")

    # Remove the pipeline status file so the UI shows all stages as pending.
    status_path = get_status_path(sha)
    if status_path.exists():
        try:
            status_path.unlink()
            deleted.append(str(status_path))
        except Exception as e:
            errors.append(f"could not remove {status_path}: {e}")

    # Clear any in-memory task state for this sample.
    with tasks_lock:
        for tid in list(tasks):
            if tasks[tid].get("sha") == sha:
                tasks.pop(tid, None)

    return jsonify({
        "ok": True,
        "sha": sha,
        "deleted": deleted,
        "errors": errors,
        "kept_session": str(SESSIONS_DIR / f"{sha}.json"),
        "kept_corpus": s.get("sample_path", ""),
    })


def _evidence_tree(sha: str) -> list[dict]:
    """Full evidence file tree for a sample (logs + session.json)."""
    base = LOGS_DIR / sha
    tree = []
    sess = SESSIONS_DIR / f"{sha}.json"
    if sess.exists():
        tree.append({
            "path": "session.json",
            "size": sess.stat().st_size,
            "stage": "session",
            "ext": "json",
            "mtime": sess.stat().st_mtime,
        })
    if not base.exists():
        return tree
    for item in sorted(base.rglob("*")):
        if item.is_file() and not item.name.startswith("."):
            rel = item.relative_to(base)
            rel_s = str(rel).replace("\\", "/")
            ext = item.suffix.lstrip(".") or "txt"
            parts = rel.parts
            if len(parts) > 1:
                stage = parts[0]
            else:
                stage = ROOT_FILE_STAGE_MAP.get(item.name, "root")
            tree.append({
                "path": rel_s,
                "size": item.stat().st_size,
                "stage": stage,
                "ext": ext,
                "mtime": item.stat().st_mtime,
            })
    return tree


# Curated report catalog (product policy — not a frontend regex).
_REPORT_ROOT_EXACT = {
    "AUDIT-REPORT.md": "audit",
    "EVIDENCE-BUNDLE.md": "bundle",
    "verdict.json": "verdict",
}
_REPORT_ROOT_PREFIXES = (
    ("REPORT-MASTER-", "master"),
    ("REPORT-TECHNICAL-", "technical"),
    ("REPORT-v", "report"),
    ("REPORT-", "report"),
)
_REPORT_INTERNAL_HINTS = (
    "prompt", "llm-raw", "llm_raw",
    "scorecard", "00-tools", "01-llm", "04-prompt", "05-llm",
)


def curated_reports(sha: str, internals: bool = False) -> list[dict]:
    """Return analyst-facing publishables; prefer root copies over stage duplicates."""
    tree = _evidence_tree(sha)
    by_name: dict[str, dict] = {}
    for f in tree:
        path = f["path"]
        name = path.rsplit("/", 1)[-1]
        # Stage publishers may use 02-REPORT-MASTER-v3.md — canonicalize
        m = re.match(r"^\d+-(REPORT-.+)$", name, re.I)
        canon = m.group(1) if m else name
        # Prefer root (no slash) over nested publish/correlate copies
        is_root = "/" not in path
        kind = None
        if canon in _REPORT_ROOT_EXACT or name in _REPORT_ROOT_EXACT:
            kind = _REPORT_ROOT_EXACT.get(canon) or _REPORT_ROOT_EXACT.get(name)
        else:
            for pref, k in _REPORT_ROOT_PREFIXES:
                if (canon.startswith(pref) or name.startswith(pref)) and name.endswith((".md", ".json", ".html")):
                    kind = k
                    break
        if not kind:
            continue
        key = canon
        prev = by_name.get(key)
        if prev is None or (is_root and "/" in prev["path"]):
            by_name[key] = {**f, "curated": True, "kind": kind, "canon_name": canon}

    out = sorted(by_name.values(), key=lambda x: (x.get("kind") or "", x["path"]))
    if internals:
        extras = []
        for f in tree:
            path = f["path"].lower()
            if any(h in path for h in _REPORT_INTERNAL_HINTS) or path.startswith("publish/") or path.startswith("correlate/"):
                if f["path"] not in {x["path"] for x in out}:
                    extras.append({**f, "curated": False, "kind": "internal"})
        out.extend(sorted(extras, key=lambda x: x["path"]))
    return out


@app.route("/api/evidence/<sha>")
def api_evidence(sha):
    """Return the evidence file tree for a sample (logs + session.json)."""
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    return jsonify(_evidence_tree(sha))


@app.route("/api/artifacts/<sha>/reports")
def api_artifacts_reports(sha):
    """Curated report catalog for the RevAI Console (Reports mode)."""
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    internals = request.args.get("internals", "").lower() in ("1", "true", "yes")
    files = curated_reports(sha, internals=internals)
    return jsonify({"sha": sha, "mode": "reports", "internals": internals, "files": files})


@app.route("/api/file/<sha>")
def api_file(sha):
    """Serve raw file content as text/plain."""
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    rel_path = request.args.get("path", "")
    if not rel_path:
        return jsonify({"error": "path parameter required"}), 400
    p = resolve_file_path(sha, rel_path)
    if not p:
        return jsonify({"error": f"file not found: {rel_path}"}), 404
    size = p.stat().st_size
    if size > _FILE_READ_MAX:
        return jsonify({"error": f"file too large ({size} bytes); use download"}), 413
    return Response(p.read_text(errors="replace"), mimetype="text/plain")


@app.route("/api/download/<sha>")
def api_download(sha):
    """Download a file with its original filename as attachment."""
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    rel_path = request.args.get("path", "")
    if not rel_path:
        return jsonify({"error": "path parameter required"}), 400
    p = resolve_file_path(sha, rel_path)
    if not p:
        return jsonify({"error": f"file not found: {rel_path}"}), 404
    raw_name = request.args.get("name") or Path(rel_path).name
    safe = re.sub(r"[^\w.\-]+", "_", raw_name)[:180] or "download.bin"
    return Response(
        p.read_bytes(),
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe}"'},
    )


@app.route("/api/render/<sha>")
def api_render(sha):
    """Return rendered HTML for markdown or JSON files."""
    rel_path = request.args.get("path", "")
    rtype = request.args.get("type", "")
    if not rel_path:
        return jsonify({"error": "path parameter required"}), 400
    p = resolve_file_path(sha, rel_path)
    if not p:
        return jsonify({"error": f"file not found: {rel_path}"}), 404
    text = p.read_text(errors="replace")
    if rtype == "json":
        try:
            obj = json.loads(text)
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
        except Exception as e:
            return jsonify({"error": f"JSON parse error: {e}"}), 400
        return Response(pretty, mimetype="application/json")
    if rtype == "markdown":
        return Response(text, mimetype="text/markdown")
    return Response(text, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Ghidra write-back (rename / bookmark / rollback)
# ---------------------------------------------------------------------------

@app.route("/api/annotate/<sha>")
def api_annotate_pending(sha):
    """Return the LLM-proposed function annotations from deep-dive.json.

    The analyst reviews these and calls /api/annotate/<sha>/apply to
    commit them (with snapshot for rollback).
    """
    dd_path = LOGS_DIR / sha / "deep-dive.json"
    if not dd_path.exists():
        dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    if not dd_path.exists():
        return jsonify({"error": "deep-dive.json not found — run deep_dive first"}), 404
    try:
        dd = json.loads(dd_path.read_text())
    except json.JSONDecodeError:
        return jsonify({"error": "deep-dive.json is corrupted"}), 500

    annotations = dd.get("function_annotations") or []
    confidence = dd.get("confidence", 0)
    ghidra_result = dd.get("ghidra_annotations", {})

    # Also check if any snapshots exist for this sample
    snap_dir = LOGS_DIR / sha / "ghidra-snapshots"
    snapshots = []
    if snap_dir.exists():
        for d in sorted(snap_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if d.is_dir():
                snapshots.append({
                    "snapshot_id": d.name.split("__")[-1] if "__" in d.name else d.name,
                    "path": str(d),
                    "size_bytes": sum(f.stat().st_size for f in d.rglob("*") if f.is_file()),
                })

    return jsonify({
        "sha": sha,
        "confidence": confidence,
        "auto_applied": ghidra_result.get("applied", False) if isinstance(ghidra_result, dict) else False,
        "skip_reason": ghidra_result.get("reason", "") if isinstance(ghidra_result, dict) else "",
        "annotations": annotations,
        "annotation_count": len(annotations),
        "snapshots": snapshots[:10],
    })


@app.route("/api/annotate/<sha>/apply", methods=["POST"])
def api_annotate_apply(sha):
    """Apply LLM-suggested function renames + bookmarks to Ghidra.

    Reads the function_annotations from deep-dive.json (or from the
    request body if provided) and applies them via ghidra_sql_client.
    Always takes a snapshot first so the analyst can rollback.

    Optional JSON body:
      {"annotations": [{address, new_name, comment?}, ...]}
      If omitted, uses the annotations from deep-dive.json.
    """
    body = request.get_json(silent=True) or {}
    custom_annotations = body.get("annotations")

    if custom_annotations:
        annotations = custom_annotations
    else:
        dd_path = LOGS_DIR / sha / "deep-dive.json"
        if not dd_path.exists():
            dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
        if not dd_path.exists():
            return jsonify({"error": "deep-dive.json not found — run deep_dive first"}), 404
        dd = json.loads(dd_path.read_text())
        annotations = dd.get("function_annotations") or []

    if not annotations:
        return jsonify({"error": "no annotations to apply"}), 400

    try:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from ghidra_sql_client import get_ghidra_sql_client
        client = get_ghidra_sql_client()
        renames = [
            {"address": int(a["address"]), "new_name": str(a["new_name"])}
            for a in annotations
            if "address" in a and "new_name" in a
        ]
        bookmarks = [
            {"address": int(a["address"]),
             "category": "LLM (manual apply)",
             "type": "Analysis",
             "comment": str(a.get("comment") or f"renamed to {a['new_name']}")}
            for a in annotations
            if "address" in a
        ]
        result = client.apply_pending(
            sha,
            {"renames": renames, "bookmarks": bookmarks},
            snapshot=True,
            dry_run=False,
        )
        return jsonify({
            "ok": result["ok"],
            "renames_applied": len([r for r in result.get("applied", []) if r.get("ok")]),
            "renames_failed": len(result.get("failed", [])),
            "snapshot": result.get("snapshot", {}).get("snapshot_id"),
            "failed_details": result.get("failed", [])[:5],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/annotate/<sha>/rollback", methods=["POST"])
def api_annotate_rollback(sha):
    """Rollback the most recent Ghidra annotation (restore from snapshot).

    Optional JSON body: {"snapshot_id": "2026-07-03T16-23-54__annotate"}
    If omitted, uses the most recent snapshot.
    """
    body = request.get_json(silent=True) or {}
    snapshot_id = body.get("snapshot_id")

    try:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from ghidra_sql_client import get_ghidra_sql_client
        client = get_ghidra_sql_client()
        result = client.rollback(sha, snapshot_id=snapshot_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# IDA write-back (rename / bookmark / comment / rollback) — local idasql
# ---------------------------------------------------------------------------

@app.route("/api/ida-annotate/<sha>")
def api_ida_annotate_pending(sha):
    """Return the LLM-proposed function annotations for IDA review.

    The IDA pathway runs locally on Remnux via idasql (no SSH).
    """
    dd_path = LOGS_DIR / sha / "deep-dive.json"
    if not dd_path.exists():
        dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    if not dd_path.exists():
        return jsonify({"error": "deep-dive.json not found - run deep_dive first"}), 404
    try:
        dd = json.loads(dd_path.read_text())
    except json.JSONDecodeError:
        return jsonify({"error": "deep-dive.json is corrupted"}), 500

    annotations = dd.get("function_annotations") or []
    ida_result = dd.get("ida_annotations", {})

    # List IDA snapshots
    snap_dir = LOGS_DIR / sha / "ida-snapshots"
    snapshots = []
    if snap_dir.exists():
        for d in sorted(snap_dir.iterdir(),
                         key=lambda p: p.stat().st_mtime, reverse=True):
            if d.is_dir():
                snapshots.append({
                    "snapshot_id": d.name,
                    "path": str(d),
                    "size_bytes": sum(
                        f.stat().st_size for f in d.rglob("*")
                        if f.is_file()),
                })

    return jsonify({
        "sha": sha,
        "annotations": annotations,
        "annotation_count": len(annotations),
        "ida_annotations_status": ida_result,
        "snapshots": snapshots[:10],
    })


@app.route("/api/ida-annotate/<sha>/apply", methods=["POST"])
def api_ida_annotate_apply(sha):
    """Apply LLM-suggested renames + bookmarks to IDA locally.

    Reads function_annotations from deep-dive.json (or from the
    request body if provided) and applies them via ida_sql_client.
    Always takes a snapshot first so the analyst can rollback.
    """
    body = request.get_json(silent=True) or {}
    custom_annotations = body.get("annotations")

    if custom_annotations:
        annotations = custom_annotations
    else:
        dd_path = LOGS_DIR / sha / "deep-dive.json"
        if not dd_path.exists():
            dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
        if not dd_path.exists():
            return jsonify({"error": "deep-dive.json not found"}), 404
        dd = json.loads(dd_path.read_text())
        annotations = dd.get("function_annotations") or []

    if not annotations:
        return jsonify({"error": "no annotations to apply"}), 400

    try:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from ida_sql_client import get_ida_sql_client
        client = get_ida_sql_client()
        renames = [
            {"address": int(a["address"]),
             "new_name": str(a["new_name"])}
            for a in annotations
            if "address" in a and "new_name" in a
        ]
        bookmarks = [
            {"address": int(a["address"]),
             "comment": str(a.get("comment") or f"renamed to {a.get('new_name', '?')}")}
            for a in annotations
            if "address" in a
        ]
        result = client.apply_pending(
            sha,
            {"renames": renames, "bookmarks": bookmarks},
            snapshot=True,
            dry_run=False,
        )
        return jsonify({
            "ok": result["ok"],
            "engine": "ida",
            "renames_applied": len([
                r for r in result.get("applied", []) if r.get("ok")
            ]),
            "renames_failed": len(result.get("failed", [])),
            "snapshot": result.get("snapshot", {}).get("snapshot_id"),
            "failed_details": result.get("failed", [])[:5],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ida-annotate/<sha>/rollback", methods=["POST"])
def api_ida_annotate_rollback(sha):
    """Restore IDA from a snapshot (local idasql).

    Optional JSON body: {"snapshot_id": "2026-07-04T00-31-32__ida-annotate"}
    If omitted, uses the most recent snapshot.
    """
    body = request.get_json(silent=True) or {}
    snapshot_id = body.get("snapshot_id")

    try:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from ida_sql_client import get_ida_sql_client
        client = get_ida_sql_client()
        result = client.rollback(sha, snapshot_id=snapshot_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# HITL #2 (manual approval of low-confidence annotations) + HITL #3
# (critical-impact findings). Pairs with the hitl modules.
# ---------------------------------------------------------------------------

# Mirror of hitl-2-confidence.py threshold. Keep in sync.
HITL_2_CONFIDENCE_THRESHOLD = 50
# Critical-impact tags (HITL #3 cross-reference).
CRITICAL_IMPACT_TAGS = {
    "airplane_safety", "medical_device", "industrial_control", "nuclear",
    "ransomware_active", "lateral_movement", "credential_dump",
}


def _collect_pending_annotations(annotations: list[dict]) -> list[dict]:
    """Return annotations that need human review (low confidence or critical).

    Returns REFERENCES to the original dicts (not copies) so the
    approve/reject endpoints can mutate them in-place before writing
    the file back.
    """
    pending = []
    for ann in annotations:
        if not isinstance(ann, dict):
            continue
        conf = int(ann.get("confidence") or 100)
        status = ann.get("hitl_status", "pending")
        tags = set(ann.get("tags") or [])
        hitl_required = conf < HITL_2_CONFIDENCE_THRESHOLD or bool(tags & CRITICAL_IMPACT_TAGS)
        if hitl_required and status == "pending":
            pending.append(ann)
    return pending


@app.route("/api/hitl/<sha>/pending", methods=["GET"])
def api_hitl_pending(sha):
    """Return pending (low-confidence or critical) annotations from deep-dive.json.

    Annotations that already passed auto-apply (confidence >= 90) are
    excluded — they're already in Ghidra/IDA. This endpoint is for
    HITL review: the analyst sees what NEEDS review, not what's done.
    """
    dd_path = LOGS_DIR / sha / "deep-dive.json"
    if not dd_path.exists():
        dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    if not dd_path.exists():
        return jsonify({"error": "deep-dive.json not found", "pending": []}), 404
    try:
        dd = json.loads(dd_path.read_text())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    annotations = dd.get("function_annotations") or []
    pending = _collect_pending_annotations(annotations)
    return jsonify({
        "sha": sha,
        "deep_dive": str(dd_path),
        "overall_confidence": dd.get("confidence", 0),
        "hitl_threshold": HITL_2_CONFIDENCE_THRESHOLD,
        "annotation_count": len(annotations),
        "pending_count": len(pending),
        "pending": pending,
    })


@app.route("/api/hitl/<sha>/approve", methods=["POST"])
def api_hitl_approve(sha):
    """Approve a pending annotation: mark hitl_status=approved and apply to Ghidra+IDA.

    Optional JSON body: {"address": int, "new_name": str, "comment": str, "reviewer": str}
    If omitted, approves all pending annotations.
    """
    body = request.get_json(silent=True) or {}
    reviewer = body.get("reviewer", "manual")
    target_addr = body.get("address")
    dd_path = LOGS_DIR / sha / "deep-dive.json"
    if not dd_path.exists():
        dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    if not dd_path.exists():
        return jsonify({"error": "deep-dive.json not found"}), 404
    dd = json.loads(dd_path.read_text())
    annotations = dd.get("function_annotations") or []
    pending = _collect_pending_annotations(annotations)
    to_approve = pending
    if target_addr is not None:
        to_approve = [a for a in pending if a.get("address") == target_addr]
    if not to_approve:
        return jsonify({"error": "no matching pending annotations", "approved": []}), 400
    # Mark as approved
    import time
    for a in to_approve:
        a["hitl_status"] = "approved"
        a["hitl_reviewer"] = reviewer
        a["hitl_ts"] = time.time()
    dd_path.write_text(json.dumps(dd, indent=2, default=str))
    # Apply to Ghidra + IDA (reuse the existing apply endpoints)
    renames = [{"address": int(a["address"]),
                "new_name": str(a["new_name"])}
               for a in to_approve if "address" in a and "new_name" in a]
    bookmarks = [{"address": int(a["address"]),
                  "category": "HITL-approved",
                  "type": "Analysis",
                  "comment": f"HITL approved by {reviewer}: {a.get('new_name', '?')}"}
                 for a in to_approve if "address" in a]
    ghidra_result = {"skipped": True, "reason": "no renames to apply"}
    ida_result = {"skipped": True, "reason": "no renames to apply"}
    if renames:
        try:
            from ghidra_sql_client import get_ghidra_sql_client
            gh = get_ghidra_sql_client()
            gh_apply = gh.apply_pending(sha, {"renames": renames, "bookmarks": bookmarks},
                                        snapshot=True, dry_run=False)
            ghidra_result = {"applied": True, "engine": "ghidra", "ok": gh_apply.get("ok")}
        except Exception as e:
            ghidra_result = {"applied": False, "engine": "ghidra", "error": str(e)}
        try:
            from ida_sql_client import get_ida_sql_client
            ida = get_ida_sql_client()
            ida_apply = ida.apply_pending(sha, {"renames": renames, "bookmarks": bookmarks},
                                          snapshot=True, dry_run=False)
            ida_result = {"applied": True, "engine": "ida", "ok": ida_apply.get("ok")}
        except Exception as e:
            ida_result = {"applied": False, "engine": "ida", "error": str(e)}
    return jsonify({
        "approved_count": len(to_approve),
        "ghidra": ghidra_result,
        "ida": ida_result,
    })


@app.route("/api/hitl/<sha>/reject", methods=["POST"])
def api_hitl_reject(sha):
    """Reject a pending annotation: mark hitl_status=rejected (do NOT apply).

    Optional JSON body: {"address": int, "reason": str, "reviewer": str}
    If address is omitted, rejects all pending annotations.
    """
    body = request.get_json(silent=True) or {}
    reviewer = body.get("reviewer", "manual")
    reason = body.get("reason", "rejected by reviewer")
    target_addr = body.get("address")
    dd_path = LOGS_DIR / sha / "deep-dive.json"
    if not dd_path.exists():
        dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    if not dd_path.exists():
        return jsonify({"error": "deep-dive.json not found"}), 404
    dd = json.loads(dd_path.read_text())
    annotations = dd.get("function_annotations") or []
    pending = _collect_pending_annotations(annotations)
    to_reject = pending
    if target_addr is not None:
        to_reject = [a for a in pending if a.get("address") == target_addr]
    if not to_reject:
        return jsonify({"error": "no matching pending annotations", "rejected": []}), 400
    import time
    for a in to_reject:
        a["hitl_status"] = "rejected"
        a["hitl_reviewer"] = reviewer
        a["hitl_ts"] = time.time()
        a["hitl_reject_reason"] = reason
    dd_path.write_text(json.dumps(dd, indent=2, default=str))
    return jsonify({"rejected_count": len(to_reject)})


# --- Orchestration Cockpit (LangGraph stage_orchestrator) ---

ORCH_TOOL_TO_STAGE = {
    "run_intake": "intake",
    "run_quick_scan": "quick_scan",
    "run_deep_dive_agentic": "deep_dive",
    "run_yara_gen": "yara_gen",
    "run_publish": "publish",
    "run_section_publish": "correlate",
    "run_audit": "audit",
}

_orch_procs: dict[str, subprocess.Popen] = {}
_orch_procs_lock = threading.Lock()


def _tail_file(path: Path, max_lines: int = 200) -> list[str]:
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-max_lines:]
    except Exception:
        return []


def _orch_marker_lines(path: Path) -> list[str]:
    """Scan full orchestrator.log for progress markers (publish stdout is huge)."""
    if not path.is_file():
        return []
    markers: list[str] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.rstrip("\n")
                if (
                    s.startswith("=====")
                    or "[orchestrator] TOOL " in s
                    or ("[orchestrator] " in s and " rc=" in s)
                    or "check_quality ok=" in s
                    or "truly_green=" in s
                ):
                    markers.append(s)
    except Exception:
        return []
    return markers


def _parse_orch_progress(log_lines: list[str]) -> dict:
    """Derive current/completed tools from orchestrator.log lines.

    Supports both formats:
      stdout: [orchestrator] TOOL run_quick_scan: ...
               [orchestrator] run_quick_scan rc=0 12s
      file:   ===== 2026-07-24T04:20:54Z run_intake CMD ...
               ===== rc=0
    """
    tools: list[dict] = []
    current = None
    for line in log_lines:
        if "[orchestrator] TOOL " in line:
            m = re.search(r"TOOL\s+(\S+):", line)
            if m:
                name = m.group(1)
                current = {"tool": name, "stage": ORCH_TOOL_TO_STAGE.get(name), "status": "running"}
                tools.append(current)
        elif re.search(r"=====\s+\S+\s+(run_\w+|check_quality)\s+CMD\b", line):
            m = re.search(r"=====\s+\S+\s+(run_\w+|check_quality)\s+CMD\b", line)
            name = m.group(1)
            current = {"tool": name, "stage": ORCH_TOOL_TO_STAGE.get(name), "status": "running"}
            tools.append(current)
        elif "[orchestrator] " in line and " rc=" in line:
            m = re.search(r"\[orchestrator\]\s+(\S+)\s+rc=(\-?\d+)", line)
            if m:
                name, rc = m.group(1), int(m.group(2))
                for t in reversed(tools):
                    if t["tool"] == name and t.get("status") == "running":
                        t["status"] = "done" if rc == 0 else "error"
                        t["rc"] = rc
                        break
                if current and current.get("tool") == name:
                    current = None
        elif re.match(r"=====\s+rc=(\-?\d+)\s*$", line.strip()):
            m = re.match(r"=====\s+rc=(\-?\d+)\s*$", line.strip())
            rc = int(m.group(1))
            if current and current.get("status") == "running":
                current["status"] = "done" if rc == 0 else "error"
                current["rc"] = rc
                current = None
            else:
                for t in reversed(tools):
                    if t.get("status") == "running":
                        t["status"] = "done" if rc == 0 else "error"
                        t["rc"] = rc
                        break
        elif "===== TIMEOUT" in line:
            if current and current.get("status") == "running":
                current["status"] = "error"
                current["rc"] = -1
                current["detail"] = "TIMEOUT"
                current = None
        elif "check_quality ok=" in line:
            m = re.search(r"check_quality ok=(\w+)", line)
            tools.append({
                "tool": "check_quality",
                "stage": None,
                "status": "done" if m and m.group(1) == "True" else "error",
                "detail": line.strip()[-200:],
            })
            current = None
        elif "truly_green=" in line:
            tools.append({"tool": "finalize", "status": "done", "detail": line.strip()[-240:]})
    running = next((t for t in reversed(tools) if t.get("status") == "running"), None)
    return {"tools": tools, "current": running}


def _load_json_safe(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _sync_pipeline_from_orch(sha: str, progress: dict) -> None:
    """Update pipeline-status.json so existing Pipeline tab reflects orch progress."""
    state = load_pipeline_state(sha)
    stages = state.setdefault("stages", {})
    for t in progress.get("tools") or []:
        stage = t.get("stage")
        if not stage:
            continue
        st = t.get("status")
        if st == "running":
            stages[stage] = {
                **(stages.get(stage) or {}),
                "status": "running",
                "via": "orchestrator",
            }
        elif st == "done":
            stages[stage] = {
                **(stages.get(stage) or {}),
                "status": "done",
                "returncode": t.get("rc", 0),
                "via": "orchestrator",
            }
        elif st == "error":
            stages[stage] = {
                **(stages.get(stage) or {}),
                "status": "error",
                "returncode": t.get("rc", 1),
                "via": "orchestrator",
            }
    save_pipeline_state(sha, state)


def orch_live_payload(sha: str) -> dict:
    sha_ok = require_sha(sha)
    if not sha_ok:
        return {"error": "invalid sha", "running": False}
    sha = sha_ok
    root = LOGS_DIR / sha
    log_path = root / "orchestrator.log"
    log_lines = _tail_file(log_path, 400)
    progress = _parse_orch_progress(_orch_marker_lines(log_path) or log_lines)
    if progress.get("tools"):
        try:
            _sync_pipeline_from_orch(sha, progress)
        except Exception:
            pass
    trace = _load_json_safe(root / "orchestrator_trace.json")
    quality = _load_json_safe(root / "quality-gate.json")
    audit = _load_json_safe(root / "pipeline-audit.json")
    deep = _load_json_safe(root / "deep_dive" / "agentic_deep_dive.json")
    with _orch_procs_lock:
        proc = _orch_procs.get(sha)
        running_flask = bool(proc and proc.poll() is None)
    # Detect CLI-started orch — require explicit --sha <full>
    cli_running = False
    try:
        ps = subprocess.run(
            ["pgrep", "-af", "stage_orchestrator"],
            capture_output=True, text=True, timeout=5,
        )
        needle = f"--sha {sha}"
        for line in (ps.stdout or "").splitlines():
            if "python" not in line or "stage_orchestrator" not in line:
                continue
            if needle in line or f"--sha\t{sha}" in line:
                cli_running = True
                break
    except Exception:
        pass
    running = running_flask or cli_running
    if not running and trace.get("truly_green") is not None:
        status = "done" if trace.get("truly_green") else "error"
    elif running:
        status = "running"
    elif log_path.is_file():
        status = "idle"
    else:
        status = "none"
    # Flask task buffer (stdout) — useful before orchestrator.log exists / for live console
    task_id = None
    task_log_tail: list[str] = []
    task_status = None
    with tasks_lock:
        for tid, t in tasks.items():
            if t.get("kind") != "orchestrator":
                continue
            if t.get("sha") not in (sha, "pending", "pending_orch"):
                continue
            if t.get("status") == "running" or task_id is None:
                task_id = tid
                task_status = t.get("status")
                task_log_tail = list(t.get("log") or [])[-120:]
                if t.get("status") == "running":
                    break
    cur = progress.get("current")
    current_tool = None
    current_stage = None
    if isinstance(cur, dict):
        current_tool = cur.get("tool")
        current_stage = cur.get("stage") or ORCH_TOOL_TO_STAGE.get(str(current_tool or ""))
    elif isinstance(cur, str):
        current_tool = cur
        current_stage = ORCH_TOOL_TO_STAGE.get(cur)
    return {
        "sha": sha,
        "status": status,
        "running": running,
        # String tool name for SPA lights; keep object for legacy/detail
        "current": current_tool,
        "current_tool": current_tool,
        "current_stage": current_stage,
        "current_detail": cur if isinstance(cur, dict) else None,
        "tools": progress.get("tools") or [],
        "log_tail": log_lines[-120:],
        "task_id": task_id,
        "task_status": task_status,
        "task_log_tail": task_log_tail,
        "truly_green": trace.get("truly_green"),
        "quality_green": trace.get("quality_green") if trace else quality.get("quality_green"),
        "all_green": audit.get("all_green"),
        "quality_issues": quality.get("issues") or [],
        "quality_checks": quality.get("checks") or {},
        "planner_model": trace.get("planner_model"),
        "judgment_model": trace.get("judgment_model"),
        "deep": {
            "checklist_ok": deep.get("checklist_ok"),
            "sql_deep_ok": deep.get("sql_deep_ok"),
            "successful_tool_calls": deep.get("successful_tool_calls"),
            "verdict": deep.get("verdict"),
            "engine": deep.get("engine") or deep.get("agentic_engine"),
        } if deep else {},
        "stages_run": trace.get("stages_run") or [],
        "elapsed_s": trace.get("elapsed_s"),
        "artifacts": {
            "orchestrator_log": log_path.is_file(),
            "orchestrator_trace": (root / "orchestrator_trace.json").is_file(),
            "quality_gate": (root / "quality-gate.json").is_file(),
            "pipeline_audit": (root / "pipeline-audit.json").is_file(),
        },
    }


def start_orchestrator(sha: str | None, sample_path: str | None) -> dict:
    """Start stage_orchestrator as a tracked Flask task."""
    if sample_path:
        sample_path = str(Path(sample_path).resolve())
        if not Path(sample_path).is_file():
            return {"ok": False, "error": f"sample not found: {sample_path}"}
        cmd = [
            "python3", str(SCRIPTS_DIR / "stage_orchestrator.py"), sample_path,
        ]
        # SHA known after intake; use placeholder until we can read logs
        track_sha = sha or "pending"
    elif sha:
        cmd = [
            "python3", str(SCRIPTS_DIR / "stage_orchestrator.py"), "--sha", sha,
        ]
        track_sha = sha
    else:
        return {"ok": False, "error": "need sha or sample_path"}

    # Kill prior flask-managed orch for same sha
    with _orch_procs_lock:
        old = _orch_procs.get(track_sha)
        if old and old.poll() is None:
            try:
                old.kill()
            except Exception:
                pass

    task_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    env = {**os.environ, **get_stage_env()}
    env["REVAI_AGENTIC_ENGINE"] = "langgraph"

    log_dir = LOGS_DIR / (sha or "pending_orch")
    if sha:
        log_dir = LOGS_DIR / sha
        log_dir.mkdir(parents=True, exist_ok=True)

    with tasks_lock:
        tasks[task_id] = {
            "task_id": task_id,
            "sha": track_sha,
            "stage": "orchestrator",
            "status": "running",
            "started_at": now,
            "finished_at": None,
            "returncode": None,
            "command": " ".join(cmd),
            "log": [f"[{now}] $ {' '.join(cmd)}"],
            "kind": "orchestrator",
        }

    def _run():
        proc = None
        resolved_sha = sha
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                cwd="/opt/scripts",
                env=env,
            )
            with _orch_procs_lock:
                _orch_procs[track_sha] = proc
                if sha:
                    _orch_procs[sha] = proc
            # Stream stdout to Flask task log only.
            # stage_orchestrator writes its own logs/<sha>/orchestrator.log — do not duplicate.
            for chunk in iter(proc.stdout.readline, b""):
                if not chunk:
                    continue
                line = chunk.decode("utf-8", errors="replace").rstrip()
                ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                tagged = f"[{ts}] {line}"
                if not resolved_sha:
                    m = re.search(r"SHA256:\s*([a-f0-9]{64})", line)
                    if not m:
                        m = re.search(r"/([a-f0-9]{64})/", line)
                    if not m:
                        m = re.search(r"--sha\s+([a-f0-9]{64})", line)
                    if m:
                        resolved_sha = m.group(1)
                        with tasks_lock:
                            tasks[task_id]["sha"] = resolved_sha
                        with _orch_procs_lock:
                            _orch_procs[resolved_sha] = proc
                with tasks_lock:
                    tasks[task_id]["log"].append(tagged)
                    if len(tasks[task_id]["log"]) > 4000:
                        tasks[task_id]["log"] = tasks[task_id]["log"][-4000:]
            rc = proc.wait()
        except Exception as e:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            with tasks_lock:
                tasks[task_id]["log"].append(f"[{ts}] EXCEPTION: {e}")
            rc = -1
        now2 = datetime.now(timezone.utc).isoformat()
        with tasks_lock:
            tasks[task_id]["status"] = "done" if rc == 0 else "error"
            tasks[task_id]["returncode"] = rc
            tasks[task_id]["finished_at"] = now2
            if resolved_sha:
                tasks[task_id]["sha"] = resolved_sha
        with _orch_procs_lock:
            for k, v in list(_orch_procs.items()):
                if v is proc:
                    _orch_procs.pop(k, None)

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "task_id": task_id, "sha": track_sha, "command": " ".join(cmd)}


@app.route("/api/orch/start", methods=["POST"])
def api_orch_start():
    data = request.get_json(force=True, silent=True) or {}
    sha = (data.get("sha") or "").strip() or None
    sample_path = (data.get("sample_path") or "").strip() or None
    if sha and (SESSIONS_DIR / f"{sha}.json").exists() and not data.get("force_intake"):
        # Resume existing session via --sha
        result = start_orchestrator(sha, None)
    else:
        if not sample_path and sha:
            samples = list_samples()
            s = next((x for x in samples if x.get("sha256") == sha), None)
            if s:
                sample_path = s.get("sample_path") or None
        if sample_path and not stage_path_allowed(sample_path):
            allowed = ", ".join(str(r) for r in STAGE_ALLOWED_ROOTS)
            return jsonify({"ok": False,
                            "error": f"sample_path outside allowed staging roots ({allowed})"}), 400
        result = start_orchestrator(sha, sample_path)
    return jsonify(result) if result.get("ok") else (jsonify(result), 400)


@app.route("/api/orch/<sha>/stop", methods=["POST"])
def api_orch_stop(sha):
    sha = require_sha(sha)
    if not sha:
        return jsonify({"ok": False, "error": "invalid sha"}), 400
    killed = []
    with _orch_procs_lock:
        proc = _orch_procs.get(sha)
        if proc and proc.poll() is None:
            try:
                proc.kill()
                killed.append("flask_child")
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500
    # Best-effort CLI kill — only exact --sha match
    try:
        ps = subprocess.run(["pgrep", "-af", "stage_orchestrator"], capture_output=True, text=True, timeout=5)
        needle = f"--sha {sha}"
        for line in (ps.stdout or "").splitlines():
            if needle not in line and f"--sha\t{sha}" not in line:
                continue
            pid = line.strip().split()[0]
            if pid.isdigit():
                subprocess.run(["kill", pid], timeout=5)
                killed.append(pid)
    except Exception:
        pass
    return jsonify({"ok": True, "killed": killed, "sha": sha})


@app.route("/api/orch/<sha>/live")
def api_orch_live(sha):
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    return jsonify(orch_live_payload(sha))


@app.route("/api/orch/<sha>/trace")
def api_orch_trace(sha):
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    p = LOGS_DIR / sha / "orchestrator_trace.json"
    if not p.is_file():
        return jsonify({"error": "no orchestrator_trace.json"}), 404
    return jsonify(_load_json_safe(p))


@app.route("/api/quality/<sha>")
def api_quality(sha):
    sha = require_sha(sha)
    if not sha:
        return jsonify({"error": "invalid sha"}), 400
    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        from report_quality import evaluate_sha_publish_quality
        q = evaluate_sha_publish_quality(LOGS_DIR, sha)
    except Exception as e:
        q = {"ok": False, "error": str(e)}
    deep = _load_json_safe(LOGS_DIR / sha / "deep_dive" / "agentic_deep_dive.json")
    q["deep_checklist_ok"] = deep.get("checklist_ok")
    q["deep_sql_deep_ok"] = deep.get("sql_deep_ok")
    q["deep_tool_calls"] = deep.get("successful_tool_calls")
    return jsonify(q)


@app.route("/api/orch/active")
def api_orch_active():
    """List running orchestrators (Flask-managed or CLI)."""
    active = []
    with _orch_procs_lock:
        for sha, proc in list(_orch_procs.items()):
            if proc.poll() is None and require_sha(sha):
                active.append({"sha": sha, "pid": proc.pid, "source": "flask"})
    try:
        ps = subprocess.run(["pgrep", "-af", "stage_orchestrator"], capture_output=True, text=True, timeout=5)
        for line in (ps.stdout or "").splitlines():
            if "python" not in line:
                continue
            m = re.search(r"--sha\s+([a-fA-F0-9]{64})", line)
            if not m:
                continue
            sha = m.group(1).lower()
            pid = line.strip().split()[0]
            if pid.isdigit():
                active.append({"sha": sha, "pid": int(pid), "source": "cli", "cmd": line[:200]})
    except Exception:
        pass
    return jsonify({"active": active})


# --- HITL #3 (critical findings) ---

@app.route("/api/hitl/<sha>/critical", methods=["GET"])
def api_hitl_critical(sha):
    """Return critical findings (HITL #3) from deep-dive.json.

    A finding is critical if:
    - It has a critical-impact tag (ransomware_active, lateral_movement, etc.)
    - OR its name/comment contains a critical keyword
    - OR the LLM summary mentions critical malware capabilities
    """
    dd_path = LOGS_DIR / sha / "deep-dive.json"
    if not dd_path.exists():
        dd_path = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
    if not dd_path.exists():
        return jsonify({"error": "deep-dive.json not found", "critical": []}), 404
    try:
        dd = json.loads(dd_path.read_text())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    sys.path.insert(0, str(SCRIPTS_DIR))
    sys.path.insert(0, "/opt/revai")
    # hitl-3-critical.py has hyphens; import via importlib from the RevAI home.
    import importlib.util
    _hitl_path = "/opt/revai/hitl/hitl-3-critical.py"
    spec = importlib.util.spec_from_file_location("hitl_3_critical", _hitl_path)
    if spec is None or spec.loader is None:
        return jsonify({"error": "failed to load hitl-3-critical.py"}), 500
    hitl3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hitl3)
    annotations = dd.get("function_annotations") or []
    flagged = hitl3.collect_critical_annotations(annotations)
    summary = dd.get("summary", "")
    summary_kws = hitl3.find_critical_keywords(summary)
    return jsonify({
        "sha": sha,
        "deep_dive": str(dd_path),
        "summary_critical_keywords": summary_kws,
        "annotation_count": len(annotations),
        "critical_count": len(flagged),
        "critical": flagged,
    })


@app.route("/favicon.svg")
@app.route("/favicon.ico")
def spa_favicon():
    for name in ("favicon.svg", "favicon.ico"):
        p = UI_DIST / name
        if p.is_file():
            return send_from_directory(UI_DIST, name)
    return ("", 204)


@app.route("/<path:path>")
def spa_catch_all(path: str):
    """Client-side routes → index.html. Never shadow /api/*."""
    if path.startswith("api/") or path == "api":
        return jsonify({"error": "not found"}), 404
    if path == "legacy":
        return legacy_ui()
    # Prefer real files from dist (e.g. vite.svg)
    candidate = (UI_DIST / path).resolve()
    try:
        candidate.relative_to(UI_DIST.resolve())
    except ValueError:
        return _spa_index()
    if candidate.is_file():
        return send_from_directory(UI_DIST, path)
    return _spa_index()


if __name__ == "__main__":
    import socket
    _hostname = socket.gethostname()
    _local_ip = socket.gethostbyname(_hostname)
    print("=== CADRE-RevAI Pipeline UI ===")
    print("  Listening on 0.0.0.0:5000")
    print(f"  SPA dist: {UI_DIST} (exists={ (UI_DIST / 'index.html').is_file() })")
    print(f"  Open http://{_local_ip}:5000 in browser")
    print(f"  Legacy Jinja: http://{_local_ip}:5000/legacy")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
