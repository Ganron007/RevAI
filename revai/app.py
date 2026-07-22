"""app.py — professional web UI for the CADRE-RevEng malware pipeline.

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

from flask import Flask, jsonify, render_template, request, Response

SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")
SCRIPTS_DIR = Path("/opt/scripts")
CONFIG_PATH = Path("/opt/samples/pipeline-config.json")

# Hard timeout for any single stage in the Flask UI.  The deep-analysis
# stages can take 1–2 hours on large samples, so cap at 4 hours.
STAGE_TIMEOUT_S = int(os.environ.get("STAGE_TIMEOUT_S", "14400"))

DEFAULT_CONFIG = {
    "remote_embed_url": "http://192.168.77.1:8000",
    "reranker_url": "http://192.168.77.1:8000",
    "use_rag": False,  # V6.1 live default = LLM-only; opt-in for lab/article
    "use_reranker": False,
    "use_hybrid": True,
    "use_ann": False,
    # LLM backend is configured by the user at runtime (env or UI settings).
    # No hardcoded model, API key, endpoint, or reasoning level in code.
    "llm_model": "",
    "llm_api_url": "",
    "llm_api_key": "",
    "llm_reasoning": "",
}

# V6.3/V6.4 — Single-mode spine (agentic deep for all sizes).
# Full CLI control plane: pipeline_single_v63.py (optional --dynamic).
STAGES = [
    ("intake",     "intake",     str(SCRIPTS_DIR / "intake_v2.py"),        []),
    ("quick_scan", "quick_scan", str(SCRIPTS_DIR / "quick_scan_v2.py"),   []),
    ("deep_dive",  "deep_dive",  str(SCRIPTS_DIR / "deep_dive_agentic.py"), []),
    ("dynamic",    "dynamic",    str(SCRIPTS_DIR / "dynamic_run_v2.py"),  ["--max-seconds", "45"]),
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
    "dynamic": ["deep_dive"],  # optional; UI can run without requiring for publish
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
        "long_desc": "Executes MalCat, capa, YARA, FLOSS, dotnet, r2, upx, xorsearch, olevba and peepdf in parallel. Assembles signal-prioritized evidence cards, queries the local bge-m3 RAG index (35K records), and asks DeepSeek for a triage verdict.",
        "artifacts": ["00-tools-raw.json", "01-sql-evidence.json", "02-prompt.txt", "03-llm-raw.json", "04-verdict.json"],
        "dir": "quick_scan",
    },
    "deep_dive": {
        "num": 3, "title": "Deep Dive (agentic)",
        "desc": "V6.3 single mode — LangGraph/agentic deep RE for all samples",
        "long_desc": (
            "Always runs deep_dive_agentic.py (SQL-first checklist + agent loop). "
            "Size-based standard/large deep fork removed in V6.3. "
            "Full spine CLI: pipeline_single_v63.py [--dynamic]."
        ),
        "artifacts": [
            "00-sql-evidence.json", "01-tools-raw.json", "02-cff-findings.json",
            "03-prompt.txt", "04-llm-raw.json", "05-deep-dive.json",
            "agentic_deep_dive.json",
        ],
        "dir": "deep_dive",
    },
    "dynamic": {
        "num": 4, "title": "Dynamic (Flare)",
        "desc": "Optional Flare-VM Frida detonation → logs/<sha>/dynamic/",
        "long_desc": (
            "Remnux orchestrates; Flare .42 detonates via SSH+Frida. "
            "Corroboration only — cannot clear high-signal YARA (V6.2.6)."
        ),
        "artifacts": ["META.json", "frida_trace.json", "network.json"],
        "dir": "dynamic",
    },
    "yara_gen": {
        "num": 5, "title": "YARA Gen",
        "desc": "Generate YARA + Sigma detection rules",
        "long_desc": "Collects strings from Ghidra/IDA, verdict IOCs, and hex signatures, then builds a YARA rule and a Sigma rule. Optionally validates the YARA rule against the sample.",
        "artifacts": ["rule.yar", "rule.yara.json", "rule.yml"],
        "dir": None,
    },
    "publish": {
        "num": 6, "title": "Publish",
        "desc": "Generate REPORT-MASTER v2 from all evidence",
        "long_desc": "Collects verdict, deep-dive, YARA, audit trail and raw tool packs, adds RAG context, and asks DeepSeek to write the 16-section REPORT-MASTER markdown.",
        "artifacts": ["00-prompt.txt", "01-llm-raw.json", "02-REPORT-MASTER-v2.md"],
        "dir": "publish",
    },
    "correlate": {
        "num": 7, "title": "Correlate",
        "desc": "Section-based Map-Reduce report with cross-references",
        "long_desc": "Pass 1 generates 17 report sections independently with focused evidence + targeted RAG. Pass 2 re-generates sections with cross-section context so each section can cite findings from the others. Produces REPORT-MASTER-v3.md.",
        "artifacts": ["00-tools-raw.json", "01-section-results.json", "02-REPORT-MASTER-v3.md"],
        "dir": "correlate",
    },
    "audit": {
        "num": 8, "title": "Audit",
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
    "function_recovery.json": "agentic_recovery",
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
            "windows_powershell": "scp -i $env:USERPROFILE\\.ssh\\remnux-lab-key C:\\path\\to\\sample.exe remnux@192.168.77.41:/opt/samples/incoming/user-drop/",
            "windows_cmd": "scp -i %USERPROFILE%\\.ssh\\remnux-lab-key C:\\path\\to\\sample.exe remnux@192.168.77.41:/opt/samples/incoming/user-drop/",
            "linux_mac": "scp -i ~/.ssh/remnux-lab-key /path/to/sample.exe remnux@192.168.77.41:/opt/samples/incoming/user-drop/",
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


def resolve_file_path(sha: str, rel_path: str) -> Path | None:
    """Resolve a relative path safely, allowing session.json as a special case."""
    if rel_path == "session.json":
        sess = SESSIONS_DIR / f"{sha}.json"
        return sess if sess.exists() else None
    base = LOGS_DIR / sha
    full = (base / rel_path).resolve()
    try:
        full.relative_to(base.resolve())
    except ValueError:
        return None
    return full if full.exists() and full.is_file() else None


def load_config() -> dict:
    """Load pipeline UI settings from persistent JSON, merging with defaults."""
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text()))
        except Exception:
            pass
    return cfg


def save_config(cfg: dict) -> None:
    """Persist pipeline UI settings."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def get_stage_env() -> dict[str, str]:
    """Build the environment variables passed to every spawned stage.

    LLM settings are injected only when the UI has explicitly set them,
    otherwise the stage scripts inherit them from the system environment.

    V6.1: live default is LLM-only (REVENG_RAG=0). Index/model keys still
    come from `/opt/cadre-v3-tools/rag/rag_active.env` for opt-in RAG.
    Master RAG toggle + hybrid/ANN come from pipeline-config (UI), not the
    switch file.
    """
    cfg = load_config()
    use_rag = bool(cfg.get("use_rag", False))
    env: dict[str, str] = {
        "REVENG_RAG": "1" if use_rag else "0",
        "REVENG_RAG_HYBRID": "1" if cfg.get("use_hybrid", True) else "0",
        "REVENG_RAG_BACKEND": "remote",
        "REVENG_REMOTE_EMBED_URL": cfg.get("remote_embed_url", "http://192.168.77.1:8000"),
        "REVENG_RAG_ANN": "1" if cfg.get("use_ann", False) else "0",
        "REVENG_EMBED_MODEL": cfg.get("embed_model") or "Qwen/Qwen3-Embedding-0.6B",
        # Post-opt standard defaults (S1/S4) — match CLI rebench / S2 ui_default
        "CADRE_FLOSS_PROFILE": os.environ.get("CADRE_FLOSS_PROFILE", "auto"),
        "CADRE_CAPA_ENGINE": os.environ.get("CADRE_CAPA_ENGINE", "auto"),
    }
    if cfg.get("use_reranker", False):
        reranker_url = cfg.get("reranker_url", "http://192.168.77.1:8000")
        if reranker_url:
            env["REVENG_RERANKER_URL"] = reranker_url
    # LIVE switch file: index/model/backend only — never override master RAG toggle.
    _skip = {"REVENG_RAG", "REVENG_RAG_HYBRID", "REVENG_RAG_ANN"}
    active = Path("/opt/cadre-v3-tools/rag/rag_active.env")
    if active.exists():
        for line in active.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k.startswith("REVENG_") and k not in _skip:
                env[k] = v
    # Re-assert UI master toggle after switch-file merge.
    env["REVENG_RAG"] = "1" if use_rag else "0"
    env["REVENG_RAG_HYBRID"] = "1" if cfg.get("use_hybrid", True) else "0"
    env["REVENG_RAG_ANN"] = "1" if cfg.get("use_ann", False) else "0"
    # LLM backend: dual-model policy
    #   planner (agentic) = flash; judgment / report / verdict = Pro
    env["REVENG_LLM_PLANNER_MODEL"] = "deepseek-v4-flash"
    llm_model = (cfg.get("llm_model") or "").strip()
    if llm_model and "flash" in llm_model.lower():
        # UI flash pin → planner only; judgment stays Pro
        env["REVENG_LLM_MODEL"] = "deepseek-v4-pro"
        env["REVENG_LLM_VERDICT_MODEL"] = "deepseek-v4-pro"
        env["REVENG_LLM_MODEL_REQUESTED"] = llm_model
    elif llm_model:
        env["REVENG_LLM_MODEL"] = llm_model
        env["REVENG_LLM_VERDICT_MODEL"] = llm_model
    else:
        env["REVENG_LLM_MODEL"] = "deepseek-v4-pro"
        env["REVENG_LLM_VERDICT_MODEL"] = "deepseek-v4-pro"
    llm_api_url = cfg.get("llm_api_url", "").strip()
    if llm_api_url:
        env["REVENG_LLM_API_URL"] = llm_api_url
    llm_reasoning = cfg.get("llm_reasoning", "").strip()
    if llm_reasoning:
        env["REVENG_LLM_REASONING"] = llm_reasoning
    else:
        env.setdefault("REVENG_LLM_REASONING", "max")
    llm_api_key = cfg.get("llm_api_key", "").strip()
    if llm_api_key:
        env["REVENG_LLM_API_KEY"] = llm_api_key
    return env



# ============== stage runner ==============

def _session_pipeline_mode(sha: str) -> str:
    """Return single|standard|large from session (V6.3 prefers single)."""
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
    if stage == "dynamic":
        return ["python3", script] + list(extra_args) + [sha]
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

@app.route("/")
def index():
    return render_template("index.html",
                           stages=[s[0] for s in STAGES],
                           stage_labels={s[0]: s[1] for s in STAGES},
                           stage_details=STAGE_DETAILS)


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


@app.route("/api/browse")
def api_browse():
    return jsonify({"dirs": list_browser_dirs(), "upload": get_upload_instructions()})


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    """Return current pipeline/RAG settings for the Flask UI."""
    return jsonify(load_config())


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    """Persist pipeline/RAG/LLM settings from the Flask UI."""
    data = request.get_json(force=True, silent=True) or {}
    cfg = load_config()
    # whitelist keys (LLM key is stored server-side; never echoed back)
    for key in DEFAULT_CONFIG:
        if key in data:
            cfg[key] = data[key]
    save_config(cfg)
    return jsonify({"ok": True, "config": cfg})


@app.route("/api/status/<sha>")
def api_status(sha):
    return jsonify(infer_pipeline_state(sha))


@app.route("/api/deps/<sha>")
def api_deps(sha):
    """Return stage dependency readiness for a sample."""
    state = load_pipeline_state(sha)
    done = {s: ((state.get("stages") or {}).get(s) or {}).get("status") == "done" for s in STAGE_ORDER}
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
        return jsonify(t)
    # task may have finished and been evicted from memory; try to recover from stage.log
    # task_id alone doesn't carry sha/stage, so this is best-effort only for currently-running tasks.
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
    samples = list_samples()
    s = next((x for x in samples if x.get("sha256") == sha), None)
    if not s:
        return jsonify({"error": f"sample not found: {sha}"}), 404

    deleted: list[str] = []
    errors: list[str] = []

    # Remove the per-sample logs directory (stage outputs, reports, stage.logs).
    log_dir = LOGS_DIR / sha
    if log_dir.exists():
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


@app.route("/api/evidence/<sha>")
def api_evidence(sha):
    """Return the evidence file tree for a sample (logs + session.json)."""
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
        return jsonify(tree)
    for item in sorted(base.rglob("*")):
        if item.is_file() and not item.name.startswith("."):
            rel = item.relative_to(base)
            ext = item.suffix.lstrip(".") or "txt"
            if "/" in str(rel):
                stage = str(rel).split("/")[0]
            else:
                stage = ROOT_FILE_STAGE_MAP.get(item.name, "root")
            tree.append({
                "path": str(rel),
                "size": item.stat().st_size,
                "stage": stage,
                "ext": ext,
                "mtime": item.stat().st_mtime,
            })
    return jsonify(tree)


@app.route("/api/file/<sha>")
def api_file(sha):
    """Serve raw file content as text/plain."""
    rel_path = request.args.get("path", "")
    if not rel_path:
        return jsonify({"error": "path parameter required"}), 400
    p = resolve_file_path(sha, rel_path)
    if not p:
        return jsonify({"error": f"file not found: {rel_path}"}), 404
    return Response(p.read_text(errors="replace"), mimetype="text/plain")


@app.route("/api/download/<sha>")
def api_download(sha):
    """Download a file with its original filename as attachment."""
    rel_path = request.args.get("path", "")
    if not rel_path:
        return jsonify({"error": "path parameter required"}), 400
    p = resolve_file_path(sha, rel_path)
    if not p:
        return jsonify({"error": f"file not found: {rel_path}"}), 404
    name = request.args.get("name") or Path(rel_path).name
    return Response(
        p.read_bytes(),
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={name}"},
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


@app.route("/api/rag/<sha>")
def api_rag(sha):
    """Extract RAG context blocks from saved prompts for this sample."""
    sources = [
        LOGS_DIR / sha / "quick_scan" / "02-prompt.txt",
        LOGS_DIR / sha / "prompt.txt",  # quick_scan writes here
        LOGS_DIR / sha / "deep_dive" / "03-prompt.txt",
        LOGS_DIR / sha / "publish" / "00-prompt.txt",
    ]
    results = []
    seen = set()
    for src in sources:
        if not src.exists() or src in seen:
            continue
        seen.add(src)
        text = src.read_text(errors="replace")
        # Extract RAG section: from '## Threat-intel context (RAG' to next '## '
        m = re.search(
            r"## Threat-intel context \(RAG.*?\n(.*?)\n## ",
            text, re.DOTALL | re.IGNORECASE,
        )
        if m:
            results.append({
                "source": str(src.relative_to(LOGS_DIR / sha)),
                "rag": m.group(1).strip(),
            })
    if not results:
        return jsonify({"query": "", "hits": [], "sources": [], "note": "No RAG context found in prompts."})
    # Use first source as canonical
    block = results[0]["rag"]
    # Query: if block is XML, label by sources; else first non-empty line
    query = ""
    if block.strip().startswith("<"):
        query = f"RAG context from {results[0]['source']}"
    else:
        lines = block.splitlines()
        if lines:
            query = lines[0].strip().strip("#:-*")
    # Extract bullet/numbered hits; if XML, keep raw lines
    hits = [l.strip() for l in block.splitlines() if l.strip().startswith(("- ", "* ", "1. ", "2. ", "3. ", "4. ", "5. "))]
    if not hits and block.strip().startswith("<"):
        hits = [block.strip()[:2000]]
    return jsonify({"query": query, "hits": hits, "sources": [r["source"] for r in results], "rag": block})


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
# (critical-impact findings). Pairs with Tools/v3-deploy/hitl/*.py.
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
    sys.path.insert(0, "/opt/cadre-v3-tools")
    # hitl-3-critical.py has hyphens; import via importlib.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "hitl_3_critical",
        "/opt/cadre-v3-tools/hitl/hitl-3-critical.py",
    )
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


if __name__ == "__main__":
    print("=== CADRE-RevEng Pipeline UI ===")
    print("  Listening on 0.0.0.0:5000")
    print("  Open http://192.168.77.41:5000 in browser")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
