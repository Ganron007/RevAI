#!/usr/bin/env python3
"""
agentic_recover_v4.py — v4 agentic function-recovery stage.

Runs between deep_dive_v2.py and publish_report_v2.py when
ENABLE_AGENTIC_RECOVERY=1.

Pipeline:
  Triage -> Signature match -> Deobfuscation flags ->
  Bottom-up LLM analysis -> Semantic synthesis -> Ghidra writeback ->
  function_recovery.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# v2_lib is on /opt/scripts; recovery package is co-located with this script.
V2_SCRIPTS = "/opt/scripts"
V4_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(V4_ROOT))
sys.path.insert(0, V2_SCRIPTS)

from v2_lib import (  # noqa: E402
    McpGhidraClient,
    audit_write,
    ensure_pipeline_runtime_env,
    get_llm_model,
    llm_judge,
    llm_call_metadata,
    load_session,
)

from recovery import (  # noqa: E402
    CallGraph,
    ContextBuilder,
    DeobfuscatorPass,
    GhidraWriteback,
    Normalizer,
    SignatureDB,
    Synthesizer,
)


LOGS_DIR = Path("/opt/samples/logs")
# Defaults tuned so the whole pipeline finishes in < 30 min on a typical sample.
# Override with env vars for deep-dive/full recovery runs. REVAI_* names are
# canonical; legacy AGENTIC_RECOVERY_* names still honored for back-compat.


def _env_int(name: str, legacy: str, default: int) -> int:
    raw = os.environ.get(name) or os.environ.get(legacy) or ""
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _env_float(name: str, legacy: str, default: float) -> float:
    raw = os.environ.get(name) or os.environ.get(legacy) or ""
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def recovery_enabled() -> bool:
    """Gated by REVAI_ENABLE_AGENTIC_RECOVERY=1 (legacy ENABLE_AGENTIC_RECOVERY honored)."""
    return (os.environ.get("REVAI_ENABLE_AGENTIC_RECOVERY") or os.environ.get(
        "ENABLE_AGENTIC_RECOVERY", "0")).strip().lower() in ("1", "true", "yes")


DEFAULT_MAX_FUNCS = _env_int("REVAI_AGENTIC_RECOVERY_MAX_FUNCS", "AGENTIC_RECOVERY_MAX_FUNCS", 200)
DEFAULT_CONFIDENCE_THRESHOLD = _env_float("REVAI_AGENTIC_RECOVERY_CONF_THRESHOLD", "AGENTIC_RECOVERY_CONF_THRESHOLD", 0.7)
DEFAULT_FUNC_CAP_PER_TIER = _env_int("REVAI_AGENTIC_RECOVERY_TIER_CAP", "AGENTIC_RECOVERY_TIER_CAP", 20)
DEFAULT_WORKERS = _env_int("REVAI_AGENTIC_RECOVERY_WORKERS", "AGENTIC_RECOVERY_WORKERS", 8)
PROMPT_DIR = V4_ROOT / "prompts"


def load_prompt_templates() -> tuple[str, str]:
    system = (PROMPT_DIR / "agentic_recovery_system.txt").read_text()
    user = (PROMPT_DIR / "agentic_recovery_user.txt").read_text()
    return system, user


def render_user_prompt(template: str, context: dict) -> str:
    """Simple Mustache-ish substitution."""
    out = template
    # Replace provided keys
    for key, val in context.items():
        marker = "{{" + key + "}}"
        if marker in out:
            rendered = _render_value(val)
            out = out.replace(marker, rendered)
    # Replace any remaining markers with (not provided)
    out = re.sub(r"\{\{\s*\w+\s*\}\}", "(not provided)", out)
    return out


def _render_value(val: Any) -> str:
    if isinstance(val, (list, tuple)):
        if not val:
            return "(none)"
        lines = []
        for item in val:
            if isinstance(item, dict):
                lines.append("- " + ", ".join(f"{k}={v}" for k, v in item.items()))
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)
    if isinstance(val, dict):
        return json.dumps(val, indent=2)
    return str(val)


def _addr_key(addr: Any) -> str:
    return str(int(addr)) if addr is not None else ""


# High-value import APIs: breakpoints on high-value Windows API calls that
# suggest logic, evasion, or communication; API references identify
# user-defined functionality. Functions referencing these are prime
# LLM-analysis candidates regardless of size.
HIGH_VALUE_IMPORT_FRAGMENTS = (
    # evasion / anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "NtProtectVirtualMemory",
    "WriteProcessMemory", "NtWriteVirtualMemory", "ReadProcessMemory",
    "CreateRemoteThread", "SetThreadContext", "NtCreateThreadEx", "QueueUserAPC",
    # persistence
    "RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx", "CreateService",
    "OpenSCManager", "StartService", "MoveFileEx",
    # C2 / network
    "InternetOpen", "InternetConnect", "HttpSendRequest", "WinHttpOpen",
    "WinHttpConnect", "WSAStartup", "socket", "connect", "send", "recv",
    "URLDownloadToFile", "WSASend", "WSARecv",
    # credentials / theft
    "GetAsyncKeyState", "SetWindowsHookEx", "GetKeyState", "OpenProcess",
    "OpenProcessToken", "LookupPrivilegeValue", "AdjustTokenPrivileges",
    "CreateToolhelp32Snapshot", "CryptAcquireContext", "CryptEncrypt",
    "CryptDecrypt", "NtReadVirtualMemory", "MiniDumpWriteDump",
    # defense impairment
    "TerminateProcess", "NtTerminateProcess", "CreateToolhelp32Snapshot",
    "EnumProcesses", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
)


def _high_value_import_sql() -> str:
    """Build a WHERE-clause fragment matching high-value API names by prefix.

    Prefix (LIKE 'name%') matching is intentional: Win32 imports commonly
    carry A/W/Ex suffixes (RegSetValueExW, VirtualAllocEx) and bare variants
    (VirtualAlloc vs VirtualAllocEx); exact IN-list matching missed those.
    """
    return " OR ".join(
        f"dst_func_name LIKE '{f.replace(chr(39), chr(39)*2)}%'"
        for f in HIGH_VALUE_IMPORT_FRAGMENTS
    )


def enumerate_functions(client, session_id: str, max_funcs: int) -> list[dict]:
    """Select candidate functions by RELEVANCE, not size (2026-08-09).

    "Focus on functions that are not identified as library functions" plus
    API-reference density; breakpoints on "high-value API calls that suggest
    logic, evasion, or communication"; dequeue functions by a relevance
    score, not size.

    Score = call_in_count (hub importance) * 2
          + string_ref_count (behavioral signal) * 1
          + high-value import count (logic/evasion/comm APIs) * 3

    Real ghidrasql schema (verified 2026-08-09):
      - imports appear in callgraph_edges as dst (dst_func_name like
        GetModuleHandleA, VirtualAllocEx, ...)
      - string_refs: ref_addr (EA of the referencing instruction) -> map to
        containing function via funcs address range
      - function_metrics.string_ref_count / call_in_count are populated

    NOTE: a single SQL statement joining funcs/function_metrics/callgraph_edges
    hung the ghidrasql server (verified 2026-08-09); the three lightweight
    queries below are fast (~2-7s each) and equivalent.

    HYBRID SLOTS (verified need 2026-08-09 on small darkgate 8cffdc409...):
    pure relevance scoring degenerates to call_in on samples whose
    string_ref_count is unpopulated and whose high-value-import callers have
    few callers themselves (VirtualAlloc callers ranked ~190, out of top-40).
    Guaranteed slots keep the highest-ranked high-value-import callers, the
    largest logic functions (size floor), and dynamic-import-resolve sites in
    the pool regardless of score:
      - REVAI_AGENTIC_RECOVERY_HV_SLOTS       (default 8)
      - REVAI_AGENTIC_RECOVERY_SIZE_SLOTS     (default 5, size >= MIN_SIZE)
      - REVAI_AGENTIC_RECOVERY_MIN_SIZE       (default 200 bytes)
      - REVAI_AGENTIC_RECOVERY_RESOLVE_SLOTS  (default 3; packed-sample core
        logic: functions calling GetProcAddress/resolvers >= 2x)
      - REVAI_AGENTIC_RECOVERY_ORACLE_SLOTS   (default 3; functions executed
        under the Speakeasy emulation oracle — real code paths, behavioral
        evidence; read from deep_dive/03-oracle.json when present)

    ANTI-ANALYSIS TERM (2026-08-09): deterministic extractor adds each
    function's distinct anti-analysis signal score (debugger APIs, PEB access,
    timing pairs, VM/analysis-tool artifact strings, TLS callbacks) to the
    relevance score — evasion logic is a prime LLM-analysis target.
    Deterministic; library-elimination happens in triage_functions.
    """
    rows = client.ghidra_query(
        session_id,
        "SELECT address, name, size FROM funcs "
        "WHERE name LIKE 'FUN_%' OR name LIKE 'func_%' OR name = ''",
        max_rows=100000,
    ).get("rows", [])

    metric_rows = client.ghidra_query(
        session_id,
        "SELECT func_addr, call_in_count, string_ref_count FROM function_metrics",
        max_rows=50000,
    ).get("rows", [])
    metric_map = {_addr_key(m["func_addr"]): m for m in metric_rows}

    # function_metrics.string_ref_count is unpopulated on some samples
    # (0 everywhere on small darkgate, verified 2026-08-09) — compute a
    # fallback from the populated string_refs table.
    sr_rows = client.ghidra_query(
        session_id,
        "SELECT func_addr, COUNT(*) AS c FROM string_refs GROUP BY func_addr",
        max_rows=100000,
    ).get("rows", [])
    sr_counts = {
        _addr_key(r["func_addr"]): int(r.get("c") or 0)
        for r in sr_rows if r.get("func_addr")
    }

    hv_rows = client.ghidra_query(
        session_id,
        f"SELECT src_func_addr, dst_func_name FROM callgraph_edges "
        f"WHERE {_high_value_import_sql()}",
        max_rows=100000,
    ).get("rows", [])
    hv_srcs: dict[str, set[str]] = {}
    for r in hv_rows:
        src = _addr_key(r.get("src_func_addr"))
        dst = str(r.get("dst_func_name") or "")
        if src and dst:
            hv_srcs.setdefault(src, set()).add(dst)

    # Deterministic signal extractors (anti-analysis + dynamic-import-resolve).
    # Anti-analysis signals add a score term (evasion logic = prime analysis
    # target); resolve sites get guaranteed pool slots (packed-sample core
    # logic). Both failure-safe.
    aa_scores: dict[str, int] = {}
    resolve_sites: list[dict] = []
    try:
        from anti_analysis_signals import extract_anti_analysis
        from dynamic_resolve_detect import extract_dynamic_resolve

        aa = extract_anti_analysis(client, session_id)
        if not aa.get("error"):
            aa_scores = {
                a: int(rec.get("score") or 0) for a, rec in (aa.get("functions") or {}).items()
            }
        dr = extract_dynamic_resolve(client, session_id)
        if not dr.get("error"):
            resolve_sites = dr.get("resolve_sites") or []
    except Exception:
        pass

    hv_slots = _env_int("REVAI_AGENTIC_RECOVERY_HV_SLOTS", "AGENTIC_RECOVERY_HV_SLOTS", 8)
    size_slots = _env_int("REVAI_AGENTIC_RECOVERY_SIZE_SLOTS", "AGENTIC_RECOVERY_SIZE_SLOTS", 5)
    min_size = _env_int("REVAI_AGENTIC_RECOVERY_MIN_SIZE", "AGENTIC_RECOVERY_MIN_SIZE", 200)
    resolve_slots = _env_int(
        "REVAI_AGENTIC_RECOVERY_RESOLVE_SLOTS", "AGENTIC_RECOVERY_RESOLVE_SLOTS", 3
    )
    oracle_slots = _env_int(
        "REVAI_AGENTIC_RECOVERY_ORACLE_SLOTS", "AGENTIC_RECOVERY_ORACLE_SLOTS", 3
    )

    # Emulation-oracle executed functions (deep_dive/03-oracle.json, when the
    # oracle ran): functions actually executed under Speakeasy emulation are
    # real code paths — guaranteed pool slots (behavioral).
    oracle_exec: set[str] = set()
    try:
        sha = str(session_id).rsplit("-", 1)[-1] if "-" in str(session_id) else ""
        oracle_path = Path("/opt/samples/logs") / sha / "deep_dive" / "03-oracle.json"
        if oracle_path.is_file():
            ora = json.loads(oracle_path.read_text())
            for f in (ora.get("executed_functions") or []):
                a = _addr_key(f.get("func_addr"))
                if a:
                    oracle_exec.add(a)
    except Exception:
        pass

    scored: list[tuple[int, dict]] = []
    for f in rows:
        m = metric_map.get(_addr_key(f["address"]), {})
        call_in = int(m.get("call_in_count") or 0)
        str_refs = max(
            int(m.get("string_ref_count") or 0),
            sr_counts.get(_addr_key(f["address"]), 0),
        )
        hv = len(hv_srcs.get(_addr_key(f["address"]), set()))
        aa = int(aa_scores.get(_addr_key(f["address"]), 0))
        score = call_in * 2 + str_refs + hv * 3 + aa
        f["relevance_score"] = score
        f["call_in_count"] = call_in
        f["string_ref_count"] = str_refs
        f["high_value_imports"] = hv
        f["anti_analysis_signals"] = aa
        scored.append((score, f))
    scored.sort(key=lambda pair: (-pair[0], -(int(pair[1].get("size") or 0))))

    selected: list[dict] = []
    seen: set[str] = set()

    def _take(pool: list[dict], n: int) -> None:
        added = 0
        for f in pool:
            if len(selected) >= max_funcs:
                return
            if added >= n:
                return
            a = _addr_key(f["address"])
            if a in seen:
                continue
            seen.add(a)
            selected.append(f)
            added += 1

    hv_pool = sorted(
        (f for f in rows if hv_srcs.get(_addr_key(f["address"]))),
        key=lambda f: (-int(f.get("relevance_score") or 0), -(int(f.get("size") or 0))),
    )
    size_pool = sorted(
        (f for f in rows if int(f.get("size") or 0) >= min_size),
        key=lambda f: -(int(f.get("size") or 0)),
    )
    resolve_addr_set = {r.get("func_addr") for r in resolve_sites}
    resolve_pool = sorted(
        (f for f in rows if _addr_key(f["address"]) in resolve_addr_set),
        key=lambda f: -(int(f.get("relevance_score") or 0)),
    )
    oracle_pool = sorted(
        (f for f in rows if _addr_key(f["address"]) in oracle_exec),
        key=lambda f: -(int(f.get("relevance_score") or 0)),
    )
    _take(hv_pool, hv_slots)
    _take(size_pool, size_slots)
    _take(resolve_pool, resolve_slots)
    _take(oracle_pool, oracle_slots)
    _take([f for _, f in scored], max_funcs)
    return selected


def load_metrics(client, session_id: str) -> dict[str, dict]:
    rows = client.ghidra_query(
        session_id,
        "SELECT func_addr, cyclomatic_complexity, call_in_count, call_out_count, "
        "instruction_count, block_count FROM function_metrics",
        max_rows=50000,
    ).get("rows", [])
    return {_addr_key(r["func_addr"]): r for r in rows}


def load_call_edges(client, session_id: str) -> list[dict]:
    return client.ghidra_query(
        session_id,
        "SELECT src_func_addr, dst_func_addr FROM call_edges",
        max_rows=200000,
    ).get("rows", [])


def triage_functions(funcs: list[dict], metrics: dict[str, dict],
                     sig_db: SignatureDB) -> tuple[list[dict], dict[str, dict], dict[str, dict]]:
    """Classify functions, match signatures, return (to_analyze, signatures, contexts).

    to_analyze: functions that still need LLM analysis.
    signatures: addr -> signature match result.
    contexts: addr -> gathered context for analysis.
    """
    to_analyze: list[dict] = []
    signatures: dict[str, dict] = {}
    contexts: dict[str, dict] = {}

    for f in funcs:
        addr = _addr_key(f["address"])
        m = metrics.get(addr, {})
        ctx = {
            "size": int(f.get("size") or 0),
            "cyclomatic_complexity": int(m.get("cyclomatic_complexity") or 0),
            "call_in_count": int(m.get("call_in_count") or 0),
            "call_out_count": int(m.get("call_out_count") or 0),
            "strings": [],
            "imports": [],
            "constants": [],
        }
        contexts[addr] = ctx

        # Direct name lookup (e.g. already-imported APIs)
        sig = sig_db.match_by_name(f.get("name", ""))
        if not sig:
            sig = sig_db.match(f, ctx)
        if sig:
            signatures[addr] = sig
        else:
            to_analyze.append(f)
    return to_analyze, signatures, contexts


def build_base_resolved(funcs: list[dict], signatures: dict[str, dict]) -> dict[str, dict]:
    """Seed resolved map with signature matches and existing non-FUN names."""
    resolved: dict[str, dict] = {}
    for f in funcs:
        addr = _addr_key(f["address"])
        name = f.get("name", "")
        sig = signatures.get(addr)
        if sig:
            resolved[addr] = {
                "function_name": sig["name"],
                "confidence": sig["score"],
                "parameters": [],
                "return_type": "void",
                "notes": f"signature match: {sig['matched_rules']}; {sig['notes']}",
                "source": "signature_db",
            }
        elif name and not name.startswith("FUN_") and name != "entry":
            resolved[addr] = {
                "function_name": name,
                "confidence": 0.95,
                "parameters": [],
                "return_type": "void",
                "notes": "existing symbol from Ghidra analysis",
                "source": "existing_symbol",
            }
    return resolved


def analyze_function(func: dict, context: dict, resolved: dict[str, dict],
                     system_template: str, user_template: str,
                     model: str, cb: ContextBuilder) -> dict:
    """Send one function to the LLM and parse the JSON result."""
    addr = _addr_key(func["address"])
    ctx = cb.build(func, resolved, obfuscation_flags=context.get("obfuscation", {}))

    # Render user prompt; cap total size to ~16k tokens budget by truncating pseudocode
    user = render_user_prompt(user_template, {
        "target_address": ctx["target_address"],
        "target_name": ctx["target_name"],
        "target_size": ctx["target_size"],
        "obfuscation_flags": _render_value(ctx["obfuscation"]),
        "normalized_pseudocode": ctx["normalized_pseudocode"],
        "string_refs": _render_value(ctx["string_refs"]),
        "data_xrefs": _render_value(ctx["data_xrefs"]),
        "callees": _render_value(ctx["callees"]),
        "callers": _render_value(ctx["callers"]),
        "neighbors": _render_value(ctx["neighbors"]),
    })

    prompt = f"{system_template}\n\n{user}"
    result = {
        "function_address": addr,
        "function_name": f"unknown_{addr}",
        "confidence": 0.0,
        "parameters": [],
        "return_type": "void",
        "notes": "LLM call failed or produced invalid JSON",
        "behavior_tags": ["unknown"],
        "source": "llm_judge",
        "prompt_length": len(prompt),
    }

    try:
        resp = llm_judge(prompt, model=model)
        meta = llm_call_metadata(resp)
        result["llm_audit"] = meta
        content = resp["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        for key in ("function_name", "confidence", "parameters", "return_type", "notes", "behavior_tags"):
            if key in parsed:
                result[key] = parsed[key]
        result["confidence"] = max(0.0, min(1.0, float(result.get("confidence") or 0)))
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    # Attach normalized pseudocode for synthesis
    result["normalized_pseudocode"] = ctx["normalized_pseudocode"]
    result["raw_pseudocode"] = ctx["raw_pseudocode"]
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--max-funcs", type=int, default=DEFAULT_MAX_FUNCS)
    ap.add_argument("--tier-cap", type=int, default=DEFAULT_FUNC_CAP_PER_TIER)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-writeback", action="store_true")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    args = ap.parse_args()

    if not recovery_enabled():
        print("[agentic_recover_v4] REVAI_ENABLE_AGENTIC_RECOVERY is not set; skipping.", file=sys.stderr)
        return

    ensure_pipeline_runtime_env()

    sha = args.sha256
    session = load_session(sha)
    session_id = session["session_id"]
    sample_path = session["sample_path"]

    ev_dir = LOGS_DIR / sha / "agentic_recovery"
    ev_dir.mkdir(parents=True, exist_ok=True)

    model = get_llm_model()
    system_template, user_template = load_prompt_templates()

    # Honest not-applicable contract: formats without a Ghidra project
    # (doc/script/raw) have no functions to recover — write an explicit
    # not_applicable result and exit 0, never a crash rc.
    if not session.get("gpr_path") or session.get("skip_ghidra"):
        recovery = {
            "sha256": sha,
            "sample_path": sample_path,
            "ok": True,
            "not_applicable": True,
            "reason": "no ghidra project (doc/script/raw format) — nothing to recover",
            "triage": {"total_functions": 0, "analyzed_in_pipeline": 0,
                       "signature_matches": 0, "llm_candidates": 0},
            "function_results": {},
            "model": model,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        recovery_path = LOGS_DIR / sha / "function_recovery.json"
        recovery_path.write_text(json.dumps(recovery, indent=2, default=str))
        (ev_dir / "06-function_recovery.json").write_text(json.dumps(recovery, indent=2, default=str))
        audit_write(sha, {
            "source": "agentic_recover_v4",
            "phase": "complete",
            "function_recovery_path": str(recovery_path),
            "not_applicable": True,
            "llm_calls": 0,
        })
        print(f"[agentic_recover_v4] not_applicable (no ghidra project) -> {recovery_path}")
        return

    client = McpGhidraClient()
    try:
        audit_write(sha, {"source": "agentic_recover_v4", "phase": "start", "model": model})

        # ---- Triage ----
        try:
            all_funcs = enumerate_functions(client, session_id, args.max_funcs)
            total_funcs = int(client.ghidra_query(
                session_id, "SELECT count(*) as c FROM funcs", max_rows=1
            )["rows"][0]["c"])
        except (FileNotFoundError, RuntimeError):
            # gpr_path exists but Ghidra never created a program (raw/script
            # formats whose import silently failed) — honest not-applicable.
            recovery = {
                "sha256": sha,
                "sample_path": sample_path,
                "ok": True,
                "not_applicable": True,
                "reason": "no ghidra program (import failed for this format) — nothing to recover",
                "triage": {"total_functions": 0, "analyzed_in_pipeline": 0,
                           "signature_matches": 0, "llm_candidates": 0},
                "function_results": {},
                "model": model,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            recovery_path = LOGS_DIR / sha / "function_recovery.json"
            recovery_path.write_text(json.dumps(recovery, indent=2, default=str))
            (ev_dir / "06-function_recovery.json").write_text(
                json.dumps(recovery, indent=2, default=str))
            audit_write(sha, {
                "source": "agentic_recover_v4",
                "phase": "complete",
                "function_recovery_path": str(recovery_path),
                "not_applicable": True,
                "llm_calls": 0,
            })
            print(f"[agentic_recover_v4] not_applicable (no ghidra program) -> {recovery_path}")
            return
        if total_funcs > args.max_funcs:
            audit_write(sha, {
                "source": "agentic_recover_v4",
                "phase": "triage",
                "note": f"function cap hit: {len(all_funcs)}/{total_funcs}",
            })

        metrics = load_metrics(client, session_id)
        sig_db = SignatureDB(threshold=_env_float("REVAI_AGENTIC_RECOVERY_SIG_THRESHOLD", "AGENTIC_RECOVERY_SIG_THRESHOLD", 0.80))
        to_analyze, signatures, contexts = triage_functions(all_funcs, metrics, sig_db)

        triage_report = {
            "total_functions": total_funcs,
            "analyzed_in_pipeline": len(all_funcs),
            "signature_matches": len(signatures),
            "llm_candidates": len(to_analyze),
        }
        (ev_dir / "00-triage.json").write_text(json.dumps(triage_report, indent=2))

        # ---- Deobfuscation flags ----
        deob = DeobfuscatorPass(sample_path)
        normalizer = Normalizer()
        cb = ContextBuilder(client, session_id, normalizer=normalizer)
        for f in all_funcs:
            addr = _addr_key(f["address"])
            pseudo = None
            try:
                rows = client.ghidra_query(
                    session_id,
                    f"SELECT text FROM pseudocode WHERE func_addr = '{addr}' LIMIT 1",
                    max_rows=1,
                ).get("rows", [])
                if rows:
                    pseudo = rows[0].get("text")
            except Exception:
                pass
            contexts[addr]["obfuscation"] = deob.analyze(f, pseudo)
            contexts[addr]["context_builder"] = cb

        deob_report = deob.run_cff_deflatten(timeout=120)
        (ev_dir / "01-deobfuscation.json").write_text(json.dumps(deob_report, indent=2, default=str))

        # ---- Bottom-up call-graph-ordered LLM analysis ----
        call_edges = load_call_edges(client, session_id)
        cg = CallGraph(all_funcs, call_edges)
        tiers = cg.bottom_up_tiers()
        resolved = build_base_resolved(all_funcs, signatures)
        results: list[dict] = []
        total_llm_calls = 0
        total_prompt_tokens_estimate = 0

        for tier_idx, tier_addrs in enumerate(tiers):
            tier_funcs = [f for f in all_funcs if _addr_key(f["address"]) in tier_addrs]
            tier_funcs = tier_funcs[: args.tier_cap]
            lock = threading.Lock()
            completed_in_tier = 0

            def _analyze_one(f: dict) -> dict:
                addr = _addr_key(f["address"])
                if addr in signatures:
                    rec = resolved[addr].copy()
                    rec["function_address"] = addr
                    return rec
                ctx = contexts[addr]
                rec = analyze_function(f, ctx, resolved, system_template, user_template, model, cb)
                with lock:
                    nonlocal completed_in_tier
                    completed_in_tier += 1
                    resolved[addr] = rec
                    audit_write(sha, {
                        "source": "agentic_recover_v4",
                        "phase": "llm_analysis",
                        "function_address": addr,
                        "function_name": rec.get("function_name"),
                        "confidence": rec.get("confidence"),
                        "llm_audit": rec.get("llm_audit"),
                    })
                    if completed_in_tier % 10 == 0 or completed_in_tier == len(tier_funcs):
                        print(f"[agentic_recover_v4] tier {tier_idx}: {completed_in_tier}/{len(tier_funcs)} done", file=sys.stderr)
                return rec

            if len(tier_funcs) <= 1 or args.workers <= 1:
                for f in tier_funcs:
                    results.append(_analyze_one(f))
            else:
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    future_to_addr = {pool.submit(_analyze_one, f): _addr_key(f["address"]) for f in tier_funcs}
                    for fut in as_completed(future_to_addr):
                        results.append(fut.result())

            total_llm_calls = sum(1 for r in results if r.get("source") == "llm_judge")
            total_prompt_tokens_estimate = sum(r.get("prompt_length", 0) // 4 for r in results if r.get("source") == "llm_judge")
            (ev_dir / f"02-tier-{tier_idx:03d}.json").write_text(
                json.dumps([r for r in results if _addr_key(r["function_address"]) in tier_addrs],
                           indent=2, default=str))

        (ev_dir / "03-function_results.json").write_text(json.dumps(results, indent=2, default=str))

        # ---- Semantic synthesis ----
        synth = Synthesizer(min_confidence=DEFAULT_CONFIDENCE_THRESHOLD)
        synthesis = synth.synthesize(results)
        (ev_dir / "04-synthesis.json").write_text(json.dumps(synthesis, indent=2, default=str))

        # ---- Write-back to Ghidra ----
        writeback_summary = {"skipped": True, "reason": "--no-writeback"}
        if not args.no_writeback:
            writer = GhidraWriteback(client, session_id, sha)
            writeback_summary = writer.apply(results, dry_run=args.dry_run)
            (ev_dir / "05-writeback.json").write_text(json.dumps(writeback_summary, indent=2, default=str))

        # ---- Export function_recovery.json ----
        recovery = {
            "sha256": sha,
            "sample_path": sample_path,
            "model": model,
            "generated_at": time.time(),
            "triage": triage_report,
            "deobfuscation": deob_report,
            "tier_count": len(tiers),
            "llm_calls": total_llm_calls,
            "estimated_prompt_tokens": total_prompt_tokens_estimate,
            "function_results": results,
            "synthesis": synthesis,
            "writeback": writeback_summary,
        }
        recovery_path = LOGS_DIR / sha / "function_recovery.json"
        recovery_path.write_text(json.dumps(recovery, indent=2, default=str))
        (ev_dir / "06-function_recovery.json").write_text(json.dumps(recovery, indent=2, default=str))

        audit_write(sha, {
            "source": "agentic_recover_v4",
            "phase": "complete",
            "function_recovery_path": str(recovery_path),
            "llm_calls": total_llm_calls,
            "signature_matches": len(signatures),
        })

        print(f"[agentic_recover_v4] -> {recovery_path}")
        print(json.dumps(triage_report, indent=2))
    finally:
        client.close()


if __name__ == "__main__":
    main()
