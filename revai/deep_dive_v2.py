#!/usr/bin/env python3
"""
deep_dive_v2.py — SQL-first deep dive + all tools + RAG + evidence pack (v3).

Prereq: intake_v2 completed for sha256.

Modes (see docs/PIPELINE-MODES.md):
  standard — this scripted fan-out (default for small/medium samples)
  large    — delegates to deep_dive_agentic.py (tool loop; avoids timeouts)

Usage:
  python3 /opt/scripts/deep_dive_v2.py <sha256> [--mode auto|standard|large]
  python3 /opt/scripts/deep_dive_v2.py <sha256> [--max-decompile 3] [--no-speakeasy]
  # --pro: prefer Pro for deep findings (default judgment is already Pro)
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    McpGhidraClient,
    EvidenceAssembler,
    LOGS_DIR,
    case_dir,
    PIPELINE_MODE_LARGE,
    PIPELINE_MODE_STANDARD,
    audit_write,
    cap_rows_for_prompt,
    dotnet_analyze,
    ensure_pipeline_runtime_env,
    _detect_format_for_tools,
    evaluate_tool_checklist,
    frida_static_probe,
    get_llm_model,
    ghidra_decompile,
    hitl_checkpoint,
    ida_query_remote,
    llm_judge,
    llm_call_metadata,
    load_session,
    apply_citation_confidence_gate,
    package_stage_evidence,
    resolve_pipeline_mode,
    run_all_tools,
    run_deep_tools_with_cache,
    run_post_upx_second_pass,
    speakeasy_emulate,
    tool_applies_to_format,
    update_session,
)

SUSPICIOUS_IMPORT_PATTERNS = [
    "Virtual",
    "Crypt",
    "Internet",
    "URLDownload",
    "CreateRemote",
    "WriteProcess",
    "OpenProcess",
    "CreateThread",
    "CreateProcess",
    "Reg",
    "Socket",
    "WSA",
    "Http",
    "Net",
    "Shell",
    "Exec",
    "MapView",
    "ReadProcess",
    "Thread",
]

IOC_STRING_PATTERNS = [
    "http", "https", "www", "ftp", "://", "@", ".com", ".net", ".org", ".ru", ".info",
    "powershell", "cmd", "rundll32", "regsvr32", "wscript", "cscript", "schtasks",
    "HKEY", "Software\\Microsoft\\Windows", "CurrentVersion", "Run", "Explorer",
    "Internet Explorer", "AppData", "Temp", "Windows", "System32",
    "password", "credential", "login", "admin", "crypt", "encrypt", "decode", "key",
    ".exe", ".dll", ".sys", ".bat", ".vbs", ".ps1", ".scr",
    "kernel32", "user32", "advapi32", "ntdll", "ws2_32",
    "Install", "CreateProcess", "CreateThread", "WriteFile", "RegSet",
]


def _like_patterns(col: str, patterns: list[str]) -> str:
    return " OR ".join(f"{col} LIKE '%{p}%'" for p in patterns)


SUSPICIOUS_IMPORT_SQL_GHIDRA = f"""
SELECT i.name, i.module, i.addr AS address
FROM imports i
WHERE {_like_patterns('i.name', SUSPICIOUS_IMPORT_PATTERNS)}
LIMIT 50
"""

SUSPICIOUS_IMPORT_DATA_ITEMS_GHIDRA = f"""
SELECT d.addr AS address, d.name AS api_name, d.data_type, d.size
FROM data_items d
WHERE d.name LIKE 'PTR_%'
  AND ({_like_patterns('d.name', [f'PTR_%{p}%' for p in SUSPICIOUS_IMPORT_PATTERNS])})
LIMIT 50
"""

SUSPICIOUS_IMPORT_SQL_IDA = f"""
SELECT module, name, addr FROM imports
WHERE {_like_patterns('name', SUSPICIOUS_IMPORT_PATTERNS)}
LIMIT 50
"""

TOP_FUNCS_GHIDRA = """
SELECT func_name, func_addr, cyclomatic_complexity AS cc
FROM function_metrics
WHERE size > 100
LIMIT 20
"""

TOP_FUNCS_IDA = """
SELECT name, addr, size FROM funcs LIMIT 20
"""

FUNCTION_METRICS_GHIDRA = """
SELECT func_name, func_addr, size, instruction_count, block_count,
       cyclomatic_complexity, call_in_count, call_out_count, string_ref_count
FROM function_metrics
LIMIT 20
"""

CALLGRAPH_HOT_GHIDRA = """
SELECT dst_func_name, dst_func_addr, COUNT(*) AS caller_count
FROM callgraph_edges
GROUP BY dst_func_addr, dst_func_name
LIMIT 20
"""

CRYPTO_NET_XREFS_GHIDRA = f"""
SELECT f.name, f.addr AS address, d.name AS api_name, x.to_addr AS to_ea
FROM data_items d
JOIN xrefs x ON x.to_addr = d.addr
JOIN funcs f ON f.addr = x.from_addr
WHERE d.name LIKE 'PTR_%'
  AND ({_like_patterns('d.name', [f'PTR_%{p}%' for p in SUSPICIOUS_IMPORT_PATTERNS])})
LIMIT 50
"""

CRYPTO_NET_XREFS_IDA = f"""
SELECT f.name, f.addr, i.name, i.module
FROM imports i
JOIN xrefs x ON x.to_addr = i.addr
JOIN funcs f ON f.addr = x.from_addr
WHERE {_like_patterns('i.name', SUSPICIOUS_IMPORT_PATTERNS)}
  AND x.is_code = 1
LIMIT 50
"""

IOC_STRINGS_GHIDRA = f"""
SELECT s.content, s.addr AS address, s.length
FROM strings s
WHERE {_like_patterns('s.content', IOC_STRING_PATTERNS)}
LIMIT 100
"""

IOC_STRINGS_IDA = f"""
SELECT s.content, s.addr, s.length
FROM strings s
WHERE {_like_patterns('s.content', IOC_STRING_PATTERNS)}
LIMIT 100
"""

ALL_IMPORTS_GHIDRA = """
SELECT i.name, i.module, i.addr AS address FROM imports i
LIMIT 100
"""

ALL_IMPORTS_IDA = """
SELECT name, module, addr FROM imports
LIMIT 100
"""

ALL_IMPORTS_FALLBACK_GHIDRA = """
SELECT d.addr AS address, d.name, d.data_type, d.size
FROM data_items d
WHERE d.name LIKE 'PTR_%'
LIMIT 100
"""

ALL_STRINGS_GHIDRA = """
SELECT s.content, s.addr AS address, s.length FROM strings s
LIMIT 100
"""

ALL_STRINGS_IDA = """
SELECT content, addr, length FROM strings
LIMIT 100
"""

STRING_REFS_GHIDRA = """
SELECT func_name, func_addr, string_value, string_addr, string_length
FROM string_refs
LIMIT 100
"""

STRING_REFS_IDA = """
SELECT func_name, func_addr, string_value, string_addr, string_length
FROM string_refs
LIMIT 100
"""

MEMORY_BLOCKS_GHIDRA = """
SELECT start_addr, end_addr, name, class, size, is_read, is_write, is_exec
FROM memory_blocks
ORDER BY start_addr
"""

SEGMENTS_IDA = """
SELECT start_addr, end_addr, name, class, perm
FROM segments
ORDER BY start_addr
"""

EXPORTS_GHIDRA = """
SELECT name, addr AS address, module FROM exports
ORDER BY name
LIMIT 50
"""

ENTRIES_IDA = """
SELECT ordinal, addr, name FROM entries
ORDER BY ordinal
LIMIT 50
"""

DB_INFO_GHIDRA = "SELECT * FROM sql_capabilities LIMIT 20;"
DB_INFO_IDA = "SELECT key, value FROM db_info;"


def load_intake_validation(sha: str) -> dict:
    """Load the intake-validation.json produced by intake_v2.py."""
    path = case_dir(sha) / "intake-validation.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE pairs from a dotenv-style file into os.environ."""
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


def gather_sql(session_id: str, ida_session_id: str | None) -> dict:
    ghidra_tables = []
    client = McpGhidraClient()
    try:
        for label, sql in [
            ("db_info", DB_INFO_GHIDRA),
            ("suspicious_imports", SUSPICIOUS_IMPORT_SQL_GHIDRA),
            ("suspicious_imports_data_items", SUSPICIOUS_IMPORT_DATA_ITEMS_GHIDRA),
            ("all_imports", ALL_IMPORTS_GHIDRA),
            ("all_imports_fallback", ALL_IMPORTS_FALLBACK_GHIDRA),
            ("top_complexity", TOP_FUNCS_GHIDRA),
            ("function_metrics", FUNCTION_METRICS_GHIDRA),
            ("callgraph_hot", CALLGRAPH_HOT_GHIDRA),
            ("crypto_net_xrefs", CRYPTO_NET_XREFS_GHIDRA),
            ("ioc_strings", IOC_STRINGS_GHIDRA),
            ("all_strings", ALL_STRINGS_GHIDRA),
            ("string_refs", STRING_REFS_GHIDRA),
            ("memory_blocks", MEMORY_BLOCKS_GHIDRA),
            ("exports", EXPORTS_GHIDRA),
        ]:
            try:
                r = client.ghidra_query(session_id, sql, max_rows=100)
                ghidra_tables.append({"label": label, "sql": sql, "result": r})
            except Exception as e:
                ghidra_tables.append({"label": label, "sql": sql, "error": str(e)})
    finally:
        client.close()

    ida_tables = []
    if ida_session_id:
        for label, sql in [
            ("db_info", DB_INFO_IDA),
            ("suspicious_imports", SUSPICIOUS_IMPORT_SQL_IDA),
            ("all_imports", ALL_IMPORTS_IDA),
            ("top_size", TOP_FUNCS_IDA),
            ("crypto_net_xrefs", CRYPTO_NET_XREFS_IDA),
            ("ioc_strings", IOC_STRINGS_IDA),
            ("all_strings", ALL_STRINGS_IDA),
            ("string_refs", STRING_REFS_IDA),
            ("segments", SEGMENTS_IDA),
            ("entries", ENTRIES_IDA),
        ]:
            try:
                r = ida_query_remote(ida_session_id, sql)
                ida_tables.append({"label": label, "sql": sql, "result": r})
            except Exception as e:
                ida_tables.append({"label": label, "sql": sql, "error": str(e)})

    return {"ghidra": ghidra_tables, "ida": ida_tables}


def pick_decompile_targets(ghidra_tables: list, max_n: int) -> list[str]:
    targets = []
    for t in ghidra_tables:
        if t.get("label") != "top_complexity":
            continue
        rows = (t.get("result") or {}).get("rows") or []
        for row in rows[:max_n]:
            addr = row.get("address") or row.get("name")
            if addr:
                targets.append(str(addr))
    return targets[:max_n]


def load_cff_findings(sha256: str) -> list[dict] | None:
    """Read cff_detect.log if present (cff_detect.py ran during intake)."""
    marker_abs = "/opt/samples/logs/cff-detector/cff_detector.log"
    if not os.path.isfile(marker_abs):
        return None
    out = []
    for line in open(marker_abs).read().splitlines():
        if line.startswith("function="):
            kv = {}
            for tok in line.split():
                k, _, v = tok.partition("=")
                kv[k] = v
            out.append(kv)
    return out


def build_prompt(session: dict, sql_evidence: dict, decompiles: list, behavioral: dict,
                 tools_results: dict, cff_findings: list[dict] | None = None,
                 dotnet_result: dict | None = None,
                 intake_validation: dict | None = None) -> str:
    intake_validation = intake_validation or {}
    source_decisions = intake_validation.get("source_decisions", {})

    lines = [
        "# Deep-dive evidence",
        f"sha256: {session['sha256']}",
        f"sample: {session['sample_path']}",
        "",
    ]

    # Source decisions from intake validation: tells the LLM which engine is
    # authoritative per evidence category so it can weight SQL evidence correctly.
    if source_decisions:
        lines.append("## Source decisions (from intake validation)")
        for cat, decision in source_decisions.items():
            if cat == "sha256":
                continue
            if isinstance(decision, dict):
                src = decision.get("source", "?")
                conf = decision.get("confidence", "?")
                reason = decision.get("reason", "")
                lines.append(f"- {cat}: {src} (confidence={conf}) — {reason}")
            else:
                lines.append(f"- {cat}: {decision}")
        lines.append("")

    lines.append("## Ghidra SQL")
    for t in sql_evidence.get("ghidra", []):
        lines.append("### " + cap_rows_for_prompt(
            {"engine": "ghidra", "label": t["label"], "sql": t["sql"],
             "result": t.get("result"), "error": t.get("error")}
        ))
        lines.append("")
    lines.append("## IDA SQL")
    for t in sql_evidence.get("ida", []):
        lines.append("### " + cap_rows_for_prompt(
            {"engine": "ida", "label": t["label"], "sql": t["sql"],
             "result": t.get("result"), "error": t.get("error")}
        ))
        lines.append("")
    lines.append("## Decompilations (ghidra_decompile)")
    for d in decompiles:
        lines.append(f"### {d.get('function')}")
        body = d.get("decompilation")
        if isinstance(body, dict):
            lines.append(json.dumps(body, indent=2)[:4000])
        else:
            lines.append(str(body)[:4000])
        lines.append("")
    lines.append("## CFF (Control-Flow Flattening) findings")
    if cff_findings:
        lines.append("Functions that look like CFF (state-machine dispatcher pattern):")
        for f in cff_findings[:10]:
            lines.append(
                f"  function={f.get('function', '?')} entry={f.get('entry','?')} "
                f"size={f.get('size','?')} cond_edges={f.get('cond_edges','?')} "
                f"unique_dsts={f.get('unique_dsts','?')} cff_score={f.get('cff_score','?')}"
            )
        lines.append(
            "  (CFF score 0-100; higher = more dispatcher-like; >= 25 is the default "
            "threshold. These functions are likely state-machine obfuscated.)"
        )
    else:
        lines.append("No CFF findings (cff_detect.log not present or no CFF candidates found).")
    lines.append("")
    lines.append("## Behavioral (Speakeasy + Frida probe)")
    lines.append(json.dumps(behavioral, indent=2)[:6000])
    lines.append("")
    if dotnet_result and dotnet_result.get("is_dotnet"):
        lines.append("## .NET analysis (dnfile + monodis)")
        lines.append(f"  runtime: {dotnet_result.get('runtime_version', '?')}")
        lines.append(f"  assembly: {dotnet_result.get('assembly_name') or dotnet_result.get('module_name', '?')}")
        lines.append(f"  language: {dotnet_result.get('language_hint', '?')}")
        lines.append(f"  external_refs: {dotnet_result.get('external_assembly_refs', [])}")
        if dotnet_result.get("suspicious_native_refs"):
            lines.append(f"  SUSPICIOUS native modules: {dotnet_result['suspicious_native_refs']}")
        if dotnet_result.get("suspicious_methods"):
            lines.append(f"  SUSPICIOUS methods: {dotnet_result['suspicious_methods']}")
        if dotnet_result.get("interesting_pinvoke"):
            lines.append(f"  P/Invoke DLLs: {dotnet_result['interesting_pinvoke']}")
        if dotnet_result.get("pinvoke_imports"):
            lines.append(f"  P/Invoke functions: {dotnet_result['pinvoke_imports'][:20]}")
        if dotnet_result.get("has_suppress_ildasm"):
            lines.append("  - SuppressIldasmAttribute present (anti-RE)")
        if dotnet_result.get("shellcode_embed_hint"):
            lines.append("  - Shellcode-embed pattern (ldc.i4 + newarr + InitializeArray) detected")
        if dotnet_result.get("il_total_lines"):
            lines.append(f"  IL disassembly: {dotnet_result['il_total_lines']} lines (showing first 50)")
        il_excerpt = (dotnet_result.get("il_excerpt") or "")[:3000]
        if il_excerpt:
            lines.append("")
            lines.append("```il")
            lines.append(il_excerpt)
            lines.append("```")
        lines.append("")

    # If capa failed/timed out, surface Malcat's static signal as a fallback.
    capa = tools_results.get("capa") or {}
    if isinstance(capa, dict) and capa.get("error"):
        lines.append("## capa fallback — Malcat high-signal static indicators")
        malcat = tools_results.get("malcat") or {}
        malcat_views = malcat.get("views") if isinstance(malcat, dict) else {}
        if malcat_views:
            imports = malcat_views.get("imports") or []
            high_imports = [imp.get("name", "") for imp in imports[:20] if imp.get("name")]
            if high_imports:
                lines.append(f"Top Malcat imports: {', '.join(high_imports)}")
            constants = malcat.get("constants") or []
            const_vals = [c.get("id", "") for c in constants[:20] if c.get("id")]
            if const_vals:
                lines.append(f"Top Malcat constants: {', '.join(str(v) for v in const_vals)}")
            anomalies = malcat.get("anomalies") or []
            anom_names = [a.get("name", "") for a in anomalies[:15] if a.get("name")]
            if anom_names:
                lines.append(f"Malcat anomalies: {', '.join(anom_names)}")
        lines.append("")

    # --- EvidenceAssembler: signal-prioritized tool cards within a budget ---
    sha = (session.get("sha256") if isinstance(session, dict) else "") or ""
    tools_for_pack = {
        "malcat": tools_results.get("malcat"),
        "capa": capa,
        "yara": tools_results.get("yara"),
        "floss": tools_results.get("floss"),
        "dotnet": dotnet_result,
        "r2": tools_results.get("r2_decomp"),
        "upx": tools_results.get("upx"),
        "xor": tools_results.get("xor"),
        "olevba": tools_results.get("olevba"),
        "peepdf": tools_results.get("peepdf"),
        "pe_imports": tools_results.get("pe_imports"),
    }
    pack = package_stage_evidence(
        "deep_dive", tools_for_pack, budget_chars=60000, sha=sha, persist=True,
    )
    lines.append(pack)
    lines.append("")

    lines.append(
        "CITATION RULE (mandatory): key_evidence[].source MUST be the engine that "
        "owns the cited fragment in the evidence above (ghidra|ida|malcat|capa|"
        "floss|yara|pe_imports|r2|upx). Never label a Ghidra/Malcat/YARA import or "
        "string as source=ida. Wrong engine attribution invalidates the report.\n"
        "DEPTH PROTOCOL (mandatory): a verdict does not end the analysis. The "
        "summary MUST address every capability domain — persistence, C2/network, "
        "evasion/anti-analysis, exfiltration, defense impairment, credential "
        "access, encryption/obfuscation, entry point, imports, strings — each as "
        "observed evidence or explicitly \"not observed\" (e.g. \"persistence: not "
        "observed\"). An unmentioned domain fails the depth gate.\n"
        "Return JSON: {summary, behaviors[], iocs[], key_evidence[], "
        "function_annotations[], confidence 0-100}\n"
        "  key_evidence: [{source, query_or_table, row_or_rule, why}, ...]\n"
        "  function_annotations: [{address: <int>, new_name: <str>, "
        "comment?: <str>}, ...] — only include functions you can confidently "
        "rename based on the evidence (e.g. \"decrypt_string\" if you see AES "
        "init + xor loop in the function body). Address is the decimal "
        "function address from the funcs table. Skip the field entirely "
        "if you have no high-confidence renames."
    )
    return "\n".join(lines)


def _run_large_agentic_deep_dive(sha: str, max_steps: int = 10) -> dict:
    """Delegate large-mode deep dive to the agentic tool loop."""
    agentic = Path("/opt/scripts/deep_dive_agentic.py")
    if not agentic.exists():
        # Local fallback for development (same directory as this script)
        alt = Path(__file__).resolve().parent / "deep_dive_agentic.py"
        agentic = alt if alt.exists() else agentic
    if not agentic.exists():
        raise FileNotFoundError("deep_dive_agentic.py not found on Remnux or alongside deep_dive_v2.py")

    print(
        f"[deep_dive_v2] LARGE mode → agentic deep dive ({agentic})",
        flush=True,
    )
    proc = subprocess.run(
        ["python3", "-u", str(agentic), sha, "--max-steps", str(max_steps)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n", flush=True)
    if proc.stderr:
        print(proc.stderr, end="" if proc.stderr.endswith("\n") else "\n", file=sys.stderr, flush=True)
    if proc.returncode != 0:
        raise RuntimeError(f"deep_dive_agentic failed rc={proc.returncode}")

    ev_dir = case_dir(sha) / "deep_dive"
    agentic_path = ev_dir / "agentic_deep_dive.json"
    # P0.8: rc=0 alone is not success — the agentic JSON must exist and
    # must not flag incomplete tooling / failed checklist.
    if not agentic_path.exists():
        raise RuntimeError(
            f"deep_dive_agentic exited 0 but {agentic_path} missing — treating as failure"
        )
    result = json.loads(agentic_path.read_text())
    if result.get("incomplete_tooling") or result.get("checklist_ok") is False:
        raise RuntimeError(
            "deep_dive_agentic incomplete: "
            f"checklist_ok={result.get('checklist_ok')} "
            f"sql_deep_ok={result.get('sql_deep_ok')} "
            f"incomplete_tooling={result.get('incomplete_tooling')}"
        )

    # Compat artifact so yara_gen / publish can still find a deep-dive JSON.
    compat = {
        "source": "deep_dive_agentic",
        "phase": "deep-dive",
        "pipeline_mode": PIPELINE_MODE_LARGE,
        "sha256": sha,
        "agentic": result,
        "summary": result.get("summary"),
        "verdict": result.get("verdict"),
        "confidence": result.get("confidence"),
        "key_evidence": result.get("key_evidence") or result.get("evidence"),
        "steps_used": result.get("steps_used"),
        "history": result.get("history"),
        # P0.8: propagate agentic completeness flags for downstream gates
        "checklist_ok": result.get("checklist_ok"),
        "sql_deep_ok": result.get("sql_deep_ok"),
        "incomplete_tooling": bool(result.get("incomplete_tooling")),
    }
    (ev_dir / "05-deep-dive.json").write_text(json.dumps(compat, indent=2, default=str))
    audit_write(sha, {"source": "deep_dive_v2", "phase": "large_delegate", "agentic_path": str(agentic_path)})
    print(f"[deep_dive_v2] LARGE mode complete -> {ev_dir / '05-deep-dive.json'}", flush=True)
    return compat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--pro", action="store_true", help="Use the configured verdict model for deep findings (default for judgment)")
    ap.add_argument("--max-decompile", type=int, default=5)
    ap.add_argument("--no-speakeasy", action="store_true")
    ap.add_argument(
        "--mode",
        choices=("auto", "standard", "large"),
        default="auto",
        help="auto uses session/classifier; large delegates to deep_dive_agentic.py",
    )
    ap.add_argument("--max-steps", type=int, default=10,
                    help="Max agentic steps when mode=large (default 10)")
    args = ap.parse_args()

    env_info = ensure_pipeline_runtime_env()
    print(f"[deep_dive_v2] runtime env: model={get_llm_model()}", flush=True)

    session = load_session(args.sha256)
    session_id = session["session_id"]
    ida_id = session.get("ida_session_id")
    sample_path = session["sample_path"]
    sha = args.sha256
    intake_validation = load_intake_validation(sha)

    mode_override = None if args.mode == "auto" else args.mode
    mode_info = resolve_pipeline_mode(session, intake_validation, override=mode_override)
    if not session.get("pipeline_mode") or mode_override:
        session = update_session(sha, {
            "pipeline_mode": mode_info["mode"],
            "pipeline_mode_reasons": mode_info.get("reasons") or [],
            "pipeline_mode_signals": mode_info.get("signals") or {},
            "pipeline_mode_source": mode_info.get("source") or "auto",
            "pipeline_mode_locked": bool(mode_override),
        })
    print(
        f"[deep_dive_v2] pipeline_mode={mode_info['mode']} "
        f"source={mode_info.get('source')} reasons={mode_info.get('reasons')}",
        flush=True,
    )

    if mode_info["mode"] == PIPELINE_MODE_LARGE:
        _run_large_agentic_deep_dive(sha, max_steps=args.max_steps)
        return

    ev_dir = case_dir(sha) / "deep_dive"
    ev_dir.mkdir(parents=True, exist_ok=True)

    hitl_checkpoint("deep_dive_v2", "pre_sql", {"sha256": sha, "phase": "gather_sql"})

    sql_evidence = gather_sql(session_id, ida_id)
    (ev_dir / "00-sql-evidence.json").write_text(
        json.dumps(sql_evidence, indent=2, default=str))

    targets = pick_decompile_targets(sql_evidence["ghidra"], args.max_decompile)

    hitl_checkpoint("deep_dive_v2", "pre_decompile", {"targets": targets})

    decompiles = []
    for fn in targets:
        try:
            decompiles.append(ghidra_decompile(session_id, fn))
        except Exception as e:
            decompiles.append({"function": fn, "error": str(e)})

    # Deterministic format routing (TOOL_MANIFEST) — not LLM. LLM judges evidence later.
    sample_fmt = _detect_format_for_tools(sample_path)
    behavioral: dict = {}
    run_speakeasy = (not args.no_speakeasy) and tool_applies_to_format("speakeasy", sample_fmt)
    run_frida = tool_applies_to_format("frida_probe", sample_fmt)
    if run_speakeasy and run_frida:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_se = pool.submit(speakeasy_emulate, sample_path)
            fut_fr = pool.submit(frida_static_probe, sample_path)
            behavioral["speakeasy"] = fut_se.result()
            behavioral["frida_probe"] = fut_fr.result()
    elif run_speakeasy:
        behavioral["speakeasy"] = speakeasy_emulate(sample_path)
        behavioral["frida_probe"] = {"skipped": True, "reason": f"not_applicable:{sample_fmt}"}
    elif run_frida:
        behavioral["speakeasy"] = {"skipped": True, "reason": f"not_applicable:{sample_fmt}"}
        behavioral["frida_probe"] = frida_static_probe(sample_path)
    else:
        behavioral["speakeasy"] = {"skipped": True, "reason": f"not_applicable:{sample_fmt}"}
        behavioral["frida_probe"] = {"skipped": True, "reason": f"not_applicable:{sample_fmt}"}

    # .NET analysis (in-process, no live execution — safe for .NET assemblies too)
    dotnet = dotnet_analyze(sample_path)

    # Run deep tools once: reuse quick_scan triage cache for capa/floss/yara/malcat
    # (same binary + same engine — no accuracy loss; avoid double wall clock).
    tools_results = run_deep_tools_with_cache(
        sample_path, sha, profile="deep", parallel=True, max_workers=10
    )
    cache_info = tools_results.get("_cache") or {}
    if cache_info.get("reused"):
        print(
            f"[deep_dive_v2] once-cache reused={cache_info.get('reused')} "
            f"from={cache_info.get('source')}",
            flush=True,
        )
    # V5.16.5 — when UPX unpack succeeds, re-analyze the unpacked payload
    upx_r = tools_results.get("upx") if isinstance(tools_results.get("upx"), dict) else {}
    unpacked = (upx_r or {}).get("unpacked_path") or ""
    if (upx_r or {}).get("upx_ok") and unpacked:
        print(f"[deep_dive_v2] post-UPX second-pass -> {unpacked}", flush=True)
        second = run_post_upx_second_pass(unpacked, profile="deep")
        tools_results["upx_second_pass"] = second
        (ev_dir / "01b-upx-second-pass.json").write_text(
            json.dumps(second, indent=2, default=str))
        print(
            f"[deep_dive_v2] post-UPX second-pass ok={second.get('ok')} "
            f"tools={list((second.get('tool_ok') or {}).keys())}",
            flush=True,
        )
    (ev_dir / "01-tools-raw.json").write_text(
        json.dumps(tools_results, indent=2, default=str))
    tool_gate = evaluate_tool_checklist(tools_results)
    (ev_dir / "01-tools-gate.json").write_text(
        json.dumps(tool_gate, indent=2, default=str))
    if not tool_gate["ok"]:
        print(
            f"[deep_dive_v2] TOOL_GATE_FAIL hard_failures={tool_gate['hard_failures']} "
            f"missing={tool_gate['missing']}",
            flush=True,
        )

    cff_findings = load_cff_findings(sha)
    if cff_findings:
        (ev_dir / "02-cff-findings.json").write_text(
            json.dumps(cff_findings, indent=2, default=str))

    record = {
        "source": "deep_dive_v2",
        "phase": "deep-dive",
        "pipeline_mode": PIPELINE_MODE_STANDARD,
        "sha256": sha,
        "intake_validation": intake_validation,
        "sql_evidence": sql_evidence,
        "decompiles": decompiles,
        "behavioral": behavioral,
        "dotnet": dotnet,
        "tools": tools_results,
        "cff_findings": cff_findings,
    }
    audit_write(sha, record)

    prompt = build_prompt(session, sql_evidence, decompiles, behavioral,
                          tools_results, cff_findings=cff_findings,
                          dotnet_result=dotnet,
                          intake_validation=intake_validation)
    (ev_dir / "03-prompt.txt").write_text(prompt)

    model = get_llm_model()
    try:
        resp = llm_judge(prompt, model=model)
        (ev_dir / "04-llm-raw.json").write_text(
            json.dumps(resp, indent=2, default=str))
        analysis = json.loads(resp["choices"][0]["message"]["content"])
        analysis["source"] = "llm_judge"
        meta = llm_call_metadata(resp)
        meta["request_model"] = model
        analysis["model"] = meta["response_model"] or model
        analysis["llm_audit"] = meta
    except Exception as e:
        analysis = {
            "source": "error",
            "error": str(e),
            "decompile_count": len(decompiles),
            "sql_evidence": sql_evidence,
            "behavioral": behavioral,
        }

    analysis["sql_evidence"] = sql_evidence
    analysis["behavioral"] = behavioral
    analysis["decompile_count"] = len(decompiles)
    analysis["tools_summary"] = {k: type(v).__name__ if not isinstance(v, dict) else list(v.keys())[:5]
                                  for k, v in tools_results.items() if not k.startswith("_")}
    analysis["tool_gate"] = tool_gate
    if not tool_gate["ok"]:
        analysis["incomplete_tooling"] = True
        # Never claim high confidence when required tools hard-failed.
        try:
            conf = int(analysis.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0
        if conf > 40:
            analysis["confidence_capped_from"] = conf
            analysis["confidence"] = 40
            analysis["confidence_cap_reason"] = "incomplete_tooling"

    # V5.12.8 — high confidence requires grounded key_evidence
    apply_citation_confidence_gate(
        analysis,
        {
            "tools": tools_results,
            "sql": sql_evidence,
            "behavioral": behavioral,
            "decompiles": decompiles[:3],
            "prompt": prompt[:4000],
        },
    )
    if analysis.get("citations_ungrounded"):
        print(
            "[deep_dive_v2] ACCURACY_HOLD: high confidence capped — key_evidence ungrounded",
            flush=True,
        )
    if analysis.get("false_engine_citations"):
        print(
            "[deep_dive_v2] ACCURACY_HOLD: false engine attribution in key_evidence "
            f"(V5.16.3) -> {analysis.get('engine_citation', {}).get('false_engine_citations')}",
            flush=True,
        )

    (ev_dir / "05-deep-dive.json").write_text(json.dumps(analysis, indent=2, default=str))

    # Backward-compat: also write deep-dive.json at logs root
    root_path = case_dir(sha) / "deep-dive.json"
    root_path.write_text(json.dumps(analysis, indent=2, default=str))

    # --- Auto-apply Ghidra + IDA annotations (write-back) ---
    # If confidence is high and the LLM proposed function renames,
    # apply them live to BOTH the Ghidra project (via ghidra_sql_client)
    # AND the IDA project on Flare-VM (via ida_sql_client, SSH).
    # Each engine takes its own snapshot first so the analyst can
    # rollback independently. Annotations are also queued to the
    # deep-dive.json file for the Flask UI to review/commit.
    annotations = analysis.get("function_annotations") or []
    confidence = int(analysis.get("confidence") or 0)
    AUTO_APPLY_THRESHOLD = 90
    ghidra_result = {"skipped": True, "reason": "no annotations proposed"}
    ida_result = {"skipped": True, "reason": "no annotations proposed"}
    if not annotations:
        ghidra_result = {"skipped": True,
                         "reason": "no annotations proposed"}
        ida_result = {"skipped": True,
                      "reason": "no annotations proposed"}
    elif confidence < AUTO_APPLY_THRESHOLD:
        skip_msg = {
            "skipped": True,
            "reason": f"confidence {confidence} < {AUTO_APPLY_THRESHOLD}",
            "annotations_proposed": len(annotations),
            "threshold": AUTO_APPLY_THRESHOLD,
            "hint": "use the Flask UI to manually apply with --no-write false",
        }
        ghidra_result = skip_msg.copy()
        ida_result = skip_msg.copy()
        renames = []
        bookmarks = []
    elif os.environ.get("REVAI_AUTO_WRITEBACK", "0") != "1":
        # P0.6: never mutate live Ghidra/IDA projects without explicit opt-in.
        # Annotations stay queued in deep-dive.json for HITL review/apply.
        skip_msg = {
            "skipped": True,
            "reason": "auto write-back disabled (set REVAI_AUTO_WRITEBACK=1 to enable)",
            "annotations_proposed": len(annotations),
            "threshold": AUTO_APPLY_THRESHOLD,
            "hint": "review via Flask HITL endpoints and apply manually",
        }
        ghidra_result = skip_msg.copy()
        ida_result = skip_msg.copy()
        renames = []
        bookmarks = []
    else:
        # Compute renames and bookmarks once (used for both engines)
        renames = [
            {"address": int(a["address"]),
             "new_name": str(a["new_name"])}
            for a in annotations
            if "address" in a and "new_name" in a
        ]
        bookmarks = [
            {"address": int(a["address"]),
             "category": "LLM",
             "type": "Analysis",
             "comment": str(a.get("comment") or f"auto-tagged by LLM (deep_dive, conf {confidence})")}
            for a in annotations
            if "address" in a and a.get("comment")
        ]
        # Apply to Ghidra
        try:
            from ghidra_sql_client import get_ghidra_sql_client
            gh_client = get_ghidra_sql_client()
            gh_apply = gh_client.apply_pending(
                sha,
                {"renames": renames, "bookmarks": bookmarks},
                snapshot=True,  # always snapshot for auto-apply
                dry_run=False,
            )
            ghidra_result = {
                "applied": True,
                "engine": "ghidra",
                "snapshot": gh_apply.get("snapshot", {}).get("snapshot_id"),
                "rename_count": len(renames),
                "bookmark_count": len(bookmarks),
                "ok": gh_apply.get("ok"),
            }
        except Exception as e:
            ghidra_result = {
                "applied": False, "engine": "ghidra",
                "error": str(e), "renames_proposed": len(annotations),
            }

        # Apply to IDA (via SSH to Flare-VM)
        try:
            from ida_sql_client import get_ida_sql_client
            ida_client = get_ida_sql_client()
            ida_apply = ida_client.apply_pending(
                sha,
                {"renames": renames, "bookmarks": bookmarks},
                snapshot=True,
                dry_run=False,
            )
            ida_result = {
                "applied": True,
                "engine": "ida",
                "snapshot": ida_apply.get("snapshot", {}).get("snapshot_id"),
                "rename_count": len(renames),
                "bookmark_count": len(bookmarks),
                "ok": ida_apply.get("ok"),
            }
        except Exception as e:
            ida_result = {
                "applied": False, "engine": "ida",
                "error": str(e), "renames_proposed": len(annotations),
            }

    # Re-write after adding the annotation fields
    (ev_dir / "05-deep-dive.json").write_text(json.dumps(analysis, indent=2, default=str))
    root_path.write_text(json.dumps(analysis, indent=2, default=str))

    print(f"[deep_dive_v2] -> {ev_dir}/")
    print(f"[deep_dive_v2] -> {root_path}")
    print(json.dumps({k: analysis[k] for k in ("source", "summary", "confidence") if k in analysis}, indent=2))
    if not tool_gate["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
