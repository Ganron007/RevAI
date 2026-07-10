#!/usr/bin/env python3
"""
deep_dive_v2.py — SQL-first deep dive + all tools + RAG + evidence pack (v3).

Prereq: intake_v2 completed for sha256.

Usage:
  python3 /opt/scripts/deep_dive_v2.py <sha256> [--pro] [--max-decompile 3] [--no-speakeasy]
"""
import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    McpGhidraClient,
    EvidenceAssembler,
    LOGS_DIR,
    audit_write,
    cap_rows_for_prompt,
    dotnet_analyze,
    frida_static_probe,
    get_llm_model,
    ghidra_decompile,
    hitl_checkpoint,
    ida_query_remote,
    llm_judge,
    llm_call_metadata,
    load_session,
    run_all_tools,
    speakeasy_emulate,
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
SELECT i.name, i.module, i.address
FROM imports i
WHERE {_like_patterns('i.name', SUSPICIOUS_IMPORT_PATTERNS)}
ORDER BY i.name
LIMIT 50
"""

SUSPICIOUS_IMPORT_DATA_ITEMS_GHIDRA = f"""
SELECT d.address, d.name AS api_name, d.data_type, d.size
FROM data_items d
WHERE d.name LIKE 'PTR_%'
  AND ({_like_patterns('d.name', [f'PTR_%{p}%' for p in SUSPICIOUS_IMPORT_PATTERNS])})
ORDER BY d.name
LIMIT 50
"""

SUSPICIOUS_IMPORT_SQL_IDA = f"""
SELECT module, name, address FROM imports
WHERE {_like_patterns('name', SUSPICIOUS_IMPORT_PATTERNS)}
ORDER BY name
LIMIT 50
"""

TOP_FUNCS_GHIDRA = """
SELECT f.name, f.address, m.cyclomatic_complexity AS cc
FROM funcs f
JOIN function_metrics m ON m.func_addr = f.address
WHERE f.size > 100
ORDER BY m.cyclomatic_complexity DESC
LIMIT 20
"""

TOP_FUNCS_IDA = """
SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 20
"""

FUNCTION_METRICS_GHIDRA = """
SELECT func_name, func_addr, size, instruction_count, block_count,
       cyclomatic_complexity, call_in_count, call_out_count, string_ref_count
FROM function_metrics
ORDER BY cyclomatic_complexity DESC
LIMIT 20
"""

CALLGRAPH_HOT_GHIDRA = """
SELECT dst_func_name, dst_func_addr, COUNT(*) AS caller_count
FROM callgraph_edges
GROUP BY dst_func_addr, dst_func_name
ORDER BY caller_count DESC
LIMIT 20
"""

CRYPTO_NET_XREFS_GHIDRA = f"""
SELECT f.name, f.address, d.name AS api_name, x.to_ea
FROM data_items d
JOIN xrefs x ON x.to_ea = d.address
JOIN funcs f ON f.address = x.from_ea
WHERE d.name LIKE 'PTR_%'
  AND ({_like_patterns('d.name', [f'PTR_%{p}%' for p in SUSPICIOUS_IMPORT_PATTERNS])})
LIMIT 50
"""

CRYPTO_NET_XREFS_IDA = f"""
SELECT f.name, f.address, i.name, i.module
FROM imports i
JOIN xrefs x ON x.to_ea = i.address
JOIN funcs f ON f.address = x.from_ea
WHERE {_like_patterns('i.name', SUSPICIOUS_IMPORT_PATTERNS)}
  AND x.is_code = 1
LIMIT 50
"""

IOC_STRINGS_GHIDRA = f"""
SELECT s.content, s.address, s.length
FROM strings s
WHERE {_like_patterns('s.content', IOC_STRING_PATTERNS)}
ORDER BY s.length DESC
LIMIT 100
"""

IOC_STRINGS_IDA = f"""
SELECT s.content, s.address, s.length
FROM strings s
WHERE {_like_patterns('s.content', IOC_STRING_PATTERNS)}
ORDER BY s.length DESC
LIMIT 100
"""

ALL_IMPORTS_GHIDRA = """
SELECT i.name, i.module, i.address FROM imports i
ORDER BY i.module, i.name
LIMIT 100
"""

ALL_IMPORTS_IDA = """
SELECT name, module, address FROM imports
ORDER BY module, name
LIMIT 100
"""

ALL_IMPORTS_FALLBACK_GHIDRA = """
SELECT d.address, d.name, d.data_type, d.size
FROM data_items d
WHERE d.name LIKE 'PTR_%'
ORDER BY d.name
LIMIT 100
"""

ALL_STRINGS_GHIDRA = """
SELECT s.content, s.address, s.length FROM strings s
ORDER BY s.length DESC
LIMIT 100
"""

ALL_STRINGS_IDA = """
SELECT content, address, length FROM strings
ORDER BY length DESC
LIMIT 100
"""

STRING_REFS_GHIDRA = """
SELECT func_name, func_addr, string_value, string_addr, string_length
FROM string_refs
ORDER BY string_length DESC
LIMIT 100
"""

STRING_REFS_IDA = """
SELECT func_name, func_addr, string_value, string_addr, string_length
FROM string_refs
ORDER BY string_length DESC
LIMIT 100
"""

MEMORY_BLOCKS_GHIDRA = """
SELECT start_ea, end_ea, name, class, size, is_read, is_write, is_exec
FROM memory_blocks
ORDER BY start_ea
"""

SEGMENTS_IDA = """
SELECT start_ea, end_ea, name, class, perm
FROM segments
ORDER BY start_ea
"""

EXPORTS_GHIDRA = """
SELECT name, address, module FROM exports
ORDER BY name
LIMIT 50
"""

ENTRIES_IDA = """
SELECT ordinal, address, name FROM entries
ORDER BY ordinal
LIMIT 50
"""

DB_INFO_GHIDRA = "SELECT * FROM db_info;"
DB_INFO_IDA = "SELECT key, value FROM db_info;"


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


def _reveng_rag_block(session, tools_results: dict, top_k: int = 5) -> str:
    """Fetch RAG context from local reveng_rag index. Env-gated by REVENG_RAG=1.

    Queries the bge-m3 / 35K index using YARA family hints + capa rules + malcat
    anomalies as the query. Returns a context block for the LLM prompt, or "" if
    RAG is disabled / unavailable. Fail-safe: never raises.

    When REVENG_RAG_HYBRID=1, uses BM25 + dense + RRF hybrid search instead of
    dense-only.
    """
    if not os.environ.get("REVENG_RAG"):
        return ""
    try:
        query_parts = []
        yara = tools_results.get("yara") or {}
        for h in (yara.get("hits") or []):
            if isinstance(h, dict):
                rule = h.get("rule") or h.get("name") or ""
                if rule:
                    query_parts.append(str(rule))
        capa = tools_results.get("capa") or {}
        for r in (capa.get("rules") or [])[:3]:
            if isinstance(r, dict):
                name = r.get("name") or ""
                if name:
                    query_parts.append(str(name))
        malcat = tools_results.get("malcat") or {}
        for a in (malcat.get("anomalies") or [])[:3]:
            if isinstance(a, dict):
                name = a.get("name") or a.get("anomaly") or ""
                if name:
                    query_parts.append(str(name))
        if not query_parts:
            sample_path = session.get("sample_path", "") if isinstance(session, dict) else ""
            query_parts.append(sample_path.split("\\")[-1].split("/")[-1])
        query = " ".join(query_parts)[:500].strip()
        if not query:
            return ""
        for mod in ("reveng_rag", "rag_hybrid"):
            if mod in sys.modules:
                del sys.modules[mod]
        sys.path.insert(0, "/opt/cadre-v3-tools/rag")

        if os.environ.get("REVENG_RAG_HYBRID"):
            from rag_hybrid import HybridSearcher
            searcher = HybridSearcher()
            hits = searcher.search(query, top_k=top_k)
            if not hits:
                return ""
            return searcher.format_hits_for_prompt(hits, max_chars=4000)
        else:
            import reveng_rag
            searcher = reveng_rag.get_searcher()
            hits = searcher.search(query, top_k=top_k)
            if not hits:
                return ""
            return searcher.format_hits_for_prompt(hits, max_chars=4000)
    except Exception as e:
        return f"<!-- RAG unavailable: {e} -->"


def build_prompt(session: dict, sql_evidence: dict, decompiles: list, behavioral: dict,
                 tools_results: dict, cff_findings: list[dict] | None = None,
                 dotnet_result: dict | None = None, rag_block: str = "") -> str:
    lines = [
        "# Deep-dive evidence",
        f"sha256: {session['sha256']}",
        f"sample: {session['sample_path']}",
        "",
        "## Ghidra SQL",
    ]
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
            lines.append("  ⚠ SuppressIldasmAttribute present (anti-RE)")
        if dotnet_result.get("shellcode_embed_hint"):
            lines.append("  ⚠ Shellcode-embed pattern (ldc.i4 + newarr + InitializeArray) detected")
        if dotnet_result.get("il_total_lines"):
            lines.append(f"  IL disassembly: {dotnet_result['il_total_lines']} lines (showing first 50)")
        il_excerpt = (dotnet_result.get("il_excerpt") or "")[:3000]
        if il_excerpt:
            lines.append("")
            lines.append("```il")
            lines.append(il_excerpt)
            lines.append("```")
        lines.append("")

    # --- EvidenceAssembler: signal-prioritized tool cards within a budget ---
    asm = EvidenceAssembler(budget_chars=60000)
    asm.add("malcat", tools_results.get("malcat"))
    asm.add("capa", tools_results.get("capa"))
    asm.add("yara", tools_results.get("yara"))
    asm.add("floss", tools_results.get("floss"))
    asm.add("dotnet", dotnet_result)
    asm.add("r2", tools_results.get("r2_decomp"))
    asm.add("r2ai", tools_results.get("r2_ai_decompile"))
    asm.add("upx", tools_results.get("upx"))
    asm.add("xor", tools_results.get("xor"))
    asm.add("olevba", tools_results.get("olevba"))
    asm.add("peepdf", tools_results.get("peepdf"))
    if asm.cards:
        lines.append(asm.render())
        lines.append("")

    # RAG context (env-gated)
    if rag_block:
        added = asm.add_rag(rag_block)
        if added:
            lines.append("## Threat-intel context (RAG — local bge-m3 index, 35K records)")
            lines.append(asm.cards[-1][1])
            lines.append("")

    lines.append(
        "Return JSON: {summary, behaviors[], iocs[], key_evidence[], "
        "function_annotations[], confidence 0-100}\n"
        "  function_annotations: [{address: <int>, new_name: <str>, "
        "comment?: <str>}, ...] — only include functions you can confidently "
        "rename based on the evidence (e.g. \"decrypt_string\" if you see AES "
        "init + xor loop in the function body). Address is the decimal "
        "function address from the funcs table. Skip the field entirely "
        "if you have no high-confidence renames."
    )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--pro", action="store_true")
    ap.add_argument("--max-decompile", type=int, default=5)
    ap.add_argument("--no-speakeasy", action="store_true")
    args = ap.parse_args()

    session = load_session(args.sha256)
    session_id = session["session_id"]
    ida_id = session.get("ida_session_id")
    sample_path = session["sample_path"]
    sha = args.sha256

    ev_dir = LOGS_DIR / sha / "deep_dive"
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

    behavioral: dict = {}
    if not args.no_speakeasy:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_se = pool.submit(speakeasy_emulate, sample_path)
            fut_fr = pool.submit(frida_static_probe, sample_path)
            behavioral["speakeasy"] = fut_se.result()
            behavioral["frida_probe"] = fut_fr.result()
    else:
        behavioral["speakeasy"] = {"skipped": True}
        behavioral["frida_probe"] = frida_static_probe(sample_path)

    # .NET analysis (in-process, no live execution — safe for .NET assemblies too)
    dotnet = dotnet_analyze(sample_path)

    # Run ALL applicable tools via manifest (deep profile). Captures raw output.
    tools_results = run_all_tools(sample_path, profile="deep", parallel=True, max_workers=10)
    (ev_dir / "01-tools-raw.json").write_text(
        json.dumps(tools_results, indent=2, default=str))

    cff_findings = load_cff_findings(sha)
    if cff_findings:
        (ev_dir / "02-cff-findings.json").write_text(
            json.dumps(cff_findings, indent=2, default=str))

    record = {
        "source": "deep_dive_v2",
        "phase": "deep-dive",
        "sha256": sha,
        "sql_evidence": sql_evidence,
        "decompiles": decompiles,
        "behavioral": behavioral,
        "dotnet": dotnet,
        "tools": tools_results,
        "cff_findings": cff_findings,
    }
    audit_write(sha, record)

    rag_block = _reveng_rag_block(session, tools_results)
    prompt = build_prompt(session, sql_evidence, decompiles, behavioral,
                          tools_results, cff_findings=cff_findings,
                          dotnet_result=dotnet, rag_block=rag_block)
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

    # --- Deobfuscation verification (opt-in, v3 mode) ---
    # If ENABLE_DEOBFUSCATION_PASS=True, scan the LLM analysis for CFF / MBA /
    # opaque-predicate claims and verify them via Z3/angr/cff_deflatten.
    # Result is added to `analysis` so it lands in 05-deep-dive.json and is
    # visible in the Flask UI.
    if os.environ.get("ENABLE_DEOBFUSCATION_PASS", "0") == "1":
        try:
            import sys as _sys
            _sys.path.insert(0, "/opt/cadre-v3-tools/deobfuscation")
            import invoke_z3_or_angr as _iza  # noqa: E402
            # Flip the wrapper's default to True (was False) so it actually runs.
            _iza.ENABLE_DEOBFUSCATION_PASS_DEFAULT = True
            analysis_text = json.dumps(analysis, default=str).lower()
            cff_results = None
            z3_results = None
            if "dispatcher" in analysis_text or "control flow flat" in analysis_text or "cff" in analysis_text:
                cff_results = _iza.invoke_z3_or_angr(
                    "cff_dispatcher", sample_path, timeout=120,
                )
                analysis["cff_results"] = cff_results
                print(f"[deep_dive] cff_deflatten: {cff_results['result']} ({cff_results['duration_s']:.1f}s)", file=sys.stderr)
            # MBA / opaque: look for a textual claim (x^y) + 2*(x&y) == x+y etc.
            mba_match = re.search(
                r"([\w\s\^\&\|\+\-\*\(\)]{3,80}\s*==\s*[\w\s\^\&\|\+\-\*\(\)]{3,80})",
                analysis_text,
            )
            if mba_match and ("mba" in analysis_text or "obfusc" in analysis_text or "opaque" in analysis_text):
                z3_results = _iza.invoke_z3_or_angr(
                    "mba_identity", sample_path, timeout=30,
                    claim_text=mba_match.group(1).strip(),
                )
                analysis["z3_results"] = z3_results
                print(f"[deep_dive] Z3: {z3_results['result']} ({z3_results['duration_s']:.2f}s)", file=sys.stderr)
        except Exception as e:
            print(f"[deep_dive] deobfuscation hook error: {type(e).__name__}: {e}", file=sys.stderr)
            analysis["deobfuscation_error"] = f"{type(e).__name__}: {e}"

    (ev_dir / "05-deep-dive.json").write_text(json.dumps(analysis, indent=2, default=str))

    # Backward-compat: also write deep-dive.json at logs root
    root_path = LOGS_DIR / sha / "deep-dive.json"
    root_path.write_text(json.dumps(analysis, indent=2, default=str))

    # --- Auto-apply Ghidra + IDA annotations (write-back) ---
    # If confidence is high and the LLM proposed function renames,
    # apply them live to BOTH the Ghidra project (via ghidra_sql_client)
    # AND the local IDA project (via ida_sql_client).
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

        # Apply to IDA (local Remnux)
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

    from v2_lib import agentic_recover
    recovery = agentic_recover(sha, pro=args.pro, dry_run=False,
                               no_writeback=os.environ.get("AGENTIC_RECOVERY_NO_WRITEBACK") == "1")
    analysis["agentic_recovery"] = recovery

    # Re-write after adding the annotations + recovery fields
    (ev_dir / "05-deep-dive.json").write_text(json.dumps(analysis, indent=2, default=str))
    root_path.write_text(json.dumps(analysis, indent=2, default=str))

    print(f"[deep_dive_v2] -> {ev_dir}/")
    print(f"[deep_dive_v2] -> {root_path}")
    print(json.dumps({k: analysis[k] for k in ("source", "summary", "confidence") if k in analysis}, indent=2))


if __name__ == "__main__":
    main()
