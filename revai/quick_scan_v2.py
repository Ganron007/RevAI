#!/usr/bin/env python3
"""
quick_scan_v2.py — Phase 2 LLM-as-judge triage.

Prereq: intake_v2.py (stage sample first)

Usage:
  python3 /opt/scripts/quick_scan_v2.py <sha256> [--pro] [--skip-malcat]
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    LOGS_DIR,
    McpGhidraClient,
    audit_write,
    cap_rows_for_prompt,
    capa_analyze,
    floss_extract,
    get_llm_model,
    ida_query_remote,
    llm_judge,
    load_session,
    malcat_analyze,
    synthesize_verdict_v1,
    is_known_goodware,
    yara_scan,
)

MAX_ROWS = 25

GHIDRA_EVIDENCE = [
    ("func_count", "Total function count (Ghidra)", "SELECT count(*) AS funcs FROM funcs"),
    ("string_count", "Total string count (Ghidra)", "SELECT count(*) AS strings FROM strings"),
    ("imports", "Imports (Ghidra)", "SELECT name, module, address FROM imports LIMIT 50"),
    (
        "crypto_strings",
        "Suspicious strings (Ghidra)",
        "SELECT address, substr(content, 1, 100) AS s FROM strings "
        "WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' "
        "ORDER BY s LIMIT 30",
    ),
    (
        "top_complexity",
        "Top funcs by complexity (Ghidra)",
        "SELECT f.name, f.address, m.cyclomatic_complexity FROM funcs f "
        "JOIN function_metrics m ON m.func_addr = f.address "
        "ORDER BY m.cyclomatic_complexity DESC LIMIT 15",
    ),
]

IDA_EVIDENCE = [
    ("welcome", "IDA database summary", "SELECT * FROM welcome"),
    ("func_count", "Total function count (IDA)", "SELECT count(*) AS funcs FROM funcs"),
    ("string_count", "Total string count (IDA)", "SELECT count(*) AS strings FROM strings"),
    ("imports", "Imports (IDA)", "SELECT module, name FROM imports ORDER BY module, name LIMIT 50"),
    (
        "crypto_strings",
        "Suspicious strings (IDA)",
        "SELECT content, printf('0x%X', address) AS addr FROM strings "
        "WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' "
        "ORDER BY content LIMIT 30",
    ),
    (
        "top_funcs_by_size",
        "Largest functions (IDA)",
        "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 15",
    ),
]


def gather_ghidra(client: McpGhidraClient, session_id: str) -> list:
    out = []
    for key, label, sql in GHIDRA_EVIDENCE:
        try:
            r = client.ghidra_query(session_id, sql, max_rows=MAX_ROWS + 5)
            out.append({"engine": "ghidra", "key": key, "label": label, "sql": sql, "result": r})
        except Exception as e:
            out.append({"engine": "ghidra", "key": key, "label": label, "sql": sql, "error": str(e)})
    return out


def gather_ida(ida_session_id: str) -> list:
    out = []
    for key, label, sql in IDA_EVIDENCE:
        try:
            r = ida_query_remote(ida_session_id, sql)
            out.append({"engine": "ida", "key": key, "label": label, "sql": sql, "result": r})
        except Exception as e:
            out.append({"engine": "ida", "key": key, "label": label, "sql": sql, "error": str(e)})
    return out


def _reveng_rag_block(session, yara, capa, top_k: int = 3) -> str:
    """Fetch RAG context from local reveng_rag index. Env-gated by REVENG_RAG=1.

    Queries the bge-m3 / 35K index (malpedia + yara + mitre + capa + capec + mbc + aptnotes + courseware)
    using YARA family hints + capa rules as the query. Returns a context block for the LLM prompt,
    or "" if RAG is disabled / unavailable. Fail-safe: never raises.

    When REVENG_RAG_HYBRID=1, uses BM25 + dense + RRF hybrid search instead of dense-only.
    """
    import os as _os
    if not _os.environ.get("REVENG_RAG"):
        return ""
    try:
        # Build query from YARA family hints + capa rule names
        query_parts = []
        yara_obj = yara if isinstance(yara, dict) else {}
        for h in (yara_obj.get("hits") or []):
            if isinstance(h, dict):
                rule = h.get("rule") or h.get("name") or ""
                if rule:
                    query_parts.append(str(rule))
        capa_obj = capa if isinstance(capa, dict) else {}
        for r in (capa_obj.get("rules") or [])[:3]:
            if isinstance(r, dict):
                name = r.get("name") or ""
                if name:
                    query_parts.append(str(name))
        if not query_parts:
            sample_path = session.get("sample_path", "") if isinstance(session, dict) else ""
            query_parts.append(sample_path.split("\\")[-1].split("/")[-1])
        query = " ".join(query_parts)[:500].strip()
        if not query:
            return ""
        # Import + search (force NEW modules from /opt/cadre-v3-tools/rag/)
        for mod in ("reveng_rag", "rag_hybrid"):
            if mod in sys.modules:
                del sys.modules[mod]
        sys.path.insert(0, "/opt/cadre-v3-tools/rag")

        if _os.environ.get("REVENG_RAG_HYBRID"):
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


def build_prompt(session, ghidra_ev, ida_ev, capa, yara, floss, malcat) -> str:
    p = [
        "# Triage evidence",
        f"sha256: {session['sha256']}",
        f"sample_path: {session['sample_path']}",
        f"ghidra_session: {session.get('session_id')}",
        f"ida_session: {session.get('ida_session_id') or '(not loaded)'}",
        "",
        "## Ghidra SQL (capped)",
    ]
    for ev in ghidra_ev:
        p.append("### " + cap_rows_for_prompt(ev))
        p.append("")
    p.append("## IDA SQL (capped)")
    for ev in ida_ev:
        p.append("### " + cap_rows_for_prompt(ev))
        p.append("")
    p.append("### capa")
    p.append(json.dumps(capa, indent=2)[:3000])
    p.append("### yara")
    p.append(json.dumps(yara, indent=2)[:2000])
    p.append("### floss")
    p.append(json.dumps(floss, indent=2)[:2000])
    p.append("### malcat views")
    p.append(json.dumps(malcat, indent=2, default=str)[:3000])
    p.append("")
    # RAG context (env-gated)
    rag_block = _reveng_rag_block(session, yara, capa)
    if rag_block:
        p.append("## Threat-intel context (RAG — local bge-m3 index, 35K records)")
        p.append(rag_block)
        p.append("")
    # Known limitations: inject if the imports health marker says EMPTY
    try:
        import os as _os
        marker = "/opt/samples/logs/cff-detector/imports_health.log"
        if _os.path.isfile(marker):
            for line in open(marker).read().splitlines():
                if "EMPTY" in line:
                    p.append("### KNOWN LIMITATION — Ghidra imports table")
                    p.append("The Ghidra `imports` virtual table for this sample reports 0 rows. "
                             "This is a known data-source gap for mixed-mode / stripped .NET PEs — "
                             "the imports EXIST in the binary (IDA has them) but Ghidra's "
                             "virtual-table exporter doesn't surface them. Do NOT treat 0 Ghidra "
                             "imports as a signal of 'clean' or 'too small to be malware'. Your "
                             "verdict must rely on the OTHER evidence sources: IDA SQL (which "
                             "correctly lists imports), capa, yara, floss, malcat. Score and verdict "
                             "SHOULD be based on these, treating empty Ghidra imports as a "
                             "data-source gap, not a verdict signal.")
                    p.append("")
                    break
    except Exception:
        pass
    p.append("")
    p.append(
        'Return JSON: {verdict, score, family_guess, cross_engine_notes, '
        'key_evidence[{source, query_or_table, row_or_rule, why}], summary}'
    )
    return "\n".join(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--pro", action="store_true")
    ap.add_argument("--skip-malcat", action="store_true")
    args = ap.parse_args()

    session = load_session(args.sha256)
    sample = session["sample_path"]

    # Goodware fingerprint short-circuit: if sample sha256 matches a known
    # goodware baseline (busybox, openssl, etc.), skip the expensive SQL
    # queries + LLM call and emit `clean` directly. Fixes LLM FP on
    # legitimate utility software (BusyBox has cryptpw, httpd, AES/RC4,
    # Luhn checks that the LLM over-interprets as malicious).
    is_good, gw_name = is_known_goodware(sample)
    if is_good:
        verdict = {
            "verdict": "clean",
            "score": 0,
            "family_guess": None,
            "key_evidence": [{
                "source": "goodware_fingerprint",
                "query_or_table": f"/opt/samples/goodware/{args.sha256}.json",
                "row_or_rule": gw_name,
                "why": f"SHA256 matches known-good fingerprint for {gw_name}",
            }],
            "cross_engine_notes": f"Sample bypassed LLM triage: SHA256 matches {gw_name} goodware fingerprint.",
            "summary": f"Clean: SHA256 matches {gw_name} goodware fingerprint. Skipped SQL/IDA/capa/yara/floss/malcat and LLM judge.",
            "source": "goodware_fingerprint",
            "model": "deterministic",
            "prompt_tokens_approx": 0,
        }
        log_dir = LOGS_DIR / args.sha256
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "verdict.json").write_text(json.dumps(verdict, indent=2))
        print(f"[quick_scan_v2] GOODWARE_FINGERPRINT match: {gw_name} -> clean", flush=True)
        print(json.dumps(verdict, indent=2))
        return

    session_id = session["session_id"]
    ida_id = session.get("ida_session_id")

    def run_ghidra():
        c = McpGhidraClient()
        try:
            return gather_ghidra(c, session_id)
        finally:
            c.close()

    with ThreadPoolExecutor(max_workers=3) as pool:
        fg = pool.submit(run_ghidra)
        fi = pool.submit(gather_ida, ida_id) if ida_id else None
        fc = pool.submit(capa_analyze, sample)
        fy = pool.submit(yara_scan, sample)
        ff = pool.submit(floss_extract, sample)
        fm = (
            pool.submit(
                malcat_analyze,
                sample,
                ["anomalies", "strings", "imports", "yara_hits"],
            )
            if not args.skip_malcat
            else None
        )
        ghidra_ev = fg.result()
        ida_ev = fi.result() if fi else []
        capa = fc.result()
        yara = fy.result()
        floss = ff.result()
        malcat = fm.result() if fm else {"skipped": True}

    record = {
        "source": "quick_scan_v2",
        "phase": 2,
        "sha256": args.sha256,
        "session_id": session_id,
        "ida_session_id": ida_id,
        "ghidra_evidence": ghidra_ev,
        "ida_evidence": ida_ev,
        "capa": capa,
        "yara": yara,
        "floss": floss,
        "malcat": malcat,
    }
    audit_path = audit_write(args.sha256, record)

    prompt = build_prompt(session, ghidra_ev, ida_ev, capa, yara, floss, malcat)
    log_dir = audit_path.parent
    (log_dir / "prompt.txt").write_text(prompt)
    model = get_llm_model()
    llm_verdict: dict = {}
    llm_ok = False
    try:
        resp = llm_judge(prompt, model=model)
        llm_verdict = json.loads(resp["choices"][0]["message"]["content"])
        llm_verdict["source"] = "llm_judge"
        llm_verdict["model"] = model
        llm_ok = True
    except Exception as e:
        print(f"[quick_scan_v2] LLM failed: {e}; using v1 fallback only", flush=True)
    # ALWAYS run the v1 secondary opinion (rule-based, structured).
    v1_verdict = synthesize_verdict_v1({"capa": capa, "yara": yara})
    v1_verdict["source"] = "fallback_v1"
    if llm_ok:
        # Compare: agreement = same family-tier verdict.
        llm_g = (llm_verdict.get("verdict") or "").strip().lower()
        v1_g = v1_verdict.get("verdict")
        # Tier mapping: malicious=high, suspicious=mid, clean=low
        def _tier(s):
            s = (s or "").lower()
            if "malicious" in s or s in ("malware", "trojan", "backdoor", "rat"):
                return "high"
            if s == "suspicious" or "likely" in s:
                return "mid"
            if s in ("clean", "legitimate", "likely_legitimate", "benign"):
                return "low"
            return None
        agreement = _tier(llm_g) == _tier(v1_g)
        if agreement:
            verdict: dict = dict(llm_verdict)
            verdict["agreement"] = "llm_and_v1_agree"
        else:
            # Disagreement: keep the LLM as primary but expose the v1 view
            # in the report so an analyst can break the tie.  The LLM verdict
            # has richer reasoning; we log the v1 verdict for traceability.
            verdict: dict = dict(llm_verdict)
            verdict["agreement"] = "llm_v1_disagree"
            verdict["v1_verdict"] = v1_verdict
        verdict["v1_summary"] = {
            "verdict": v1_verdict.get("verdict"),
            "score": v1_verdict.get("score"),
            "findings": v1_verdict.get("findings"),
        }
    else:
        # LLM call failed entirely; fall back to v1.
        verdict = v1_verdict

    verdict_path = log_dir / "verdict.json"
    verdict_path.write_text(json.dumps(verdict, indent=2))
    print(f"[quick_scan_v2] verdict -> {verdict_path}")
    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()

