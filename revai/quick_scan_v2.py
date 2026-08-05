#!/usr/bin/env python3
"""
quick_scan_v2.py â€” Phase 2 LLM-as-judge triage (plan v2.0, uses v2_lib).

Prereq: intake_v2_full.py

Usage:
  python3 /opt/scripts/quick_scan_v2.py <sha256> [--skip-malcat]
  # --pro: prefer Pro for quick verdict (default judgment is already Pro)
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    LOGS_DIR,
    TOOL_MANIFEST,
    McpGhidraClient,
    audit_write,
    cap_rows_for_prompt,
    capa_analyze,
    ensure_pipeline_runtime_env,
    evaluate_tool_checklist,
    floss_extract,
    get_llm_model,
    ida_query_remote,
    llm_judge,
    load_session,
    malcat_analyze,
    pe_import_signals,
    apply_citation_confidence_gate,
    apply_yara_family_verdict_gate,
    package_stage_evidence,
    ti_hash_enrich,
    synthesize_verdict_v1,
    is_known_goodware,
    tool_applies_to_format,
    tool_result_ok,
    yara_scan,
    _detect_format_for_tools,
    normalize_llm_json,
)

MAX_ROWS = 25

GHIDRA_EVIDENCE = [
    ("func_count", "Total function count (Ghidra)", "SELECT count(*) AS funcs FROM funcs"),
    ("string_count", "Total string count (Ghidra)", "SELECT count(*) AS strings FROM strings"),
    (
        "imports",
        "Imports (Ghidra) from data_items",
        "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50",
    ),
    (
        "imports_resolved",
        "Imports resolved (Ghidra sidecar)",
        None,
    ),
    (
        "crypto_strings",
        "Suspicious strings (Ghidra)",
        "SELECT address, substr(content, 1, 100) AS s FROM strings "
        "WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' "
        "LIMIT 30",
    ),
]

IDA_EVIDENCE = [
    ("welcome", "IDA database summary", "SELECT * FROM welcome"),
    ("func_count", "Total function count (IDA)", "SELECT count(*) AS funcs FROM funcs"),
    ("string_count", "Total string count (IDA)", "SELECT count(*) AS strings FROM strings"),
    ("imports", "Imports (IDA)", "SELECT module, name FROM imports LIMIT 50"),
    (
        "crypto_strings",
        "Suspicious strings (IDA)",
        "SELECT content, printf('0x%X', address) AS addr FROM strings "
        "WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' "
        "LIMIT 30",
    ),
    (
        "top_funcs_by_size",
        "Largest functions (IDA)",
        "SELECT name, address, size FROM funcs LIMIT 15",
    ),
]


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


def load_ghidra_imports_sidecar(sha: str) -> list[dict]:
    """Load the resolved Ghidra imports sidecar produced by PopulateImportsFromPTR.py."""
    path = LOGS_DIR / sha / "ghidra_imports_resolved.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def gather_ghidra(client: McpGhidraClient, session_id: str, sha: str) -> list:
    out = []
    for key, label, sql in GHIDRA_EVIDENCE:
        try:
            if key == "imports_resolved":
                rows = load_ghidra_imports_sidecar(sha)
                r = {
                    "columns": ["address", "name", "module", "confidence"],
                    "rows": rows,
                    "row_count": len(rows),
                    "total_row_count": len(rows),
                    "truncated": False,
                    "source": "ghidra_imports_resolved_sidecar",
                    "session_id": session_id,
                }
                out.append({"engine": "ghidra", "key": key, "label": label, "sql": "sidecar", "result": r})
            else:
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


def load_intake_validation(sha: str) -> dict:
    """Load the intake-validation.json produced by intake_v2.py.

    Contains tool_summaries (Malcat/Ghidra/IDA), warnings, and LLM/rule-based
    source_decisions. Returns empty dict if missing or unreadable.
    """
    path = LOGS_DIR / sha / "intake-validation.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def build_prompt(session, ghidra_ev, ida_ev, capa, yara, floss, malcat,
                 intake_validation: dict | None = None, pe_imports=None,
                 ti_enrich: dict | None = None) -> str:
    intake_validation = intake_validation or {}
    source_decisions = intake_validation.get("source_decisions", {})

    p = [
        "# Triage evidence",
        f"sha256: {session['sha256']}",
        f"sample_path: {session['sample_path']}",
        f"ghidra_session: {session.get('session_id')}",
        f"ida_session: {session.get('ida_session_id') or '(not loaded)'}",
        "",
    ]

    # Source decisions from intake validation: tells the LLM which engine is
    # authoritative per evidence category, so it can weight evidence correctly.
    if source_decisions:
        p.append("## Source decisions (from intake validation)")
        for cat, decision in source_decisions.items():
            if cat == "sha256":
                continue
            if isinstance(decision, dict):
                src = decision.get("source", "?")
                conf = decision.get("confidence", "?")
                reason = decision.get("reason", "")
                p.append(f"- {cat}: {src} (confidence={conf}) — {reason}")
            else:
                p.append(f"- {cat}: {decision}")
        p.append("")

    p.append("## Ghidra SQL (capped)")
    for ev in ghidra_ev:
        p.append("### " + cap_rows_for_prompt(ev))
        p.append("")
    p.append("## IDA SQL (capped)")
    for ev in ida_ev:
        p.append("### " + cap_rows_for_prompt(ev))
        p.append("")

    # Ranked stage-tagged tool pack (primary LLM evidence path)
    sha = (session.get("sha256") if isinstance(session, dict) else "") or ""
    tool_pack = package_stage_evidence(
        "quick_scan",
        {
            "malcat": malcat,
            "capa": capa,
            "pe_imports": pe_imports,
            "yara": yara,
            "floss": floss,
        },
        budget_chars=28000,
        sha=sha,
        persist=True,
    )
    p.append(tool_pack)
    p.append("")
    # Compact raw dumps kept as secondary (capped) for citation grounding
    p.append("### capa (raw JSON, capped)")
    p.append(json.dumps(capa, indent=2)[:2000])
    p.append("### yara (raw JSON, capped)")
    p.append(json.dumps(yara, indent=2)[:1500])
    p.append("### floss (raw JSON, capped)")
    p.append(json.dumps(floss, indent=2)[:1500])
    if pe_imports is not None:
        p.append("### pe_imports (raw JSON, capped)")
        p.append(json.dumps(pe_imports, indent=2, default=str)[:1500])
    p.append("### malcat deep profile (raw JSON, capped)")
    p.append(json.dumps(malcat, indent=2, default=str)[:4000])
    p.append("")

    # If capa failed/timed out, surface Malcat capa_summary + static signals as fallback.
    # LLM must cite capa_summary / malcat fallback in key_evidence so audit can salvage.
    if isinstance(capa, dict) and capa.get("error"):
        p.append("### capa fallback — use Malcat capa_summary (REQUIRED when capa failed)")
        p.append(
            "capa returned an error. You MUST prefer Malcat `capa_summary` (or views.capa_summary) "
            "for ATT&CK/capability evidence, and cite source=`malcat` / `capa_summary` in key_evidence."
        )
        malcat_views = malcat.get("views") if isinstance(malcat, dict) else {}
        capa_summary = None
        if isinstance(malcat_views, dict):
            capa_summary = malcat_views.get("capa_summary") or malcat_views.get("capa")
        if capa_summary is None and isinstance(malcat, dict):
            capa_summary = malcat.get("capa_summary")
        if capa_summary is not None:
            p.append("#### malcat capa_summary")
            p.append(json.dumps(capa_summary, indent=2, default=str)[:4000])
        if malcat_views:
            imports = malcat_views.get("imports") or []
            high_imports = [imp.get("name", "") for imp in imports[:20] if imp.get("name")]
            if high_imports:
                p.append(f"Top Malcat imports: {', '.join(high_imports)}")
            constants = malcat.get("constants") or []
            const_vals = [c.get("id", "") for c in constants[:20] if c.get("id")]
            if const_vals:
                p.append(f"Top Malcat constants: {', '.join(str(v) for v in const_vals)}")
            anomalies = malcat.get("anomalies") or []
            anom_names = [a.get("name", "") for a in anomalies[:15] if a.get("name")]
            if anom_names:
                p.append(f"Malcat anomalies: {', '.join(anom_names)}")
        p.append("")

    # Optional external TI hash enrich (REVAI_TI_ENRICH=1) — never overrides local gates
    if isinstance(ti_enrich, dict) and ti_enrich.get("enabled") and ti_enrich.get("prompt_card"):
        p.append("## External TI (hash lookup only — optional)")
        p.append(ti_enrich["prompt_card"])
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
                             "This can be a data-source gap for mixed-mode / stripped .NET PEs. "
                             "Do NOT treat empty Ghidra imports as 'clean'. Use whichever engine "
                             "block in THIS prompt actually lists the import/string (IDA SQL, "
                             "Malcat, capa, yara, floss, pe_imports). "
                             "CRITICAL: key_evidence.source MUST be the engine section that "
                             "contains the cited row — never guess 'ida' for an import that "
                             "only appears under Ghidra/Malcat/YARA.")
                    p.append("")
                    break
    except Exception:
        pass
    p.append("")
    p.append(
        "CITATION RULE (mandatory): For every key_evidence item, set source to the "
        "exact engine that owns the fragment in the prompt (ghidra|ida|malcat|capa|"
        "floss|yara|pe_imports). Do not attribute Ghidra/Malcat rows to ida."
    )
    p.append(
        'Return JSON: {verdict, score, family_guess, cross_engine_notes, '
        'key_evidence[{source, query_or_table, row_or_rule, why}], summary}'
    )
    p.append(
        "SCORE SCALE (mandatory): score MUST be an integer 0-100. "
        "100 = definitive malicious, 0 = definitive clean. Never use a 0-10 scale."
    )
    return "\n".join(p)


def main():
    env_info = ensure_pipeline_runtime_env()
    print(f"[quick_scan_v2] runtime env: model={get_llm_model()}", flush=True)
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--pro", action="store_true", help="Use the configured verdict model for quick verdict (default)")
    ap.add_argument("--skip-malcat", action="store_true")
    args = ap.parse_args()

    session = load_session(args.sha256)
    sample = session["sample_path"]
    intake_validation = load_intake_validation(args.sha256)

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
            return gather_ghidra(c, session_id, args.sha256)
        finally:
            c.close()

    import time as _time

    def _timed(fn, *a, **kw):
        t0 = _time.time()
        try:
            r = fn(*a, **kw)
        except Exception as e:
            r = {"error": f"{type(e).__name__}: {e}"}
        if isinstance(r, dict):
            r.setdefault("duration_s", round(_time.time() - t0, 2))
        return r, round(_time.time() - t0, 2)

    fmt = _detect_format_for_tools(sample)
    floss_applies = tool_applies_to_format("floss", fmt)

    pe_imports_applies = tool_applies_to_format("pe_imports", fmt)

    # Root-cause: Remnux is ~15 Gi RAM. Ghidra headless defaults to
    # -Xmx12G (see Tools/Ghidra-Optimization.md). Running Ghidra/IDA in
    # parallel with capa/FLOSS caused SIGKILL (rc=-9) on capa/FLOSS under OOM.
    # Phase A = triage tools; Phase B = SQL engines after Phase A completes.
    print(
        "[quick_scan_v2] phase_A triage tools (capa/yara/floss/malcat) "
        "before ghidra/ida — avoid OOM with -Xmx12G",
        flush=True,
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        _capa_manifest_to = (TOOL_MANIFEST.get("capa") or {}).get("timeout")
        _floss_manifest_to = (TOOL_MANIFEST.get("floss") or {}).get("timeout")
        fc = pool.submit(_timed, capa_analyze, sample, _capa_manifest_to)
        fy = pool.submit(_timed, yara_scan, sample)
        if floss_applies:
            ff = pool.submit(_timed, floss_extract, sample, 80, _floss_manifest_to)
        else:
            ff = None
        fp = pool.submit(_timed, pe_import_signals, sample) if pe_imports_applies else None
        fm = (
            pool.submit(
                _timed,
                malcat_analyze,
                sample,
                profile="deep",
            )
            if not args.skip_malcat
            else None
        )
        capa, capa_dt = fc.result()
        yara, yara_dt = fy.result()
        if ff:
            floss, floss_dt = ff.result()
        else:
            floss, floss_dt = {
                "skipped": True,
                "fail_open": True,
                "reason": f"not_applicable:{fmt}",
                "error": f"FLOSS supports PE only (got {fmt})",
                "string_count": 0,
                "strings": [],
            }, 0.0
        if fp:
            pe_imports, pe_imports_dt = fp.result()
        else:
            pe_imports, pe_imports_dt = {
                "skipped": True,
                "reason": f"not_applicable:{fmt}",
                "engine": "pe_imports",
                "signal_count": 0,
                "signals": [],
            }, 0.0
        if fm:
            malcat, malcat_dt = fm.result()
        else:
            malcat, malcat_dt = {"skipped": True}, 0.0

    print("[quick_scan_v2] phase_B ghidra/ida after triage tools", flush=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        fg = pool.submit(run_ghidra)
        fi = pool.submit(gather_ida, ida_id) if ida_id else None
        ghidra_ev = fg.result()
        ida_ev = fi.result() if fi else []

    # Persist triage tools once — deep_dive reuses this cache (no second capa/FLOSS run).
    qs_dir = LOGS_DIR / args.sha256 / "quick_scan"
    qs_dir.mkdir(parents=True, exist_ok=True)
    tools_raw = {
        "capa": capa,
        "pe_imports": pe_imports,
        "yara": yara,
        "floss": floss,
        "malcat": malcat,
        "_format": fmt,
        "_timings": {
            "capa": capa_dt,
            "pe_imports": pe_imports_dt,
            "yara": yara_dt,
            "floss": floss_dt,
            "malcat": malcat_dt,
        },
        "_stage": "quick_scan",
    }
    (qs_dir / "00-tools-raw.json").write_text(json.dumps(tools_raw, indent=2, default=str))
    print(
        f"[quick_scan_v2] tools cache -> {qs_dir / '00-tools-raw.json'} "
        f"format={fmt} timings={tools_raw['_timings']}",
        flush=True,
    )

    # Hard gate: triage tools must be ok (no silent empty).
    # capa may soft-fail on large when malcat+pe_imports ok (not pretended green).
    # Real malcat capa_summary (if present) is evidence for LLM — does NOT mark capa ok.
    triage_required = ["capa", "yara", "floss", "malcat"]
    if pe_imports_applies:
        triage_required.append("pe_imports")
    triage_tools = {
        "capa": capa,
        "pe_imports": pe_imports,
        "yara": yara,
        "floss": floss,
        "malcat": malcat,
        "_format": fmt,
    }
    tool_gate = evaluate_tool_checklist(triage_tools, required=triage_required)
    if args.skip_malcat:
        print("[quick_scan_v2] TOOL_GATE_FAIL: --skip-malcat not allowed for audited runs", flush=True)
        tool_gate["ok"] = False
        tool_gate["hard_failures"] = list(tool_gate.get("hard_failures") or []) + ["malcat"]
    capa_salvage = False
    views = (malcat.get("views") if isinstance(malcat, dict) else {}) or {}
    capa_summary = views.get("capa_summary") or (
        malcat.get("capa_summary") if isinstance(malcat, dict) else None
    )
    # Only real capa_summary view — not functions / fns_top_list mislabel.
    if capa_summary not in (None, {}, [], "") and not tool_result_ok(capa, "capa")[0]:
        capa_salvage = True
        tool_gate["capa_salvage_available"] = True
        tool_gate["capa_still_incomplete"] = True
        print(
            "[quick_scan_v2] capa incomplete; malcat capa_summary present as EXTRA evidence "
            "(capa remains incomplete — not marked green)",
            flush=True,
        )
    if tool_gate.get("soft_failures"):
        print(
            f"[quick_scan_v2] SOFT_FAIL (large) soft_failures={tool_gate['soft_failures']}",
            flush=True,
        )
    if not tool_gate["ok"]:
        print(
            f"[quick_scan_v2] TOOL_GATE_FAIL hard_failures={tool_gate['hard_failures']}",
            flush=True,
        )

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
        "tool_gate": tool_gate,
    }
    audit_path = audit_write(args.sha256, record)

    # Optional VT/HA hash enrich (lookup only). Default OFF.
    ti_enrich = ti_hash_enrich(args.sha256)
    qs_ti = LOGS_DIR / args.sha256 / "quick_scan"
    qs_ti.mkdir(parents=True, exist_ok=True)
    (qs_ti / "ti-enrich.json").write_text(json.dumps(ti_enrich, indent=2, default=str))
    if ti_enrich.get("enabled"):
        print(
            f"[quick_scan_v2] TI enrich enabled ok={ti_enrich.get('ok')} "
            f"vt={(ti_enrich.get('providers') or {}).get('virustotal', {}).get('ok')} "
            f"ha={(ti_enrich.get('providers') or {}).get('hybrid_analysis', {}).get('ok')}",
            flush=True,
        )

    prompt = build_prompt(
        session, ghidra_ev, ida_ev, capa, yara, floss, malcat, intake_validation,
        pe_imports=pe_imports,
        ti_enrich=ti_enrich,
    )
    log_dir = audit_path.parent
    (log_dir / "prompt.txt").write_text(prompt)
    model = get_llm_model()
    llm_verdict: dict = {}
    llm_ok = False
    try:
        resp = llm_judge(prompt, model=model)
        llm_verdict = normalize_llm_json(resp["choices"][0]["message"]["content"])
        llm_verdict["source"] = "llm_judge"
        llm_verdict["model"] = model
        # Normalize score to a consistent 0-100 scale. The LLM sometimes
        # emits 0-10 ("9/10") despite the prompt; a value ≤ 10 on a verdict
        # that is clearly malicious would silently under-report confidence.
        try:
            sc = float(llm_verdict.get("score") or 0)
            if sc <= 10 and sc > 0:
                llm_verdict["score"] = int(round(sc * 10))
                llm_verdict["score_was"] = "rescaled_0_10_to_0_100"
            elif sc:
                llm_verdict["score"] = int(round(sc))
        except (TypeError, ValueError):
            llm_verdict["score"] = 0
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

    verdict["tool_gate"] = tool_gate
    if not tool_gate["ok"]:
        verdict["incomplete_tooling"] = True
    # Malcat capa_summary is EXTRA evidence only — does not make capa green.
    if capa_salvage or tool_gate.get("capa_salvage_available"):
        blob = json.dumps(verdict, default=str).lower()
        cited = any(
            n in blob
            for n in ("capa_summary", "capa fallback", "views.capa", "malcat capa")
        )
        verdict["capa_salvage"] = {
            "available": True,
            "llm_cited": cited,
            "capa_still_incomplete": True,
        }
        if not cited:
            print(
                "[quick_scan_v2] NOTE: malcat capa_summary available but LLM did not cite it "
                "(capa remains incomplete)",
                flush=True,
            )
    # V5.11: never allow high-confidence benign/clean when capa or floss incomplete.
    v_label = (verdict.get("verdict") or "").strip().lower()
    benignish = any(x in v_label for x in ("benign", "clean", "legitimate"))
    capa_incomplete = not tool_result_ok(capa, tool_name="capa")[0]
    floss_incomplete = (
        floss_applies and not tool_result_ok(floss, tool_name="floss")[0]
    )
    if benignish and (capa_incomplete or floss_incomplete or not tool_gate.get("ok")):
        verdict["incomplete_tooling"] = True
        verdict["accuracy_hold"] = {
            "reason": "benign_blocked_incomplete_capa_floss",
            "capa_incomplete": capa_incomplete,
            "floss_incomplete": floss_incomplete,
            "original_verdict": verdict.get("verdict"),
            "original_score": verdict.get("score"),
        }
        verdict["verdict"] = "suspicious"
        try:
            score = float(verdict.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        verdict["score"] = min(score, 40) if score else 40
        verdict["confidence"] = min(int(verdict.get("confidence") or 50), 40)
        print(
            "[quick_scan_v2] ACCURACY_HOLD: benign/clean blocked — capa/floss incomplete; "
            "forced suspicious",
            flush=True,
        )
    # Attach TI enrich metadata (never used to clear local gates)
    if ti_enrich.get("enabled"):
        verdict["ti_enrich"] = {
            "ok": ti_enrich.get("ok"),
            "providers": {
                k: {pk: pv for pk, pv in (v or {}).items() if pk != "raw_keys"}
                for k, v in (ti_enrich.get("providers") or {}).items()
            },
            "policy": ti_enrich.get("policy"),
        }
    # V5.12.8b — high-signal YARA (CADRE_*/family) cannot clear as clean
    apply_yara_family_verdict_gate(verdict, yara)
    if (verdict.get("accuracy_hold") or {}).get("yara_family_block"):
        print(
            f"[quick_scan_v2] ACCURACY_HOLD: YARA family gate → {verdict.get('verdict')} "
            f"rules={verdict.get('yara_family_hits')}",
            flush=True,
        )
    # V5.12.8 — high confidence requires grounded key_evidence in tool JSON
    apply_citation_confidence_gate(
        verdict,
        {
            "capa": capa, "yara": yara, "floss": floss, "malcat": malcat,
            "pe_imports": pe_imports, "ghidra": ghidra_ev, "ida": ida_ev,
            "prompt": prompt[:4000],
        },
    )
    if verdict.get("citations_ungrounded"):
        print(
            "[quick_scan_v2] ACCURACY_HOLD: high confidence capped — key_evidence ungrounded",
            flush=True,
        )
    verdict_path = log_dir / "verdict.json"
    verdict_path.write_text(json.dumps(verdict, indent=2))
    print(f"[quick_scan_v2] verdict -> {verdict_path}")
    print(json.dumps(verdict, indent=2))
    if not tool_gate["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()

