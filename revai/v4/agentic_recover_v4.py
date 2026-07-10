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
# Override with env vars for deep-dive/full recovery runs.
DEFAULT_MAX_FUNCS = int(os.environ.get("AGENTIC_RECOVERY_MAX_FUNCS", "200"))
DEFAULT_CONFIDENCE_THRESHOLD = float(os.environ.get("AGENTIC_RECOVERY_CONF_THRESHOLD", "0.7"))
DEFAULT_FUNC_CAP_PER_TIER = int(os.environ.get("AGENTIC_RECOVERY_TIER_CAP", "20"))
DEFAULT_WORKERS = int(os.environ.get("AGENTIC_RECOVERY_WORKERS", "8"))
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


def enumerate_functions(client, session_id: str, max_funcs: int) -> list[dict]:
    rows = client.ghidra_query(
        session_id,
        f"SELECT address, name, size FROM funcs ORDER BY size DESC LIMIT {max_funcs}",
        max_rows=max_funcs,
    ).get("rows", [])
    return rows


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

    if os.environ.get("ENABLE_AGENTIC_RECOVERY", "0") != "1":
        print("[agentic_recover_v4] ENABLE_AGENTIC_RECOVERY is not set; skipping.", file=sys.stderr)
        return

    sha = args.sha256
    session = load_session(sha)
    session_id = session["session_id"]
    sample_path = session["sample_path"]

    ev_dir = LOGS_DIR / sha / "agentic_recovery"
    ev_dir.mkdir(parents=True, exist_ok=True)

    model = get_llm_model()
    system_template, user_template = load_prompt_templates()

    client = McpGhidraClient()
    try:
        audit_write(sha, {"source": "agentic_recover_v4", "phase": "start", "model": model})

        # ---- Triage ----
        all_funcs = enumerate_functions(client, session_id, args.max_funcs)
        total_funcs = int(client.ghidra_query(
            session_id, "SELECT count(*) as c FROM funcs", max_rows=1
        )["rows"][0]["c"])
        if total_funcs > args.max_funcs:
            audit_write(sha, {
                "source": "agentic_recover_v4",
                "phase": "triage",
                "note": f"function cap hit: {len(all_funcs)}/{total_funcs}",
            })

        metrics = load_metrics(client, session_id)
        sig_db = SignatureDB(threshold=float(os.environ.get("AGENTIC_RECOVERY_SIG_THRESHOLD", "0.80")))
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
