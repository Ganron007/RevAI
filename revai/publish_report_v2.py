#!/usr/bin/env python3
"""
publish_report_v2.py — REPORT-MASTER 16-section report from v2 evidence.

Usage:
  python3 /opt/scripts/publish_report_v2.py <sha256> [--template full|triage|ir]

LLM model / API key / API URL / reasoning are read from environment:
  REVENG_LLM_MODEL, REVENG_LLM_API_KEY, REVENG_LLM_API_URL, REVENG_LLM_REASONING
(Fallbacks: DEEPSEEK_API_KEY, cadre.env)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    REPORT_MASTER_SECTIONS,
    TECHNICAL_REPORT_SECTIONS,
    EvidenceAssembler,
    audit_write,
    build_technical_evidence_block,
    dotnet_analyze,
    get_llm_model,
    hitl_checkpoint,
    llm_judge,
    llm_call_metadata,
    load_session,
    r2_ai_decompile,
)

LOGS = Path("/opt/samples/logs")
TEMPLATE_PATH = Path("/opt/samples/templates/REPORT-MASTER-headings.md")


def load_json(path: Path) -> dict | None:
    if path.exists():
        return json.loads(path.read_text())
    return None


def load_audit_tail(sha: str, limit: int = 40) -> list:
    audit = LOGS / sha / "audit.jsonl"
    if not audit.exists():
        return []
    out = []
    for line in audit.read_text().splitlines()[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def section_checklist() -> str:
    return "\n".join(f"- {s}" for s in REPORT_MASTER_SECTIONS)


def _reveng_rag_block(query_hint: str, top_k: int = 5) -> str:
    """Fetch RAG context from local reveng_rag index. Env-gated by REVENG_RAG=1.

    When REVENG_RAG_HYBRID=1, uses BM25 + dense + RRF hybrid search instead of
    dense-only.
    """
    if not os.environ.get("REVENG_RAG"):
        return ""
    try:
        query = (query_hint or "").strip()[:500]
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


def build_prompt_full(session: dict, verdict: dict | None, deep: dict | None, yara_meta: dict | None, audit: list,
                      dotnet_result: dict | None = None, r2_decomp: dict | None = None,
                      r2_ai: dict | None = None, frida_trace: dict | None = None,
                      upx: dict | None = None, xor_hits: dict | None = None,
                      olevba: dict | None = None, peepdf: dict | None = None,
                      malcat_result: dict | None = None, rag_block: str = "",
                      function_recovery: dict | None = None) -> str:
    lines = [
        "# Publish report v2 — REPORT-MASTER (16 sections)",
        "",
        "You MUST produce markdown with ALL of these level-1 headings (exact titles):",
        section_checklist(),
        "",
        f"sha256: {session['sha256']}",
        f"sample_path: {session['sample_path']}",
        f"project_name: {session.get('project_name', '?')}",
        "",
        "## Evidence — triage verdict.json",
        json.dumps(verdict or {}, indent=2)[:8000],
        "",
        "## Evidence — deep-dive.json",
        json.dumps(deep or {}, indent=2)[:12000],
        "",
        "## Evidence — rule.yara.json",
        json.dumps(yara_meta or {}, indent=2)[:4000],
        "",
        "## Audit trail (cite source + sql where present)",
    ]
    for entry in audit:
        slim = {k: entry[k] for k in ("source", "sql", "phase", "ts") if k in entry}
        lines.append(json.dumps(slim))
    lines.append("")
    if upx is not None:
        lines.append("## Evidence — UPX unpack")
        lines.append(json.dumps(upx, indent=2, default=str)[:1500])
        lines.append("")
    if xor_hits is not None:
        lines.append("## Evidence — xorsearch (XOR'd string recovery)")
        lines.append(json.dumps(xor_hits, indent=2, default=str)[:1500])
        lines.append("")
    if olevba is not None:
        lines.append("## Evidence — olevba (Office VBA macros)")
        lines.append(json.dumps(olevba, indent=2, default=str)[:2000])
        lines.append("")
    if peepdf is not None:
        lines.append("## Evidence — peepdf (PDF structure + JS + embedded files)")
        lines.append(json.dumps(peepdf, indent=2, default=str)[:2000])
        lines.append("")
    if dotnet_result is not None:
        lines.append("## Evidence — .NET analysis (dnfile + monodis)")
        if dotnet_result.get("is_dotnet"):
            lines.append(f"  runtime: {dotnet_result.get('runtime_version', '?')}")
            lines.append(f"  assembly: {dotnet_result.get('assembly_name') or dotnet_result.get('module_name', '?')}")
            lines.append(f"  language: {dotnet_result.get('language_hint', '?')}")
            if dotnet_result.get('suspicious_native_refs'):
                lines.append(f"  SUSPICIOUS native modules: {dotnet_result['suspicious_native_refs']}")
            if dotnet_result.get('suspicious_methods'):
                lines.append(f"  SUSPICIOUS methods: {dotnet_result['suspicious_methods']}")
            if dotnet_result.get('interesting_pinvoke'):
                lines.append(f"  P/Invoke DLLs: {dotnet_result['interesting_pinvoke']}")
            if dotnet_result.get('pinvoke_imports'):
                lines.append(f"  P/Invoke functions: {dotnet_result['pinvoke_imports'][:20]}")
            if dotnet_result.get('has_suppress_ildasm'):
                lines.append("  ⚠ SuppressIldasmAttribute present (anti-RE)")
            if dotnet_result.get('shellcode_embed_hint'):
                lines.append("  ⚠ Shellcode-embed pattern detected")
            il_excerpt = (dotnet_result.get("il_excerpt") or "")[:2000]
            if il_excerpt:
                lines.append("")
                lines.append("```il")
                lines.append(il_excerpt)
                lines.append("```")
        else:
            lines.append("  (not a .NET assembly)")
        lines.append("")
    if r2_decomp is not None and r2_decomp.get("disassembly"):
        lines.append(f"## Evidence — r2 disassembly ({r2_decomp.get('engine','pdf (asm)')})")
        for addr, body in list(r2_decomp["disassembly"].items())[:3]:
            lines.append(f"### {addr}")
            lines.append("```asm")
            lines.append(body[:2500])
            lines.append("```")
            lines.append("")
    if r2_ai is not None and r2_ai.get("explanations"):
        lines.append("## Evidence — r2ai / decai (AI-assisted decompilation)")
        for addr, body in list(r2_ai["explanations"].items())[:2]:
            lines.append(f"### {addr}")
            lines.append(body[:2500])
            lines.append("")
    if frida_trace is not None and frida_trace.get("frida_stdout"):
        lines.append("## Evidence — Frida runtime trace")
        lines.append("```")
        lines.append((frida_trace.get("frida_stdout") or "")[:2000])
        lines.append("```")
        lines.append("")
    # --- EvidenceAssembler: signal-prioritized tool cards within a budget ---
    asm = EvidenceAssembler(budget_chars=60000)
    asm.add("malcat", malcat_result)
    asm.add("dotnet", dotnet_result)
    asm.add("r2", r2_decomp)
    asm.add("upx", upx)
    asm.add("xor", xor_hits)
    asm.add("olevba", olevba)
    asm.add("peepdf", peepdf)
    if asm.cards:
        lines.append(asm.render())
        lines.append("")
    if rag_block:
        asm2 = EvidenceAssembler(budget_chars=20000)
        added = asm2.add_rag(rag_block)
        if added:
            lines.append("## Threat-intel context (RAG — local bge-m3 index, 35K records)")
            lines.append(asm2.cards[-1][1])
            lines.append("")
    if function_recovery is not None:
        lines.append("## Evidence — agentic function recovery (v4)")
        rec_out = {
            "triage": function_recovery.get("triage"),
            "llm_calls": function_recovery.get("llm_calls"),
            "signature_matches": function_recovery.get("triage", {}).get("signature_matches"),
            "top_recovered": sorted(
                [r for r in function_recovery.get("function_results", [])
                 if r.get("confidence", 0) >= 0.7 and not r.get("function_name", "").startswith("FUN_")],
                key=lambda x: x.get("confidence", 0),
                reverse=True,
            )[:15],
            "proposed_struct_count": len(function_recovery.get("synthesis", {}).get("proposed_structs", [])),
            "writeback": function_recovery.get("writeback"),
        }
        lines.append(json.dumps(rec_out, indent=2, default=str)[:6000])
        lines.append("")
    lines.append(
        "Write analyst-grade content under each section. Use tables where appropriate. "
        "Mark unknowns explicitly. Cite evidence as (source: ghidra_query / capa / yara / speakeasy). "
        'Return JSON: {"title": "...", "markdown": "<full report>", "sections_present": ["..."]}'
    )
    return "\n".join(lines)


def build_prompt_triage(session: dict, verdict: dict | None) -> str:
    v = verdict or {}
    return f"""Write a 15-minute triage drill markdown for {session['sample_path']}.
Verdict: {json.dumps(v, indent=2)[:4000]}
Return JSON: {{"title": "...", "markdown": "..."}}"""


def build_prompt_ir(session: dict, verdict: dict | None, deep: dict | None) -> str:
    return f"""Write an IR playbook markdown with phases: Detection, Containment, Eradication, Recovery, Lessons Learned.
Sample: {session['sha256']}
Verdict: {json.dumps(verdict or {}, indent=2)[:3000]}
Deep dive excerpt: {json.dumps(deep or {}, indent=2)[:4000]}
Return JSON: {{"title": "...", "markdown": "..."}}"""


def build_prompt_technical(session: dict, verdict: dict | None, deep: dict | None,
                           yara_meta: dict | None, audit: list,
                           technical_evidence: str) -> str:
    """Build a prompt for a technical analyst-grade report with evidence snippets."""
    lines = [
        "# Technical Malware Analysis Report v2",
        "",
        "You MUST produce markdown with ALL of these level-1 headings (exact titles):",
        "\n".join(f"- {s}" for s in TECHNICAL_REPORT_SECTIONS),
        "",
        "Rules:",
        "- This is a TECHNICAL report, not an executive summary. Every claim must be supported by an evidence snippet.",
        "- Use tables for structured data (metadata, IOCs, ATT&CK mapping, capabilities).",
        "- Include code snippets, decompilation excerpts, disassembly, strings, or constants where relevant.",
        "- Cite evidence as (source: malcat / capa / yara / ghidra_query / r2 / dotnet / RAG / etc.).",
        "- Do NOT dump raw JSON. Present only the relevant, human-readable excerpt.",
        "- Mark unknowns explicitly with '(unknown)' and explain why.",
        "",
        f"sha256: {session['sha256']}",
        f"sample_path: {session['sample_path']}",
        f"project_name: {session.get('project_name', '?')}",
        "",
        "## Structured Evidence",
        technical_evidence,
        "",
        "## High-level verdict context",
        f"verdict.json: {json.dumps(verdict or {}, indent=2)[:2000]}",
        "",
        f"deep-dive.json: {json.dumps(deep or {}, indent=2)[:3000]}",
        "",
        f"rule.yara.json: {json.dumps(yara_meta or {}, indent=2)[:2000]}",
        "",
        "## Audit trail (cite source + sql where present)",
    ]
    for entry in audit[-20:]:
        slim = {k: entry[k] for k in ("source", "sql", "phase", "ts") if k in entry}
        lines.append(json.dumps(slim))
    lines.append("")
    lines.append(
        "Write analyst-grade technical content under each section. "
        'Return JSON: {"title": "...", "markdown": "<full report>", "sections_present": ["..."]}'
    )
    return "\n".join(lines)


def verify_sections(md: str) -> list[str]:
    missing = []
    for s in REPORT_MASTER_SECTIONS:
        key = s.split(".", 1)[-1].strip() if s[0].isdigit() else s
        if key.lower() not in md.lower() and s.lower() not in md.lower():
            missing.append(s)
    return missing


def verify_technical_sections(md: str) -> list[str]:
    missing = []
    for s in TECHNICAL_REPORT_SECTIONS:
        key = s.split(".", 1)[-1].strip() if s[0].isdigit() else s
        if key.lower() not in md.lower() and s.lower() not in md.lower():
            missing.append(s)
    return missing



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--template", choices=("full", "triage", "ir"), default="full")
    args = ap.parse_args()

    session = load_session(args.sha256)
    verdict = load_json(LOGS / args.sha256 / "verdict.json")
    deep = load_json(LOGS / args.sha256 / "deep-dive.json")
    yara_meta = load_json(LOGS / args.sha256 / "rule.yara.json")
    sample_path = session.get("sample_path", "")

    # Deep-dive tools raw evidence: prefer already-saved pack, else run now
    tools_raw_deep = load_json(LOGS / args.sha256 / "deep_dive" / "01-tools-raw.json")
    tools_raw_quick = load_json(LOGS / args.sha256 / "quick_scan" / "00-tools-raw.json")
    tools_results = tools_raw_deep or tools_raw_quick or {}

    dotnet_result = tools_results.get("dotnet") or dotnet_analyze(sample_path)
    upx = tools_results.get("upx")
    xor_hits = tools_results.get("xor")
    olevba = tools_results.get("olevba")
    peepdf = tools_results.get("peepdf")
    r2_decomp = tools_results.get("r2_decomp")
    r2_ai = tools_results.get("r2_ai_decompile") or tools_results.get("r2_ai")
    malcat_result = tools_results.get("malcat")

    # Fill in r2_ai if missing (not in TOOL_MANIFEST yet)
    if r2_ai is None:
        try:
            r2_ai = r2_ai_decompile(sample_path, ["0x401000"])
        except Exception as e:
            r2_ai = {"error": str(e)}

    frida_trace = None  # full Frida instrumentation requires running the sample in a sandbox
    audit = load_audit_tail(args.sha256)

    # Build RAG query from verdict family + key evidence
    rag_query_parts = []
    if verdict:
        rag_query_parts.append(verdict.get("family_guess") or "")
        rag_query_parts.append(verdict.get("verdict") or "")
    if deep:
        rag_query_parts.append(deep.get("family_guess") or "")
    rag_query = " ".join(p for p in rag_query_parts if p).strip()
    rag_block = _reveng_rag_block(rag_query)

    function_recovery = load_json(LOGS / args.sha256 / "function_recovery.json")

    hitl_checkpoint("publish_report_v2", "pre_llm", {"template": args.template})

    if args.template == "full":
        prompt = build_prompt_full(session, verdict, deep, yara_meta, audit,
                                   dotnet_result=dotnet_result, r2_decomp=r2_decomp,
                                   r2_ai=r2_ai, frida_trace=frida_trace,
                                   upx=upx, xor_hits=xor_hits,
                                   olevba=olevba, peepdf=peepdf,
                                   malcat_result=malcat_result, rag_block=rag_block,
                                   function_recovery=function_recovery)
    elif args.template == "triage":
        prompt = build_prompt_triage(session, verdict)
    else:
        prompt = build_prompt_ir(session, verdict, deep)

    # Evidence directory
    ev_dir = LOGS / args.sha256 / "publish"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "00-prompt.txt").write_text(prompt)

    # ============================================================
    # Executive / REPORT-MASTER report
    # ============================================================
    report: dict[str, Any]
    try:
        resp = llm_judge(prompt)
        (ev_dir / "01-llm-raw.json").write_text(json.dumps(resp, indent=2, default=str))
        report = json.loads(resp["choices"][0]["message"]["content"])
        meta = llm_call_metadata(resp)
        meta["request_model"] = get_llm_model()
        report["model"] = meta.get("response_model") or get_llm_model()
        report["llm_audit"] = meta
        report["source"] = "llm_judge"
        report["template"] = args.template
        report["generated_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        report = {
            "title": f"RE Report {args.sha256[:12]}",
            "markdown": f"# Report\n\nLLM failed: {e}\n\n## Executive Summary\n\nSee verdict.json.\n",
            "source": "fallback",
            "template": args.template,
        }

    md = report.get("markdown", "")
    if args.template == "full":
        missing = verify_sections(md)
        report["sections_missing"] = missing
        report["sections_complete"] = len(REPORT_MASTER_SECTIONS) - len(missing)

    md_path = LOGS / args.sha256 / "REPORT-v2.md"
    md_path.write_text(md)
    (ev_dir / "02-REPORT-MASTER-v2.md").write_text(md)
    if args.template == "full":
        master_path = LOGS / args.sha256 / "REPORT-MASTER-v2.md"
        master_path.write_text(md)

    json_path = LOGS / args.sha256 / "report-v2.json"
    json_path.write_text(json.dumps(report, indent=2))
    audit_write(args.sha256, {"source": "publish_report_v2", "paths": [str(md_path), str(json_path)]})
    print(f"[publish_report_v2] -> {md_path} (template={args.template})")
    if report.get("sections_missing"):
        print(f"[publish_report_v2] missing sections: {report['sections_missing'][:5]}...")

    # ============================================================
    # Technical report (co-exists with executive report)
    # ============================================================
    if args.template == "full":
        technical_evidence = build_technical_evidence_block(
            session, verdict, deep, yara_meta, tools_results, audit,
            dotnet_result=dotnet_result, r2_decomp=r2_decomp,
            r2_ai=r2_ai, frida_trace=frida_trace,
            upx=upx, xor_hits=xor_hits,
            olevba=olevba, peepdf=peepdf,
            malcat_result=malcat_result, rag_block=rag_block,
        )
        (ev_dir / "03-technical-evidence.md").write_text(technical_evidence)
        prompt_tech = build_prompt_technical(
            session, verdict, deep, yara_meta, audit, technical_evidence
        )
        (ev_dir / "04-prompt-technical.txt").write_text(prompt_tech)

        technical_report: dict[str, Any]
        try:
            resp_tech = llm_judge(prompt_tech)
            (ev_dir / "05-llm-technical-raw.json").write_text(
                json.dumps(resp_tech, indent=2, default=str)
            )
            technical_report = json.loads(resp_tech["choices"][0]["message"]["content"])
            meta_tech = llm_call_metadata(resp_tech)
            meta_tech["request_model"] = get_llm_model()
            technical_report["model"] = meta_tech.get("response_model") or get_llm_model()
            technical_report["llm_audit"] = meta_tech
            technical_report["source"] = "llm_judge"
            technical_report["template"] = "technical"
            technical_report["generated_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            technical_report = {
                "title": f"Technical Report {args.sha256[:12]}",
                "markdown": f"# Technical Report\n\nLLM failed: {e}\n\nSee REPORT-v2.md.\n",
                "source": "fallback",
                "template": "technical",
            }

        tech_md = technical_report.get("markdown", "")
        missing_tech = verify_technical_sections(tech_md)
        technical_report["sections_missing"] = missing_tech
        technical_report["sections_complete"] = len(TECHNICAL_REPORT_SECTIONS) - len(missing_tech)

        tech_md_path = LOGS / args.sha256 / "REPORT-TECHNICAL-v2.md"
        tech_md_path.write_text(tech_md)
        (ev_dir / "06-REPORT-TECHNICAL-v2.md").write_text(tech_md)
        tech_json_path = LOGS / args.sha256 / "report-technical-v2.json"
        tech_json_path.write_text(json.dumps(technical_report, indent=2))
        audit_write(args.sha256, {"source": "publish_report_v2_technical",
                                   "paths": [str(tech_md_path), str(tech_json_path)]})
        print(f"[publish_report_v2] -> {tech_md_path} (template=technical)")
        if technical_report.get("sections_missing"):
            print(f"[publish_report_v2] technical missing sections: {technical_report['sections_missing'][:5]}...")


if __name__ == "__main__":
    main()
