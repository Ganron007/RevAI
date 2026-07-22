#!/usr/bin/env python3
"""
publish_report_v2.py — REPORT-MASTER 16-section report from v2 evidence (plan v2 T4).

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
    append_technical_evidence_appendix,
    audit_write,
    build_technical_evidence_block,
    compact_json_for_prompt,
    align_publish_markdown_to_upstream,
    cross_stage_verdict_lock,
    infer_publish_verdict_from_markdown,
    strip_accuracy_hold_banner,
    surface_verdict_sources_panel,
    dotnet_analyze,
    ensure_pipeline_runtime_env,
    get_llm_model,
    hitl_checkpoint,
    llm_judge,
    llm_call_metadata,
    load_session,
    r2_ai_decompile,
    rag_query_terms_from_tools,
    rag_enabled,
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
    if not rag_enabled():
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
                      function_recovery: dict | None = None,
                      capa_result: dict | None = None, yara_result: dict | None = None,
                      floss_result: dict | None = None, pe_imports_result: dict | None = None) -> str:
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
        compact_json_for_prompt(
            verdict or {},
            max_chars=8000,
            keep_keys=[
                "verdict", "score", "confidence", "family_guess", "summary",
                "key_evidence", "iocs", "mitre", "agreement", "accuracy_hold",
                "tool_gate", "incomplete_tooling",
            ],
        ),
        "",
        "## Evidence — deep-dive.json",
        compact_json_for_prompt(
            deep or {},
            max_chars=12000,
            keep_keys=[
                "verdict", "score", "confidence", "family_guess", "summary",
                "key_evidence", "iocs", "mitre", "checklist_ok", "sql_ok",
                "findings", "incomplete",
            ],
        ),
        "",
        "## Evidence — rule.yara.json",
        compact_json_for_prompt(yara_meta or {}, max_chars=4000),
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
    asm.add("capa", capa_result)
    asm.add("pe_imports", pe_imports_result)
    asm.add("yara", yara_result)
    asm.add("floss", floss_result)
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
    # V5.12 accuracy: publish must not clear upstream malicious/suspicious triage
    v = verdict if isinstance(verdict, dict) else {}
    upstream = (v.get("verdict") or "").strip().lower()
    yara_hits = v.get("yara_family_hits") or (v.get("accuracy_hold") or {}).get("yara_rules") or []
    if upstream in ("malicious", "suspicious") or yara_hits:
        lines.append("## ACCURACY CONSTRAINT (mandatory)")
        lines.append(
            f"- Upstream triage verdict is **{v.get('verdict') or upstream or 'malicious'}** "
            f"(family={v.get('family_guess')})."
        )
        if yara_hits:
            lines.append(f"- High-signal YARA fired: {yara_hits}.")
        lines.append(
            "- Dual-use RATs (NetSupport, AnyDesk, TeamViewer, etc.) abused in malware campaigns "
            "MUST be classified **malicious** (or at least suspicious), NOT 'legitimate' / 'clean' / 'benign'."
        )
        lines.append(
            "- You may note vendor signing and dual-use nature, but Classification.Verdict must "
            "match upstream triage. Do not clear the sample."
        )
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
        "Rules (V5.16 — evidence-first, MORE detail preferred):",
        "- This is a TECHNICAL report for reverse engineers. Prefer MORE evidence over less.",
        "- COPY tables/rows from Structured Evidence into the matching sections (do not summarize away addresses).",
        "- Every claim MUST include (source: <engine>) and an address, rule name, or table row when available.",
        "- REQUIRED embeds when present in evidence: section layout table, full IAT, capa+YARA tables,",
        "  high-signal strings WITH engine+ea, UPX stdout + unpacked_path, function metrics, EP/decompress disasm.",
        "- If Speakeasy/Frida show zero events, write 'not observed' — never invent runtime behavior.",
        "- Citation source must match the evidence engine (e.g. Malcat string ≠ IDA SQL).",
        "- Use tables heavily. Include code fences for disasm/decompilation excerpts from evidence.",
        "- Mark unknowns with '(unknown)' and why. Prefer attaching evidence over theory.",
        "- Do NOT omit the Static Code Analysis disassembly blocks that appear in Structured Evidence.",
        "",
        f"sha256: {session['sha256']}",
        f"sample_path: {session['sample_path']}",
        f"project_name: {session.get('project_name', '?')}",
        "",
        "## Structured Evidence (AUTHORITATIVE — copy into report sections)",
        technical_evidence,
        "",
        "## High-level verdict context",
        f"verdict.json: {json.dumps(verdict or {}, indent=2)[:4000]}",
        "",
        f"deep-dive.json: {json.dumps(deep or {}, indent=2)[:5000]}",
        "",
        f"rule.yara.json: {json.dumps(yara_meta or {}, indent=2)[:3000]}",
        "",
        "## Audit trail (cite source + sql where present)",
    ]
    for entry in audit[-20:]:
        slim = {k: entry[k] for k in ("source", "sql", "phase", "ts") if k in entry}
        lines.append(json.dumps(slim))
    lines.append("")
    lines.append(
        "Write analyst-grade technical content under each section. "
        "When in doubt, paste more evidence tables. "
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


def _extract_report_json(content: str) -> dict:
    """Parse LLM JSON; tolerate markdown fences / prose wrapping."""
    s = (content or "").strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    try:
        data = json.loads(s)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    start, end = s.find("{"), s.rfind("}")
    if start >= 0 and end > start:
        data = json.loads(s[start : end + 1])
        if isinstance(data, dict):
            return data
    # Raw markdown fallback
    if s.lstrip().startswith("#"):
        return {"title": "RE Report", "markdown": s, "source": "llm_raw_markdown"}
    raise ValueError(f"no JSON/markdown report in LLM content: {s[:200]!r}")


def build_deterministic_master(
    session: dict,
    verdict: dict | None,
    deep: dict | None,
    yara_meta: dict | None,
    tools_results: dict,
    *,
    reason: str,
) -> str:
    """Full REPORT-MASTER skeleton from evidence when LLM fails — never empty."""
    v = verdict or {}
    d = deep or {}
    y = yara_meta or {}
    capa = tools_results.get("capa") or {}
    yara = tools_results.get("yara") or {}
    malcat = tools_results.get("malcat") or {}
    family = v.get("family_guess") or d.get("family_guess") or "unknown"
    summary = d.get("summary") or v.get("summary") or "(no summary)"
    conf = d.get("confidence") or v.get("confidence") or "?"
    rules = capa.get("top_rules") or []
    yhits = yara.get("matches") or []
    iocs = d.get("iocs") or v.get("iocs") or []
    key_ev = d.get("key_evidence") or v.get("key_evidence") or []

    def _bullets(items, limit=12):
        if not items:
            return "- (none / unknown)\n"
        out = []
        for it in items[:limit]:
            out.append(f"- `{json.dumps(it, default=str)[:240]}`")
        return "\n".join(out) + "\n"

    sections = {
        "Executive Summary": (
            f"{summary}\n\n"
            f"- **verdict:** {v.get('verdict', '?')}\n"
            f"- **family_guess:** {family}\n"
            f"- **confidence:** {conf}\n"
            f"- **agreement:** {v.get('agreement', '?')}\n"
            f"- **fallback_reason:** {reason}\n"
        ),
        "1. Sample Identification": (
            f"- **sha256:** `{session.get('sha256')}`\n"
            f"- **path:** `{session.get('sample_path')}`\n"
            f"- **project:** {session.get('project_name', '?')}\n"
            f"- **file_type:** {json.dumps(session.get('file_type') or {}, default=str)[:500]}\n"
        ),
        "2. Classification": (
            f"- verdict: {v.get('verdict', '?')}\n"
            f"- family: {family}\n"
            f"- score: {v.get('score', v.get('numeric_score', '?'))}\n"
        ),
        "3. Initial Triage (15 minutes)": (
            f"### YARA\n{_bullets(yhits, 10)}"
            f"### capa top rules\n{_bullets(rules, 10)}"
            f"### Malcat summary\n"
            f"- anomalies: {len(malcat.get('anomalies') or [])}\n"
            f"- file_summary keys: {list((malcat.get('file_summary') or {}).keys())[:20]}\n"
        ),
        "4. Static Analysis": (
            f"{summary}\n\n### Key evidence\n{_bullets(key_ev, 15)}"
            f"### Tools present\n{_bullets([k for k in tools_results if not str(k).startswith('_')], 20)}"
        ),
        "5. Behavioral Analysis": (
            f"{json.dumps(d.get('behavioral') or d.get('behaviors') or {}, indent=2, default=str)[:4000]}\n"
        ),
        "6. Network Analysis": (
            f"IOCs / network hints:\n{_bullets(iocs if isinstance(iocs, list) else [iocs], 20)}"
        ),
        "7. Capability Assessment": f"capa rules:\n{_bullets(rules, 20)}",
        "8. MITRE ATT&CK Mapping": (
            "Derived from capa `attack` fields where present:\n"
            + _bullets(
                [
                    {"rule": r.get("name"), "attack": r.get("attack")}
                    for r in rules
                    if isinstance(r, dict) and r.get("attack")
                ],
                20,
            )
        ),
        "9. Comparison with Known Families": f"Family hypothesis: **{family}**. Validate against RAG / malpedia in follow-up.\n",
        "10. Attribution": "Attribution: (unknown) — insufficient campaign linkage in this automated pass.\n",
        "11. Indicators of Compromise": _bullets(iocs if isinstance(iocs, list) else [iocs], 30),
        "12. Detection Rules": (
            f"YARA meta / generated rule:\n```\n{json.dumps(y, indent=2, default=str)[:3000]}\n```\n"
        ),
        "13. Containment, Eradication, Recovery": (
            "1. Isolate host\n2. Block C2 / NetSupport-related egress if confirmed\n"
            "3. Collect disk+memory\n4. Rebuild from golden image\n"
        ),
        "14. Recommendations": (
            "- Block known NetSupport / SmartApeSG indicators after confirmation\n"
            "- Alert on PCICL32.dll / NSMClient32 patterns\n"
            "- Re-run deep dive after Defender re-enabled if needed\n"
        ),
        "15. Appendices": (
            f"Auto-assembled fallback report. LLM path reason: {reason}\n"
            f"deep_dive source: {d.get('source')}\n"
        ),
        "16. Author + Sign-off": (
            f"- generator: publish_report_v2 deterministic fallback\n"
            f"- sha256: `{session.get('sha256')}`\n"
            f"- generated_at: {datetime.now(timezone.utc).isoformat()}\n"
        ),
    }
    parts = [f"# RE Report — {session.get('sha256', '')[:16]}", ""]
    for title in REPORT_MASTER_SECTIONS:
        parts.append(f"# {title}")
        parts.append("")
        parts.append(sections.get(title, "(unknown)\n"))
        parts.append("")
    return "\n".join(parts)


def build_deterministic_technical(
    session: dict,
    verdict: dict | None,
    deep: dict | None,
    technical_evidence: str,
    *,
    reason: str,
) -> str:
    """Evidence-first technical report (used as fallback and completeness backstop)."""
    v = verdict or {}
    d = deep or {}
    evidence = technical_evidence or ""
    body = {
        "1. Executive Summary": (
            f"{d.get('summary') or v.get('summary') or '(unknown)'}\n\n"
            f"verdict={v.get('verdict')} score={v.get('score')} family={v.get('family_guess')}\n"
            f"(source: verdict.json / deep-dive.json)"
        ),
        "2. Sample Metadata": (
            f"| Field | Value |\n|---|---|\n"
            f"| sha256 | `{session.get('sha256')}` |\n"
            f"| path | `{session.get('sample_path')}` |\n"
            f"| project | `{session.get('project_name')}` |\n"
            f"| verdict | {v.get('verdict')} |\n"
            f"| family_guess | {v.get('family_guess')} |\n"
            f"| agreement | {v.get('agreement')} |\n\n"
            f"Full Malcat/PE metadata is in the Structured Evidence appendix."
        ),
        "3. File Layout & Structural Analysis": (
            "See **Malcat Structured Analysis → File Layout** and SQL memory_blocks/segments "
            "in the appendix. Copy those tables for review."
        ),
        "4. Malcat Triage Summary": (
            "See **Malcat Structured Analysis** (anomalies, YARA, imports, high-signal strings, "
            "decompilations, virtual files) in the appendix."
        ),
        "5. Static Code Analysis": (
            f"{d.get('summary') or '(see evidence)'}\n\n"
            "See **radare2 Disassembly**, **Ghidra / IDA SQL Evidence** (function_metrics), "
            "and Malcat decompilations in the appendix — those blocks are authoritative."
        ),
        "6. Behavioral & Dynamic Analysis": (
            "See **Speakeasy** / **Frida Probe** sections in the appendix. "
            "If api_calls/key_events are 0 → **not observed** (do not invent).\n\n"
            f"deep iocs/behaviors: {json.dumps({'behaviors': d.get('behaviors'), 'iocs': d.get('iocs')}, indent=2, default=str)[:4000]}"
        ),
        "7. Network Indicators & C2": (
            json.dumps(d.get("iocs") or [], indent=2, default=str)[:4000]
            or "(unknown — no network IOCs in deep/triage; check high-signal strings)"
        ),
        "8. Capabilities & MITRE ATT&CK Mapping": (
            "See **capa Capability Rules** and **PE Imports / Signals** tables in the appendix."
        ),
        "9. Indicators of Compromise": (
            "sha256 (sample), high-signal strings (engine+ea), YARA rule names, unpacked path if UPX.\n\n"
            f"{json.dumps(d.get('iocs') or [], indent=2, default=str)[:4000]}"
        ),
        "10. Detection Engineering": (
            "See **YARA Matches (pipeline)** + generated rule.yar / rule.yara.json in appendix."
        ),
        "11. What We Don't Know": (
            f"{reason}\n\n"
            "Also list: unpacked-payload second-pass (if UPX ok but not re-analyzed), "
            "empty Speakeasy, missing C2 confirmation."
        ),
        "12. Appendix: Analysis Environment": (
            f"Remnux publish_report_v2 @ {datetime.now(timezone.utc).isoformat()} · "
            f"evidence-first deterministic path · reason={reason}"
        ),
    }
    parts = [
        f"# Technical Report — {session.get('sha256', '')[:16]}",
        "",
        "_Evidence-first report. Full Structured Evidence Pack is appended below._",
        "",
    ]
    for title in TECHNICAL_REPORT_SECTIONS:
        parts.append(f"# {title}")
        parts.append("")
        parts.append(str(body.get(title, "(unknown)")))
        parts.append("")
    # Full evidence always included (also re-appended by finalize helper)
    parts.append("## Structured Evidence (inline)")
    parts.append("")
    parts.append(evidence)
    parts.append("")
    return "\n".join(parts)


def main():
    env_info = ensure_pipeline_runtime_env()
    print(
        f"[publish_report_v2] runtime env: rag={env_info.get('rag')} "
        f"hybrid={env_info.get('hybrid')} model={os.environ.get('REVENG_LLM_MODEL', '')}",
        flush=True,
    )
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--template", choices=("full", "triage", "ir"), default="full")
    args = ap.parse_args()

    session = load_session(args.sha256)
    verdict = load_json(LOGS / args.sha256 / "verdict.json")
    deep = load_json(LOGS / args.sha256 / "deep-dive.json")
    if not deep:
        deep = load_json(LOGS / args.sha256 / "deep_dive" / "05-deep-dive.json")
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

    capa_result = tools_results.get("capa")
    yara_result = tools_results.get("yara")
    floss_result = tools_results.get("floss")
    pe_imports_result = tools_results.get("pe_imports")

    # V5.12: RAG from tool terms — never raw verdict/benign/malicious.
    tool_terms = rag_query_terms_from_tools(tools_results)
    family = ""
    if isinstance(verdict, dict):
        family = (verdict.get("family_guess") or "").strip()
    if not family and isinstance(deep, dict):
        family = (deep.get("family_guess") or "").strip()
    # Drop family if it looks like a product brand with no tool support
    rag_parts = list(tool_terms[:12])
    if family and family.lower() not in ("unknown", "n/a", "none"):
        rag_parts.insert(0, family)
    rag_query = " ".join(rag_parts).strip()
    if not rag_query:
        rag_query = (session.get("project_name") or session.get("sha256") or "")[:64]
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
                                   function_recovery=function_recovery,
                                   capa_result=capa_result, yara_result=yara_result,
                                   floss_result=floss_result,
                                   pe_imports_result=pe_imports_result)
    elif args.template == "triage":
        prompt = build_prompt_triage(session, verdict)
    else:
        prompt = build_prompt_ir(session, verdict, deep)

    # Evidence directory
    ev_dir = LOGS / args.sha256 / "publish"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "00-prompt.txt").write_text(prompt)
    (ev_dir / "00-rag-query.txt").write_text(
        json.dumps(
            {
                "query": rag_query,
                "tool_terms": tool_terms,
                "family": family,
                "rag_enabled": rag_enabled(),
                "hybrid": rag_enabled() and str(os.environ.get("REVENG_RAG_HYBRID") or "").strip() in ("1", "true", "yes", "on"),
            },
            indent=2,
        )
    )
    print(f"[publish_report_v2] RAG query -> {ev_dir / '00-rag-query.txt'}: {rag_query[:200]}", flush=True)

    # ============================================================
    # Executive / REPORT-MASTER report
    # ============================================================
    report: dict[str, Any]
    llm_err: str | None = None
    try:
        resp = llm_judge(prompt)
        (ev_dir / "01-llm-raw.json").write_text(json.dumps(resp, indent=2, default=str))
        report = _extract_report_json(resp["choices"][0]["message"]["content"])
        meta = llm_call_metadata(resp)
        meta["request_model"] = get_llm_model()
        report["model"] = meta.get("response_model") or get_llm_model()
        report["llm_audit"] = meta
        report["source"] = report.get("source") or "llm_judge"
        report["template"] = args.template
        report["generated_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        llm_err = str(e)
        print(f"[publish_report_v2] LLM failed, using deterministic fallback: {e}", flush=True)
        md_fb = build_deterministic_master(
            session, verdict, deep, yara_meta, tools_results, reason=llm_err
        )
        report = {
            "title": f"RE Report {args.sha256[:12]}",
            "markdown": md_fb,
            "source": "deterministic_fallback",
            "template": args.template,
            "llm_error": llm_err,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    md = report.get("markdown", "") or ""
    if args.template == "full":
        missing = verify_sections(md)
        if missing:
            # Second chance: deterministic fill if LLM omitted sections
            print(
                f"[publish_report_v2] incomplete LLM report ({len(missing)} missing) "
                "→ deterministic master",
                flush=True,
            )
            md = build_deterministic_master(
                session, verdict, deep, yara_meta, tools_results,
                reason=llm_err or f"missing_sections:{missing[:3]}",
            )
            report["markdown"] = md
            report["source"] = "deterministic_fallback_after_incomplete_llm"
            missing = verify_sections(md)
        report["sections_missing"] = missing
        report["sections_complete"] = len(REPORT_MASTER_SECTIONS) - len(missing)

    # V5.12.7 / V5.12.13 — cross-stage verdict lock (honest multi-source surface)
    quick_v = (verdict or {}).get("verdict") if isinstance(verdict, dict) else None
    deep_v = (deep or {}).get("verdict") if isinstance(deep, dict) else None
    pub_claimed = report.get("verdict") or infer_publish_verdict_from_markdown(md)
    lock = cross_stage_verdict_lock(pub_claimed, quick_verdict=quick_v, deep_verdict=deep_v)
    report["rag_query"] = rag_query
    report["quick_verdict"] = quick_v
    report["deep_verdict"] = deep_v
    report["publish_llm_verdict"] = pub_claimed
    report["triage_verdict"] = lock.get("upstream") or "unknown"
    if lock.get("conflict"):
        # Lock final to triage; surface both — do not rewrite LLM prose to look unanimous
        claimed = lock.get("publish")
        upstream = lock.get("upstream") or "malicious"
        yara_rules = []
        if isinstance(verdict, dict):
            yara_rules = list(
                verdict.get("yara_family_hits")
                or (verdict.get("accuracy_hold") or {}).get("yara_rules")
                or []
            )
        family = None
        if isinstance(verdict, dict):
            family = verdict.get("family_guess")
        md = align_publish_markdown_to_upstream(
            md,
            upstream=upstream,
            family=family,
            yara_rules=yara_rules,
            publish_claimed=claimed,
            quick_verdict=quick_v,
            deep_verdict=deep_v,
        )
        final_v = upstream
        lock = cross_stage_verdict_lock(final_v, quick_verdict=quick_v, deep_verdict=deep_v)
        report["accuracy_hold"] = {
            "aligned": True,
            "transparent": True,
            "original_publish_claim": claimed,
            "upstream": upstream,
            "yara_rules": yara_rules[:12],
        }
        report["publish_claimed_verdict"] = claimed
        report["publish_llm_verdict"] = claimed
        report["markdown"] = md
        print(
            f"[publish_report_v2] VERDICT_LOCK_ALIGN: "
            f"triage={upstream} publish_llm={claimed} final={final_v} "
            f"lock_ok={lock.get('ok')} (narrative preserved)",
            flush=True,
        )
    else:
        final_v = pub_claimed or lock.get("upstream") or "unknown"
    report["final_verdict"] = final_v
    report["verdict"] = final_v  # backward-compat machine field = final locked
    report["verdict_lock"] = lock
    # Always surface multi-source table (conflict path already has a richer panel)
    if not (isinstance(report.get("accuracy_hold"), dict) and report["accuracy_hold"].get("aligned")):
        panel = surface_verdict_sources_panel(
            final_verdict=final_v,
            triage_verdict=report.get("triage_verdict"),
            quick_verdict=quick_v,
            deep_verdict=deep_v,
            publish_llm_verdict=report.get("publish_llm_verdict"),
            locked=False,
        )
        md = panel + strip_accuracy_hold_banner(md)
    report["markdown"] = md

    md_path = LOGS / args.sha256 / "REPORT-v2.md"
    md_path.write_text(md)
    (ev_dir / "02-REPORT-MASTER-v2.md").write_text(md)
    if args.template == "full":
        master_path = LOGS / args.sha256 / "REPORT-MASTER-v2.md"
        master_path.write_text(md)

    json_path = LOGS / args.sha256 / "report-v2.json"
    json_path.write_text(json.dumps(report, indent=2))
    audit_write(
        args.sha256,
        {
            "source": "publish_report_v2",
            "paths": [str(md_path), str(json_path)],
            "rag_query": rag_query[:300],
            "verdict_lock": lock,
        },
    )
    print(f"[publish_report_v2] -> {md_path} (template={args.template}) source={report.get('source')}")
    if report.get("sections_missing"):
        print(f"[publish_report_v2] missing sections: {report['sections_missing'][:5]}...")

    # ============================================================
    # Technical report (co-exists with executive report)
    # ============================================================
    tech_missing: list[str] = []
    if args.template == "full":
        sql_evidence = load_json(LOGS / args.sha256 / "deep_dive" / "00-sql-evidence.json")
        technical_evidence = build_technical_evidence_block(
            session, verdict, deep, yara_meta, tools_results, audit,
            dotnet_result=dotnet_result, r2_decomp=r2_decomp,
            r2_ai=r2_ai, frida_trace=frida_trace,
            upx=upx, xor_hits=xor_hits,
            olevba=olevba, peepdf=peepdf,
            malcat_result=malcat_result, rag_block=rag_block,
            sql_evidence=sql_evidence,
            speakeasy=tools_results.get("speakeasy"),
            frida_probe=tools_results.get("frida_probe"),
        )
        (ev_dir / "03-technical-evidence.md").write_text(technical_evidence)
        # Standalone filled evidence bundle (V5.16.6)
        (LOGS / args.sha256 / "EVIDENCE-BUNDLE.md").write_text(technical_evidence)
        prompt_tech = build_prompt_technical(
            session, verdict, deep, yara_meta, audit, technical_evidence
        )
        (ev_dir / "04-prompt-technical.txt").write_text(prompt_tech)

        technical_report: dict[str, Any]
        tech_err: str | None = None
        try:
            resp_tech = llm_judge(prompt_tech)
            (ev_dir / "05-llm-technical-raw.json").write_text(
                json.dumps(resp_tech, indent=2, default=str)
            )
            technical_report = _extract_report_json(resp_tech["choices"][0]["message"]["content"])
            meta_tech = llm_call_metadata(resp_tech)
            meta_tech["request_model"] = get_llm_model()
            technical_report["model"] = meta_tech.get("response_model") or get_llm_model()
            technical_report["llm_audit"] = meta_tech
            technical_report["source"] = technical_report.get("source") or "llm_judge"
            technical_report["template"] = "technical"
            technical_report["generated_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            tech_err = str(e)
            print(f"[publish_report_v2] technical LLM failed → deterministic: {e}", flush=True)
            technical_report = {
                "title": f"Technical Report {args.sha256[:12]}",
                "markdown": build_deterministic_technical(
                    session, verdict, deep, technical_evidence, reason=tech_err
                ),
                "source": "deterministic_fallback",
                "template": "technical",
                "llm_error": tech_err,
            }

        tech_md = technical_report.get("markdown", "") or ""
        tech_missing = verify_technical_sections(tech_md)
        if tech_missing:
            tech_md = build_deterministic_technical(
                session, verdict, deep, technical_evidence,
                reason=tech_err or f"missing_sections:{tech_missing[:3]}",
            )
            technical_report["markdown"] = tech_md
            technical_report["source"] = "deterministic_fallback_after_incomplete_llm"
            tech_missing = verify_technical_sections(tech_md)
        # V5.16: always append full evidence pack so reports cannot be theory-only
        tech_md = append_technical_evidence_appendix(tech_md, technical_evidence)
        technical_report["markdown"] = tech_md
        technical_report["evidence_appendix"] = True
        technical_report["sections_missing"] = tech_missing
        technical_report["sections_complete"] = len(TECHNICAL_REPORT_SECTIONS) - len(tech_missing)

        tech_md_path = LOGS / args.sha256 / "REPORT-TECHNICAL-v2.md"
        tech_md_path.write_text(tech_md)
        (ev_dir / "06-REPORT-TECHNICAL-v2.md").write_text(tech_md)
        tech_json_path = LOGS / args.sha256 / "report-technical-v2.json"
        tech_json_path.write_text(json.dumps(technical_report, indent=2))
        audit_write(args.sha256, {"source": "publish_report_v2_technical",
                                   "paths": [str(tech_md_path), str(tech_json_path)]})
        print(f"[publish_report_v2] -> {tech_md_path} (template=technical) source={technical_report.get('source')}")
        if technical_report.get("sections_missing"):
            print(f"[publish_report_v2] technical missing sections: {technical_report['sections_missing'][:5]}...")

    master_missing = report.get("sections_missing") or []
    ok = (not master_missing) and (args.template != "full" or not tech_missing)
    print(f"[publish_report_v2] complete ok={ok} master_missing={len(master_missing)} tech_missing={len(tech_missing) if args.template=='full' else 0}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
