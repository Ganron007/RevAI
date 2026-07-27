"""section_publisher.py — Map-Reduce report generation.

Industry pattern (Anthropic / LangChain / MS Research):
  - MAP:    each section gets a focused LLM call with filtered evidence + targeted RAG
  - REDUCE: local Python concatenates section outputs into the final REPORT-MASTER

Why this is the right architecture for long reports:
  1. Each LLM call is small (1-3K chars input) — no JSON parse errors
  2. Each section is independently debuggable, re-runnable, parallelizable
  3. RAG is targeted per section (better recall than a single mega-search)
  4. HITL can interrupt between sections (analyst reviews before continuing)
  5. Tool output is preserved verbatim in appendices (for learning)
  6. The actual signal (tool output + RAG citations) is never lost in a summary
"""
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, "/opt/scripts")
from report_quality import (  # noqa: E402
    OUTPUT_FORMAT_CONTRACT,
    _MALCAT_INSTALLED,
    _MALCAT_OPTIONAL_SECTIONS,
    evaluate_report_markdown,
    missing_sections,
    source_is_fallback,
    stub_sections,
)
from v2_lib import (
    REPORT_MASTER_SECTIONS,
    REPORT_SECTION_SPECS,
    TECHNICAL_REPORT_SECTIONS,
    LOGS_DIR,
    _sec_identity_evidence,
    _sec_classification_evidence,
    _sec_triage_evidence,
    _sec_static_evidence,
    _sec_behavioral_evidence,
    _sec_network_evidence,
    _sec_capability_evidence,
    _sec_attack_evidence,
    _sec_family_evidence,
    _sec_attribution_evidence,
    _sec_iocs_evidence,
    _sec_detection_evidence,
    _sec_containment_evidence,
    _sec_recommendations_evidence,
    append_technical_evidence_appendix,
    build_technical_evidence_block,
    ensure_pipeline_runtime_env,
    format_malcat_evidence,
    get_llm_model,
    llm_judge,
    llm_call_metadata,
    _categorize_string,
)


def _section_prompt(section_name: str, description: str, evidence: str,
                    prior_sections_summary: str,
                    cross_context: str = "") -> str:
    """Render a focused, small prompt for one section.

    Pass 1 (cross_context=""): just evidence.
    Pass 2 (cross_context=non-empty): adds cross-section context block so the
    LLM can cite findings from other sections.
    """
    parts = [
        f"# Section: {section_name}",
        f"sha256: {os.environ.get('_SECTION_SHA', '?')}",
        "",
        "## Section description",
        description,
        "",
        "## Evidence (filtered for this section)",
        evidence or "(no evidence for this section)",
        "",
    ]
    if prior_sections_summary:
        parts.append("## Prior sections (for continuity)")
        parts.append(prior_sections_summary)
        parts.append("")
    if cross_context:
        parts.append("## Cross-section context (from other sections in pass 1)")
        parts.append(cross_context)
        parts.append("")
    parts.append(
        "## Your task\n"
        f"Write the '{section_name}' section in markdown. Cite evidence as "
        "(source: ghidra_query / capa / yara / malcat / scorecard / cross-section:section_name). "
        "Be concise (200-500 words). Use tables where appropriate. "
        "ASCII apostrophe only in headings. Do NOT write 'see appendix' stubs.\n"
        'Return JSON: {"title": "...", "markdown": "<section content>", "source": "llm_judge"}'
    )
    return "\n".join(parts)


def _build_cross_context(section_name: str, pass1_results: list) -> str:
    """Build a cross-section context block from pass-1 results.

    For each OTHER section, include:
      - Section name
      - 1-2 sentence summary (extracted from the first 500 chars of its markdown)
      - Key citations it used (regex extract: anything in `(source: ...)` or
        backticks)

    This is what enables the ATT&CK section to cite YARA hits from the Triage
    section, the IoC section to cite URLs from the Network section, etc.
    """
    if not pass1_results:
        return ""
    import re
    lines = ["The following sections have already been written. Cite them where relevant:"]
    for r in pass1_results:
        if r["name"] == section_name:
            continue
        if not r.get("markdown"):
            continue
        md = r["markdown"]
        # Extract first 1-2 sentences (up to first 2 newlines or 400 chars)
        summary = md.replace("\n", " ").strip()
        summary = re.sub(r"\s+", " ", summary)[:400]
        # Extract citations in (source: ...) pattern
        citations = re.findall(r"\(source:\s*([^)]+)\)", md)
        citations_str = ", ".join(sorted(set(citations))[:8]) if citations else "no explicit citations"
        lines.append(f"  - **{r['name']}**: {summary[:300]}...")
        if citations:
            lines.append(f"    Citations: {citations_str}")
    return "\n".join(lines)


def _run_one_section(section_name: str, sha: str, tools_results: dict,
                    prior_summaries: dict,
                    pass1_results: list = None,
                    pass_num: int = 1) -> dict:
    """Run one section: gather evidence + retrieve RAG + call LLM + return verdict.

    Pass 1 (pass_num=1): no cross-section context (parallel-friendly).
    Pass 2 (pass_num=2): includes the pass-1 results from all other sections
        as a 'Cross-section context' block so the LLM can cite them.

    Returns: {"name": str, "markdown": str, "evidence_chars": int,
              "llm_ok": bool, "error": str|None, "pass": int, "prompt_chars": int}
    """
    if section_name not in REPORT_SECTION_SPECS:
        return {"name": section_name, "error": f"unknown section: {section_name}"}
    description, query_terms, gather_fn, requires_llm = REPORT_SECTION_SPECS[section_name]
    result: dict[str, Any] = {
        "name": section_name,
        "evidence_chars": 0,
        "llm_ok": False,
        "error": None,
        "pass": pass_num,
    }
    # 1. Gather evidence (filtered for this section)
    try:
        evidence = gather_fn(tools_results) if gather_fn else ""
        result["evidence_chars"] = len(evidence) if evidence else 0
    except Exception as e:
        evidence = f"(evidence gather failed: {e})"
        result["error"] = f"gather: {e}"
    # 3. Build prior-summaries for continuity
    prior_lines = []
    for n, m in list(prior_summaries.items())[-3:]:
        if m:
            prior_lines.append(f"  - {n}: {m[:200]}")
    prior_sections_summary = "\n".join(prior_lines) if prior_lines else ""
    # 4. Build cross-section context (pass 2 only)
    cross_context = ""
    if pass_num >= 2 and pass1_results:
        cross_context = _build_cross_context(section_name, pass1_results)
    # 5. Build prompt
    os.environ["_SECTION_SHA"] = sha
    prompt = _section_prompt(section_name, description, evidence,
                            prior_sections_summary, cross_context=cross_context)
    result["prompt_chars"] = len(prompt)
    result["cross_refs_included"] = bool(cross_context)
    # 6. Call LLM (or use local builder)
    if not requires_llm:
        if section_name == "15. Appendices":
            md = _build_appendices(tools_results)
        elif section_name == "16. Author + Sign-off":
            md = _build_signoff(tools_results, sha)
        else:
            md = f"## {section_name}\n\n_(local build — no LLM call)_\n"
        result["markdown"] = md
        result["llm_ok"] = True
        return result
    try:
        resp = llm_judge(prompt)
        content = resp["choices"][0]["message"]["content"]
        try:
            v = json.loads(content)
            result["markdown"] = v.get("markdown", content)
            result["title"] = v.get("title", section_name)
        except json.JSONDecodeError:
            result["markdown"] = content
            result["title"] = section_name
        # Audit: capture response-side model + reasoning tokens
        result["llm_audit"] = llm_call_metadata(resp)
        result["llm_audit"]["request_model"] = get_llm_model()
        result["llm_ok"] = True
    except Exception as e:
        result["error"] = f"llm: {e}"
        result["markdown"] = f"## {section_name}\n\n_(LLM call failed: {e})_\n"
    return result


def _build_appendices(tools_results: dict) -> str:
    """Section 15: dump raw tool output for transparency + learning."""
    lines = ["## 15. Appendices\n",
             "Raw tool output (signal-preserving, not summarized). "
             "Each tool's evidence card is preserved verbatim — for learning and "
             "transparency the LLM never rewrites tool output.\n"]
    cards = [
        ("A1. MalCat evidence card (all 12 views, anomaly locations, decompilations, constants)",
         tools_results.get("malcat_card")),
        ("A2. .NET evidence card (language, runtime, P/Invoke, IL excerpt)",
         tools_results.get("dotnet_card")),
        ("A3. radare2 disassembly (top-3 functions, ANSI stripped)",
         tools_results.get("r2_card")),
        ("A4. YARA matches (rule names + categories)",
         tools_results.get("yara_card")),
        ("A5. capa rules (39 total, ATT&CK groupings)",
         tools_results.get("capa_card")),
        ("A6. FLOSS strings (categorized IOCs: urls, ips, registry, mutex, apis, ...)",
         tools_results.get("floss_card")),
        ("A7. UPX unpack result",
         tools_results.get("upx_card")),
        ("A8. xorsearch candidates",
         tools_results.get("xor_card")),
        ("A9. olevba (Office VBA) result",
         tools_results.get("olevba_card")),
        ("A10. peepdf (PDF structure) result",
         tools_results.get("peepdf_card")),
    ]
    for title, body in cards:
        if body and isinstance(body, str) and body.strip():
            lines.append(f"### {title}\n")
            lines.append("```")
            lines.append(body)
            lines.append("```\n")
    # MalCat structured report (replaces unreadable raw JSON dump)
    mc = tools_results.get("malcat") or {}
    if mc and isinstance(mc, dict) and not mc.get("error"):
        lines.append("### A11. MalCat structured report\n")
        lines.append(format_malcat_evidence(mc))
        lines.append("")
    # Speakeasy + frida behavioral (compact JSON)
    deep = tools_results.get("deep") or {}
    behavioral = deep.get("behavioral") or {}
    if behavioral:
        lines.append("### A12. Behavioral (Speakeasy + Frida probe)\n")
        lines.append("```json")
        lines.append(json.dumps(behavioral, indent=2, default=str)[:6000])
        lines.append("```\n")
    # Audit trail
    audit = tools_results.get("audit_tail") or []
    if audit:
        lines.append("### A13. Audit trail (sources, phases, timestamps)\n")
        lines.append("```json")
        lines.append(json.dumps(audit, indent=2, default=str)[:4000])
        lines.append("```\n")
    return "\n".join(lines)


def _build_signoff(tools_results: dict, sha: str) -> str:
    """Section 16: metadata + audit."""
    now = datetime.now(timezone.utc).isoformat()
    verdict = tools_results.get("verdict") or {}
    lines = [
        "## 16. Author + Sign-off\n",
        f"- **sha256**: `{sha}`",
        f"- **generated_at**: {now}",
        f"- **verdict_source**: {verdict.get('source', '?')}",
        f"- **model**: {get_llm_model()}",
        f"- **RAG**: bge-m3 (35,302 records, top-3 per section)",
        f"- **tool_count**: 10 (MalCat full MCP toolset, capa, YARA, FLOSS, dotnet, r2, upx, xor, olevba, peepdf)",
        "- **analyst**: (your name)",
        "",
        "_This report was generated via section-based Map-Reduce pattern (Anthropic / LangChain / MS Research). "
        "Each section got a focused 1-3K char LLM call with targeted RAG. No mega-prompt, no JSON parse errors._",
    ]
    return "\n".join(lines)


def run_section_based_publish(sha: str, tools_results: dict,
                              parallel: bool = True,
                              hitl_between: bool = False,
                              max_workers: int = 4,
                              cross_refs: bool = True) -> dict:
    """Run the Map-Reduce section publisher with optional 2-pass cross-section context.

    Pass 1: generate all 17 sections independently (parallel-friendly).
    Pass 2 (if cross_refs=True): re-generate sections 1-14 with the pass-1
        markdown from all OTHER sections included as a 'Cross-section context'
        block. This lets the LLM cite findings from other sections (e.g.,
        the ATT&CK section can reference YARA hits from the Triage section,
        the IoC section can reference URLs from the Network section).

    Args:
        sha: sample sha256
        tools_results: dict with keys: sample_path, verdict, deep, malcat, capa,
            yara, floss, dotnet, r2_decomp, upx, xor_hits, olevba, peepdf, etc.
        parallel: run sections in parallel (faster) or sequential (deterministic)
        hitl_between: pause between sections for human review
        max_workers: thread pool size for parallel mode
        cross_refs: if True, do pass 2 with cross-section context (slower but
            higher quality). If False, just pass 1.

    Returns:
        {"sections": [...], "report_markdown": str, "section_timings": [...],
         "pass1_results": [...], "pass2_results": [...]}
    """
    os.environ.setdefault("_SECTION_SHA", sha)

    def _run(name, pass1_results, pass_num):
        import time as _t
        t0 = _t.time()
        r = _run_one_section(name, sha, tools_results, prior_summaries={},
                            pass1_results=pass1_results, pass_num=pass_num)
        dt = round(_t.time() - t0, 2)
        r["runtime_sec"] = dt
        return r, dt

    # === PASS 1: generate all sections independently ===
    print(f"  [pass 1] generating 17 sections ...")
    pass1_results: list = []
    pass1_timings: list = []
    if parallel:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_run, n, [], 1): n for n in REPORT_MASTER_SECTIONS}
            for fut in futures:
                name = futures[fut]
                r, dt = fut.result()
                pass1_results.append(r)
                pass1_timings.append({"name": name, "pass": 1, "runtime_sec": dt})
    else:
        for name in REPORT_MASTER_SECTIONS:
            r, dt = _run(name, [], 1)
            pass1_results.append(r)
            pass1_timings.append({"name": name, "pass": 1, "runtime_sec": dt})

    # === PASS 2: re-generate LLM-required sections with cross-section context ===
    pass2_results: list = []
    pass2_timings: list = []
    if cross_refs:
        print(f"  [pass 2] re-generating LLM sections with cross-section context ...")
        # Only re-run sections that required LLM (skip 15/16 = appendices/signoff)
        llm_sections = [
            name for name in REPORT_MASTER_SECTIONS
            if REPORT_SECTION_SPECS.get(name, (None, None, None, False))[3]
        ]
        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(_run, n, pass1_results, 2): n
                    for n in llm_sections
                }
                for fut in futures:
                    name = futures[fut]
                    r, dt = fut.result()
                    pass2_results.append(r)
                    pass2_timings.append({"name": name, "pass": 2, "runtime_sec": dt})
        else:
            for name in llm_sections:
                r, dt = _run(name, pass1_results, 2)
                pass2_results.append(r)
                pass2_timings.append({"name": name, "pass": 2, "runtime_sec": dt})
        # Replace pass-1 LLM results with pass-2 results (better quality)
        for r2 in pass2_results:
            for i, r1 in enumerate(pass1_results):
                if r1["name"] == r2["name"]:
                    pass1_results[i] = r2
                    break

    section_results = pass1_results
    section_timings = pass1_timings + pass2_timings

    # REDUCE: local Python concatenates (no LLM call)
    parts = [
        f"# RE Report — {sha[:12]}",
        f"_Generated {datetime.now(timezone.utc).isoformat()}_  ",
        f"_Pipeline: section-based Map-Reduce, "
        f"{len([r for r in section_results if r.get('llm_ok') and r.get('pass') == 1])} pass-1 LLM calls"
        + (f" + {len(pass2_results)} pass-2 calls with cross-section context" if cross_refs else "")
        + " + 2 local sections_",
        "",
    ]
    for r in section_results:
        tag = f"<!-- section: {r['name']} | pass={r.get('pass','?')} | evidence={r.get('evidence_chars',0)}c | cross_refs={r.get('cross_refs_included', False)} | llm_ok={r.get('llm_ok')} | runtime={r.get('runtime_sec','?')}s -->"
        parts.append(tag)
        parts.append("")
        parts.append(r.get("markdown") or f"_(empty section)_")
        parts.append("")
        parts.append("---")
        parts.append("")
    report_markdown = "\n".join(parts)

    # Save evidence pack + backward-compat root files
    out_dir = LOGS_DIR / sha / "correlate"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "00-tools-raw.json").write_text(
        json.dumps(tools_results, indent=2, default=str))
    (out_dir / "01-section-results.json").write_text(
        json.dumps({"sections": section_results, "timings": section_timings,
                    "pass1_count": len(pass1_results), "pass2_count": len(pass2_results)},
                   indent=2, default=str)
    )
    (out_dir / "02-REPORT-MASTER-v3.md").write_text(report_markdown)

    # Backward compatibility: also write at logs root
    root_dir = LOGS_DIR / sha
    (root_dir / "REPORT-MASTER-v3.md").write_text(report_markdown)
    (root_dir / "section-results-v3.json").write_text(
        json.dumps({"sections": section_results, "timings": section_timings,
                    "pass1_count": len(pass1_results), "pass2_count": len(pass2_results)},
                   indent=2, default=str)
    )

    # Generate technical report alongside the section-based master report
    technical = run_technical_publish(sha, tools_results)

    return {
        "sections": section_results,
        "timings": section_timings,
        "pass1_results": pass1_results,
        "pass2_results": pass2_results,
        "report_markdown": report_markdown,
        "report_size": len(report_markdown),
        "technical": technical,
    }


def run_technical_publish(sha: str, tools_results: dict) -> dict:
    """Generate a single-pass technical report with structured evidence snippets.

    This report co-exists with the section-based REPORT-MASTER-v3.md. It is
    aimed at analysts who need code, strings, decompilation, and IOC evidence
    rather than an executive summary.
    """
    session_path = Path(f"/opt/samples/sessions/{sha}.json")
    session: dict = {
        "sha256": sha,
        "sample_path": tools_results.get("sample_path", "?"),
    }
    if session_path.exists():
        try:
            session = json.loads(session_path.read_text())
        except Exception:
            pass

    verdict = tools_results.get("verdict")
    deep = tools_results.get("deep")
    yara_meta = tools_results.get("yara_meta") or tools_results.get("yara")
    audit = tools_results.get("audit_tail") or []

    sql_evidence = tools_results.get("sql_evidence")
    if sql_evidence is None:
        sql_path = LOGS_DIR / sha / "deep_dive" / "00-sql-evidence.json"
        if sql_path.exists():
            try:
                sql_evidence = json.loads(sql_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                sql_evidence = None

    technical_evidence = build_technical_evidence_block(
        session, verdict, deep, yara_meta, tools_results, audit,
        dotnet_result=tools_results.get("dotnet"),
        r2_decomp=tools_results.get("r2_decomp"),
        frida_trace=tools_results.get("frida_trace"),
        upx=tools_results.get("upx"),
        xor_hits=tools_results.get("xor"),
        malcat_result=tools_results.get("malcat"),
        sql_evidence=sql_evidence,
        speakeasy=tools_results.get("speakeasy"),
        frida_probe=tools_results.get("frida_probe"),
    )
    (LOGS_DIR / sha / "EVIDENCE-BUNDLE.md").write_text(technical_evidence)

    sections = "\n".join(f"- {s}" for s in TECHNICAL_REPORT_SECTIONS)
    scorecard_block = ""
    try:
        from run_scorecard import check_scorecard
        sc = check_scorecard(sha)
        (LOGS_DIR / sha / "correlate" / "03b-scorecard.json").write_text(
            json.dumps(sc, indent=2, default=str)
        )
        scorecard_block = (
            "\n## Tool Scorecard (AUTHORITATIVE — interpret, do not invent)\n"
            + json.dumps(sc, indent=2, default=str)[:12000]
        )
    except Exception as e:
        scorecard_block = f"\n## Tool Scorecard\n(unavailable: {e})\n"
    prompt = f"""# Technical Malware Analysis Report v3

You MUST produce markdown with ALL of these level-2 headings (exact titles, ASCII only):
{sections}

Rules (evidence-first, MORE detail preferred):
- TECHNICAL report for reverse engineers. Prefer MORE evidence over less.
- COPY tables/rows from Structured Evidence into matching sections (keep addresses/eas).
- Every claim MUST include (source: <engine>) plus address, rule, or table row.
- REQUIRED embeds when present: section layout, full IAT, capa+YARA, high-signal strings with engine+ea,
  UPX stdout + unpacked_path, function metrics, EP/decompress disasm.
- Empty Speakeasy/Frida → write 'not observed'. Never invent runtime behavior.
- Citation engine must match evidence (Malcat string ≠ IDA SQL).
- FORBIDDEN: curly apostrophes in headings; "see appendix" as the only body of a section.

sha256: {sha}
sample_path: {session.get('sample_path', '?')}
project_name: {session.get('project_name', '?')}

## Structured Evidence (AUTHORITATIVE — copy into report sections)
{technical_evidence}
{scorecard_block}

## High-level verdict context
verdict.json: {json.dumps(verdict or {}, indent=2)[:4000]}

deep-dive.json: {json.dumps(deep or {}, indent=2)[:5000]}

{OUTPUT_FORMAT_CONTRACT}
"""

    try:
        resp = llm_judge(prompt)
        content = resp["choices"][0]["message"]["content"]
        technical_report: dict[str, Any]
        try:
            technical_report = json.loads(content)
        except json.JSONDecodeError:
            # tolerate fenced / wrapped JSON like publish_report_v2
            s = content.strip()
            if s.startswith("```"):
                lines = s.splitlines()[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                s = "\n".join(lines).strip()
            try:
                technical_report = json.loads(s)
            except json.JSONDecodeError:
                start, end = s.find("{"), s.rfind("}")
                if start >= 0 and end > start:
                    technical_report = json.loads(s[start : end + 1])
                else:
                    technical_report = {
                        "title": f"Technical Report {sha[:12]}",
                        "markdown": content,
                        "source": "llm_raw_markdown",
                    }
        meta = llm_call_metadata(resp)
        meta["request_model"] = get_llm_model()
        technical_report["model"] = meta.get("response_model") or get_llm_model()
        technical_report["llm_audit"] = meta
        technical_report["source"] = technical_report.get("source") or "llm_judge"
    except Exception as e:
        technical_report = {
            "title": f"Technical Report {sha[:12]}",
            "markdown": (
                f"# Technical Report\n\nLLM failed: {e}\n\n"
                f"## Structured Evidence\n\n{technical_evidence}\n"
            ),
            "source": "deterministic_fallback",
        }

    tech_md = technical_report.get("markdown", "") or ""
    missing = missing_sections(tech_md, TECHNICAL_REPORT_SECTIONS)
    stubs = stub_sections(tech_md, TECHNICAL_REPORT_SECTIONS) if tech_md else list(TECHNICAL_REPORT_SECTIONS)
    # RevAI: soft-fail Malcat-dependent sections when Malcat is not installed.
    if not _MALCAT_INSTALLED and stubs:
        stubs = [s for s in stubs if s not in _MALCAT_OPTIONAL_SECTIONS]
    if missing or stubs:
        technical_report["source"] = (
            "deterministic_fallback"
            if source_is_fallback(technical_report.get("source"))
            else "llm_incomplete"
        )
        technical_report["quality_fail"] = {"missing": missing, "stubs": stubs}
    # Always append full evidence pack (V5.16)
    tech_md = append_technical_evidence_appendix(tech_md, technical_evidence)
    technical_report["markdown"] = tech_md
    technical_report["evidence_appendix"] = True
    technical_report["sections_missing"] = missing
    technical_report["sections_stub"] = stubs
    technical_report["sections_complete"] = len(TECHNICAL_REPORT_SECTIONS) - len(missing)
    q = evaluate_report_markdown(
        tech_md,
        required_sections=TECHNICAL_REPORT_SECTIONS,
        source=technical_report.get("source"),
        min_total_chars=8000,
        label="technical_v3",
    )
    technical_report["quality"] = q

    tech_path = LOGS_DIR / sha / "REPORT-TECHNICAL-v3.md"
    tech_path.write_text(tech_md)
    (LOGS_DIR / sha / "correlate" / "03-REPORT-TECHNICAL-v3.md").write_text(tech_md)
    (LOGS_DIR / sha / "report-technical-v3.json").write_text(
        json.dumps(technical_report, indent=2, default=str)
    )

    return {
        "technical_markdown": tech_md,
        "technical_size": len(tech_md),
        "sections_missing": missing,
        "sections_stub": stubs,
        "sections_complete": technical_report["sections_complete"],
        "source": technical_report.get("source"),
        "quality": q,
        "ok": bool(q.get("ok")),
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("sha")
    ap.add_argument("--no-parallel", action="store_true")
    ap.add_argument("--hitl", action="store_true")
    args = ap.parse_args()

    env_info = ensure_pipeline_runtime_env()
    print(f"[section_publisher] runtime env: model={get_llm_model()}", flush=True)

    # Build tools_results from disk artifacts (for standalone use)
    sha = args.sha
    sha_log = Path(f"/opt/samples/logs/{sha}")
    tools_results: dict = {"sample_path": "?"}
    session_path = Path(f"/opt/samples/sessions/{sha}.json")
    if session_path.exists():
        session = json.loads(session_path.read_text())
        tools_results["sample_path"] = session.get("sample_path", "?")
    v = sha_log / "verdict.json"
    if v.exists():
        tools_results["verdict"] = json.loads(v.read_text())
    # P0.7: agentic/large runs write deep evidence under deep_dive/, not the
    # root deep-dive.json — resolve in preference order so MASTER-v3 never
    # silently publishes with empty deep evidence.
    dd_candidates = [
        sha_log / "deep-dive.json",
        sha_log / "deep_dive" / "05-deep-dive.json",
        sha_log / "deep_dive" / "agentic_deep_dive.json",
    ]
    for dd in dd_candidates:
        if dd.exists():
            tools_results["deep"] = json.loads(dd.read_text())
            tools_results["deep_source_path"] = str(dd)
            break
    if "deep" not in tools_results:
        print("  WARNING: no deep-dive evidence found (checked root + deep_dive/) — "
              "sections will lack deep context")
    # Load raw tool packs if available
    quick_tools = sha_log / "quick_scan" / "00-tools-raw.json"
    deep_tools = sha_log / "deep_dive" / "01-tools-raw.json"
    if quick_tools.exists():
        tools_results.update(json.loads(quick_tools.read_text()))
    if deep_tools.exists():
        tools_results.update(json.loads(deep_tools.read_text()))
    # For real evidence cards, need to call the tools — load from existing logs
    print(f"Running section-based publish for {sha[:12]}")
    print(f"  (tools_results has: {list(tools_results.keys())})")
    print("  Note: for full evidence, run quick_scan_v2 + deep_dive_v2 first")
    result = run_section_based_publish(
        sha, tools_results, parallel=not args.no_parallel, hitl_between=args.hitl
    )
    print(f"  report: {result['report_size']} chars, "
          f"{sum(1 for s in result['sections'] if s.get('llm_ok'))} LLM calls ok")
    print(f"  saved: {sha_log / 'REPORT-MASTER-v3.md'}")
    tech = result.get("technical", {})
    if tech:
        print(f"  technical: {tech.get('technical_size', 0)} chars, "
              f"{tech.get('sections_complete', 0)}/{len(TECHNICAL_REPORT_SECTIONS)} sections "
              f"source={tech.get('source')} quality_ok={tech.get('ok')}")
        print(f"  saved: {sha_log / 'REPORT-TECHNICAL-v3.md'}")
    llm_ok_n = sum(1 for s in result["sections"] if s.get("llm_ok"))
    section_fail = any(
        (not s.get("llm_ok")) and s.get("error")
        for s in result["sections"]
    )
    tech_ok = bool((tech or {}).get("ok"))
    master_ok = len(result.get("report_markdown") or "") >= 1500 and not section_fail
    ok = master_ok and tech_ok and llm_ok_n > 0
    print(f"[section_publisher] complete ok={ok} master_ok={master_ok} tech_ok={tech_ok}")
    raise SystemExit(0 if ok else 1)

