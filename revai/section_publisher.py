"""section_publisher.py — Map-Reduce report generation.

Section-based Map-Reduce pattern:
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
import re
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
    require_run_mode,
    LOGS_DIR,
    case_dir,
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
    attach_analysis_scripts,
    attach_dynamic_corroboration,
    attach_dynamic_analysis_section,
    attach_ioc_confidence,
    attach_what_we_dont_know,
    build_technical_evidence_block,
    ensure_pipeline_runtime_env,
    format_malcat_evidence,
    get_llm_model,
    llm_judge,
    llm_call_metadata,
    normalize_llm_content,
    normalize_llm_json,
    provenance_block,
    revai_provenance,
    _categorize_string,
)

from report_sections import attach_alignment_sections  # noqa: E402


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
        "(source: ghidra_query / capa / yara / malcat / cross-section:section_name). "
        "Be concise (200-500 words). Use tables where appropriate. "
        "ASCII apostrophe only in headings. Do NOT write 'see appendix' stubs.\n"
        "EXPLAIN, DON'T DUMP: every evidence row / code block you include must "
        "be introduced and interpreted (what + why + confidence); never paste "
        "evidence bare. Hedge inferences ('likely', 'possibly', 'we assess'). "
        "A reader with no context must follow the section without asking the "
        "model for clarification.\n"
        "DYNAMIC-ANALYSIS HONESTY: if Speakeasy/Frida tools RAN — even with "
        "zero recorded events — state that they ran and what they recorded; "
        "never write 'no dynamic analysis was performed' when the tools "
        "executed.\n"
        "ENTROPY UNITS: whole-file Shannon entropy in bits/byte (0-8); "
        "per-section values must name the section; never present an unlabeled "
        "tool metric as the file's entropy.\n"
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
            result["markdown"] = normalize_llm_content(v) or content
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
        f"- **model**: configured-llm",
        f"- **RAG**: bge-m3 (35,302 records, top-3 per section)",
        f"- **tool_count**: 10 (MalCat full MCP toolset, capa, YARA, FLOSS, dotnet, r2, upx, xor, olevba, peepdf)",
        "- **analyst**: (your name)",
        "",
        "_This report was generated via section-based Map-Reduce pattern. "
        "Each section got a focused 1-3K char LLM call with targeted RAG. No mega-prompt, no JSON parse errors._",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Technical report, section-wise.
#
# Why this exists, measured 2026-10-01 on win32k_dll: the technical report was
# assembled in ONE llm_judge call asking for all 13 sections. That request does
# not fit in one response -- the largest successful call that run was 46,415
# chars against a 16,384-token cap -- so the output came back truncated after
# section 1, finish_reason=length, and every completeness number downstream
# described a stub. v2's technical path was already section-wise and scored
# 13/13; v3 was not, and scored 1/13. Same defect class, adjacent file.
#
# The evidence pack is already structured by topic (34 markdown headings), so
# each section is routed the evidence it needs rather than every section
# receiving all 46KB. That keeps each prompt focused AND, more importantly,
# each expected response small -- output size is the constraint, not input.
#
# One pass, parallel, mirroring the master's execution model. Cross-section
# pass 2 is deliberately not done here: it doubles cost and is a quality
# refinement, whereas the defect being fixed is truncation.

TECHNICAL_SECTION_EVIDENCE: dict[str, tuple[str, ...]] = {
    "1. Executive Summary": ("verdict", "key_evidence", "deep", "summary"),
    "2. Sample Metadata": ("file summary", "metadata", "hash", "imports"),
    "3. File Layout & Structural Analysis": (
        "file layout", "sections/regions", "virtual files", "structures",
        "pe imports", "header"),
    "4. Static Code Analysis": (
        "decompilation", "functions", "constants", "anomal", "strings",
        "floss", "high-signal", "entropy", "xor", "capa", "yara", "imports",
        "r2", "disasm", "ghidra", "sql"),
    "5. Behavioral & Dynamic Analysis": (
        "speakeasy", "frida", "dynamic", "behavio", "upx", "unpack", "emulat",
        "trace"),
    "6. Network Indicators & C2": (
        "network", "c2", "url", "domain", "dns", "socket", "http", "iocs",
        "indicators"),
    "7. Capabilities Assessment": (
        "capa", "capabilit", "technique", "tactic", "attack"),
    "8. Indicators of Compromise": (
        "ioc", "indicator", "hash", "registry", "mutex", "service", "url"),
    "9. Detection Engineering": ("yara", "detection", "rule", "signature"),
    "10. MITRE ATT&CK Mapping": ("mitre", "attack", "tactic", "technique"),
    "11. What We Don't Know": ("unknown", "gap", "coverage", "limitation"),
    "12. Appendix A: Tool Evidence Trail": (
        "tool", "engine", "source", "environment", "version"),
    "13. Appendix B: Analysis Environment": (
        "environment", "tool", "version", "host", "platform"),
}

TECHNICAL_SECTION_DESCRIPTIONS: dict[str, str] = {
    "1. Executive Summary": (
        "What this sample is, what it does, and why it matters. Ground every "
        "claim in the verdict and the deep-dive key evidence."),
    "2. Sample Metadata": (
        "Identity facts: filename, size, hashes, format, arch, compile/link "
        "times, signed or not, packer."),
    "3. File Layout & Structural Analysis": (
        "Section layout, regions, entry point, virtual files and structures. "
        "Explain what the structure implies about how the binary was built."),
    "4. Static Code Analysis": (
        "Functions, decompilation, imports, strings, anomalies, entropy. "
        "Interpret the code: what it implements and what that implies."),
    "5. Behavioral & Dynamic Analysis": (
        "What execution shows. If Speakeasy/Frida/UPX RAN, say so and report "
        "what they recorded; never claim no dynamic analysis happened when the "
        "tools did run. Empty results are 'not observed', stated plainly."),
    "6. Network Indicators & C2": (
        "Network infrastructure: URLs, domains, IPs, protocols. State whether "
        "each item is a static string or observed traffic, and never present "
        "one as the other."),
    "7. Capabilities Assessment": (
        "What the sample is capable of, tied to capa rules and MITRE "
        "techniques, with evidence for each capability."),
    "8. Indicators of Compromise": (
        "Concrete, copy-pasteable indicators. Cite the engine that produced "
        "each one. Quote registry paths in full, never abbreviated."),
    "9. Detection Engineering": (
        "How an analyst would detect this: YARA logic, behavioural signatures, "
        "and what makes each rule specific rather than generic."),
    "10. MITRE ATT&CK Mapping": (
        "Tactic/technique table. Map only techniques the evidence supports."),
    "11. What We Don't Know": (
        "Explicit gaps: what was not analysed, which tools did not run, and "
        "what would resolve each gap. No speculation presented as fact."),
    "12. Appendix A: Tool Evidence Trail": (
        "Which engine produced which claim, so any statement can be traced back "
        "to its source."),
    "13. Appendix B: Analysis Environment": (
        "Tool versions and the platform the analysis ran on."),
}

#: Evidence every section receives, so none is written blind of the verdict.
_TECHNICAL_ALWAYS_BLOCKS = ("verdict", "deep-dive summary")

#: Per-section evidence cap. The point of routing is a focused prompt; without a
#: cap, one section's gather could re-create the oversized request that caused
#: the truncation in the first place.
_TECHNICAL_EVIDENCE_CAP = 40_000


def _split_evidence_blocks(text: str) -> list[tuple[str, str]]:
    r"""Split an evidence pack into (heading, block) pairs.

    Splits on EVERY heading level, not just `##`. The real EVIDENCE-BUNDLE.md
    nests its most useful material under `###`: Decompilations, Imports,
    Strings, Functions and Structures all live below `## Malcat Structured
    Analysis`. Splitting only on `##` leaves them merged under a parent heading
    that matches none of the per-section keywords, so "4. Static Code Analysis"
    received essentially no evidence while still looking complete -- the silent
    failure mode routing has to be tested against.

    Routing matches on heading text lowercased, so a new evidence block routes by
    what it is called rather than by a hand-maintained exhaustive list.
    """
    if not text:
        return []
    heading_re = re.compile(r"^#{1,6}\s")
    lines = text.splitlines()
    blocks: list[tuple[str, str]] = []
    head = "(preamble)"
    current: list[str] = []
    for line in lines:
        if heading_re.match(line):
            blocks.append((head, "\n".join(current)))
            head = line
            current = [line]
        else:
            current.append(line)
    blocks.append((head, "\n".join(current)))
    return [(h, b) for h, b in blocks if b.strip()]


def _technical_section_evidence(name: str, blocks: list[tuple[str, str]],
                               header: str = "") -> str:
    """The evidence blocks relevant to one technical section."""
    keys = TECHNICAL_SECTION_EVIDENCE.get(name, ())
    picked: list[str] = [header] if header else []
    for head, body in blocks:
        h = head.lower()
        if any(k in h for k in keys) or any(
                k in h for k in _TECHNICAL_ALWAYS_BLOCKS):
            picked.append(body)
    out = "\n".join(picked)
    if len(out) > _TECHNICAL_EVIDENCE_CAP:
        kept: list[str] = []
        size = 0
        for part in picked:
            if size + len(part) > _TECHNICAL_EVIDENCE_CAP and kept:
                kept.append(f"\n[truncated: evidence for this section exceeded "
                            f"{_TECHNICAL_EVIDENCE_CAP} chars]\n")
                break
            kept.append(part)
            size += len(part)
        out = "\n".join(kept)
    return out


def _technical_section_prompt(name: str, description: str, evidence: str,
                              sha: str, prior_sections_summary: str = "") -> str:
    """One focused prompt per technical section.

    Carries the same rules as the old monolithic prompt so quality does not
    regress, but asks for one section instead of thirteen, which is what keeps
    the response inside the output cap.
    """
    parts = [
        f"# Technical Report Section: {name}",
        f"sha256: {sha}",
        "",
        "## Section description",
        description,
        "",
        "## Evidence for this section (filtered)",
        evidence or "(no evidence routed to this section -- say so explicitly)",
        "",
    ]
    if prior_sections_summary:
        parts += ["## Prior sections (for continuity)",
                  prior_sections_summary, ""]
    parts.append(
        "## Rules\n"
        f"- Write ONLY the '{name}' section, as markdown, beginning with a "
        "level-2 heading carrying that exact title.\n"
        "- TECHNICAL report for reverse engineers. Prefer MORE evidence over "
        "less.\n"
        "- COPY tables/rows from the evidence into the section, keeping "
        "addresses and eas exactly.\n"
        "- Every claim MUST include (source: <engine>) plus an address, rule or "
        "table row.\n"
        "- Quote registry paths and IoCs in FULL. Never abbreviate a path with "
        "'...' -- an unverifiable indicator is worse than none.\n"
        "- If a tool did not run or produced nothing, write 'not observed'. "
        "Never invent runtime behavior, and never claim no dynamic analysis "
        "happened when the tools did run.\n"
        "- The citation engine must match the evidence (a Malcat string is not "
        "an IDA SQL row).\n"
        "- FORBIDDEN: curly apostrophes in headings; 'see appendix' as the only "
        "body of a section.\n"
        "- EXPLAIN, DON'T DUMP: every disassembly block, string table or "
        "evidence row must be introduced with a sentence and followed by an "
        "interpretation paragraph (what it does, why it matters, what behavior "
        "it implies, confidence). Hedge inferences ('likely', 'possibly', 'we "
        "assess').\n"
        "- ASCII apostrophes only.\n"
        'Return JSON: {"title": "...", "markdown": "<section content>", '
        '"source": "llm_judge"}'
    )
    return "\n".join(parts)


def _generate_technical_section(
    name: str, blocks: list[tuple[str, str]], header: str, sha: str,
    prior_summaries: dict[str, str] | None = None) -> dict[str, Any]:
    """Generate ONE technical section. Never raises: a failure is recorded."""
    description = TECHNICAL_SECTION_DESCRIPTIONS.get(name, name)
    result: dict[str, Any] = {"name": name, "llm_ok": False, "error": None,
                              "pass": 1}
    try:
        evidence = _technical_section_evidence(name, blocks, header)
    except Exception as exc:                      # noqa: BLE001
        evidence = f"(evidence routing failed: {exc})"
        result["error"] = f"route: {exc}"

    prior_lines = [f"  - {n}: {m[:200]}"
                   for n, m in list((prior_summaries or {}).items())[-3:] if m]
    prompt = _technical_section_prompt(
        name, description, evidence, sha,
        "\n".join(prior_lines) if prior_lines else "")
    result["evidence_chars"] = len(evidence)
    result["prompt_chars"] = len(prompt)

    try:
        resp = llm_judge(prompt)
        content = resp["choices"][0]["message"]["content"]
        try:
            v = json.loads(content)
            result["markdown"] = normalize_llm_content(v) or content
        except json.JSONDecodeError:
            result["markdown"] = content
        meta = llm_call_metadata(resp)
        if meta:
            meta["request_model"] = get_llm_model()
            result["llm_audit"] = meta
        result["llm_ok"] = True
    except Exception as exc:                      # noqa: BLE001
        result["error"] = f"llm: {exc}"
        result["markdown"] = f"## {name}\n\n_(section generation failed: {exc})_\n"
    return result


def _technical_sectionwise_enabled() -> bool:
    """Section-wise is the default. REVAI_TECHNICAL_SECTIONWISE=0 restores the
    monolithic call, kept only as a rollback lever for this change."""
    return (os.environ.get("REVAI_TECHNICAL_SECTIONWISE") or "1").strip().lower() \
        not in ("0", "false", "no", "off")


def generate_technical_sectionwise(
    sha: str, technical_evidence: str, *, parallel: bool = True,
    max_workers: int = 6) -> tuple[list[dict[str, Any]], str]:
    """Generate all 13 technical sections independently, then assemble.

    Returns (results, markdown). A section that fails is recorded with
    llm_ok=False and a stated reason; the remaining sections are still produced,
    because one bad section must not cost the whole report.
    """
    blocks = _split_evidence_blocks(technical_evidence)
    header = "\n".join(
        f"- sha256: {sha}"
        f"\n- verdict: {(blocks[0][1][:200] if blocks else '')}")

    print(f"  [technical] section-wise: generating "
          f"{len(TECHNICAL_REPORT_SECTIONS)} sections "
          f"({len(blocks)} evidence blocks routed)", flush=True)

    results: list[dict[str, Any]] = []
    if parallel:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_generate_technical_section, name, blocks, header,
                            sha): name
                for name in TECHNICAL_REPORT_SECTIONS
            }
            for fut in futures:
                results.append(fut.result())
    else:
        for name in TECHNICAL_REPORT_SECTIONS:
            results.append(
                _generate_technical_section(name, blocks, header, sha))

    order = {n: i for i, n in enumerate(TECHNICAL_REPORT_SECTIONS)}
    results.sort(key=lambda r: order.get(r.get("name", ""), 999))

    parts = [f"# Technical Malware Analysis Report\n"]
    for r in results:
        md = (r.get("markdown") or "").strip()
        if md:
            parts.append(md)
            parts.append("")
    return results, "\n".join(parts)


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
    report_markdown = provenance_block() + "\n".join(parts)

    # Save evidence pack + backward-compat root files
    out_dir = case_dir(sha) / "correlate"
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
    root_dir = case_dir(sha)
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
        sql_path = case_dir(sha) / "deep_dive" / "00-sql-evidence.json"
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
    # WinRE dynamic corroboration (presence-gated: no-op without a pack)
    # Analysis-scripts appendix (plan #11; presence-gated: stage not run -> unchanged)
    technical_evidence = attach_analysis_scripts(technical_evidence, sha)
    technical_evidence = attach_dynamic_corroboration(technical_evidence, sha)
    (case_dir(sha) / "EVIDENCE-BUNDLE.md").write_text(technical_evidence)

    if _technical_sectionwise_enabled():
        # Section-wise is the default path. The monolithic call below is kept
        # byte-identical and reachable only via REVAI_TECHNICAL_SECTIONWISE=0,
        # as a rollback lever, because it is the direct cause of the v3 technical
        # truncation: one call cannot hold 13 sections inside the output cap, so
        # it returned finish_reason=length after section 1 and every
        # completeness figure then described a stub.
        try:
            tech_results, tech_md_built = generate_technical_sectionwise(
                sha, technical_evidence)
            failed = [r["name"] for r in tech_results if not r.get("llm_ok")]
            print(
                f"  [technical] {len(tech_results) - len(failed)}/"
                f"{len(tech_results)} sections LLM-generated"
                + (f"; failed: {failed}" if failed else ""),
                flush=True,
            )
            technical_report = {
                "title": f"Technical Report {sha[:12]}",
                "markdown": tech_md_built,
                "source": "llm_judge" if not failed else "partial_llm_judge",
                "section_results": tech_results,
                "model": get_llm_model(),
            }
        except Exception as exc:                # noqa: BLE001
            print(f"  [technical] section-wise generation failed "
                  f"({type(exc).__name__}: {exc}); using deterministic fallback",
                  flush=True)
            technical_report = {
                "title": f"Technical Report {sha[:12]}",
                "markdown": (
                    f"# Technical Report\n\nSection-wise generation failed: "
                    f"{exc}\n\n## Structured Evidence\n\n{technical_evidence}\n"
                ),
                "source": "deterministic_fallback",
            }
        return _finalize_technical(sha, technical_report, technical_evidence,
                                   tools_results)

    sections = "\n".join(f"- {s}" for s in TECHNICAL_REPORT_SECTIONS)
    # NOTE: no scorecard — RevAI does not use the legacy run_scorecard /
    # RAG verification harness. Tool I/O truth is enforced by
    # audit_pipeline.py (tools_all_ok, engine_citation_ok, ...).
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
- EXPLAIN, DON'T DUMP: every disassembly block / string table / evidence row is
  introduced with a sentence and followed by an interpretation paragraph
  (what it does, why it matters, what behavior it implies, confidence).
  Hedge inferences ('likely', 'possibly', 'we assess'). A reader with no prior
  context must be able to follow each section from evidence to conclusion
  without asking the model for clarification.

sha256: {sha}
sample_path: {session.get('sample_path', '?')}
project_name: {session.get('project_name', '?')}

## Structured Evidence (AUTHORITATIVE — copy into report sections)
{technical_evidence}

## High-level verdict context
verdict.json: {json.dumps(verdict or {}, indent=2)[:4000]}

deep-dive.json: {json.dumps(deep or {}, indent=2)[:5000]}

{OUTPUT_FORMAT_CONTRACT}
"""

    # Bounded retry on incomplete/truncated output (provider finding
    # 2026-08-08): the single-giant-call technical assembly occasionally
    # truncates (only section 1 written, rest missing/stub). Retry ONCE with a
    # short completion nudge before falling back.
    try:
        resp = llm_judge(prompt)
        content = resp["choices"][0]["message"]["content"]
        technical_report = normalize_llm_json(content)
        meta = llm_call_metadata(resp)
        meta["request_model"] = get_llm_model()
        technical_report["model"] = meta.get("response_model") or get_llm_model()
        technical_report["llm_audit"] = meta
        technical_report["source"] = technical_report.get("source") or "llm_judge"
        _md = str(technical_report.get("markdown") or "")
        _miss1 = missing_sections(_md, TECHNICAL_REPORT_SECTIONS)
        if _miss1:
            # Truncated assembly: retry once with an explicit completeness nudge.
            #
            # The retry is isolated in its own try/except on purpose. It used to
            # sit inside the outer try, so when the retry's llm_judge exhausted
            # its attempts the exception propagated to the outer handler and
            # REPLACED the first response -- which was a real, partially
            # complete report -- with a deterministic fallback stub. Measured on
            # win32k_dll 2026-10-01: the first call returned a usable section 1,
            # the retry failed, and the published report was
            # "LLM failed: llm_judge failed" with 1 of 13 sections and 10 stubs.
            #
            # A failed retry must leave the better of what we already have, not
            # erase it. The retry exists to improve the report, never to decide
            # whether one exists at all.
            print(
                f"[section_publisher] technical assembly incomplete "
                f"(missing {len(_miss1)} sections); retrying once with nudge",
                flush=True,
            )
            try:
                resp2 = llm_judge(
                    prompt
                    + "\n\nYour previous output was incomplete: it is missing "
                    "these sections: "
                    + ", ".join(_miss1)
                    + ". Complete the FULL report with every required heading; "
                    "do not truncate. Return the complete markdown."
                )
                content2 = resp2["choices"][0]["message"]["content"]
                technical_report2 = normalize_llm_json(content2)
                _md2 = str(technical_report2.get("markdown") or "")
                if len(_md2) > len(_md):
                    technical_report = technical_report2
                    technical_report["technical_assembly_retried"] = True
                    technical_report["model"] = (
                        (llm_call_metadata(resp2) or {}).get("response_model")
                        or get_llm_model()
                    )
            except Exception as retry_exc:
                # Keep the first response. It is partial but real, and the
                # missing sections are already reported downstream by
                # missing_sections(), so nothing is hidden by keeping it.
                print(
                    f"[section_publisher] technical completeness retry failed "
                    f"({type(retry_exc).__name__}: {str(retry_exc)[:80]}); "
                    f"keeping the partial first response "
                    f"({len(_md)} chars, missing {len(_miss1)} sections)",
                    flush=True,
                )
                technical_report["technical_assembly_retry_failed"] = str(
                    retry_exc)[:200]
    except Exception as e:
        technical_report = {
            "title": f"Technical Report {sha[:12]}",
            "markdown": (
                f"# Technical Report\n\nLLM failed: {e}\n\n"
                f"## Structured Evidence\n\n{technical_evidence}\n"
            ),
            "source": "deterministic_fallback",
        }

    return _finalize_technical(sha, technical_report, technical_evidence,
                               tools_results)


def _finalize_technical(sha: str, technical_report: dict,
                        technical_evidence: str,
                        tools_results: dict | None = None) -> dict:
    """Score completeness, append the deterministic sections, write the outputs.

    Shared by the section-wise and monolithic paths so the two cannot drift on
    how completeness is measured or what lands on disk. Extracted rather than
    duplicated: the scoring below is what the audit and the hollow-success
    detector read, and two copies of it would be free to disagree.
    """
    tools_results = tools_results or {}
    tech_md = technical_report.get("markdown", "") or ""
    missing = missing_sections(tech_md, TECHNICAL_REPORT_SECTIONS)
    stubs = (stub_sections(tech_md, TECHNICAL_REPORT_SECTIONS) if tech_md
             else list(TECHNICAL_REPORT_SECTIONS))
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
    # Always append full evidence pack (V5.16); provenance banner BEFORE the
    # quality eval so the byline_ok style gate reads it.
    tech_md = append_technical_evidence_appendix(tech_md, technical_evidence)
    technical_report["provenance"] = revai_provenance()
    tech_md = provenance_block() + tech_md
    # Deterministic alignment sections (plan #12) - IOC tiers, dynamic analysis,
    # explicit gaps - appended before quality eval. The gap scan uses the report
    # as the LLM wrote it, so it cannot quote our own caveats.
    _report_scan_text = tech_md
    tech_md = attach_ioc_confidence(tech_md, sha)
    tech_md = attach_dynamic_analysis_section(tech_md, sha)
    tech_md = attach_alignment_sections(
        tech_md, case_root=case_dir(sha),
        sample_path=tools_results.get("sample_path"),
        provenance=technical_report.get("provenance"))
    tech_md = attach_what_we_dont_know(tech_md, sha, scan_text=_report_scan_text)
    technical_report["markdown"] = tech_md
    technical_report["evidence_appendix"] = True
    technical_report["sections_missing"] = missing
    technical_report["sections_stub"] = stubs
    technical_report["sections_complete"] = (
        len(TECHNICAL_REPORT_SECTIONS) - len(missing))
    q = evaluate_report_markdown(
        tech_md,
        required_sections=TECHNICAL_REPORT_SECTIONS,
        source=technical_report.get("source"),
        min_total_chars=8000,
        label="technical_v3",
    )
    technical_report["quality"] = q

    tech_path = case_dir(sha) / "REPORT-TECHNICAL-v3.md"
    tech_path.write_text(tech_md)
    (case_dir(sha) / "correlate" / "03-REPORT-TECHNICAL-v3.md").write_text(tech_md)
    (case_dir(sha) / "report-technical-v3.json").write_text(
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

    # Mode-keyed by design: sections are written into logs/<sha>/<mode>/ and the
    # audit reads the same place.
    require_run_mode("section_publisher")

    env_info = ensure_pipeline_runtime_env()
    print(f"[section_publisher] runtime env: model={get_llm_model()}", flush=True)

    # Build tools_results from disk artifacts (for standalone use)
    sha = args.sha
    sha_log = Path(f"/opt/samples/logs/{sha}")
    mode_dir = case_dir(sha)  # mode-keyed (REVAI_RUN_MODE); flat when unset

    def _first_existing(paths: list[Path]) -> Path | None:
        for p in paths:
            if p.exists():
                return p
        return None

    tools_results: dict = {"sample_path": "?"}
    session_path = Path(f"/opt/samples/sessions/{sha}.json")
    if session_path.exists():
        session = json.loads(session_path.read_text())
        tools_results["sample_path"] = session.get("sample_path", "?")
    v = _first_existing([mode_dir / "verdict.json", sha_log / "verdict.json"])
    if v is not None:
        tools_results["verdict"] = json.loads(v.read_text())
    # P0.7: agentic/large runs write deep evidence under deep_dive/, not the
    # root deep-dive.json — resolve in preference order so MASTER-v3 never
    # silently publishes with empty deep evidence. Mode-keyed runs (#15/R1)
    # write under logs/<sha>/<mode>/ — check that first, then the flat legacy
    # layout.
    dd_candidates = [
        mode_dir / "deep-dive.json",
        mode_dir / "deep_dive" / "05-deep-dive.json",
        mode_dir / "deep_dive" / "agentic_deep_dive.json",
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
        print("  WARNING: no deep-dive evidence found (checked mode dir + root + deep_dive/) — "
              "sections will lack deep context")
    # Load raw tool packs if available (quick triage is mode-independent: flat;
    # deep tools are mode-keyed with a flat legacy fallback)
    quick_tools = _first_existing([
        sha_log / "quick_scan" / "00-tools-raw.json",
        mode_dir / "quick_scan" / "00-tools-raw.json",
    ])
    deep_tools = _first_existing([
        mode_dir / "deep_dive" / "01-tools-raw.json",
        sha_log / "deep_dive" / "01-tools-raw.json",
    ])
    if quick_tools is not None:
        tools_results.update(json.loads(quick_tools.read_text()))
    if deep_tools is not None:
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

