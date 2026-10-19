"""Section-scoped report generation from run-bound evidence.

The publisher routes run-bound evidence by report topic, asks the configured
model to interpret it, and assembles the returned sections locally. It does not
perform lookup itself; an upstream optional VirusTotal/Hybrid Analysis hash-only
result may be supplied as run-bound evidence. Report stages do not query a
malware-family or campaign-intelligence corpus. The deep-dive agent has a
separate offline Windows API reference lookup; it is not report-stage threat
intelligence or sample-behavior evidence.
The input manifest identifies source artifacts and hashes; appendices contain
selected evidence cards rather than complete raw tool output.
"""
import hashlib
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
    ensure_section_heading,
    missing_sections,
    redact_model_names,
    source_is_fallback,
    stub_sections,
    uncited_report_claims,
)
from v2_lib import (
    REPORT_MASTER_SECTIONS,
    REPORT_SECTION_SPECS,
    TECHNICAL_REPORT_SECTIONS,
    require_run_mode,
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
    format_ti_hash_enrichment_evidence,
    _sec_iocs_evidence,
    _sec_detection_evidence,
    _sec_containment_evidence,
    _sec_recommendations_evidence,
    append_technical_evidence_appendix,
    attach_analysis_scripts,
    attach_dynamic_corroboration,
attach_capability_coverage,
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
    assert_report_input_manifest,
    format_report_input_manifest,
    load_attested_case_json,
    report_input_manifest_digest,
    record_report_outputs,
    report_execution_comment,
    cross_stage_verdict_lock,
    infer_publish_verdict_from_markdown,
    require_execution_context,
    validate_report_input_manifest,
    _categorize_string,
    dynamic_analysis_status,
)
from skills import report_methodology_block  # noqa: E402
from behavioural_model import (  # noqa: E402
    attach_behavioural_model,
)

from report_sections import attach_alignment_sections  # noqa: E402


def _section_prompt(section_name: str, description: str, evidence: str,
                    prior_sections_summary: str,
                    cross_context: str = "",
                    provenance_block_text: str = "") -> str:
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
    if provenance_block_text:
        parts.extend((provenance_block_text, ""))
    parts.extend((report_methodology_block([section_name, description]), ""))
    if prior_sections_summary:
        parts.append("## Prior sections (for continuity)")
        parts.append(prior_sections_summary)
        parts.append("")
    if cross_context:
        parts.append("## Cross-section context (draft context from other sections in pass 1)")
        parts.append(cross_context)
        parts.append("")
    parts.append(
        "## Your task\n"
        f"Write the '{section_name}' section in markdown. Cite evidence as "
        "(source: <engine>, query_or_table: <artifact or table>, "
        "row_or_rule: <exact observed row, address, or rule>). A source label "
        "without a concrete row_or_rule is not a usable citation. "
        "Verdict/summary prose is NARRATIVE CONTEXT, never a claim's "
        "(source: ...): cite the tool row that observed the fact or write "
        "'not observed'. "
        "Be concise (200-500 words). Use tables where appropriate. "
        "ASCII apostrophe only in headings. Do NOT write 'see appendix' stubs.\n"
        "CITATION SCOPE: put an evidence citation on every factual claim sentence "
        "and every evidence-table row, not merely once per paragraph. Use the "
        "original tool/artifact citation shown in the evidence; never cite "
        "cross-section prose as evidence. Cross-section context is draft text "
        "for consistency only, not a source of facts. Use the exact "
        "parenthesized citation form above at the end of each factual sentence. "
        "For a table row, place the complete citation in the claim cell; do not "
        "place bare source metadata in another cell. Keep each factual sentence "
        "focused so its cited rows establish the complete claim. If a source row "
        "is not available, state the limitation or unknown instead of repeating "
        "an uncited claim. Prefer one factual sentence per bullet; never use one "
        "citation to cover multiple sentences, and split independent facts into "
        "separately cited claims. Before returning, check each factual sentence "
        "and table claim cell for its own exact source locator; remove any claim "
        "that cannot be tied to one. When the evidence exposes a verdict score "
        "and deep-dive confidence, keep them as separate source fields with exact "
        "labels and values; cite each field and never substitute or combine them. "
        "If cross-section text conflicts with the pipeline-"
        "selected verdict control, the control label takes precedence.\n"
        "EXPLAIN, DON'T DUMP: every evidence row / code block you include must "
        "be introduced and interpreted (what + why + confidence); never paste "
        "evidence bare. Hedge inferences ('likely', 'possibly', 'we assess'). "
        "A reader with no context must follow the section without asking the "
        "model for clarification.\n"
        "DYNAMIC-ANALYSIS HONESTY: the DYNAMIC-ANALYSIS STATUS line (in the "
        "evidence) is authoritative for the whole run. When discussing runtime, "
        "cite it as source: dynamic_analysis_status and state the relevant "
        "component status exactly. "
        "Treat this as global context, not boilerplate to repeat: state the full "
        "run status in the Executive Summary. In behavior or network sections, "
        "cite only the component-specific runtime observations and coverage limits "
        "that affect that section's conclusion. Other sections should mention it "
        "only when needed to qualify their specific conclusion. "
        "The filtered evidence for a section is not the complete run corpus; do "
        "not claim that a mechanism did not run or that evidence is unavailable "
        "overall only because it is absent from this section's filtered evidence. "
        "A tool that failed or was not run must not be described as having executed.\n"
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


def _dynamic_status_sentence(sha: str) -> str:
    """The authoritative one-line dynamic-analysis status for a run.

    Empty when it cannot be read, so a missing fact is never presented as a
    fabrication-free fact.
    """
    try:
        from v2_lib import dynamic_analysis_status
        return dynamic_analysis_status(sha).get("sentence", "")
    except Exception:
        return ""


def _persist_llm_call(sha: str, mode: str | None, stage: str, section: str,
                      prompt: str, *, response: dict | None = None,
                      error: str | None = None) -> dict:
    """Persist exact LLM input and raw output so every generated section is auditable."""
    if mode is None:
        try:
            mode = (require_execution_context(sha, stage="report_llm_call") or {}).get("mode")
        except Exception:
            mode = None
    root = case_dir(sha, mode) if mode else case_dir(sha)
    call_dir = root / "correlate" / "llm-calls"
    call_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", section.lower()).strip("-") or "section"
    stem = f"{stage}-{slug}"
    prompt_path = call_dir / f"{stem}.prompt.txt"
    response_path = call_dir / f"{stem}.response.json"
    metadata_path = call_dir / f"{stem}.metadata.json"

    def write_atomic(path: Path, value: str) -> None:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(value, encoding="utf-8")
        temporary.replace(path)

    prompt_bytes = prompt.encode("utf-8")
    write_atomic(prompt_path, prompt)
    raw_response = json.dumps(response, ensure_ascii=False, indent=2, default=str) \
        if response is not None else json.dumps({"error": error or "no response"}, indent=2)
    write_atomic(response_path, raw_response)
    metadata = {
        "sha256": sha,
        "analysis_mode": mode,
        "stage": stage,
        "section": section,
        "prompt_path": str(prompt_path.relative_to(root)).replace("\\", "/"),
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "prompt_chars": len(prompt),
        "response_path": str(response_path.relative_to(root)).replace("\\", "/"),
        "response_sha256": hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
        "response_chars": len(raw_response),
        "error": error,
    }
    write_atomic(metadata_path, json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
    return metadata


def _run_one_section(section_name: str, sha: str, tools_results: dict,
                    prior_summaries: dict,
                    pass1_results: list = None,
                    pass_num: int = 1) -> dict:
    """Run one section: gather run-bound evidence, call LLM and record the exchange.

    Pass 1 (pass_num=1): no cross-section context (parallel-friendly).
    Pass 2 (pass_num=2): includes the pass-1 results from all other sections
        as a 'Cross-section context' block so the LLM can cite them.

    Returns: {"name": str, "markdown": str, "evidence_chars": int,
              "llm_ok": bool, "error": str|None, "pass": int, "prompt_chars": int}
    """
    if section_name not in REPORT_SECTION_SPECS:
        return {"name": section_name, "error": f"unknown section: {section_name}"}
    description, gather_fn, requires_llm = REPORT_SECTION_SPECS[section_name]
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
    # Deterministic dynamic status: the report must state what dynamic analysis
    # ACTUALLY happened, read from artifacts, not infer it from tool names.
    # Without this the model once wrote "Speakeasy and Frida executed
    # successfully" for a sample whose oracle failed and where no Frida or
    # WinRE pack exists.
    st_block = str(
        ((tools_results.get("_dynamic_status") or {}).get("sentence") or "")
    ) or _dynamic_status_sentence(sha)
    if st_block:
        evidence = (f"DYNAMIC-ANALYSIS STATUS (authoritative, read from the "
                    f"run's artifacts; applies to the whole run): {st_block} "
                    f"(source: dynamic_analysis_status, query_or_table: "
                    f"run-scoped status, row_or_rule: run-scoped status)\n\n{evidence}")
    quick_result = tools_results.get("verdict")
    deep_result = tools_results.get("deep")
    quick_verdict = (quick_result.get("verdict")
                     if isinstance(quick_result, dict) else None)
    deep_verdict = (deep_result.get("verdict")
                    if isinstance(deep_result, dict) else None)
    verdict_control = cross_stage_verdict_lock(
        None, quick_verdict=quick_verdict, deep_verdict=deep_verdict)
    locked_verdict = verdict_control.get("upstream") or "unknown"
    if locked_verdict != "unknown":
        evidence = (
            "PIPELINE-SELECTED REPORT VERDICT CONTROL (not raw sample evidence): "
            f"{locked_verdict}. Use this exact label in every verdict field, "
            "classification statement, and executive-summary conclusion. Do not "
            "upgrade or downgrade it. If evidence appears to disagree, identify "
            "the disagreement as a limitation while preserving this report label. "
            "Do not cite this control line as evidence for behavior, capability, "
            "family, or ATT&CK claims.\n\n"
            + evidence
        )
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
                            prior_sections_summary, cross_context=cross_context,
                            provenance_block_text=str(
                                tools_results.get("_report_provenance_block") or ""))
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
    response = None
    call_record = None
    mode = (tools_results.get("_execution_context") or {}).get("mode")
    try:
        resp = llm_judge(prompt)
        response = resp
        choice = (resp.get("choices") or [{}])[0]
        if choice.get("finish_reason") not in (None, "stop"):
            raise ValueError(
                f"incomplete section response (finish_reason={choice.get('finish_reason')})"
            )
        content = resp["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("section response has no textual content")
        call_record = _persist_llm_call(
            sha, mode, f"master-p{pass_num}", section_name, prompt, response=resp)
        v = normalize_llm_json(content)
        result["markdown"] = ensure_section_heading(
            normalize_llm_content(v) or content, section_name
        )
        result["title"] = v.get("title", section_name)
        result["first_draft_policy"] = (
            "first draft is preserved; the claim-support gate reports defects "
            "instead of asking the writer to repair its own unsupported claims"
        )
        result["uncited_claim_count"] = len(
            uncited_report_claims(result["markdown"])
        )
        # Audit: capture response-side model + reasoning tokens
        result["llm_audit"] = llm_call_metadata(resp)
        result["llm_audit"]["request_model"] = get_llm_model()
        result["llm_call"] = call_record
        result["llm_ok"] = True
    except Exception as e:
        if call_record is None:
            call_record = _persist_llm_call(
                sha, mode, f"master-p{pass_num}", section_name, prompt,
                response=response, error=f"{type(e).__name__}: {e}")
        result["llm_call"] = call_record
        result["error"] = f"llm: {e}"
        result["markdown"] = f"## {section_name}\n\n_(LLM call failed: {e})_\n"
    return result


def _build_appendices(tools_results: dict) -> str:
    """Section 15: show selected evidence cards and identify their source manifest."""
    manifest_sha = str(tools_results.get("_report_input_manifest_sha256") or "not available")
    lines = ["## 15. Appendices\n",
             "Selected signal-prioritized evidence cards are shown below. They are "
             "not complete raw tool output. The report-input manifest identifies "
             "the source artifacts and their hashes; consult those artifacts for "
             "the underlying data where retained. See `publish/report-input-manifest.json` "
             f"(SHA-256 `{manifest_sha}`) for the exact report inputs.\n"]
    cards = [
        ("A1. Selected MalCat evidence card (anomaly locations, decompilations, constants)",
         tools_results.get("malcat_card")),
        ("A2. .NET evidence card (language, runtime, P/Invoke, IL excerpt)",
         tools_results.get("dotnet_card")),
        ("A3. radare2 disassembly (top-3 functions, ANSI stripped)",
         tools_results.get("r2_card")),
        ("A4. YARA matches (rule names + categories)",
         tools_results.get("yara_card")),
        ("A5. Selected capa rules and ATT&CK groupings",
         tools_results.get("capa_card")),
        ("A6. Selected FLOSS strings and IOC categories",
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
        lines.append("### A11. Selected structured MalCat evidence\n")
        lines.append(format_malcat_evidence(mc))
        lines.append("")
    # Speakeasy + frida behavioral (compact JSON)
    deep = tools_results.get("deep") or {}
    behavioral = deep.get("behavioral") or {}
    if behavioral:
        lines.append("### A12. Selected behavioral summary (Speakeasy + Frida probe)\n")
        lines.append("```json")
        behavioral_text = json.dumps(behavioral, indent=2, default=str)
        lines.append(behavioral_text[:6000])
        if len(behavioral_text) > 6000:
            lines.append("[Excerpt truncated at 6,000 characters; see the run-bound source artifacts.] ")
        lines.append("```\n")
    ti_result = tools_results.get("ti_enrich")
    if isinstance(ti_result, dict):
        lines.append("### A13. Optional external hash-enrichment record\n")
        lines.append(format_ti_hash_enrichment_evidence(ti_result))
        lines.append("")
    return "\n".join(lines)


def _build_signoff(tools_results: dict, sha: str) -> str:
    """Section 16: metadata + audit."""
    now = datetime.now(timezone.utc).isoformat()
    verdict = tools_results.get("verdict") or {}
    ti_result = tools_results.get("ti_enrich")
    if not isinstance(ti_result, dict):
        ti_status = "status not recorded in supplied run inputs"
    elif ti_result.get("enabled") is not True:
        ti_status = "not performed (disabled in this run)"
    else:
        provider_rows = ti_result.get("providers")
        provider_rows = provider_rows if isinstance(provider_rows, dict) else {}
        states = []
        for provider, label in (("virustotal", "VirusTotal"),
                                ("hybrid_analysis", "Hybrid Analysis")):
            row = provider_rows.get(provider)
            if not isinstance(row, dict):
                continue
            error = str(row.get("error") or "")
            if row.get("ok") is True:
                state = "result returned"
            elif error.endswith("API_KEY not set"):
                state = "not queried (key not configured)"
            elif error == "no_prior_reports":
                state = "queried; no prior report"
            elif error:
                state = "queried; request failed"
            else:
                state = "result unavailable"
            states.append(f"{label}: {state}")
        ti_status = ("hash lookup enabled; " + "; ".join(states)
                     if states else "enabled, but provider outcomes are not recorded")
    lines = [
        "## 16. Author + Sign-off\n",
        f"- **sha256**: `{sha}`",
        f"- **generated_at**: {now}",
        f"- **verdict_source**: {verdict.get('source', '?')}",
        f"- **model**: configured-llm",
        f"- **optional external hash lookup**: {ti_status}",
        "- **evidence sources**: run-bound tool artifacts listed in the report-input manifest",
        "- **analyst**: not recorded",
        "",
        "_The report was generated from section-routed evidence and configured-LLM "
        "interpretation. Input size and completion status are recorded per call; "
        "the claim-support gate determines whether cited sources establish each claim._",
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
        "claim in the verdict and the deep-dive key evidence. State the run's "
        "authoritative dynamic-analysis status accurately."),
    "2. Sample Metadata": (
        "Identity facts: filename, size, hashes, format, arch, compile/link "
        "times, signed or not, packer. If describing dynamic analysis, use the "
        "authoritative run status and distinguish WinRE from RevAI components."),
    "3. File Layout & Structural Analysis": (
        "Section layout, regions, entry point, virtual files and structures. "
        "Explain what the structure implies about how the binary was built."),
    "4. Static Code Analysis": (
        "Functions, decompilation, imports, strings, anomalies, entropy. "
        "Interpret the code: what it implements and what that implies."),
    "5. Behavioral & Dynamic Analysis": (
        "What execution shows. State the DYNAMIC-ANALYSIS STATUS line at the top "
        "of the evidence verbatim: it says, from the run's own artifacts, which "
        "mechanisms ran, which failed, and which were not performed. A tool that "
        "FAILED or was not run is not 'executed' -- do not describe it as such. "
        "Empty results are 'not observed', stated plainly."),
    "6. Network Indicators & C2": (
        "Network infrastructure: URLs, domains, IPs, protocols. State the "
        "authoritative DYNAMIC-ANALYSIS STATUS line and whether each item is a "
        "static string or observed traffic; never present one as the other."),
    "7. Capabilities Assessment": (
        "What the sample is capable of, tied to capa rules and MITRE "
        "techniques, with evidence for each capability."),
    # Rendered deterministically from iocs.json, not authored -- see
    # _build_ioc_section for the measurement that forced it.
    "8. Indicators of Compromise": "(rendered deterministically)",
    "9. Detection Engineering": (
        "How an analyst would detect this: YARA logic, behavioural signatures, "
        "and what makes each rule specific rather than generic."),
    "10. MITRE ATT&CK Mapping": (
        "Tactic/technique table. Map only techniques the evidence supports."),
    "11. What We Don't Know": (
        "Explicit gaps: distinguish what the run did from what it did not "
        "examine. State the authoritative DYNAMIC-ANALYSIS STATUS line, and "
        "do not claim that a recorded detonation, runtime trace, or capture "
        "was absent. Explain remaining coverage limits and how to resolve them."),
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


# ---------------------------------------------------------------------------
# Section 8 is built deterministically, not authored by the model.
#
# Measured 2026-10-02 on win32k_dll: with the technical report complete (13/13),
# the audit failed on report:unverified_iocs:11 -- every entry a canonical Windows
# registry path (`...\CurrentVersion\Run`, `...\Winlogon`, `...\Policies\...`)
# that appears NOWHERE in the evidence pack. iocs.json for that sample has
# registry_keys: []. The model was writing well-known Windows locations from
# training, not reporting observations.
#
# Two prompt-level instructions against this had already failed (winservices 2,
# win32k_dll 11), because a report whose indicator section is empty looks like a
# failed analysis -- the instruction fights the section's own purpose. So the
# list is no longer authored at all: it is rendered from iocs.json, which records
# what the engines actually produced and which of them. An indicator that no
# engine produced cannot enter, because nothing generates it.
#
# The prose is deterministic too, and states what was searched and what was NOT
# found. That is the honest version of the section, and it is strictly more
# useful to a responder than invented Run keys.

_IOC_KINDS = (
    ("hashes", "File hashes"),
    ("domains", "Domains"),
    ("urls", "URLs"),
    ("ips", "IP addresses"),
    ("files", "File names / paths"),
    ("registry_keys", "Registry keys"),
    ("mutexes", "Mutexes"),
    ("emails", "Email addresses"),
    ("wallets_btc", "Cryptocurrency addresses (BTC)"),
    ("wallets_eth", "Cryptocurrency addresses (ETH)"),
)


def _ioc_value(v) -> str:
    """Render one indicator value readably.

    Extraction keeps defanged forms and can carry trailing junk from a string
    table: a NUL-padded value such as a URL followed by padding bytes and
    unrelated text. NUL padding and control characters are stripped and the value
    is fenced, so the report shows what the tool saw rather than embedding
    invisible bytes in the markdown.
    """
    if isinstance(v, dict):
        parts = [f"{k}={_ioc_value(x)}" for k, x in v.items()]
        return ", ".join(parts)
    s = str(v)
    # Cut at the first NUL, then strip control characters.
    if "\x00" in s:
        s = s.split("\x00", 1)[0]
    s = "".join(ch for ch in s if ch.isprintable() or ch == " ")
    return s.strip().rstrip("\\").strip() or str(v)


def _build_ioc_section(sha: str, tools_results: dict | None = None) -> str:
    """Render section 8 from iocs.json. Never calls the LLM.

    Absence is reported explicitly and attributed: "no registry keys were
    observed" plus the engines that searched is a finding. Inventing the
    canonical Run key to fill the space is not.
    """
    tools_results = tools_results or {}
    title = "8. Indicators of Compromise"
    out = [f"## {title}", ""]

    iocs_path = case_dir(sha) / "iocs.json"
    data: dict = {}
    if iocs_path.is_file():
        try:
            data = json.loads(iocs_path.read_text(errors="replace")) or {}
        except Exception as exc:                  # noqa: BLE001
            out += [f"Indicator extraction could not be read: {exc}.", ""]
    if not data:
        out += ["No indicator set was produced for this sample, so no "
                "indicators are listed. Nothing is claimed here: an absent "
                "indicator set means the extractors produced nothing to report, "
                "not that the sample is clean.", ""]
        return "\n".join(out)

    sources = data.get("source") or []
    engines = sorted({str(s) for s in sources if s})

    total = 0
    lines: list[str] = []
    for key, label in _IOC_KINDS:
        vals = data.get(key) or []
        if isinstance(vals, dict):
            vals = [vals]
        shown = [_ioc_value(v) for v in vals if _ioc_value(v)]
        if not shown:
            continue
        total += len(shown)
        lines.append(f"**{label}**")
        for v in shown:
            lines.append(f"- `{v}`")
        lines.append("")

    out += ["Every indicator below was produced by the analysis engines named in "
            "the attribution line and rendered from `iocs.json`; non-printable "
            "padding is removed for readability and stored defanging is kept. "
            "Nothing in this section is inferred, reconstructed, or supplied "
            "from general knowledge of what malware of this kind usually "
            "does.", ""]
    if lines:
        out += lines
    else:
        out += ["The extractors ran and produced no indicators.", ""]

    # What was searched and came back empty. This is the part an invented
    # indicator would otherwise overwrite.
    empty = [label for key, label in _IOC_KINDS
             if not (data.get(key) or ({} if key == "hashes" else []))]
    if empty:
        out += [f"**Not observed.** No {'; no '.join(empty)} were extracted from "
                "this sample. Absence here is a statement about what the tools "
                "recovered, not a claim that the behaviour is absent: a packed "
                "or obfuscated sample frequently hides these from static "
                "extraction, and dynamic analysis would be the next step.", ""]

    if engines:
        out += ["**Attribution.** Extracted deterministically from "
                + ", ".join(f"`{e}`" for e in engines)
                + ". Values are shown in the defanged form the extractor "
                "produced.", ""]
    out += [f"**Review before sharing.** {str(data.get('note') or '').strip()} "
            "Incident-response indicator sets routinely contain "
            "victim-specific data from ransom notes and similar artefacts.",
            ""]
    out += [f"Total indicators: **{total}**. Full set with provenance: "
            "`iocs.json`.", ""]
    return "\n".join(out)


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
                              sha: str, prior_sections_summary: str = "",
                              provenance_block_text: str = "",
                              locked_verdict: str | None = None) -> str:
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
    if provenance_block_text:
        parts.extend((provenance_block_text, ""))
    parts.extend((report_methodology_block([name, description]), ""))
    if prior_sections_summary:
        parts += ["## Prior sections (for continuity)",
                  prior_sections_summary, ""]
    if locked_verdict and locked_verdict != "unknown":
        parts += [
            "## Pipeline-selected report verdict control (not raw sample evidence)",
            f"The report verdict is locked to **{locked_verdict}**. Use this exact "
            "label in verdict fields and conclusions; do not upgrade or downgrade it. "
            "If evidence appears to disagree, report the disagreement as a limitation "
            "while preserving this report label. Do not cite this control as evidence "
            "for behavior, capability, family, or ATT&CK claims.",
            "",
        ]
    parts.append(
        "## Rules\n"
        f"- Write ONLY the '{name}' section, as markdown, beginning with a "
        "level-2 heading carrying that exact title.\n"
        "- TECHNICAL report for reverse engineers. Prefer MORE evidence over "
        "less.\n"
        "- COPY tables/rows from the evidence into the section, keeping "
        "addresses and eas exactly.\n"
        "- Every factual claim sentence and every evidence-table row MUST include "
        "(source: <engine>, query_or_table: <artifact or table>, row_or_rule: "
        "<exact observed row, address, or rule>). A source label alone is not a "
        "usable citation.\n"
        "- Use that exact parenthesized syntax at the end of EACH factual sentence. "
        "For table rows, include the full citation in the claim cell; do not put "
        "bare source metadata in a separate cell. Keep each sentence focused so "
        "its cited rows establish the complete claim. Prefer one factual sentence "
        "per bullet; never use one citation to cover multiple sentences, and split "
        "independent facts into separately cited claims. Before returning, check "
        "each factual sentence and table claim cell for its own exact source "
        "locator; remove any claim that cannot be tied to one.\n"
        "- When evidence exposes a verdict score and deep-dive confidence, keep "
        "them as separate source fields with exact labels and values; cite each "
        "field and never substitute or combine them.\n"
        "- Cross-section context is draft text for consistency only; cite the "
        "original tool artifact and row, never cross-section prose.\n"
        "- Quote registry paths and IoCs in FULL. Never abbreviate a path with "
        "'...' -- an unverifiable indicator is worse than none.\n"
        "- If a tool did not run or produced nothing, write 'not observed'. "
        "Never invent runtime behavior. The authoritative DYNAMIC-ANALYSIS "
        "STATUS block, when present in the evidence, is ground truth for the "
        "whole run: use it faithfully, but state the full run-wide status only "
        "in the Executive Summary. A component-specific absence (for "
        "example, RevAI's static Frida probe did not execute the sample) does "
        "not mean another path such as WinRE did not run. Do not say dynamic "
        "analysis or sandbox execution was not performed when the status block "
        "records an executed mechanism. Treat the status as global context, not "
        "boilerplate to repeat: state the full run status in the Executive Summary. "
        "In behavior or network sections, cite only component-specific runtime "
        "observations and coverage limits that affect that section's conclusion. "
        "Other sections should mention it only when needed to qualify their "
        "specific conclusion. Use "
        "'not observed' for behavior absent "
        "from the recorded window, and state the coverage limit.\n"
        "- The citation engine must match the evidence (a Malcat string is not "
        "an IDA SQL row).\n"
        "- The Verdict and Deep-Dive blocks are NARRATIVE CONTEXT, not "
        "evidence: their `summary` / `verdict.summary` prose was written by an "
        "earlier stage. Never cite it as a claim's (source: ...). Cite the tool "
        "artifact that observed the fact (malcat, yara, floss, capa, ghidra, "
        "deep_dive_agentic); if no tool observed it, write 'not observed'.\n"
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
    prior_summaries: dict[str, str] | None = None,
    provenance_block_text: str = "", mode: str | None = None,
    locked_verdict: str | None = None) -> dict[str, Any]:
    """Generate ONE technical section. Never raises: a failure is recorded."""
    description = TECHNICAL_SECTION_DESCRIPTIONS.get(name, name)
    result: dict[str, Any] = {"name": name, "llm_ok": False, "error": None,
                              "pass": 1}

    # Section 8 is rendered from iocs.json rather than authored. See
    # _build_ioc_section for the measurement that forced it.
    if name == "8. Indicators of Compromise":
        result["markdown"] = _build_ioc_section(sha)
        result["deterministic"] = True
        result["llm_ok"] = True
        return result

    try:
        evidence = _technical_section_evidence(name, blocks, header)
    except Exception as exc:                      # noqa: BLE001
        evidence = f"(evidence routing failed: {exc})"
        result["error"] = f"route: {exc}"
    # Every model-authored section gets the same deterministic execution fact.
    # Otherwise the executive summary or metadata can contradict the dedicated
    # dynamic section even when that section has the right status. The status is
    # short, authoritative evidence and is included again in pass 2.
    st_block = _dynamic_status_sentence(sha)
    if st_block:
        evidence = (f"DYNAMIC-ANALYSIS STATUS (authoritative, read from the "
                    f"run's artifacts -- state it exactly, and do NOT claim "
                    f"a tool ran or evidence was absent when this says otherwise): "
                    f"{st_block}\n\n{evidence}")

    prior_lines = [f"  - {n}: {m[:200]}"
                   for n, m in list((prior_summaries or {}).items())[-3:] if m]
    prompt = _technical_section_prompt(
        name, description, evidence, sha,
        "\n".join(prior_lines) if prior_lines else "",
        provenance_block_text=provenance_block_text,
        locked_verdict=locked_verdict)
    result["evidence_chars"] = len(evidence)
    result["prompt_chars"] = len(prompt)

    response = None
    call_record = None
    try:
        resp = llm_judge(prompt)
        response = resp
        choice = (resp.get("choices") or [{}])[0]
        if choice.get("finish_reason") not in (None, "stop"):
            raise ValueError(
                f"incomplete technical section response "
                f"(finish_reason={choice.get('finish_reason')})"
            )
        content = resp["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("technical section response has no textual content")
        call_record = _persist_llm_call(
            sha, mode, "technical-p1", name, prompt, response=resp)
        v = normalize_llm_json(content)
        result["markdown"] = ensure_section_heading(
            normalize_llm_content(v) or content, name
        )
        result["title"] = v.get("title", name)
        result["uncited_claim_count"] = len(
            uncited_report_claims(result["markdown"]))
        result["first_draft_policy"] = (
            "first draft is preserved; claim support is assessed by the final gate"
        )
        meta = llm_call_metadata(resp)
        if meta:
            meta["request_model"] = get_llm_model()
            result["llm_audit"] = meta
        result["llm_call"] = call_record
        result["llm_ok"] = True
    except Exception as exc:                      # noqa: BLE001
        if call_record is None:
            call_record = _persist_llm_call(
                sha, mode, "technical-p1", name, prompt, response=response,
                error=f"{type(exc).__name__}: {exc}")
        result["llm_call"] = call_record
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
    max_workers: int = 6,
    provenance_block_text: str = "", mode: str | None = None,
    locked_verdict: str | None = None
    ) -> tuple[list[dict[str, Any]], str]:
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
                            sha, provenance_block_text=provenance_block_text,
                            mode=mode, locked_verdict=locked_verdict): name
                for name in TECHNICAL_REPORT_SECTIONS
            }
            for fut in futures:
                results.append(fut.result())
    else:
        for name in TECHNICAL_REPORT_SECTIONS:
            results.append(
                _generate_technical_section(
                    name, blocks, header, sha,
                        provenance_block_text=provenance_block_text,
                        mode=mode, locked_verdict=locked_verdict))

    order = {n: i for i, n in enumerate(TECHNICAL_REPORT_SECTIONS)}
    results.sort(key=lambda r: order.get(r.get("name", ""), 999))

    parts = [f"# Technical Malware Analysis Report\n"]
    for r in results:
        md = (r.get("markdown") or "").strip()
        if md:
            parts.append(md)
            parts.append("")
    return results, "\n".join(parts)


def _section_invocation_counts(pass1_results: list, pass2_results: list) -> dict[str, int]:
    """Count LLM section generations separately from local section builders."""
    def _requires_llm(result: dict) -> bool:
        spec = REPORT_SECTION_SPECS.get(result.get("name"), (None, None, False))
        return bool(spec[2])

    return {
        "pass1_llm_generation_calls": sum(1 for result in pass1_results if _requires_llm(result)),
        "pass2_llm_generation_calls": sum(1 for result in pass2_results if _requires_llm(result)),
        "local_sections": sum(1 for result in pass1_results if not _requires_llm(result)),
    }


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
    # Persist the same artifact-derived run status used by report prompts. The
    # prior code referenced `status_artifact` only while serializing the
    # section-results manifest; it was never initialized, so every section
    # report run crashed after writing the master report and before technical
    # publication, provenance binding, or downstream audit.
    status_artifact = dynamic_analysis_status(sha)

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
            futures = {
                pool.submit(_run, n, [], 1): n
                for n in REPORT_MASTER_SECTIONS
            }
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

    # Preserve the first-pass records before pass 2 replaces those entries in
    # the final assembly. Counts must represent the work actually performed.
    pass1_initial_results = list(pass1_results)

    # === PASS 2: re-generate LLM-required sections with cross-section context ===
    pass2_results: list = []
    pass2_timings: list = []
    if cross_refs:
        print(f"  [pass 2] re-generating LLM sections with cross-section context ...")
        # Only re-run sections that required LLM (skip 15/16 = appendices/signoff)
        llm_sections = [
            name for name in REPORT_MASTER_SECTIONS
            if REPORT_SECTION_SPECS.get(name, (None, None, False))[2]
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

    invocation_counts = _section_invocation_counts(
        pass1_initial_results, pass2_results
    )
    section_results = pass1_results
    section_timings = pass1_timings + pass2_timings

    # REDUCE: local Python concatenates (no LLM call)
    parts = [
        f"# RE Report — {sha[:12]}",
        f"_Generated {datetime.now(timezone.utc).isoformat()}_  ",
        f"_Pipeline: section-based Map-Reduce, "
        f"{invocation_counts['pass1_llm_generation_calls']} pass-1 LLM section calls"
        + (f" + {invocation_counts['pass2_llm_generation_calls']} pass-2 LLM section calls with cross-section context" if cross_refs else "")
        + f" + {invocation_counts['local_sections']} local sections"
        + "_",
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
    run_context = tools_results.get("_execution_context") or {}
    manifest_sha = tools_results.get("_report_input_manifest_sha256") or ""
    execution_comment = report_execution_comment(sha, run_context, manifest_sha) + "\n"
    report_markdown = provenance_block(sha) + execution_comment + "\n".join(parts)

    # Save evidence pack + backward-compat root files
    out_dir = case_dir(sha) / "correlate"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "00-tools-raw.json").write_text(
        json.dumps(tools_results, indent=2, default=str))
    (out_dir / "01-section-results.json").write_text(
        json.dumps({"sections": section_results, "timings": section_timings,
                    "pass1_initial_results": pass1_initial_results,
                    "pass2_results": pass2_results,
                    "pass1_count": len(pass1_initial_results), "pass2_count": len(pass2_results),
                    "invocation_counts": invocation_counts},
                   indent=2, default=str)
    )
    report_markdown, _master_models = redact_model_names(report_markdown)
    if _master_models:
        print(f"[section_publisher] master_v3: redacted model name(s) "
              f"{_master_models}", flush=True)
    (out_dir / "02-REPORT-MASTER-v3.md").write_text(report_markdown)
    quick_verdict = (tools_results.get("verdict") or {}).get("verdict")
    deep_verdict = (tools_results.get("deep") or {}).get("verdict")
    master_verdict_lock = cross_stage_verdict_lock(
        infer_publish_verdict_from_markdown(report_markdown),
        quick_verdict=quick_verdict,
        deep_verdict=deep_verdict,
    )
    master_quality = evaluate_report_markdown(
        report_markdown,
        required_sections=REPORT_MASTER_SECTIONS,
        source="llm_judge",
        min_total_chars=1500,
        label="master_v3",
        evidence_root=case_dir(sha),
        verdict_lock=master_verdict_lock,
    )

    # Backward compatibility: also write at logs root
    root_dir = case_dir(sha)
    (root_dir / "REPORT-MASTER-v3.md").write_text(report_markdown)
    (root_dir / "section-results-v3.json").write_text(
        json.dumps({"sha256": sha,
                    "run_id": (revai_provenance(sha).get("run_id")),
                    "analysis_mode": (tools_results.get("_execution_context") or {}).get("mode"),
                    "report_input_manifest_sha256": tools_results.get(
                        "_report_input_manifest_sha256"),
                    "sections": section_results, "timings": section_timings,
                    "pass1_initial_results": pass1_initial_results,
                    "pass2_results": pass2_results,
                    "pass1_count": len(pass1_initial_results), "pass2_count": len(pass2_results),
                    "invocation_counts": invocation_counts,
                    "master_v3_quality": master_quality,
                    "master_v3_verdict_lock": master_verdict_lock,
                    "dynamic_analysis_status": status_artifact},
                   indent=2, default=str)
    )

    # Generate technical report alongside the section-based master report
    technical = run_technical_publish(sha, tools_results)

    return {
        "sections": section_results,
        "timings": section_timings,
        "pass1_results": pass1_results,
        "pass1_initial_results": pass1_initial_results,
        "pass2_results": pass2_results,
        "invocation_counts": invocation_counts,
        "report_markdown": report_markdown,
        "report_size": len(report_markdown),
        "master_quality": master_quality,
        "master_verdict_lock": master_verdict_lock,
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
        "run_id": (tools_results.get("_execution_context") or {}).get("run_id"),
        "analysis_mode": (tools_results.get("_execution_context") or {}).get("mode"),
        "_report_provenance_block": tools_results.get("_report_provenance_block", ""),
        "_report_input_manifest_sha256": tools_results.get(
            "_report_input_manifest_sha256"),
    }
    if session_path.exists():
        try:
            session = json.loads(session_path.read_text())
        except Exception:
            pass
    session.update({
        "sha256": sha,
        "run_id": (tools_results.get("_execution_context") or {}).get("run_id"),
        "analysis_mode": (tools_results.get("_execution_context") or {}).get("mode"),
        "_report_provenance_block": tools_results.get("_report_provenance_block", ""),
        "_report_input_manifest_sha256": tools_results.get(
            "_report_input_manifest_sha256"),
    })

    verdict = tools_results.get("verdict")
    deep = tools_results.get("deep")
    yara_meta = tools_results.get("yara_meta") or tools_results.get("yara")
    audit = tools_results.get("audit_tail") or []

    sql_evidence = tools_results.get("sql_evidence")
    if sql_evidence is None:
        context = tools_results.get("_execution_context") or {}
        if context:
            sql_evidence = load_attested_case_json(
                case_dir(sha, context.get("mode")),
                "deep_dive/00-sql-evidence.json", sha, context)

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
            quick_result = tools_results.get("verdict")
            deep_result = tools_results.get("deep")
            verdict_control = cross_stage_verdict_lock(
                None,
                quick_verdict=(quick_result.get("verdict")
                               if isinstance(quick_result, dict) else None),
                deep_verdict=(deep_result.get("verdict")
                              if isinstance(deep_result, dict) else None),
            )
            tech_results, tech_md_built = generate_technical_sectionwise(
                sha, technical_evidence,
                provenance_block_text=str(
                    tools_results.get("_report_provenance_block") or ""),
                mode=(tools_results.get("_execution_context") or {}).get("mode"),
                locked_verdict=verdict_control.get("upstream"))
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
                "report_input_manifest_sha256": tools_results.get(
                    "_report_input_manifest_sha256"),
                "report_input_manifest": tools_results.get("_report_input_manifest"),
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
    # No legacy run_scorecard is used. The completed report set is checked by
    # the source-bound claim-support gate during quality aggregation; tool I/O
    # truth is checked by audit_pipeline.py.
    prompt = f"""# Technical Malware Analysis Report v3

You MUST produce markdown with ALL of these level-2 headings (exact titles, ASCII only):
{sections}

Rules (evidence-first, MORE detail preferred):
- TECHNICAL report for reverse engineers. Prefer MORE evidence over less.
- COPY tables/rows from Structured Evidence into matching sections (keep addresses/eas).
- Every claim MUST include (source: <engine>, query_or_table: <artifact or table>,
  row_or_rule: <exact observed row, address, or rule>). A source label alone is
  not a usable citation.
- REQUIRED embeds when present: section layout, full IAT, capa+YARA, high-signal strings with engine+ea,
  UPX stdout + unpacked_path, function metrics, EP/decompress disasm.
- Empty Speakeasy/Frida → write 'not observed'. Never invent runtime behavior.
- Citation engine must match evidence (Malcat string ≠ IDA SQL).
- The Verdict and Deep-Dive blocks are NARRATIVE CONTEXT, not evidence: their
  `summary` / `verdict.summary` prose was written by an earlier stage. Never
  cite it as a claim's (source: ...). Cite the tool artifact that observed the
  fact (malcat, yara, floss, capa, ghidra, deep_dive_agentic); if no tool
  observed it, write 'not observed'.
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
    mono_call_num = 1
    try:
        mono_prompt = prompt
        resp = llm_judge(prompt)
        _persist_llm_call(
            sha, (tools_results.get("_execution_context") or {}).get("mode"),
            "technical-monolithic-1", "full-report", mono_prompt, response=resp)
        if (resp.get("choices") or [{}])[0].get("finish_reason") not in (None, "stop"):
            raise ValueError(
                "incomplete technical report response "
                f"(finish_reason={(resp.get('choices') or [{}])[0].get('finish_reason')})"
            )
        content = resp["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("technical report response has no textual content")
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
            retry_response = None
            try:
                retry_prompt = (
                    prompt
                    + "\n\nYour previous output was incomplete: it is missing "
                    "these sections: "
                    + ", ".join(_miss1)
                    + ". Complete the FULL report with every required heading; "
                    "do not truncate. Return the complete markdown."
                )
                resp2 = llm_judge(retry_prompt)
                retry_response = resp2
                _persist_llm_call(
                    sha, (tools_results.get("_execution_context") or {}).get("mode"),
                    "technical-monolithic-2", "full-report", retry_prompt,
                    response=resp2)
                if (resp2.get("choices") or [{}])[0].get("finish_reason") not in (None, "stop"):
                    raise ValueError(
                        "incomplete technical retry response "
                        f"(finish_reason={(resp2.get('choices') or [{}])[0].get('finish_reason')})"
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
                if retry_response is None and "retry_prompt" in locals():
                    _persist_llm_call(
                        sha, (tools_results.get("_execution_context") or {}).get("mode"),
                        "technical-monolithic-2", "full-report", retry_prompt,
                        error=f"{type(retry_exc).__name__}: {retry_exc}")
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
        if "mono_prompt" in locals() and "resp" not in locals():
            _persist_llm_call(
                sha, (tools_results.get("_execution_context") or {}).get("mode"),
                f"technical-monolithic-{mono_call_num}", "full-report", mono_prompt,
                error=f"{type(e).__name__}: {e}")
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
    technical_report["provenance"] = revai_provenance(sha)
    run_context = (tools_results or {}).get("_execution_context") or {}
    manifest = (tools_results or {}).get("_report_input_manifest") or {}
    manifest_sha = (tools_results or {}).get("_report_input_manifest_sha256")
    if run_context:
        technical_report.update({
            "run_id": run_context.get("run_id"),
            "analysis_mode": run_context.get("mode"),
            "report_input_manifest_sha256": manifest_sha,
            "report_input_manifest": manifest,
        })
    if technical_report["provenance"].get("run_id"):
        technical_report["run_id"] = technical_report["provenance"]["run_id"]
    execution_comment = report_execution_comment(sha, run_context, manifest_sha or "") + "\n"
    tech_md = provenance_block(sha) + execution_comment + tech_md
    # Deterministic alignment sections (plan #12) - IOC tiers, dynamic analysis,
    # explicit gaps - appended before quality eval. The gap scan uses the report
    # as the LLM wrote it, so it cannot quote our own caveats.
    _report_scan_text = tech_md
    tech_md = attach_ioc_confidence(tech_md, sha)
    tech_md = attach_capability_coverage(tech_md, sha)
    tech_md = attach_behavioural_model(tech_md, sha)
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
    technical_report["markdown"] = tech_md
    tech_md, _tech_models = redact_model_names(tech_md)
    if _tech_models:
        technical_report["model_names_redacted"] = _tech_models
        print(f"[section_publisher] technical_v3: redacted model name(s) "
              f"{_tech_models}", flush=True)
    technical_report["markdown"] = tech_md
    technical_verdict_lock = cross_stage_verdict_lock(
        infer_publish_verdict_from_markdown(tech_md),
        quick_verdict=(tools_results.get("verdict") or {}).get("verdict"),
        deep_verdict=(tools_results.get("deep") or {}).get("verdict"),
    )
    technical_report["verdict_lock"] = technical_verdict_lock
    q = evaluate_report_markdown(
        tech_md,
        required_sections=TECHNICAL_REPORT_SECTIONS,
        source=technical_report.get("source"),
        min_total_chars=8000,
        label="technical_v3",
        evidence_root=case_dir(sha),
        verdict_lock=technical_verdict_lock,
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

    # The v3 publisher consumes the exact run manifest written by v2. Never
    # search the flat case directory or another mode: equal sample hashes do
    # not make artifacts from separate executions interchangeable.
    sha = args.sha
    context = require_execution_context(sha, stage="section_publisher")
    mode_dir = case_dir(sha, context["mode"])
    manifest_path = mode_dir / "publish" / "report-input-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"section_publisher requires the v2 input manifest: {exc}") from exc
    required_inputs = [
        "verdict.json", "quick_scan/00-tools-raw.json",
        "deep_dive/01-tools-raw.json", "deep_dive/05-deep-dive.json",
        "rule.yara.json", "deep_dive/02-dynamic-pack.json",
        "dynamic-analysis-status.json", "iocs.json",
    ]
    assert_report_input_manifest(manifest, required_inputs)
    validate_report_input_manifest(manifest, sha, context, mode_dir)
    manifest_digest = report_input_manifest_digest(manifest)
    provenance_text = format_report_input_manifest(manifest)

    tools_results: dict = {
        "sample_path": "?",
        "_execution_context": context,
        "_report_input_manifest": manifest,
        "_report_input_manifest_sha256": manifest_digest,
        "_report_provenance_block": provenance_text,
        "_report_source_artifacts": {
            "verdict": "verdict.json",
            "quick_scan": "quick_scan/00-tools-raw.json",
            "deep_dive": "deep_dive/01-tools-raw.json",
            "deep_summary": "deep_dive/05-deep-dive.json",
            "yara_generation": "rule.yara.json",
            "dynamic_pack": "deep_dive/02-dynamic-pack.json",
            "dynamic_status": "dynamic-analysis-status.json",
            "iocs": "iocs.json",
            "ti_enrich": "quick_scan/ti-enrich.json",
        },
    }
    session_path = Path(f"/opt/samples/sessions/{sha}.json")
    if session_path.is_file():
        session = json.loads(session_path.read_text(encoding="utf-8"))
        if session.get("sha256") not in (None, sha):
            raise RuntimeError("session metadata SHA-256 does not match the active report")
        tools_results["sample_path"] = session.get("sample_path", "?")

    def _input(rel: str, *, required: bool = False) -> dict | None:
        return load_attested_case_json(
            mode_dir, rel, sha, context, required=required)

    verdict = _input("verdict.json", required=True)
    deep = _input("deep_dive/05-deep-dive.json", required=True)
    quick_raw = _input("quick_scan/00-tools-raw.json", required=True) or {}
    deep_raw = _input("deep_dive/01-tools-raw.json", required=True) or {}
    tools_results["verdict"] = verdict
    tools_results["deep"] = deep
    tools_results["yara_meta"] = _input("rule.yara.json", required=True)
    tools_results["iocs"] = _input("iocs.json", required=True)
    tools_results["ti_enrich"] = _input("quick_scan/ti-enrich.json")
    tools_results["_dynamic_status"] = _input(
        "dynamic-analysis-status.json", required=True)
    tools_results["dynamic_pack"] = _input(
        "deep_dive/02-dynamic-pack.json", required=True)

    # Strip pack-level identity before merging tool keys; the exact source
    # artifact map above remains the provenance for citations.
    quick_raw.pop("_cadre_provenance", None)
    deep_raw.pop("_cadre_provenance", None)
    tools_results.update(quick_raw)
    tools_results.update(deep_raw)

    from v2_lib import cross_stage_verdict_lock
    _quick_verdict = (verdict or {}).get("verdict")
    _deep_verdict = (deep or {}).get("verdict")
    _lock = cross_stage_verdict_lock(
        _quick_verdict, quick_verdict=_quick_verdict,
        deep_verdict=_deep_verdict)
    _locked = (_lock or {}).get("upstream") or _quick_verdict
    if _locked and _locked != _quick_verdict:
        tools_results["verdict"] = dict(verdict or {})
        tools_results["verdict"].update(
            verdict=_locked, locked_from=_quick_verdict, verdict_lock=_lock)
    # For real evidence cards, need to call the tools — load from existing logs
    print(f"Running section-based publish for {sha[:12]}")
    print(f"  (tools_results has: {list(tools_results.keys())})")
    print("  Note: for full evidence, run quick_scan_v2 + deep_dive_v2 first")
    result = run_section_based_publish(
        sha, tools_results, parallel=not args.no_parallel, hitl_between=args.hitl
    )
    print(f"  report: {result['report_size']} chars, "
          f"{sum(1 for s in result['sections'] if s.get('llm_ok'))} LLM calls ok")
    print(f"  saved: {mode_dir / 'REPORT-MASTER-v3.md'}")
    tech = result.get("technical", {})
    if tech:
        print(f"  technical: {tech.get('technical_size', 0)} chars, "
              f"{tech.get('sections_complete', 0)}/{len(TECHNICAL_REPORT_SECTIONS)} sections "
              f"source={tech.get('source')} quality_ok={tech.get('ok')}")
        print(f"  saved: {mode_dir / 'REPORT-TECHNICAL-v3.md'}")
    llm_ok_n = sum(1 for s in result["sections"] if s.get("llm_ok"))
    section_fail = any(
        (not s.get("llm_ok")) and s.get("error")
        for s in result["sections"]
    )
    tech_ok = bool((tech or {}).get("ok"))
    master_ok = bool((result.get("master_quality") or {}).get("ok")) and not section_fail
    ok = master_ok and tech_ok and llm_ok_n > 0
    # v3 has now finalized both reports. Rebind the complete report set so the
    # downstream audit can reject stale or post-generation edits by hash.
    record_report_outputs(
        mode_dir, sha, context,
        tools_results["_report_input_manifest_sha256"],
        report_names=[
            "REPORT-v2.md", "REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md",
            "REPORT-MASTER-v3.md", "REPORT-TECHNICAL-v3.md",
        ])
    print(f"[section_publisher] complete ok={ok} master_ok={master_ok} tech_ok={tech_ok}")
    raise SystemExit(0 if ok else 1)

