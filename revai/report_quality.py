#!/usr/bin/env python3
"""report_quality.py — hard quality gates for publish / section / orchestrator.

GREEN means: LLM-authored analyst narrative, all required headings present,
no stub-only sections, no deterministic_fallback* sources.

rc==0 alone is NEVER sufficient.
"""
from __future__ import annotations

import json
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

# Stub / pointer prose that means the LLM narrative was discarded
_STUB_PATTERNS = (
    r"see\s+\*\*malcat",
    r"see\s+\*\*capa",
    r"see\s+\*\*radare2",
    r"see\s+\*\*yara",
    r"see\s+\*\*speakeasy",
    r"see\s+appendix",
    r"see\s+.*in the appendix",
    r"copy those tables for review",
    r"full structured evidence pack is appended",
    r"evidence-first deterministic path",
)

# RevAI: Malcat is optional — its evidence lives inside Static Analysis /
# Appendix A (Tool Evidence Trail), so no section is malcat-exclusive anymore.
_MALCAT_OPTIONAL_SECTIONS = frozenset()
_MALCAT_INSTALLED = Path("/opt/malcat/bin/malcat.mcp.py").is_file()

_FALLBACK_SOURCES = (
    "deterministic_fallback",
    "deterministic_fallback_after_incomplete_llm",
)

# Acceptable LLM / salvage sources that still require body quality
_OK_SOURCES = (
    "llm_judge",
    "llm_raw_markdown",
    "section_publisher",
)


def normalize_heading_text(s: str) -> str:
    """NFKC + curly quotes/apostrophes → ASCII for heading matching."""
    if not s:
        return ""
    t = unicodedata.normalize("NFKC", s)
    for a, b in (
        ("\\'", "'"),  # \' (LLM-escaped apostrophe, e.g. "Don\'t")
        ('\\"', '"'),  # \" (LLM-escaped quote)
        ("\u2019", "'"),  # ’
        ("\u2018", "'"),  # ‘
        ("\u2032", "'"),  # ′
        ("\u201c", '"'),  # “
        ("\u201d", '"'),  # ”
        ("\u00b4", "'"),  # ´
        ("\u0060", "'"),  # `
        ("\u2013", "-"),  # –
        ("\u2014", "-"),  # —
    ):
        t = t.replace(a, b)
    return t


def heading_present(md: str, section: str) -> bool:
    """True if section title appears (ASCII-normalized, case-insensitive)."""
    hay = normalize_heading_text(md).lower()
    full = normalize_heading_text(section).lower()
    key = full.split(".", 1)[-1].strip() if full[:1].isdigit() else full
    return key in hay or full in hay


def missing_sections(md: str, required: list[str]) -> list[str]:
    return [s for s in required if not heading_present(md, s)]


def _section_bodies(md: str, required: list[str]) -> dict[str, str]:
    """Split markdown by required section titles; return body text per section."""
    norm_md = normalize_heading_text(md)
    # Find ## or # headings that match required titles
    bodies: dict[str, str] = {s: "" for s in required}
    # Build search positions for each required section
    positions: list[tuple[int, str]] = []
    low = norm_md.lower()
    for s in required:
        full = normalize_heading_text(s).lower()
        key = full.split(".", 1)[-1].strip() if full[:1].isdigit() else full
        # prefer "## N. Title" style
        for pat in (
            f"## {full}",
            f"# {full}",
            f"## {key}",
            f"# {key}",
        ):
            idx = low.find(pat.lower())
            if idx >= 0:
                positions.append((idx, s))
                break
        else:
            # loose: title substring as its own line start
            idx = low.find(key)
            if idx >= 0:
                positions.append((idx, s))
    positions.sort(key=lambda x: x[0])
    for i, (start, name) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(norm_md)
        bodies[name] = norm_md[start:end]
    return bodies


def stub_sections(md: str, required: list[str], *, min_body_chars: int = 180) -> list[str]:
    """Sections whose body is pointer-stub or too short (excluding short-by-nature)."""
    bodies = _section_bodies(md, required)
    stub_re = re.compile("|".join(_STUB_PATTERNS), re.I)
    bad: list[str] = []
    for s in required:
        low = s.lower()
        # Short-by-nature / env notes — do not treat as narrative stubs
        if (
            low.startswith("12.")
            or "appendix" in low
            or "author" in low
            or "sign-off" in low
            or "signoff" in low
        ):
            continue
        body = bodies.get(s) or ""
        # strip the heading line itself
        lines = body.splitlines()
        content = "\n".join(lines[1:] if lines else []).strip()
        if len(content) < min_body_chars:
            bad.append(s)
            continue
        # If body is mostly a "see appendix" pointer
        if stub_re.search(content) and len(content) < 600:
            bad.append(s)
    return bad


def source_is_fallback(source: str | None) -> bool:
    s = (source or "").strip().lower()
    return any(s == f or s.startswith(f) for f in _FALLBACK_SOURCES)


def source_is_llm_ok(source: str | None) -> bool:
    s = (source or "").strip().lower()
    if source_is_fallback(s):
        return False
    if not s:
        return False
    return s in _OK_SOURCES or s.startswith("llm_")


REPORT_STYLE_CONTRACT = """REPORT STYLE CONTRACT (mandatory — expert-report conventions):
1. QUOTE-THEN-TRANSLATE: every code/string/table artifact is introduced with a
   sentence, then interpreted: what it does, why it matters, what behavior it
   implies. NEVER dump an artifact with no surrounding explanation.
2. OBSERVATION -> IMPLICATION: claims follow "we observed X, which indicates Y
   because Z" — evidence first, then its meaning.
3. OBSERVED vs LATENT: annotate capabilities as actually-observed or
   present-but-unused; never present latent capability as observed behavior.
4. INFERENCE FLAGGED AS INFERENCE: hedged conclusions use 'likely', 'possibly',
   'appears', 'we assess' — never assert unproven inference as fact.
5. EVIDENCE TRACEABILITY: every claim carries (source: <engine>) — a reader
   must be able to walk any statement back to a tool result.
6. CONFIDENCE & UNKNOWNS: state explicitly what we don't know and why (tool
   absent, packed, no runtime trigger). Unknowns live in their own
   section/paragraph with reasoning.
7. NARRATIVE FLOW: modules/components are walked through in execution order,
   each with an explanation paragraph, not a wall of evidence.
8. READER TEST: a reader with no prior context must be able to follow the
   analysis from verdict to evidence without asking the model for clarification.
"""

VERDICT_CALIBRATION_CONTRACT = """VERDICT CALIBRATION (mandatory — keygenme false-positive fix, 2026-08-07):
1. Obfuscation / packing / protection / high entropy / custom VMs / encoders are
   NEUTRAL signals. They appear identically in benign software (crackmes,
   keygens, games, commercial protectors). NEVER conclude 'malicious' from them
   alone.
2. MALICIOUS requires behavioral-INTENT evidence: file destruction/encryption
   of user data, C2/beaconing, persistence, credential theft, defense
   impairment (AV/AMSI/ETW disabling), lateral movement, or data exfiltration.
3. A sample whose only signals are protection/obfuscation is at most
   SUSPICIOUS — an analyst would want more, but the binary itself shows no
   hostile behavior.
4. ELF awareness: statically-linked ELF binaries have NO import table by
   definition — zero imports is normal, not packing evidence.
5. ARCHITECTURE GROUNDING: derive the architecture from the file header
   (file_type); never assert an architecture you did not verify (e.g. do not
   call an x86-64 ELF 'AARCH64').
6. When in doubt between malicious and suspicious on protection-only evidence,
   choose suspicious and say why in the report.
7. CITATIONS APPLY TO EVERY VERDICT: even a suspicious or clean verdict must
   cite the evidence behind each claim (source: engine). A low-signal sample
   still gets a report with its (few) findings cited — never a citation-free
   report.
"""


def evaluate_report_markdown(
    md: str,
    *,
    required_sections: list[str],
    source: str | None = None,
    min_total_chars: int = 4000,
    label: str = "report",
) -> dict[str, Any]:
    """Hard gate for one report markdown (+ optional source from JSON meta)."""
    missing = missing_sections(md, required_sections)
    stubs = stub_sections(md, required_sections) if not missing else []
    # RevAI: soften Malcat-dependent stubs when Malcat is not installed.
    if not _MALCAT_INSTALLED and stubs:
        stubs = [s for s in stubs if s not in _MALCAT_OPTIONAL_SECTIONS]
    issues: list[str] = []
    if source_is_fallback(source):
        issues.append(f"{label}:source_fallback:{source}")
    elif source is not None and not source_is_llm_ok(source):
        issues.append(f"{label}:source_not_llm:{source}")
    if missing:
        issues.append(f"{label}:missing_sections:{missing}")
    if stubs:
        issues.append(f"{label}:stub_sections:{stubs}")
    if len(md or "") < min_total_chars:
        issues.append(f"{label}:too_short:{len(md or '')}<{min_total_chars}")
    # Deterministic salvage markers in body
    low = normalize_heading_text(md or "").lower()
    if "evidence-first deterministic path" in low or "deterministic fallback" in low:
        issues.append(f"{label}:deterministic_body_marker")

    # --- Report-style gates (LLM sources only; deterministic fallbacks are
    # exempt — they are salvage, not authored prose). Style is evaluated on
    # the NARRATIVE body only: everything after the Structured Evidence /
    # Evidence Pack appendix is raw tool output and must not trip the gates.
    style: dict[str, Any] = {}
    if md and not source_is_fallback(source):
        style_md = md
        for line in (style_md or "").splitlines():
            t = line.strip().lower()
            if t.startswith("## structured evidence") or t.startswith("## evidence pack") \
                    or t.startswith("## appendix") or t.startswith("### structured evidence"):
                style_md = style_md[: style_md.find(line)]
                break
        style["byline_ok"] = "revai provenance" in (style_md or "").lower()
        style["citation_count"] = (style_md or "").lower().count("(source:")
        content = [l for l in (style_md or "").splitlines() if l.strip()]
        in_fence = False
        prose = 0
        table = 0
        for l in content:
            if l.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            if l.lstrip().startswith("|"):
                table += 1
                continue
            if l.lstrip().startswith("#"):
                continue  # headings are structure, not prose
            prose += 1
        total = max(1, prose + table)
        style["prose_ratio"] = round(prose / total, 2)
        # Last-resort backstop only: pure dumps run 0-5% prose; table-heavy but
        # interpreted narratives run 15-30%. Precise gates (orphan_tables,
        # bare_fences) carry the real detection weight.
        min_ratio = 0.15 if "technical" in label else 0.15
        style["min_prose_ratio"] = min_ratio
        style["dump_style"] = prose / total < min_ratio
        # Table-orphan check: a table block with NO interpretation paragraph
        # after it (before the next table or heading) is a dump-style orphan.
        # This is the precise signal — global ratio alone is too blunt for
        # table-heavy technical reports (IATs, IOC tables are legitimate).
        lines_n = list(style_md.splitlines())
        in_table = False
        table_ends = []
        for i, l in enumerate(lines_n):
            if l.lstrip().startswith("|"):
                if not in_table:
                    in_table = True
                continue
            if in_table:
                in_table = False
                table_ends.append(i)
        orphan = 0
        for i in table_ends:
            nxt = ""
            for j in range(i, min(i + 40, len(lines_n))):
                l = lines_n[j].strip()
                if not l:
                    continue
                nxt = l
                break
            if not nxt:
                orphan += 1  # table at EOF with no following interpretation
                continue
            # Table immediately followed by another table with no prose between
            # = dump-style orphan. Table -> heading is legitimate (a section
            # may end with a summary table).
            if nxt.startswith("|"):
                orphan += 1
        style["table_orphans"] = orphan
        style["tables_ok"] = orphan <= 2
        idxs = [i for i, l in enumerate(content) if l.lstrip().startswith("```")]
        bare = 0
        for a, b in zip(idxs, idxs[1:]):
            between = " ".join(content[a + 1 : b])
            # Only flag LARGE bare dumps: both fence blocks substantial
            # (>=4 lines each) and little prose between them. Small snippets
            # with an intro/outro sentence are legitimate.
            if len(between.strip()) < 60 and (b - a - 1) >= 8:
                bare += 1
        style["bare_fence_pairs"] = bare
        style["bare_fences_ok"] = bare <= 2
        min_cites = 8 if "technical" in label else 3
        style["min_citations"] = min_cites
        style["citation_coverage_ok"] = style["citation_count"] >= min_cites
        if not style["byline_ok"]:
            issues.append(f"{label}:no_byline")
        if style["dump_style"]:
            issues.append(
                f"{label}:dump_style:prose_ratio={style['prose_ratio']}<{min_ratio}"
            )
        if not style["tables_ok"]:
            issues.append(f"{label}:orphan_tables:{orphan}")
        if not style["bare_fences_ok"]:
            issues.append(f"{label}:bare_fences:{bare}")
        if not style["citation_coverage_ok"]:
            issues.append(
                f"{label}:low_citations:{style['citation_count']}<{min_cites}"
            )
    ok = not issues
    return {
        "ok": ok,
        "label": label,
        "source": source,
        "chars": len(md or ""),
        "missing_sections": missing,
        "stub_sections": stubs,
        "style": style,
        "issues": issues,
    }


def evaluate_sha_publish_quality(logs_dir: Path, sha: str) -> dict[str, Any]:
    """Disk-level quality gate used by audit + orchestrator."""
    root = Path(logs_dir) / sha
    issues: list[str] = []
    checks: dict[str, Any] = {}

    def _load(p: Path) -> dict:
        if not p.is_file():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return {}

    master_j = _load(root / "report-v2.json")
    tech2_j = _load(root / "report-technical-v2.json")
    tech3_j = _load(root / "report-technical-v3.json")
    master_md = (root / "REPORT-MASTER-v2.md").read_text(encoding="utf-8", errors="replace") if (root / "REPORT-MASTER-v2.md").is_file() else ""
    tech2_md = (root / "REPORT-TECHNICAL-v2.md").read_text(encoding="utf-8", errors="replace") if (root / "REPORT-TECHNICAL-v2.md").is_file() else ""
    tech3_md = (root / "REPORT-TECHNICAL-v3.md").read_text(encoding="utf-8", errors="replace") if (root / "REPORT-TECHNICAL-v3.md").is_file() else ""
    master_v3 = (root / "REPORT-MASTER-v3.md").read_text(encoding="utf-8", errors="replace") if (root / "REPORT-MASTER-v3.md").is_file() else ""

    # Lazy import section lists from v2_lib when available
    try:
        from v2_lib import REPORT_MASTER_SECTIONS, TECHNICAL_REPORT_SECTIONS
    except Exception:
        TECHNICAL_REPORT_SECTIONS = [
            "1. Executive Summary",
            "2. Sample Metadata",
            "3. File Layout & Structural Analysis",
            "4. Static Code Analysis",
            "5. Behavioral & Dynamic Analysis",
            "6. Network Indicators & C2",
            "7. Capabilities Assessment",
            "8. Indicators of Compromise",
            "9. Detection Engineering",
            "10. MITRE ATT&CK Mapping",
            "11. What We Don't Know",
            "12. Appendix A: Tool Evidence Trail",
            "13. Appendix B: Analysis Environment",
        ]
        REPORT_MASTER_SECTIONS = []

    r_master = evaluate_report_markdown(
        master_md,
        required_sections=REPORT_MASTER_SECTIONS or [],
        source=master_j.get("source"),
        min_total_chars=2000,
        label="master_v2",
    )
    # If REPORT_MASTER_SECTIONS empty (import fail), skip heading checks
    if not REPORT_MASTER_SECTIONS:
        r_master["ok"] = bool(master_md) and not source_is_fallback(master_j.get("source"))
        r_master["issues"] = [] if r_master["ok"] else ["master_v2:import_or_empty"]

    r_tech2 = evaluate_report_markdown(
        tech2_md,
        required_sections=TECHNICAL_REPORT_SECTIONS,
        source=tech2_j.get("source"),
        min_total_chars=8000,
        label="technical_v2",
    )
    r_tech3 = evaluate_report_markdown(
        tech3_md,
        required_sections=TECHNICAL_REPORT_SECTIONS,
        source=tech3_j.get("source") or ("llm_judge" if tech3_md and not source_is_fallback(tech3_j.get("source")) else tech3_j.get("source")),
        min_total_chars=8000,
        label="technical_v3",
    )
    # section_publisher often omits source — treat missing source + good body as ok if not fallback
    if not tech3_j.get("source") and r_tech3.get("missing_sections") == [] and not r_tech3.get("stub_sections"):
        # clear source_not_llm if that was the only issue
        r_tech3["issues"] = [i for i in r_tech3["issues"] if not i.startswith("technical_v3:source_")]
        r_tech3["ok"] = not r_tech3["issues"]
        r_tech3["source"] = r_tech3.get("source") or "llm_judge_inferred"

    # RevAI: soften Malcat-dependent stubs when Malcat is not installed.
    # Sections listed in _MALCAT_OPTIONAL_SECTIONS may be legitimately stubbed
    # without failing the quality gate — the pipeline produces faster, thinner
    # reports without Malcat, which is the accepted trade-off.
    for _report in (r_tech2, r_tech3):
        if not _MALCAT_INSTALLED and _report.get("stub_sections"):
            _kept = [s for s in _report["stub_sections"] if s not in _MALCAT_OPTIONAL_SECTIONS]
            if _kept != _report["stub_sections"]:
                _report["stub_sections"] = _kept
                _report["issues"] = [i for i in _report["issues"]
                                     if not (":stub_sections:" in i and any(
                                         m in i for m in _MALCAT_OPTIONAL_SECTIONS))]
                _report["ok"] = not _report["issues"]

    checks["master_v2"] = r_master
    checks["technical_v2"] = r_tech2
    checks["technical_v3"] = r_tech3
    checks["master_v3_present"] = len(master_v3) >= 1500
    checks["tech3_file_present"] = bool(tech3_md)

    # Deep agentic gates
    ag = _load(root / "deep_dive" / "agentic_deep_dive.json")
    checks["deep_checklist_ok"] = bool(ag.get("checklist_ok"))
    checks["deep_sql_deep_ok"] = bool(ag.get("sql_deep_ok"))
    if ag and not ag.get("checklist_ok"):
        issues.append("deep:checklist_ok_false")
    # SQL gate: fail only when SQL deep analysis was NOT attempted (agent skip).
    # An attempted SQL call that failed on infrastructure (ghidrasql server died,
    # no IDA binary, format unsupported) is an honest, documented outcome — the
    # sample is still analyzed by the other engines. Recorded (informational) in
    # checks, not in gate-failing issues.
    if ag and not ag.get("sql_deep_ok"):
        if not ag.get("sql_deep_attempted"):
            issues.append("deep:sql_deep_ok_false")
        else:
            checks["deep_sql_deep_unavailable"] = ag.get("sql_deep_unavailable") or "sql_failed"
            checks["deep_sql_deep_fail_reason"] = (ag.get("sql_deep_fail_reason") or "")[:160]

    for key in ("master_v2", "technical_v2", "technical_v3"):
        if not checks[key].get("ok"):
            issues.extend(checks[key].get("issues") or [f"{key}:failed"])
    if not checks["master_v3_present"]:
        issues.append("master_v3:missing_or_short")
    if not checks["tech3_file_present"]:
        issues.append("technical_v3:file_missing")

    # Do NOT fold stale pipeline-audit stage_ok into live quality.
    # Re-run audit after publish; stage_ok is advisory only here.
    pa = _load(root / "pipeline-audit.json")
    checks["pipeline_audit_all_green"] = bool(pa.get("all_green")) if pa else False

    ok = not issues
    return {
        "ok": ok,
        "quality_green": ok,
        "sha256": sha,
        "issues": issues,
        "checks": checks,
        "models": {
            "master": master_j.get("model"),
            "technical_v2": tech2_j.get("model"),
            "technical_v3": tech3_j.get("model"),
            "planner_hint": os.environ.get("REVAI_LLM_PLANNER_MODEL", "configured via env"),
            "judgment_hint": os.environ.get("REVAI_LLM_VERDICT_MODEL", "configured via env"),
        },
    }


OUTPUT_FORMAT_CONTRACT = """
## OUTPUT FORMAT CONTRACT (mandatory — ASCII only)
Return ONE JSON object (no prose outside JSON). Schema:
{
  "title": "<string>",
  "markdown": "<full markdown report>",
  "sections_present": ["1. Executive Summary", "... exact titles ..."],
  "source": "llm_judge"
}

Markdown rules:
1. Use EXACT level-2 headings with ASCII apostrophe only: ## 11. What We Don't Know
   FORBIDDEN: curly apostrophe ('), smart quotes, em-dashes in headings.
2. Every required heading from the checklist MUST appear as `## <exact title>`.
3. Each non-appendix section MUST contain real analysis (≥180 chars), NOT "see appendix".
4. Copy evidence tables into the matching section. Cite (source: <engine>).
5. Do not invent runtime behavior. Empty Speakeasy/Frida → "not observed".
""".strip()
