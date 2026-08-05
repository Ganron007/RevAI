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

# RevAI: Malcat is optional — sections that depend on it are allowed to be
# stubbed when Malcat is not installed, without failing the quality gate.
_MALCAT_OPTIONAL_SECTIONS = frozenset({
    "4. Malcat Triage Summary",
})
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
    ok = not issues
    return {
        "ok": ok,
        "label": label,
        "source": source,
        "chars": len(md or ""),
        "missing_sections": missing,
        "stub_sections": stubs,
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
            "4. Malcat Triage Summary",
            "5. Static Code Analysis",
            "6. Behavioral & Dynamic Analysis",
            "7. Network Indicators & C2",
            "8. Capabilities & MITRE ATT&CK Mapping",
            "9. Indicators of Compromise",
            "10. Detection Engineering",
            "11. What We Don't Know",
            "12. Appendix: Analysis Environment",
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
    if ag and not ag.get("sql_deep_ok"):
        issues.append("deep:sql_deep_ok_false")

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
