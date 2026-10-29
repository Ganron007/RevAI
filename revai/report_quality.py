#!/usr/bin/env python3
"""report_quality.py — hard quality gates for publish / section / orchestrator.

GREEN means: LLM-authored analyst narrative, all required headings present,
no stub-only sections, no deterministic_fallback* sources.

rc==0 alone is NEVER sufficient.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

from citation_syntax import (
    has_citation_locator,
    is_disassembly_listing_line,
    parse_citation_annotations,
    strip_citation_annotations,
)
from report_schema import is_non_factual_markdown_line

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
    """True if an exact Markdown heading exists outside a fenced code block."""
    wanted = _section_heading_key(section)
    return any(
        _section_heading_key(title) == wanted
        for _, title in _markdown_heading_lines(md or "")
    )


def missing_sections(md: str, required: list[str]) -> list[str]:
    return [s for s in required if not heading_present(md, s)]


def ensure_section_heading(markdown: str, title: str) -> str:
    """Make the known section title deterministic while preserving its body.

    Section publishers already know which report section a response belongs
    to. If the model omits or changes that heading, prefix the canonical title
    instead of discarding otherwise useful evidence-grounded content.
    """
    text = str(markdown or "").strip()
    if not missing_sections(text, [title]):
        return text
    prefix = f"## {title}"
    return f"{prefix}\n\n{text}" if text else f"{prefix}\n"


def _section_bodies(md: str, required: list[str]) -> dict[str, str]:
    """Split markdown at exact required headings; return each section body.

    Do not search for titles in arbitrary prose. A narrative commonly mentions
    a later section (for example, "see What We Don't Know below"); treating
    that mention as a boundary truncates the real section and can turn a
    substantive report into a false stub.
    """
    norm_md = normalize_heading_text(md)
    bodies: dict[str, str] = {s: "" for s in required}
    wanted: dict[str, str] = {}
    for section in required:
        key = _section_heading_key(section)
        if key:
            wanted.setdefault(key, section)

    # A section boundary must be an exact Markdown heading outside fenced
    # code. This avoids references inside prose, tables, evidence quotes, or
    # code examples making a missing section appear present.
    positions: list[tuple[int, str]] = []
    for offset, title in _markdown_heading_lines(norm_md):
        section = wanted.get(_section_heading_key(title))
        if section is not None:
            positions.append((offset, section))

    # If a required heading appears more than once, the first occurrence owns
    # its body. Duplicates remain visible to other report-quality checks.
    unique_positions: list[tuple[int, str]] = []
    seen: set[str] = set()
    for position, section in positions:
        if section not in seen:
            unique_positions.append((position, section))
            seen.add(section)
    unique_positions.sort(key=lambda item: item[0])

    for i, (start, name) in enumerate(unique_positions):
        end = unique_positions[i + 1][0] if i + 1 < len(unique_positions) else len(norm_md)
        bodies[name] = norm_md[start:end]
    return bodies


def _markdown_heading_lines(md: str):
    """Yield (offset, title) pairs for Markdown headings outside fenced code."""
    offset = 0
    fence_char: str | None = None
    fence_len = 0
    for line in (md or "").splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", bare)
        if fence:
            marker = fence.group(1)
            if fence_char is None:
                fence_char, fence_len = marker[0], len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_len and not fence.group(2).strip():
                fence_char, fence_len = None, 0
            offset += len(line)
            continue
        if fence_char is None:
            match = re.match(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", bare)
            if match:
                yield offset, match.group(1)
        offset += len(line)


def _section_heading_key(title: str) -> str:
    """Canonicalize a Markdown heading for exact required-title matching."""
    value = normalize_heading_text(title).strip()
    value = re.sub(r"[*_`~]", "", value)
    value = re.sub(r"^\d+\s*\.\s*", "", value)
    value = re.sub(r"\s+", " ", value)
    return value.casefold()


def _report_narrative_body(markdown: str) -> str:
    """Return the report prose before its structured evidence/appendix area.

    Numbered headings such as ``## 12. Appendix A: Tool Evidence Trail`` are
    common in generated reports. The former prefix-only check missed those and
    counted evidence-trail material as analyst narrative.
    """
    text = markdown or ""
    for offset, title in _markdown_heading_lines(text):
        normalized = normalize_heading_text(title).strip()
        normalized = re.sub(r"^\d+(?:\.\d+)*[.)]?\s*", "", normalized)
        normalized = re.sub(r"[*_`~]", "", normalized).strip().lower()
        if normalized.startswith((
            "structured evidence",
            "evidence pack",
            "appendix",
            "appendices",
        )):
            return text[:offset]
    return text


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
   must be able to walk any statement back to a tool result. Attach the source
   to each claim sentence or evidence-table row; a citation elsewhere in the
   paragraph or a reference to another report section does not ground it.
6. CONFIDENCE & UNKNOWNS: state explicitly what we don't know and why (tool
   absent, packed, no runtime trigger). Unknowns live in their own
   section/paragraph with reasoning.
7. NARRATIVE FLOW: modules/components are walked through in execution order,
   each with an explanation paragraph, not a wall of evidence.
8. READER TEST: a reader with no prior context must be able to follow the
   analysis from verdict to evidence without asking the model for clarification.
9. DYNAMIC-ANALYSIS HONESTY (2026-08-12): if Speakeasy/Frida tools RAN — even
   with zero recorded events — say that they ran and what they recorded.
   NEVER write "no dynamic analysis was performed" when the tools executed;
   the honest phrasing is "dynamic analysis ran and observed no runtime
   events" (zero calls is a finding about anti-analysis, not a non-attempt).
10. ENTROPY UNITS (2026-08-12): entropy figures must be whole-file Shannon
    entropy in bits/byte (0-8); per-section values must name the section.
    Never present an unlabeled tool metric (e.g. Malcat's raw entropy field)
    as the file's entropy — it is a different measurement.
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
8. DO NOT OVER-CALIBRATE REAL MALWARE (vidar finding, 2026-08-07): calibration
   caps obfuscation-only samples. It does NOT excuse samples whose tools fire
   BEHAVIORAL signals — token/credential manipulation (win_token, lsass, token
   APIs), screen capture (screenshot), privilege escalation (escalate_priv),
   registry manipulation, anti-debug, process injection, C2 strings. When YARA
   or capa report such behavioral rules, those are behavioral-intent evidence —
   do NOT wave them off as 'generic' or 'neutral protection'. A dual-use
   branding (NSudo, Lync, AnyDesk, TeamViewer) is MASQUERADE unless the tool
   evidence proves the exact legitimate build; 'the filename suffix reflects
   collection context' is a hypothesis you must not treat as a finding.
"""


def count_table_orphans(md: str) -> int:
    """Count dump-style orphan tables by the quality gate's own rule.

    A table block immediately followed by another table (no prose between),
    or a table at end-of-text with no interpretation, counts as one orphan.
    Table -> heading is legitimate (a section may end with a summary table).
    Shared with the orphan-table repair pass (RC-32) so the gate and the
    repair can never drift apart.
    """
    lines_n = list((md or "").splitlines())
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
    return orphan


def evaluate_report_markdown(
    md: str,
    *,
    required_sections: list[str],
    source: str | None = None,
    min_total_chars: int = 4000,
    label: str = "report",
    evidence_root: Path | None = None,
    verdict_lock: dict[str, Any] | None = None,
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
    if verdict_lock is not None and not verdict_lock.get("ok", False):
        issues.append(
            f"{label}:verdict_lock_conflict:"
            f"{verdict_lock.get('reason') or 'publish claim contradicts upstream'}"
        )
    # Deterministic salvage markers in body
    low = normalize_heading_text(md or "").lower()
    if "evidence-first deterministic path" in low or "deterministic fallback" in low:
        issues.append(f"{label}:deterministic_body_marker")

    # --- Report-style gates (LLM sources only; deterministic fallbacks are
    # exempt — they are salvage, not authored prose). Style is evaluated on
    # the NARRATIVE body only: material after the appendix/evidence marker is
    # evaluated as evidence material, not prose. It may be selected or summarized
    # and must not be described as a complete verbatim copy of tool output.
    style: dict[str, Any] = {}
    if md and not source_is_fallback(source):
        style_md = _report_narrative_body(md)
        style["byline_ok"] = "revai provenance" in (style_md or "").lower()
        # Count the same balanced citation annotations the source resolver
        # consumes. Literal substring counts drifted from accepted syntax
        # (square-bracket annotations and metadata-only table cells), making
        # the displayed coverage number disagree with the claim gate.
        style["citation_count"] = len(parse_citation_annotations(style_md or ""))
        uncited_claims = _uncited_report_claims(style_md or "")
        style["uncited_claim_count"] = len(uncited_claims)
        style["uncited_claim_examples"] = uncited_claims[:8]
        style["claim_citations_ok"] = not uncited_claims
        content = [l for l in (style_md or "").splitlines() if l.strip()]
        in_fence = False
        prose = 0
        table = 0
        prose_chars = 0
        table_chars = 0
        for l in content:
            if l.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            if l.lstrip().startswith("|"):
                table += 1
                table_chars += len(l.rstrip())
                continue
            if l.lstrip().startswith("#"):
                continue  # headings are structure, not prose
            prose += 1
            prose_chars += len(l.rstrip())
        total = max(1, prose + table)
        total_chars = max(1, prose_chars + table_chars)
        style["prose_ratio"] = round(prose / total, 2)  # per line (legacy)
        style["prose_ratio_chars"] = round(prose_chars / total_chars, 3)
        # Last-resort backstop only: pure dumps run 0-5% prose; table-heavy but
        # interpreted narratives run 15-30%. Precise gates (orphan_tables,
        # bare_fences) carry the real detection weight.
        # Measured by CHARACTER volume: markdown paragraphs are single long
        # lines while tables are one line per row, so a line-based ratio
        # mis-flags table-heavy but well-explained reports (rehearsal
        # 2026-09-21: master v2 = 0.14 per line but 0.41 per char, 27 long
        # paragraphs, 0 orphan tables).
        min_ratio = 0.15
        style["min_prose_ratio"] = min_ratio
        style["dump_style"] = prose_chars / total_chars < min_ratio
        # Table-orphan check: a table block with NO interpretation paragraph
        # after it (before the next table or heading) is a dump-style orphan.
        # This is the precise signal — global ratio alone is too blunt for
        # table-heavy technical reports (IATs, IOC tables are legitimate).
        orphan = count_table_orphans(style_md)
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
                f"{label}:dump_style:prose_ratio_chars="
                f"{style.get('prose_ratio_chars')}<{min_ratio} "
                f"(per-line {style['prose_ratio']})"
            )
        if not style["tables_ok"]:
            issues.append(f"{label}:orphan_tables:{orphan}")
        if not style["bare_fences_ok"]:
            issues.append(f"{label}:bare_fences:{bare}")
        if not style["citation_coverage_ok"]:
            issues.append(
                f"{label}:low_citations:{style['citation_count']}<{min_cites}"
            )
        if not style["claim_citations_ok"]:
            issues.append(
                f"{label}:uncited_claims:{style['uncited_claim_count']}"
            )
    ioc_verification: dict[str, Any] | None = None
    if evidence_root is not None:
        try:
            evidence_text, evidence_files = collect_evidence_text(Path(evidence_root))
            ioc_verification = verify_claimed_iocs(
                md or "", evidence_text,
                metadata_hashes=_report_metadata_hashes(Path(evidence_root)),
            )
            ioc_verification["evidence_files"] = evidence_files
            if not evidence_files:
                issues.append(f"{label}:evidence_corpus_missing")
            ioc_issue = _ioc_factcheck_issue(ioc_verification)
            if ioc_issue:
                issues.append(f"{label}:{ioc_issue}")
        except Exception as exc:
            ioc_verification = {
                "error": f"{type(exc).__name__}: {exc}",
            }
            issues.append(f"{label}:ioc_factcheck_error:{type(exc).__name__}")
    ok = not issues
    return {
        "ok": ok,
        "label": label,
        "source": source,
        "chars": len(md or ""),
        "missing_sections": missing,
        "stub_sections": stubs,
        "style": style,
        "claimed_ioc_verification": ioc_verification,
        "issues": issues,
    }


_DYN_NEGATION_RE = re.compile(
    r"\bno\b.{0,140}\b(?:dynamic[- ]analysis(?:\s+tool)?|dynamic execution|"
    r"sandbox (?:analysis|execution))\b.{0,140}\b(?:performed|conducted|run|"
    r"invoked|executed|present|available|captured|collected)\b"
    r"|\b(?:dynamic[- ]analysis|dynamic execution)\b.{0,45}\b"
    r"(?:was|were|is|are)\s+not\s+(?:performed|conducted|run|invoked|"
    r"executed|present|available|captured|collected)\b",
    re.IGNORECASE,
)

# Explicit double-negation wording is affirmative: "it is not the case that no
# dynamic analysis was performed" means some dynamic analysis did run. Remove
# only that complete clause before checking for a blanket execution denial.
_DYN_NEGATED_NEGATION_RE = re.compile(
    r"\bit(?:'s| is| was)\s+not\s+the\s+case\s+that\s+"
    r"(?:there\s+(?:was|is)\s+)?no\s+"
    r"(?:dynamic[- ]analysis(?:\s+tool)?|dynamic execution|"
    r"sandbox (?:analysis|execution))\b.{0,100}\b"
    r"(?:performed|conducted|run|invoked|executed|present|available|"
    r"captured|collected)\b",
    re.IGNORECASE,
)

_DYN_META_NEGATION_RE = re.compile(
    r"\b(?:does\s+not|doesn't|do\s+not|don't|did\s+not|didn't)\s+"
    r"(?:mean|imply|indicate|establish|show)\s+(?:that\s+)?"
    r"(?:there\s+is\s+)?no\s+(?:dynamic[- ]analysis(?:\s+tool)?|"
    r"dynamic execution|sandbox (?:analysis|execution))\b.{0,100}\b"
    r"(?:performed|conducted|run|invoked|executed|present|available|"
    r"captured|collected)\b",
    re.IGNORECASE,
)

_DYN_META_AFFIRMATION_RE = re.compile(
    # "No dynamic analysis was skipped" is a double negative that affirms the
    # stages ran. Remove only that meta-clause before checking for a component
    # denial later in the same sentence.
    r"\bno\s+(?:dynamic[- ]analysis(?:\s+tool)?|dynamic execution|"
    r"sandbox (?:analysis|execution))\s+(?:was|were|is|are)\s+"
    r"(?:skipped|omitted|missed)\b",
    re.IGNORECASE,
)

_DYN_INNER_PAYLOAD_GAP_RE = re.compile(
    r"\bno\b[^\n.!?;,]{0,80}\b(?:dynamic|sandbox)\s+"
    r"(?:analysis|execution|detonation)\b[^\n.!?;,]{0,100}\b(?:of|for)\s+"
    r"(?:the\s+)?(?:inner|embedded)\s+(?:pe|payload)\b"
    r"(?:[^\n.!?;,]{0,100}\b(?:performed|conducted|run|executed|available|"
    r"present|captured|collected|in this run)\b)?"
    r"|\b(?:dynamic|sandbox)\s+(?:analysis|execution|detonation)\b"
    r"[^\n.!?;,]{0,70}\b(?:of|for)\s+(?:the\s+)?(?:inner|embedded)\s+"
    r"(?:pe|payload)\b[^\n.!?;,]{0,45}\b(?:was|were|is|are)\s+not\s+"
    r"(?:performed|conducted|run|executed|available|present)\b"
    r"|\b(?:inner|embedded)\s+(?:pe|payload)\b[^\n.!?;,]{0,70}\b"
    r"(?:was|were|is|are)\s+not\s+(?:dynamically\s+)?"
    r"(?:executed|detonated|run)\b",
    re.IGNORECASE,
)

_DYN_FRIDA_NEGATION_RE = re.compile(
    r"\bno\b.{0,80}\bfrida\b.{0,100}\b(?:trace|session|instrumentation|"
    r"runtime events?)\b.{0,55}\b(?:present|performed|invoked|run|executed|"
    r"recorded|captured)\b"
    r"|\bfrida\b.{0,55}\b(?:trace|session|instrumentation|runtime events?)\b"
    r".{0,45}\b(?:was|were|is|are)\s+not\s+"
    r"(?:present|performed|invoked|run|executed|recorded|captured|"
    r"observed|available)\b"
    r"|\bneither\b.{0,70}\bfrida\b.{0,55}\b(?:was|were|is|are)\s+"
    r"(?:not\s+)?(?:performed|invoked|run|executed|recorded|captured)\b"
    r"|\b(?:frida|both tools?)\b.{0,45}\b(?:recorded|captured|observed|"
    r"produced|returned|generated|yielded|had)\s+(?:zero|0|no)\s+"
    r"(?:runtime\s+)?events?\b"
    r"|\bfrida\s*[:\-]\s*(?:zero|0|no)\s+(?:runtime\s+)?events?\b",
    re.IGNORECASE,
)

_DYN_WINRE_NEGATION_RE = re.compile(
    # Bind the negation to the WinRE execution noun. A sentence may begin
    # "No dynamic behaviour has been asserted beyond what the WinRE
    # detonation ... recorded"; a broad `no ... winre ... recorded` pattern
    # mistakes that scope limitation for a denial that detonation occurred.
    r"\bno\s+(?:(?:the\s+)?winre(?:'s)?\s+)?(?:sample\s+)?"
    r"(?:detonation|sample execution|runtime execution|runtime run)\b"
    r".{0,80}\b(?:performed|conducted|run|invoked|executed|occurred|"
    r"completed|present|captured|recorded)\b"
    r"|\bwinre\b.{0,55}\b(?:detonation|sample execution|runtime execution|"
    r"runtime run)\b.{0,45}\b(?:(?:was|were|is|are)\s+not\s+"
    r"(?:performed|conducted|run|invoked|executed|occurred|completed|"
    r"captured|recorded)|did\s+not\s+(?:run|occur|happen|complete))\b",
    re.IGNORECASE,
)

_DYN_PCAP_NEGATION_RE = re.compile(
    r"\bno\s+(?:network traffic capture(?:\s*\(pcap\))?|packet capture|"
    r"pcap(?:ng)?(?:\s+file)?)\b.{0,55}\b"
    r"(?:present|collected|captured|recorded|exists)\b"
    r"|\b(?:pcap|packet capture|network traffic capture)\b.{0,45}\b"
    r"(?:(?:was|were|is|are)\s+not\s+"
    r"(?:present|collected|captured|recorded)|does\s+not\s+exist)\b",
    re.IGNORECASE,
)

_DYN_EXECUTED_RE = re.compile(
    r"(?:the dynamic (?:runs?|analysis) (?:executed|completed|ran|was performed))"
    r"|(?:dynamic analysis (?:was|were) (?:performed|conducted|run))"
    r"|(?:sandbox (?:execution|run|runs?) .{0,30}(?:executed|ran|invoked|completed))"
    r"|(?:frida .{0,40}(?:instrumentation|trace|hook) .{0,30}"
    r"(?:was|were|invoked|ran|executed|recorded))"
    r"|(?:emulation (?:oracle )?(?:completed|succeeded|executed|ran|produced a trace))"
    r"|(?:(?:winre|flare[- ]?vm)[^\n.]{0,50}(?:detonation ran|sample launch confirmed|"
    r"confirmed sample launch|sample launched|launch confirmed))"
    r"|(?:sample (?:was )?launched[^\n.]{0,35}(?:winre|flare[- ]?vm))"
    r"|(?:both invoked during)",
    re.IGNORECASE,
)

#: RC-05: claims that attribute EXECUTION or OBSERVED BEHAVIOUR to the SAMPLE.
#: These are fabrications whenever `any_dynamic_performed` is false, whatever
#: the component statuses say -- the engine may have been invoked, but that
#: never makes the sample executed. Kept to prose shapes (articles, subjects,
#: counts) so honest table cells like "| Sample executed | no |" do not match;
#: the after-match negation window also tolerates a leading table pipe now.
_DYN_SAMPLE_EXECUTED_RE = re.compile(
    r"(?:\bthe\s+(?:sample|specimen|binary|executable|malware)\s+"
    r"(?:was\s+|is\s+)?(?:executed|run|ran|launched|detonated))"
    r"|(?:\b(?:we|this\s+analysis|the\s+pipeline|the\s+orchestrator)\s+"
    r"(?:executed|ran|launched|detonated)\s+the\s+(?:sample|specimen|binary))"
    r"|(?:\bsample\s+launch\s+(?:was\s+)?confirmed)"
    r"|(?:\b(?:runtime|dynamic|behavioral|behavioural)\s+"
    r"(?:behaviou?r|events?|activity|traces?)\s+(?:was|were)\s+"
    r"(?:observed|recorded|captured|collected))"
    r"|(?:\bdetonation\s+(?:of\s+the\s+)?(?:sample|specimen)\s+"
    r"(?:ran|completed|succeeded|produced))"
    r"|(?:\bthe\s+(?:sample|specimen)\s+produced\s+\d+\s+"
    r"(?:api\s+)?(?:calls?|events?))",
    re.IGNORECASE,
)

#: A component can be truthfully described as having been INVOKED while it
#: produced nothing. That is a status description, not a claim that the sample
#: executed, and the sentence has to say so about the SAME component: "the
#: Speakeasy emulation ran and recorded zero API calls" is honest; "the WinRE
#: detonation ran and no packet capture was produced" claims the detonation
#: while only a DIFFERENT component is absent, so it is still a run claim.
_DYN_COMPONENT_ABSENCE_MARKERS = (
    "zero api", "zero call", "zero event", "zero key event", "no oracle result",
    "produced no oracle", "produced no result", "produced no api",
    "produced no key", "recorded no api", "recorded no call",
    # Reports write the same fact with digits ("recorded 0 API calls and 0 key
    # events"), which the word-only list missed on 2026-10-24 and failed a
    # truthful sentence a second time.
    " 0 api", " 0 call", " 0 event", " 0 key event", "recorded 0",
    "no api call", "no key event",
)

#: Only an EMULATOR can be invoked and produce nothing: Speakeasy starts, runs
#: the sample under emulation, and may reach no oracle result. A detonation,
#: sandbox run or packet capture either happened or did not, so "the detonation
#: ran and recorded 0 events" is still a claim that the sample executed and is
#: deliberately NOT covered by the allowance above.
_DYN_EMULATION_SUBJECT_RE = re.compile(
    r"emulat|speakeasy|oracle", re.IGNORECASE)


def _sentence_window_after(md: str, end: int, limit: int = 200) -> str:
    """The rest of the current sentence after `end`, lowercased and bounded."""
    tail = md[end:end + limit]
    for i, char in enumerate(tail):
        if char in ".!?\n":
            return tail[:i].lower()
    return tail.lower()


def _emulation_null_result_nearby(md: str, start: int, end: int,
                                  window: int = 2) -> bool:
    """A null result for the EMULATION component within ±`window` sentences.

    RC-05: the null result may live in the sentence AFTER the engine claim
    ("Speakeasy emulation ran successfully (speakeasy_ok=true) against the
    sample. The emulation stage recorded zero API calls."), which the
    same-sentence-only rule flagged on run 65be0144. A neighbouring sentence
    counts only when it names the emulation subject too, so a DIFFERENT
    component's null result cannot excuse the engine sentence; the same
    sentence needs no subject check because the match itself names it.
    """
    bounds: list[tuple[int, int]] = []
    sentence_start = 0
    for i, ch in enumerate(md):
        if ch in ".!?\n":
            bounds.append((sentence_start, i + 1))
            sentence_start = i + 1
    if sentence_start < len(md):
        bounds.append((sentence_start, len(md)))
    index = None
    for i, (s, e) in enumerate(bounds):
        if s <= start < e:
            index = i
            break
    if index is None:
        return False
    for j in range(max(0, index - window),
                   min(len(bounds), index + window + 1)):
        text = md[bounds[j][0]:bounds[j][1]].lower()
        if not any(marker in text for marker in _DYN_COMPONENT_ABSENCE_MARKERS):
            continue
        if j == index or _DYN_EMULATION_SUBJECT_RE.search(text):
            return True
    return False


#: The verdict panel has two shapes: the legacy bold `**Final**` cell, and the
#: claim-level schema's plain `| Verdict | malicious | ... |` table row (the
#: renderer emits the table, so the cell is not bold). The second shape is
#: what the schema-authored master report carries, and reading it is what
#: stopped a report whose prose said "a benign reading cannot stand" from
#: being read as a 'benign' report (2026-10-21: a false
#: `master_tech_verdict_mismatch`).
#: The verdict panel has two shapes: the legacy bold `**Final**` cell, and the
#: claim-level schema's plain `| Verdict | malicious | ... |` table row (the
#: renderer emits the table, so the cell is not bold). The second shape is
#: what the schema-authored master report carries, and reading it is what
#: stopped a report whose prose said "a benign reading cannot stand" from
#: being read as a 'benign' report (2026-10-21: a false
#: `master_tech_verdict_mismatch`).
_VERDICT_PANEL_RE = re.compile(
    r"\|\s*\*\*Final\*\*\s*\|\s*\*+([^*|]+?)\*+\s*\|"
    r"|\|\s*\**Verdict\**\s*\|\s*\**([^*|]+?)\**\s*\|",
    re.IGNORECASE,
)

_ENTROPY_MENTION_RE = re.compile(
    r"(?<![A-Za-z])entropy\b([^0-9\n]{0,40})(?<![A-Za-z0-9])(\d{1,2}(?:\.\d+)?)",
    re.IGNORECASE,
)

_COMPARATIVE_ENTROPY_RE = re.compile(
    r"(?i)(above|over|exceed|greater than|more than|below|between|under|>|at least)",
)

_ENTROPY_SECTION_SCOPE_RE = re.compile(
    r"\.(?:text|data|rdata|rsrc|reloc|idata|edata|pdata|tls)\b"
    r"|\bsection\b|\boverlay\b|\bsegment\b|\bupx\d\b",
    re.IGNORECASE,
)


def _file_shannon_entropy(path: Path | None) -> float | None:
    """Whole-file Shannon entropy (bits/byte), stdlib-only. None if unreadable."""
    if not path or not path.is_file():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    e = -sum((c / n) * math.log2(c / n) for c in freq if c)
    return e if e else 0.0


def _sample_path_for(root: Path, sha: str) -> Path | None:
    """Resolve the sample file from the session record (best-effort).

    `root` = /opt/samples/logs/<sha>; sessions live at /opt/samples/sessions.
    """
    sp = root.parent.parent / "sessions" / f"{sha}.json"
    if not sp.is_file():
        return None
    try:
        d = json.loads(sp.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    p = d.get("sample_path")
    return Path(p) if p else None


_APPENDIX_MARKERS = (
    "## Appendix",
    "# Appendix",
    "## Structured Evidence",
    "# Structured Evidence",
    "Evidence Pack",
)


def _narrative_portion(md: str) -> str:
    """Cut a report at the first appendix/evidence marker.

    Style checks run on narrative prose only. Appendix content may be selected
    or summarized evidence; this boundary does not imply completeness or verbatim
    preservation of source artifacts.
    """
    text = md or ""
    cut = len(text)
    low = text.lower()
    for marker in _APPENDIX_MARKERS:
        i = low.find(marker.lower())
        if i != -1:
            cut = min(cut, i)
    return text[:cut]


def _entropy_claim_violations(md: str, file_entropy: float) -> list[str]:
    """Flag entropy citations that contradict the file's measured entropy.

    Ground truth = whole-file Shannon entropy computed from the sample bytes
    (malcat's `entropy` field is not whole-file entropy — verified 2026-08-12:
    getdown 5.54 bits/byte vs malcat 104). Section-scoped citations (.text,
    overlay, ...) and anomaly-table category cells are skipped.
    """
    out: list[str] = []
    seen: set[str] = set()
    narrative = _narrative_portion(md)
    for m in _ENTROPY_MENTION_RE.finditer(narrative):
        line_start = narrative.rfind("\n", 0, m.start()) + 1
        pipes_before = narrative[line_start:m.start()].count("|")
        if pipes_before >= 2:
            continue
        ctx = narrative[max(0, m.start() - 120):m.end() + 120]
        if _ENTROPY_SECTION_SCOPE_RE.search(ctx):
            continue
        try:
            quoted = float(m.group(2))
        except ValueError:
            continue
        # Comparative-threshold guard (koti.xlsm false positive, 2026-08-13):
        # "flag files with entropy above 7.0", "entropy > 200", "exceeds",
        # "between 7.0 and" — inequality statements about thresholds or other
        # regions, not equality-style metric citations of the file.
        if _COMPARATIVE_ENTROPY_RE.search(m.group(1)):
            continue
        # Unit-suffix guard (drtg false positive, 2026-08-13): anomaly
        # descriptions like "medium-to-high-entropy 10KB+ buffer" put a SIZE
        # after "entropy" — "10KB+" is a byte count, not an entropy metric.
        if re.search(r"(?i)^\s*(kb|mb|gb|bytes?|%)\b", narrative[m.end():m.end() + 8]):
            continue
        # Theoretical-maximum guard (raas false positive, 2026-08-13):
        # "approaches the maximum entropy of 8.0" states a theory fact
        # (max bits/byte = 8.0), not the file's measured entropy. The window
        # spans past the match so "maximum entropy" adjacency resolves.
        if re.search(
            r"(?i)(maximum entropy|max entropy|theoretical max|upper bound)",
            narrative[max(0, m.start() - 60):m.end()],
        ):
            continue
        if 8.0 < quoted <= 800.0:
            quoted = quoted / 100.0
        elif quoted > 8.0:
            continue
        key = f"{quoted:.2f}"
        if key in seen:
            continue
        seen.add(key)
        if abs(quoted - file_entropy) > 0.5:
            out.append(
                f"entropy_quoted_vs_file_mismatch(quoted={quoted}, file={file_entropy:.2f})"
            )
        low = ctx.lower()
        if any(w in low for w in ("normal", "typical", "expected")) and not (
            3.5 <= file_entropy <= 8.0
        ):
            out.append(
                f"entropy_normal_claim_contradicts_file(quoted={quoted}, file={file_entropy:.2f})"
            )
    return out


def _panel_final_verdict(md: str) -> str:
    m = _VERDICT_PANEL_RE.search(md or "")
    if not m:
        return ""
    value = m.group(1) if m.group(1) is not None else m.group(2)
    return (value or "").strip().strip("*").strip().lower()


# Words that make a dynamic-execution phrase a NEGATION rather than a claim.
# Without this, "No dynamic/Speakeasy/Frida trace was captured for this sample"
# matches the affirmative pattern and the gate reports a fabrication that does
# not exist -- the same over-matching the _signal_hits negation guard fixed
# for behavioral signals (2026-09-21).
_DYN_NEGATION_MARKERS = (
    "no ", "not ", "zero ", "without", "none", "never", "nor ",
    "did not", "didn't", "was not", "were not", "not been", "not any",
    "absent", "no dynamic", "no runtime",
)

# A negation can also sit AFTER the matched verb phrase: "Frida
# instrumentation was not performed" matches _DYN_EXECUTED_RE (frida ...
# instrumentation ... was) and negates only in what FOLLOWS. The pre-2026-10-13
# version looked exclusively backwards, so the truthful sentence this whole
# fix exists to produce was flagged as a fabrication -- a correct report went
# red and the orchestrator burned a retry cycle re-publishing it (msil
# agentic, 2026-10-13). The negation must arrive before the next verb word:
# "in fact, not performed" is negated; "performed without errors" is an
# affirmative claim whose "without" describes the claim, not negates it.
_DYN_NEGATED_AFTER_RE = re.compile(
    r"^(?:[a-z,]+\s+){0,3}?(?:not|no|never|n't|nor)\s", re.IGNORECASE)


def _negation_window_before(md: str, start: int) -> str:
    """The current sentence's text before `start`, lowercased.

    The negation context must stop at the SENTENCE boundary: a blind
    character window leaks a negation from the previous sentence ("...no
    runtime API hooking occurred.") into the next one and suppresses a real
    claim there. A negation in the same sentence negates; a negation in the
    sentence before does not.
    """
    lb = max(md.rfind(c, 0, start) for c in (".", "!", "?", "\n"))
    return md[lb + 1:start].lower()


def _affirmative_dynamic_claim(md: str, dyn_status: dict | None = None) -> str | None:
    """The first dynamic-execution claim in `md` that is NOT negated.

    Returns the matched phrase, or None. A claim whose context negates it
    ("no Frida trace was captured", "Frida instrumentation was not
    performed") is honest and must not be flagged. The negation is checked
    on BOTH sides of the match: the current sentence before it, and a
    negation arriving before the next verb word after it. Checking only
    backwards flagged the exact sentence this fix is meant to produce --
    measured on msil_crypt_dotnet agentic 2026-10-13, where a report that
    correctly said "Frida instrumentation was not performed" was failed as
    a fabrication.

    RC-05 redesign (status-driven, replacing the marker-list ladder):
      * a claim that attributes execution or observed behaviour to the SAMPLE
        is a fabrication whenever no dynamic analysis ran -- no component
        status can make it true;
      * an ENGINE-invocation sentence about the emulation component is judged
        by the status contract: when the tool recorded `engine_ran=True`
        (speakeasy_ok) the sentence is true about the TOOL and stands only if
        the null result is stated in the same or a neighbouring (±2) sentence;
        when `engine_ran=False` the sentence is a fabrication; unknown keeps
        the honest-null allowance;
      * every other mechanism claim (detonation, sandbox, Frida trace) either
        happened or did not, so with `any_dynamic_performed=false` it stays
        flagged.
    """
    if not md:
        return None
    emulation = ((dyn_status or {}).get("emulation") or {})
    engine_ran = emulation.get("engine_ran")
    for regex in (_DYN_SAMPLE_EXECUTED_RE, _DYN_EXECUTED_RE):
        for m in regex.finditer(md):
            window = _negation_window_before(md, m.start())
            after = md[m.end():m.end() + 45].lstrip(" \t|*_")
            if any(neg in window for neg in _DYN_NEGATION_MARKERS):
                continue
            if _DYN_NEGATED_AFTER_RE.match(after):
                continue
            # A CONDITIONAL clause is a hypothesis about the code, not a claim
            # that this run executed the sample: "if the binary is executed,
            # the lack of ASLR weakens the host's posture" (2026-10-26, run
            # d9836cde). Skip when the sentence introduces the match with
            # if/unless/whether.
            if re.search(r"\b(?:if|unless|whether)\b", window):
                continue
            if _DYN_EMULATION_SUBJECT_RE.search(m.group(0)) \
                    and regex is _DYN_EXECUTED_RE:
                # The emulation allowance: a status description of the TOOL,
                # never of the sample. See the docstring for the status rule.
                if engine_ran is False:
                    return m.group(0).strip()
                if _emulation_null_result_nearby(md, m.start(), m.end()):
                    continue
                return m.group(0).strip()
            return m.group(0).strip()
    return None


def _dynamic_absence_claim(md: str, dyn_status: dict) -> str | None:
    """Find an execution-absence statement contradicted by run artifacts.

    Check the sentence containing each claim. A caveat elsewhere in a long
    report must not cancel a contradiction. A clearly scoped statement that
    only the absent Speakeasy engine did not run, or that the RevAI Frida probe
    was static-only, remains valid when WinRE separately detonated the sample.
    """
    emulation_ran = bool((dyn_status.get("emulation") or {}).get("ok"))
    winre_ran = (dyn_status.get("winre") or {}).get("detonation_ran") is True
    frida = dyn_status.get("frida_runtime") or {}
    frida_ran = bool(frida.get("observed_runtime_events")
                     or frida.get("trace_artifact_present"))
    capture = dyn_status.get("packet_capture") or {}
    pcap_present = bool(capture.get("present"))

    sentences: list[tuple[str, str]] = []
    for line in (md or "").splitlines():
        table_line = line.lstrip()
        while table_line.startswith(">"):
            table_line = table_line[1:].lstrip()
        if table_line.startswith("|"):
            # A Markdown row is a set of independent cells. Joining its prose
            # lets a true "no execution" in one component cell combine with
            # "dynamic-analysis status" / "re-run" in later cells and create
            # a false blanket-denial match. Check each cell on its own; escaped
            # pipes remain part of their cell.
            fragments = re.split(r"(?<!\\)\|", table_line)
        else:
            fragments = [line]
        for fragment in fragments:
            parts = re.split(r"(?<=[.!?])\s+|\n+", fragment)
            sentences.extend(
                (part, parts[index - 1] if index else "")
                for index, part in enumerate(parts)
            )

    for sentence, previous_sentence in sentences:
        lower = sentence.lower()
        previous_lower = previous_sentence.lower()
        # A missing runtime stream attributed only to the RevAI static-only
        # probe is true even when WinRE separately generated runtime events.
        # Exempt that component-level Frida statement only; the broader dynamic,
        # WinRE, and packet-capture checks below still run on this sentence.
        static_probe_scoped_frida_absence = (
            "frida" in lower
            and "probe" in lower
            and (
                re.search(r"\bstatic[- ]only\b", lower) is not None
                or (
                    "frida" in previous_lower
                    and "probe" in previous_lower
                    and re.search(r"\bstatic[- ]only\b", previous_lower) is not None
                )
            )
            and re.search(
                r"\b(?:by|from|through)\s+(?:this|that)\s+"
                r"(?:frida\s+)?(?:static[- ]only\s+)?(?:probe|component|path)\b"
                r"|\bfor\s+(?:this|that)\s+(?:frida\s+)?"
                r"(?:static[- ]only\s+)?(?:probe|component|path)\b",
                lower,
            ) is not None
        )
        # A statement limited to the absent RevAI emulator is compatible with
        # a separate WinRE detonation. Broad statements that mention multiple
        # engines or a sandbox do not qualify for this exception.
        speakeasy_only = (
            not emulation_ran
            and re.search(r"\bno\s+(?:revai(?:'s)?\s+)?speakeasy\b", lower)
            and not re.search(r"\b(frida|winre|sandbox|dynamic execution)\b", lower)
        )
        if speakeasy_only:
            continue
        # RC-20 (run 2168d92e, 2026-10-25): a sentence that denies a NAMED
        # ENUMERATION of dynamic paths — "because no dynamic execution path
        # (WinRE detonation, Frida runtime trace, or packet capture) was
        # performed" — is truthful when every named path's status is absent,
        # even while a DIFFERENT path (the emulation oracle, ok=true) ran.
        # The enumeration scopes the denial; a broad denial of dynamic
        # analysis with no such scope still fails below.
        enum_scope = re.search(
            r"\(([^)]*(?:detonation|winre|frida|packet capture|pcap|emulation|"
            r"sandbox)[^)]*)\)", lower)
        if enum_scope and re.search(r"\bno\b", lower):
            scope_ok = True
            for item in re.split(r",|\bor\b", enum_scope.group(1)):
                item = item.strip().lower()
                if not item:
                    continue
                if "winre" in item or "detonation" in item:
                    scope_ok = scope_ok and not winre_ran
                elif "frida" in item:
                    scope_ok = scope_ok and not frida_ran
                elif "packet capture" in item or "pcap" in item:
                    scope_ok = scope_ok and not pcap_present
                elif "emulation" in item or "speakeasy" in item \
                        or "oracle" in item:
                    scope_ok = scope_ok and not emulation_ran
            if scope_ok:
                continue
        # Reports can state a component-level gap (RevAI's static-only Frida
        # probe) or an unexecuted nested payload (the embedded PE) while the
        # outer sample was run through WinRE. Remove only those scoped clauses;
        # a separate blanket denial in the same sentence must still fail.
        # Evidence locator values can contain words such as "dynamic analysis"
        # and "captured". They are not report prose and must not participate in
        # the semantic execution check (e.g. "cannot assert ... no runtime
        # behaviour (source: dynamic-analysis-status, ... runtime events
        # captured)").
        prose_sentence = strip_citation_annotations(sentence)
        # A denial scoped to NAMED components is truthful when every component
        # it names is absent, even if a DIFFERENT component ran. Measured
        # 2026-10-26 (RC-20b): "No packet-capture artifact was produced for
        # this run; ... records 'no packet capture artifact present'" was
        # failed while the emulation oracle ran, because the previous rule only
        # recognised a PARENTHESISED enumeration. A broad denial that names no
        # component ("no dynamic analysis was performed") still falls through
        # and fails, which is correct when something did run.
        named_status: list[bool | None] = []
        for _label, _ran, _pattern in (
                ("winre", winre_ran, r"\b(?:winre|detonation)\b"),
                ("frida", frida_ran, r"\bfrida\b"),
                ("pcap", pcap_present, r"\b(?:packet[- ]capture|pcap)\b"),
                ("emulation", emulation_ran,
                 r"\b(?:speakeasy|emulation|oracle)\b"),
        ):
            if re.search(_pattern, prose_sentence, re.IGNORECASE):
                named_status.append(_ran)
        if re.search(r"\bsandbox\b", prose_sentence, re.IGNORECASE):
            # No status is recorded for a sandbox; never grant the exemption.
            named_status.append(None)
        _broad_denial = re.search(
            r"\bno\s+(?:dynamic|runtime)\s+(?:analysis|activity|run)\b"
            r"|\bno\s+(?:dynamic|runtime)\s+execution(?!\s+paths?\b)",
            prose_sentence, re.IGNORECASE)
        if (named_status and not _broad_denial
                and all(_ran is False for _ran in named_status)):
            continue
        dynamic_claim_text = _DYN_META_NEGATION_RE.sub("", prose_sentence)
        dynamic_claim_text = _DYN_META_AFFIRMATION_RE.sub("", dynamic_claim_text)
        dynamic_claim_text = _DYN_INNER_PAYLOAD_GAP_RE.sub("", dynamic_claim_text)
        dynamic_claim_text = _DYN_NEGATED_NEGATION_RE.sub("", dynamic_claim_text)
        if _DYN_NEGATION_RE.search(dynamic_claim_text):
            return sentence.strip()[:180]
        if (frida_ran and not static_probe_scoped_frida_absence
                and _DYN_FRIDA_NEGATION_RE.search(prose_sentence)):
            return sentence.strip()[:180]
        if winre_ran and _DYN_WINRE_NEGATION_RE.search(prose_sentence):
            return sentence.strip()[:180]
        if pcap_present and _DYN_PCAP_NEGATION_RE.search(prose_sentence):
            return sentence.strip()[:180]
    return None


def evaluate_capability_disclosure(root: Path, sha: str,
                                   reports: list[str]) -> dict[str, Any]:
    """#56 (c): the report must disclose the capabilities it could not examine.

    This is the gate the whole capability-coverage ledger exists to feed. The
    ledger records which capability domains were examined to a determination and
    which were not. A domain that was never examined is a gap in the ANALYSIS --
    it must never be read as a finding about the sample, and it must never be
    silently absent from the report.

    The check is therefore graduated rather than absolute:

      * no domain-graph run (flat engine) -> not applicable, no violation;
      * unknown domains exist AND the report names them -> pass;
      * unknown domains exist AND the report is silent -> FAIL.

    It deliberately does not require zero unknowns: some domains genuinely
    cannot be determined for some samples. What it requires is that the analyst
    can see which ones.
    """
    from v2_lib import build_capability_coverage, format_capability_coverage
    try:
        cov = build_capability_coverage(sha, logs_dir=root.parent)
    except Exception:
        return {"ok": True, "applicable": False,
                "reason": "capability ledger unreadable"}
    if not cov or not cov.get("domains"):
        return {"ok": True, "applicable": False,
                "reason": "no domain-graph run (flat engine)"}

    unknown = list((cov.get("provenance") or {}).get("unknown") or [])
    if not unknown:
        return {"ok": True, "applicable": True, "unknown": [],
                "provenance_counts": cov.get("provenance_counts")}

    blob = "\n".join(r or "" for r in reports).lower()
    missing = [k for k in unknown if k not in blob]
    if missing:
        return {
            "ok": False, "applicable": True, "unknown": unknown,
            "undisclosed": missing,
            "violation": (
                "capability_disclosure_missing: the run could not examine "
                f"{len(unknown)} capability domain(s) ({', '.join(unknown)}) and "
                f"the report does not name {', '.join(missing)}. An unexamined "
                "capability is a gap in the analysis, not a finding about the "
                "sample, and a silent gap is worse than a stated one."),
        }
    return {"ok": True, "applicable": True, "unknown": unknown,
            "provenance_counts": cov.get("provenance_counts")}


def _cross_report_consistency(
    master_md: str,
    tech2_md: str,
    tech3_md: str,
    file_entropy: float | None,
    dyn_status: dict | None = None,
    *,
    master_v3_md: str = "",
) -> dict[str, Any]:
    """Deterministic cross-report + fact-vs-file consistency checks.

    Gate-failing violations:
    - a report claims dynamic analysis EXECUTED when the run performed none,
      or the reverse;
    - published reports state different verdicts, including when no system
      verdict panel is present;
    - entropy citations contradict the file's measured whole-file entropy.

    The earlier version flagged this by word-matching a negation in one report
    against "hook candidate identified" (a STATIC probe on a FAILED oracle) in
    the other -- which misdiagnosed the actual defect: a report claiming a
    dynamic run that did not happen. Both directions are now grounded on the
    run's deterministic dynamic status.
    """
    violations: list[str] = []
    checks: dict[str, Any] = {"file_entropy": file_entropy}

    all_md = "\n".join([
        master_md or "", master_v3_md or "", tech2_md or "", tech3_md or "",
    ])
    raw_any_dyn = (None if dyn_status is None
                   else dyn_status.get("any_dynamic_performed"))
    any_dyn = None if raw_any_dyn is None else bool(raw_any_dyn)
    checks["dynamic_performed"] = any_dyn

    if any_dyn is False:
        # No dynamic analysis ran. An affirmative execution claim anywhere is a
        # fabrication; name the phrase and the ground truth. The claim must be
        # AFFIRMATIVE -- a negation ("no Frida trace was captured") is the
        # honest statement this fix is meant to produce. The claim is judged
        # against the component status (RC-05): engine-invocation sentences are
        # evaluated against `engine_ran`, sample-attribution claims never pass.
        claim = _affirmative_dynamic_claim(all_md, dyn_status or {})
        checks["dyn_executed_claim"] = bool(claim)
        if claim:
            gt = (f" (ground truth: {dyn_status.get('sentence')})"
                  if dyn_status and dyn_status.get("sentence") else "")
            violations.append(
                "cross_report:dynamic_execution_claimed_but_none_performed"
                f"('{claim[:90]}'){gt}")
    elif any_dyn is True:
        # A mechanism DID run. Check execution-absence statements per sentence
        # and against component status; report-wide caveats cannot mask them.
        claim = _dynamic_absence_claim(all_md, dyn_status or {})
        checks["dyn_absence_claim"] = claim
        if claim:
            violations.append(
                "cross_report:dynamic_performed_but_report_says_none"
                f"('{claim[:120]}')")
    elif any_dyn is None and dyn_status is not None:
        checks["dynamic_status_unverified"] = True
        if (dyn_status.get("winre") or {}).get("pack_present"):
            violations.append("cross_report:dynamic_execution_status_unverified")

    from v2_lib import infer_publish_verdict_from_markdown

    def _report_verdict(markdown: str) -> str:
        return (infer_publish_verdict_from_markdown(markdown)
                or _panel_final_verdict(markdown))

    mv = _report_verdict(master_md)
    mv3 = _report_verdict(master_v3_md)
    tv2 = _report_verdict(tech2_md)
    tv3 = _report_verdict(tech3_md)
    checks["master_verdict"] = mv
    checks["master_v3_verdict"] = mv3
    checks["technical_v2_verdict"] = tv2
    checks["technical_v3_verdict"] = tv3
    for master_label, master_verdict, tech_label, tech_verdict in (
        ("master_v2", mv, "technical_v2", tv2),
        ("master_v2", mv, "technical_v3", tv3),
        ("master_v3", mv3, "technical_v2", tv2),
        ("master_v3", mv3, "technical_v3", tv3),
    ):
        if master_verdict and tech_verdict and master_verdict != tech_verdict:
            if master_label == "master_v2" and tech_label == "technical_v2":
                issue_name = "master_tech_verdict_mismatch"
            elif master_label == "master_v3" and tech_label == "technical_v3":
                issue_name = "master_v3_tech_verdict_mismatch"
            else:
                issue_name = f"{master_label}_{tech_label}_verdict_mismatch"
            violations.append(
                f"cross_report:{issue_name}("
                f"master={master_verdict}, technical={tech_verdict})")
    if file_entropy is not None:
        for md, label in (
            (master_md, "master"),
            (master_v3_md, "master_v3"),
            (tech2_md, "technical_v2"),
            (tech3_md, "technical_v3"),
        ):
            for v in _entropy_claim_violations(md, file_entropy):
                violations.append(f"cross_report:{label}:{v}")
    return {"ok": not violations, "violations": violations, "checks": checks}


def evaluate_sha_publish_quality(logs_dir: Path, sha: str, *,
                                 case_root: Path | None = None) -> dict[str, Any]:
    """Disk-level quality gate used by audit + orchestrator.

    ``case_root`` pins the exact directory to evaluate (the audit already knows
    it: logs/<sha> or logs/<sha>/<mode>) and keeps the reported sha correct.
    Without it, the mode-keyed dir is preferred when it carries publish
    artifacts.
    """
    root = Path(case_root) if case_root else Path(logs_dir) / sha
    if case_root is None:
        # Mode-keyed runs write their artifacts under logs/<sha>/<mode>/ — prefer
        # that dir when it carries publish artifacts so the orchestrator's quality
        # gate evaluates the run it just made (rehearsal 2026-09-22: an agentic run
        # reported 0-length/missing reports while its mode dir held complete ones).
        try:
            from v2_lib import case_dir

            mode_root = case_dir(sha)
            if mode_root != root and any(
                (mode_root / n).exists()
                for n in ("REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md", "report-v2.json")
            ):
                root = mode_root
        except Exception:
            pass
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
    master_v3_j = _load(root / "section-results-v3.json")
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
        evidence_root=root,
        verdict_lock=master_j.get("verdict_lock"),
    )
    r_master_v3 = evaluate_report_markdown(
        master_v3,
        required_sections=REPORT_MASTER_SECTIONS or [],
        source="llm_judge" if master_v3 else None,
        min_total_chars=1500,
        label="master_v3",
        evidence_root=root,
        verdict_lock=master_v3_j.get("master_v3_verdict_lock"),
    )
    r_tech2 = evaluate_report_markdown(
        tech2_md,
        required_sections=TECHNICAL_REPORT_SECTIONS,
        source=tech2_j.get("source"),
        min_total_chars=8000,
        label="technical_v2",
        evidence_root=root,
        verdict_lock=tech2_j.get("verdict_lock"),
    )
    r_tech3 = evaluate_report_markdown(
        tech3_md,
        required_sections=TECHNICAL_REPORT_SECTIONS,
        source=tech3_j.get("source") or ("llm_judge" if tech3_md and not source_is_fallback(tech3_j.get("source")) else tech3_j.get("source")),
        min_total_chars=8000,
        label="technical_v3",
        evidence_root=root,
        verdict_lock=tech3_j.get("verdict_lock"),
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
    checks["master_v3"] = r_master_v3
    checks["technical_v2"] = r_tech2
    checks["technical_v3"] = r_tech3
    checks["master_v3_present"] = len(master_v3) >= 1500
    checks["tech3_file_present"] = bool(tech3_md)

    # Cross-report consistency + factual-number sanity (2026-08-12, #2 night-run
    # publication gate): structural green is not enough — catch master-vs-tech
    # contradictions and claims that contradict the file's measured entropy.
    _entropy = _file_shannon_entropy(_sample_path_for(root, sha))
    from v2_lib import dynamic_analysis_status
    try:
        _dyn_status = dynamic_analysis_status(sha)
    except Exception:
        _dyn_status = None
    consistency = _cross_report_consistency(
        master_md, tech2_md, tech3_md, _entropy, _dyn_status,
        master_v3_md=master_v3)
    checks["cross_report_consistency"] = consistency
    for _viol in consistency.get("violations") or []:
        issues.append(_viol)

    # #6: trace each citation to its source-specific machine artifact and
    # review the full claim against the exact source row. Missing evidence or
    # reviewer failure is not a pass: a gate exception must never become green.
    try:
        from entailment import check_report_entailment
        _ent = check_report_entailment(sha, case_root=root)
    except Exception as _ent_exc:
        _ent = {"ok": False, "applicable": True, "status": "error",
                "reason": f"entailment check unavailable: {_ent_exc}"}
    checks["claim_entailment"] = _ent
    if not _ent.get("ok"):
        _ent_status = str(_ent.get("status") or "failed")
        # Name the actual cause in the ISSUE, not only inside the artifact: a
        # reviewer failure and a genuine claim failure are different problems,
        # and the audit summary is what an operator reads first (2026-10-24).
        _ent_reason = str(_ent.get("review_error") or _ent.get("reason") or "")[:200]
        issues.append(
            f"claim_entailment:{_ent_status}"
            + (f": {_ent_reason}" if _ent_reason else ""))
        for _v in (_ent.get("violations") or [])[:20]:
            issues.append(f"entailment:{_v.get('status')}:"
                          f"{str(_v.get('claim'))[:120]}")

    # #56 (c): the report must disclose the capabilities it could not examine.
    _capdisc = evaluate_capability_disclosure(
        root, sha, [master_md, master_v3, tech2_md, tech3_md])
    checks["capability_disclosure"] = _capdisc
    if not _capdisc.get("ok"):
        issues.append(_capdisc["violation"])

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

    for key in ("master_v2", "master_v3", "technical_v2", "technical_v3"):
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

    # Check every published draft independently. A clean technical report must
    # not mask unsupported claims in either master report or the other version.
    checks["claimed_ioc_verification"] = {
        name: check.get("claimed_ioc_verification") or {}
        for name, check in (
            ("master_v2", r_master),
            ("master_v3", r_master_v3),
            ("technical_v2", r_tech2),
            ("technical_v3", r_tech3),
        )
    }

    # Plan #14d, calibrated 2026-09-27 on the 56-case published corpus: behaviour
    # statements are cross-checked against the deterministic pe_imports high-signal
    # map, and the promotion to a blocking gate was REJECTED on the evidence
    # (54/54 flags were false positives; the 11-candidate contradiction form was
    # 11/11 specificity or dynamic-observation denials). Recorded, never gating.
    try:
        _surface, _surface_sources = collect_import_surface(root)
        _behavior = verify_behavior_prerequisites(
            tech3_md or tech2_md or master_md, _surface, packed=_is_packed(root))
        _behavior["import_surface_sources"] = _surface_sources
        _map_names, _map_used, _map_meta = _load_high_signal_map(root)
        _behavior["import_map"] = _map_meta
        _behavior["import_map_names"] = len(_map_names)
        checks["behavior_prerequisites"] = _behavior
    except Exception as exc:  # a check error must never break the gate
        checks["behavior_prerequisites"] = {"advisory": True, "error": str(exc)}

    ok = not issues
    return {
        "ok": ok,
        "quality_green": ok,
        "sha256": sha,
        "issues": issues,
        "checks": checks,
        "advisory": {
            "behavior_prerequisites": checks.get("behavior_prerequisites", {}),
        },
        "models": {
            "master": master_j.get("model"),
            "technical_v2": tech2_j.get("model"),
            "technical_v3": tech3_j.get("model"),
            "default_hint": os.environ.get("REVAI_LLM_MODEL", "configured via env"),
            "planner_hint": os.environ.get("REVAI_LLM_PLANNER_MODEL", "configured via env"),
            "judgment_hint": os.environ.get("REVAI_LLM_VERDICT_MODEL", "configured via env"),
        },
    }


# --- claimed-IOC fact verification (plan #10; enforced per report) ---

_CLAIM_URL_RE = re.compile(r"(?i)\b(?:hxxps?|https?|ftp)(?:\[:\]|:)?//[^\s\"'<>()\[\]{}\\]+")
# The trailing lookahead rejects a follow-on `.`/`[.]` + digit, so `1.2.3.4`
# inside `1.2.3.4.5` is not extracted as a four-octet claim -- the checker must
# not manufacture the partial value the scrubber would then mangle.
_CLAIM_IP_RE = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}(?!(?:\[\.\]|\.)\d)\b")
_CLAIM_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\.\]|\.))+[a-z]{2,}(?![\w.-])",
    re.IGNORECASE)
_CLAIM_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_CLAIM_REGKEY_RE = re.compile(
    r"(?i)\bHK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)\\(?:[^\s\"'<>|]+"
    r"(?: (?=[A-Za-z0-9._-]+\\)[^\s\"'<>|]*)?)*")
_CLAIM_EMAIL_RE = re.compile(r"\b[\w.+-]+(?:\[@\]|@)[\w-]+(?:(?:\[\.\]|\.)[\w-]+)+\b")

#: Provenance banner line: "> **RevAI provenance** — commit `<hash>` · engine ..."
#:
#: The optional `-<suffix>` matters: a deploy from a dirty tree writes
#: commit `<hash>-dirty`, and that is the normal state during development.
#: Requiring the closing backtick right after the hex run made this regex
#: miss every `-dirty` banner, which silently disabled the "a report cites
#: the commit of the deploy that generated it" exclusion -- after a redeploy
#: the stale cited commit was then reported as an unverified sha256
#: indicator, exactly the noise the exclusion exists to prevent. Found live
#: 2026-10-03 re-auditing winservices after repointing REVAI_COMMIT at the
#: pushed HEAD.
_PROVENANCE_BANNER_RE = re.compile(r"commit\s*`([0-9a-fA-F]{7,40})(?:-[a-z]+)?`")

#: Fenced code blocks. Illustrative snippets (and their placeholders) are not
#: indicator claims: a report that shows `pe.imphash() == "…"  // placeholder`
#: must not be audited as if it claimed a hash. Claims are collected from prose,
#: tables and list items only.
#:
#: The second alternative handles an UNTERMINATED fence: an odd number of ```
#: markers otherwise leaves everything after the last one classified as prose,
#: so indicators inside it were extracted as claims (and scrubbed) by one pass
#: while the fence-aware splitter kept them verbatim -- the two passes silently
#: disagreeing about what is code.
_FENCED_CODE_RE = re.compile(r"```.*?```|```.*\Z", re.DOTALL)
_REPORT_EXECUTION_COMMENT_RE = re.compile(
    r"<!--\s*execution:\s*sha256=[0-9a-f]{64};\s*"
    r"run_id=[0-9a-f]{32};\s*mode=[^;\r\n]+;\s*"
    r"evidence_manifest_sha256=[0-9a-f]{64}\s*-->",
    re.IGNORECASE,
)

#: Canonical persistence templates: cited as verification targets ("RegSetValue
#: under HKCU\...\Run (or equivalent) — not observed") far more often than as
#: observed artifacts. Both hive spellings are accepted -- `HKCU\...` and
#: `HKEY_CURRENT_USER\...` name the identical hive, and treating them
#: differently inside one report is incoherent (before 2026-10-03 the short
#: form was excluded as a template while the long form of the same fabrication
#: was flagged unverified).
#: Excluded ONLY when used as a verification target (see
#: _CANONICAL_TEMPLATE_TARGET_RE); if a tool did observe the key, the evidence
#: match verifies it normally; and a bare unobserved assertion ("persists via
#: HKCU\...\Run") is a claim like any other -- it goes to `unverified` and the
#: scrubber neutralises it.
_CANONICAL_REGISTRY_TEMPLATE_RE = re.compile(
    r"^(?:hk(?:cu|lm|cr)|hkey_current_user|hkey_local_machine|hkey_classes_root)"
    r"\\software\\microsoft\\windows\\currentversion\\"
    r"run(?:once|services)?$")

#: Phrases that mark a canonical template mention as a verification target
#: rather than an assertion about the sample. Matched against the same window
#: _is_guidance_reference uses (whole bullet, or sentence in prose), so a
#: mention in a sentence that ASSERTS the behavior ("persists via ...") never
#: qualifies.
_CANONICAL_TEMPLATE_TARGET_RE = re.compile(
    r"(?i)\b(?:not\s+observed|not\s+detected|no\s+evidence|no\s+specific|"
    r"absen(?:t|ce)|"
    r"did\s+not|or\s+equivalent|would\s+(?:indicate|suggest|be)|"
    r"appears\s+in\s+the\s+evidence|presence\s+of|if\s+present|"
    r"persistence\s+check|"
    r"monitor|watch|check|hunt|verify|look\s+for)\b")

#: An abbreviated registry path, e.g. `HKCU\...\Run` or
#: `HKEY_CURRENT_USER\...\Run`. This is ordinary analyst shorthand for a class
#: of locations: it names a mechanism, not a single path, so it can never match
#: the evidence verbatim. The canonical template above only ever matched the
#: fully written-out path, so every elided path fell through to the verbatim
#: comparison and was reported unverified -- which is how winservices and
#: win32k_dll each ended up with a red audit for the prose `HKCU\...\Run`.
_ELIDED_REGISTRY_RE = re.compile(
    r"^(?:hk(?:cu|lm|cr|u|cc)|hkey_[a-z_]+)"
    r"(?:\\(?:…|\.\.\.))"      # at least one elided segment
    r".*$",
    re.IGNORECASE)

#: Imperative defender guidance. A registry path named inside one of these is a
#: location the report tells the analyst to inspect, clean, or GO AND COLLECT
#: EVIDENCE ABOUT -- not an indicator the report claims the sample produced.
#: Both survivors on the real audits were exactly this:
#:
#:   winservices  "**Registry:** Monitor `RegSetValueExA` ... on
#:                 `HKLM\...\FirewallPolicy` and the `Run` key"
#:   win32k_dll   "2. Remove registry persistence entries:
#:                 - HKLM\Software\Microsoft\Windows NT\...\UserList"
#:   WannaCry     "Resolution: execute the sample in an isolated VM ... capture
#:                 the full process tree, registry writes under
#:                 HKLM\\SYSTEM\\CurrentControlSet\\Services\\*, and ..."
#:
#: The third is the same speech act as the first two and was the last one this
#: exemption missed: the verbs that name COLLECTING FUTURE EVIDENCE (capture,
#: collect, obtain, execute, re-run) were absent, so a path the report
#: recommended gathering data about was read as an assertion that the sample
#: wrote there. WannaCry's audit stayed red on
#: `report:unverified_iocs:1` with exactly that path, across two reports where
#: the SAME path was correctly excused in one and counted as a claim in the
#: other.
#:
#: Same speech act as the canonical persistence template already exempted above
#: ("a verification target, not an observed artifact"). Counted and reported
#: under `guidance_references`, never silently dropped.
_GUIDANCE_VERB_RE = re.compile(
    r"(?i)\b(?:monitor|watch|remove|delete|clean|purge|inspect|scan|check|"
    r"audit|remediate|remediation|verify|look\s+for|hunt|clear|close|"
    # evidence-collection guidance: what the analyst should go and capture
    r"capture|collect|obtain|execute|gather|re-?run|confirm|reproduce|"
    r"triage|investigate|analyse|analyze|review)\b")

#: A path named inside a question about future observation ("whether
#: RegDeleteKeyW targets keys outside ...") is a verification target, not an
#: assertion that the sample touched it. The 2026-10-20 technical report used
#: this construction for its dynamic-monitoring plan, and the literal hive paths
#: were counted as unverified sample indicators.
_VERIFICATION_TARGET_RE = re.compile(
    r"(?i)\bwhether\b[^.;\n]{0,120}\b(?:targets?|writes?|creates?|accesses?|"
    r"uses?|touches?|modifies?|deletes?|reads?|opens?)\b[^.;\n]{0,80}"
    r"\b(?:outside|beyond|unexpected|other|different)\b")

#: Conditional defender guidance ("If an environment monitors ...", "If a
#: dynamic detonation is performed, focus monitoring on ..."), which names a
#: location to watch rather than one the report attributes to the sample. Kept
#: narrower than a bare "if" so an observed conditional write is still judged
#: as a claim.
_CONDITIONAL_GUIDANCE_RE = re.compile(
    r"(?i)\bif\s+(?:an?\s+)?(?:environment|analyst|organisation|organization|"
    r"defender|edr|monitor(?:ing)?|dynamic\s+(?:detonation|analysis)|"
    r"detonation|re-?run|execution)\b")

#: A markdown/numbered list item, whose line is the unit of guidance.
_BULLET_RE = re.compile(r"(?:[-*+]\s+|\d+[.)]\s+)")

#: A concrete registry path as it appears in raw tool evidence.
#:
#: Segments may contain a space (`Windows NT`), but ONLY when the segment is
#: followed by another separator -- each continuation word after the space must
#: start uppercase AND be followed by `\`. The strictness is load-bearing in
#: both directions: without it the extractor stopped at the space and read
#: `...\Microsoft\Windows NT\CurrentVersion\Winlogon` as `...\Microsoft\Windows`,
#: so an elided claim of the real Winlogon path could never ground (2026-10-03);
#: with a looser space rule, prose after a path ("HKCU\Run and HKLM\RunOnce")
#: would be swallowed into one candidate whose tail then falsely grounds
#: claims the evidence does not support.
_EVIDENCE_REGKEY_RE = re.compile(
    r"(?i)\b(?:HK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)|HKEY_[A-Z_]+)"
    r"(?:\\[^\s\"'<>|)\n]{2,}(?:[ \t]+[A-Z][^\s\"'<>|)\n]*(?=\s*\\))*)+")

#: Hive aliases, so `HKCU\...\Run` and `HKEY_CURRENT_USER\...\Run` are
#: recognised as naming the same location. Keyed by the long form.
_REGISTRY_HIVE_ALIASES = {
    "hkey_current_user": "hkcu",
    "hkey_local_machine": "hklm",
    "hkey_classes_root": "hkcr",
    "hkey_users": "hku",
    "hkey_current_config": "hkcc",
}


def _regkey_parts(value: str) -> tuple[str, list[str]] | None:
    """Split a registry path into (canonical hive, subkeys). None if malformed."""
    raw = (value or "").strip().strip("\\").replace("/", "\\")
    if not raw or "\\" not in raw:
        return None
    head, _, rest = raw.partition("\\")
    hive = head.strip().lower()
    hive = _REGISTRY_HIVE_ALIASES.get(hive, hive)
    subkeys = [s.strip().lower() for s in rest.split("\\") if s.strip()]
    return (hive, subkeys) if subkeys else None


def _ground_elided_regkey(plain: str, evidence: str) -> str | None:
    r"""Resolve an abbreviated registry path to a concrete one in the evidence.

    ``HKCU\...\Run`` is not an indicator that can be matched verbatim, so the
    verifier has to decide whether it *corresponds* to observed evidence. It
    does when the evidence contains a concrete path under the same hive whose
    subkeys include the one the report named -- that is what makes it a
    legitimate reference to an observed Run-key write rather than a generic
    persistence claim.

    The named segment may appear anywhere in the candidate's path, not only as
    its final subkey: real evidence lines carry a value name after the key
    (``...\Winlogon\Shell = explorer.exe``), and requiring the claim's segment
    to be the LAST one would leave the very paths analysts abbreviate most
    ungrounded. Exact-tail matches still win over deeper ones.

    This is a stricter test than exempting elisions outright: an elided path
    with nothing corresponding in the evidence still lands in ``unverified``.
    The matched concrete path is returned so the finding can show what the
    abbreviation referred to.
    """
    parsed = _regkey_parts(plain)
    if not parsed:
        return None
    hive, subkeys = parsed
    # Skip the elision segment itself: it names no real location, so it can never
    # be matched. Everything the claim ACTUALLY names is what the candidate must
    # carry.
    named = [s for s in subkeys if s not in (".", "..", "…", "...")]
    if not named:
        return None

    text = evidence or ""
    best: tuple[tuple[int, int], str] | None = None
    for m in _EVIDENCE_REGKEY_RE.finditer(text):
        candidate = m.group(0)
        cparsed = _regkey_parts(candidate)
        if not cparsed:
            continue
        chive, csubkeys = cparsed
        if chive != hive or not csubkeys:
            continue
        # EVERY named segment must appear in the candidate, in the order the
        # claim wrote them.
        #
        # Matching on the last segment alone made a single shared leaf enough to
        # ground a path -- so `HKLM\...\Services\MyDriver\Parameters` was
        # "verified" against `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\
        # Parameters\Interface`, and `HKCU\...\Policies\Explorer\Run` against
        # the real `HKCU\...\CurrentVersion\Run` (review finding MEDIUM-2,
        # 2026-10-03). Both are common segment names an LLM reaches for when
        # writing from training data, so the loose rule converted fabrication
        # into GREEN -- strictly worse than failing to ground it, because the
        # gate then certifies the invented path.
        ci = 0
        for seg in named:
            while ci < len(csubkeys) and csubkeys[ci] != seg:
                ci += 1
            if ci >= len(csubkeys):
                break
            ci += 1
        else:
            # Exact tail match ranks first regardless of depth; among equal
            # ranks, the deepest path is the most specific corroboration.
            rank = (0 if csubkeys[-1] == named[-1] else 1, len(csubkeys))
            if best is None or rank > best[0]:
                best = (rank, candidate)
    return best[1] if best else None


def _evidence_has_regkey(plain: str, evidence: str) -> str | None:
    r"""The concrete evidence path with this hive AND subkey list, or None.

    Substring matching cannot verify a canonical-path claim across hive
    spellings: the evidence's `HKCU\Software\...\Run` does not contain the
    literal `HKEY_CURRENT_USER\Software\...\Run`, so the long spelling of an
    OBSERVED key failed verification while the short spelling of the same key
    passed. Comparison is on the parsed hive + full subkey list, which is
    stricter than a substring in every other respect.
    """
    parsed = _regkey_parts(plain)
    if not parsed:
        return None
    hive, subkeys = parsed
    for m in _EVIDENCE_REGKEY_RE.finditer(evidence or ""):
        candidate = m.group(0)
        if _regkey_parts(candidate) == (hive, subkeys):
            return candidate
    return None


def _claim_context_window(scan: str, start: int, end: int) -> str:
    r"""The text a reader would hold in mind at this position.

    The scope has to match the unit the reader sees, and choosing it wrong is
    how this class of check launders real claims:

      * inside a list item, the whole bullet is the unit -- both real cases are
        bullets ("Remove ... - HKLM\...\UserList (delete added values)")
      * in running prose, the unit is the sentence. Scoping to the LINE would
        let "Remove persistence. The observed write was X" excuse X, which is
        exactly backwards.

    A guidance verb anywhere else in the document must not reach across a
    section boundary, which is why neither scope extends beyond the item.
    """
    text = scan or ""
    line_start = text.rfind("\n", 0, start) + 1
    nxt_nl = text.find("\n", end)
    line_end = nxt_nl if nxt_nl != -1 else len(text)
    line = text[line_start:line_end]

    stripped = line.lstrip()
    if _BULLET_RE.match(stripped):
        return line
    sent_start = max(text.rfind(".", 0, start),
                     text.rfind(";", 0, start),
                     text.rfind("!", 0, start),
                     line_start - 1) + 1
    return text[sent_start:line_end]


def _is_guidance_reference(scan: str, raw: str,
                           spans: dict[tuple[str, str], list[tuple[int, int]]]) -> bool:
    r"""True when a registry path is named inside defender guidance.

    A path counts as guidance only when EVERY occurrence sits in a guidance
    window. Classifying on the first occurrence alone laundered the opposite
    direction: a value first mentioned in "Monitor ..." guidance and later
    asserted bare ("The sample writes to X") was excused by its first mention
    and never judged as the claim it also was.
    """
    text = scan or ""
    span_list = spans.get(("registry_key", _plain_claim(raw or "").lower()))
    if not span_list:
        return False
    for start, end in span_list:
        window = _claim_context_window(text, start, end)
        if not (_GUIDANCE_VERB_RE.search(window)
                or _VERIFICATION_TARGET_RE.search(window)
                or _CONDITIONAL_GUIDANCE_RE.search(window)):
            return False
    return True


def _claims_text(markdown: str) -> str:
    """Narrative text without code blocks or the generated run identity tag."""
    text = _FENCED_CODE_RE.sub("\n", markdown or "")
    return _REPORT_EXECUTION_COMMENT_RE.sub("\n", text)


#: RFC 5737 documentation ranges + loopback/unspecified: these are placeholders
#: in prose (examples), never claims about the sample.
_DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "127.", "0.0.0.0")


def _is_doc_placeholder_ip(value: str) -> bool:
    v = (value or "").strip().strip(".")
    return v.startswith(_DOC_IP_PREFIXES) or v == "255.255.255.255"

#: Only indicators whose final label is a real TLD count as domain claims.
#: Without this, prose and code identifiers ("powershell.exe",
#: "capability.attack.execution") parse as domains and inflate the unverified set.
_KNOWN_TLDS = frozenset("""
com net org edu gov mil int io co ai app dev me us uk de fr nl it es pl ru ua
tr cn jp kr in br mx ca au nz ch se no fi dk be at cz gr pt ro hu bg hr sk si
rs lt lv ee il sa ae eg za ng ke gh pk bd vn th sg my id ph hk tw
info biz top xyz site online live club shop store tech space website world
cc tv pw su tk ml ga cf gq ws to fm am nu la sh st ws
""".split())


def _looks_like_domain(value: str) -> bool:
    plain = _plain_claim(value).strip(".")
    if plain.count(".") < 1:
        return False
    tld = plain.rsplit(".", 1)[-1].lower()
    return tld in _KNOWN_TLDS


_REPORT_METADATA_PREFIX_RE = re.compile(
    r"^(?:>\s*)?(?:\*\*(?:sha-?256|generated_at|pipeline|source|run_id)"
    r"\*\*\s*:|_(?:generated|pipeline)\b|<!--\s*section:|"
    r"\*\*revai provenance\b|_\(local build\b)",
    re.IGNORECASE,
)


def _split_report_sentences(text: str) -> list[str]:
    """Split prose without treating punctuation inside citations as prose.

    Evidence locators often quote tool output containing periods or ellipses.
    Splitting those locators first made a valid citation appear detached from
    its claim. A citation after terminal punctuation belongs to the preceding
    claim, while the next sentence must still be checked independently.
    """
    value = (text or "").strip()
    if not value:
        return []
    spans = {
        int(annotation["start"]): int(annotation["end"])
        for annotation in parse_citation_annotations(value)
        if annotation.get("start") is not None and annotation.get("end") is not None
    }
    parts: list[str] = []
    start = 0
    index = 0
    while index < len(value):
        annotation_end = spans.get(index)
        if annotation_end is not None:
            index = annotation_end
            continue

        char = value[index]
        if char not in ".!?":
            index += 1
            continue

        punctuation_end = index + 1
        if char == ".":
            if index > 0 and value[index - 1] == ".":
                index += 1
                continue
            while punctuation_end < len(value) and value[punctuation_end] == ".":
                punctuation_end += 1

        next_start = punctuation_end
        while next_start < len(value) and value[next_start].isspace():
            next_start += 1
        if next_start == punctuation_end and next_start not in spans:
            index = punctuation_end
            continue

        if next_start in spans:
            # Attach one or more citations that follow the sentence-ending
            # punctuation, then resume at the next prose character.
            cursor = spans[next_start]
            while True:
                while cursor < len(value) and value[cursor].isspace():
                    cursor += 1
                if cursor not in spans:
                    break
                cursor = spans[cursor]
            # Citation annotations stop before punctuation that follows the
            # closing parenthesis, e.g. ``claim. (source: ..., row: ...).``
            # Consume that punctuation with the cited sentence so it cannot
            # become a standalone, apparently uncited claim.
            while cursor < len(value) and value[cursor] in ".!?":
                cursor += 1
            parts.append(value[start:cursor].strip())
            start = cursor
            index = cursor
            continue

        if next_start >= len(value):
            parts.append(value[start:punctuation_end].strip())
            start = len(value)
            break

        parts.append(value[start:punctuation_end].strip())
        start = next_start
        index = next_start

    if start < len(value):
        parts.append(value[start:].strip())
    return [part for part in parts if part and any(char.isalnum() for char in part)]


def uncited_report_claims(markdown: str) -> list[str]:
    """Return narrative assertions that lack a nearby source citation.

    Every factual table row and narrative assertion requires a concrete source
    citation with a row/rule locator; a populated Source or Evidence cell alone
    does not bind the claim to an observation.
    Fenced evidence dumps are excluded because they are source material, while
    narrative that interprets them must remain cited.
    This is a structural coverage check; it does not claim that a citation
    semantically entails the sentence.
    """
    if not markdown:
        return []

    lines: list[str] = []
    in_fence = False
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)

    uncited: list[str] = []
    in_table = False
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            in_table = False
            continue
        # The claim-level schema renders assessment/recommendation/note blocks
        # with a fixed marker. These are explicitly non-factual and do not need
        # a citation, but their text is still scanned for claimed indicators.
        # The marker is the only exemption: unmarked prose remains a claim.
        if is_non_factual_markdown_line(line):
            in_table = False
            continue
        # Machine-rendered verdict lines are pipeline output, not model
        # claims (#6-a, 2026-10-29): the RC-04b calibration blockquote is
        # printed by the publisher itself (its provenance is the publish
        # record and verdict-calibration.json), and it read as two uncited
        # claims on run b4e280408534. A blockquote line that is not the
        # calibration marker stays a claim.
        if line.startswith(">") and "[verdict calibration]" in line.lower():
            in_table = False
            continue
        if line.startswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if not in_table:
                in_table = True
                continue
            if all(re.fullmatch(r"\s*:?-{2,}:?\s*", cell) for cell in cells):
                continue
            # The verdict panel row is the report's own structured verdict
            # statement (#6-a): machine-checked by the verdict locks and the
            # panel-agreement gate, not a claim that needs a citation. Match
            # the exact panel shapes the locks read (| Verdict | ... | and
            # | **Final** | ... |); any other row stays a claim.
            if cells and re.fullmatch(
                    r"(?:\*\*)?(?:verdict|final)(?:\*\*)?", cells[0],
                    re.IGNORECASE):
                continue
            # A populated Evidence/Source cell is not provenance by itself.
            # Require a parseable citation with a concrete row locator so the
            # entailment gate can resolve this exact row to a run artifact.
            if not has_citation_locator(line):
                excerpt = re.sub(r"\s+", " ", line)
                uncited.append(excerpt[:240])
            continue

        in_table = False
        if line.startswith("#") or line.startswith("<!--"):
            continue
        # RC-18: a disassembly listing that leaked outside a code fence is
        # source material, not a narrative claim. The schema rejects such
        # blocks at generation time; this keeps any that still slip through
        # from inflating uncited_claims (run 65be0144: 12 listing lines).
        if is_disassembly_listing_line(line):
            continue
        # Bold-only labels are markdown headings even when the author chose
        # not to use ``#`` syntax. Treating these as unsupported factual claims
        # avoids treating a bold label as an unsupported factual assertion.
        if re.fullmatch(r"(?:[-*+]\s+)?\*\*[^*\n]+\*\*\s*:?[：:]?", line):
            continue
        if _REPORT_METADATA_PREFIX_RE.match(line):
            continue

        # Numbered-list syntax is not part of the claim. Without this removal,
        # the sentence splitter treated `1.` as a standalone uncited assertion
        # before it reached the actual list item.
        if re.fullmatch(r"\d+[.)]", line):
            continue
        prose_line = re.sub(r"^\s*\d+[.)]\s+", "", raw_line)
        for sentence in _split_report_sentences(prose_line):
            claim = re.sub(r"\s+", " ", sentence).strip()
            claim = re.sub(r"^(?:[-*+]\s+|>\s*)+", "", claim)
            # A source label alone is not a traceable citation. The entailment
            # checker classifies it as source-only because a reviewer cannot
            # locate the observation. Require a concrete row/rule locator in
            # narrative and table citations.
            if has_citation_locator(claim):
                continue
            if _REPORT_METADATA_PREFIX_RE.match(claim):
                continue
            if claim.lower().startswith((
                "this report ", "this section ", "in this section ",
                "all citations ", "citation format ", "the following sections ",
                "the following tables reproduce ", "every row is cited ",
                "the table below ", "the following table ",
                "the summary below ", "the figure below ",
                "the following figure ", "the list below ",
                "the timeline below ", "the chart below ",
                "the evidence trail below ",
            )):
                continue
            uncited.append(claim[:240])
    return uncited


# Backwards compatibility for existing in-repo callers and focused tests.
_uncited_report_claims = uncited_report_claims

#: Evidence files worth searching, most specific first. Anything absent is
#: skipped, so a scripted run without a dynamic pack still verifies statically.
_EVIDENCE_FILES = (
    "deep_dive/05-deep-dive.json",
    "deep_dive/01-tools-raw.json",
    "deep_dive/02-signals.json",
    "deep_dive/agentic_deep_dive.json",
    "quick_scan/00-tools-raw.json",
    "dynamic-analysis-status.json",
    # The YARA-generation stage records the sample's imphash and emitted rule
    # metadata here. Reports cite that artifact for exact hashes and detection
    # claims, so excluding it made the scrubber replace a valid imphash with an
    # "unobserved" marker (seen on the 2026-10-16 integrated report run).
    "rule.yara.json",
    "iocs.json",
    "verdict.json",
    "evidence-pack.md",
    "deep-dive-agentic-history.json",
    "evidence/strings.txt",
    "evidence/raw-strings.txt",
)


def _plain_claim(value: str) -> str:
    """Undefang a claimed indicator for matching (the original is kept for output)."""
    for token in ("[.]", "[dot]", "(.)"):
        value = value.replace(token, ".")
    value = value.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    # Collapse runs of backslashes. A registry path written inside markdown is
    # escaped, so the same path reaches us as both `HKCU\Software\...` and
    # `HKCU\\Software\\...`. Left alone they hash to two different claims, so one
    # indicator was counted twice in `unverified_items` (win32k_dll, 2026-10-02:
    # HKEY_CURRENT_USER Run key reported as two separate unverified claims), and
    # an ELIDED path escaped detection entirely -- `\\` followed by `...` does not
    # match _ELIDED_REGISTRY_RE, which expects one separator then the ellipsis, so
    # the escaped spelling fell through to a verbatim evidence comparison and was
    # flagged unverified when the shorthand form would have been grounded.
    value = re.sub(r"\\{2,}", r"\\", value)
    return re.sub(r"^hxxps?", "http", value, flags=re.IGNORECASE)


def _provenance_commit() -> str:
    """The deployed pipeline commit (as shown in the provenance banner), or ''.

    Same lookup as v2_lib.revai_provenance: REVAI_COMMIT env or
    /opt/revai/config/REVAI_COMMIT (written by scripts/deploy.sh). The
    `-dirty` suffix is stripped so only the hash itself is compared.
    """
    commit = (os.environ.get("REVAI_COMMIT") or "").strip()
    if not commit:
        try:
            commit = Path("/opt/revai/config/REVAI_COMMIT").read_text(
                encoding="utf-8"
            ).strip()
        except Exception:
            return ""
    return commit.lower().removesuffix("-dirty")


def _sample_sha256() -> str:
    """The analysed sample's sha256, when the caller can tell us which it is.

    Read from REVAI_CASE_DIR, which the stages set -- NOT from the report's own
    `sha256:` line, because a claim must never be used to exempt itself.

    The case dir is `logs/<sha>/<mode>/` (the mode-keyed layout), so the sha is
    one level UP from the directory name, not the name itself. Returns '' when
    unknown, which exempts nothing.
    """
    case = os.environ.get("REVAI_CASE_DIR", "").strip()
    if not case:
        return ""
    # the deepest 64-hex component wins: logs/<sha>/<mode>/, but tolerate a bare
    # logs/<sha> as well
    for part in reversed(Path(case).parts):
        if re.fullmatch(r"[0-9a-fA-F]{64}", part):
            return part.lower()
    return ""


def _report_metadata_hashes(evidence_root: Path) -> dict[str, str]:
    """Return exact run-bound report digests and their provenance categories.

    Reports expose input-artifact digests, the manifest digest, and the run ID.
    Those identify the analysis record, not malware indicators. Trust this
    narrow classification only when the manifest belongs to the same sample
    and execution context.
    """
    root = Path(evidence_root)
    manifest_path = root / "publish" / "report-input-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if (not isinstance(manifest, dict)
            or manifest.get("schema") != "revai-report-input-manifest/v1"):
        return {}

    expected_sha = _sample_sha256()
    if not expected_sha:
        expected_sha = next(
            (part.lower() for part in reversed(root.parts)
             if re.fullmatch(r"[0-9a-fA-F]{64}", part)), "")
    manifest_sha = str(manifest.get("sample_sha256") or "").lower()
    if (not expected_sha or manifest_sha != expected_sha
            or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha)):
        return {}

    try:
        context = json.loads((root / "execution-context.json").read_text(
            encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(context, dict):
        return {}
    expected_run_id = str(context.get("run_id") or "").lower()
    manifest_run_id = str(manifest.get("run_id") or "").lower()
    expected_mode = str(context.get("mode") or "")
    if (not re.fullmatch(r"[0-9a-f]{32}", expected_run_id)
            or manifest_run_id != expected_run_id
            or not expected_mode
            or str(manifest.get("mode") or "") != expected_mode):
        return {}

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return {}
    hashes: dict[str, str] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        digest = str(item.get("sha256") or "").lower()
        if (item.get("status") in {"attested", "unattested"}
                and re.fullmatch(r"[0-9a-f]{64}", digest)):
            hashes.setdefault(digest, "input_artifact_digest")
    # The report appendix exposes this manifest digest alongside the artifact
    # hashes. It is run provenance, not a hash attributed to the sample.
    manifest_digest = hashlib.sha256(json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    hashes[manifest_digest] = "report_input_manifest_digest"
    hashes[manifest_run_id] = "run_id"
    return hashes


def _hash_mention_is_report_metadata(
    scan: str, spans: list[tuple[int, int]], metadata_kind: str,
) -> bool:
    """Require every occurrence to be explicitly presented as run metadata.

    A digest can appear in a provenance appendix and also be misrepresented as
    a sample IOC elsewhere. The value alone must never exempt every occurrence.
    """
    if not spans:
        return False
    for start, end in spans:
        line_start = scan.rfind("\n", 0, start) + 1
        line_end = scan.find("\n", end)
        if line_end < 0:
            line_end = len(scan)
        line = scan[line_start:line_end]
        folded = line.casefold()
        local = scan[max(line_start, start - 48):min(line_end, end + 48)].casefold()
        if metadata_kind == "run_id":
            explicitly_labelled = bool(re.search(r"\brun(?:[ _-]?id)?\b", folded))
        elif metadata_kind == "report_input_manifest_digest":
            explicitly_labelled = (
                "manifest" in folded
                and bool(re.search(
                    r"(?<![a-z0-9])sha[_-]?256(?![a-z0-9]|_)|\b(?:digest|hash)\b",
                    folded,
                ))
            )
        elif metadata_kind == "input_artifact_digest":
            explicitly_labelled = bool(re.search(
                r"\b(?:attested|report[- ]input|input|evidence|source)\s+artifact\b"
                r"|\bartifact\s+(?:sha-?256|digest|hash)\b"
                r"|\b(?:sha-?256|digest|hash)\b.{0,80}\b(?:artifact|file)\b"
                # The report-input manifest table renders rows as
                # `| artifact | digest | size | attested | (source: manifest,
                # query_or_table: revai-report-input-manifest/v1,
                # row_or_rule: $.artifacts[N]) |`.  These are run provenance
                # rows, not sample indicators. Keep the exemption tied to the
                # manifest citation, not merely to the word "attested".
                r"|\b(?:attested|manifest|artifact)\b.{0,140}\b"
                r"(?:revai-report-input-manifest|source:\s*manifest"
                r"|query_or_table:\s*manifest|\$\.artifacts\[\d+\])"
                r"|\$\.artifacts\[\d+\]",
                folded,
            ))
        else:
            return False
        if not explicitly_labelled:
            return False
        # If this occurrence is framed as an indicator or malware hash, keep it
        # in the claim set even when the same bytes also identify an input file.
        if re.search(
            r"\b(?:ioc|indicator|malware|payload|drop(?:ped|per)?(?:\s+file)?|"
            r"blocklist|c2|hash-based)\b",
            local,
        ):
            return False
    return True


def verify_claimed_iocs(markdown: str, evidence_text: str, *,
                        provenance_commit: str | None = None,
                        metadata_hashes: dict[str, str] | set[str] | None = None) -> dict:
    """Check every indicator a report claims against the raw tool evidence.

    Deterministic and code-based: no LLM re-reading of the report. A claim is
    *verified* when its plain (re-fanged) value appears in the concatenated raw
    evidence, *unverified* otherwise. The report must keep evidence for its
    sample-specific claims in the run's evidence pack; unsupported values fail
    the per-report quality gate.

    Hash claims equal to the pipeline's own provenance commit are excluded:
    the provenance banner is build metadata, not a sample indicator
    (rehearsal 2026-09-21: REVAI_COMMIT in the banner was flagged as an
    "unverified sha256").
    """
    prov = ((provenance_commit if provenance_commit is not None
             else _provenance_commit()) or "").lower()
    # Claims are collected from prose/tables only: fenced snippets (and their
    # `// placeholder` values) are illustrations, not indicator claims.
    scan = _claims_text(markdown)
    # A value inside a citation annotation is a locator, not an assertion about
    # the sample. The 2026-10-20 report cited its verdict-calibration digest as
    # `(source: verdict-calibration, sha256 ...)`; the gate counted that digest
    # as an unverified sample hash. Resolve every occurrence against the
    # parsed annotation spans, so a digest asserted elsewhere in the same report
    # is still judged as a claim.
    citation_spans = [
        (int(item["start"]), int(item["end"]))
        for item in parse_citation_annotations(scan)
        if item.get("start") is not None and item.get("end") is not None
    ]
    # Commits cited in the report's own provenance banner are build metadata as
    # well: a report generated by an earlier deploy keeps its commit hash after
    # a redeploy, and flagging it as an unverified sha256 is noise.
    banner_commits = {m.group(1).lower()
                      for m in _PROVENANCE_BANNER_RE.finditer(markdown or "")}
    evidence = (evidence_text or "").lower()
    sample_sha = _sample_sha256()
    if isinstance(metadata_hashes, dict):
        report_artifact_hashes = {
            str(value).lower(): str(kind)
            for value, kind in metadata_hashes.items()
            if re.fullmatch(r"[0-9a-fA-F]{32,64}", str(value))
        }
    else:
        # Backward-compatible for callers that supplied a set before metadata
        # categories were introduced; such values are treated conservatively.
        report_artifact_hashes = {
            str(value).lower(): "input_artifact_digest"
            for value in (metadata_hashes or set())
            if re.fullmatch(r"[0-9a-fA-F]{32,64}", str(value))
        }
    claims: dict[tuple[str, str], str] = {}
    claim_spans: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for kind, regex in (
        ("url", _CLAIM_URL_RE),
        ("ip", _CLAIM_IP_RE),
        ("domain", _CLAIM_DOMAIN_RE),
        ("hash", _CLAIM_HASH_RE),
        ("registry_key", _CLAIM_REGKEY_RE),
        ("email", _CLAIM_EMAIL_RE),
    ):
        for m in regex.finditer(scan):
            # The trailing strip must include markdown emphasis and code
            # punctuation. `*` and a backtick are not in _CLAIM_URL_RE's
            # exclusion set, so a URL written as `` `http://icanhazip.com`** ``
            # was captured as "http://icanhazip.com\`**" and then failed its own
            # evidence match -- flagged unverified while being present 10 times
            # in the evidence pack and 4 times in iocs.json (win32k_dll,
            # 2026-10-02). Stripping `*` and `` ` `` from both ends fixes the
            # whole class: a real indicator must not be able to fail
            # verification on typography alone.
            raw = m.group(0).strip().strip(".,;:()[]{}'\"`*_\\")
            if len(raw) < 4:
                continue
            if kind == "domain" and not _looks_like_domain(raw):
                continue
            if kind == "url" and "." not in _plain_claim(raw).split("//", 1)[-1]:
                continue
            claims.setdefault((kind, _plain_claim(raw).lower()), raw)
            # Keep where EVERY occurrence was found. The classification pass
            # below needs the positions to reason about surrounding context,
            # and it runs over the deduplicated dict -- where the match object
            # from this loop is long gone. Keeping only the FIRST span made
            # guidance classification reversible: a value first mentioned in
            # "Monitor ..." guidance and later asserted bare was excused by
            # its first mention.
            claim_spans.setdefault((kind, _plain_claim(raw).lower()), [])
            claim_spans[(kind, _plain_claim(raw).lower())].append(
                (m.start(), m.end()))

    verified: list[dict[str, str]] = []
    unverified: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    guidance: list[dict[str, str]] = []
    for (kind, plain), raw in sorted(claims.items()):
        if kind == "hash":
            hash_spans = claim_spans.get((kind, plain), [])
            if hash_spans and citation_spans and all(
                any(start >= c_start and end <= c_end
                    for c_start, c_end in citation_spans)
                for start, end in hash_spans
            ):
                excluded.append({
                    "type": kind, "value": raw,
                    "reason": "hash appears only inside a citation locator, "
                              "not as a sample indicator",
                })
                continue
            metadata_kind = report_artifact_hashes.get(plain)
            if metadata_kind and _hash_mention_is_report_metadata(
                    scan, hash_spans, metadata_kind):
                excluded.append({
                    "type": kind, "value": raw,
                    "reason": "run-bound report provenance value in a metadata "
                              "context, not a sample indicator",
                })
                continue
            # The analysed sample's own sha256: identity, not an indicator.
            # WannaCry's audit went red on exactly this -- the hash appears in
            # the report's Sample Metadata (which the pipeline writes) but not
            # in the tool-output corpus it is verified against. A report must
            # never be red on the fact that it names the sample it analysed.
            if sample_sha and plain == sample_sha:
                excluded.append({
                    "type": kind, "value": raw,
                    "reason": "the analysed sample's own sha256, not an indicator",
                })
                continue
            cited = any(c.startswith(plain) or plain.startswith(c)
                        for c in banner_commits)
            if cited or (prov and (plain == prov or
                                   (len(plain) >= 8 and prov.startswith(plain)))):
                excluded.append({"type": kind, "value": raw,
                                 "reason": "pipeline provenance commit, not a sample indicator"})
                continue
        if kind == "ip" and _is_doc_placeholder_ip(plain):
            excluded.append({"type": kind, "value": raw,
                             "reason": "documentation/placeholder address range (RFC 5737/loopback)"})
            continue
        if kind in ("domain", "url"):
            try:
                from ioc_confidence import is_benign_domain, url_host
                host = url_host(raw) if kind == "url" else plain
                if host and is_benign_domain(host):
                    excluded.append({"type": kind, "value": raw,
                                     "reason": "well-known vendor/telemetry domain"})
                    continue
            except Exception:
                pass
        if kind == "registry_key" and _plain_claim(raw).count("\\") < 2:
            # "HKEY_CURRENT_USER\Run" is a hive name, not a specific path - there
            # is nothing referenceable to verify.
            excluded.append({"type": kind, "value": raw,
                             "reason": "generic hive key without a specific subkey"})
            continue
        if kind == "registry_key" and _is_guidance_reference(scan, raw, claim_spans):
            # Named inside imperative defender guidance: a location to inspect
            # or clean, not an indicator the report attributes to the sample.
            # Reported, not counted as a claim.
            guidance.append({"type": kind, "value": raw,
                              "reason": "named in defender guidance, not "
                                        "claimed as an observed artifact"})
            continue
        if kind == "registry_key" and _ELIDED_REGISTRY_RE.match(plain):
            # Abbreviated path: resolve it rather than exempting it. `tail` is
            # the subkey the report actually named, i.e. what an evidence path
            # has to end with for the abbreviation to be grounded.
            parsed = _regkey_parts(plain) or ("", [])
            concrete = [s for s in parsed[1]
                        if s not in (".", "..", "…", "...")]
            tail = concrete[-1] if concrete else ""
            # If the evidence shows a concrete path under the same hive ending
            # in the subkey the report named, the abbreviation is a legitimate
            # reference to an observed artifact -- verified, with the concrete
            # path recorded. If nothing corresponds, it stays unverified,
            # because a generic persistence claim is still not an observation.
            grounded = _ground_elided_regkey(plain, evidence_text or "")
            if grounded:
                verified.append({"type": kind, "value": raw,
                                 "abbreviated_from": grounded})
            else:
                # Deliberately NOT excluded. The report asserts a persistence
                # mechanism at a specific subkey; if no concrete path with that
                # subkey appears in the evidence, the assertion is unsupported
                # and belongs in `unverified` where the gate can see it.
                unverified.append({
                    "type": kind, "value": raw,
                    "reason": "abbreviated registry path; no concrete path with "
                              f"this subkey found in the evidence (claimed "
                              f"{tail or 'subkey'})"})
            continue
        if kind == "registry_key" and _CANONICAL_REGISTRY_TEMPLATE_RE.match(plain):
            # A report names the canonical Run key. Three cases, kept strictly
            # apart: a tool really observed it (verified below, in either hive
            # spelling); it is used as a verification TARGET -- "RegSetValue
            # under HKCU\...\Run (or equivalent) - not observed" -- which the
            # context window shows, and is excluded; or it is a bare unobserved
            # assertion ("persists via HKCU\...\Run"), which is a claim like
            # any other and falls through to `unverified`, where the scrubber
            # neutralises it. Before the context check the template branch
            # excluded ALL unobserved mentions, so the exact fabrication #42
            # exists for -- a canonical path written from training data --
            # shipped while the audit counted zero.
            if plain in evidence or raw.lower() in evidence:
                verified.append({"type": kind, "value": raw})
                continue
            matched = _evidence_has_regkey(plain, evidence_text or "")
            if matched:
                verified.append({"type": kind, "value": raw,
                                 "abbreviated_from": matched})
                continue
            span_list = claim_spans.get((kind, plain)) or []
            scan_text = scan
            if span_list and all(
                _CANONICAL_TEMPLATE_TARGET_RE.search(
                    _claim_context_window(scan_text, s, e))
                for s, e in span_list):
                excluded.append({"type": kind, "value": raw,
                                 "reason": "canonical persistence template used as a "
                                           "verification target, not an observed artifact"})
                continue
            unverified.append({"type": kind, "value": raw})
            continue
        if plain in evidence or raw.lower() in evidence:
            verified.append({"type": kind, "value": raw})
        else:
            unverified.append({"type": kind, "value": raw})

    excluded_reason_counts: dict[str, int] = {}
    for item in excluded:
        reason = str(item.get("reason") or "unspecified")
        excluded_reason_counts[reason] = excluded_reason_counts.get(reason, 0) + 1
    resolved = [v for v in verified if v.get("abbreviated_from")]
    return {
        "advisory": True,
        # Paths named in defender guidance are collected by the same regex but
        # are not indicator claims, so they are counted out of `claims` and
        # reported separately rather than inflating the judged total.
        "claims": len(claims) - len(guidance),
        "verified": len(verified),
        "unverified": len(unverified),
        "excluded": len(excluded),
        "excluded_reason_counts": excluded_reason_counts,
        "guidance_references": len(guidance),
        "unverified_items": unverified[:40],
        "excluded_items": excluded[:10],
        "guidance_items": guidance[:10],
        # An abbreviated claim is verified against the concrete path it stood
        # for, not by a literal match, so the substitution has to be auditable
        # -- otherwise "verified" is unfalsifiable for these.
        "resolved_abbreviations": resolved[:20],
        "method": ("case-insensitive substring match of the plain value against "
                   "concatenated raw tool evidence (both fanged and defanged "
                   "forms); an abbreviated registry path is instead resolved to "
                   "a concrete evidence path under the same hive with the same "
                   "trailing subkey"),
    }


#: Fenced blocks, captured so the splitter can keep them verbatim. The second
#: alternative keeps an UNTERMINATED fence verbatim too, so the scrubber and
#: the claim extractor agree on where code ends even when the report's markdown
#: is unbalanced (see _FENCED_CODE_RE).
_FENCE_BLOCK_SPLIT_RE = re.compile(r"(```.*?```|```.*\Z)", re.DOTALL)

#: What an unobserved indicator is replaced with, per claim type.
#:
#: Deliberately NOT a deletion. A sentence like "code paths that write to
#: `HKCU\...\Run` and create scheduled tasks (source: yara)" carries a real,
#: evidenced finding -- capa matched T1112 Modify Registry and T1543.003, and a
#: yara rule fired. Deleting the clause would throw that away and make the report
#: less informative. The fabricated part is the concrete PATH, so only the path
#: is neutralised and the evidenced capability survives intact.
_UNVERIFIED_MARKERS = {
    "registry_key": "[registry path not observed in evidence]",
    "url": "[URL not observed in evidence]",
    "ip": "[IP not observed in evidence]",
    "domain": "[domain not observed in evidence]",
    "hash": "[hash not observed in evidence]",
    "email": "[email not observed in evidence]",
    "value": "[value not observed in evidence]",
}


#: Text immediately after a scrub marker that continues the removed path.
#: See the `orphan_fragments` result in `scrub_unverified_indicators`.
#:
#: The continuation is ` WORD\...`, not `\...`: when the extractor truncated
#: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` at the space, the
#: removed part ended at `Windows` and what remained was ` NT\CurrentVersion\
#: Winlogon`. Matching only a leading separator would have missed exactly the
#: case that occurred.
_ORPHAN_FRAGMENT_RE = re.compile(
    r"\[(?:registry path|URL|IP|domain|hash|email|value) not observed in "
    r"evidence\]\s?(?:[A-Za-z0-9._-]+)?\\[A-Za-z0-9._\\-]+")


#: The only model identifier allowed to appear in published markdown.
#:
#: Reports are public documents; vendor and model names are scrubbed from them
#: (docs hygiene rule). JSON artifacts are NOT scrubbed -- verdict.json,
#: pipeline-audit.json and report-*.json keep the real name, because they are
#: machine evidence and an auditor needs to know which model judged the sample.
#: The published markdown says a configured LLM did it, which is the honest
#: claim a reader can actually verify.
PUBLIC_MODEL_LABEL = "configured-llm"


def configured_model_names() -> list[str]:
    """Every model name this deployment is configured with, longest first.

    Longest-first matters: the verdict model and the default model are often
    two names sharing a prefix (e.g. `<name>-pro` and `<name>`), and replacing
    the shorter first would leave the suffix dangling in the output.

    The resolvers read os.environ, which the pipeline populates via
    ensure_pipeline_runtime_env(). If that has not run -- a bare import, a unit
    test, a maintenance script -- this falls back to reading the MODEL
    variables out of the env file so redaction cannot silently become a no-op.
    A silent no-op is the failure mode worth avoiding here: the caller would
    report success while publishing the name it was asked to remove.

    Only `*_MODEL`-shaped variables are read. Keys and secrets in the same file
    are neither read nor retained.
    """
    names: set[str] = set()
    for fn in ("get_default_model", "get_planner_model", "get_verdict_model"):
        try:
            from v2_lib import fn as _fn  # type: ignore
            v = _fn()
        except Exception:
            continue
        if v and isinstance(v, str):
            names.add(v.strip())
    for var in ("REVAI_LLM_MODEL", "REVAI_LLM_PLANNER_MODEL",
                "REVAI_LLM_VERDICT_MODEL", "REVAI_FORCE_MODEL"):
        v = os.environ.get(var, "").strip()
        if v:
            names.add(v)
    if not names:
        for path in (Path("/opt/revai/config/llm.env"),
                     Path(__file__).resolve().parent.parent
                     / "config" / "llm.env"):
            try:
                if not path.is_file():
                    continue
                for line in path.read_text(
                        encoding="utf-8", errors="replace").splitlines():
                    s = line.strip()
                    if not s or s.startswith("#") or "=" not in s:
                        continue
                    k, _, v = s.partition("=")
                    k, v = k.strip(), v.strip()
                    if k.endswith("_MODEL") and v and len(v) >= 3:
                        names.add(v)
            except Exception:
                continue
            if names:
                break
    return sorted((n for n in names if len(n) >= 3), key=len, reverse=True)


def redact_model_names(markdown: str) -> tuple[str, list[str]]:
    """Replace configured model names in published markdown with the public label.

    Two reasons this exists rather than only fixing the injection site:

    1. The technical evidence pack renders the verdict's `model` field, and the
       model then COPIES that string into its own prose. Fixing the injection
       stops the source but not the copy.
    2. A published report is a document a reader may screenshot or quote; the
       provider name is not part of the analysis.

    Only names this deployment is actually configured with are replaced, so
    prose that happens to contain a similar word is untouched. Exact-match
    rather than a fuzzy model-name regex, on purpose: a regex broad enough to
    catch unknown vendors is also broad enough to mangle analysis text.
    """
    if not markdown:
        return markdown, []
    replaced: list[str] = []
    out = markdown
    for name in configured_model_names():
        if name and name in out:
            out = out.replace(name, PUBLIC_MODEL_LABEL)
            replaced.append(name)
    return out, sorted(set(replaced))


_REPORT_CREDENTIAL_PATTERNS = (
    ("telegram-bot-token", re.compile(
        r"(?<![A-Za-z0-9])\d{6,12}:[A-Za-z0-9_-]{25,}(?![A-Za-z0-9_-])")),
    ("github-personal-access-token", re.compile(
        r"(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
)


def redact_credential_like_values(markdown: str) -> tuple[str, list[str]]:
    """Mask high-confidence credential formats in human-facing Markdown.

    Raw tool evidence and LLM call records remain untouched for authorized
    analysis. The report keeps its surrounding claim and source locator, while
    the credential itself is replaced before quality checks and publication.
    Return category names only; never return or log the matched values.
    """
    if not markdown:
        return markdown, []
    out = markdown
    categories: list[str] = []
    for category, pattern in _REPORT_CREDENTIAL_PATTERNS:
        out, count = pattern.subn(f"[REDACTED {category.upper()}]", out)
        if count:
            categories.append(category)
    return out, categories


def _flex_claim_re(value: str) -> re.Pattern:
    """Match any markdown rendering of one indicator value.

    The body is built from the PLAIN (undefanged) value, and the characters
    that defanging rewrites match either spelling: `.` matches `[.]`, `(.)` and
    `[dot]`, `:` matches `[:]`, `@` matches `[@]`/`[at]`, and an `http` prefix
    matches its `hxxp` rendering. Without this, whichever spelling came first
    in the report was removed and the other survived -- `remaining_unverified`
    stayed above zero while the scrub reported success (2026-10-03: `evil.com`
    in prose and `evil[.]com` in a table row are one claim).

    Registry paths reach us escaped (``HKCU\\\\Software\\\\...``) as often as
    plain (``HKCU\\Software\\...``), so each separator matches one or two
    backslashes. The boundaries stop a claim from matching inside a longer
    token, and deliberately allow ``*`` and a backtick to follow, so the
    typography that broke URL claims does not also defeat removal.

    The trailing boundary rejects a following separator, which is what stops a
    shorter claim from being cut out of the middle of a longer one. That is not
    hypothetical: `HKLM\\...\\Microsoft\\Windows` is a prefix of
    `HKLM\\...\\Microsoft\\Windows\\CurrentVersion\\Run`, and the LONGER path is
    excluded from `unverified` by _CANONICAL_REGISTRY_TEMPLATE_RE -- so it is
    absent from the scrubber's work list while the shorter one still matches
    inside it, leaving a dangling `\\CurrentVersion\\Run` in the published report.

    A `.` that continues a longer indicator is rejected in both directions:
    `evil.com` must not be cut out of the verified `sub.evil.com` (lookbehind:
    preceded by a letter + dot), and `1.2.3.4` must not be cut out of
    `1.2.3.4.5` (lookahead: followed by a dot + digit). A sentence-final period
    passes both, because it is followed by space or end of line.

    A placeholder value name is the one legitimate way a separator may follow,
    because `...\\CurrentVersion\\Run\\<value_name>` names the same key the
    report was claiming. An ellipsis tail (`...\\Run\\...`, the report naming
    the key as a location class without a concrete value -- winservices
    2026-10-03: `HKCU\\...\\Run\\...` in "no specific registry key path
    appears in the evidence") is the same shape and is consumed too, so the
    strict boundary still applies to what comes after it.

    Segments containing a space are matched whole rather than truncated at it.
    That is not cosmetic: `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`
    is a real key, and an earlier version of this stopped at the space, so the
    claim was read as `...\\Microsoft\\Windows` and the scrubber then replaced
    that prefix and published the orphan tail ` NT\\CurrentVersion\\Winlogon`
    beside the marker. `remaining_unverified` stayed at 0, because the leftover
    is not itself a registry claim -- which is why the fragment check in
    `scrub_unverified_indicators` exists alongside it.
    """
    plain = _plain_claim(value)
    body_parts: list[str] = []
    for ch in plain:
        if ch == "\\":
            body_parts.append(r"\\{1,2}")
        elif ch == ".":
            body_parts.append(r"(?:\.|\[\.\]|\(\.\)|\[dot\])")
        elif ch == ":":
            body_parts.append(r"(?:\[:\]|:)")
        elif ch == "@":
            body_parts.append(r"(?:\[@\]|\[at\]|@)")
        else:
            body_parts.append(re.escape(ch))
    body = "".join(body_parts)
    # hxxp/hxxps is the same URL as http/https for claim purposes; the plain
    # body starts with `http`, so widen exactly that prefix.
    body = re.sub(r"^h(?:t{2}p)", r"h(?:ttp|x{2}p)", body)
    placeholder = r"(?:\\{1,2}(?:<[^>\n]*>|\.{3}|…))?"
    return re.compile(
        r"(?<![A-Za-z0-9_\\])(?<![A-Za-z]\.)" + body + placeholder
        + r"(?![A-Za-z0-9_\\-])(?!\.[A-Za-z0-9])(?!\[\.\][0-9])",
        re.IGNORECASE)


def scrub_unverified_indicators(
    markdown: str,
    evidence_text: str,
    *,
    provenance_commit: str | None = None,
) -> tuple[str, list[dict], dict]:
    """Legacy diagnostic transform; report publishers must not call this.

    Production publishing preserves unsupported claims and lets the quality
    gate fail; this utility remains only for historical/offline comparisons.

    Plan item #42. Two prompt-level attempts to stop the model naming canonical
    registry paths failed, so this does not try to out-prompt it: the report is
    made accurate after the fact. Every claim that `verify_claimed_iocs` calls
    unverified is replaced with a marker naming the kind of thing that was
    removed, and the removal is recorded so the audit can see it happened.

    What this is NOT: an exemption. Nothing is added to an exclusion list and no
    check is relaxed -- the text simply stops asserting values that no tool
    produced, so there is nothing left to fail. `remaining_unverified` re-verifies
    the result, so a scrub that silently fails to take effect is visible rather
    than assumed.

    Fenced blocks are preserved: claims are collected outside them, so a value
    appearing inside a code fence is an illustration and must survive.

    The third element always carries the same keys, including on the no-op paths,
    so a caller can read `indicators_removed` unconditionally rather than
    branching on whether anything was found.
    """
    if not markdown:
        return markdown, [], {
            "indicators_removed": 0, "indicators_removed_detail": [],
            "unverified_before": 0, "remaining_unverified": 0,
            "verified_after": 0, "orphan_fragments": [],
        }
    verification = verify_claimed_iocs(
        markdown, evidence_text, provenance_commit=provenance_commit)
    unverified = verification.get("unverified_items") or []
    if not unverified:
        return markdown, [], {
            "indicators_removed": 0, "indicators_removed_detail": [],
            "unverified_before": verification.get("unverified", 0),
            "remaining_unverified": verification.get("unverified", 0),
            "verified_after": verification.get("verified", 0),
            "orphan_fragments": [],
        }

    parts = _FENCE_BLOCK_SPLIT_RE.split(markdown)
    removed: list[dict] = []
    out: list[str] = []
    # Longest value first. Defensive rather than load-bearing: the strict
    # trailing boundary in _flex_claim_re is what actually prevents a prefix
    # from matching inside a longer path, since a longer path may be verified or
    # excluded and therefore absent from `unverified` entirely.
    ordered = sorted(unverified,
                     key=lambda it: len(str(it.get("value") or "")), reverse=True)
    for part in parts:
        if part.startswith("```"):
            out.append(part)
            continue
        for item in ordered:
            kind = str(item.get("type") or "value")
            value = str(item.get("value") or "")
            if not value:
                continue
            marker = _UNVERIFIED_MARKERS.get(kind, _UNVERIFIED_MARKERS["value"])
            part, n = _flex_claim_re(value).subn(marker, part)
            if n:
                removed.append({"type": kind, "value": value,
                                "occurrences": n, "replaced_with": marker})
        out.append(part)

    scrubbed = "".join(out)
    # A fragment is text left adjacent to a marker that continues the path it
    # replaced -- "NT\CurrentVersion\Winlogon" after
    # "...\Microsoft\Windows" was removed. It is NOT an unverified CLAIM, so
    # the count above cannot see it, and it ships as orphan prose naming a
    # registry location nothing observed. Remove it (the marker stays, the
    # leftover tail goes) and report what was cut; leaving it in the published
    # document while merely counting it was the 2026-10-03 review finding.
    fragments = [m.group(0) for m in _ORPHAN_FRAGMENT_RE.finditer(scrubbed)]
    if fragments:
        scrubbed = _ORPHAN_FRAGMENT_RE.sub(
            lambda m: m.group(0)[:m.group(0).index("]") + 1], scrubbed)
    after = verify_claimed_iocs(
        scrubbed, evidence_text, provenance_commit=provenance_commit)
    return scrubbed, removed, {
        "indicators_removed": len(removed),
        "indicators_removed_detail": removed[:40],
        "unverified_before": verification.get("unverified", 0),
        "remaining_unverified": after.get("unverified", 0),
        "verified_after": after.get("verified", 0),
        "orphan_fragments": fragments[:10],
    }


def scrub_report_indicators(
    case: Path, markdown: str, label: str,
) -> tuple[str, dict]:
    """Legacy diagnostic wrapper; do not use this to publish a report.

    Kept for offline comparisons of historic reports. Production publishers
    preserve generated claims and use evaluate_report_markdown to record
    unsupported values as quality failures.

    `case` is the mode-keyed case directory. The evidence files consulted are
    the same ones the audit uses later, and all of them are pre-report tool
    artifacts, so the decision is made against the same material the gate will
    judge.

    Never raises: a report that cannot be scrubbed is published unchanged and
    the audit still sees the unverified claims. Failing closed here would mean
    losing the report entirely, which is worse than losing one sentence.
    """
    try:
        evidence, evidence_files = collect_evidence_text(case)
    except Exception as exc:  # noqa: BLE001
        return markdown, {"label": label, "indicators_removed": 0,
                          "error": f"evidence unavailable: {type(exc).__name__}"}
    if not evidence_files:
        # An EMPTY corpus is the dangerous case, not an absent one.
        #
        # collect_evidence_text returns ("", []) with NO exception when the root
        # holds none of _EVIDENCE_FILES, so the `except` above never fires. Every
        # claim then fails its evidence match, every claim is "unverified", and
        # every claim gets deleted -- including the sample's own sha256 and its
        # C2 URLs -- with `remaining_unverified: 0` self-certifying the success.
        #
        # That is the e879318 failure (wrong evidence root) reproducing silently:
        # the report loses all its indicators and the audit never sees a removal
        # record. Refuse to scrub against nothing. Reproduced 2026-10-03 with an
        # empty root: 3 claims in, 2 indicators removed, 0 remaining, no error.
        return markdown, {
            "label": label,
            "indicators_removed": 0,
            "error": "empty evidence corpus - scrub skipped",
            "evidence_files": [],
            "remaining_unverified": None,
        }
    scrubbed, removed, meta = scrub_unverified_indicators(markdown, evidence)
    meta["label"] = label
    meta["evidence_files"] = evidence_files
    if removed:
        print(f"[report_quality] {label}: removed {meta['indicators_removed']} "
              f"unobserved indicator value(s); unverified "
              f"{meta['unverified_before']} -> {meta['remaining_unverified']}",
              flush=True)
    return scrubbed, meta


def _ioc_factcheck_issue(claims: dict) -> str | None:
    """Gate message for unverified claims, or None when clean.

    An unverified report claim is never promoted to green by a configuration
    switch: external context must be represented in the evidence pack and cited.
    """
    count = int(claims.get("unverified") or 0)
    return f"report:unverified_iocs:{count}" if count else None


def collect_evidence_text(root: Path, max_bytes: int = 40 * 1024 * 1024) -> tuple[str, list[str]]:
    """Concatenate a case's raw evidence for claim verification (bounded)."""
    chunks: list[str] = []
    used: list[str] = []
    total = 0
    for rel in _EVIDENCE_FILES:
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        remaining = max_bytes - total
        if remaining <= 0:
            break
        chunks.append(text[:remaining])
        used.append(rel)
        total += len(chunks[-1])
    # WinRE dynamic pack (optional companion): the corroboration block's network
    # intel and Frida-decoded paths are raw evidence, so a report citing them
    # must verify. Presence-gated: no pack -> byte-identical corpus (users
    # without WinRE keep the exact previous behavior).
    try:
        dyn_text, dyn_files = _dynamic_pack_evidence_text(root)
    except Exception:
        dyn_text, dyn_files = "", []
    if dyn_text:
        remaining = max_bytes - total
        if remaining > 0:
            chunks.append(dyn_text[:remaining])
            used.extend(dyn_files)
    return "\n".join(chunks), used


def _dynamic_pack_evidence_text(root: Path) -> tuple[str, list[str]]:
    """Evidence text contributed by the case's WinRE dynamic pack, if any.

    Values come from v2_lib's pack loader, so a report that cites the dynamic
    block verifies against the same numbers the block rendered.

    Gated on the SAME shared opt-out as the block itself
    (`v2_lib.dynamic_corroboration_enabled()`). Without it, a run with
    REVAI_DISABLE_DYNAMIC_CORROBORATION=1 still loads the pack into the
    grounding corpus: the report carries no dynamic block, so a reader cannot see
    where a value came from, while a claim that happens to coincide with a pack
    value is still certified "verified" against it. Grounding a published claim
    against a source the published report does not show is exactly what the
    "verified/unverified" distinction is for.
    """
    sha = root.name if re.fullmatch(r"[0-9a-fA-F]{64}", root.name or "") else root.parent.name
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""):
        return "", []
    from v2_lib import dynamic_corroboration_enabled
    if not dynamic_corroboration_enabled():
        return "", []
    winre_root = Path(os.environ.get("REVAI_WINRE_LOGS") or "/opt/winre/logs")
    if not winre_root.is_dir():
        return "", []
    from v2_lib import load_dynamic_pack

    expected_run_id = None
    try:
        context = json.loads((root / "execution-context.json").read_text(
            encoding="utf-8"))
        if isinstance(context, dict):
            expected_run_id = str(context.get("run_id") or "") or None
    except (OSError, json.JSONDecodeError):
        pass
    pack = load_dynamic_pack(
        sha, winre_root=winre_root, expected_run_id=expected_run_id)
    if not pack or not pack.get("present"):
        return "", []
    ni = pack.get("network_intel") or {}
    caps = ((ni.get("captures") or [{}])[0] if isinstance(ni, dict) else {}) or {}
    src = pack.get("source") or "pack"
    values: list[str] = [f"winre dynamic pack source={src}"]
    for label in ("META.json", "META.job.json"):
        payload = pack.get("meta" if label == "META.json" else "job_meta") or {}
        if isinstance(payload, dict) and payload:
            values.append(f"{label}: {json.dumps(payload, sort_keys=True, default=str)}")
    values.append("META.json fields: producer/source, ok, error, schema_version, "
                  "verdict_policy.static_yara_wins")
    values.append("META.job.json fields: detonation_ran, sample_pid, window.requested_s, "
                  "window.effective_s, window.adaptive, window.stop_reason")

    # Preserve the exact source rows for sample-PID Procmon citations before
    # other dynamic evidence, so a large IOC list cannot push them past the
    # audit corpus limit.
    for event in pack.get("procmon_sample_events") or []:
        if not isinstance(event, dict):
            continue
        values.append(
            f"Procmon data row {event.get('row')}; PID {event.get('pid')}; "
            f"operation {event.get('operation')}; process {event.get('process')}; "
            f"time {event.get('time')}; path {event.get('path')}; "
            f"result {event.get('result')}; detail {event.get('detail')}"
        )
    for file_record in pack.get("procmon_created_written_files") or []:
        if not isinstance(file_record, dict):
            continue
        for operation in ("create", "write"):
            event = file_record.get(operation) or {}
            if not isinstance(event, dict):
                continue
            values.append(
                f"Procmon data row {event.get('row')}; PID {event.get('pid')}; "
                f"operation {event.get('operation') or operation}; "
                f"path {event.get('path')}; "
                f"result {event.get('result')}; detail {event.get('detail')}"
            )
    for event in pack.get("procmon_instrumentation_exclusions") or []:
        if not isinstance(event, dict):
            continue
        values.append(
            f"Procmon data row {event.get('row')}; PID {event.get('pid')}; "
            f"operation {event.get('operation')}; path {event.get('path')}; "
            f"result {event.get('result')}; Frida instrumentation exclusion "
            f"count={event.get('count')}"
        )
    for key in ("dns_queries", "tls_sni", "http_requests"):
        cap = 20 if key == "dns_queries" else 12
        entries = (caps.get(key) or [])[:cap]
        if entries:
            values.append(f"captures[0].{key}: " + ", ".join(str(x) for x in entries))
    network = pack.get("network") or {}
    if isinstance(network, dict) and network.get("domains_guess"):
        values.append("network.json domains_guess: " + ", ".join(
            str(x) for x in network["domains_guess"][:20]
        ))
    frida = pack.get("frida_summary") or {}
    for p in (frida.get("decoded_paths") or []) if isinstance(frida, dict) else []:
        values.append(f"frida_summary.json decoded_paths entry: {p}")
    if isinstance(frida, dict) and frida.get("events") is not None:
        values.append(f"frida_summary.json events={frida.get('events')}")
    if isinstance(frida, dict):
        scalar_fields = [key for key, value in frida.items()
                         if isinstance(value, (int, float, str) )][:6]
        if scalar_fields:
            values.append("frida_summary.json fields: " + ", ".join(scalar_fields))
        for key, value in frida.items():
            if isinstance(value, list) and value and "api" in key.lower():
                values.append(f"frida_summary.json {key}: " + json.dumps(value[:8], default=str))
    trace = pack.get("frida_trace") or {}
    if isinstance(trace, dict):
        values.append(
            "frida_trace provenance: " + json.dumps({key: trace.get(key) for key in (
                "status", "sample_sha256", "run_id", "artifact_sha256",
                "manifest_sha256", "record_count", "attributed_record_count",
                "attributed_call_count", "endpoint_count",
                "process_coverage_complete", "attributed_pids",
                "attribution_status", "reason",
            )}, sort_keys=True, default=str)
        )
        if trace.get("status") == "valid":
            for invocation in trace.get("invocations") or []:
                if not isinstance(invocation, dict):
                    continue
                index = invocation.get("index")
                values.append(
                    f"frida_trace.invocations[{index}]: "
                    + json.dumps(invocation, ensure_ascii=False,
                                 sort_keys=True, default=str)
                )
            for collection in ("endpoints", "process_events"):
                for index, item in enumerate(trace.get(collection) or []):
                    if isinstance(item, dict):
                        values.append(
                            f"frida_trace.{collection}[{index}]: "
                            + json.dumps(item, ensure_ascii=False,
                                         sort_keys=True, default=str)
                        )
            for index, item in enumerate(trace.get("raw_rows") or []):
                if (not isinstance(item, dict)
                        or item.get("sample_attributed") is not True):
                    continue
                values.append(
                    f"frida_trace.raw_rows[{index}]: "
                    + json.dumps(item, ensure_ascii=False,
                                 sort_keys=True, default=str)
                )
    capture = pack.get("external_capture") or {}
    if isinstance(capture, dict) and capture:
        values.append("external_capture.json fields: status, packets_captured, elapsed_s, pcap_sha256")
        values.append("external_capture.json " + "; ".join(
            f"{key}={capture.get(key)}" for key in (
                "status", "packets_captured", "elapsed_s", "pcap_sha256"
            ) if capture.get(key) is not None
        ))
    art = pack.get("unpack_artifact") or {}
    if isinstance(art, dict) and art.get("name"):
        values.append(f"unpacked artifact analysis: {art['name']}")
        values.append("agentic-dbg artifact metadata: " + "; ".join(
            f"{key}={art.get(key)}" for key in (
                "dump_kind", "dump_source", "rebuild_hint", "bytes"
            ) if art.get(key) is not None
        ))
    return "\n".join(values), [
        f"winre:{src}:META.json",
        f"winre:{src}:META.job.json",
        f"winre:{src}:network_intel.json",
        f"winre:{src}:frida_summary.json",
        f"winre:{src}:frida_trace.jsonl",
        f"winre:{src}:procmon.csv",
    ]


# --- behavior prerequisites vs import surface (plan #14d; advisory) --------

#: Conservative behaviour -> required import surface. Only rules whose import
#: requirement is essentially definitional are listed: a behaviour reached
#: through an unlisted API would otherwise be reported as unsupported, which is
#: exactly the false negative this check exists to avoid. Keep this list short
#: and high-precision; anything ambiguous belongs in review, not here.
_BEHAVIOR_IMPORT_RULES = (
    (
        "process injection",
        ("process injection", "code injection", "dll injection", "process hollowing",
         "reflective load", "thread injection", "process doppelganging"),
        ("createremotethread", "ntcreatethreadex", "writeprocessmemory",
         "ntwritevirtualmemory", "queueuserapc", "setthreadcontext",
         "wow64setthreadcontext", "mapviewofsection", "ntmapviewofsection",
         "virtualallocex", "ntallocatevirtualmemory", "rtlmovememory"),
    ),
    (
        "persistence",
        ("persistence", "autostart", "run key", "registry run", "startup folder",
         "create a service", "installs itself"),
        ("regsetvalueex", "regsetvalue", "regcreatekeyex", "regcreatekey",
         "createservice", "openscmanager", "changeserviceconfig", "schtasks"),
    ),
    (
        "credential access",
        ("credential", "credential dumping", "stolen credentials", "browser password",
         "password stealer", "harvest passwords"),
        ("credread", "credenumerate", "cryptunprotectdata", "lsaopenpolicy",
         "samconnect", "minidumpwritedump", "ntquerysysteminformation"),
    ),
)


def _harvest_import_surface(node, out: set[str]) -> None:
    """Collect API-ish strings from import-bearing structures anywhere in the JSON."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("api_match", "function", "name", "api") and isinstance(value, str):
                out.add(value.lower())
            elif key in ("imports", "imported_functions", "signals", "functions",
                         "top_rules", "dlls"):
                _harvest_import_surface(value, out)
            elif isinstance(value, (dict, list)):
                _harvest_import_surface(value, out)
    elif isinstance(node, list):
        for item in node:
            _harvest_import_surface(item, out)


# A plausible Win32 API identifier. The JSON harvest above also returns capa
# finding titles ("encrypt data using rc4 prga"), section names (".text") and
# Ghidra function names, which made the surface useless: the #14d calibration on
# 2026-09-27 found 0/27 behaviour APIs "present" in a real Win32 GUI sample purely
# because the surface was noise. Only identifier-shaped tokens count now, and the
# rejected count is recorded so the filter is auditable rather than silent.
_API_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{2,}$")
_REJECT_SAMPLE = (" ", ".", "/", "\\", "-")


def _accept_api_name(name: str) -> str:
    """Return the usable API name from a harvested token, or "" to reject it."""
    token = (name or "").strip().lower()
    if not token:
        return ""
    # module-qualified forms (gdi32.OFT) contribute the function part
    if "." in token:
        tail = token.rsplit(".", 1)[-1]
        token = tail if _API_NAME_RE.match(tail) else ""
    if not token or not _API_NAME_RE.match(token):
        return ""
    if any(ch in token for ch in _REJECT_SAMPLE):
        return ""
    return token


def _load_high_signal_map(root: Path) -> tuple[set[str], list[str], dict]:
    """Read the deterministic ``pe_imports`` high-signal map.

    Important property, established by the #14d calibration (2026-09-27): this
    artifact is a *curated* map of security-relevant imports (``{"engine":
    "pe_imports", "signal_count": n, "signals": [{"api_match": ...}]}``), NOT the
    full import table. Nothing in the evidence pack holds the full table, so the
    absence of an API here is not evidence of absence - which is why the check
    reports contradictions (provable) and keeps bare absence advisory.
    """
    names: set[str] = set()
    used: list[str] = []
    meta: dict = {"kind": "none", "signal_count": None}
    # quick_scan/pe-imports.json is the canonical artifact (#28, 2026-10-03):
    # quick_scan writes the tool's own map there, so the authoritative source
    # no longer has to be dug out of 00-tools-raw.json. The .txt spellings
    # predate it and stay for older cases.
    for rel in ("quick_scan/pe-imports.json", "pe-imports.txt",
                "quick_scan/pe-imports.txt", "deep_dive/pe-imports.txt"):
        path = root / rel
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        data: object = None
        try:
            data = json.loads(raw)
        except Exception:
            data = None
        before = len(names)
        if isinstance(data, dict):
            meta = {"kind": "pe_imports_high_signal_map",
                    "signal_count": data.get("signal_count")}
            signals = data.get("signals") or []
            for sig in signals:
                if isinstance(sig, dict):
                    for key in ("api_match", "api", "name", "function"):
                        token = _accept_api_name(str(sig.get(key) or ""))
                        if token:
                            names.add(token)
                else:
                    token = _accept_api_name(str(sig))
                    if token:
                        names.add(token)
        elif isinstance(data, list):
            meta = {"kind": "pe_imports_high_signal_map", "signal_count": len(data)}
            for sig in data:
                if isinstance(sig, dict):
                    token = _accept_api_name(
                        str(sig.get("api_match") or sig.get("api") or sig.get("name") or ""))
                else:
                    token = _accept_api_name(str(sig))
                if token:
                    names.add(token)
        else:
            # Plain-text dump: one API per line.
            for line in raw.splitlines():
                token = _accept_api_name(line)
                if token:
                    names.add(token)
        if len(names) > before:
            used.append(rel)
        break
    return names, used, meta


def collect_import_surface(root: Path) -> tuple[str, list[str]]:
    """Build the import surface used by the behaviour cross-check.

    Authority order: the deterministic ``pe_imports`` high-signal map, then
    structured import evidence from the tool JSONs, then - only if both are empty
    - the broader evidence text, which is a weaker source and is labelled as such.
    """
    names, used, _meta = _load_high_signal_map(root)
    if names:
        return "\n".join(sorted(names)), used
    structured: set[str] = set()
    for rel in ("quick_scan/00-tools-raw.json", "deep_dive/01-tools-raw.json",
                "deep_dive/02-signals.json"):
        path = root / rel
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        raw: set[str] = set()
        _harvest_import_surface(data, raw)
        before = len(structured)
        for token in raw:
            clean = _accept_api_name(token)
            if clean:
                structured.add(clean)
        if len(structured) > before:
            used.append(rel)
    if structured:
        return "\n".join(sorted(structured)), used
    text, evidence_used = collect_evidence_text(root)
    return text.lower(), [f"{u} (evidence-text fallback)" for u in evidence_used]


def _is_packed(root: Path) -> bool:
    for rel in ("packer.txt", "quick_scan/packer.txt"):
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except Exception:
            continue
        if "packed" in text and "not packed" not in text:
            return True
        if "suspicious" in text or "high entropy" in text:
            return True
    return False


# A behaviour phrase only counts as a *claim* when the sentence asserting it is
# not negated and not a legend/catalogue mention. Calibration 2026-09-27: on the
# ghyte report, 6/6 flags were false positives - the report said "no registry or
# service imports", "not a persistence or exfil timer", "There is no mapping for
# ... persistence (T1547)" and a Maldev catalogue note. A report that correctly
# denies a behaviour was being recorded as claiming it.
_NEGATION_MARKERS = (
    "no ", "not ", "no.", "none", "never", "absent", "unsupported",
    "does not", "doesn't", "isn't", "cannot", "can't", "lacks", "lack of",
    "neither", "nor ", "unconfirmed", "no evidence", "not observed",
    "not recovered", "not reconstructed", "not supported",
)
# Hypothetical projection ("in a real-world scenario without analysis tools, it
# would likely ... establish persistence") affirms the behaviour; the negation in
# it modifies the *situation*, not the behaviour. Classifying that as a denial was
# the last of the three false-positive classes found in the 2026-09-27
# calibration, so the check stays advisory.
_AFFIRMATION_MARKERS = (
    "would likely", "would proceed", "would then", "in a real-world scenario",
    "it would", "would attempt", "likely establish", "expected to",
)
_CATALOGUE_MARKERS = (
    "catalog", "catalogue", "cheat sheet", "timeline_events", "capability map",
    "capability table", "no mapping for", "tactic list",
)
# A denial that is about *specificity or observation*, not about the behaviour's
# existence. Calibration 2026-09-27: every remaining candidate contradiction on the
# published corpus was one of these ("no specific registry keys ... were
# identified", "no persistence actions were observed" - in a report that claims
# persistence from static evidence). Counting them as denials of the behaviour
# produced 11 false flags across 56 human-reviewed case studies.
_DETAIL_QUALIFIERS = (
    "specific", "exact", "precise", "detail", "which key", "what key", "key path",
    "at runtime", "were observed", "was observed", "observed", "identified",
    "extracted", "recovered", "reconstructed", "injected into", "of the",
)


def _classify_sentence(sentence: str) -> str:
    """claim | negated | detail | catalogue - what a matched phrase is doing here.

    ``negated`` is only used when the sentence denies the behaviour's *existence*;
    a denial carrying a specificity/observation qualifier is ``detail`` and never
    counts as a contradiction.
    """
    low = sentence.lower()
    if any(marker in low for marker in _CATALOGUE_MARKERS):
        return "catalogue"
    if any(marker in low for marker in _AFFIRMATION_MARKERS):
        return "claim"
    if any(marker in low for marker in _NEGATION_MARKERS):
        if any(qualifier in low for qualifier in _DETAIL_QUALIFIERS):
            return "detail"
        return "negated"
    return "claim"


def _sentences(markdown: str) -> list[str]:
    """Line- and sentence-split, so a negation binds to the phrase it denies."""
    out: list[str] = []
    for line in (markdown or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Keep the table-row and bullet context: split on sentence enders only.
        parts = re.split(r"(?<=[.!?])\s+", line)
        for part in parts:
            part = part.strip()
            if part:
                out.append(part)
    return out


def verify_behavior_prerequisites(markdown: str, import_surface: str,
                                  packed: bool = False) -> dict:
    """Cross-check the report's behaviour statements against the PE import map.

    ADVISORY, and deliberately so. Promotion to a blocking gate was evaluated on
    2026-09-27 (plan #14d) against the 56-case published corpus and **rejected on
    the evidence**; the numbers are in `internal/IMPROVEMENT-PLAN.md` (#14d):

    1. The original form (phrase present + no API in the surface) produced 54 flags
       across 117 behaviour entries - **all false positives**. Absence from the
       ``pe_imports`` high-signal map proves nothing: that artifact is a curated
       subset of security-relevant imports, not the full import table, and no
       evidence-pack artifact holds the full table.
    2. A contradiction form (report *denies* a behaviour the map *shows*) cut that
       to 11 (9.4%), but reading all 11 showed every one was a denial of
       *specificity or dynamic observation* ("no **specific** registry keys were
       identified", "no persistence actions **were observed**") inside reports that
       claim the behaviour from static evidence. Phrase-level polarity cannot
       separate "X was not observed at runtime" from "X does not exist", so a gate
       here would have produced 11 false reds on human-reviewed case studies.

    What is reported, all measured and none of it gate-failing:
    ``contradictions``   denials of existence whose defining API *is* in the map
    ``uncorroborated``   claims with no defining API (advisory: absence is not proof)
    ``negated_mentions`` corroborated absences - the report denying a behaviour
    ``detail_mentions``  denials of specificity/observation, not of the behaviour
    ``catalogue_mentions`` legend/catalogue vocabulary
    """
    surface = (import_surface or "").lower()
    sentences = _sentences(markdown)
    checked: list[dict] = []
    contradictions: list[dict] = []
    uncorroborated: list[dict] = []
    negated_total = 0
    catalogue_total = 0
    detail_total = 0

    for behavior, phrases, required in _BEHAVIOR_IMPORT_RULES:
        matched: list[str] = []
        negated: list[str] = []
        catalogue: list[str] = []
        detail: list[str] = []
        for sentence in sentences:
            low = sentence.lower()
            hits = [p for p in phrases if p in low]
            if not hits:
                continue
            kind = _classify_sentence(sentence)
            if kind == "negated":
                negated.extend(hits)
            elif kind == "catalogue":
                catalogue.extend(hits)
            elif kind == "detail":
                detail.extend(hits)
            else:
                matched.extend(hits)
        if not (matched or negated or catalogue or detail):
            continue
        present = [api for api in required if api in surface]
        entry = {
            "behavior": behavior,
            "matched_phrases": list(dict.fromkeys(matched)),
            "negated_phrases": list(dict.fromkeys(negated)),
            "catalogue_phrases": list(dict.fromkeys(catalogue)),
            "detail_phrases": list(dict.fromkeys(detail)),
            "required_any": list(required),
            "present": present,
        }
        checked.append(entry)
        negated_total += len(entry["negated_phrases"])
        catalogue_total += len(entry["catalogue_phrases"])
        detail_total += len(entry["detail_phrases"])
        if present and entry["negated_phrases"]:
            contradictions.append(entry)
        elif entry["matched_phrases"] and not present:
            uncorroborated.append(entry)

    return {
        "advisory": True,
        "promotion": "rejected 2026-09-27 on the 56-case corpus; see docstring",
        "checked": len(checked),
        "unsupported": len(contradictions),
        "unsupported_items": contradictions,
        "contradictions": contradictions,
        "uncorroborated": len(uncorroborated),
        "uncorroborated_items": uncorroborated,
        "negated_mentions": negated_total,
        "catalogue_mentions": catalogue_total,
        "detail_mentions": detail_total,
        "packed": bool(packed),
        "analysis_incomplete": bool(packed and uncorroborated),
        "method": ("report sentences matching a behaviour phrase are classified as "
                   "claim / negated / detail / catalogue mention. A contradiction is a "
                   "denial of the behaviour's existence whose defining API is in the "
                   "deterministic pe_imports high-signal map. An unnegated claim with "
                   "no defining API is uncorroborated, never a gate: that map is a "
                   "curated subset, not the full import table. Packed samples report "
                   "'analysis incomplete'."),
    }


OUTPUT_FORMAT_CONTRACT = """
## OUTPUT FORMAT CONTRACT (mandatory — ASCII only)
Call the supplied `submit_report` function exactly once. Put the complete report
in its `markdown` field and, optionally, the document title in `title`. Do not
put the report in message text or return a JSON envelope in Markdown.

Markdown rules:
1. Use EXACT level-2 headings with ASCII apostrophe only: ## 11. What We Don't Know
   FORBIDDEN: curly apostrophe ('), smart quotes, em-dashes in headings.
2. Every required heading from the checklist MUST appear as `## <exact title>`.
3. Each non-appendix section MUST contain real analysis (≥180 chars), NOT "see appendix".
4. Copy evidence tables into the matching section. Cite (source: <engine>).
5. Do not invent runtime behavior. Empty Speakeasy/Frida → "not observed".
""".strip()
