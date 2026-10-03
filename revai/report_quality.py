#!/usr/bin/env python3
"""report_quality.py — hard quality gates for publish / section / orchestrator.

GREEN means: LLM-authored analyst narrative, all required headings present,
no stub-only sections, no deterministic_fallback* sources.

rc==0 alone is NEVER sufficient.
"""
from __future__ import annotations

import json
import math
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
        # Citation marker: the system prompt instructs "{source: engine}" but
        # some models emit "(source: engine)". Count BOTH (the provider
        # finding 2026-08-08 — curly-brace citations were uncounted and a
        # fully-cited report failed low_citations).
        style["citation_count"] = (style_md or "").lower().count("(source:") + (
            style_md or ""
        ).lower().count("{source:")
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


_DYN_NEGATION_RE = re.compile(
    r"(?:no dynamic analysis.{0,60}?(?:was|were).{0,15}?(?:performed|conducted|run))"
    r"|(?:dynamic analysis (?:was|were)\s+not (?:performed|conducted|run))"
    r"|(?:dynamic analysis was not performed)",
    re.IGNORECASE,
)

_TECH_DYN_EVIDENCE_RE = re.compile(
    r"speakeasy_ok:\s*True|emulation completed|hook candidates"
    r"|identified the following hook",
    re.IGNORECASE,
)

_VERDICT_PANEL_RE = re.compile(
    r"\|\s*\*\*Final\*\*\s*\|\s*\*+([^*|]+?)\*+\s*\|",
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
    """Cut a report at the first appendix/evidence-dump marker.

    Style and fact checks run on the narrative only; appendices are verbatim
    tool evidence and are not judged as report prose.
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
    return (m.group(1) or "").strip().lower() if m else ""


def _cross_report_consistency(
    master_md: str,
    tech2_md: str,
    tech3_md: str,
    file_entropy: float | None,
) -> dict[str, Any]:
    """Deterministic cross-report + fact-vs-file consistency checks.

    Gate-failing violations (night-run #2 publication defects, 2026-08-12):
    - master claims no dynamic analysis ran while the technical report carries
      real Speakeasy/Frida execution evidence;
    - master and technical verdict panels state different final verdicts;
    - entropy citations contradict the file's measured whole-file entropy.
    """
    violations: list[str] = []
    master_neg = bool(_DYN_NEGATION_RE.search(master_md or ""))
    tech_dyn_ev = bool(_TECH_DYN_EVIDENCE_RE.search((tech2_md or "") + "\n" + (tech3_md or "")))
    checks = {
        "master_dyn_negation": master_neg,
        "tech_dyn_evidence": tech_dyn_ev,
        "file_entropy": file_entropy,
    }
    if master_neg and tech_dyn_ev:
        violations.append(
            "cross_report:master_claims_no_dynamic_analysis_but_technical_has_dynamic_findings"
        )
    mv = _panel_final_verdict(master_md)
    tv = _panel_final_verdict(tech2_md) or _panel_final_verdict(tech3_md)
    checks["master_verdict"] = mv
    checks["tech_verdict"] = tv
    if mv and tv and mv != tv:
        violations.append(
            f"cross_report:master_tech_verdict_mismatch(master={mv}, technical={tv})"
        )
    if file_entropy is not None:
        for md, label in (
            (master_md, "master"),
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

    # Cross-report consistency + factual-number sanity (2026-08-12, #2 night-run
    # publication gate): structural green is not enough — catch master-vs-tech
    # contradictions and claims that contradict the file's measured entropy.
    _entropy = _file_shannon_entropy(_sample_path_for(root, sha))
    consistency = _cross_report_consistency(master_md, tech2_md, tech3_md, _entropy)
    checks["cross_report_consistency"] = consistency
    for _viol in consistency.get("violations") or []:
        issues.append(_viol)

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

    # Plan #10, advisory phase: re-verify report-claimed indicators against the
    # raw evidence by code (never by LLM self-review). Recorded in checks and the
    # advisory block; deliberately NOT folded into `issues` until calibrated
    # against the published corpus shows an acceptable false-positive rate.
    try:
        _evidence_text, _evidence_files = collect_evidence_text(root)
        _report_for_claims = tech3_md or tech2_md or master_md
        _claims = verify_claimed_iocs(_report_for_claims, _evidence_text)
        _claims["evidence_files"] = _evidence_files
        checks["claimed_ioc_verification"] = _claims
        _ioc_issue = _ioc_factcheck_issue(_claims)
        if _ioc_issue:
            issues.append(_ioc_issue)
    except Exception as exc:  # advisory must never break the gate
        checks["claimed_ioc_verification"] = {"advisory": True, "error": str(exc)}

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
            "claimed_ioc_verification": checks.get("claimed_ioc_verification", {}),
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


# --- claimed-IOC fact verification (plan #10; advisory until calibrated) ---

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
#: location the report tells the analyst to inspect or clean, not an indicator
#: the report claims the sample produced. Both survivors on the real audits were
#: exactly this:
#:
#:   winservices  "**Registry:** Monitor `RegSetValueExA` ... on
#:                 `HKLM\...\FirewallPolicy` and the `Run` key"
#:   win32k_dll   "2. Remove registry persistence entries:
#:                 - HKLM\Software\Microsoft\Windows NT\...\UserList"
#:
#: Same speech act as the canonical persistence template already exempted above
#: ("a verification target, not an observed artifact"). Counted and reported
#: under `guidance_references`, never silently dropped.
_GUIDANCE_VERB_RE = re.compile(
    r"(?i)\b(?:monitor|watch|remove|delete|clean|inspect|scan|check|audit|"
    r"remediate|remediation|verify|look\s+for|hunt|clear|close)\b")

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
    r"(?:\\[^\s\"'<>|)\n]{2,}(?:\s+[A-Z][^\s\"'<>|)\n]*(?=\s*\\))*)+")

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
    # The trailing subkey is the informative one. Skip the elision segment
    # itself: it names no real location, so it can never be matched.
    concrete_tail = [s for s in subkeys if s not in (".", "..", "…", "...")]
    if not concrete_tail:
        return None
    tail = concrete_tail[-1]

    text = evidence or ""
    best: tuple[str, list[str]] | None = None
    for m in _EVIDENCE_REGKEY_RE.finditer(text):
        candidate = m.group(0)
        cparsed = _regkey_parts(candidate)
        if not cparsed:
            continue
        chive, csubkeys = cparsed
        if chive != hive or not csubkeys:
            continue
        if tail in csubkeys:
            # Exact tail match ranks first regardless of depth; among equal
            # ranks, the deepest path is the most specific corroboration.
            rank = (0 if csubkeys[-1] == tail else 1, len(csubkeys))
            if best is None or rank > best[0]:
                best = (rank, candidate, csubkeys)
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
    return all(
        bool(_GUIDANCE_VERB_RE.search(
            _claim_context_window(text, start, end)))
        for start, end in span_list)


def _claims_text(markdown: str) -> str:
    """Report text with fenced code blocks removed (claims live outside them)."""
    return _FENCED_CODE_RE.sub("\n", markdown or "")


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

#: Evidence files worth searching, most specific first. Anything absent is
#: skipped, so a scripted run without a dynamic pack still verifies statically.
_EVIDENCE_FILES = (
    "deep_dive/05-deep-dive.json",
    "deep_dive/01-tools-raw.json",
    "deep_dive/02-signals.json",
    "deep_dive/agentic_deep_dive.json",
    "quick_scan/00-tools-raw.json",
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


def verify_claimed_iocs(markdown: str, evidence_text: str, *,
                        provenance_commit: str | None = None) -> dict:
    """Check every indicator a report claims against the raw tool evidence.

    Deterministic and code-based: no LLM re-reading of the report. A claim is
    *verified* when its plain (re-fanged) value appears in the concatenated raw
    evidence, *unverified* otherwise. Unverified is not automatically wrong - an
    analyst may cite knowledge outside the evidence pack - which is why this is
    recorded as advisory rather than folded into the gate until calibrated.

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
    # Commits cited in the report's own provenance banner are build metadata as
    # well: a report generated by an earlier deploy keeps its commit hash after
    # a redeploy, and flagging it as an unverified sha256 is noise.
    banner_commits = {m.group(1).lower()
                      for m in _PROVENANCE_BANNER_RE.finditer(markdown or "")}
    evidence = (evidence_text or "").lower()
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
    """Neutralise indicator values in prose that no tool observed.

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
    """Scrub one report against its own case's evidence, and record the result.

    Every published report goes through this, not just the one the audit reads
    (`claimed_ioc_verification` checks `tech3 or tech2 or master`, so a fix
    applied to a single report would leave the other three asserting values no
    tool produced -- and on the 2026-10-02 win32k_dll run the unverified claims
    were spread across master-v2, master-v3 and technical-v3).

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
    """Gate message for unverified claims, or None when clean/advisory.

    Promoted 2026-09-16 (plan #10). ``REVAI_IOC_FACTCHECK=advisory`` records the
    result without failing, for a run whose report legitimately cites sources
    outside the evidence pack.
    """
    if os.environ.get("REVAI_IOC_FACTCHECK", "enforce").strip().lower() == "advisory":
        return None
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
    """
    sha = root.name if re.fullmatch(r"[0-9a-fA-F]{64}", root.name or "") else root.parent.name
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""):
        return "", []
    winre_root = Path(os.environ.get("REVAI_WINRE_LOGS") or "/opt/winre/logs")
    if not winre_root.is_dir():
        return "", []
    from v2_lib import load_dynamic_pack

    pack = load_dynamic_pack(sha, winre_root=winre_root)
    if not pack or not pack.get("present"):
        return "", []
    ni = pack.get("network_intel") or {}
    caps = ((ni.get("captures") or [{}])[0] if isinstance(ni, dict) else {}) or {}
    values: list[str] = []
    for key in ("dns_queries", "tls_sni", "http_requests"):
        values.extend(str(x) for x in (caps.get(key) or []))
    for p in (pack.get("frida_summary") or {}).get("decoded_paths") or []:
        values.append(str(p))
    art = pack.get("unpack_artifact") or {}
    if isinstance(art, dict) and art.get("name"):
        values.append(str(art["name"]))
    src = pack.get("source") or "pack"
    return "\n".join(values), [f"winre:{src}:network_intel.json",
                               f"winre:{src}:frida_summary.json"]


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
