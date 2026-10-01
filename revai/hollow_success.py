"""Hollow-success detection: catch artifacts that are empty of real content.

Five defects on 2026-09-28..10-01 exited `rc=0` while producing worthless or
wrong output (see internal/IMPROVEMENT-PLAN.md #30-#33):

  * a Ghidra lock storm produced no function context at all
  * a `timeout` argument swallowed by a shim made every context query fail open,
    so recovery "recovered" 110 functions named `unknown_*` at confidence 0.1
    with empty pseudocode
  * an un-indexed range join cost 200 s per function and returned nothing
  * the hollow-response checker rejected a VALID answer, so llm_judge failed on
    a good reply
  * the verdict lock corrected the structured verdict while the report's markdown
    panel kept the model's own label

Not one of them was visible from a return code or an error count. Every one was
found by measuring the artifact. So the pipeline needs the same measurement as a
gate.

Deliberately deterministic and artifact-based: no LLM call, no new dependency,
no network. A hollow-success check that needed a model would be able to be wrong
in exactly the same way, and would cost a call per run to tell us whether the
calls worked.

Each check returns a list of Finding; an empty list means the artifact carried
real content. Thresholds are deliberately loose -- the goal is to catch "this is
obviously empty", not to grade quality.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: A confidence at or below this is the default an LLM path emits when it fails
#: to produce a real judgment (analyze_function seeds result["confidence"]=0.0
#: and the parse path floors it at 0.1).
CONFIDENCE_FLOOR = 0.1

#: Fraction of LLM-named results that may be `unknown_*` before the artifact is
#: treated as hollow. A genuinely obfuscated sample can defeat naming, but not
#: almost all of it, when the calls are succeeding.
MAX_UNKNOWN_NAME_RATIO = 0.90

#: Fraction of results allowed to carry no pseudocode.
MAX_EMPTY_PSEUDOCODE_RATIO = 0.50

#: A result set smaller than this is not judged on ratios -- a sample with three
#: functions should not be failed for having three placeholders.
MIN_RESULTS_FOR_RATIO_CHECK = 10

#: Verdict sources that mean "no real judgment was made".
FALLBACK_SOURCES = frozenset({
    "fallback_v1", "deterministic_fallback", "fallback", "heuristic_v1",
    "llm_incomplete", "deterministic_fallback_after_incomplete_llm",
})

_DEGENERATE_TOKEN = re.compile(r"\S+")
_TICKER_RE = re.compile(r"\|\s*\*\*Final\*\*\s*\|\s*\*+([^*|]+?)\*+\s*\|",
                         re.IGNORECASE)


@dataclass
class Finding:
    """One hollow-success observation. `check` is a stable machine key."""
    check: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"check": self.check, "detail": self.detail,
                "evidence": self.evidence}


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return None


# --------------------------------------------------------------- function recovery

def check_function_recovery(data: dict | None) -> list[Finding]:
    """Recovery that "succeeded" while naming nothing.

    This is the exact shape of defect #31: 110 results, 0 errors, every name
    `unknown_*`, every confidence at the floor, every pseudocode empty.
    """
    if not data:
        return []
    results = data.get("function_results") or data.get("results") or []
    llm = [r for r in results
           if isinstance(r, dict) and r.get("source") == "llm_judge"]
    if len(llm) < MIN_RESULTS_FOR_RATIO_CHECK:
        return []

    findings: list[Finding] = []
    n = len(llm)

    unknown = [r for r in llm
               if str(r.get("function_name") or "").startswith("unknown_")]
    if len(unknown) / n > MAX_UNKNOWN_NAME_RATIO:
        findings.append(Finding(
            check="recovery.unknown_names",
            detail=(f"{len(unknown)}/{n} LLM-named functions are "
                    f"'unknown_*' (>{MAX_UNKNOWN_NAME_RATIO:.0%}): the naming "
                    f"calls are not producing names"),
            evidence={"results": n, "unknown": len(unknown),
                      "ratio": round(len(unknown) / n, 3)}))

    empty = [r for r in llm
             if not (r.get("normalized_pseudocode") or "").strip()]
    if len(empty) / n > MAX_EMPTY_PSEUDOCODE_RATIO:
        findings.append(Finding(
            check="recovery.empty_pseudocode",
            detail=(f"{len(empty)}/{n} named functions have empty pseudocode "
                    f"(>{MAX_EMPTY_PSEUDOCODE_RATIO:.0%}): the Ghidra context "
                    f"step is returning nothing"),
            evidence={"results": n, "empty": len(empty),
                      "ratio": round(len(empty) / n, 3)}))

    floored = [r for r in llm
               if float(r.get("confidence") or 0) <= CONFIDENCE_FLOOR]
    if len(floored) / n > MAX_UNKNOWN_NAME_RATIO:
        findings.append(Finding(
            check="recovery.confidence_floor",
            detail=(f"{len(floored)}/{n} results sit at the confidence floor "
                    f"(<={CONFIDENCE_FLOOR}): the calls failed and were parsed "
                    f"as defaults"),
            evidence={"results": n, "floored": len(floored)}))

    names = Counter(str(r.get("function_name") or "") for r in llm)
    if names:
        top, count = names.most_common(1)[0]
        if count / n > 0.5 and top:
            findings.append(Finding(
                check="recovery.degenerate_names",
                detail=(f"{count}/{n} results share one name ({top!r}): the "
                        f"naming calls are degenerate, not diverse"),
                evidence={"name": top, "count": count, "results": n}))

    return findings


# ------------------------------------------------------------------ verdict path

def check_verdict_sources(verdict: dict | None, deep: dict | None,
                          report: dict | None = None) -> list[Finding]:
    """A verdict produced by a fallback is not a verdict.

    `fallback_v1` means the LLM judgment never landed and the deterministic
    heuristic answered instead. That is a legitimate degradation, but it must
    never read as a judged verdict.
    """
    findings: list[Finding] = []
    for label, blob in (("quick_scan", verdict), ("deep_dive", deep),
                        ("publish", report)):
        if not isinstance(blob, dict):
            continue
        src = str(blob.get("source") or "").strip()
        if src and src in FALLBACK_SOURCES:
            findings.append(Finding(
                check=f"verdict.fallback_source.{label}",
                detail=(f"{label} verdict came from {src!r}, not a judge: "
                        f"no LLM judgment was recorded for this stage"),
                evidence={"source": src,
                          "verdict": blob.get("verdict"),
                          "llm_error": str(blob.get("llm_error") or "")[:200]}))
    return findings


def check_verdict_panel_agreement(case: Path) -> list[Finding]:
    """The markdown panel must agree across reports and with the locked verdict.

    Defect from 2026-10-01: the lock reported `final=malicious lock_ok=True`
    while the master panel read `**suspicious**` and the technical panel
    `**unknown**`. publish_report_v2 now repairs the panel, so a mismatch here
    means either the repair did not run or a new drift path appeared.
    """
    panels: dict[str, str] = {}
    for name in ("REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md",
                 "REPORT-MASTER-v3.md", "REPORT-TECHNICAL-v3.md"):
        p = case / name
        if not p.is_file():
            continue
        try:
            m = _TICKER_RE.search(p.read_text(errors="replace")[:200000])
        except OSError:
            continue
        if m:
            panels[name] = m.group(1).strip().lower()

    findings: list[Finding] = []
    distinct = set(panels.values())
    if len(distinct) > 1:
        findings.append(Finding(
            check="verdict.panel_disagreement",
            detail=(f"report verdict panels disagree: {panels}"),
            evidence={"panels": panels}))
    return findings


# ------------------------------------------------------------------ LLM call path

def check_exhausted_llm_calls(case: Path) -> list[Finding]:
    """Calls that burned every attempt are recorded, not silently absorbed.

    Scans the case's stage log for the terminal forms llm_judge prints when it
    gives up. Budget unlimited does not make a failed call harmless: it means
    that piece of analysis is missing from the report.
    """
    logs = list(case.glob("*.log")) + [case / "pipeline_single.log"]
    logs = [p for p in dict.fromkeys(logs) if p.is_file()]
    patterns = {
        "llm.exhausted": "llm_judge failed",
        "llm.terminal_abort": "attempt 3/3 failed",
    }
    counts: Counter[str] = Counter()
    for path in logs:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for key, needle in patterns.items():
            counts[key] += text.count(needle)
    return [Finding(
        check=k, detail=f"{v} occurrence(s) of {k} in the run logs",
        evidence={"count": v})
        for k, v in sorted(counts.items()) if v]


# ------------------------------------------------------------------ report text

def check_report_degenerate(md: str | None) -> list[Finding]:
    """Reports that are byte-repetitive or near-empty.

    The provider has degenerated into repeated placeholder tokens before
    (rehearsal 2026-09-21: ~275 KB of one token). _looks_degenerate catches that
    per response; this catches it in the assembled document, where repetition can
    also come from assembling the same section twice.
    """
    if not md or not md.strip():
        return []
    findings: list[Finding] = []
    toks = _DEGENERATE_TOKEN.findall(md)
    if len(toks) >= 200:
        counts = Counter(t.lower() for t in toks)
        top, n = counts.most_common(1)[0]
        if n / len(toks) > 0.30:
            findings.append(Finding(
                check="report.degenerate_repetition",
                detail=(f"one token ({top!r}) is {n / len(toks):.0%} of the "
                        f"document: the report is repetitive filler"),
                evidence={"token": top, "count": n, "tokens": len(toks)}))
    if len(md.strip()) < 2000:
        findings.append(Finding(
            check="report.too_short",
            detail=f"report body is only {len(md.strip())} chars",
            evidence={"chars": len(md.strip())}))
    return findings


def check_duplicate_sections(md: str | None) -> list[Finding]:
    """Identical sections mean a report was assembled twice or reused."""
    if not md:
        return []
    parts = re.split(r"^#\s+", md, flags=re.MULTILINE)[1:]
    bodies = {}
    for p in parts:
        title = p.split("\n", 1)[0].strip().lower()
        body = "\n".join(p.split("\n")[1:]).strip()
        if title and body:
            bodies.setdefault(body, []).append(title)
    dupes = {tuple(v) for v in bodies.values() if len(v) > 1}
    if dupes:
        return [Finding(
            check="report.duplicate_sections",
            detail=f"identical section bodies repeated: {sorted(dupes)[:4]}",
            evidence={"groups": len(dupes)})]
    return []


# --------------------------------------------------------------------- aggregate

def evaluate_case(case: Path) -> dict[str, Any]:
    """Run every hollow-success check against one case directory."""
    case = Path(case)
    findings: list[Finding] = []

    recovery = _load(case / "function_recovery.json")
    findings += check_function_recovery(recovery)
    findings += check_verdict_sources(
        _load(case / "verdict.json"),
        _load(case / "deep_dive" / "05-deep-dive.json"),
        _load(case / "report-v2.json"))
    findings += check_verdict_panel_agreement(case)
    findings += check_exhausted_llm_calls(case)

    for name in ("REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md"):
        p = case / name
        if p.is_file():
            try:
                md = p.read_text(errors="replace")
            except OSError:
                continue
            tag = "REPORT-MASTER-v2" if "MASTER" in name else "REPORT-TECHNICAL-v2"
            for f in check_report_degenerate(md) + check_duplicate_sections(md):
                findings.append(Finding(
                    check=f"{f.check}.{tag.lower()}",
                    detail=f"[{tag}] {f.detail}",
                    evidence=f.evidence))

    return {
        "ok": not findings,
        "findings": [f.as_dict() for f in findings],
        "count": len(findings),
        "advisory": _advisory(recovery),
    }


def _advisory(recovery: dict | None) -> dict[str, Any]:
    """Quality signals that are real but must NOT gate the run.

    Partial naming failure is a depth problem, not a hollow success: on
    2026-10-01 two of twelve cases left ~52% of recovered functions named
    `unknown_*` while carrying real pseudocode and a real confidence spread, and
    both had passed every gate. Gating that would be wrong (the artifact has
    content) and ignoring it would hide the reason `function_recovery.json`
    reports 87 of 200 `llm_candidates` on the large samples.
    """
    if not recovery:
        return {}
    llm = [r for r in (recovery.get("function_results") or [])
           if isinstance(r, dict) and r.get("source") == "llm_judge"]
    if len(llm) < MIN_RESULTS_FOR_RATIO_CHECK:
        return {"llm_results": len(llm), "judged": False}
    n = len(llm)
    unknown = sum(1 for r in llm
                  if str(r.get("function_name") or "").startswith("unknown_"))
    empty = sum(1 for r in llm
                if not (r.get("normalized_pseudocode") or "").strip())
    triage = recovery.get("triage") or {}
    return {
        "llm_results": n,
        "judged": True,
        "unresolved_name_ratio": round(unknown / n, 3),
        "empty_pseudocode_ratio": round(empty / n, 3),
        "llm_candidates": triage.get("llm_candidates"),
        "results_vs_candidates": (
            f"{n}/{triage['llm_candidates']}"
            if triage.get("llm_candidates") else None),
        "note": ("partial naming is a depth signal, not a hollow success; "
                 "gated only at >90% unknown_*"),
    }
