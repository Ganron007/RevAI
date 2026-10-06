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
#: Two report formats exist since #39 made the technical report section-wise:
#:
#:   1. the v2 table row    | **Final** | *suspicious* |
#:   2. the v3 inline panel **Verdict: suspicious** (confidence: 70/100, ...)
#:
#: A reader that knows only #1 goes blind on every run that emits #3, which is
#: every run since #39 shipped -- observed live as
#: `verdict.panels_unreadable: 5 report(s) present but only 1 verdict panel(s)
#: parseable` on a run whose reports were complete (13/13 and 17/17,
#: quality_ok=True) and whose verdicts were stated in prose in all of them.
#:
#: The v3 alternative is deliberately NARROW: it requires the confidence clause
#: that follows, so a paragraph that merely mentions a verdict cannot satisfy
#: the panel check. A looser `\\bverdict[:\s*]+(\\w+)` would match the report
#: talking ABOUT verdicts, which is how this check would stop meaning anything.
_TICKER_RE = re.compile(
    r"\|\s*\*\*Final\*\*\s*\|\s*\*+([^*|]+?)\*+\s*\|"
    r"|\*\*verdict\s*:\s*[\s*`]*([a-z][a-z _-]{2,30}?)[\s*`]*"
    r"(?:\(|,)\s*(?:confidence|score)[\s:]*\d",
    re.IGNORECASE)

#: Written by pipeline_single at the top of every run (see
#: pipeline_single.run_single). Case dirs are reused and the stage log is
#: append-only, so this timestamp is the boundary between one run's artifacts
#: and the previous run's.
_RUN_START_RE = re.compile(
    r"===== RUN START (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) =====")

#: The one log that carries the banner. pipeline_single.run_single appends it
#: there; every other case log is a stage's own file, and treating them as
#: banner-bearing is what zeroed the exhausted-call check (defect A2).
STAGE_LOG_NAME = "pipeline_single.log"


def _banner_stamp(case: Path) -> str | None:
    """The newest RUN START banner stamp in the case's stage log, if any."""
    try:
        text = (Path(case) / STAGE_LOG_NAME).read_text(errors="replace")
    except OSError:
        return None
    stamps = _RUN_START_RE.findall(text)
    return stamps[-1] if stamps else None


def _banner_epoch(stamp: str) -> float | None:
    """UTC epoch of one banner stamp, or None when it does not parse."""
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(
            stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _boundary_is_unsound(case: Path, epoch: float) -> bool:
    """True when a clock step has made the banner unusable as a cutoff.

    The banner is appended to the stage log, so that file's mtime can NEVER be
    older than the instant the banner was written. When it is, the clock
    stepped back after the banner and every artifact written since carries an
    mtime behind the boundary. A strict cutoff then discards THIS run's own
    artifacts and calls the case clean -- the false-green direction this gate
    must never take (defect A3), so the boundary is abandoned rather than
    trusted.
    """
    try:
        return (Path(case) / STAGE_LOG_NAME).stat().st_mtime < epoch
    except OSError:
        return False


def _run_start_epoch(case: Path) -> float | None:
    """UTC epoch of the newest RUN START banner in the case's stage log.

    None when there is no banner (another runner, a legacy case, or a flat log
    layout): every artifact is then judged, exactly as before. With a banner,
    checks that would otherwise mix runs -- report sidecars, markdown panels,
    exhausted-call needles in the append-only log -- only see artifacts from
    the run that wrote it. A publish-only re-run therefore cannot inherit the
    previous run's stale reports as findings of its own.

    Also None when the banner cannot be trusted as a cutoff (see
    :func:`_boundary_is_unsound`): an unsound boundary is dropped, which fails
    OPEN -- stale artifacts are judged again -- instead of silently skipping
    the current run's.
    """
    stamp = _banner_stamp(case)
    if stamp is None:
        return None
    epoch = _banner_epoch(stamp)
    if epoch is None or _boundary_is_unsound(case, epoch):
        return None
    return epoch


def _has_run_banner(case: Path) -> bool:
    """True when the case's stage log records that a run started here.

    Deliberately independent of :func:`_run_start_epoch`: a banner whose
    timestamp cannot be used as a cutoff (clock skew) still proves a run began,
    which is what the produced-something check needs to know.
    """
    return _banner_stamp(case) is not None


def _is_current_run(path: Path, run_start: float | None) -> bool:
    """True when `path` belongs to the current run (or no boundary is known)."""
    if run_start is None:
        return True
    try:
        return path.stat().st_mtime >= run_start
    except OSError:
        return True


def _log_text_for_this_run(path: Path) -> str:
    """A log's content, sliced to the current run when THIS file has a banner.

    The boundary is per FILE, not per case. Only the stage log carries a
    banner, so slicing every log at a marker it does not contain returned ""
    and zeroed the whole check: the orchestrator log, the ghidrasql/idasql
    server logs and the WinRE run log all record exhausted LLM calls and
    attempts that then contributed nothing (defect A2, a regression in the
    other direction).
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return ""
    idx = text.rfind("===== RUN START ")
    if idx == -1:
        # No banner in this file: it is not an append-only record shared
        # between runs, so all of it describes the current run.
        return text
    return text[idx:]


@dataclass
class Finding:
    """One hollow-success observation. `check` is a stable machine key."""
    check: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"check": self.check, "detail": self.detail,
                "evidence": self.evidence}


def _load(path: Path) -> Any:
    """A JSON payload, or None when the file is absent or unparseable.

    Returns whatever `json.loads` produced, which is not always a dict: a
    valid-but-non-dict payload must not short-circuit a caller's discovery (see
    `_publish_sidecar`) or blow it up with an AttributeError (see
    `check_function_recovery`). Every caller checks the type.
    """
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
    if not isinstance(data, dict):
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
    # Discovered, not enumerated, for the same reason as REPORT_MD_GLOB: a fixed
    # list of report filenames is a check that silently stops covering the
    # moment a version is added. Stale reports from an earlier run are not
    # COMPARED when a RUN START banner exists -- a re-run must not inherit the
    # previous run's panel disagreement as its own finding -- but they are
    # still counted as reports on disk (defect A5): a publish that wrote the
    # master and died before the technical report must land on the blind side
    # of this check, not on the side where there is nothing left to compare.
    run_start = _run_start_epoch(case)
    md_files: list[Path] = []
    current: list[Path] = []
    for path in sorted(case.glob(REPORT_MD_GLOB)):
        if not path.is_file():
            continue
        md_files.append(path)
        if not _is_current_run(path, run_start):
            continue
        current.append(path)
        try:
            m = _TICKER_RE.search(path.read_text(errors="replace")[:200000])
        except OSError:
            continue
        if m:
            # group(1) is the v2 table row; group(2) the v3 inline panel. Reading
            # only group(1) is what left the v3 reports unreadable.
            verdict = (m.group(1) or m.group(2) or "").strip().lower()
            if verdict:
                panels[path.name] = verdict

    findings: list[Finding] = []
    distinct = set(panels.values())
    if len(distinct) > 1:
        findings.append(Finding(
            check="verdict.panel_disagreement",
            detail=(f"report verdict panels disagree: {panels}"),
            evidence={"panels": panels}))
    # Blind, not passing: with several reports on disk and fewer than two
    # panels parsed, there is nothing to disagree WITH -- the check would
    # vacuously pass on a format change that stopped emitting the panel,
    # which is the check that cannot fail again. Two reports are required so
    # a legitimately single-report case is not flagged for having nothing to
    # compare. The threshold is on the reports PRESENT, not on the ones that
    # survived the current-run filter: counting only the survivors is how a
    # half-written report set read as a single-report case and passed.
    if len(md_files) >= 2 and len(panels) < 2:
        findings.append(Finding(
            check="verdict.panels_unreadable",
            detail=(f"{len(md_files)} report(s) present but only {len(panels)} "
                    "verdict panel(s) parseable -- panel agreement is not "
                    "checkable"),
            evidence={"files": [p.name for p in md_files],
                      "current_run": [p.name for p in current],
                      "parsed": sorted(panels)}))
    return findings


# ------------------------------------------------------------------ LLM call path

def check_exhausted_llm_calls(case: Path) -> list[Finding]:
    """Calls that burned every attempt are recorded, not silently absorbed.

    Scans every log the case holds -- the stage log plus the stage logs the
    individual stages keep (orchestrator, ghidrasql/idasql servers, WinRE
    runner) -- for the terminal forms llm_judge prints when it gives up. Budget
    unlimited does not make a failed call harmless: it means that piece of
    analysis is missing from the report.
    """
    logs = list(case.glob("*.log")) + [case / "pipeline_single.log"]
    logs = [p for p in dict.fromkeys(logs) if p.is_file()]
    patterns = {
        "llm.exhausted": "llm_judge failed",
        "llm.terminal_abort": "attempt 3/3 failed",
    }
    counts: Counter[str] = Counter()
    for path in logs:
        # Append-only log: only the segment since this file's OWN last banner
        # is this run's record. Without the boundary a re-run inherited the
        # previous run's exhausted calls as its own findings; applying the
        # case's banner to every file instead zeroed every log except the
        # stage log, which is the only one that writes a banner.
        text = _log_text_for_this_run(path)
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


# ------------------------------------------------------- declared completeness

#: Report sidecars. Discovered, not enumerated: `report*.json` matches
#: report-v2.json, report-technical-v2.json, report-technical-v3.json and
#: whatever a future version adds. The hardcoded pair of v2 filenames this
#: replaced was why the 2026-10-01 win32k_dll run passed the detector while
#: report-technical-v3.json was declaring 1 of 13 sections complete, 10 stubs
#: and a deterministic_fallback source.
REPORT_SIDECAR_GLOB = "report*.json"

#: Per-section provenance manifests (section-results-v3.json and siblings).
SECTION_MANIFEST_GLOB = "section-results-*.json"

#: Markdown reports, any version.
REPORT_MD_GLOB = "REPORT-*.md"


def check_report_sidecars(case: Path) -> list[Finding]:
    """Each report's OWN declaration of whether it is complete.

    This is the check that should have caught the v3 technical collapse, and
    reading the declaration beats re-deriving quality from the markdown for
    three reasons: it is version-agnostic, it cannot be bypassed by a new report
    path existing, and it is the stage's own verdict rather than a heuristic of
    ours. A report that says it fell back, or that it is missing sections, is
    hollow by its own account -- there is nothing left to infer.

    Measured on the three known-good cases (raas, winservices, fgg_js): every
    sidecar reports source=llm_judge with 0 missing and 0 stub sections, so
    flagging either is free of false positives there.
    """
    findings: list[Finding] = []
    run_start = _run_start_epoch(case)
    for path in sorted(Path(case).glob(REPORT_SIDECAR_GLOB)):
        if not _is_current_run(path, run_start):
            # A report older than this run's banner belongs to a previous run;
            # judging it here is how a re-run failed on findings it never
            # produced (2026-10-03 stale-artifact review).
            continue
        data = _load(path)
        if not isinstance(data, dict):
            continue
        name = path.name
        src = str(data.get("source") or "").strip()
        missing = data.get("sections_missing") or []
        stubs = data.get("sections_stub") or []
        complete = data.get("sections_complete")

        if src in FALLBACK_SOURCES:
            findings.append(Finding(
                check="report.fallback_source",
                detail=(f"{name} declares source={src!r}: no LLM authored this "
                        f"report, so it carries a deterministic rendering, not "
                        f"analysis"),
                evidence={"file": name, "source": src,
                          "sections_complete": complete}))

        if stubs:
            findings.append(Finding(
                check="report.stub_sections",
                detail=(f"{name} has {len(stubs)} stub section(s) -- "
                        f"placeholders where real content belongs: "
                        f"{list(stubs)[:3]}"),
                evidence={"file": name, "stubs": len(stubs),
                          "names": [str(s)[:60] for s in list(stubs)[:5]],
                          "sections_complete": complete}))

        if missing:
            findings.append(Finding(
                check="report.sections_missing",
                detail=(f"{name} is missing {len(missing)} section(s) with only "
                        f"{complete} complete: {list(missing)[:3]}"),
                evidence={"file": name, "missing": len(missing),
                          "sections_complete": complete,
                          "names": [str(s)[:60] for s in list(missing)[:5]]}))

        if isinstance(complete, int) and complete == 0 and not missing:
            findings.append(Finding(
                check="report.empty",
                detail=f"{name} reports zero completed sections",
                evidence={"file": name, "sections_complete": 0}))
    return findings


def check_section_manifests(case: Path) -> list[Finding]:
    """Section manifests record per-section LLM success as `llm_ok`.

    Only an explicit `False` counts. An absent key means the producer did not
    report provenance, which is not evidence of a hollow section, so treating
    absence as failure would flag healthy manifests.

    Same current-run boundary as the other report readers: a manifest older
    than the run's banner belongs to the previous run. Without the filter this
    was the one reader that still judged stale artifacts, so the same file was
    skipped by one check and judged by another (2026-10-03 review, defect A1).
    The balance for that filter is `check_run_produced_artifacts`: a re-run that
    wrote no manifest of its own does not silently inherit a clean verdict.
    """
    findings: list[Finding] = []
    run_start = _run_start_epoch(case)
    for path in sorted(Path(case).glob(SECTION_MANIFEST_GLOB)):
        if not _is_current_run(path, run_start):
            continue
        data = _load(path)
        if not isinstance(data, dict):
            continue
        sections = data.get("sections")
        if not isinstance(sections, list) or not sections:
            continue
        failed = [s for s in sections
                  if isinstance(s, dict) and s.get("llm_ok") is False]
        if not failed:
            continue
        names = [str(s.get("name") or s.get("title") or "?")[:50]
                 for s in failed[:5]]
        findings.append(Finding(
            check="report.section_llm_failed",
            detail=(f"{path.name}: {len(failed)}/{len(sections)} sections were "
                    f"not LLM-authored: {names}"),
            evidence={"file": path.name, "failed": len(failed),
                      "total": len(sections), "names": names}))
    return findings


def check_run_produced_artifacts(case: Path) -> list[Finding]:
    """A run that started and produced nothing must not read as clean.

    The current-run filter is what stops a re-run from inheriting the previous
    run's findings, and it is exactly what hid a crashed run: with the previous
    run's reports still on disk and a banner in the stage log, every report
    check above sees an empty case and returns clean. Reproduced 2026-10-03 --
    a case dir holding stale reports plus a stage log containing only a RUN
    START banner and `===== TIMEOUT` evaluated to ok=True with zero findings;
    deleting the banner line made the same artifacts yield four findings.

    So the filter is balanced by a requirement rather than trusted on its own:
    when a run demonstrably started (a banner exists) and EVERY report artifact
    in the case predates that banner, the run produced no report at all. The
    publisher writes unconditionally on success, so there is no legitimate
    "up to date, nothing to do" path that this would flag.

    Fires only when stale artifacts exist to mask the emptiness: a first-time
    case whose run died before publishing is caught by the ordinary missing
    -artifact checks, and flagging it here too would add a second, vaguer
    signal for the same defect.
    """
    if not _has_run_banner(case):
        return []
    run_start = _run_start_epoch(case)
    fresh: list[str] = []
    stale: list[str] = []
    for pattern in (REPORT_SIDECAR_GLOB, SECTION_MANIFEST_GLOB, REPORT_MD_GLOB):
        for path in sorted(Path(case).glob(pattern)):
            if not path.is_file():
                continue
            (fresh if _is_current_run(path, run_start)
             else stale).append(path.name)
    if fresh or not stale:
        return []
    return [Finding(
        check="run.produced_nothing",
        detail=(f"this run produced no report artifact: all {len(stale)} report "
                f"file(s) in the case predate its RUN START banner, so every "
                f"report check was skipped and the case read as clean"),
        evidence={"stale_files": sorted(stale)[:10], "stale": len(stale),
                  "current": 0})]


def _publish_sidecar(case: Path) -> dict | None:
    """The publish stage's verdict-source sidecar, discovered not assumed.

    ``report-v2.json`` is the current publisher's artifact and was the one
    filename the discovery rule did not cover: if a future version stops
    writing it, the verdict-source check would silently no-op. Prefer the
    known name; otherwise take the newest remaining report sidecar that
    declares a source.

    Two rules this reader shares with the other sidecar readers: the payload
    must be a dict -- a valid JSON array or string is not a verdict and used to
    short-circuit discovery, silently disabling the check (defect A4) -- and a
    sidecar older than the run's banner is a previous run's, so the same file
    is not skipped by one check and judged by this one.
    """
    run_start = _run_start_epoch(case)
    known = Path(case) / "report-v2.json"
    if known.is_file() and _is_current_run(known, run_start):
        data = _load(known)
        if isinstance(data, dict):
            return data
    candidates: list[tuple[float, dict]] = []
    for p in Path(case).glob(REPORT_SIDECAR_GLOB):
        if not p.is_file() or not _is_current_run(p, run_start):
            continue
        data = _load(p)
        if isinstance(data, dict) and data.get("source"):
            try:
                candidates.append((p.stat().st_mtime, data))
            except OSError:
                continue
    return max(candidates, key=lambda c: c[0])[1] if candidates else None


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
        _publish_sidecar(case))
    findings += check_verdict_panel_agreement(case)
    findings += check_exhausted_llm_calls(case)
    findings += check_report_sidecars(case)
    findings += check_section_manifests(case)

    # Markdown is now discovered too, so a v3 report is checked for degeneration
    # and duplicated sections exactly as a v2 one is. Stale reports from an
    # earlier run are skipped when a RUN START banner exists.
    run_start = _run_start_epoch(case)
    for path in sorted(case.glob(REPORT_MD_GLOB)):
        if not _is_current_run(path, run_start):
            continue
        try:
            md = path.read_text(errors="replace")
        except OSError:
            continue
        tag = path.stem
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
    adv = {
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

    # The deobfuscation leg has been a silent no-op since 2026-09-28
    # (pyghidra not importable). It still contributes nothing on the samples it
    # skips, so state it. Advisory: the obfuscation flags are computed
    # heuristically either way and no verdict depends on flattening.
    deob = recovery.get("deobfuscation")
    if isinstance(deob, dict) and deob.get("skipped"):
        adv["deobfuscation_leg"] = "skipped"
        adv["deobfuscation_reason"] = str(
            deob.get("reason") or deob.get("error") or "unknown")[:200]
    return adv
