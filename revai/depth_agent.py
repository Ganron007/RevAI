"""revai/depth_agent.py — the depth mode: understand HOW the sample works.

A separate mode because the operator's five reasons all hold: expensive, long,
unpredictable (it loops until the picture is complete), needs pause/resume, and
needs status the examiner can act on. This is NOT the main pipeline and must
never gate it. It runs AFTER the main pipeline and reads that pipeline's
artifacts as its starting context.

The objective is UNDERSTANDING, not a verdict. A depth run that produces a
verdict has failed its own objective — this stage produces a function map, not a
judgment.

What makes it buildable is the convergence contract, not the budget. "Whatever is
required to understand the exe" cannot be a stopping rule. Every function or
region gets a status from a fixed vocabulary, each with a reason and an evidence
citation, and the loop terminates when the unknown set is empty or explicitly
costed.

Two honest boundaries are structural here, not aspirational:

* An OVERSTATED status is worse than an admitted unknown. 'understood' with no
  citation is not accepted, so a confident wrong answer cannot enter the map.
* A cutoff is not a failure. Hitting the ceiling forces a consolidate-and-declare
  phase, so the run always yields a partial-but-honest map rather than nothing —
  which is what makes an unpredictable run acceptable.

Stop triggers: BOTH, per the operator. An examiner can stop at any time, and a
wall-clock/token ceiling stops it unattended. Either way the run consolidates
before it exits.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

#: The env knob. Operator requirement: a separate mode with an ON/OFF switch.
DEPTH_ENV = "REVAI_DEPTH"

#: Statuses a region can carry. This vocabulary is the convergence contract --
#: "whatever is required to understand the exe" becomes checkable only once
# "not understood" has a small number of named, distinguishable shapes.
STATUS_UNDERSTOOD = "understood"
STATUS_PARTIAL = "partial"
STATUS_NOT_RECONSTRUCTED = "not-reconstructed"
STATUS_NOT_EXPLORED = "not-explored"
VALID_STATUSES = (STATUS_UNDERSTOOD, STATUS_PARTIAL,
                 STATUS_NOT_RECONSTRUCTED, STATUS_NOT_EXPLORED)

#: Statuses that count as "still unknown" for the termination check.
UNKNOWN_STATUSES = (STATUS_PARTIAL, STATUS_NOT_RECONSTRUCTED,
                   STATUS_NOT_EXPLORED)

#: The state file the loop checkpoints after every region. This is what makes
#: pause and resume real rather than a restart, and what a stop consolidates.
STATE_FILE = "understanding.json"

#: Default ceiling. Deliberately generous but NOT open: an unbounded loop is how
#: a token budget burns without converging. The operator asked for a very-high
#: budget AND a ceiling, and both are true here -- the ceiling is high and its
#: effect is consolidation, not truncation.
DEFAULT_CEILING_SECONDS = 7200


def depth_enabled() -> bool:
    """Whether depth mode is on. Off by default — the main pipeline is unaffected.

    The vocabulary is deliberately 1/true/on and NOT the wider "yes" accepted by
    other startup gates: `REVAI_DEPTH` also carries the historical
    `REVAI_DEPTH=full` spelling from plan #26, which means a *depth profile*
    rather than "on". Widening the truthy set here would make R2's future
    `full` profile indistinguishable from "on". tests/test_depth_mode.py pins
    this; a change here is a change to the documented contract, not a fix.
    """
    return os.environ.get(DEPTH_ENV, "").strip().lower() in ("1", "true", "on")


#: The #26 full profile's spelling and its label.
PROFILE_FULL = "full"
PROFILE_D0 = "d0"

#: The full profile's own default ceiling. The operator's directive is
#: explicit -- a depth run taking hours is not a failure -- so the full
#: profile defaults far above D0's. An explicit REVAI_DEPTH_CEILING_SECONDS
#: still wins for both profiles.
FULL_DEFAULT_CEILING_SECONDS = 14400

#: What the full profile forces ON for its own investigation. setdefault
#: semantics: an operator's explicit value wins, and the forced list is
#: recorded in the artifact so the run states what it enabled rather than
#: leaving it to be inferred from the trace.
_FULL_FORCED_FEATURES = (
    ("REVAI_DOMAIN_GRAPH", "1"),              # the #20 substrate itself
    ("REVAI_DOMAIN_STEP_BUDGET", "8"),        # the very-high budget lever
    ("REVAI_ENABLE_EMULATION_ORACLE", "1"),   # forced emulator
    ("REVAI_ENABLE_UNPACK_PASS", "1"),        # forced unpack
    ("ENABLE_DEOBFUSCATION_PASS", "1"),       # forced solver
)


def depth_profile() -> str:
    """Which depth profile `REVAI_DEPTH` asks for: "full", "d0", or "".

    `REVAI_DEPTH=full` is the #26 profile spelling, reserved since the
    vocabulary was built. It is deliberately NOT a truthy alias for "on":
    `depth_enabled()` keeps its narrow meaning so the two profiles can never
    be confused at a call site, and the stage gates use `depth_requested()`.
    """
    raw = (os.environ.get(DEPTH_ENV) or "").strip().lower()
    if raw == PROFILE_FULL:
        return PROFILE_FULL
    if raw in ("1", "true", "on"):
        return PROFILE_D0
    return ""


def depth_requested() -> bool:
    """Whether ANY depth run was asked for -- either profile.

    This is what the stage gates use. `depth_enabled()` keeps its narrow
    meaning ("on", not "which profile"), because widening it would make the
    two profiles indistinguishable everywhere it is checked.
    """
    return bool(depth_profile())


def status_requires_evidence(status: str) -> bool:
    """Whether a status must carry a citation.

    ONLY 'not-explored' is excused: it asserts nothing beyond that the region was
    not looked at, and forcing a citation there would force a fabrication. Every
    other status claims something and must show its work.
    """
    return status != STATUS_NOT_EXPLORED


def unrecognised_statuses(regions: dict) -> list[str]:
    """Names carrying a status outside the vocabulary.

    An unrecognised label is NOT 'unknown' and NOT 'understood' -- it is a defect
    in the state itself, and it must be visible rather than silently dropped from
    both sets. `unknown_set` used to test membership in UNKNOWN_STATUSES, so a
    typo'd status was excluded from the unknown set (the loop would terminate with
    the region never understood) AND from cost_summary's counts (regions_total
    under-counted by one). Only has_converged noticed, and nothing called it.
    """
    known = set(VALID_STATUSES)
    return sorted(name for name, r in (regions or {}).items()
                  if str((r or {}).get("status")) not in known)


def unknown_set(regions: dict) -> list[str]:
    """Names still unknown, PLUS anything with a malformed status.

    Defensive because this is the set a loop's termination depends on: treating an
    unrecognised status as 'not unknown' would end the run with a region never
    understood and reported as such.
    """
    return sorted(set(unknown_set_known(regions)) | set(unrecognised_statuses(regions)))


def unknown_set_known(regions: dict) -> list[str]:
    """Names carrying one of the recognised UNKNOWN statuses."""
    return sorted(name for name, r in (regions or {}).items()
                  if str((r or {}).get("status")) in UNKNOWN_STATUSES)


def has_converged(regions: dict) -> bool:
    """True when EVERY region carries a fully understood status.

    Explicitly NOT "nothing is unknown": a status label outside the vocabulary
    must not count toward completion. Treating an unrecognised value as
    understood means a typo silently marks the run finished, which is the same
    failure as an unverified claim being counted as verified.
    """
    return bool(regions) and all(
        str((r or {}).get("status")) == STATUS_UNDERSTOOD
        for r in (regions or {}).values())


def load_state(case_dir: Path) -> dict:
    """The depth state for a case, or an empty skeleton when there is none."""
    p = Path(case_dir) / STATE_FILE
    if not p.is_file():
        return {"sha256": None, "regions": {}, "stop_reason": None,
                "spend": {"llm_calls": 0, "seconds": 0.0, "tokens": 0}}
    try:
        d = json.loads(p.read_text(errors="replace"))
        d.setdefault("regions", {})
        d.setdefault("stop_reason", None)
        d.setdefault("spend", {"llm_calls": 0, "seconds": 0.0, "tokens": 0})
        return d
    except Exception:
        return {"regions": {}, "stop_reason": None,
                "spend": {"llm_calls": 0, "seconds": 0.0, "tokens": 0}}


def save_state(case_dir: Path, state: dict) -> None:
    """Checkpoint the state. Called after every region so a stop is cheap."""
    p = Path(case_dir) / STATE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)  # atomic: a stop mid-write must not corrupt the resume


def ceiling_seconds(profile: str | None = None) -> int:
    """The wall-clock ceiling for a depth run.

    The full profile (#26) defaults far higher -- long runtimes are expected
    there by design -- and an explicit REVAI_DEPTH_CEILING_SECONDS wins for
    both. A non-numeric value falls back to the profile's default rather
    than failing a run.
    """
    profile = profile if profile is not None else depth_profile()
    default = (FULL_DEFAULT_CEILING_SECONDS if profile == PROFILE_FULL
               else DEFAULT_CEILING_SECONDS)
    raw = os.environ.get("REVAI_DEPTH_CEILING_SECONDS", "") or str(default)
    try:
        return max(60, int(raw))
    except (TypeError, ValueError):
        return default


def cost_summary(regions: dict, spend: dict) -> dict:
    """The number that makes a cutoff a partial success rather than a failure.

    Reported by every depth run: N regions understood / partial / not
    reconstructed / not explored, plus what it cost. Without this the operator
    cannot tell a run that finished from one that was stopped, and cannot set
    budgets by measurement.
    """
    counts = {s: 0 for s in VALID_STATUSES}
    malformed = 0
    for r in (regions or {}).values():
        s = str((r or {}).get("status"))
        if s in counts:
            counts[s] += 1
        else:
            malformed += 1
    unknown = sum(counts[s] for s in UNKNOWN_STATUSES)
    return {"regions_total": sum(counts.values()) + malformed,
             "by_status": counts,
             "malformed_status": malformed,
             # A region with an unrecognised status is not accounted 'unknown',
             # but it is certainly not understood -- report both so the number
             # reconciles and cannot be read as a clean completion.
             "unknown_remaining": unknown + malformed,
             "spend": spend}


def _case_sample_sha(case: Path, existing: object = None) -> str | None:
    """Resolve the sample identity from its canonical case directory.

    Agentic cases live at ``logs/<sha>/agentic`` while scripted cases live at
    ``logs/<sha>``. The path is the source of truth; an old/null state field
    must not erase the identity from a newly written understanding artifact.
    """
    for candidate in (Path(case).name, Path(case).parent.name):
        if (len(candidate) == 64
                and all(c in "0123456789abcdefABCDEF" for c in candidate)):
            return candidate.lower()
    if isinstance(existing, str) and len(existing) == 64 and all(
            c in "0123456789abcdefABCDEF" for c in existing):
        return existing.lower()
    return None


def _depth_progress_usage(case: Path) -> dict:
    """Read successful LLM response usage emitted by the depth graph.

    The domain graph can make several provider requests per capability region.
    Counting regions as ``llm_calls`` and writing zero tokens hid the actual
    usage. The progress stream is reset for each domain pass, so this helper
    must be called immediately after each pass and its result accumulated.
    """
    progress = Path(case) / "deep_dive" / "deep-dive-progress.jsonl"
    calls = 0
    tokens = 0
    missing_usage = 0
    malformed = 0
    try:
        lines = progress.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            malformed += 1
            continue
        if not isinstance(event, dict) or event.get("event") != "llm_end":
            continue
        calls += 1
        usage = event.get("tokens")
        total = usage.get("total_tokens") if isinstance(usage, dict) else None
        try:
            total = int(total)
        except (TypeError, ValueError):
            missing_usage += 1
            continue
        if total < 0:
            missing_usage += 1
            continue
        tokens += total
    return {
        "llm_calls": calls,
        "tokens": tokens,
        "token_usage_complete": bool(calls) and missing_usage == 0 and malformed == 0,
        "token_usage_missing_responses": missing_usage,
        "progress_malformed_lines": malformed,
    }


def _domain_questions() -> dict[str, dict]:
    """The capability domains, from the vocabulary the pipeline already enforces."""
    try:
        import domain_graph as dg
        return {d["key"]: d for d in dg.DOMAINS}
    except Exception:
        return {}


def seed_regions(case: Path) -> dict[str, dict]:
    """The regions this depth run must deepen, seeded from the capability ledger.

    A region is a capability domain the main pipeline could NOT establish to an
    evidence-backed determination -- provenance `inferred` or `unknown` (#56).
    A domain already `observed` needs no depth: the evidence is already cited.
    That is what makes this loop converge on something measurable rather than
    re-deriving what the deep dive already established.

    Returns the seeded region map; a case with no ledger (flat engine, or
    REVAI_DOMAIN_GRAPH off) seeds nothing and the caller says so rather than
    inventing regions.
    """
    regions: dict[str, dict] = {}
    try:
        from v2_lib import build_capability_coverage, LOGS_DIR
        _logs = Path(os.environ.get("REVAI_LOGS_DIR") or LOGS_DIR)
        # case is <logs>/<sha>[/<mode>]; build_capability_coverage wants <logs>+<sha>
        sha = case.name if len(case.name) == 64 else case.parent.name
        cov = build_capability_coverage(sha, logs_dir=_logs)
    except Exception:
        return regions
    if not cov or not cov.get("domains"):
        return regions

    questions = _domain_questions()
    for key, entry in (cov.get("domains") or {}).items():
        prov = entry.get("provenance") or "unknown"
        if prov == "observed":
            continue
        d = questions.get(key) or {}
        regions[key] = {
            "status": STATUS_NOT_EXPLORED,
            "reason": "",
            "evidence": [],
            "title": d.get("title", key),
            "question": d.get("question", ""),
            "seeded_from_provenance": prov,
            "pipeline_determination": str(entry.get("answer") or "")[:400],
            "pipeline_evidence_count": entry.get("evidence") or 0,
            # What the pipeline CITED, not just what it concluded. A region
            # handed only the conclusion cannot re-derive or challenge it.
            "pipeline_evidence": list(entry.get("evidence_items") or [])[:8],
        }
    return regions


def _stop_requested(case: Path) -> bool:
    """The examiner's stop switch. Touching <case>/depth.stop ends the loop."""
    return (Path(case) / "depth.stop").exists()


def investigate_region(case: Path, name: str, region: dict) -> dict:
    """One bounded investigation of one region. Returns the updated region.

    The honesty rule is enforced HERE, not trusted: a status that claims
    something must cite evidence, and a status outside the vocabulary is not
    silently accepted. 'understood' with no citation is downgraded to 'partial'
    with the reason recorded -- a confident wrong answer must not enter the map.
    """
    # The depth stage runs as its own process, so it must load the pipeline's
    # runtime env (llm.env) itself. Without this every investigation fails with
    # "LLM API key not configured" and the whole loop reports
    # not-reconstructed -- found on the first live run, where the loop
    # terminated correctly and all three regions failed for this reason alone.
    try:
        from v2_lib import ensure_pipeline_runtime_env
        ensure_pipeline_runtime_env()
    except Exception:
        pass

    from v2_lib import llm_judge
    title = region.get("title") or name
    question = region.get("question") or f"What does this sample do for {title}?"
    prior = str(region.get("pipeline_determination") or "")
    prompt = (
        "You are deepening ONE capability domain of a malware reverse-engineering "
        "analysis. The main pipeline already examined it and could NOT establish "
        "an evidence-backed determination. Your job is to close that gap or say "
        "honestly that it cannot be closed from the available evidence.\n\n"
        f"## Domain: {title}\n{question}\n\n"
        f"## What the main pipeline concluded (provenance: "
        f"{region.get('seeded_from_provenance')})\n{prior or '(nothing recorded)'}\n\n"
        f"## Evidence the pipeline cited for it\n"
        + ("\n".join(f"- {e}" for e in
                      (region.get("pipeline_evidence") or [])[:8])
           or "- (the pipeline cited nothing for this domain)\n")
        + "\n"
        "## Rules\n"
        "- Cite CONCRETE evidence for every claim: a tool, a SQL query, a "
        "function name, an offset, a string. 'understood' with no citation is "
        "not accepted and will be downgraded.\n"
        "- If the evidence does not establish the behaviour, say 'not observed' "
        "and name what you checked. 'not observed' with the checks named IS a "
        "determination.\n"
        "- Never infer a capability from the sample's family or filename.\n"
        "- Reply with ONE JSON object: "
        '{"status": "understood|partial|not-reconstructed", '
        '"answer": "...", "evidence": ["...", "..."], "reason": "..."}\n'
        "- 'not-reconstructed' means the available tools could not reach the "
        "answer (packed, unsupported format, no SQL server).\n"
    )
    try:
        raw = llm_judge(prompt)
    except Exception as exc:
        region["status"] = STATUS_NOT_RECONSTRUCTED
        region["reason"] = f"investigation call failed: {type(exc).__name__}: {exc}"
        region["evidence"] = []
        return region

    # llm_judge returns the FULL response dict, not the content string. Taking
    # `raw` directly (or json.dumps of it) hands parse_domain_reply the
    # {"choices": [...]} envelope, whose keys are not the answer -- so every
    # region reported status '' on the first live runs even though the model
    # answered. The content is at choices[0].message.content.
    text = ""
    if isinstance(raw, dict):
        try:
            text = str(raw["choices"][0]["message"]["content"] or "")
        except Exception:
            text = json.dumps(raw, default=str)
    elif isinstance(raw, str):
        text = raw
    else:
        text = json.dumps(raw, default=str)
    # domain_graph.parse_domain_reply, not normalize_llm_json: it scans for
    # BALANCED top-level objects, so a correctly-formed answer wrapped in prose
    # ("Based on the three queries I ran: {...}") is recovered. normalize_llm_json
    # returned {} for exactly that shape on the first live run -- the model
    # answered and the parser threw it away, reporting status '' for all three
    # regions.
    parsed = {}
    try:
        from domain_graph import parse_domain_reply
        parsed, _why = parse_domain_reply(text)
        if not isinstance(parsed, dict):
            parsed = {}
    except Exception:
        parsed = {}

    status = str(parsed.get("status") or "").strip().lower()
    evidence = [str(e)[:160] for e in (parsed.get("evidence") or [])[:8]]
    answer = str(parsed.get("answer") or "")[:1200]
    reason = str(parsed.get("reason") or "")[:400]

    if status not in VALID_STATUSES or status == STATUS_NOT_EXPLORED:
        # Not in the vocabulary, or claiming "I never looked" while answering:
        # both are the model over- or under-stating. Record what it said and
        # take the conservative grade.
        region["model_status"] = status or "(none)"
        region["status"] = STATUS_PARTIAL
        region["reason"] = reason or (
            f"model returned status {status!r}, outside the vocabulary or "
            "contradicting its own answer")
        region["status_contradicts_answer"] = True
    else:
        region["status"] = status
        region["reason"] = reason

    # THE rule: a claim needs a citation. Enforced here so a confident wrong
    # answer cannot enter the map.
    if status_requires_evidence(region["status"]) and not evidence:
        if region["status"] == STATUS_UNDERSTOOD:
            region["status"] = STATUS_PARTIAL
            region["reason"] = (
                (region.get("reason") or "")
                + " | downgraded from understood: no evidence cited")
            region["downgraded_for_no_evidence"] = True

    region["answer"] = answer
    region["evidence"] = evidence
    region["investigated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return region


def _force_full_profile_features() -> list[str]:
    """Force the investigation features the full profile promises.

    setdefault, so an operator's explicit value still wins; the forced list
    is recorded in the artifact so the run states what it enabled.
    """
    forced = []
    for key, val in _FULL_FORCED_FEATURES:
        if not (os.environ.get(key) or "").strip():
            os.environ[key] = val
            forced.append(f"{key}={val}")
    return forced


@contextmanager
def _preserve_pipeline_deep_dive(case: Path) -> Iterator[Path]:
    """Keep full-profile graph output separate from the main pipeline record.

    The domain graph uses the regular case directory for its tools and output.
    Renaming just the two summary files before that pass made the main audit
    unable to find its required deep-dive artifacts; leaving them in place let
    the graph overwrite evidence already cited by published reports. Snapshot
    the whole directory, let the graph use the normal working path, then retain
    its complete output under ``depth_runs/full/<run-id>/`` and restore the
    exact pipeline directory, even when the graph raises.
    """
    case = Path(case)
    pipeline_dir = case / "deep_dive"
    run_id = (
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        + f"-{time.time_ns() % 1_000_000_000:09d}"
    )
    run_dir = case / "depth_runs" / "full" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    baseline = run_dir / "pipeline-deep_dive"
    depth_output = run_dir / "deep_dive"
    had_pipeline_dir = pipeline_dir.is_dir()
    if had_pipeline_dir:
        shutil.copytree(pipeline_dir, baseline)
    try:
        yield run_dir
    finally:
        # Move the potentially overwritten working tree aside as the depth
        # record, then atomically put the saved pipeline tree back in place.
        if pipeline_dir.exists():
            try:
                pipeline_dir.replace(depth_output)
            except OSError:
                # Same-volume directory rename is expected. If an external
                # process prevents it, retain output by copy before clearing
                # the temporary working tree so the baseline can be restored.
                shutil.copytree(pipeline_dir, depth_output, dirs_exist_ok=True)
                shutil.rmtree(pipeline_dir)
        if had_pipeline_dir and baseline.exists():
            baseline.replace(pipeline_dir)


def _full_max_steps() -> int:
    """The deep-dive step budget the full profile asks the substrate for."""
    raw = os.environ.get("REVAI_DEPTH_FULL_MAX_STEPS", "").strip()
    try:
        val = int(raw)
        if val > 0:
            return val
    except ValueError:
        pass
    return 16


def run_domain_depth_pass(sha: str, case: Path) -> dict:
    """One #20 domain-graph investigation pass -- the full profile's substrate.

    Each capability domain is investigated by its own bounded tool-calling
    node (the structure the operator asked for), instead of one flat loop or
    one evidence-only LLM call. Returns the finalized deep-dive result --
    `findings.domain_graph` carries the per-domain determinations -- or {}
    when the substrate could not run. An empty result is NOT papered over
    with the flat investigation: a stated failure beats a fabricated unknown.
    """
    try:
        from deep_dive_agentic import langgraph_helpers
        from agentic_langgraph import run_langgraph_deep_dive
    except Exception as exc:
        print(f"[depth] domain substrate unavailable: {exc}",
              file=sys.stderr, flush=True)
        return {}
    try:
        result = run_langgraph_deep_dive(
            sha, max_steps=_full_max_steps(), helpers=langgraph_helpers())
    except Exception as exc:
        print(f"[depth] domain pass failed: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return {}
    return result or {}


def _fold_domain_results(st: dict, dom: dict) -> dict[str, dict]:
    """Fold a domain-graph pass into the understanding map.

    Two sources, because the substrate publishes them separately: the
    summary's `domains` map carries the per-domain STATUS (a string -- the
    coverage record), and the deep-dive history carries the per-domain
    RESULT (answer, evidence, reason, tool spend) under `domain:<key>`.
    Reading only the summary would produce statuses with nothing behind
    them; reading only the history would miss a domain the graph recorded
    as failed.

    The per-domain entries become regions under the SAME four-status
    vocabulary and the SAME citation rule as D0, so both profiles' maps are
    read by the same consumers. A node's status outside the vocabulary, or a
    claim with no evidence, is graded conservatively here exactly as
    `investigate_region` grades it -- the substrate changes, the honesty rule
    does not.
    """
    folded: dict[str, dict] = {}
    dom = dom or {}
    findings = dom.get("findings") or {}
    dg = findings.get("domain_graph") or {}
    statuses = dg.get("domains") or {}
    details: dict[str, dict] = {}
    for h in dom.get("history") or []:
        tool = str(h.get("tool") or "")
        if tool.startswith("domain:"):
            res = h.get("result")
            details[tool.split(":", 1)[1]] = res if isinstance(res, dict) else {}
    findings_text = str(findings.get("domain_findings") or "")
    for key, status in statuses.items():
        entry = details.get(key) or {}
        status = str(status or "").strip().lower() or str(
            entry.get("status") or "").strip().lower()
        evidence = [str(e)[:160] for e in (entry.get("evidence") or [])[:8]]
        answer = str(entry.get("answer") or "")[:1200]
        reason = str(entry.get("reason") or "")[:400]
        region = {
            "status": status,
            "answer": answer,
            "evidence": evidence,
            "reason": reason,
            "substrate": "domain-graph",
            "tool_calls_used": entry.get("tool_calls_used"),
            "investigated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime()),
        }
        has_answer = bool(answer) or bool(evidence)
        if status not in VALID_STATUSES:
            region["model_status"] = status or "(none)"
            region["status"] = STATUS_PARTIAL
            region["reason"] = reason or (
                f"node returned status {status!r}, outside the vocabulary")
            region["status_contradicts_answer"] = True
        elif status == STATUS_NOT_EXPLORED and has_answer:
            # Claimed it did not look, and supplied an answer anyway: the
            # answer is evidence it WAS investigated. Same grading the domain
            # nodes apply (agentic_langgraph) and investigate_region applies.
            region["model_status"] = status
            region["status"] = STATUS_PARTIAL
            region["reason"] = reason or (
                "node claimed not-explored while supplying an answer")
            region["status_contradicts_answer"] = True
        # else: the claimed status stands -- including an honest not-explored
        # with nothing supplied.
        if status_requires_evidence(region["status"]) and not evidence:
            if region["status"] == STATUS_UNDERSTOOD:
                region["status"] = STATUS_PARTIAL
                region["reason"] = (
                    (region.get("reason") or "")
                    + " | downgraded from understood: no evidence cited")
                region["downgraded_for_no_evidence"] = True
        if findings_text:
            region["domain_findings_excerpt"] = findings_text[:4000]
        folded[key] = region
    return folded


def _stream_emit(case: Path, event: dict) -> None:
    """Append one event to the Phase 0 state stream (best-effort).

    The stream is the audit trail of the depth run; a failure to write it
    must never fail the investigation, so this is deliberately silent on
    error -- understanding.json remains the artifact of record.
    """
    try:
        import re_state
        fields = {k: v for k, v in (event or {}).items() if k != "kind"}
        re_state.append_event(Path(case) / re_state.EVENT_FILE,
                              event.get("kind", "note"), **fields)
    except Exception:
        pass


def _stream_region(case: Path, name: str, region: dict, *,
                   include_spend: bool = True) -> None:
    """Emit a region's status (and its spend) to the stream."""
    try:
        import re_state
        ev = re_state.region_event({}, name, region.get("status", ""),
                                   region.get("reason", ""),
                                   region.get("evidence") or [])
        _stream_emit(case, ev)
        if include_spend:
            _stream_emit(case, {"kind": "spend", "llm_calls": 1,
                                "seconds": float(region.get("seconds") or 0.0),
                                "domain_investigations": 1,
                                "token_usage_complete": False})
    except Exception:
        pass


def _stream_snapshot(case: Path) -> None:
    """Fold the log into the snapshot beside it (best-effort)."""
    try:
        import re_state
        events, _dropped = re_state.load_log(Path(case) / re_state.EVENT_FILE)
        re_state.save_checkpoint(Path(case), re_state.fold_events(events))
    except Exception:
        pass


def _run_full_profile(case: Path, ceiling: int, st: dict,
                      t0: float) -> str | None:
    """Drive the full profile: domain-graph passes until costed or ceiling.

    One pass investigates every domain on the #20 substrate; the loop's
    normal termination rules then apply (attempts, examiner stop, ceiling),
    and every exit consolidates. Returns the stop_reason, or None to fall
    through to the shared tail.
    """
    import re_state  # noqa: F401  (availability probe; import errors surface below)

    sha = _case_sample_sha(case)
    if sha:
        st["sha256"] = sha
    forced = _force_full_profile_features()
    st["profile"] = PROFILE_FULL
    st["substrate"] = "domain-graph (#20)"
    st["forced_features"] = forced
    _stream_emit(case, {"kind": "init", "sample_sha256": sha,
                        "run_id": str(int(time.time()))})
    _stream_emit(case, {"kind": "phase", "phase": "investigate"})

    attempts_allowed = _max_attempts()
    stop_reason = None
    while True:
        pending = [n for n in unknown_set(st["regions"])
                   if int((st["regions"].get(n) or {}).get("attempts") or 0)
                   < attempts_allowed]
        if not pending:
            remaining = unknown_set(st["regions"])
            stop_reason = (
                "converged: every region understood" if not remaining else
                f"costed: {len(remaining)} region(s) investigated and still "
                f"unknown ({', '.join(remaining)}) -- declared, not retried")
            break
        if _stop_requested(case):
            stop_reason = (f"stopped by examiner (depth.stop); "
                           f"{len(pending)} region(s) still unattempted")
            break
        elapsed = time.time() - t0
        if elapsed >= ceiling:
            stop_reason = (
                f"ceiling reached after {int(elapsed)}s; "
                f"{len(pending)} region(s) unattempted -- consolidated, "
                "not truncated")
            break
        before = time.time()
        dom = run_domain_depth_pass(sha, case)
        pass_seconds = round(time.time() - before, 1)
        usage = _depth_progress_usage(case)
        spend = st["spend"]
        spend["llm_calls"] = int(spend.get("llm_calls") or 0) + usage["llm_calls"]
        spend["tokens"] = int(spend.get("tokens") or 0) + usage["tokens"]
        spend["seconds"] = round(
            float(spend.get("seconds") or 0.0) + pass_seconds, 1)
        spend["domain_investigations"] = (
            int(spend.get("domain_investigations") or 0) + len(pending))
        spend["token_usage_missing_responses"] = (
            int(spend.get("token_usage_missing_responses") or 0)
            + usage["token_usage_missing_responses"])
        previous_complete = spend.get("token_usage_complete")
        spend["token_usage_complete"] = (
            usage["token_usage_complete"] if previous_complete is None
            else bool(previous_complete) and usage["token_usage_complete"])
        spend["progress_malformed_lines"] = (
            int(spend.get("progress_malformed_lines") or 0)
            + usage["progress_malformed_lines"])
        _stream_emit(case, {
            "kind": "spend",
            "llm_calls": usage["llm_calls"],
            "seconds": pass_seconds,
            "tokens": usage["tokens"],
            "domain_investigations": len(pending),
            "token_usage_complete": usage["token_usage_complete"],
        })
        if not dom:
            stop_reason = (
                "domain-graph pass produced no usable result; the flat "
                "evidence-only investigation was NOT substituted for it -- "
                "a stated failure beats a fabricated unknown")
            _stream_emit(case, {"kind": "phase", "phase": "failed"})
            break
        folded = _fold_domain_results(st, dom)
        pass_seconds = round(time.time() - before, 1)
        for name in pending:
            region = st["regions"].get(name) or {}
            # EVERY pending region spends an attempt, returned or not: the
            # pass investigated it. Without this a substrate that never
            # answers a region leaves its attempts at zero and the loop
            # spins on it forever -- the 27M-call defect the attempts bound
            # exists to prevent.
            region["attempts"] = int(region.get("attempts") or 0) + 1
            if name in folded:
                new = dict(folded[name])
                new["attempts"] = region["attempts"]
                st["regions"][name] = new
                _stream_region(case, name, new, include_spend=False)
            else:
                region["reason"] = (
                    (region.get("reason") or "")
                    + " | the domain-node pass returned no determination "
                    "for this region; it stays unknown and costed").lstrip(" |")
                st["regions"][name] = region
                _stream_region(case, name, region, include_spend=False)
        save_state(case, st)
        _stream_snapshot(case)

    st["stop_reason"] = stop_reason
    st["converged"] = has_converged(st["regions"])
    st["cost"] = cost_summary(st["regions"], st["spend"])
    st["attempts_allowed"] = attempts_allowed
    # The gap section is REQUIRED for the full profile: every region carries
    # a status and a reason, and the unknown set is declared with its cost.
    st["gap_section"] = {
        "unknown_regions": unknown_set(st["regions"]),
        "by_status": st["cost"]["by_status"],
        "regions_total": st["cost"]["regions_total"],
        "unknown_remaining": st["cost"]["unknown_remaining"],
    }
    _stream_emit(case, {"kind": "phase", "phase": "consolidated"})
    _stream_snapshot(case)
    save_state(case, st)
    return stop_reason


def _max_attempts() -> int:
    """How many times one region may be investigated. Default 1.

    Retrying a region that just came back unknown is how the loop spins: the
    same question, the same tools, the same answer, forever -- measured on
    packed_rook_native at 27 MILLION llm_calls for three regions, because a
    non-converging region was picked again and again. A region that stays
    unknown after its attempts is COSTED, not retried; that is what makes the
    run terminate.
    """
    raw = os.environ.get("REVAI_DEPTH_MAX_ATTEMPTS", "").strip()
    if not raw:
        return 1
    try:
        val = int(raw)
    except ValueError:
        return 1
    return val if val > 0 else 1


def _seed_all_domains(st: dict) -> list[str]:
    """Seed EVERY capability domain as a region (the full profile's seeding).

    D0 seeds only what the flat pipeline could NOT establish, because D0's
    objective is gap-filling. The full profile's objective is a COMPLETE
    understanding map, so every domain in the #20 vocabulary is a region:
    on a packed sample the flat pipeline's domains are "observed" from the
    STUB (#58) or the ledger is absent entirely (`depth_coverage: null`,
    measured on the UPX sample 2026-10-13), and gap-only seeding would map
    nothing -- a depth run that produces no map has failed its objective.

    A region the flat pipeline DID establish keeps that provenance recorded,
    so the map distinguishes what the substrate established from what it
    inherited. Returns the names added.
    """
    added = []
    questions = _domain_questions()
    for key in questions:
        if key in st["regions"]:
            continue
        st["regions"][key] = {
            "status": STATUS_NOT_EXPLORED,
            "reason": "seeded by the full profile: every capability domain "
                      "is a region of the understanding map",
            "evidence": [],
            "attempts": 0,
            "substrate": "domain-graph",
        }
        added.append(key)
    return added


def run_depth_loop(case: Path, ceiling: int | None = None) -> dict:
    """The convergence loop: deepen every seeded region until understood or costed.

    Terminates on ANY of: every region understood, every region attempted, the
    wall-clock ceiling, or the examiner's stop file. Every exit consolidates --
    a cutoff yields a partial-but-honest map, never nothing.

    Checkpoints after EVERY region, so a pause is a resume rather than a restart.

    `REVAI_DEPTH=full` (#26) drives the SAME loop with the domain-node
    substrate: one graph pass investigates every region with tool access,
    under the raised ceiling, emitting the Phase 0 state stream. The
    vocabulary, the termination rules and the honesty rules are shared; only
    the investigation substrate and the budget differ.
    """
    case = Path(case)
    profile = depth_profile()
    ceiling = ceiling if ceiling is not None else ceiling_seconds(profile)
    t0 = time.time()
    st = load_state(case)
    st.setdefault("regions", {})
    if not isinstance(st.get("spend"), dict):
        st["spend"] = {"llm_calls": 0, "seconds": 0.0, "tokens": 0}
    else:
        st["spend"].setdefault("llm_calls", 0)
        st["spend"].setdefault("seconds", 0.0)
        st["spend"].setdefault("tokens", 0)
    for key, default in (
            ("domain_investigations", 0),
            ("token_usage_complete", None),
            ("token_usage_missing_responses", 0),
            ("progress_malformed_lines", 0)):
        st["spend"].setdefault(key, default)
    sample_sha = _case_sample_sha(case, st.get("sha256"))
    if sample_sha:
        st["sha256"] = sample_sha
    st["profile"] = profile or PROFILE_D0

    # Resume: regions already carried keep their status; only re-seed the ones
    # that were never investigated.
    seeded = seed_regions(case)
    for name, region in seeded.items():
        st["regions"].setdefault(name, region)
    if profile == PROFILE_FULL:
        # The full profile maps EVERY capability domain, not just the gaps
        # (see _seed_all_domains: a packed sample's ledger is stub-derived or
        # absent, and gap-only seeding would produce an empty map).
        _seed_all_domains(st)
    if not st["regions"]:
        st["stop_reason"] = (
            "no-regions-to-deepen: every capability domain the main pipeline "
            "examined already carries an evidence-backed determination, or the "
            "run produced no capability ledger. Nothing to converge on.")
        st["gap_section"] = {"unknown_regions": [], "regions_total": 0,
                             "note": st["stop_reason"]}
        save_state(case, st)
        _stream_emit(case, {"kind": "phase", "phase": "no-regions"})
        _stream_snapshot(case)
        return st

    if profile == PROFILE_FULL:
        with _preserve_pipeline_deep_dive(case) as depth_artifacts:
            _run_full_profile(case, ceiling, st, t0)
        st["depth_artifact_dir"] = str(depth_artifacts.relative_to(case))
        st["pipeline_deep_dive_preserved"] = True
        save_state(case, st)
        return st

    attempts_allowed = _max_attempts()
    stop_reason = None
    while True:
        # Only regions that have NOT exhausted their attempts. A region that was
        # investigated and came back unknown stays in the unknown set -- it is
        # reported as a cost, not retried into an infinite loop.
        pending = [
            n for n in unknown_set(st["regions"])
            if int((st["regions"].get(n) or {}).get("attempts") or 0)
            < attempts_allowed
        ]
        if not pending:
            remaining = unknown_set(st["regions"])
            stop_reason = (
                "converged: every region understood" if not remaining else
                f"costed: {len(remaining)} region(s) investigated and still "
                f"unknown ({', '.join(remaining)}) -- declared, not retried")
            break
        if _stop_requested(case):
            stop_reason = (f"stopped by examiner (depth.stop); "
                           f"{len(pending)} region(s) still unattempted")
            break
        elapsed = time.time() - t0
        if elapsed >= ceiling:
            stop_reason = (
                f"ceiling reached after {int(elapsed)}s; "
                f"{len(pending)} region(s) unattempted -- consolidated, "
                "not truncated")
            break

        name = pending[0]
        region = st["regions"][name]
        region["attempts"] = int(region.get("attempts") or 0) + 1
        before = time.time()
        st["regions"][name] = investigate_region(case, name, region)
        st["spend"]["llm_calls"] = int(st["spend"].get("llm_calls", 0)) + 1
        st["spend"]["domain_investigations"] = (
            int(st["spend"].get("domain_investigations", 0) or 0) + 1)
        st["spend"]["token_usage_complete"] = False
        st["spend"]["seconds"] = round(
            float(st["spend"].get("seconds", 0.0)) + (time.time() - before), 1)
        # Checkpoint after EVERY region: a pause is a resume.
        save_state(case, st)

    st["stop_reason"] = stop_reason
    st["converged"] = has_converged(st["regions"])
    st["cost"] = cost_summary(st["regions"], st["spend"])
    st["attempts_allowed"] = attempts_allowed
    # The gap section, and the Phase 0 stream, for D0 as well: the two
    # profiles' maps and trails are read by the same consumers.
    st["gap_section"] = {
        "unknown_regions": unknown_set(st["regions"]),
        "by_status": st["cost"]["by_status"],
        "regions_total": st["cost"]["regions_total"],
        "unknown_remaining": st["cost"]["unknown_remaining"],
    }
    _stream_emit(case, {"kind": "init", "sample_sha256": st.get("sha256") or "",
                        "run_id": str(int(t0))})
    for _name, _r in st["regions"].items():
        _stream_region(case, _name, _r)
    _stream_emit(case, {"kind": "phase", "phase": "consolidated"})
    _stream_snapshot(case)
    save_state(case, st)
    return st


def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="depth mode")
    ap.add_argument("target", nargs="?",
                    help="case directory (default: read REVAI_CASE_DIR)")
    ap.add_argument("--status", action="store_true",
                    help="report the depth state as JSON and exit")
    ap.add_argument("--run", action="store_true",
                    help="run the convergence loop (deepen every region the "
                         "main pipeline could not establish)")
    args = ap.parse_args()

    # Resolve the case dir the SAME way the other stages do. The first version
    # took a bare path and pipeline_single passed a sha, so the stage read
    # /opt/samples/logs/<sha>/understanding.json -- a path that never exists --
    # and reported an empty map with rc=0. That is indistinguishable in the trace
    # from 'the sample has no functions', which is exactly the hollow-success
    # failure the rest of the pipeline gates against.
    case = None
    target = args.target or os.environ.get("REVAI_CASE_DIR", "")
    if target:
        p = Path(target)
        if p.is_dir():
            case = p
        else:
            # A sha resolves through case_dir() -- but case_dir() CREATES the
            # directory, so `is_dir()` is always True afterwards and the
            # "fail loudly when the case does not exist" branch below could
            # never fire. The stage would resolve a sha that was never run,
            # report an empty map and exit 0 -- the hollow green this whole
            # path exists to prevent. Check whether the case existed BEFORE
            # resolving, which is the only thing that distinguishes "a sample
            # that was run" from "a sha nobody has analysed".
            from v2_lib import LOGS_DIR
            _logs = Path(os.environ.get("REVAI_LOGS_DIR") or LOGS_DIR)
            _pre_existing = _logs.is_dir() and (_logs / target).exists()
            try:
                from v2_lib import case_dir
                case = case_dir(target)
            except Exception:
                case = p
            if not _pre_existing:
                print(f"[depth] case for {target[:16]}... does not exist under "
                      f"{_logs}: the sample has not been run, so there is nothing "
                      "to deepen. Run the pipeline first.",
                      file=sys.stderr, flush=True)
                return 3

    if case is None:
        print(f"depth enabled: {depth_enabled()}  "
              f"profile: {depth_profile() or PROFILE_D0}  "
              f"ceiling: {ceiling_seconds()}s")
        return 0

    if args.run:
        if case is None:
            print("[depth] --run needs a case directory or a run sha",
                  file=sys.stderr, flush=True)
            return 2
        st = run_depth_loop(case)
        summary = cost_summary(st.get("regions"), st.get("spend") or {})
        summary["case_dir"] = str(case)
        summary["converged"] = st.get("converged")
        summary["stop_reason"] = st.get("stop_reason")
        summary["profile"] = st.get("profile") or depth_profile() or PROFILE_D0
        if st.get("substrate"):
            summary["substrate"] = st["substrate"]
        if st.get("gap_section"):
            summary["gap_section"] = st["gap_section"]
        print(json.dumps(summary, indent=2))
        # rc=0 only when the loop actually ran. An empty region set is an honest
        # outcome, not a failure, but it is reported on stderr so a hollow run
        # cannot look like a converged one.
        if not st.get("regions"):
            print(f"[depth] {st.get('stop_reason')}", file=sys.stderr, flush=True)
        return 0

    st = load_state(case)
    summary = cost_summary(st["regions"], st["spend"])
    summary["case_dir"] = str(case)
    summary["converged"] = has_converged(st["regions"])
    summary["stop_reason"] = st.get("stop_reason")

    # A depth run that has done nothing must not read as a depth run that
    # finished. This invocation REPORTED state; it did not investigate anything
    # (no regions, no spend). The convergence loop exists and is driven by
    # --run; an empty map here means no depth run has been performed on this
    # case, which is exactly the hollow-success shape the rest of the pipeline
    # gates against.
    spend = st.get("spend") or {}
    if not st.get("regions") and not spend.get("llm_calls"):
        summary["stop_reason"] = (
            "no-depth-analysis-performed: this invocation reported the case's "
            "depth state and investigated nothing. The convergence loop exists "
            "and is driven by `depth_agent.py <case> --run`; no depth run has "
            "been performed on this case. regions_total=0 means nothing was "
            "looked at, not that the sample has no functions."
        )
        summary["depth_run_with"] = "depth_agent.py <case> --run"
        print("[depth] WARNING: no depth analysis has been performed on this "
              "case. Run `depth_agent.py <case> --run` to deepen the capability "
              "domains the main pipeline could not establish.",
              file=sys.stderr, flush=True)
        # Write the artifact with that reason inside it. A stage that produced
        # nothing and left no trace is indistinguishable in the trace from one
        # that legitimately found nothing.
        try:
            out = case / "understanding.json"
            out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            summary["understanding_json"] = str(out)
        except OSError as exc:
            print(f"[depth] could not write understanding.json: {exc}",
                  file=sys.stderr, flush=True)

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
