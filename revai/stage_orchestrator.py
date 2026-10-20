#!/usr/bin/env python3
"""
stage_orchestrator.py — LangGraph ReAct stage orchestrator.

Real agentic control plane (create_react_agent + StructuredTools), NOT a fixed
subprocess wrapper loop. The LLM planner chooses stage tools; deep_dive_agentic
itself runs LangGraph ReAct over the RE ToolRegistry.

Stages (core only — no Flare/dynamic):
  intake → quick_scan → deep_dive_agentic → yara → publish → section → audit

Usage:
  python3 /opt/scripts/stage_orchestrator.py /path/to/sample.exe
  python3 /opt/scripts/stage_orchestrator.py --sha <sha256>   # resume after intake
  REVAI_HITL_VERDICT=1 python3 ...   # stop before publish if quick≠deep

Traces: logs/<sha>/orchestrator_trace.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    LOGS_DIR,
    SESSIONS_DIR,
    begin_execution,
    case_dir,
    current_run_id,
    ensure_pipeline_runtime_env,
    get_llm_chat_options,
    get_llm_temperature,
    get_planner_model,
    get_verdict_model,
    get_llm_model,
    is_transient_failure,
    load_session,
    revai_provenance,
    run_profile,
    update_session,
)
from report_quality import evaluate_sha_publish_quality  # noqa: E402

SCRIPTS = Path(os.environ.get("REVAI_SCRIPTS_DIR") or "/opt/scripts")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _truncate(s: str, n: int = 4000) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"... (truncated {len(s) - n} chars)"


def _verdict_label(v: str) -> str:
    """Normalize a verdict string to its core label for conflict comparison.

    Verdicts are prose ("malicious (lumma info stealer)", "MALWARE — packed
    loader", "suspicious: likely X"). String inequality would flag harmless
    wording differences as HITL conflicts, so we reduce to the dominant
    verdict token. Unknown/empty stays "".
    """
    v = (v or "").strip().lower()
    if not v:
        return ""
    for tok in (
        "malware", "malicious", "suspicious", "clean", "benign", "legitimate",
        "unknown", "undetermined", "troj", "rat", "stealer", "dropper",
        "loader", "ransomware", "packed", "crypter", "backdoor", "worm",
        "miner", "banker", "spyware", "adware", "phishing", "spam", "pua",
        "keylogger", "infostealer", "reconnaissance", "apt",
    ):
        if tok in v:
            return tok
    # fall back to the first token of the prose
    return v.split()[0] if v.split() else ""


def _planner_stage_order(
    *,
    need_intake: bool,
    winre: bool,
    function_recovery: bool,
    artifact_gen: bool,
    behavioural_model: bool,
    depth: bool,
) -> str:
    """Return the agentic plan order, including every enabled optional stage."""
    stages: list[str] = []
    if need_intake:
        stages.append("run_intake")
    stages.append("run_quick_scan")
    if winre:
        stages.append("run_winre_dynamic")
    stages.extend(("run_deep_dive_agentic", "read_verdicts"))
    if function_recovery:
        stages.append("run_function_recovery")
    if artifact_gen:
        stages.append("run_artifact_gen")
    if behavioural_model:
        stages.append("run_behavioural_model")
    stages.extend((
        "run_yara_gen", "run_publish",
        "run_section_publish", "run_audit", "check_quality",
    ))
    if depth:
        stages.append("run_depth")
    return " → ".join(stages)


def _stage_timeout(env_name: str, default: int) -> int:
    """Resolve a positive per-stage timeout override, falling back safely."""
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(
            f"[orchestrator] {env_name}={raw!r} is not a number; using {default}",
            file=sys.stderr,
            flush=True,
        )
        return default
    return value if value > 0 else default


def _verdicts(sha: str) -> dict[str, str]:
    qv = dv = ""
    try:
        p = case_dir(sha) / "verdict.json"
        if p.exists():
            qv = str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        pass
    try:
        p = case_dir(sha) / "deep_dive" / "05-deep-dive.json"
        if p.exists():
            dv = str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        pass
    ql, dl = _verdict_label(qv), _verdict_label(dv)
    return {
        "quick": qv,
        "deep": dv,
        "quick_label": ql,
        "deep_label": dl,
        "conflict": bool(ql and dl and ql != dl),
    }


def _reconcile_deep_verdict(sha: str, *, hitl_enabled: bool = False) -> dict[str, Any]:
    """Persist the deterministic verdict reconciliation before report stages.

    The deep-dive artifact is evidence consumed by both publishers. Mutating it
    after publication makes the reports stale and fails the freshness audit, so
    every publish entry point runs this idempotent step first.
    """
    if hitl_enabled:
        return {"ok": True, "changed": False, "reason": "hitl_verdict_enabled"}

    verdicts = _verdicts(sha)
    if not verdicts.get("conflict"):
        return {"ok": True, "changed": False, "reason": "verdicts_aligned"}

    strict = {"malicious": 3, "suspicious": 2, "benign": 1}
    quick_label = verdicts.get("quick_label") or ""
    deep_label = verdicts.get("deep_label") or ""
    if strict.get(quick_label, 0) <= strict.get(deep_label, 0):
        return {"ok": True, "changed": False, "reason": "deep_verdict_not_less_severe"}

    deep_path = case_dir(sha) / "deep_dive" / "05-deep-dive.json"
    if not deep_path.is_file():
        return {"ok": False, "changed": False,
                "reason": "deep_artifact_missing", "path": str(deep_path)}
    temporary: Path | None = None
    try:
        deep = json.loads(deep_path.read_text(encoding="utf-8"))
        if not isinstance(deep, dict):
            raise ValueError("deep artifact must contain a JSON object")
        deep["verdict"] = verdicts["quick"]
        deep["verdict_reconciled"] = {
            "from": verdicts["deep"],
            "to": verdicts["quick"],
            "quick_label": quick_label,
            "reason": (
                "Deterministic quick-triage evidence (capa/YARA/Malcat/imports) "
                f"outranks the conflicting deep-dive label ({deep_label})."
            ),
        }
        prior_summary = str(deep.get("summary") or "")
        marker = f"[VERDICT RECONCILED: deep={deep_label} -> {quick_label}"
        if marker not in prior_summary:
            deep["summary"] = f"{prior_summary} {marker} from quick triage]".strip()
        temporary = deep_path.with_name(f".{deep_path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(deep, indent=2, default=str), encoding="utf-8")
        os.replace(temporary, deep_path)
        return {
            "ok": True, "changed": True,
            "from": verdicts["deep"], "to": verdicts["quick"],
            "path": str(deep_path),
        }
    except Exception as exc:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except Exception:
                pass
        return {"ok": False, "changed": False,
                "reason": f"deep_artifact_reconciliation_failed:{type(exc).__name__}:{exc}",
                "path": str(deep_path)}


class StageRunner:
    """Execute one spine stage; record every call for orchestrator_trace."""

    def __init__(self, sha: str, sample: Path | None, events: list[dict]):
        self.sha = sha
        self.sample = sample
        self.events = events
        self._report_stage_calls: dict[str, int] = {}
        self.run_log = case_dir(sha) / "orchestrator.log"
        self.run_log.parent.mkdir(parents=True, exist_ok=True)

    def _claim_report_stage(self, name: str) -> dict[str, Any] | None:
        """Make each expensive report publisher single-shot per pipeline run.

        LLM tool-call instructions are advisory. A duplicate call must not
        silently regenerate an entire report set, overwrite the first attempt,
        and turn a false-positive audit into another hour of model traffic.
        Individual publisher calls keep their own bounded section-level repair.
        """
        attempt = self._report_stage_calls.get(name, 0) + 1
        self._report_stage_calls[name] = attempt
        if attempt == 1:
            return None
        event = {
            "type": "tool_result", "tool": name,
            "cmd": ["single_shot_report_stage_guard"],
            "rc": 1, "ok": False, "elapsed_s": 0.0,
            "ts": _utc(), "attempt": attempt, "timed_out": False,
            "artifacts_written": False,
            "failure_reason": (
                f"duplicate {name} invocation blocked; report stages run once "
                "per pipeline execution and must not overwrite their first artifacts"
            ),
        }
        self.events.append(event)
        print(f"[orchestrator] {event['failure_reason']}", flush=True)
        return {key: value for key, value in event.items() if key != "type"}

    def _run(
        self,
        name: str,
        cmd: list[str],
        timeout: int,
        *,
        retry_timeouts: bool = True,
        retry_stage_failures: bool = True,
    ) -> dict[str, Any]:
        """Execute one spine stage with bounded transient retries.

        Retry policy (run_profile): rc!=0 whose failure text classifies as
        transient (tool timeout, MCP/server connection loss, OOM) is retried
        up to `stage_retries` times unless the caller disables whole-stage
        retries. Attempts are recorded on the tool_result event. Publishers and
        the semantic audit can disable retries because their partial output has
        no reliable whole-stage resume contract.
        """
        profile = run_profile()
        retries = int(profile.get("stage_retries") or 0)
        transient_only = bool(profile.get("retry_transient_only", True))
        attempts = 0
        last_rc = -1
        reason = ""
        timed_out = False
        retry_suppressed = False
        while True:
            attempts += 1
            marker = f"===== {_utc()} {name} ATTEMPT {attempts} CMD {' '.join(cmd)}\n"
            print(f"[orchestrator] TOOL {name} (attempt {attempts}): {' '.join(cmd)}", flush=True)
            st = time.time()
            rc = None
            timed_out = False
            with self.run_log.open("a", encoding="utf-8") as lf:
                lf.write(marker)
                lf.flush()
                try:
                    p = subprocess.run(
                        cmd,
                        stdout=lf,
                        stderr=subprocess.STDOUT,
                        timeout=timeout,
                        env=os.environ.copy(),
                    )
                    rc = int(p.returncode)
                    lf.write(f"===== rc={rc}\n")
                except subprocess.TimeoutExpired:
                    rc = 124
                    timed_out = True
                    lf.write("===== TIMEOUT\n")
            reason = self._failure_reason(marker)
            last_rc = rc
            entry = {
                "type": "tool_result",
                "tool": name,
                "cmd": cmd,
                "rc": rc,
                "ok": rc == 0,
                "elapsed_s": round(time.time() - st, 1),
                "ts": _utc(),
                "attempt": attempts,
                "timed_out": timed_out,
            }
            self.events.append(entry)
            print(f"[orchestrator] {name} rc={rc} {entry['elapsed_s']}s", flush=True)
            if timed_out and not retry_timeouts:
                retry_suppressed = True
                entry["retry_suppressed"] = "timed_out_non_resumable_stage"
                print(
                    f"[orchestrator] {name} timed out; not retrying the "
                    "non-resumable stage",
                    flush=True,
                )
                break
            if rc == 0 or attempts > retries or not retry_stage_failures:
                if rc != 0 and not retry_stage_failures and attempts <= retries:
                    print(
                        f"[orchestrator] {name} whole-stage retry disabled; "
                        "preserving the failed audit result",
                        flush=True,
                    )
                break
            if transient_only and not is_transient_failure(reason):
                print(
                    f"[orchestrator] {name} rc={rc} NOT retried (non-transient): "
                    f"{reason[:160]}",
                    flush=True,
                )
                break
            print(
                f"[orchestrator] {name} rc={rc} transient -> retry "
                f"{attempts}/{retries + 1} ({reason[:160]})",
                flush=True,
            )
        out = {
            "ok": last_rc == 0,
            "rc": last_rc,
            "elapsed_s": entry["elapsed_s"],
            "sha256": self.sha,
            "tool": name,
            "attempts": attempts,
            "failure_reason": (reason or "")[:500],
            "timed_out": timed_out,
        }
        if retry_suppressed:
            out["retry_suppressed"] = "timed_out_non_resumable_stage"
        if attempts > 1:
            out["retried"] = True
            out["retry_reason"] = (reason or "")[:500]
        return out

    def _failure_reason(self, marker: str) -> str:
        """Pull the failure text of the last stage attempt from the run log."""
        try:
            txt = self.run_log.read_text(encoding="utf-8", errors="replace")
            idx = txt.rfind(marker)
            if idx < 0:
                return ""
            return txt[idx : idx + 12000]
        except Exception:
            return ""

    def run_intake(self) -> dict:
        if self.sample is None or not self.sample.is_file():
            return {"ok": False, "error": "sample path required for intake"}
        project = self.sample.parent.parent.name if self.sample.parent.parent else "v63"
        cmd = [
            sys.executable, str(SCRIPTS / "intake_v2.py"), str(self.sample),
            "--project-name", project[:64], "--mode", "large",
        ]
        out = self._run("run_intake", cmd, 7200)
        if out.get("ok"):
            try:
                update_session(self.sha, {
                    "pipeline_mode": "single",
                    "pipeline_mode_source": "stage_orchestrator",
                    "pipeline_mode_reasons": ["v6.3_langgraph_react"],
                })
            except Exception as e:
                out["session_warn"] = str(e)
        return out

    def run_quick_scan(self) -> dict:
        return self._run(
            "run_quick_scan",
            [sys.executable, str(SCRIPTS / "quick_scan_v2.py"), self.sha],
            7200,
        )

    def run_deep_dive_agentic(self) -> dict:
        # Nested LangGraph ReAct (REVAI_AGENTIC_ENGINE=langgraph)
        env_note = os.environ.get("REVAI_AGENTIC_ENGINE") or "langgraph"
        winre_requested = (os.environ.get("REVAI_WINRE_RUN") or "").strip().lower() in (
            "1", "true", "yes",
        )
        winre_recorded = any(
            e.get("type") == "tool_result" and e.get("tool") == "run_winre_dynamic"
            for e in self.events
        )
        if winre_requested and not winre_recorded:
            # The dynamic pack is an input to the deep-dive prompt. Enforce this
            # dependency at the stage boundary in case the planner omits the
            # optional tool despite the configured plan.
            print(
                "[orchestrator] WinRE is enabled but was not run before deep dive; "
                "running the configured pre-dive stage now",
                flush=True,
            )
            self.run_winre_dynamic()
        out = self._run(
            "run_deep_dive_agentic",
            [
                sys.executable, str(SCRIPTS / "deep_dive_agentic.py"),
                self.sha, "--engine", "langgraph",
            ],
            14400,
        )
        out["agentic_engine"] = env_note
        return out

    def run_function_recovery(self) -> dict:
        """Optional v4 stage: recover symbols/types via call-graph LLM analysis.

        Skips (rc=0, skipped=True) unless REVAI_ENABLE_AGENTIC_RECOVERY=1.
        """
        enabled = (
            os.environ.get("REVAI_ENABLE_AGENTIC_RECOVERY")
            or os.environ.get("ENABLE_AGENTIC_RECOVERY", "0")
        ).strip().lower() in ("1", "true", "yes")
        if not enabled:
            print("[orchestrator] run_function_recovery skipped (env not set)", flush=True)
            return {"ok": True, "rc": 0, "skipped": True, "sha256": self.sha, "tool": "run_function_recovery"}
        out = self._run(
            "run_function_recovery",
            [sys.executable, str(SCRIPTS / "agentic_recover_v4.py"), self.sha],
            3600,
        )
        return out

    def run_artifact_gen(self) -> dict:
        """Optional stage 3.6: verifiable artifact generation (plan #11).

        Generates a sample-specific extraction script, runs it in a bounded
        sandbox, and re-derives every claimed value from the sample bytes
        deterministically. Skips (rc=0) unless REVAI_ENABLE_ARTIFACT_GEN=1; never
        gates the verdict, and publish attaches a presence-gated appendix.
        """
        if not (os.environ.get("REVAI_ENABLE_ARTIFACT_GEN") or "").strip().lower() in (
            "1", "true", "yes", "on",
        ):
            print("[orchestrator] run_artifact_gen skipped (env not set)", flush=True)
            return {"ok": True, "rc": 0, "skipped": True, "sha256": self.sha,
                    "tool": "run_artifact_gen", "reason": "REVAI_ENABLE_ARTIFACT_GEN not set"}
        return self._run(
            "run_artifact_gen",
            [sys.executable, str(SCRIPTS / "artifact_gen.py"), self.sha],
            1800,
        )

    def run_yara_gen(self) -> dict:
        return self._run(
            "run_yara_gen",
            [sys.executable, str(SCRIPTS / "yara_gen_v2.py"), self.sha],
            1800,
        )

    def run_winre_dynamic(self) -> dict:
        """Optional: detonate the sample on the WinRE FlareVM, pull the pack.

        Runs only when REVAI_WINRE_RUN=1 AND WinRE is installed + configured
        (Console Settings -> Dynamic analysis (WinRE)). When explicitly enabled,
        a missing driver, failed detonation or uncorrelated evidence is a tool
        failure; it must not produce a green dynamic run using stale evidence.
        """
        run_enabled = os.environ.get("REVAI_WINRE_RUN", "").strip().lower() in (
            "1", "true", "yes",
        )
        if not run_enabled:
            print(
                "[orchestrator] run_winre_dynamic skipped (REVAI_WINRE_RUN not set)",
                flush=True,
            )
            out = {
                "ok": True, "rc": 0, "skipped": True,
                "tool": "run_winre_dynamic",
                "reason": "REVAI_WINRE_RUN not set",
            }
            self.events.append({"type": "tool_result", **out, "ts": _utc()})
            return out
        try:
            from winre_runner import availability, run_dynamic
        except Exception as e:
            print(f"[orchestrator] run_winre_dynamic unavailable: {e}", flush=True)
            out = {"ok": False, "rc": 1, "skipped": False,
                   "tool": "run_winre_dynamic", "reason": f"winre_runner import failed: {e}"}
            self.events.append({"type": "tool_result", **out, "ts": _utc()})
            return out
        try:
            ok, reason = availability()
        except Exception as e:
            out = {"ok": False, "rc": 1, "skipped": False,
                   "tool": "run_winre_dynamic",
                   "reason": f"availability check failed: {type(e).__name__}: {e}"}
            self.events.append({"type": "tool_result", **out, "ts": _utc()})
            return out
        if not ok:
            print(f"[orchestrator] run_winre_dynamic unavailable: {reason}", flush=True)
            out = {"ok": False, "rc": 1, "skipped": False,
                   "tool": "run_winre_dynamic", "reason": reason}
            self.events.append({"type": "tool_result", **out, "ts": _utc()})
            return out
        try:
            out = run_dynamic(
                self.sha,
                sample_path=str(self.sample) if self.sample else None,
                run_id=current_run_id(self.sha),
            )
        except Exception as e:
            out = {
                "ok": False,
                "rc": 1,
                "state": "error",
                "error": f"{type(e).__name__}: {e}",
                "pack_present": False,
            }
        self.events.append({
            "type": "tool_result", "tool": "run_winre_dynamic",
            "rc": out.get("rc"), "ok": bool(out.get("ok")),
            "state": out.get("state"),
            "pack_present": out.get("pack_present"),
            "run_id": out.get("run_id"),
            "pack_correlation": out.get("pack_correlation"), "ts": _utc(),
        })
        return {**out, "ok": bool(out.get("ok")),
                "rc": out.get("rc", 1), "tool": "run_winre_dynamic"}

    def run_publish(self) -> dict:
        blocked = self._claim_report_stage("run_publish")
        if blocked is not None:
            return blocked
        preflight = self._prepare_publish("run_publish")
        if preflight is not None:
            return preflight
        hitl = os.environ.get("REVAI_HITL_VERDICT", "").strip().lower() in ("1", "true", "yes")
        v = _verdicts(self.sha)
        if hitl and v.get("conflict"):
            entry = {
                "type": "hitl_stop",
                "tool": "run_publish",
                "reason": f"quick={v['quick']} deep={v['deep']}",
                "ts": _utc(),
            }
            self.events.append(entry)
            return {"ok": False, "skipped": True, "hitl": True, **entry}
        return self._run(
            "run_publish",
            [
                sys.executable, str(SCRIPTS / "publish_report_v2.py"),
                self.sha, "--template", "full",
            ],
            _stage_timeout("REVAI_STAGE_TIMEOUT_PUBLISH", 14400),
            retry_timeouts=False,
        )

    def run_section_publish(self) -> dict:
        blocked = self._claim_report_stage("run_section_publish")
        if blocked is not None:
            return blocked
        preflight = self._prepare_publish("run_section_publish")
        if preflight is not None:
            return preflight
        return self._run(
            "run_section_publish",
            [sys.executable, str(SCRIPTS / "section_publisher.py"), self.sha],
            _stage_timeout("REVAI_STAGE_TIMEOUT_PUBLISH", 14400),
            retry_timeouts=False,
        )

    def _prepare_publish(self, stage: str) -> dict[str, Any] | None:
        hitl = os.environ.get("REVAI_HITL_VERDICT", "").strip().lower() in (
            "1", "true", "yes",
        )
        result = _reconcile_deep_verdict(self.sha, hitl_enabled=hitl)
        self.events.append({
            "type": "observe", "tool": "verdict_reconciliation",
            "data": {"stage": stage, **result}, "ts": _utc(),
        })
        if result.get("changed"):
            print(
                f"[orchestrator] verdict reconciled before {stage}: "
                f"{result.get('from')} -> {result.get('to')}",
                flush=True,
            )
        if result.get("ok"):
            return None
        failure = {
            "type": "tool_result", "tool": stage,
            "cmd": ["pre_publish_verdict_reconciliation"],
            "rc": 1, "ok": False, "elapsed_s": 0.0,
            "ts": _utc(), "attempt": 1, "timed_out": False,
            "failure_reason": str(result.get("reason") or "verdict reconciliation failed"),
        }
        self.events.append(failure)
        return {key: value for key, value in failure.items() if key != "type"}

    def run_audit(self) -> dict:
        return self._run(
            "run_audit",
            [
                sys.executable, str(SCRIPTS / "audit_pipeline.py"),
                self.sha, "--mode", "single",
            ],
            _stage_timeout("REVAI_STAGE_TIMEOUT_AUDIT", 7200),
            # The audit calls the semantic reviewer over many claim batches.
            # Restarting the entire audit on timeout replays completed calls;
            # bounded per-request retries handle transient provider failures.
            retry_timeouts=False,
            retry_stage_failures=False,
        )

    def run_behavioural_model(self) -> dict:
        """Stage 3.7: behavioural model (plan #8), gated by
        REVAI_ENABLE_BEHAVIOURAL_MODEL.

        Mirrors run_artifact_gen's contract: an opt-in stage that self-skips with
        rc=0 when the gate is off, so an absent run is byte-identical. The case
        directory is passed as the CLI target so the child reads this mode's
        evidence even if an inherited REVAI_RUN_MODE names another mode.
        """
        try:
            from behavioural_model import behavioural_model_enabled
        except Exception as exc:  # pragma: no cover - not deployed
            return {"ok": True, "skipped": True,
                    "reason": f"behavioural_model unavailable: {exc}"}
        if not behavioural_model_enabled():
            out = {"ok": True, "skipped": True,
                   "reason": "REVAI_ENABLE_BEHAVIOURAL_MODEL is not set",
                   "note": "the behavioural model is opt-in; set "
                           "REVAI_ENABLE_BEHAVIOURAL_MODEL=1 to enable"}
            self.events.append({"type": "observe",
                                "tool": "behavioural_model", "data": out,
                                "ts": _utc()})
            return out
        case = case_dir(self.sha)
        try:
            return self._run(
                "behavioural_model",
                [sys.executable, str(SCRIPTS / "behavioural_model.py"), str(case)],
                1800,
            )
        except Exception as exc:  # pragma: no cover - defensive
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def run_depth(self) -> dict:
        """Stage 9: depth mode (plan #48), gated by REVAI_DEPTH.

        Returns early with a recorded skip when the gate is off, so the trace
        shows "asked for and skipped" rather than a stage that never existed.
        When it is on, the case dir is passed explicitly: depth_agent resolves
        a sha through case_dir(), which needs REVAI_RUN_MODE to be right, and in
        agentic mode that is `agentic` -- not the scripted default.
        """
        try:
            from depth_agent import ceiling_seconds, depth_profile, depth_requested
        except Exception as exc:  # pragma: no cover - not deployed
            return {"ok": True, "skipped": True,
                    "reason": f"depth_agent unavailable: {exc}"}
        if not depth_requested():
            out = {"ok": True, "skipped": True,
                   "reason": "REVAI_DEPTH is not set",
                   "note": "depth mode is opt-in; set REVAI_DEPTH=1 (or "
                           "REVAI_DEPTH=full for the #26 profile) to enable"}
            self.events.append({"type": "observe", "tool": "depth_understanding",
                                "data": out, "ts": _utc()})
            return out
        case = case_dir(self.sha)
        env = dict(os.environ)
        env["REVAI_CASE_DIR"] = str(case)
        # Pass the PROFILE through, not a flattened "1": REVAI_DEPTH=full must
        # reach depth_agent as "full" or the domain-node substrate never runs.
        env["REVAI_DEPTH"] = depth_profile() or "1"
        try:
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "depth_agent.py"), self.sha, "--run"],
                capture_output=True, text=True, timeout=ceiling_seconds() + 300,
                env=env, cwd=str(SCRIPTS),
            )
        except subprocess.TimeoutExpired:
            return {"ok": True, "skipped": True,
                    "reason": "depth hit its ceiling; the run is not failed by it"}
        except Exception as exc:
            return {"ok": True, "skipped": True, "reason": str(exc)}
        # Depth never gates this pipeline, so a non-zero rc is recorded, not
        # raised: the objective is understanding, and a partial map is a result.
        out = {"ok": proc.returncode == 0, "rc": proc.returncode,
               "case_dir": str(case),
               "stdout_tail": (proc.stdout or "")[-600:],
               "stderr_tail": (proc.stderr or "")[-300:]}
        self.events.append({"type": "observe", "tool": "depth_understanding",
                            "data": out, "ts": _utc()})
        return out

    def read_verdicts(self) -> dict:
        v = _verdicts(self.sha)
        self.events.append({"type": "observe", "tool": "read_verdicts", "data": v, "ts": _utc()})
        return v

    def read_evidence(self, relative_path: str = "verdict.json") -> dict:
        """Read a small artifact under logs/<sha>/ for planner observation."""
        rel = (relative_path or "verdict.json").lstrip("/\\")
        if ".." in rel.replace("\\", "/").split("/"):
            return {"ok": False, "error": "path traversal blocked"}
        path = LOGS_DIR / self.sha / rel
        if not path.is_file():
            return {"ok": False, "error": f"missing {rel}"}
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix == ".json":
                data = json.loads(text)
                return {"ok": True, "path": rel, "json": _truncate(json.dumps(data, default=str), 3000)}
            return {"ok": True, "path": rel, "text": _truncate(text, 3000)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def check_quality(self) -> dict:
        """Hard quality gate — NOT the same as subprocess rc==0."""
        q = evaluate_sha_publish_quality(LOGS_DIR, self.sha)
        # Latest attempt per tool wins (retries must clear earlier failures)
        latest_by_tool: dict[str, dict] = {}
        for e in self.events:
            if e.get("type") == "tool_result" and e.get("tool"):
                latest_by_tool[str(e["tool"])] = e
        failed_tools = [e for e in latest_by_tool.values() if not e.get("ok")]
        deep = {}
        try:
            p = LOGS_DIR / self.sha / "deep_dive" / "agentic_deep_dive.json"
            if p.exists():
                deep = json.loads(p.read_text())
        except Exception:
            pass
        # Prefer live artifact quality over stale pipeline-audit stage_ok from a prior fail
        issues = list(q.get("issues") or [])
        # Drop stale stage_ok_false:publish if live publish artifacts are LLM-ok
        issues = [i for i in issues if not i.startswith("stage_ok_false:")]
        out = {
            "ok": bool(q.get("ok")) and not failed_tools,
            "quality_green": bool(q.get("ok")) and not failed_tools,
            "issues": issues,
            "failed_tools": [
                {"tool": e.get("tool"), "rc": e.get("rc")} for e in failed_tools
            ],
            "deep_checklist_ok": deep.get("checklist_ok"),
            "deep_sql_deep_ok": deep.get("sql_deep_ok"),
            "models": {
                "default": get_llm_model(),
                "planner": get_planner_model(),
                "judgment": get_verdict_model(),
                **(q.get("models") or {}),
            },
            "checks": q.get("checks"),
            "latest_tool_rc": {k: v.get("rc") for k, v in latest_by_tool.items()},
        }
        if failed_tools:
            out["issues"] = out["issues"] + [
                f"tool_rc_nonzero:{e.get('tool')}:{e.get('rc')}" for e in failed_tools
            ]
            out["ok"] = False
            out["quality_green"] = False
        if deep and not deep.get("checklist_ok"):
            out["ok"] = False
            out["quality_green"] = False
            out["issues"].append("deep:checklist_ok_false")
        if deep and not deep.get("sql_deep_ok"):
            # Honest distinction: SQL attempted but infrastructure-failed
            # (ghidrasql server died / no IDA / unsupported format) is recorded,
            # not a hard fail. Only a complete non-attempt fails.
            if not deep.get("sql_deep_attempted"):
                out["ok"] = False
                out["quality_green"] = False
                out["issues"].append("deep:sql_deep_ok_false")
            else:
                out["issues"].append(
                    "deep:sql_deep_unavailable:" + str(deep.get("sql_deep_unavailable") or "sql_failed")
                )
        self.events.append({"type": "quality_gate", "data": {
            "ok": out["ok"], "issues": out["issues"][:20], "ts": _utc(),
        }, "ts": _utc()})
        (LOGS_DIR / self.sha / "quality-gate.json").write_text(
            json.dumps(out, indent=2, default=str)
        )
        print(
            f"[orchestrator] check_quality ok={out['ok']} issues={out['issues'][:8]}",
            flush=True,
        )
        return out


def _build_lc_tools(runner: StageRunner, need_intake: bool) -> list:
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, Field

    class Empty(BaseModel):
        pass

    class EvidenceArgs(BaseModel):
        relative_path: str = Field(
            "verdict.json",
            description="Path under logs/<sha>/ e.g. verdict.json, deep_dive/05-deep-dive.json",
        )

    tools = []

    def _add(name: str, fn: Callable, desc: str, schema: type[BaseModel] = Empty):
        def _runner(**kwargs):
            if schema is Empty:
                return json.dumps(fn(), default=str)
            return json.dumps(fn(**kwargs), default=str)

        _runner.__name__ = name
        _runner.__doc__ = desc
        tools.append(
            StructuredTool.from_function(
                func=_runner, name=name, description=desc, args_schema=schema,
            )
        )

    if need_intake:
        _add(
            "run_intake",
            runner.run_intake,
            "Stage 1: intake sample into Ghidra/IDA, write session.json. REQUIRED first if new sample.",
        )
    _add(
        "run_quick_scan",
        runner.run_quick_scan,
        "Stage 2: triage tools + LLM verdict → logs/<sha>/verdict.json",
    )
    _add(
        "run_deep_dive_agentic",
        runner.run_deep_dive_agentic,
        "Stage 3: LangGraph ReAct deep RE (ToolRegistry: SQL, capa, malcat, …). "
        "WinRE detonation, when enabled, must precede this stage so its evidence "
        "is loaded into the deep-dive prompt. REQUIRED.",
    )
    _add(
        "run_function_recovery",
        runner.run_function_recovery,
        "Optional stage 3.5: v4 agentic function recovery (call-graph LLM analysis → "
        "function_recovery.json + Ghidra writeback). Only if REVAI_ENABLE_AGENTIC_RECOVERY=1 "
        "and the sample is NOT gated by size; skips otherwise.",
    )
    _add(
        "run_artifact_gen",
        runner.run_artifact_gen,
        "Optional stage 3.6: verifiable artifact generation (plan #11) - author a "
        "sample-specific extraction script, run it in a bounded sandbox, and "
        "re-derive every claimed value from the sample bytes. Call it after "
        "run_deep_dive_agentic and BEFORE run_yara_gen. Skips itself (rc=0) unless "
        "REVAI_ENABLE_ARTIFACT_GEN=1; never gates the verdict.",
    )
    _add(
        "run_behavioural_model",
        runner.run_behavioural_model,
        "Optional stage 3.7: behavioural model (plan #8) -- assemble what the "
        "sample DOES from the capability ledger, the IoCs and the observations. "
        "Call it after any enabled run_artifact_gen stage and BEFORE run_yara_gen. Skips itself "
        "(rc=0) unless REVAI_ENABLE_BEHAVIOURAL_MODEL=1; never gates the verdict.",
    )
    _add(
        "run_yara_gen",
        runner.run_yara_gen,
        "Stage 4: generate YARA/Sigma rules from evidence",
    )
    _add(
        "run_winre_dynamic",
        runner.run_winre_dynamic,
        "Optional dynamic corroboration: detonate the sample on the WinRE FlareVM "
        "(remote driver) and pull the detonation pack before deep dive so the "
        "agent can reason over its evidence; publish also attaches the presence-gated "
        "dynamic-analysis block. Call it after run_quick_scan and BEFORE "
        "run_deep_dive_agentic. Skips itself (rc=0) unless REVAI_WINRE_RUN=1 and the "
        "Console's Dynamic analysis (WinRE) settings are configured; Flare-side "
        "failures are recorded in winre-run.json and never block the pipeline.",
    )
    _add(
        "run_publish",
        runner.run_publish,
        "Stage 5: REPORT-MASTER v2 publish from static evidence plus any current WinRE runtime pack. "
        "Keep Speakeasy, the RevAI Frida static probe, and WinRE detonation as separate scopes; "
        "do not infer execution from static hook candidates. Respects HITL if quick≠deep.",
    )
    _add(
        "run_section_publish",
        runner.run_section_publish,
        "Stage 6: section-based REPORT-MASTER v3 + technical report",
    )
    _add(
        "run_audit",
        runner.run_audit,
        "Stage 7: pipeline audit → pipeline-audit.json. all_green alone is NOT enough.",
    )
    _add(
        "check_quality",
        runner.check_quality,
        "Stage 8 REQUIRED: hard quality gate on TECHNICAL/MASTER sources, stubs, "
        "deep checklist_ok/sql_deep_ok, and tool rc. GREEN only if quality_green=true. "
        "Report stages are single-shot in this pipeline execution; do not call either "
        "publisher again. Publisher-level section repairs are already bounded and "
        "recorded. If output or audit is red, preserve the failure and stop.",
    )
    _add(
        "run_depth",
        runner.run_depth,
        "Stage 9, LAST, once, and only meaningful when REVAI_DEPTH is set: "
        "post-pipeline depth mode. REVAI_DEPTH=1 deepens the capability domains "
        "the pipeline could not establish; REVAI_DEPTH=full runs the #26 profile "
        "on the domain-node substrate -- every capability domain investigated by "
        "its own bounded tool-calling node, a raised ceiling, and "
        "emulation/unpack/solver forced on. Call it AFTER run_audit and "
        "check_quality, as the final stage; it never gates the pipeline and a "
        "partial map is a result. Skips itself (rc=0, recorded) when REVAI_DEPTH "
        "is unset.",
    )
    _add(
        "read_verdicts",
        runner.read_verdicts,
        "Observe quick vs deep verdicts; check for conflict before publish",
    )
    _add(
        "read_evidence",
        runner.read_evidence,
        "Read a small artifact under logs/<sha>/ for observation",
        EvidenceArgs,
    )
    return tools


def run_langgraph_orchestrator(sample: Path | None, sha: str | None) -> dict:
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langchain_openai import ChatOpenAI

    # langchain>=1.x create_agent uses system_prompt=; langgraph prebuilt uses prompt=
    _agent_factory = None
    _agent_prompt_kw = "prompt"
    try:
        from langchain.agents import create_agent as _agent_factory  # type: ignore
        _agent_prompt_kw = "system_prompt"
    except ImportError:
        from langgraph.prebuilt import create_react_agent as _agent_factory  # type: ignore
        _agent_prompt_kw = "prompt"

    ensure_pipeline_runtime_env()
    # CLI default = agentic; an explicit REVAI_RUN_MODE from the caller (e.g.
    # the UI service injects "ui") must win so artifacts land in the right
    # mode-keyed directory instead of polluting agentic/.
    os.environ.setdefault("REVAI_RUN_MODE", "agentic")
    os.environ.setdefault("REVAI_AGENTIC_ENGINE", "langgraph")

    need_intake = False
    if sample is not None:
        sample = sample.resolve()
        if not sample.is_file():
            raise SystemExit(f"sample not found: {sample}")
        sha = _sha_of(sample)
        need_intake = True
    else:
        assert sha
        sess = load_session(sha)
        sp = sess.get("sample_path")
        if not sp:
            raise SystemExit("session missing sample_path — pass sample path for intake")
        sample = Path(sp)
        # Each invocation gets a new run ID and archives prior evidence. Re-run
        # intake so its output is bound to this execution, not a previous run.
        need_intake = True

    execution = begin_execution(
        sha,
        mode=os.environ.get("REVAI_RUN_MODE", "agentic").strip() or "agentic",
        engine=os.environ.get("REVAI_AGENTIC_ENGINE", "langgraph").strip() or "langgraph",
        started_at=_utc(),
    )

    events: list[dict[str, Any]] = []
    runner = StageRunner(sha, sample, events)
    lc_tools = _build_lc_tools(runner, need_intake=need_intake)

    api_key = os.environ.get("REVAI_LLM_API_KEY")
    api_url = (os.environ.get("REVAI_LLM_API_URL") or "").rstrip("/")
    if api_url.endswith("/chat/completions"):
        api_url = api_url[: -len("/chat/completions")]
    planner = get_planner_model()
    judgment = get_verdict_model()

    llm = ChatOpenAI(
        model=planner,
        api_key=api_key,
        base_url=api_url,
        # REVAI_LLM_TEMPERATURE, honoured here too (see agentic_langgraph).
        temperature=get_llm_temperature(),
        **get_llm_chat_options(2048, api_url=api_url),
    )

    artifact_gen_on = (os.environ.get("REVAI_ENABLE_ARTIFACT_GEN") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )
    behavioural_model_on = (
        (os.environ.get("REVAI_ENABLE_BEHAVIOURAL_MODEL") or "").strip().lower()
        in ("1", "true", "yes", "on")
    )
    winre_on = (os.environ.get("REVAI_WINRE_RUN") or "").strip().lower() in (
        "1", "true", "yes",
    )
    function_recovery_on = (
        (os.environ.get("REVAI_ENABLE_AGENTIC_RECOVERY")
         or os.environ.get("ENABLE_AGENTIC_RECOVERY", "0"))
        .strip().lower() in ("1", "true", "yes")
    )
    try:
        from depth_agent import depth_requested
        depth_on = bool(depth_requested())
    except Exception:
        depth_on = False
    order = _planner_stage_order(
        need_intake=need_intake,
        winre=winre_on,
        function_recovery=function_recovery_on,
        artifact_gen=artifact_gen_on,
        behavioural_model=behavioural_model_on,
        depth=depth_on,
    )

    system_prompt = f"""You are the RevAI stage orchestrator (LangGraph ReAct).

Sample path: {sample}
SHA256: {sha}
Need intake: {need_intake}
Models: planner/agents={planner}; publish/section judgment={judgment}

Policy (non-negotiable — industry agentic + deterministic gates):
1. Call stage tools in this order (do not skip early stages):
   {order}
2. deep_dive MUST use run_deep_dive_agentic (nested LangGraph RE tools) — never skip.
3. run_yara_gen is MANDATORY — the audit hard-requires rule.yar. Never skip it.
4. Call read_verdicts immediately after deep. If conflict and HITL env is on,
   run_publish may skip — then stop and report.
5. Follow the ordered plan for optional stages. When enabled, run_winre_dynamic
   appears between quick scan and deep dive so the deep-dive prompt receives its
   evidence. Do not call optional stages absent from the plan. Evidence comes
   from tool outputs and deterministic score checks.
6. rc==0 is NOT success. After run_audit you MUST call check_quality.
7. Report publishers are single-shot per pipeline execution. Never call
   run_publish or run_section_publish twice, whether the first call succeeded,
   failed, or timed out. Their own bounded section repairs are recorded in their
   artifacts. If check_quality.ok is false, preserve the failure and stop.
8. FINAL JSON only when done:
   {{"status":"ok|hitl_stop|failed","sha256":"...","stages_run":["..."],
     "all_green":true|false,"quality_green":true|false,"issues":[],"summary":"..."}}
   Set quality_green from check_quality. Never invent quality_green=true.
9. BUDGET DISCIPLINE: never repeat a stage. After the first report attempt, run
   audit and check_quality once, then report the result.
   If run_depth appears in the ordered plan, call it once after check_quality, then emit
   FINAL JSON. Wasting calls on redundant stage re-runs is a failure mode.

Use tools. Do not claim success without check_quality.ok=true.
"""

    agent = _agent_factory(llm, tools=lc_tools, **{_agent_prompt_kw: system_prompt})
    # intake+7 stages + observes ≈ need generous recursion
    # recursion budget from run profile (REVAI_RUN_PROFILE / REVAI_ORCH_RECURSION_LIMIT)
    recursion_limit = int(run_profile().get("recursion_limit") or 40)
    started_at = _utc()
    t0 = time.monotonic()
    print(
        f"[orchestrator] LangGraph ReAct invoke planner={planner} tools={len(lc_tools)} "
        f"recursion_limit={recursion_limit}",
        flush=True,
    )

    final_status = None
    try:
        result = agent.invoke(
            {
                "messages": [
                    HumanMessage(
                        content=(
                            f"Orchestrate the full analysis pipeline for {sha}. "
                            f"need_intake={need_intake}. Call tools in order, then FINAL JSON."
                        )
                    )
                ]
            },
            config={"recursion_limit": recursion_limit},
        )
        messages = result.get("messages") or []
        for msg in messages:
            if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
                events.append({
                    "type": "planner_tool_calls",
                    "tool_calls": [
                        {"name": tc.get("name"), "args": tc.get("args")}
                        for tc in (msg.tool_calls or [])
                    ],
                    "ts": _utc(),
                })
            if isinstance(msg, AIMessage) and isinstance(msg.content, str) and msg.content.strip():
                text = msg.content.strip()
                if "{" in text and "status" in text:
                    try:
                        start, end = text.find("{"), text.rfind("}")
                        final_status = json.loads(text[start : end + 1])
                    except Exception:
                        pass
            if isinstance(msg, ToolMessage):
                events.append({
                    "type": "tool_message",
                    "name": getattr(msg, "name", None),
                    "content": _truncate(str(msg.content), 500),
                    "ts": _utc(),
                })
    except Exception as e:
        print(f"[orchestrator] agent.invoke error: {e}", flush=True)
        events.append({"type": "error", "error": str(e), "ts": _utc()})

    # Deterministic finalize — never trust planner FINAL alone
    audit = {}
    aj = case_dir(sha) / "pipeline-audit.json"
    if aj.exists():
        try:
            audit = json.loads(aj.read_text())
        except Exception:
            pass

    # Always run quality gate at end (even if planner forgot)
    q = runner.check_quality()

    # Deterministic mandatory-stage enforcement — never trust planner FINAL.
    # The audit hard-requires rule.yar (yara_gen stage). A planner that
    # skips run_yara_gen would fail the audit with no retry path, so we
    # run it deterministically here when missing, then re-run the gate.
    rule_yar = case_dir(sha) / "rule.yar"
    if not rule_yar.exists() and "run_yara_gen" not in [
        e.get("tool") for e in events if e.get("type") == "tool_result"
    ]:
        print(
            "[orchestrator] yara_gen missing (planner skipped) — running deterministically",
            flush=True,
        )
        yr = runner.run_yara_gen()
        if yr.get("ok"):
            ra = runner._run(
                "run_audit",
                [sys.executable, str(SCRIPTS / "audit_pipeline.py"), sha, "--mode", "single"],
                _stage_timeout("REVAI_STAGE_TIMEOUT_AUDIT", 7200),
                retry_timeouts=False,
                retry_stage_failures=False,
            )
            q = runner.check_quality()
            # Reload the audit — it was re-written by the deterministic re-audit.
            if aj.exists():
                try:
                    audit = json.loads(aj.read_text())
                except Exception:
                    pass
        else:
            print(f"[orchestrator] deterministic yara_gen failed: {yr}", flush=True)

    # Part A — deterministic verdict reconciliation is normally completed by
    # the publish-stage preflight. Keep an idempotent final guard for planners
    # that skipped publication or changed evidence after publishing. If it
    # changes the deep artifact here, regenerate reports before the final audit.
    _hitl_env = os.environ.get("REVAI_HITL_VERDICT", "").strip().lower() in ("1", "true", "yes")
    _reconciliation = _reconcile_deep_verdict(sha, hitl_enabled=_hitl_env)
    if not _reconciliation.get("ok"):
        events.append({
            "type": "error", "tool": "verdict_reconciliation",
            "error": _reconciliation.get("reason"), "ts": _utc(),
        })
    elif _reconciliation.get("changed"):
        already_published = any(
            e.get("type") == "tool_result"
            and e.get("tool") in ("run_publish", "run_section_publish")
            for e in events
        )
        if already_published:
            events.append({
                "type": "error", "tool": "verdict_reconciliation",
                "error": (
                    "deep verdict changed after report generation; preserving the "
                    "stale-output failure instead of rerunning publishers on this SHA"
                ),
                "ts": _utc(),
            })
        else:
            print(
                "[orchestrator] late verdict reconciliation detected before "
                "publication; generating reports from reconciled evidence",
                flush=True,
            )
            runner.run_publish()
            runner.run_section_publish()

    # Part B — mandatory publish/section enforcement (planner may skip publish;
    # the audit then fails on missing reports with no retry path). Same pattern
    # as the yara_gen enforcement above.
    _master_md = case_dir(sha) / "REPORT-MASTER-v2.md"
    _did_publish = "run_publish" in [
        e.get("tool") for e in events if e.get("type") == "tool_result"
    ]
    if not _master_md.exists() and not _did_publish:
        print(
            "[orchestrator] publish missing (planner skipped) — running deterministically",
            flush=True,
        )
        runner.run_publish()
        runner.run_section_publish()

    # Part C — do not replay full report stages after the audit. The publishers
    # already own bounded section-level repair; a complete rerun can overwrite
    # the first artifacts and multiply model latency without fixing the cause.
    if aj.exists():
        try:
            _audit_now = json.loads(aj.read_text())
            _pub = (_audit_now.get("stages") or {}).get("publish") or {}
            _eng = _pub.get("engine_citation") or {}
            if (
                not _pub.get("ok")
                and not _eng.get("ok", True)
                and int(_eng.get("corrections", {}).get("corrected") or 0) == 0
            ):
                events.append({
                    "type": "observe",
                    "tool": "publish_recovery",
                    "data": {
                        "skipped": True,
                        "reason": (
                            "report stages are single-shot; engine citation issue "
                            "must be fixed at its source and validated on a new SHA"
                        ),
                    },
                    "ts": _utc(),
                })
        except Exception:
            pass

    # Deterministic final re-audit — if an artifact-writing stage ran after
    # the planner's first audit, refresh the audit so it covers the final files.
    # Single-shot guard events have artifacts_written=False and do not trigger it.
    ev_tools = [e for e in events if e.get("type") == "tool_result"]
    write_stages = ("run_publish", "run_section_publish", "run_yara_gen")
    last_write_i = max(
        (i for i, e in enumerate(ev_tools)
         if e.get("tool") in write_stages
         and e.get("artifacts_written") is not False),
        default=-1,
    )
    last_audit_i = max(
        (i for i, e in enumerate(ev_tools) if e.get("tool") == "run_audit"),
        default=-1,
    )
    if last_write_i > last_audit_i:
        print(
            "[orchestrator] publish/section/yara ran after last audit — final re-audit",
            flush=True,
        )
        runner._run(
            "run_audit",
            [sys.executable, str(SCRIPTS / "audit_pipeline.py"), sha, "--mode", "single"],
            _stage_timeout("REVAI_STAGE_TIMEOUT_AUDIT", 7200),
            retry_timeouts=False,
            retry_stage_failures=False,
        )
        q = runner.check_quality()
        # Reload the audit — it now reflects the final artifacts.
        if aj.exists():
            try:
                audit = json.loads(aj.read_text())
            except Exception:
                pass

    stages_run = [
        e["tool"] for e in events
        if e.get("type") == "tool_result" and e.get("tool")
    ]
    hitl = next((e for e in events if e.get("type") == "hitl_stop"), None)
    # A tool counts as failed only if its FINAL attempt failed. A transient
    # failure the planner recovered from (a successful retry) must not poison
    # truly_green — the final artifacts are what matter.
    last_ok: dict = {}
    for e in events:
        if e.get("type") == "tool_result" and e.get("tool"):
            last_ok[e["tool"]] = bool(e.get("ok"))
    tool_fail = any(not ok for ok in last_ok.values())

    try:
        if (SESSIONS_DIR / f"{sha}.json").exists():
            update_session(sha, {
                "pipeline_mode": "single",
                "pipeline_mode_source": "stage_orchestrator",
            })
    except Exception:
        pass

    quality_green = bool(q.get("quality_green")) and not tool_fail
    # GREEN only when audit + quality + no tool failures
    truly_green = bool(audit.get("all_green")) and quality_green

    trace = {
        "schema": "v6.3.orchestrator.langgraph_react",
        "sha256": sha,
        "run_id": execution["run_id"],
        "sample_path": str(sample),
        "mode": "langgraph_react",
        "planner_model": planner,
        "judgment_model": judgment,
        "dynamic_requested": winre_on,
        "with_dynamic": any(
            e.get("type") == "tool_result"
            and e.get("tool") == "run_winre_dynamic"
            and e.get("pack_present") is True
            for e in events
        ),
        "provenance": revai_provenance(),
        "run_config": run_profile(),
        "started_at": started_at,
        "finished_at": _utc(),
        "elapsed_s": round(time.monotonic() - t0, 1),
        "stages_run": stages_run,
        "events": events,
        "final_status": final_status,
        "hitl_stop": hitl,
        "all_green": bool(audit.get("all_green")),
        "quality_green": quality_green,
        "truly_green": truly_green,
        "quality": q,
        "stage_ok": audit.get("stage_ok"),
        "pipeline_audit_present": bool(audit),
    }
    out = case_dir(sha) / "orchestrator_trace.json"
    out.write_text(json.dumps(trace, indent=2, default=str))
    (case_dir(sha) / "stage_trace.json").write_text(json.dumps(trace, indent=2, default=str))
    print(
        f"[orchestrator] trace -> {out} all_green={trace['all_green']} "
        f"quality_green={quality_green} truly_green={truly_green} stages={stages_run}",
        flush=True,
    )
    return trace


def main() -> int:
    ap = argparse.ArgumentParser(description="RevAI LangGraph ReAct stage orchestrator")
    ap.add_argument("sample", nargs="?", help="path to sample (new intake)")
    ap.add_argument("--sha", default=None, help="resume from existing session")
    args = ap.parse_args()
    sample = Path(args.sample) if args.sample else None
    if sample is None and not args.sha:
        ap.error("need sample path or --sha")
    trace = run_langgraph_orchestrator(sample, args.sha)
    # HITL stop after deep is an honest non-failure pause (not green)
    if trace.get("hitl_stop") and "run_deep_dive_agentic" in (trace.get("stages_run") or []):
        return 0
    # Process success ONLY when truly_green (audit + quality + tools)
    return 0 if trace.get("truly_green") else 1


if __name__ == "__main__":
    raise SystemExit(main())
