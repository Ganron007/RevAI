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
  REVENG_HITL_VERDICT=1 python3 ...   # stop before publish if quick≠deep

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
    ensure_pipeline_runtime_env,
    get_planner_model,
    get_verdict_model,
    load_session,
    update_session,
)
from report_quality import evaluate_sha_publish_quality  # noqa: E402

SCRIPTS = Path(os.environ.get("REVENG_SCRIPTS_DIR") or "/opt/scripts")


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


def _verdicts(sha: str) -> dict[str, str]:
    qv = dv = ""
    try:
        p = LOGS_DIR / sha / "verdict.json"
        if p.exists():
            qv = str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        pass
    try:
        p = LOGS_DIR / sha / "deep_dive" / "05-deep-dive.json"
        if p.exists():
            dv = str(json.loads(p.read_text()).get("verdict") or "").lower()
    except Exception:
        pass
    return {"quick": qv, "deep": dv, "conflict": bool(qv and dv and qv != dv)}


class StageRunner:
    """Execute one spine stage; record every call for orchestrator_trace."""

    def __init__(self, sha: str, sample: Path | None, events: list[dict]):
        self.sha = sha
        self.sample = sample
        self.events = events
        self.run_log = LOGS_DIR / sha / "orchestrator.log"
        self.run_log.parent.mkdir(parents=True, exist_ok=True)

    def _run(self, name: str, cmd: list[str], timeout: int) -> dict[str, Any]:
        print(f"[orchestrator] TOOL {name}: {' '.join(cmd)}", flush=True)
        st = time.time()
        with self.run_log.open("a", encoding="utf-8") as lf:
            lf.write(f"\n===== {_utc()} {name} CMD {' '.join(cmd)}\n")
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
                lf.write("===== TIMEOUT\n")
        entry = {
            "type": "tool_result",
            "tool": name,
            "cmd": cmd,
            "rc": rc,
            "ok": rc == 0,
            "elapsed_s": round(time.time() - st, 1),
            "ts": _utc(),
        }
        self.events.append(entry)
        print(f"[orchestrator] {name} rc={rc} {entry['elapsed_s']}s", flush=True)
        return {
            "ok": rc == 0,
            "rc": rc,
            "elapsed_s": entry["elapsed_s"],
            "sha256": self.sha,
            "tool": name,
        }

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
        # Nested LangGraph ReAct (REVENG_AGENTIC_ENGINE=langgraph)
        env_note = os.environ.get("REVENG_AGENTIC_ENGINE") or "langgraph"
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

    def run_yara_gen(self) -> dict:
        return self._run(
            "run_yara_gen",
            [sys.executable, str(SCRIPTS / "yara_gen_v2.py"), self.sha],
            1800,
        )

    def run_publish(self) -> dict:
        hitl = os.environ.get("REVENG_HITL_VERDICT", "").strip().lower() in ("1", "true", "yes")
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
            3600,
        )

    def run_section_publish(self) -> dict:
        return self._run(
            "run_section_publish",
            [sys.executable, str(SCRIPTS / "section_publisher.py"), self.sha],
            3600,
        )

    def run_audit(self) -> dict:
        return self._run(
            "run_audit",
            [
                sys.executable, str(SCRIPTS / "audit_pipeline.py"),
                self.sha, "--mode", "single",
            ],
            600,
        )

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
            out["ok"] = False
            out["quality_green"] = False
            out["issues"].append("deep:sql_deep_ok_false")
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
        "Stage 3: LangGraph ReAct deep RE (ToolRegistry: SQL, capa, malcat, …). REQUIRED.",
    )
    _add(
        "run_yara_gen",
        runner.run_yara_gen,
        "Stage 4: generate YARA/Sigma rules from evidence",
    )
    _add(
        "run_publish",
        runner.run_publish,
        "Stage 5: REPORT-MASTER v2 publish (static evidence only). Respects HITL if quick≠deep.",
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
        "If issues mention fallback/stubs/llm_incomplete — re-run run_publish then "
        "run_section_publish then check_quality again (max 1 retry).",
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
    os.environ.setdefault("REVENG_AGENTIC_ENGINE", "langgraph")
    os.environ.setdefault("REVENG_RAG", "0")

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

    events: list[dict[str, Any]] = []
    runner = StageRunner(sha, sample if need_intake else sample, events)
    lc_tools = _build_lc_tools(runner, need_intake=need_intake)

    api_key = os.environ.get("REVENG_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    api_url = (os.environ.get("REVENG_LLM_API_URL") or "https://api.deepseek.com").rstrip("/")
    if api_url.endswith("/chat/completions"):
        api_url = api_url[: -len("/chat/completions")]
    planner = get_planner_model()
    judgment = get_verdict_model()

    llm = ChatOpenAI(
        model=planner,
        api_key=api_key,
        base_url=api_url,
        temperature=0.0,
        max_tokens=2048,
    )

    order = (
        "run_intake → " if need_intake else ""
    ) + (
        "run_quick_scan → run_deep_dive_agentic → run_yara_gen → read_verdicts → "
        "run_publish → run_section_publish → run_audit → check_quality"
    )

    system_prompt = f"""You are the CADRE-RevAI stage orchestrator (LangGraph ReAct).

Sample path: {sample}
SHA256: {sha}
Need intake: {need_intake}
Models: planner/agents={planner} (flash) · publish/section judgment={judgment} (pro)

Policy (non-negotiable — industry agentic + deterministic gates):
1. Call stage tools in this order (do not skip early stages):
   {order}
2. deep_dive MUST use run_deep_dive_agentic (nested LangGraph RE tools) — never skip.
3. After deep, call read_verdicts. If conflict and HITL env is on, run_publish may skip — then stop and report.
4. No Flare/dynamic tools. RAG is off. Evidence = tool outputs + scorecard only.
5. rc==0 is NOT success. After run_audit you MUST call check_quality.
6. If check_quality.ok is false (fallback / stub sections / llm_incomplete / checklist fail):
   you may retry run_publish → run_section_publish → check_quality ONCE, then stop.
7. FINAL JSON only when done:
   {{"status":"ok|hitl_stop|failed","sha256":"...","stages_run":["..."],
     "all_green":true|false,"quality_green":true|false,"issues":[],"summary":"..."}}
   Set quality_green from check_quality. Never invent quality_green=true.

Use tools. Do not claim success without check_quality.ok=true.
"""

    agent = _agent_factory(llm, tools=lc_tools, **{_agent_prompt_kw: system_prompt})
    # intake+7 stages + observes ≈ need generous recursion
    recursion_limit = 40
    t0 = time.time()
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
    aj = LOGS_DIR / sha / "pipeline-audit.json"
    if aj.exists():
        try:
            audit = json.loads(aj.read_text())
        except Exception:
            pass

    # Always run quality gate at end (even if planner forgot)
    q = runner.check_quality()

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
        "sample_path": str(sample),
        "mode": "langgraph_react",
        "planner_model": planner,
        "judgment_model": judgment,
        "with_dynamic": False,
        "started_at": _utc(),
        "finished_at": _utc(),
        "elapsed_s": round(time.time() - t0, 1),
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
    out = LOGS_DIR / sha / "orchestrator_trace.json"
    out.write_text(json.dumps(trace, indent=2, default=str))
    (LOGS_DIR / sha / "stage_trace.json").write_text(json.dumps(trace, indent=2, default=str))
    print(
        f"[orchestrator] trace -> {out} all_green={trace['all_green']} "
        f"quality_green={quality_green} truly_green={truly_green} stages={stages_run}",
        flush=True,
    )
    return trace


def main() -> int:
    ap = argparse.ArgumentParser(description="CADRE-RevAI LangGraph ReAct stage orchestrator")
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
