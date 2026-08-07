#!/usr/bin/env python3
"""
agentic_langgraph.py — LangGraph ReAct engine for large-mode deep dive.

Called from deep_dive_agentic.py when REVAI_AGENTIC_ENGINE=langgraph (default).
Reuses the same ToolRegistry + checklist + SQL seed + honesty finalize path.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, "/opt/scripts")

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field

from v2_lib import (  # noqa: E402
    ensure_pipeline_runtime_env,
    get_planner_model,
    get_verdict_model,
    load_session,
    llm_judge,
)


# Tools the LangGraph agent may call after the deterministic checklist.
# Checklist already covered static scanners; agent focuses on SQL deep RE + optional extras.
AGENT_TOOL_NAMES = [
    "ghidra_query",
    "ida_query",
    "ghidra_decompile",
    "pe_import_signals",
    "capa_analyze",
    "floss_extract",
    "malcat_analyze",
    "yara_scan",
    "speakeasy_emulate",
    "r2_decompile",
    "z3_solve",
    "angr_analyze",
]


class GhidraQueryArgs(BaseModel):
    sql: str = Field(..., description="SQL against Ghidra tables (funcs, strings, imports, ...)")
    max_rows: int = Field(50, description="Max rows to return")


class IdaQueryArgs(BaseModel):
    sql: str = Field(..., description="SQL against IDA tables")


class GhidraDecompileArgs(BaseModel):
    function_addr: str = Field(..., description="Function address, e.g. 0x401000")


class EmptyArgs(BaseModel):
    pass


class MalcatArgs(BaseModel):
    profile: str = Field("deep", description="triage|deep")


class Z3SolveArgs(BaseModel):
    claim_text: str = Field("", description="MBA identity claim to verify, e.g. x^y + 2*(x&y) == x+y")
    timeout: int = Field(60, description="Timeout in seconds")


class AngrAnalyzeArgs(BaseModel):
    timeout: int = Field(120, description="Timeout in seconds")


_ARG_MODELS: dict[str, type[BaseModel]] = {
    "ghidra_query": GhidraQueryArgs,
    "ida_query": IdaQueryArgs,
    "ghidra_decompile": GhidraDecompileArgs,
    "malcat_analyze": MalcatArgs,
    "z3_solve": Z3SolveArgs,
    "angr_analyze": AngrAnalyzeArgs,
}


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"... (truncated {len(s) - n} chars)"


def _build_lc_tools(registry: Any, session: dict, history: list, findings: dict,
                    max_chars: int, discipline: dict | None = None) -> list:
    """Build LangGraph StructuredTools.

    `discipline` (optional) carries the agent-loop discipline helpers shared
    with the custom engine: redundant-call detection (Feature 2) and budget
    warnings (Feature 1, delivered via the tool's returned output, which the
    model reads as a ToolMessage on its next turn).
    """
    discipline = discipline or {}
    _loop_flag = discipline.get("_loop_flag") or (lambda name: True)
    _call_signature = discipline.get("_call_signature")
    _call_with_tool_retry = discipline.get("_call_with_tool_retry")
    budget = discipline.get("budget")            # tool-call budget (int) or None
    state = discipline.setdefault("state", {"calls": 0, "redundant": 0, "seen": set()})
    tools = []

    def _budget_note() -> str:
        """Feature 1: convergence warning keyed to remaining tool calls."""
        if not budget or not _loop_flag("REVAI_BUDGET_WARNINGS"):
            return ""
        remaining = budget - state["calls"]
        if remaining <= 0:
            return "\n[BUDGET] tool budget exhausted — submit your final answer now."
        if remaining <= 2:
            return f"\n[BUDGET CRITICAL] {remaining} tool call(s) left — prepare your final answer NOW."
        if state["calls"] == max(1, budget // 2):
            return f"\n[BUDGET] half of tool budget used ({state['calls']}/{budget}) — prioritize."
        return ""

    def _make(name: str) -> Callable:
        model = _ARG_MODELS.get(name, EmptyArgs)

        def _runner(**kwargs):
            # Feature 2: redundant-call detection — identical (tool,args) skipped.
            if _call_signature is not None and _loop_flag("REVAI_REDUNDANT_NUDGE"):
                sig = _call_signature(name, kwargs or {})
                if sig in state["seen"]:
                    state["redundant"] += 1
                    history.append({
                        "step": len(history) + 1,
                        "tool": name,
                        "args": kwargs or {},
                        "reason": "langgraph tool call (redundant, skipped)",
                        "error": "redundant tool call (identical to a previous call)",
                        "engine": "langgraph",
                    })
                    print(f"[agentic_langgraph] REDUNDANT {name} skipped "
                          f"(total redundant={state['redundant']})", flush=True)
                    return (
                        "[REDUNDANT] This exact call was already made — reuse its earlier "
                        "output instead of repeating it. " + _budget_note()
                    )
                state["seen"].add(sig)

            state["calls"] += 1
            if _call_with_tool_retry is not None:
                result = _call_with_tool_retry(registry, name, kwargs or {}, session)
            else:
                result = registry.call(name, kwargs or {}, session)
            err = result.get("error") if isinstance(result, dict) else None
            history.append({
                "step": len(history) + 1,
                "tool": name,
                "args": kwargs or {},
                "reason": "langgraph tool call",
                "result": result,
                "error": err,
                "engine": "langgraph",
            })
            findings[f"lg_{name}_{len(history)}"] = result
            return _truncate(json.dumps(result, default=str), max_chars) + _budget_note()

        _runner.__name__ = name
        _runner.__doc__ = f"Run tool `{name}` on the current sample/session."
        return StructuredTool.from_function(
            func=_runner,
            name=name,
            description=_runner.__doc__,
            args_schema=model,
        )

    for name in AGENT_TOOL_NAMES:
        if name in registry.tools:
            tools.append(_make(name))
    return tools


def _extract_verdict_from_messages(messages: list, coerce_fn: Callable) -> dict | None:
    for msg in reversed(messages or []):
        content = None
        if isinstance(msg, AIMessage):
            content = msg.content
        elif isinstance(msg, dict):
            content = msg.get("content")
        if not content or not isinstance(content, str):
            continue
        text = content.strip()
        if not text:
            continue
        # Prefer JSON blob
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                data = json.loads(text[start : end + 1])
                coerced = coerce_fn(data)
                if coerced:
                    return coerced
                if isinstance(data, dict) and data.get("verdict") and data.get("summary"):
                    return data
        except Exception:
            continue
    return None


def run_langgraph_deep_dive(sha: str, max_steps: int = 10, helpers: dict | None = None) -> dict:
    helpers = helpers or {}
    ensure_pipeline_runtime_env()

    ToolRegistry = helpers["ToolRegistry"]
    _run_standard_checklist = helpers["_run_standard_checklist"]
    _history_has_sql_deep = helpers["_history_has_sql_deep"]
    _tool_call_ok = helpers["_tool_call_ok"]
    _coerce_final_answer = helpers["_coerce_final_answer"]
    _finalize_agentic_result = helpers["_finalize_agentic_result"]
    load_intake_validation = helpers["load_intake_validation"]
    GHIDRA_SCHEMA = helpers["GHIDRA_SCHEMA"]
    IDA_SCHEMA = helpers["IDA_SCHEMA"]
    max_chars = int(helpers.get("MAX_TOOL_RESULT_CHARS") or 2000)
    # Agent-loop discipline helpers (shared with the custom engine).
    _loop_flag = helpers.get("_loop_flag") or (lambda name: True)
    _call_signature = helpers.get("_call_signature")
    _unsupported_claims = helpers.get("_unsupported_claims")

    session = load_session(sha)
    # Normalize session_id for ToolRegistry
    if not session.get("session_id"):
        session["session_id"] = session.get("ghidra_session_id") or session.get("session_id")
    file_type = session.get("file_type", {}).get("format", "unknown")
    intake_validation = load_intake_validation(sha)
    source_decisions = intake_validation.get("source_decisions", {})

    registry = ToolRegistry()
    history, findings, tools_raw, tool_gate = _run_standard_checklist(registry, session, sha)
    checklist_ok = bool(tool_gate.get("ok"))
    planner_model = get_planner_model()
    verdict_model = get_verdict_model()

    # SQL seed (same as custom loop)
    if checklist_ok and not _history_has_sql_deep(history):
        ghidra_sid = session.get("ghidra_session_id") or session.get("session_id")
        if ghidra_sid:
            print("[agentic_langgraph] SQL seed: ghidra_query", flush=True)
            args = {
                "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25",
                "max_rows": 25,
            }
            result = registry.call("ghidra_query", args, session)
            entry = {
                "step": 0,
                "tool": "ghidra_query",
                "args": args,
                "reason": "Auto SQL seed for large-mode deep RE gate",
                "result": result,
                "error": result.get("error") if isinstance(result, dict) else None,
                "auto_sql": True,
            }
            history.append(entry)
            findings["auto_ghidra_query_0"] = result

    sql_ok = _history_has_sql_deep(history)
    # Tool-call budget for discipline warnings (Feature 1/2). Scaled from max_steps.
    tool_budget = max(10, int(max_steps) * 2)
    discipline = {
        "_loop_flag": _loop_flag,
        "_call_signature": _call_signature,
        "budget": tool_budget,
        "state": {"calls": 0, "redundant": 0, "seen": set()},
    }
    lc_tools = _build_lc_tools(registry, session, history, findings, max_chars, discipline)

    api_key = os.environ.get("REVAI_LLM_API_KEY")
    api_url = (os.environ.get("REVAI_LLM_API_URL") or "").rstrip("/")
    # ChatOpenAI expects base without /chat/completions
    if api_url.endswith("/chat/completions"):
        api_url = api_url[: -len("/chat/completions")]

    llm = ChatOpenAI(
        model=planner_model,
        api_key=api_key,
        base_url=api_url,
        temperature=0.0,
        max_tokens=4096,
    )

    findings_preview = _truncate(json.dumps(findings, default=str), 3500)
    system_prompt = f"""You are an agentic malware reverse-engineering assistant using tool calling.

Sample: {session.get('sample_path')}
SHA256: {sha}
File type: {file_type}
Checklist complete: {checklist_ok}
SQL deep RE already seeded: {sql_ok}
Source decisions: {json.dumps(source_decisions, default=str)[:1500]}

Ghidra SQL schema:
{GHIDRA_SCHEMA}

IDA SQL schema:
{IDA_SCHEMA}

Checklist findings (already collected — do not re-run the whole checklist unless needed):
{findings_preview}

Your job:
1. Use ghidra_query / ida_query / ghidra_decompile to deepen the RE (imports, suspicious funcs, strings).
2. Use z3_solve to verify MBA/opaque-predicate claims when the analysis mentions obfuscation.
3. Use angr_analyze to deflatten CFF/control-flow-flattened functions when cff_detect found candidates.
4. When done, reply with a FINAL flat JSON object ONLY (no markdown) with keys:
   verdict, confidence (0-100 or high/medium/low), summary, key_evidence (list of strings).
Do not wrap the final answer in "actions" or "final_answer" nesting.
Cite concrete tool/SQL evidence in key_evidence.
BUDGET DISCIPLINE: you have a limited tool-call budget. Do not repeat an identical
query; reuse earlier outputs. When a tool result carries a [BUDGET] note, converge
and prepare your final answer. Only claim techniques/behaviors backed by tool evidence.
MASQUERADE AWARENESS: VersionInfo / product / company metadata is trivially forged and
is NOT evidence of legitimacy. If deterministic tools (Malcat obfuscation anomalies,
YARA family/keylogger rules, capa persistence/injection, high-signal imports) fire
maliciously, the verdict MUST be malicious even if strings/product names look
legitimate. Never call a tool-flagged sample benign on brand metadata alone.
"""

    agent = create_react_agent(llm, tools=lc_tools, prompt=system_prompt)
    recursion_limit = max(8, int(max_steps) * 2 + 4)
    print(
        f"[agentic_langgraph] invoke recursion_limit={recursion_limit} tools={len(lc_tools)}",
        flush=True,
    )

    final_answer = None
    try:
        result = agent.invoke(
            {
                "messages": [
                    HumanMessage(
                        content=(
                            f"Analyze sample {sha}. SQL seed status sql_ok={sql_ok}. "
                            "Run at least one useful SQL or decompile query if needed, "
                            "then produce the final flat JSON verdict."
                        )
                    )
                ]
            },
            config={"recursion_limit": recursion_limit},
        )
        messages = result.get("messages") or []
        # Record AI/tool turns lightly for audit
        for msg in messages:
            if isinstance(msg, ToolMessage):
                # already recorded in tool wrappers
                continue
            if isinstance(msg, AIMessage) and msg.tool_calls:
                history.append({
                    "step": len(history) + 1,
                    "tool": None,
                    "reason": "langgraph planner tool_calls",
                    "tool_calls": [
                        {"name": tc.get("name"), "args": tc.get("args")}
                        for tc in (msg.tool_calls or [])
                    ],
                    "engine": "langgraph",
                })
        final_answer = _extract_verdict_from_messages(messages, _coerce_final_answer)
    except Exception as e:
        print(f"[agentic_langgraph] agent.invoke error: {e}", flush=True)
        history.append({"step": len(history) + 1, "error": f"langgraph invoke failed: {e}"})

    sql_ok = _history_has_sql_deep(history)

    if not final_answer:
        # Forced flash verdict from accumulated findings (same honesty path as custom)
        prompt = (
            "Produce a flat JSON object with keys verdict, confidence, summary, key_evidence. "
            "No markdown, no nested final_answer.\n\n"
            f"checklist_ok={checklist_ok} sql_ok={sql_ok}\n"
            f"findings:\n{_truncate(json.dumps(findings, default=str), 6000)}\n"
        )
        try:
            resp = llm_judge(prompt, model=verdict_model)
            content = resp["choices"][0]["message"]["content"]
            start = content.find("{")
            end = content.rfind("}")
            raw = json.loads(content[start : end + 1]) if start >= 0 and end > start else {}
            final_answer = _coerce_final_answer(raw) or raw
        except Exception as e:
            final_answer = {
                "verdict": "unknown",
                "confidence": 0,
                "summary": f"LangGraph deep dive failed to produce verdict: {e}",
            }

    # Feature 3: hallucination check — final claims must be evidence-grounded.
    # One grounded correction pass if any claim lacks supporting tool evidence.
    if (
        final_answer
        and _unsupported_claims is not None
        and _loop_flag("REVAI_HALLUCINATION_CHECK")
    ):
        unsupported = _unsupported_claims(final_answer, history, findings)
        if unsupported:
            print(
                f"[agentic_langgraph] HALLUCINATION CHECK: {len(unsupported)} unsupported "
                f"claim(s); running grounded correction pass",
                flush=True,
            )
            history.append({
                "step": len(history) + 1,
                "error": (
                    "final_answer hallucination check: unsupported claims: "
                    + "; ".join(str(u)[:80] for u in unsupported[:3])
                ),
                "engine": "langgraph",
            })
            try:
                prompt = (
                    "Your previous verdict contained claims with no supporting tool evidence: "
                    + "; ".join(str(u)[:120] for u in unsupported[:5])
                    + "\nRe-derive the verdict STRICTLY from the tool evidence below. Drop any "
                    "claim not present in the evidence. Return a flat JSON object with keys "
                    "verdict, confidence, summary, key_evidence (list of strings). No markdown.\n\n"
                    f"evidence:\n{_truncate(json.dumps(findings, default=str), 6000)}\n"
                )
                resp = llm_judge(prompt, model=verdict_model)
                content = resp["choices"][0]["message"]["content"]
                start = content.find("{")
                end = content.rfind("}")
                raw = json.loads(content[start : end + 1]) if start >= 0 and end > start else {}
                corrected = _coerce_final_answer(raw) or raw
                if isinstance(corrected, dict) and corrected.get("verdict"):
                    final_answer = corrected
            except Exception as e:
                print(f"[agentic_langgraph] hallucination correction pass failed: {e}", flush=True)

    return _finalize_agentic_result(
        sha=sha,
        session=session,
        history=history,
        findings=findings,
        tools_raw=tools_raw,
        tool_gate=tool_gate,
        checklist_ok=checklist_ok,
        sql_ok=sql_ok,
        final_answer=final_answer,
        planner_model=planner_model,
        verdict_model=verdict_model,
        intake_validation=intake_validation,
        engine="langgraph",
        redundant_calls=discipline["state"].get("redundant", 0),
    )
