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
import time
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, "/opt/scripts")

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field

from skills import skill_grounding_block as _skill_grounding_block  # noqa: E402
from domain_graph import (  # noqa: E402
    DOMAINS,
    domain_graph_enabled,
    domain_step_budget,
)
from report_quality import VERDICT_CALIBRATION_CONTRACT  # noqa: E402
from v2_lib import (  # noqa: E402
    case_dir,
    ensure_pipeline_runtime_env,
    get_llm_temperature,
    get_planner_model,
    get_verdict_model,
    load_session,
    llm_judge,
    normalize_llm_json,
    llm_usage_journal,
)


class _UsageCallback(BaseCallbackHandler):
    """Journal planner-loop LLM usage and stream tool progress as JSONL.

    Progress is what makes the ReAct loop observable while it runs: one line per
    tool start/end and LLM turn, tailed by the Console's live poller. Writing is
    best-effort - a progress failure must never break a run.
    """

    def __init__(self, model: str, progress_path: Path | None = None) -> None:
        self.model = model
        self.progress_path = progress_path
        self._run_names: dict[str, str] = {}

    def _progress(self, entry: dict) -> None:
        if self.progress_path is None:
            return
        try:
            entry["ts"] = time.time()
            with self.progress_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass

    def on_llm_end(self, response, **kwargs) -> None:  # noqa: ARG002
        try:
            token_usage = getattr(response, "llm_output", None) or {}
            usage = token_usage.get("token_usage") or {}
            # LangChain may expose usage_metadata on generations (newer versions)
            if not usage:
                gen = (response.generations or [[]])[0]
                if gen:
                    usage = (getattr(gen[0], "generation_info", None) or {}).get(
                        "token_usage"
                    ) or {}
            if usage:
                llm_usage_journal(
                    model=self.model,
                    response={"usage": usage, "model": self.model},
                    stage="deep_dive_planner",
                    note="langgraph-chatopenai",
                )
            self._progress({"event": "llm_end", "model": self.model,
                            "tokens": usage or {}})
        except Exception:
            pass

    def on_tool_start(self, serialized, input_str, **kwargs) -> None:
        try:
            name = (serialized or {}).get("name") if isinstance(serialized, dict) else None
            run_id = str(kwargs.get("run_id") or "")
            if run_id:
                self._run_names[run_id] = name or "?"
            self._progress({"event": "tool_start", "tool": name,
                            "input": str(input_str)[:300]})
        except Exception:
            pass

    def on_tool_end(self, output, **kwargs) -> None:
        try:
            run_id = str(kwargs.get("run_id") or "")
            self._progress({"event": "tool_end",
                            "tool": self._run_names.pop(run_id, None),
                            "output_chars": len(str(output))})
        except Exception:
            pass


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
    "api_lookup",
    "compare_files",
    # load_skill MUST stay in this list. The system prompt tells the model to load
    # a procedure before doing the work it covers; a tool the prompt names but the
    # graph does not bind cannot execute (the provider rejects the unbound function
    # name), so the step is consumed, the procedure never arrives, and the agent
    # falls back to recall -- the exact failure the skills layer exists to prevent.
    "load_skill",
]

#: Per-tool result caps. The agentic loop truncates tool results to a shared
#: budget (MAX_TOOL_RESULT_CHARS, 2000) so one noisy tool cannot eat the context.
#: A skill is a procedure document: truncating it at 2000 chars cuts the "Stop
#: conditions" and "What this skill does NOT cover" sections and -- for
#: verdict-calibration -- the calibration contract itself, which is the part the
#: skill exists to deliver. Re-calling does not help (the redundant-call detector
#: flags it), so the procedure must arrive whole. Skills are bounded by
#: MAX_SKILL_CHARS in skills.py, so this stays a fixed, predictable cost.
TOOL_RESULT_CHARS = {
    "load_skill": 6000,
}


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


class ApiLookupArgs(BaseModel):
    api: str = Field("", description="API symbol as a disassembler shows it, e.g. ZwOpenProcess")
    query: str = Field("", description="Free-text search instead of a symbol, e.g. 'process hollowing'")
    limit: int = Field(10, description="Max search results")


class CompareFilesArgs(BaseModel):
    b: str = Field(..., description="Path to the second file (e.g. an extracted payload)")
    a: str = Field("", description="Reference file; defaults to the analyzed sample")


class LoadSkillArgs(BaseModel):
    skill: str = Field(
        ...,
        description=(
            "Procedure to load, by name: re-methodology, unpack-and-verify, "
            "obfuscation-recognition, ghidra-sql-recipes, verdict-calibration. "
            "An unknown name is an error -- do not substitute a guess."
        ),
    )


_ARG_MODELS: dict[str, type[BaseModel]] = {
    "ghidra_query": GhidraQueryArgs,
    "ida_query": IdaQueryArgs,
    "ghidra_decompile": GhidraDecompileArgs,
    "malcat_analyze": MalcatArgs,
    "z3_solve": Z3SolveArgs,
    "angr_analyze": AngrAnalyzeArgs,
    "api_lookup": ApiLookupArgs,
    "compare_files": CompareFilesArgs,
    "load_skill": LoadSkillArgs,
}

#: Model-facing descriptions where the generic "Run tool X" text is not enough.
_TOOL_DOC = {
    "api_lookup": (
        "Offline Windows-API grounding: what an API does and how malware abuses it "
        "(reference text, curated malicious-use notes, malapi.io attack categories). "
        "Args: api (symbol as a disassembler shows it - A/W, Nt/Zw, __imp_, @N all fold) "
        "OR query (free-text search). Call this before describing any Windows API's "
        "behaviour; if it reports no entry, say it was not found."
    ),
    "compare_files": (
        "Compare two binaries structurally (loader vs payload, packed vs unpacked): "
        "sizes, imphash equality, shared/unique sections with entropy deltas, import "
        "overlap, exact 64-byte chunk containment. Args: b (second file path); a "
        "defaults to the analyzed sample. Facts only - do not claim a family from it."
    ),
    "load_skill": (
        "Load a reverse-engineering PROCEDURE by name and follow it: re-methodology, "
        "unpack-and-verify, obfuscation-recognition, ghidra-sql-recipes, "
        "verdict-calibration. Returns the cited, versioned procedure text in full. "
        "Load the procedure BEFORE attempting the work it covers -- a procedure "
        "recalled from memory is not evidence. Load verdict-calibration before "
        "rendering any judgment. Args: skill (name, required). An unknown name is an "
        "error; do not substitute a guess."
    ),
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
            # A skill is a procedure document, not a query result: it needs its
            # own (larger) cap or the stop-conditions section -- the part that says
            # when to stop digging -- is the part that gets cut. See TOOL_RESULT_CHARS.
            _cap = TOOL_RESULT_CHARS.get(name, max_chars)
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
            return _truncate(json.dumps(result, default=str), _cap) + _budget_note()

        _runner.__name__ = name
        _runner.__doc__ = _TOOL_DOC.get(name) or f"Run tool `{name}` on the current sample/session."
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


#: What the ReAct diagram can honestly say. The prebuilt ReAct graph is a
#: two-node loop, so the picture shows *what executes*, not what the model
#: reasons about - the UI states this rather than implying more.
GRAPH_CAVEAT = (
    "Topology only: the prebuilt ReAct graph is a two-node loop "
    "(agent <-> tools). It shows what executes, not what the model decides."
)


def agent_graph_mermaid() -> dict:
    """Return the deep-dive agent graph as Mermaid, plus its tool inventory.

    Built from the same ``create_react_agent`` call the pipeline uses, with a
    placeholder tool and a non-calling model client, so no session, sample or
    LLM request is needed. Fail-open: if LangGraph cannot build the graph the
    caller still gets the tool inventory and the static node names.
    """
    static_nodes = ["agent", "tools"]
    base = {
        "engine": "langgraph",
        "tools": list(AGENT_TOOL_NAMES),
        "node_names": static_nodes,
        "caveat": GRAPH_CAVEAT,
    }
    try:
        from langchain_core.tools import StructuredTool

        placeholder = StructuredTool.from_function(
            func=lambda: "noop",
            name="topology_placeholder",
            description="Placeholder so the graph includes its tools node.",
        )
        model = ChatOpenAI(**{
            "model": os.environ.get("REVAI_LLM_MODEL") or "configured-llm",
            "api_key": os.environ.get("REVAI_LLM_API_KEY") or "not-used",
            "base_url": (os.environ.get("REVAI_LLM_API_URL") or "http://127.0.0.1").rstrip("/"),
            "temperature": 0.0,
        })
        agent = create_react_agent(model, tools=[placeholder], prompt="")
        graph = agent.get_graph()
        nodes = [getattr(n, "id", None) or getattr(n, "name", None)
                 for n in graph.nodes.values()]
        return {
            **base,
            "ok": True,
            "mermaid": graph.draw_mermaid(),
            "node_names": [n for n in nodes if n] or static_nodes,
        }
    except Exception as exc:  # fail-open: the endpoint must answer regardless
        return {**base, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


def messages_from_stream_chunks(chunks) -> list:
    """Flatten ``stream(stream_mode="updates")`` chunks into one message list.

    Each chunk is ``{node_name: {"messages": [...]}}``; the final message list is
    identical to what ``invoke`` would have returned, so downstream verdict
    extraction does not care which path ran.
    """
    messages: list = []
    for chunk in chunks or []:
        if not isinstance(chunk, dict):
            continue
        for payload in chunk.values():
            if isinstance(payload, dict):
                messages.extend(payload.get("messages") or [])
    return messages


def _llm_json(text: str) -> dict:
    """Parse a model reply into a dict, tolerating fences and prose.

    A domain node's reply is free text; an unparseable one must become a partial
    result rather than an exception, because one badly-formed domain should not
    end the whole dive.
    """
    try:
        out = normalize_llm_json(text or "")
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}

def _need(helpers: dict, name: str):
    """Fetch a helper by name, failing loudly at the boundary.

    The domain path used to call `_coerce_final_answer` as though it were
    module level. It is a local of the flat engine, so every domain node raised
    NameError, degraded to `not-reconstructed`, and synthesis then caught its own
    NameError and returned a TRUTHY `{"verdict": "unknown"}` -- which suppressed
    the flat-engine fallback, so the run reported a fabricated verdict at
    confidence 0 instead of falling back to a real dive.

    Resolving helpers through one function puts the failure here, where the
    caller can still fall back, rather than nine times inside a graph.
    """
    fn = (helpers or {}).get(name)
    if not callable(fn):
        raise KeyError(f"domain graph requires helper {name!r}")
    return fn


def _unpacked_image_context(findings: dict) -> str:
    """The unpacked image's evidence, as context for every capability domain.

    Measured on packed_rook_native (2026-10-10): `unpack_pass` succeeded
    (UPX0/UPX1/UPX2) and the unpacked capa rules carried the real behavioural
    evidence, yet all nine domain answers reasoned over the PACKED stub -- "no
    persistence in the packed binary", "4 imports" -- and reported 0 observed /
    9 inferred while the deep dive's own summary cited a C2 domain and unpacked
    behavioural rules. The domains were analysing the wrong image.

    Returns "" when nothing was unpacked, so an unpacked-less run is unchanged.
    """
    if not findings:
        return ""
    up = findings.get("unpack_pass") or {}
    upx = findings.get("checklist_upx_unpack") or {}
    if not (up.get("ok") or upx.get("upx_ok")):
        return ""

    lines = ["## UNPACKED IMAGE (authoritative for behaviour)",
             "",
             "This sample is PACKED. The import table and strings you will read "
             "from the original binary belong to the packer stub, not to the "
             "sample's real logic. The unpacked image below is what the "
             "behaviour actually lives in.",
             ""]
    if up.get("ok"):
        secs = up.get("sections") or []
        if secs:
            lines.append("Unpacked sections: " + ", ".join(
                f"{s.get('name')} (rva {s.get('rva')}, "
                f"vsize {s.get('virtual_size')})" for s in secs[:8]))
        for key in ("imports", "strings", "capa", "notes"):
            v = up.get(key)
            if v:
                lines.append(f"Unpacked {key}: {str(v)[:600]}")
    if upx.get("upx_ok"):
        lines.append(f"UPX unpack: succeeded ({str(upx.get('sample'))[-60:]})")
    lines += ["",
              "Reason over BOTH images. When you cite a finding, say which image "
              "it came from (\"unpacked:\" or \"packed stub:\"). A capability "
              "absent from the stub but present in the unpacked image is "
              "OBSERVED, not absent -- the stub's four imports prove nothing "
              "about the sample.",
              ""]
    return "\n".join(lines)


def _domain_recursion_limit(budget: int) -> int:
    """Super-step ceiling for one domain node.

    LangGraph counts super-steps, not tool calls: an agent node is one step and
    each tool node another, and a single agent turn may fan out to several tools
    at once. So this CANNOT express "at most N tool calls" -- the first real run
    proved it, spending 4-6 calls against a budget of 3 under a limit computed as
    2*budget+2.

    What it does give is a ceiling that cannot run away, plus enough headroom for
    the node to actually REACH AN ANSWER. That headroom matters: at the old size
    seven of nine nodes were cut off mid-investigation and returned "Sorry, need
    more steps to process this request", which is a truncated agent, not a
    finding.

    Measured on packed_rook_native (2026-10-10): a budget of 3 still left
    `persistence` (12 tool calls) and `c2_network` (10) truncated under a limit
    of 20, and a truncated node can NEVER be `observed` -- so the ceiling was
    silently costing evidence. The tool budget is a REQUEST the node is asked to
    respect; the ceiling is what stops a runaway. Sizing the ceiling off the
    budget conflates them and penalises the node that investigates most
    thoroughly. It is now generous and independently settable.
    """
    raw = os.environ.get("REVAI_DOMAIN_MAX_STEPS", "").strip()
    if raw:
        try:
            val = int(raw)
            if val > 0:
                return val
        except ValueError:
            pass
    # ~25-30 tool calls of headroom: a node that fans out or works in parallel
    # spends several super-steps per turn.
    return max(60, int(budget) * 12 + 8)


def run_domain_deep_dive(sha: str, max_steps: int, helpers: dict,
                         registry: Any, session: dict, file_type: str,
                         history: list, findings: dict, lc_tools: list,
                         llm: Any, system_prompt: str,
                         verdict_model: str | None = None) -> dict:
    """Plan #20: run the deep dive as named domain nodes.

    Each domain node gets its own bounded investigation over the SAME tool
    registry, so a stubborn injection question can no longer time out the whole
    run before persistence was ever looked at. The graph's node list is the
    coverage record -- "what did you examine" is structural, not a sentence the
    model was asked to write.

    Returns the same final_answer shape `run_langgraph_deep_dive` produces, so
    the caller (and every gate downstream) is unchanged. Returns FALSY when no
    domain produced a usable answer, which is the caller's signal to fall back
    to the flat engine: a real dive always beats a fabricated `unknown`.
    """
    import domain_graph as dg

    # Resolve up front: a missing helper must abort the domain path BEFORE any
    # node runs, not be discovered nine times as a swallowed NameError. It must
    # also be FALSY to the caller, so the flat engine still runs -- an exception
    # escaping here would take the whole deep dive with it.
    try:
        coerce = _need(helpers, "_coerce_final_answer")
    except Exception as exc:
        print(f"[agentic_langgraph] domain path unavailable: {exc}", flush=True)
        history.append({"step": len(history) + 1,
                        "error": f"domain path unavailable: {exc}",
                        "engine": "domain-graph"})
        return {}

    budget = dg.domain_step_budget()
    limit = _domain_recursion_limit(budget)
    # #58: on a packed sample the domains used to reason over the stub. Give
    # every node the unpacked image so a capability hidden by the packer is not
    # reported as absent.
    _unpack_ctx = _unpacked_image_context(findings)
    per_domain: dict[str, dict] = {}
    domain_history: list[dict] = []

    def _node(state: dict, domain: dict) -> dict:
        key = domain["key"]
        _prompt = (
            f"{system_prompt}\n\n"
            f"{_unpack_ctx}"
            f"## Domain under investigation: {domain['title']}\n\n"
            f"{domain['question']}\n\n"
            f"Domain-specific instructions:\n"
            f"- You have a budget of {budget} tool calls on THIS domain and a "
            f"hard ceiling of {limit} steps. The runtime stops you at the "
            f"ceiling and a truncated node returns nothing useful, so stop "
            f"investigating and answer with what you have.\n"
            f"- Answer for THIS domain only. Other domains are handled by their "
            f"own nodes -- do not pre-empt them.\n"
            f"- Cite the concrete evidence you used (tool, SQL, or offset).\n"
            f"- If the evidence does not establish the behaviour, say so as "
            f"\"not observed\" with what you checked. 'not observed' is a valid, "
            f"useful answer; a guess is not.\n"
            f"- 'not-explored' asserts nothing beyond not having looked. "
            f"Anything else needs evidence.\n"
            f"- Your ENTIRE reply must be one JSON object and nothing else: no "
            f"preamble, no markdown, no code fence, no commentary before or "
            f"after it. Prose instead of JSON is recorded as an unstructured "
            f"partial answer.\n\n"
            f"Reply with exactly this shape:\n"
            f"{{\"status\": \"understood|partial|not-reconstructed|not-explored\","
            f" \"answer\": \"...\", \"evidence\": [\"...\"], \"reason\": \"...\"}}\n"
        )
        agent = create_react_agent(llm, tools=lc_tools, prompt=_prompt)
        msgs = agent.invoke(
            {"messages": [("user", f"Investigate {key} for "
                                     f"{session.get('sample_path', '')}")]},
            config={"recursion_limit": limit},
        )
        history_msgs = msgs.get("messages") or []
        text = ""
        finish = None
        for m in reversed(history_msgs):
            meta = getattr(m, "response_metadata", None) or {}
            if isinstance(meta, dict) and meta.get("finish_reason"):
                finish = str(meta.get("finish_reason"))
            c = getattr(m, "content", "")
            if isinstance(c, str) and c.strip():
                text = c
                break
        # What the node ACTUALLY spent, as opposed to what it was asked for.
        used = sum(len(getattr(m, "tool_calls", None) or [])
                   for m in history_msgs)
        parsed, why = dg.parse_domain_reply(text)
        # `_coerce_final_answer` is the VERDICT coercer: it takes the raw JSON
        # string llm_judge returned. `parse_domain_reply` already returns a dict,
        # and handing that dict to the coercer makes it return a non-dict -- which
        # discarded 7 of 9 correctly-formed domain answers on the first real run.
        # Use the coercer when it helps, and keep the parsed dict when it does not.
        coerced = coerce(parsed) if parsed else {}
        if isinstance(coerced, dict) and coerced:
            parsed = coerced
        elif not isinstance(parsed, dict):
            parsed, why = {}, (why or "reply was not a dict")
        fmt = "json"
        if not parsed and text.strip():
            # No JSON, but the node may still have ANSWERED -- and a markdown
            # "not observed, here is what I checked" is a real finding, not
            # nothing. Keep the prose as the answer instead of discarding the
            # analysis, and mark it unstructured so the distinction survives.
            parsed = {"status": dg.STATUS_PARTIAL, "answer": text.strip()[:1200],
                      "evidence": [], "reason": why}
            fmt = "prose"
        answer = str(parsed.get("answer") or "")
        has_finding = bool(answer or parsed.get("evidence"))
        model_status = str(parsed.get("status") or "").strip().lower() or None
        contradict = False
        if not text:
            status = dg.STATUS_NOT_EXPLORED
        elif model_status in (dg.STATUS_NOT_EXPLORED, dg.STATUS_NOT_RECONSTRUCTED) \
                and not has_finding:
            # Said it did not look, and supplied nothing. That is an honest
            # report of an unfinished domain, not a plumbing failure.
            status = model_status
        elif not has_finding:
            status = dg.STATUS_PARTIAL
        elif model_status in (dg.STATUS_NOT_EXPLORED, dg.STATUS_NOT_RECONSTRUCTED):
            # The node used tools, produced an answer, and then claimed it had
            # not investigated. Three of nine domains did exactly this on the
            # first working run -- "not-reconstructed" alongside a complete
            # analysis. The claim is self-contradictory: the answer is evidence
            # it WAS investigated. Recording the claim verbatim would understate
            # the work, and recording `understood` would overstate the
            # conclusion, so it becomes `partial` with the claim preserved.
            status = dg.STATUS_PARTIAL
            contradict = True
        else:
            status = model_status or dg.STATUS_PARTIAL
        entry = {
            "status": status,
            "answer": answer[:1200],
            "evidence": [str(e)[:120] for e in (parsed.get("evidence") or [])[:8]],
            "reason": str(parsed.get("reason") or "")[:400],
            "format": fmt,
            "tool_calls_used": used,
            "step_budget": budget,
            "recursion_limit": limit,
            # Whether this node was given the unpacked image. A packed sample
            # whose nodes were NOT given it is exactly the #58 defect, and this
            # makes that visible in the artifact rather than inferable.
            "unpack_evidence": bool(_unpack_ctx),
        }
        if model_status:
            entry["model_status"] = model_status
        if contradict:
            entry["status_contradicts_answer"] = True
        if finish:
            entry["finish_reason"] = finish
        if fmt != "json" or not has_finding:
            # Enough of the reply to diagnose, and the reason it did not parse.
            # The first real run recorded a 400-char slice, which is not enough
            # to tell a truncated reply from a prose one -- the JSON never
            # closed inside the slice, so the artifact could not be re-parsed.
            entry["raw_excerpt"] = text[:2000]
            entry["parse_failure"] = why
            if finish == "length":
                entry["parse_failure"] += " (finish_reason=length)"
            elif finish is None and "need more steps" in text[:200].lower():
                # LangGraph reported no finish_reason, and the reply is its
                # out-of-steps placeholder: this node was truncated.
                entry["truncated"] = True
        if used > budget:
            entry["over_budget"] = True
        domain_history.append({"domain": key, "step_budget": budget,
                               "recursion_limit": limit, "result": entry,
                               "engine": "domain-graph"})
        return entry

    try:
        compiled = dg.build_domain_graph(_node)
        state = compiled.invoke({"sha": sha, "session": session,
                                 "file_type": file_type})
        per_domain = state.get("domains") or {}
    except Exception as exc:
        print(f"[agentic_langgraph] domain graph failed: {exc}", flush=True)
        history.append({"step": len(history) + 1,
                        "error": f"domain graph failed: {exc}",
                        "engine": "domain-graph"})
        return {}

    for entry in domain_history:
        history.append({"step": len(history) + 1,
                        "tool": f"domain:{entry['domain']}",
                        "reason": entry["result"]["answer"][:120],
                        "result": entry["result"],
                        "error": entry["result"].get("reason") or None,
                        "engine": "domain-graph"})
    summary = dg.summarise(per_domain)
    findings["domain_graph"] = summary
    findings["domain_findings"] = dg.domain_findings_text(per_domain)

    if not summary["substantive"]:
        # Nothing was actually SAID. Every status alone would pass: nine
        # `partial` nodes with an empty answer each are a total failure wearing
        # a full set of nodes. Synthesising a verdict from nine empty bullets is
        # fabrication, so fall back and run a real dive.
        reason = (f"falling back to the flat engine: domain graph produced no "
                  f"substantive answer (statuses="
                  f"{sorted(set(summary['domains'].values()))}, "
                  f"substantive={len(summary['substantive'])}/"
                  f"{len(dg.DOMAIN_KEYS)})")
        print(f"[agentic_langgraph] {reason}", flush=True)
        history.append({"step": len(history) + 1, "tool": "domain:summary",
                        "error": reason, "engine": "domain-graph"})
        return {}

    return _domain_final_answer(per_domain, helpers, verdict_model, coerce)


def _domain_final_answer(per_domain: dict, helpers: dict,
                         verdict_model: str | None, coerce=None) -> dict:
    """One verdict from the per-domain picture.

    The domains are evidence, not votes: each contributes what it found, and the
    judgment call stays with the model exactly as it does on the flat path.
    """
    coerce = coerce or _need(helpers, "_coerce_final_answer")
    import domain_graph as dg
    cov = dg.domain_coverage(per_domain)
    text = "\n".join(
        f"- **{k}** [{v.get('status')}]: {v.get('answer', '')}"
        for k, v in per_domain.items())
    prompt = (
        "A deep dive examined these capability domains, one node each:\n\n"
        f"{text}\n\n"
        "Render the final judgment as a JSON object with keys verdict, "
        "confidence (0-100), summary, key_evidence (list of strings).\n"
        "Coverage matters: name every domain the evidence supports AND the "
        "domains that came back 'not observed'. A domain you never mention is a "
        "coverage failure. The verdict follows the evidence, not the count of "
        "domains.\n"
        + VERDICT_CALIBRATION_CONTRACT
    )
    if cov["unusable"]:
        # Say it in the prompt rather than let the model read nine bullets and
        # assume nine investigations.
        prompt += (
            "\n\nCOVERAGE HONESTY: these domains did NOT yield a usable "
            f"answer: {', '.join(cov['unusable'])}. Do not describe them as "
            "investigated, and do not let their absence inflate confidence.\n")
    try:
        raw = llm_judge(prompt, model=verdict_model)
        return coerce(raw) or {}
    except Exception as exc:
        # FALSY, not `unknown`: a synthesis that failed has produced no
        # verdict, and returning a shaped one here suppresses the caller's
        # flat-engine fallback.
        print(f"[agentic_langgraph] domain synthesis failed: {exc}", flush=True)
        return {}


def run_langgraph_deep_dive(sha: str, max_steps: int = 10, helpers: dict | None = None) -> dict:
    helpers = helpers or {}
    ensure_pipeline_runtime_env()

    ToolRegistry = helpers["ToolRegistry"]
    _run_standard_checklist = helpers["_run_standard_checklist"]
    _history_has_sql_deep = helpers["_history_has_sql_deep"]
    _tool_call_ok = helpers["_tool_call_ok"]
    _coerce_final_answer = helpers["_coerce_final_answer"]
    _complete_final_answer_retry = helpers.get("_complete_final_answer_retry")
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
                "sql": "SELECT name, addr, size FROM funcs ORDER BY size DESC LIMIT 25",
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

    # Progress stream (observability): fresh JSONL per run, tailed by /live.
    progress_path: Path | None = case_dir(sha) / "deep_dive" / "deep-dive-progress.jsonl"
    try:
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        progress_path.write_text("", encoding="utf-8")
    except Exception:
        progress_path = None

    llm = ChatOpenAI(
        model=planner_model,
        api_key=api_key,
        base_url=api_url,
        # REVAI_LLM_TEMPERATURE, honoured here too: this site hardcoded 0.0,
        # so the setting only ever applied to the urllib request path.
        temperature=get_llm_temperature(),
        max_tokens=4096,
        callbacks=[_UsageCallback(planner_model, progress_path)],
    )

    # One definition of the skills instruction, shared with the custom
    # engine's build_messages. Two copies is how the LangGraph engine came
    # to have load_skill bound but never told the model about it.
    skill_block = _skill_grounding_block()
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
API GROUNDING: before describing what a Windows API does or how malware abuses it,
call api_lookup for that symbol (it accepts the spelling a disassembler shows - A/W,
Nt/Zw, __imp_, @N decoration all fold). If api_lookup reports no entry, say it was
not found instead of recalling an answer.

{skill_block}
"""

    # Plan #20: the deep dive as named domain nodes, opt-in.
    #
    # The flat ReAct loop above asks the model to self-check every capability
    # domain before answering -- a request, not a structure. A domain it never
    # visits is a coverage failure the depth gate can only see afterwards, in
    # the summary's prose. The domain graph makes it structural: one node per
    # domain, its own budget, its own result.
    #
    # Off by default so the flat engine stays the validated path until this is
    # exercised on a real sample. Both engines share the registry, the
    # checklist and the gates.
    if domain_graph_enabled():
        print(f"[agentic_langgraph] domain graph ({len(DOMAINS)} domains, "
              f"budget {domain_step_budget()} each)", flush=True)
        _dom = run_domain_deep_dive(
            sha, max_steps, helpers, registry, session, file_type,
            history, findings, lc_tools, llm, system_prompt,
            verdict_model=get_verdict_model())
        if _dom:
            return _finalize_agentic_result(
                _dom, history, findings, verdict_model=get_verdict_model(),
                label="langgraph-domains")
        # An empty result means the graph itself failed: fall through to the
        # flat engine rather than ending the dive with nothing.

    agent = create_react_agent(llm, tools=lc_tools, prompt=system_prompt)
    recursion_limit = max(8, int(max_steps) * 2 + 4)
    print(
        f"[agentic_langgraph] invoke recursion_limit={recursion_limit} tools={len(lc_tools)}",
        flush=True,
    )

    final_answer = None
    agent_input = {
        "messages": [
            HumanMessage(
                content=(
                    f"Analyze sample {sha}. SQL seed status sql_ok={sql_ok}. "
                    "Run at least one useful SQL or decompile query if needed, "
                    "then produce the final flat JSON verdict."
                )
            )
        ]
    }
    # REVAI_DEEP_STREAM=1 (plan #19c) consumes the graph as a stream instead of a
    # single invoke, so steps are observable as they happen. The emitted messages
    # are identical, and `invoke` remains the default because it is the proven path.
    stream_mode = os.environ.get("REVAI_DEEP_STREAM", "").strip().lower() in (
        "1", "true", "yes", "on")
    try:
        if stream_mode:
            messages: list = []
            messages = messages_from_stream_chunks(agent.stream(
                agent_input,
                config={"recursion_limit": recursion_limit},
                stream_mode="updates",
            ))
            result = {"messages": messages}
        else:
            result = agent.invoke(
                agent_input, config={"recursion_limit": recursion_limit})
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

    if _complete_final_answer_retry is not None:
        final_answer = _complete_final_answer_retry(
            final_answer, findings, verdict_model, label="langgraph"
        )

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
