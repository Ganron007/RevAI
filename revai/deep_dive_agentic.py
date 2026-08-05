#!/usr/bin/env python3
"""
deep_dive_agentic.py — Agentic LLM-driven deep dive for large mode.

Engines (REVENG_AGENTIC_ENGINE):
  langgraph — LangChain tools + LangGraph create_react_agent (default)
  custom    — JSON planner loop (stopgap / fallback)

Flow for both engines:
  TOOL_MANIFEST checklist → SQL seed → agent loop → honesty gates → artifacts

Planner = configured via REVENG_LLM_PLANNER_MODEL; final verdict / judgment = REVENG_LLM_VERDICT_MODEL.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from v2_lib import (  # noqa: E402
    McpGhidraClient,
    LOGS_DIR,
    capa_analyze,
    pe_import_signals,
    dotnet_analyze,
    ensure_pipeline_runtime_env,
    evaluate_tool_checklist,
    floss_extract,
    frida_static_probe,
    ghidra_decompile,
    get_planner_model,
    get_verdict_model,
    ida_query_remote,
    llm_judge,
    load_session,
    malcat_analyze,
    olevba_analyze,
    peepdf_analyze,
    package_stage_evidence,
    r2_decompile,
    speakeasy_emulate,
    tool_applies_to_format,
    tool_result_ok,
    upx_unpack,
    run_post_upx_second_pass,
    xor_string_search,
    yara_scan,
)

MAX_STEPS = 16
MAX_TOOL_RESULT_CHARS = 2000
MAX_FINDINGS_CHARS = 4000

# Agent tool name → TOOL_MANIFEST key (same checklist as standard deep_dive_v2).
CHECKLIST_PE = [
    ("yara_scan", "yara", {}),
    ("malcat_analyze", "malcat", {"profile": "deep"}),
    ("capa_analyze", "capa", {}),
    ("pe_import_signals", "pe_imports", {}),
    ("floss_extract", "floss", {}),
    ("dotnet_analyze", "dotnet", {}),
    ("r2_decompile", "r2_decomp", {}),
    ("upx_unpack", "upx", {}),
    ("xor_string_search", "xor", {}),
    ("speakeasy_emulate", "speakeasy", {}),
    ("frida_static_probe", "frida_probe", {}),
]
SQL_DEEP_TOOLS = {"ghidra_query", "ida_query", "ghidra_decompile"}


def _tool_call_ok(h: dict) -> bool:
    if not h.get("tool"):
        return False
    if h.get("error"):
        return False
    res = h.get("result")
    if isinstance(res, dict) and res.get("error"):
        return False
    return True


def _count_successful_tool_calls(hist: list, *, non_bootstrap_only: bool = False) -> int:
    n = 0
    for h in hist:
        if non_bootstrap_only and h.get("bootstrap"):
            continue
        if _tool_call_ok(h):
            n += 1
    return n


def _extract_json_object(text: str) -> dict:
    """Parse LLM JSON; tolerate markdown fences and leading prose."""
    if not text:
        raise ValueError("empty LLM content")
    s = text.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        # drop first fence and optional trailing fence
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    try:
        data = json.loads(s)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    start = s.find("{")
    end = s.rfind("}")
    if start >= 0 and end > start:
        data = json.loads(s[start : end + 1])
        if isinstance(data, dict):
            return data
    raise ValueError(f"no JSON object in LLM content: {s[:200]!r}")


def _final_answer_complete(ans: dict | None) -> bool:
    if not isinstance(ans, dict):
        return False
    verdict = (ans.get("verdict") or "").strip() if isinstance(ans.get("verdict"), str) else ans.get("verdict")
    summary = (ans.get("summary") or "").strip()
    return bool(verdict) and bool(summary)


def _coerce_final_answer(data: dict | None) -> dict | None:
    """Unwrap nested / planner-shaped LLM JSON into a flat final_answer dict.

    Stopgap for flash models that return:
      {"reasoning":..., "actions":..., "final_answer": {"verdict":...}}
    instead of a flat {verdict, summary, key_evidence}.
    """
    if not isinstance(data, dict):
        return None
    if _final_answer_complete(data):
        return {
            "verdict": data.get("verdict"),
            "confidence": data.get("confidence"),
            "summary": data.get("summary", ""),
            "key_evidence": data.get("key_evidence") or data.get("evidence") or [],
            "reasoning": data.get("reasoning", ""),
        }
    nested = data.get("final_answer")
    if isinstance(nested, dict) and _final_answer_complete(nested):
        out = {
            "verdict": nested.get("verdict"),
            "confidence": nested.get("confidence", data.get("confidence")),
            "summary": nested.get("summary", ""),
            "key_evidence": nested.get("key_evidence") or nested.get("evidence") or [],
            "reasoning": data.get("reasoning") or nested.get("reasoning", ""),
        }
        return out
    # actions list may contain type=final_answer
    for action in data.get("actions") or []:
        if not isinstance(action, dict):
            continue
        at = action.get("type") or action.get("action")
        if at == "final_answer" and _final_answer_complete(action):
            return {
                "verdict": action.get("verdict"),
                "confidence": action.get("confidence"),
                "summary": action.get("summary", ""),
                "key_evidence": action.get("key_evidence") or action.get("evidence") or [],
                "reasoning": data.get("reasoning", ""),
            }
        fa = action.get("final_answer")
        if isinstance(fa, dict) and _final_answer_complete(fa):
            return {
                "verdict": fa.get("verdict"),
                "confidence": fa.get("confidence"),
                "summary": fa.get("summary", ""),
                "key_evidence": fa.get("key_evidence") or fa.get("evidence") or [],
                "reasoning": data.get("reasoning", ""),
            }
    return None


def _normalize_actions(data: dict) -> list:
    """Normalize planner JSON into a list of action dicts with type tool_call|final_answer."""
    if not isinstance(data, dict):
        return []
    coerced = _coerce_final_answer(data)
    # Prefer explicit actions; if only a complete final answer, emit that.
    raw = data.get("actions")
    if not isinstance(raw, list):
        raw = []
    if not raw and coerced and _final_answer_complete(coerced):
        return [{"type": "final_answer", **coerced}]
    if not raw and _final_answer_complete(data):
        return [{"type": "final_answer", **data}]

    out = []
    for action in raw:
        if not isinstance(action, dict):
            continue
        at = action.get("type") or action.get("action")
        if at == "final_answer" or ("verdict" in action and "summary" in action and not action.get("tool")):
            fa = _coerce_final_answer(action) or action
            out.append({"type": "final_answer", **fa})
            continue
        # Bare tool dict: {tool, args|params} or nested tool_call
        tool_call = action.get("tool_call") if isinstance(action.get("tool_call"), dict) else action
        tool_name = tool_call.get("tool") or tool_call.get("name")
        tool_args = (
            tool_call.get("args")
            or tool_call.get("params")
            or tool_call.get("arguments")
            or {}
        )
        if not isinstance(tool_args, dict):
            tool_args = {}
        if tool_name:
            out.append({
                "type": "tool_call",
                "tool": tool_name,
                "args": tool_args,
                "reason": action.get("reason", ""),
            })
    return out

# SQL schema hints for the LLM
GHIDRA_SCHEMA = """Ghidra SQL tables:
- funcs: name, address, size
- strings: content, address, length
- imports: name, module, address
- data_items: name, address, data_type, size
- function_metrics: func_name, func_addr, size, instruction_count, block_count, cyclomatic_complexity, call_in_count, call_out_count, string_ref_count
- callgraph_edges: from_func_addr, from_func_name, dst_func_addr, dst_func_name
- xrefs: from_ea, from_func_addr, to_ea, to_func_addr, is_code
- memory_blocks: start_ea, end_ea, name, class, size, is_read, is_write, is_exec
- exports: name, address, module
- db_info: key, value
- string_refs: func_name, func_addr, string_value, string_addr, string_length"""

IDA_SCHEMA = """IDA SQL tables:
- funcs: name, address, size
- strings: content, address, length
- imports: module, name, address
- segments: start_ea, end_ea, name, class, perm
- entries: ordinal, address, name
- xrefs: from_ea, from_func_addr, to_ea, to_func_addr, is_code
- db_info: key, value
- string_refs: func_name, func_addr, string_value, string_addr, string_length"""

TOOL_DESCRIPTIONS = {
    "malcat_analyze": "Run Malcat static profile. Args: sample_path, profile='triage'|'deep', views=['anomalies','strings','imports','yara_hits','capa_summary','functions','constants','carved','virtual_files','structures','decompile','unpack_donut']",
    "ghidra_query": "Run a SQL query on the Ghidra database. Args: session_id, sql, max_rows",
    "ida_query": "Run a SQL query on the IDA database. Args: ida_session_id, sql",
    "ghidra_decompile": "Decompile a Ghidra function. Args: session_id, function_addr",
    "capa_analyze": "Run Mandiant/capa-rs capability detection. Large samples may incomplete (honest); not replaced by pe_imports.",
    "pe_import_signals": "PE import high-signal API map via pefile. Separate from capa. Args: (none — uses session sample_path)",
    "yara_scan": "Run YARA signature scan. Args: sample_path",
    "floss_extract": "Run FLOSS string extraction. Args: sample_path",
    "dotnet_analyze": "Run .NET analysis. Args: sample_path",
    "speakeasy_emulate": "Run Speakeasy emulation. Args: sample_path",
    "frida_static_probe": "Run Frida static probe. Args: sample_path",
    "r2_decompile": "Run radare2 disassembly. Args: sample_path, function_addrs",
    "upx_unpack": "Run UPX packer detection. Args: sample_path",
    "xor_string_search": "Run xorsearch XOR string search. Args: sample_path",
    "olevba_analyze": "Run olevba Office VBA analysis. Args: sample_path",
    "peepdf_analyze": "Run peepdf PDF analysis. Args: sample_path",
}


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def load_intake_validation(sha: str) -> dict:
    path = LOGS_DIR / sha / "intake-validation.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _truncate(s: str, max_chars: int) -> str:
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + f"... (truncated {len(s) - max_chars} chars)"


def _normalize_confidence(conf) -> int:
    if isinstance(conf, (int, float)):
        return max(0, min(100, int(conf)))
    if isinstance(conf, str):
        s = conf.strip().lower()
        if s in ("high", "very high"):
            return 90
        if s in ("medium", "moderate"):
            return 70
        if s in ("low", "very low"):
            return 40
        try:
            return max(0, min(100, int(float(s))))
        except ValueError:
            return 50
    return 50


def _confidence_final(conf, incomplete: bool) -> int:
    """Confidence for a *complete* deep dive must never be 0.

    The LLM sometimes omits/zeroes the confidence field while producing a
    full verdict + key_evidence. A 0 paired with a complete analysis is a
    reporting artifact, not a real assessment — treat it as "not stated"
    (50). For incomplete dives we keep the true value so the report stays
    honest about the low-confidence incomplete state.
    """
    conf = _normalize_confidence(conf)
    if not incomplete and conf <= 0:
        return 50
    return conf


def build_messages(
    session,
    step,
    max_steps,
    history,
    findings,
    source_decisions,
    tool_list,
    file_type,
    *,
    checklist_ok: bool = False,
    sql_ok: bool = False,
) -> list:
    system = (
        "You are an agentic malware reverse-engineering assistant. "
        "The required static tool checklist already ran deterministically. "
        "Your job is SQL-first deep RE: ghidra_query / ida_query / ghidra_decompile, "
        "then RAG/Z3/angr as needed. Use z3_solve for MBA/opaque-predicate verification "
        "and angr_analyze for CFF/control-flow-flattening deflatten. Return JSON with "
        "'reasoning' and 'actions' (a list). Each action is either a tool_call or a final_answer."
    )
    tool_desc = "\n".join(tool_list)
    findings_text = _truncate(json.dumps(findings, default=str), MAX_FINDINGS_CHARS)
    history_text = "\n".join(
        f"  - {h.get('tool','?')}: {h.get('reason','')[:60]}" +
        (" [ERR]" if h.get("error") else "")
        for h in history[-20:]
    ) or "(no tool calls yet)"

    user = f"""Goal: Complete SQL deep RE on the sample, then produce a verdict with evidence.

Current state:
  Step: {step}/{max_steps}
  Sample: {session['sample_path']}
  File type: {file_type}
  Checklist complete: {checklist_ok}
  SQL deep RE done: {sql_ok}
  Source decisions from intake: {json.dumps(source_decisions, indent=2, default=str)}

SQL schema (for ghidra_query and ida_query):
{GHIDRA_SCHEMA}
{IDA_SCHEMA}

Available tools:
{tool_desc}

Tool call history:
{history_text}

Current findings:
{findings_text}

IMPORTANT:
- Static TOOL_MANIFEST checklist already ran (yara/malcat/capa/floss/dotnet/r2/upx/xor/speakeasy/frida).
- Before final_answer you MUST run >=1 SQL/decompile tool: ghidra_query, ida_query, or ghidra_decompile.
- Prefer ranking suspicious funcs/imports/strings via SQL, then decompile top hits.
- Use z3_solve to verify MBA/opaque-predicate claims (e.g., x^y + 2*(x&y) == x+y).
- Use angr_analyze to deflatten CFF/control-flow-flattened functions when cff_detect found candidates.
- final_answer MUST include non-empty: verdict, summary, key_evidence (list).
- Do not claim high confidence without citing tool/SQL evidence already in findings.

Return JSON with 'reasoning' and 'actions' (list)."""
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


class ToolRegistry:
    def __init__(self):
        self.tools = {
            "malcat_analyze": self._malcat_analyze,
            "ghidra_query": self._ghidra_query,
            "ida_query": self._ida_query,
            "ghidra_decompile": self._ghidra_decompile,
            "capa_analyze": self._capa_analyze,
            "pe_import_signals": self._pe_import_signals,
            "yara_scan": self._yara_scan,
            "floss_extract": self._floss_extract,
            "dotnet_analyze": self._dotnet_analyze,
            "speakeasy_emulate": self._speakeasy_emulate,
            "frida_static_probe": self._frida_static_probe,
            "r2_decompile": self._r2_decompile,
            "upx_unpack": self._upx_unpack,
            "xor_string_search": self._xor_string_search,
            "olevba_analyze": self._olevba_analyze,
            "peepdf_analyze": self._peepdf_analyze,
            "z3_solve": self._z3_solve,
            "angr_analyze": self._angr_analyze,
            "signature_match": self._signature_match,
        }

    def _malcat_analyze(self, args, session):
        sample_path = session["sample_path"]
        profile = args.get("profile", "triage")
        views = args.get("views")
        return malcat_analyze(sample_path, views=views, profile=profile)

    def _ghidra_query(self, args, session):
        session_id = session["session_id"]
        sql = (args.get("sql") or "").strip()
        if not sql:
            return {"error": "ghidra_query requires non-empty args.sql"}
        client = McpGhidraClient()
        try:
            return client.ghidra_query(session_id, sql, max_rows=args.get("max_rows", 200))
        finally:
            client.close()

    def _ida_query(self, args, session):
        ida_id = session.get("ida_session_id")
        if not ida_id:
            return {"error": "IDA session not loaded"}
        sql = (args.get("sql") or "").strip()
        if not sql:
            return {"error": "ida_query requires non-empty args.sql"}
        return ida_query_remote(ida_id, sql)

    def _ghidra_decompile(self, args, session):
        session_id = session["session_id"]
        function_addr = args.get("function_addr")
        if not function_addr:
            return {"error": "function_addr required"}
        return ghidra_decompile(session_id, function_addr)

    def _capa_analyze(self, args, session):
        # Size-aware timeout inside capa_analyze; optional override
        timeout = args.get("timeout")
        if timeout is not None:
            try:
                timeout = int(timeout)
            except (TypeError, ValueError):
                timeout = None
        return capa_analyze(session["sample_path"], timeout=timeout)

    def _pe_import_signals(self, args, session):
        return pe_import_signals(session["sample_path"])

    def _yara_scan(self, args, session):
        return yara_scan(session["sample_path"])

    def _floss_extract(self, args, session):
        return floss_extract(session["sample_path"])

    def _dotnet_analyze(self, args, session):
        return dotnet_analyze(session["sample_path"])

    def _speakeasy_emulate(self, args, session):
        fmt = (session.get("file_type") or {}).get("format") or "unknown"
        if not tool_applies_to_format("speakeasy", fmt):
            return {"skipped": True, "reason": f"not_applicable:{fmt}"}
        return speakeasy_emulate(session["sample_path"])

    def _frida_static_probe(self, args, session):
        return frida_static_probe(session["sample_path"])

    def _r2_decompile(self, args, session):
        return r2_decompile(session["sample_path"], function_addrs=args.get("function_addrs"))

    def _upx_unpack(self, args, session):
        return upx_unpack(session["sample_path"])

    def _xor_string_search(self, args, session):
        return xor_string_search(session["sample_path"])

    def _olevba_analyze(self, args, session):
        return olevba_analyze(session["sample_path"])

    def _peepdf_analyze(self, args, session):
        return peepdf_analyze(session["sample_path"])

    def _z3_solve(self, args, session):
        try:
            from extensions.deobfuscation import invoke_z3_or_angr as iza  # type: ignore
        except ImportError:
            _candidates = [
                Path(__file__).resolve().parent.parent / "extensions" / "deobfuscation",
                Path.home() / "RevAI" / "extensions" / "deobfuscation",
            ]
            _ext = next((p for p in _candidates if p.is_dir()), None)
            if _ext:
                if str(_ext) not in sys.path:
                    sys.path.insert(0, str(_ext))
                import invoke_z3_or_angr as iza  # type: ignore
            else:
                return {"error": "invoke_z3_or_angr not found in extensions/deobfuscation/"}
        iza.ENABLE_DEOBFUSCATION_PASS_DEFAULT = True
        return iza.invoke_z3_or_angr(
            "mba_identity",
            session["sample_path"],
            timeout=args.get("timeout", 60),
            claim_text=args.get("claim_text", ""),
        )

    def _angr_analyze(self, args, session):
        try:
            from extensions.deobfuscation import invoke_z3_or_angr as iza  # type: ignore
        except ImportError:
            _candidates = [
                Path(__file__).resolve().parent.parent / "extensions" / "deobfuscation",
                Path.home() / "RevAI" / "extensions" / "deobfuscation",
            ]
            _ext = next((p for p in _candidates if p.is_dir()), None)
            if _ext:
                if str(_ext) not in sys.path:
                    sys.path.insert(0, str(_ext))
                import invoke_z3_or_angr as iza  # type: ignore
            else:
                return {"error": "invoke_z3_or_angr not found in extensions/deobfuscation/"}
        iza.ENABLE_DEOBFUSCATION_PASS_DEFAULT = True
        return iza.invoke_z3_or_angr(
            "cff_dispatcher",
            session["sample_path"],
            timeout=args.get("timeout", 120),
        )

    def _signature_match(self, args, session):
        """Match function against signature DBs (crypto/stdlib/winapi).

        Args:
            args: {
                'func_name': str,
                'imports': list[str],
                'strings': list[str],
                'constants': list[int],
                'size': int
            }
        """
        try:
            from v2_lib import signature_match
            return signature_match(
                func_name=args.get("func_name", ""),
                imports=args.get("imports", []),
                strings=args.get("strings", []),
                constants=args.get("constants", []),
                size=args.get("size", 0),
            )
        except Exception as e:
            return {"error": str(e)}

    def call(self, tool_name: str, args: dict, session: dict) -> dict:
        if not isinstance(tool_name, str) or tool_name not in self.tools:
            return {"error": f"unknown tool: {tool_name}"}
        try:
            return self.tools[tool_name](args, session)
        except Exception as e:
            return {"error": str(e)}


def _run_standard_checklist(registry: "ToolRegistry", session: dict, sha: str) -> tuple[list, dict, dict, dict]:
    """Deterministic TOOL_MANIFEST parity — same required tools as standard deep_dive_v2.

    Runs one tool at a time (size-aware timeouts inside wrappers).
    Writes deep_dive/01-tools-raw.json + 01-tools-gate.json for audit parity.
    """
    history: list = []
    findings: dict = {}
    tools_raw: dict = {"_format": (session.get("file_type") or {}).get("format", "unknown"),
                       "_sample_path": session.get("sample_path"),
                       "_source": "deep_dive_agentic_checklist"}
    program = Path(session.get("sample_path") or "").name

    def _run(tool: str, args: dict, reason: str, *, checklist: bool = True) -> dict:
        print(f"[deep_dive_agentic] checklist: {tool} -> {reason}", flush=True)
        result = registry.call(tool, args, session)
        err = None
        if isinstance(result, dict):
            ok, why = tool_result_ok(result)
            if not ok:
                err = result.get("error") or why
        else:
            err = "non-dict result"
            result = {"error": err}
        history.append({
            "step": 0,
            "tool": tool,
            "args": args,
            "reason": reason,
            "result": result,
            "error": err,
            "checklist": checklist,
            "bootstrap": checklist,  # keep legacy field for older auditors
        })
        findings[f"checklist_{tool}"] = result
        return result

    fmt = str(tools_raw.get("_format") or "unknown")
    yara_res = {}
    for agent_tool, manifest_key, args in CHECKLIST_PE:
        if not tool_applies_to_format(manifest_key, fmt):
            print(
                f"[deep_dive_agentic] checklist skip {manifest_key} "
                f"(not_applicable:{fmt})",
                flush=True,
            )
            continue
        res = _run(agent_tool, dict(args), f"Required checklist tool ({manifest_key})")
        tools_raw[manifest_key] = res
        if agent_tool == "yara_scan":
            yara_res = res if isinstance(res, dict) else {}

    # V5.16.5 — post-UPX second-pass on unpacked payload
    upx_r = tools_raw.get("upx") if isinstance(tools_raw.get("upx"), dict) else {}
    unpacked = (upx_r or {}).get("unpacked_path") or ""
    if (upx_r or {}).get("upx_ok") and unpacked:
        print(f"[deep_dive_agentic] post-UPX second-pass -> {unpacked}", flush=True)
        second = run_post_upx_second_pass(unpacked, profile="deep")
        tools_raw["upx_second_pass"] = second
        findings["checklist_upx_second_pass"] = second
        history.append({
            "step": 0,
            "tool": "upx_second_pass",
            "args": {"unpacked_path": unpacked},
            "reason": "V5.16.5 post-UPX second-pass (capa/yara/floss/malcat/pe_imports)",
            "result": {
                "ok": second.get("ok"),
                "tool_ok": second.get("tool_ok"),
                "unpacked_path": unpacked,
            },
            "error": None if second.get("ok") else second.get("skipped_reason"),
            "checklist": True,
        })

    # Format-aware gate (Speakeasy never required for .NET)
    gate = evaluate_tool_checklist(tools_raw)

    ev_dir = LOGS_DIR / sha / "deep_dive"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "01-tools-raw.json").write_text(json.dumps(tools_raw, indent=2, default=str))
    (ev_dir / "01-tools-gate.json").write_text(json.dumps(gate, indent=2, default=str))
    if isinstance(tools_raw.get("upx_second_pass"), dict):
        (ev_dir / "01b-upx-second-pass.json").write_text(
            json.dumps(tools_raw["upx_second_pass"], indent=2, default=str)
        )
    # Same stage-tagged evidence pack as deep_dive_v2.
    tools_for_pack = {
        "malcat": tools_raw.get("malcat"),
        "capa": tools_raw.get("capa"),
        "yara": tools_raw.get("yara"),
        "floss": tools_raw.get("floss"),
        "dotnet": tools_raw.get("dotnet"),
        "r2": tools_raw.get("r2_decomp"),
        "upx": tools_raw.get("upx"),
        "xor": tools_raw.get("xor"),
        "olevba": tools_raw.get("olevba"),
        "peepdf": tools_raw.get("peepdf"),
        "pe_imports": tools_raw.get("pe_imports"),
        "speakeasy": tools_raw.get("speakeasy"),
        "frida_probe": tools_raw.get("frida_probe"),
    }
    pack = package_stage_evidence(
        "deep_dive", tools_for_pack, budget_chars=60000, sha=sha, persist=True,
    )
    print(
        f"[deep_dive_agentic] checklist gate_ok={gate['ok']} "
        f"hard_failures={gate.get('hard_failures')} "
        f"evidence_pack_chars={len(pack)}",
        flush=True,
    )
    return history, findings, tools_raw, gate


def _history_has_sql_deep(history: list) -> bool:
    for h in history:
        if h.get("tool") in SQL_DEEP_TOOLS and _tool_call_ok(h):
            return True
    return False


# ── Agent-loop discipline (AgentRE-Bench-inspired; env-gated, default ON) ──
# 1. budget warnings   REVENG_BUDGET_WARNINGS
# 2. redundant nudges  REVENG_REDUNDANT_NUDGE
# 3. hallucination chk REVENG_HALLUCINATION_CHECK
# 4. failure taxonomy  REVENG_FAILURE_TAXONOMY

def _loop_flag(name: str) -> bool:
    """Env-gated loop feature flag; defaults ON."""
    return os.environ.get(name, "1").strip().lower() in ("1", "true", "yes", "on")


def _budget_warning(step: int, max_steps: int) -> str | None:
    """Convergence nudge at half-budget and near-end (AgentRE-Bench pattern)."""
    if not _loop_flag("REVENG_BUDGET_WARNINGS"):
        return None
    half = max(1, max_steps // 2)
    last_two = max(1, max_steps - 2)
    if step == half:
        return (
            f"BUDGET WARNING: half of your step budget used ({step}/{max_steps}). "
            f"Prioritize the highest-value evidence; stop exploratory queries."
        )
    if step == last_two:
        return (
            f"CRITICAL BUDGET: only {max_steps - step} step(s) left. "
            f"Prepare your final_answer NOW using the evidence collected so far."
        )
    return None


def _call_signature(tool_name: str, args: dict) -> str:
    """Stable signature for redundant-call detection."""
    try:
        return str(tool_name) + "::" + json.dumps(args or {}, sort_keys=True, default=str)
    except Exception:
        return str(tool_name) + "::" + repr(args)


_HALLUC_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "in", "on", "to", "for", "with",
    "is", "are", "was", "were", "by", "at", "from", "as", "it", "this",
    "that", "be", "has", "have", "had", "via", "using", "uses", "used",
    "not", "no", "but", "its", "into", "over", "than", "then", "there",
}


def _halluc_tokens(text: str) -> set:
    toks = re.findall(r"[a-z0-9_]{3,}", str(text or "").lower())
    return {t for t in toks if t not in _HALLUC_STOPWORDS}


def _unsupported_claims(candidate: dict, history: list, findings: dict) -> list:
    """key_evidence claims with no token overlap against collected evidence.

    Conservative: a claim is flagged only if NONE of its significant tokens
    appear anywhere in the serialized tool evidence. Returns flagged claims.
    """
    if not _loop_flag("REVENG_HALLUCINATION_CHECK"):
        return []
    evidence_blob = json.dumps(findings, default=str).lower()
    for h in history:
        if h.get("result") is not None:
            try:
                evidence_blob += " " + json.dumps(h.get("result"), default=str).lower()
            except Exception:
                evidence_blob += " " + str(h.get("result")).lower()
    claims = candidate.get("key_evidence") or candidate.get("evidence") or []
    if isinstance(claims, str):
        claims = [claims]
    flagged = []
    for c in claims:
        if not isinstance(c, str):
            c = json.dumps(c, default=str)
        toks = _halluc_tokens(c)
        if not toks:
            continue
        if not any(t in evidence_blob for t in toks):
            flagged.append(c)
    return flagged


def _classify_failures(history: list, final_answer: dict, *,
                       checklist_ok: bool, sql_ok: bool, fa_ok: bool) -> dict:
    """Post-run failure taxonomy (AgentRE-Bench 6 buckets)."""
    if not _loop_flag("REVENG_FAILURE_TAXONOMY"):
        return {}
    buckets = {
        "json_format_violation": 0,
        "tool_misuse": 0,
        "early_termination": 0,
        "api_hallucination": 0,
        "byte_level_reasoning": 0,
        "control_flow_misinterpretation": 0,
    }
    for h in history:
        err = str(h.get("error") or "")
        if not err:
            continue
        low = err.lower()
        if "planner failed" in low or "json" in low or "no actions" in low:
            buckets["json_format_violation"] += 1
        elif "invalid tool_call" in low or "unknown action" in low:
            buckets["tool_misuse"] += 1
        elif "redundant" in low:
            buckets["tool_misuse"] += 1
        elif "hallucination" in low:
            buckets["api_hallucination"] += 1
    if not fa_ok:
        buckets["early_termination"] += 1
    blob = (
        str((final_answer or {}).get("verdict") or "") + " "
        + str((final_answer or {}).get("summary") or "")
    ).lower()
    if "syscall" in blob or "opcode" in blob or "shellcode" in blob:
        buckets["byte_level_reasoning"] += 1
    if "dispatcher" in blob or "control flow" in blob or "flatten" in blob or "opaque" in blob:
        buckets["control_flow_misinterpretation"] += 1
    active = {k: v for k, v in buckets.items() if v > 0}
    return {
        "counts": buckets,
        "active": active,
        "primary": max(active, key=lambda k: active[k]) if active else None,
        "clean": not active,
    }


def _custom_loop_body(sha: str, max_steps: int = MAX_STEPS) -> dict:
    """JSON planner custom loop (stopgap / fallback)."""
    session = load_session(sha)
    file_type = session.get("file_type", {}).get("format", "unknown")
    intake_validation = load_intake_validation(sha)
    source_decisions = intake_validation.get("source_decisions", {})

    registry = ToolRegistry()
    tool_list = [f"- {name}: {desc}" for name, desc in TOOL_DESCRIPTIONS.items()]

    history, findings, tools_raw, tool_gate = _run_standard_checklist(registry, session, sha)
    final_answer = None
    checklist_ok = bool(tool_gate.get("ok"))

    # flash = agentic planner loop; Pro = final verdict / validation
    planner_model = get_planner_model()
    verdict_model = get_verdict_model()

    def _seed_sql_deep(step_tag: int) -> bool:
        """Ensure ≥1 SQL/decompile observation before planner loop / final."""
        if _history_has_sql_deep(history):
            return True
        ghidra_sid = session.get("ghidra_session_id") or session.get("session_id")
        ida_sid = session.get("ida_session_id")
        seeds = []
        if ghidra_sid:
            seeds.append((
                "ghidra_query",
                {
                    "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25",
                    "max_rows": 25,
                },
            ))
            seeds.append((
                "ghidra_decompile",
                {"address": None},  # registry may pick largest; if fails try query-only
            ))
        if ida_sid:
            seeds.append((
                "ida_query",
                {
                    "sql": "SELECT name, start_ea, size FROM functions ORDER BY size DESC LIMIT 25",
                    "max_rows": 25,
                },
            ))
        for tool_name, args in seeds:
            # Skip decompile seed if no address — use query-only path
            if tool_name == "ghidra_decompile" and not args.get("address"):
                continue
            print(f"[deep_dive_agentic] SQL seed: {tool_name}", flush=True)
            result = registry.call(tool_name, args, session)
            entry = {
                "step": step_tag,
                "tool": tool_name,
                "args": args,
                "reason": "Auto SQL/decompile seed for large-mode deep RE gate",
                "result": result,
                "error": result.get("error") if isinstance(result, dict) else None,
                "auto_sql": True,
            }
            history.append(entry)
            findings[f"auto_{tool_name}_{step_tag}"] = result
            if _tool_call_ok(entry):
                return True
        return _history_has_sql_deep(history)

    # Seed SQL immediately after checklist so planner is not the only path to sql_ok
    if checklist_ok and not _history_has_sql_deep(history):
        _seed_sql_deep(0)

    planner_failures = 0
    seen_signatures: set = set()
    redundant_calls = 0
    hallucination_corrected = False
    for step in range(1, max_steps + 1):
        sql_ok = _history_has_sql_deep(history)
        messages = build_messages(
            session, step, max_steps, history, findings, source_decisions, tool_list, file_type,
            checklist_ok=checklist_ok, sql_ok=sql_ok,
        )
        # Feature 1: budget convergence warning (AgentRE-Bench pattern)
        _bw = _budget_warning(step, max_steps)
        if _bw:
            messages[1]["content"] += "\n\n" + _bw
            print(f"[deep_dive_agentic] budget warning at step {step}/{max_steps}", flush=True)
        try:
            resp = llm_judge(messages[1]["content"], model=planner_model)
            content = resp["choices"][0]["message"]["content"]
            data = _extract_json_object(content)
        except Exception as e:
            planner_failures += 1
            history.append({"step": step, "error": f"planner failed: {e}"})
            # Stopgap: do not abort the whole loop on one bad JSON blob.
            if planner_failures >= 3:
                break
            continue

        actions = _normalize_actions(data)
        if not actions:
            # Nested final_answer without actions
            coerced = _coerce_final_answer(data)
            if coerced:
                actions = [{"type": "final_answer", **coerced}]
            else:
                history.append({"step": step, "error": "no actions returned"})
                planner_failures += 1
                if planner_failures >= 3:
                    break
                continue

        # Reject final until checklist green + ≥1 SQL/decompile tool.
        wants_final = any((a.get("type") or a.get("action")) == "final_answer" for a in actions)
        sql_ok = _history_has_sql_deep(history)
        if wants_final and (not checklist_ok or not sql_ok):
            history.append({
                "step": step,
                "error": (
                    f"LLM tried final_answer too early "
                    f"(checklist_ok={checklist_ok}, sql_ok={sql_ok}); "
                    f"need full TOOL_MANIFEST checklist + ≥1 ghidra/ida SQL or decompile"
                ),
            })
            # Auto-run a seed SQL query once if checklist is ok but SQL missing.
            if checklist_ok and not sql_ok:
                _seed_sql_deep(step)
            continue

        # Execute all tool calls, collect observations
        for action in actions:
            action_type = action.get("type") or action.get("action")
            if action_type == "final_answer":
                candidate = _coerce_final_answer(action) or {
                    "verdict": action.get("verdict"),
                    "confidence": action.get("confidence"),
                    "summary": action.get("summary", ""),
                    "key_evidence": action.get("key_evidence", action.get("evidence", [])),
                    "reasoning": data.get("reasoning", ""),
                }
                if not _final_answer_complete(candidate):
                    history.append({
                        "step": step,
                        "error": "final_answer missing verdict/summary — prompting again",
                    })
                    break
                # Feature 3: hallucination check — claims must have tool evidence
                unsupported = _unsupported_claims(candidate, history, findings)
                if unsupported and not hallucination_corrected:
                    hallucination_corrected = True
                    history.append({
                        "step": step,
                        "error": (
                            "final_answer rejected (hallucination check): no tool evidence for: "
                            + "; ".join(str(u)[:80] for u in unsupported[:3])
                            + " — gather evidence or drop these claims, then resubmit."
                        ),
                    })
                    print(
                        f"[deep_dive_agentic] HALLUCINATION CHECK rejected final_answer "
                        f"({len(unsupported)} unsupported claim(s)); 1 correction turn granted",
                        flush=True,
                    )
                    # do not break — give the planner one correction turn
                else:
                    final_answer = candidate
                    break
                continue
            if action_type != "tool_call":
                history.append({"step": step, "error": f"unknown action type: {action_type}"})
                continue

            tool_name = action.get("tool")
            tool_args = action.get("args") or {}
            reason = action.get("reason", "")
            if not tool_name or tool_name not in registry.tools:
                history.append({
                    "step": step,
                    "error": f"invalid tool_call: tool={tool_name!r}",
                })
                continue

            print(f"[deep_dive_agentic] step {step}: {tool_name} -> {reason}", flush=True)

            # Feature 2: redundant-call detection (AgentRE-Bench pattern)
            _sig = _call_signature(tool_name, tool_args)
            if _loop_flag("REVENG_REDUNDANT_NUDGE") and _sig in seen_signatures:
                redundant_calls += 1
                history.append({
                    "step": step,
                    "tool": tool_name,
                    "args": tool_args,
                    "error": (
                        "redundant tool call (identical to a previous call) — "
                        "analyze the output you already have or move on"
                    ),
                })
                print(
                    f"[deep_dive_agentic] step {step}: REDUNDANT {tool_name} skipped "
                    f"(total redundant={redundant_calls})",
                    flush=True,
                )
                continue
            seen_signatures.add(_sig)

            result = registry.call(tool_name, tool_args, session)
            history.append({
                "step": step,
                "tool": tool_name,
                "args": tool_args,
                "reason": reason,
                "result": result,
                "error": result.get("error") if isinstance(result, dict) else None,
            })
            findings[f"{tool_name}_{step}"] = result

        if final_answer:
            break

    sql_ok = _history_has_sql_deep(history)
    if not final_answer:
        messages = build_messages(
            session, max_steps, max_steps, history, findings, source_decisions, tool_list, file_type,
            checklist_ok=checklist_ok, sql_ok=sql_ok,
        )
        messages[1]["content"] += (
            "\n\nYou have used all steps. Return ONLY a flat JSON object with "
            "keys: verdict, confidence, summary, key_evidence (list of strings). "
            "Do NOT wrap in actions/reasoning."
        )
        try:
            resp = llm_judge(messages[1]["content"], model=verdict_model)
            raw = _extract_json_object(resp["choices"][0]["message"]["content"])
            final_answer = _coerce_final_answer(raw) or raw
        except Exception as e:
            final_answer = {
                "verdict": "unknown",
                "confidence": 0,
                "summary": f"Agentic loop failed: {e}",
                "source": "error",
            }

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
        engine="custom",
        redundant_calls=redundant_calls,
    )


def _finalize_agentic_result(
    *,
    sha: str,
    session: dict,
    history: list,
    findings: dict,
    tools_raw: dict,
    tool_gate: dict,
    checklist_ok: bool,
    sql_ok: bool,
    final_answer: dict | None,
    planner_model: str,
    verdict_model: str,
    intake_validation: dict,
    engine: str,
    redundant_calls: int = 0,
) -> dict:
    succ = _count_successful_tool_calls(history)
    succ_extra = _count_successful_tool_calls(history, non_bootstrap_only=True)
    final_answer = _coerce_final_answer(final_answer) or (final_answer or {})
    fa_ok = _final_answer_complete(final_answer)
    incomplete = not checklist_ok or not fa_ok
    reasons = []
    if not checklist_ok:
        reasons.append("checklist")
    if not sql_ok:
        reasons.append("sql_deep")
    if not fa_ok:
        reasons.append("final_answer_incomplete")
    if incomplete:
        final_answer["verdict"] = final_answer.get("verdict") or "unknown"
        if not (final_answer.get("summary") or "").strip():
            final_answer["summary"] = (
                "Incomplete agentic deep dive — " + (", ".join(reasons) or "unknown gate")
            )
        final_answer["confidence"] = min(_confidence_final(final_answer.get("confidence"), incomplete=True), 40)
        final_answer["summary"] = (
            f"{final_answer.get('summary')} "
            f"[INCOMPLETE: checklist_ok={checklist_ok}, sql_ok={sql_ok}, "
            f"final_ok={fa_ok}, reasons={reasons}, total_ok={succ}, "
            f"hard_failures={tool_gate.get('hard_failures')}]"
        ).strip()
        final_answer["incomplete_tooling"] = True
    else:
        final_answer["incomplete_tooling"] = False
    final_answer["successful_tool_calls"] = succ
    final_answer["successful_non_bootstrap_tools"] = succ_extra
    final_answer["tool_gate"] = tool_gate
    final_answer["checklist_ok"] = checklist_ok
    final_answer["sql_deep_ok"] = sql_ok
    final_answer["tools_raw_keys"] = [k for k in tools_raw.keys() if not k.startswith("_")]
    final_answer["confidence"] = _confidence_final(final_answer.get("confidence"), incomplete=bool(incomplete))
    final_answer["source"] = "deep_dive_agentic"
    final_answer["engine"] = engine
    final_answer["planner_model"] = planner_model
    final_answer["verdict_model"] = verdict_model
    final_answer["steps_used"] = len(history)
    final_answer["history"] = history
    final_answer["findings"] = findings
    final_answer["intake_validation"] = intake_validation
    # Feature 2/4: loop-discipline metrics (AgentRE-Bench-inspired)
    final_answer["redundant_calls"] = redundant_calls
    final_answer["failure_taxonomy"] = _classify_failures(
        history, final_answer,
        checklist_ok=checklist_ok, sql_ok=sql_ok, fa_ok=fa_ok,
    )

    # --- Post-analysis deobfuscation pass (conditional) ---
    # If ENABLE_DEOBFUSCATION_PASS=1, scan LLM analysis for CFF/MBA claims
    # and verify them via Z3/angr. Same pattern as RevEng deep_dive_v2.py.
    if os.environ.get("ENABLE_DEOBFUSCATION_PASS", "0") == "1" and not incomplete:
        try:
            import re as _re
            _candidates = [
                Path(__file__).resolve().parent.parent / "extensions" / "deobfuscation",
                Path.home() / "RevAI" / "extensions" / "deobfuscation",
            ]
            _ext = next((p for p in _candidates if p.is_dir()), None)
            if _ext and str(_ext) not in sys.path:
                sys.path.insert(0, str(_ext))
            import invoke_z3_or_angr as _iza  # type: ignore
            _iza.ENABLE_DEOBFUSCATION_PASS_DEFAULT = True
            _analysis_text = json.dumps(final_answer, default=str).lower()
            _cff_results = None
            _z3_results = None
            if "dispatcher" in _analysis_text or "control flow flat" in _analysis_text or "cff" in _analysis_text:
                _cff_results = _iza.invoke_z3_or_angr("cff_dispatcher", session["sample_path"], timeout=120)
                final_answer["cff_results"] = _cff_results
                print(f"[deep_dive_agentic] cff_deflatten: {_cff_results.get('result')} ({_cff_results.get('duration_s', 0):.1f}s)", flush=True)
            _mba_match = _re.search(
                r"([\w\s\^\&\|\+\-\*\(\)]{3,80}\s*==\s*[\w\s\^\&\|\+\-\*\(\)]{3,80})",
                _analysis_text,
            )
            if _mba_match and ("mba" in _analysis_text or "obfusc" in _analysis_text or "opaque" in _analysis_text):
                _z3_results = _iza.invoke_z3_or_angr("mba_identity", session["sample_path"], timeout=30, claim_text=_mba_match.group(1).strip())
                final_answer["z3_results"] = _z3_results
                print(f"[deep_dive_agentic] Z3: {_z3_results.get('result')} ({_z3_results.get('duration_s', 0):.2f}s)", flush=True)
        except Exception as _deob_err:
            print(f"[deep_dive_agentic] deobfuscation hook error: {type(_deob_err).__name__}: {_deob_err}", flush=True)
            final_answer["deobfuscation_error"] = f"{type(_deob_err).__name__}: {_deob_err}"

    ev_dir = LOGS_DIR / sha / "deep_dive"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "agentic_deep_dive.json").write_text(json.dumps(final_answer, indent=2, default=str))
    compat = {
        "source": "deep_dive_agentic",
        "engine": engine,
        "verdict": final_answer.get("verdict"),
        "confidence": final_answer.get("confidence"),
        "summary": final_answer.get("summary"),
        "key_evidence": final_answer.get("key_evidence") or [],
        "incomplete_tooling": bool(final_answer.get("incomplete_tooling")),
        "successful_tool_calls": final_answer.get("successful_tool_calls"),
        "successful_non_bootstrap_tools": final_answer.get("successful_non_bootstrap_tools"),
        "checklist_ok": checklist_ok,
        "sql_deep_ok": sql_ok,
        "tool_gate": tool_gate,
    }
    (ev_dir / "05-deep-dive.json").write_text(json.dumps(compat, indent=2, default=str))
    print(f"[deep_dive_agentic] engine={engine} -> {ev_dir / 'agentic_deep_dive.json'}", flush=True)
    print(f"[deep_dive_agentic] -> {ev_dir / '05-deep-dive.json'}", flush=True)
    return final_answer


def _run_custom_engine(sha: str, max_steps: int) -> dict:
    """Entry used when REVENG_AGENTIC_ENGINE=custom (or langgraph fallback)."""
    return _agentic_deep_dive_custom(sha, max_steps=max_steps)


def agentic_deep_dive(sha: str, max_steps: int = MAX_STEPS) -> dict:
    engine = (os.environ.get("REVENG_AGENTIC_ENGINE") or "langgraph").strip().lower()
    if engine not in ("langgraph", "custom"):
        print(f"[deep_dive_agentic] unknown engine={engine!r}; using langgraph", flush=True)
        engine = "langgraph"

    if engine == "langgraph":
        try:
            from agentic_langgraph import run_langgraph_deep_dive  # type: ignore

            print("[deep_dive_agentic] engine=langgraph", flush=True)
            return run_langgraph_deep_dive(
                sha,
                max_steps=max_steps,
                # inject shared helpers / registry from this module
                helpers={
                    "ToolRegistry": ToolRegistry,
                    "CHECKLIST_PE": CHECKLIST_PE,
                    "SQL_DEEP_TOOLS": SQL_DEEP_TOOLS,
                    "_run_standard_checklist": _run_standard_checklist,
                    "_history_has_sql_deep": _history_has_sql_deep,
                    "_tool_call_ok": _tool_call_ok,
                    "_coerce_final_answer": _coerce_final_answer,
                    "_final_answer_complete": _final_answer_complete,
                    "_finalize_agentic_result": _finalize_agentic_result,
                    "_normalize_confidence": _normalize_confidence,
                    "GHIDRA_SCHEMA": GHIDRA_SCHEMA,
                    "IDA_SCHEMA": IDA_SCHEMA,
                    "load_intake_validation": load_intake_validation,
                    "MAX_TOOL_RESULT_CHARS": MAX_TOOL_RESULT_CHARS,
                },
            )
        except Exception as e:
            print(f"[deep_dive_agentic] langgraph failed ({e}); falling back to custom", flush=True)

    print("[deep_dive_agentic] engine=custom", flush=True)
    return _agentic_deep_dive_custom(sha, max_steps=max_steps)


def _agentic_deep_dive_custom(sha: str, max_steps: int = MAX_STEPS) -> dict:
    # Preserve prior function body under a new name — agentic_deep_dive now dispatches.
    # The custom loop implementation lives in the renamed body above via call chain:
    return _custom_loop_body(sha, max_steps)


def main():
    env_info = ensure_pipeline_runtime_env()
    print(f"[deep_dive_agentic] runtime env: model={os.environ.get('REVENG_LLM_MODEL', '')}", flush=True)
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--max-steps", type=int, default=MAX_STEPS)
    ap.add_argument(
        "--engine",
        choices=("langgraph", "custom"),
        default=None,
        help="Override REVENG_AGENTIC_ENGINE (default: langgraph)",
    )
    args = ap.parse_args()
    if args.engine:
        os.environ["REVENG_AGENTIC_ENGINE"] = args.engine
    result = agentic_deep_dive(args.sha256, max_steps=args.max_steps)
    print(json.dumps({k: result[k] for k in ("verdict", "confidence", "summary", "engine") if k in result}, indent=2))
    if result.get("incomplete_tooling"):
        sys.exit(1)


if __name__ == "__main__":
    main()
