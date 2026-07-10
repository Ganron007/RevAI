#!/usr/bin/env python3
"""
v2_lib.py — shared helpers for CADRE-RevAI agents and MCP façades on REMnux.

Session registry, audit logging, ghidra/ida SQL clients, subprocess tools
(capa, floss, yara), malcat_analyze façade, ghidra_decompile helper.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
import sys
import time
from pathlib import Path
from typing import Any, cast

SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")
CADRE_ENV = Path("/opt/secrets/cadre.env")
# MCP_GHIDRA constant removed 2026-07-03: Ghidra now uses the direct
# ghidrasql HTTP client in ghidra_sql_client.py. The MCP transport
# (mcp-ghidra/mcp_ghidra.py) is no longer spawned.
MCP_MALCAT = "/opt/malcat/bin/malcat.mcp.py"
GHIDRA_RPC_MCP = "/opt/scripts/ghidra_rpc_mcp.py"
# YARA rules: scan the full flat/ directory by default (440+ rules including
# APT/RANSOM/MALW/RAT/EK families from rule-sets.yar + the 9 case-study
# rules under case-studies/). The 5 hand-curated CADRE_custom.yar rules are
# also in flat/, so the v2 pipeline picks them up automatically.
# Set CADRE_YARA_RULES env var to override (e.g. a single rule file for
# deterministic reproduction).
import os as _os
YARA_RULES = _os.environ.get("CADRE_YARA_RULES", "/opt/samples/rules/flat/*.yar")
CAPA_RULES = "/opt/capa-rules"

MAX_ROWS_DEFAULT = 25
# IDA SQL queries run locally on Remnux via idasql (v0.0.17).
# On a raw binary, the first query triggers idalib analysis (~30-60s);
# subsequent queries on the same session are fast (cached in idasql).
IDA_QUERY_TIMEOUT = int(os.environ.get("REVENG_IDA_QUERY_TIMEOUT", "120"))

MALCAT_VIEW_TOOLS = {
    "anomalies": ("anomalies_list", {}),
    "strings": ("strings_top_list", {"maximum_number_of_strings": 200}),
    "yara_hits": ("yara_list", {}),
    "capa_summary": ("fns_top_list", {"maximum_number_of_functions": 30}),
}


# ============================================================================
# TOOL MANIFEST — single source of truth for all malware analysis tools.
# Adding a new tool = adding ONE entry here. Every script (intake, quick_scan,
# deep_dive, section_publisher, thorough_test) auto-discovers and runs all
# applicable tools via run_all_tools() below.
# ============================================================================
# Each entry: (name, fn, kwargs, applies_to_formats, timeout)
#   - name: short identifier used as key in tools_results dict
#   - fn: callable taking (sample_path, **kwargs) -> dict
#   - kwargs: extra kwargs to pass to fn (beyond sample_path)
#   - applies_to_formats: list of file formats the tool is valid for
#     (["pe","elf","macho","dotnet"] or None for "always runs")
#   - timeout: max seconds for the tool
TOOL_MANIFEST = {
    # MalCat — full MCP toolset (12 views, anomaly locations, decompilations)
    "malcat": {
        "fn": "malcat_analyze",
        "kwargs": {"profile": "deep"},
        "applies_to": ["pe", "elf", "macho", "dotnet", "unknown"],
        "timeout": 120,
    },
    # capa — capability detection (works on PE, ELF, Mach-O)
    "capa": {
        "fn": "capa_analyze",
        "kwargs": {},
        "applies_to": ["pe", "elf", "macho", "dotnet", "unknown"],
        "timeout": 120,
    },
    # YARA — pattern matching
    "yara": {
        "fn": "yara_scan",
        "kwargs": {},
        "applies_to": ["pe", "elf", "macho", "dotnet", "unknown"],
        "timeout": 60,
    },
    # FLOSS — obfuscated string extraction (PE only — FLOSS doesn't support ELF/Mach-O)
    "floss": {
        "fn": "floss_extract",
        "kwargs": {},
        "applies_to": ["pe", "dotnet"],
        "timeout": 120,
    },
    # .NET analysis — PE-only (mono/dotnet assembly)
    "dotnet": {
        "fn": "dotnet_analyze",
        "kwargs": {},
        "applies_to": ["dotnet", "pe"],
        "timeout": 60,
    },
    # radare2 — disassembly (works on PE, ELF, Mach-O)
    "r2_decomp": {
        "fn": "r2_decompile",
        "kwargs": {},
        "applies_to": ["pe", "elf", "macho", "dotnet", "unknown"],
        "timeout": 90,
    },
    # UPX — packer detection (PE-only, mostly)
    "upx": {
        "fn": "upx_unpack",
        "kwargs": {},
        "applies_to": ["pe", "dotnet", "elf"],
        "timeout": 30,
    },
    # xorsearch — XOR-encoded strings
    "xor": {
        "fn": "xor_string_search",
        "kwargs": {},
        "applies_to": ["pe", "elf", "macho", "dotnet", "unknown"],
        "timeout": 60,
    },
    # olevba — Office VBA macro extraction (Office docs only)
    "olevba": {
        "fn": "olevba_analyze",
        "kwargs": {},
        "applies_to": ["office", "compound"],
        "timeout": 30,
    },
    # peepdf — PDF structure analyzer
    "peepdf": {
        "fn": "peepdf_analyze",
        "kwargs": {},
        "applies_to": ["pdf"],
        "timeout": 30,
    },
    # Speakeasy — Windows PE emulation (PE-only)
    "speakeasy": {
        "fn": "speakeasy_emulate",
        "kwargs": {},
        "applies_to": ["pe", "dotnet"],
        "timeout": 90,
    },
    # Frida static probe — function cataloging (PE-only)
    "frida_probe": {
        "fn": "frida_static_probe",
        "kwargs": {},
        "applies_to": ["pe", "dotnet"],
        "timeout": 60,
    },
    # Frida full runtime trace — sandbox required (PE-only)
    "frida_trace": {
        "fn": "frida_trace_runtime",
        "kwargs": {"function_names": []},
        "applies_to": ["pe", "dotnet"],
        "timeout": 120,
    },
}


def _detect_format_for_tools(sample_path: str) -> str:
    """Detect file format to filter applicable tools."""
    try:
        import sys as _sys
        if "/opt/scripts" not in _sys.path:
            _sys.path.insert(0, "/opt/scripts")
        from file_type import detect_file_type
        info = detect_file_type(sample_path)
        return info.get("format", "unknown")
    except Exception:
        return "unknown"


def run_all_tools(sample_path: str, profile: str = "deep",
                  tools_filter: list | None = None,
                  parallel: bool = True, max_workers: int = 8) -> dict:
    """Auto-discover and run ALL applicable tools for the file type.

    Args:
        sample_path: path to the sample
        profile: "triage" (fast, smaller caps) or "deep" (full)
        tools_filter: optional list of tool names to run (None = all)
        parallel: run in parallel via ThreadPoolExecutor
        max_workers: thread pool size

    Returns:
        dict mapping tool_name -> tool_result, e.g.
        {"malcat": {...}, "capa": {...}, "yara": {...}, ...}
    """
    fmt = _detect_format_for_tools(sample_path)
    results: dict[str, Any] = {"_format": fmt, "_sample_path": sample_path, "_errors": {}}
    # Build the list of (name, fn, kwargs) tuples
    tasks = []
    for tool_name, spec in TOOL_MANIFEST.items():
        if tools_filter and tool_name not in tools_filter:
            continue
        applies = spec.get("applies_to") or [fmt]
        if fmt not in applies and "unknown" not in applies:
            continue
        # Look up the function in this module's globals
        fn = globals().get(spec["fn"])
        if fn is None:
            results["_errors"][tool_name] = f"function {spec['fn']} not found"
            continue
        kwargs = dict(spec.get("kwargs") or {})
        if tool_name == "malcat":
            kwargs["profile"] = profile
        tasks.append((tool_name, fn, kwargs, spec.get("timeout", 120)))

    def _run_one(name, fn, kwargs, timeout):
        import time as _t
        t0 = _t.time()
        try:
            r = fn(sample_path, **kwargs)
            return name, r, round(_t.time() - t0, 2), None
        except Exception as e:
            return name, {"error": f"{type(e).__name__}: {e}"}, round(_t.time() - t0, 2), str(e)

    if parallel and len(tasks) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_run_one, n, f, k, t): n for n, f, k, t in tasks}
            for fut in futures:
                name, result, dt, err = fut.result()
                results[name] = result
                if err:
                    results["_errors"][name] = err
    else:
        for name, fn, kwargs, timeout in tasks:
            n, r, dt, err = _run_one(name, fn, kwargs, timeout)
            results[n] = r
            if err:
                results["_errors"][n] = err
    return results

# High-signal anomaly names — for these we ask MalCat for the locations
_HIGH_SIGNAL_ANOMALIES = {
    "XorInLoop", "SequentialFunction", "CryptoApiUsage",
    "DynamicString", "BigResourceHighEntropy", "HighEntropy",
    "NonAsciiFunctionName", "SpaghettiFunction", "HighXrefLoopingFunction",
    "ManyUniqueImmediateBytes", "ManyHighValueImmediates",
    "ExternalModule", "NativeMethods", "BigStaticArray",
    "DotnetCryptoApiUsage", "DotnetDownloaderApiUsage", "DotnetDynamicLoadingApiUsage",
    "NoChecksum", "ResourceDirectoryGap", "GuiSubsystemNoWindowApi",
}


def load_session(sha256: str) -> dict:
    path = SESSIONS_DIR / f"{sha256}.json"
    if not path.exists():
        raise FileNotFoundError(f"session registry not found: {path}")
    return json.loads(path.read_text())


def audit_write(sha256: str, record: dict) -> Path:
    audit_dir = LOGS_DIR / sha256
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / "audit.jsonl"
    if "ts" not in record:
        record["ts"] = time.time()
    with audit_path.open("a") as f:
        f.write(json.dumps(record) + "\n")
    return audit_path


def load_api_key() -> str:
    """Return the LLM API key from env or cadre.env file.

    Env precedence:
      1. REVENG_LLM_API_KEY
      2. DEEPSEEK_API_KEY
      3. DEEPSEEK_API_KEY inside CADRE_ENV file

    For public deployments, set REVENG_LLM_API_KEY in the environment so no
    file-based secret path is required.
    """
    for env_key in ("REVENG_LLM_API_KEY", "DEEPSEEK_API_KEY"):
        v = os.environ.get(env_key)
        if v:
            return v.strip().strip('"').strip("'")
    if not CADRE_ENV.exists():
        raise RuntimeError(
            "LLM API key not configured. Set REVENG_LLM_API_KEY (or DEEPSEEK_API_KEY) "
            f"in the environment, or place it in {CADRE_ENV}"
        )
    for line in CADRE_ENV.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == "DEEPSEEK_API_KEY":
            return v.strip().strip('"').strip("'")
    raise RuntimeError(
        "LLM API key not configured. Set REVENG_LLM_API_KEY (or DEEPSEEK_API_KEY) "
        f"in the environment, or place DEEPSEEK_API_KEY in {CADRE_ENV}"
    )


def get_llm_model() -> str:
    """Return the LLM model name from env. No hardcoded default."""
    model = os.environ.get("REVENG_LLM_MODEL")
    if not model:
        raise ValueError("REVENG_LLM_MODEL is not set in the environment")
    return model


def get_llm_api_url() -> str:
    """Return the LLM API base URL from env, and ensure it points to the
    chat-completions endpoint. No hardcoded default."""
    url = os.environ.get("REVENG_LLM_API_URL")
    if not url:
        raise ValueError("REVENG_LLM_API_URL is not set in the environment")
    # Treat the env value as a base URL: append the OpenAI-compatible path.
    url = url.rstrip("/")
    return f"{url}/chat/completions"


def get_llm_reasoning() -> str | None:
    """Return the requested reasoning/thinking effort from env, or None.

    DeepSeek v4-pro supports reasoning with effort values such as
    'high' or 'max'. Set REVENG_LLM_REASONING=max to request the highest
    reasoning effort. Set it to 'disabled' or 'none' to disable thinking.
    """
    return os.environ.get("REVENG_LLM_REASONING")


def _build_reasoning_body(reasoning: str | None) -> dict:
    """Build the reasoning/thinking control parameters for the LLM body.

    Returns a dict that can be merged into the chat-completions request body.
    """
    if not reasoning:
        return {}
    r = reasoning.strip().lower()
    if r in ("disabled", "none", "off"):
        return {"thinking": {"type": "disabled"}}
    # DeepSeek OpenAI-format supports reasoning_effort values including 'max'
    # and 'high'. 'low'/'medium' are mapped to 'high', 'xhigh' to 'max'.
    return {
        "thinking": {"type": "enabled"},
        "reasoning_effort": r,
    }


def llm_judge(prompt: str, model: str | None = None, max_retries: int = 3) -> dict:
    """Call the configured LLM chat API with retries. Returns the FULL response dict.

    Configuration is read from environment at runtime (no hardcoded defaults):
      - REVENG_LLM_MODEL    (required)
      - REVENG_LLM_API_URL  (required)
      - REVENG_LLM_API_KEY  (required; falls back to DEEPSEEK_API_KEY or cadre.env)
      - REVENG_LLM_REASONING (optional: 'max', 'high', 'low', 'disabled', etc.)
    """
    import time
    import urllib.request
    import urllib.error

    api_key = load_api_key()
    effective_model = model or get_llm_model()
    api_url = get_llm_api_url()
    reasoning = get_llm_reasoning()

    body = {
        "model": effective_model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a malware analyst. Return valid JSON only. "
                    "Cite evidence as {source, query_or_table, row_or_rule, why}."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }
    body.update(_build_reasoning_body(reasoning))

    last_error: Exception | None = None
    timeout_s = 180
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                api_url,
                data=json.dumps(body).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                sleep_s = 2 ** attempt
                print(f"[llm_judge] attempt {attempt}/{max_retries} failed ({type(e).__name__}: {e}); retrying in {sleep_s}s...", flush=True)
                time.sleep(sleep_s)
            else:
                break
    raise last_error or RuntimeError("llm_judge failed")


def llm_call_metadata(response: dict) -> dict:
    """Extract auditable LLM metadata from a chat-completions response.
    Use this in every place that records `model: <name>` so we capture the
    RESPONSE-side model (verifying the request model) and reasoning tokens.
    """
    if not isinstance(response, dict):
        return {}
    usage = response.get("usage") or {}
    details = usage.get("completion_tokens_details") or {}
    return {
        "request_model": None,  # caller fills in
        "response_model": response.get("model"),
        "response_id": response.get("id"),
        "system_fingerprint": response.get("system_fingerprint"),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "reasoning_tokens": details.get("reasoning_tokens"),
        "is_reasoning_model": bool(details.get("reasoning_tokens", 0) > 0),
    }


class ToolScope:
    """Per-MCP-tool call-time policy.

    MCP servers already do their own argument validation. This ToolScope is
    defense-in-depth for the v2 layer: a hard `denied_args` block, plus a
    simple `read_only` flag that detects shell-meta characters in path-like
    arguments. Not a sandbox; rely on `run_agent_sandbox.sh` for that.
    """

    __slots__ = ("name", "denied_args", "read_only", "cwd_allowlist")

    def __init__(
        self,
        name: str,
        denied_args: list[str] | None = None,
        read_only: bool = False,
        cwd_allowlist: list[str] | None = None,
    ):
        self.name = name
        self.denied_args = list(denied_args or ())
        self.read_only = read_only
        self.cwd_allowlist = list(cwd_allowlist or ())


# Default scopes shipped with v2.0 (2026-06-29):
#   - ghidra_query + ida_query: read-only SQL (no path writes)
#   - capa_analyze / floss_extract / yara_scan: read-only (path is read by tool)
#   - malcat_analyze: full (path is read, but allowlist restricts)
#   - ghidra_decompile: full
# Read-only tools: read paths under /opt/samples/ or /opt/sessions/.
# (ghidra_query / ida_query take a `sql` arg, not a path - cwd_allowlist is
# unused for those; the shell-meta check still applies to whatever they read.)
DEFAULT_MCP_SCOPES: dict[str, ToolScope] = {
    n: ToolScope(n, read_only=True, cwd_allowlist=["/opt/samples/", "/opt/sessions/"])
    for n in (
        "ghidra_query", "ida_query",
        "capa_analyze", "floss_extract", "yara_scan",
    )
}
DEFAULT_MCP_SCOPES["malcat_analyze"] = ToolScope(
    "malcat_analyze",
    read_only=True,
    cwd_allowlist=["/opt/samples/", "/home/remnux/.malcat/"],
)
# ghidra_decompile: full - decompilation writes back to the project
DEFAULT_MCP_SCOPES["ghidra_decompile"] = ToolScope("ghidra_decompile")


class McpJsonClient:
    """Minimal stdio MCP client for single-server subprocess calls."""

    # LSP cannot infer that subprocess.Popen.__init__ always returns the
    # constructed instance (it sees it as `None`).  Every self.proc.stdin/.stdout
    # call therefore trips `union-attr`.  The fixes below avoid the noise without
    # `# type: ignore` per-line:
    #   * `_w`, `_r` wrap writes/reads in a single typed boundary; LSP trusts
    #     what they return.
    #   * `self.proc` is forced to the concrete non-Optional type via a runtime
    #     re-bind immediately after construction.
    proc: "subprocess.Popen[bytes]"

    def _w(self, payload: str) -> None:
        """One write + flush, swallowing a closed-pipe EPIPE.

        Uses `getattr` to dodge the LSP-only error where typeshed declares
        `Popen.stdin / .stdout / .stderr` as Optional[IO] when text=True or
        when the runtime pipe was never opened.  Behaviourally we always pass
        stdin=PIPE/stdout=PIPE/stderr=PIPE so this is safe; the `getattr`
        shushes the type checker only.
        """
        proc = self.proc
        stdin = getattr(proc, "stdin", None)
        if stdin is None:
            return
        try:
            stdin.write(payload)
            stdin.flush()
        except (BrokenPipeError, ValueError):
            # server already exited; the next read will surface the cause.
            pass

    def _r(self) -> str:
        """One readline; raises if the server is dead."""
        proc = self.proc
        stdout = getattr(proc, "stdout", None)
        stderr = getattr(proc, "stderr", None)
        # stdout is always a file object when Popen is created with
        # stdout=PIPE. The getattr+None-check is just defensive
        # against the LSP checker; the assert makes the type explicit.
        assert stdout is not None, "MCP subprocess has no stdout pipe"
        line = stdout.readline() if stdout else ""
        if not line:
            err = stderr.read() if stderr else ""
            raise RuntimeError(f"MCP {self._name} closed: {err}")
        return line

    def __init__(
        self,
        script: str,
        extra_args: list[str] | None = None,
        name: str = "v2",
        scopes: list["ToolScope"] | None = None,
    ):
        """MCP JSON-RPC client with optional per-tool scope policy.

        Args:
            script: path to the MCP server script.
            extra_args: extra CLI args to pass to the server.
            name: client name for the MCP initialize handshake.
            scopes: list of ToolScope. When call_tool(name, ...) is invoked,
                the first scope matching `name` is consulted to validate
                arguments. Set scopes=None to disable enforcement.
        """
        self.proc = subprocess.Popen(  # type: ignore[assignment]
            [sys.executable, script, *(extra_args or [])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,
        )
        self._id = 0
        self._name = name
        self._scopes = {s.name: s for s in (scopes or [])}
        self._call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": name, "version": "0.2"},
                },
            }
        )
        self._w(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )

    def _enforce_scope(self, tool: str, arguments: dict) -> None:
        """Reject + raise if a scope is configured for `tool` and its rules
        are violated by `arguments`.

        Enforces:
          - denied_args: any argument name in this list is rejected.
          - read_only: True -> reject `path` / `src` / `file` arguments that
            contain shell-meta characters (`&&`, `;`, `|`, `$(`, backtick, redirects)
            OR do not start with any entry in cwd_allowlist.
          - cwd_allowlist: when set, an empty cwd_allowlist with read_only=True
            blocks ALL paths; a populated cwd_allowlist restricts reads to
            those prefixes.

        Argument ENFORCEMENT is intended as defense-in-depth against an LLM
        that starts calling creative arguments. It is NOT a sandbox.
        """
        scope = self._scopes.get(tool)
        if scope is None:
            return
        for k in (arguments or {}):
            if k in scope.denied_args:
                raise PermissionError(
                    f"MCP {self._name}: tool {tool} denies argument {k!r}"
                )
        if scope.read_only:
            for k in ("path", "src", "file"):
                v = (arguments or {}).get(k)
                if not isinstance(v, str):
                    continue
                # Reject shell-meta characters in path-like args.
                if any(tok in v for tok in ("&&", ";", "|", "$(", "`", " > ", " >> ")):
                    raise PermissionError(
                        f"MCP {self._name}: tool {tool} read_only - denied shell-meta in {k}={v!r}"
                    )
                # If cwd_allowlist is set, the path MUST start with one of
                # the allowed prefixes. Empty cwd_allowlist with read_only=True
                # blocks all paths.
                if scope.cwd_allowlist:
                    if not any(v.startswith(p) for p in scope.cwd_allowlist):
                        raise PermissionError(
                            f"MCP {self._name}: tool {tool} read_only - {k}={v!r} not under any allowlist prefix ({scope.cwd_allowlist})"
                        )
                else:
                    # read_only with empty allowlist = block everything
                    raise PermissionError(
                        f"MCP {self._name}: tool {tool} read_only - {k}={v!r} blocked (no cwd_allowlist configured)"
                    )

    def _call(self, msg: dict) -> dict:
        self._w(json.dumps(msg) + "\n")
        line = self._r()
        return json.loads(line)

    def call_tool(self, tool: str, arguments: dict) -> Any:
        self._enforce_scope(tool, arguments)
        self._id += 1
        resp = self._call(
            {
                "jsonrpc": "2.0",
                "id": self._id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            }
        )
        result = resp.get("result", {})
        if result.get("isError"):
            raise RuntimeError(result["content"][0]["text"])
        text = result["content"][0]["text"]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def close(self):
        proc = self.proc
        stdin = getattr(proc, "stdin", None)
        if stdin is not None:
            try:
                stdin.close()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


class McpGhidraClient:
    """Backwards-compat shim. The MCP transport for Ghidra was removed
    in 2026-07-03 (see Tools/v2-deploy/ghidra_sql_client.py). This
    shim re-exports the same .ghidra_query() interface but routes
    through the direct ghidrasql HTTP client (2 layers instead of 4).
    """
    def __init__(self):
        from ghidra_sql_client import get_ghidra_sql_client
        self._client = get_ghidra_sql_client()

    def ghidra_query(self, session_id: str, sql: str, max_rows: int = 200) -> dict:
        return self._client.ghidra_query(session_id, sql, max_rows=max_rows)

    def close(self) -> None:
        # Owned by the singleton; no per-instance cleanup.
        pass


def ida_query_remote(ida_session_id: str, sql: str, max_rows: int = MAX_ROWS_DEFAULT + 5) -> dict:
    """Query IDA database via local idasql on Remnux (no SSH)."""
    from ida_sql_client import get_ida_sql_client
    client = get_ida_sql_client()
    return client.ida_query(ida_session_id, sql, max_rows=max_rows)


def capa_analyze(sample_path: str) -> dict:
    try:
        proc = subprocess.run(
            ["capa", "-j", "-r", CAPA_RULES, sample_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode == 0:
            j = json.loads(proc.stdout)
            rules = j.get("rules", {})
            return {
                "rule_count": len(rules),
                "top_rules": sorted(
                    [
                        {
                            "name": k,
                            "attack": v.get("attack", []),
                            "mbc": v.get("mbc", []),
                        }
                        for k, v in rules.items()
                    ],
                    key=lambda x: -len(x.get("attack", [])) - len(x.get("mbc", [])),
                )[:15],
            }
        return {"error": f"capa rc={proc.returncode}", "stderr": proc.stderr[-500:]}
    except Exception as e:
        return {"error": str(e)}


def _collect_floss_strings(data: dict, max_strings: int = 80) -> tuple[list[str], dict[str, int]]:
    """Flatten a floss --json output into a deduped list of strings + per-category counts."""
    def _collect_from_list(items):
        out = []
        for item in items or []:
            if isinstance(item, dict):
                s = item.get("string") or item.get("s") or ""
            else:
                s = str(item)
            s = s.strip()
            if len(s) >= 6:
                out.append(s[:200])
        return out

    strings: list[str] = []
    per_category: dict[str, int] = {}

    priority_categories = (
        "decoded_strings",
        "stack_strings",
        "tight_strings",
        "language_strings",
        "language_strings_missed",
        "static_strings",
    )

    inner = data.get("strings")
    if isinstance(inner, dict):
        for cat in priority_categories:
            items = inner.get(cat) or []
            vals = _collect_from_list(items)
            per_category[cat] = len(vals)
            strings.extend(vals)
        leftover = [k for k in inner.keys() if k not in priority_categories]
        for cat in leftover:
            items = inner.get(cat) or []
            vals = _collect_from_list(items)
            per_category[cat] = len(vals)
            strings.extend(vals)
    else:
        for cat in priority_categories:
            items = data.get(cat) or []
            vals = _collect_from_list(items)
            per_category[cat] = len(vals)
            strings.extend(vals)

    seen: set[str] = set()
    deduped: list[str] = []
    for s in strings:
        if s in seen:
            continue
        seen.add(s)
        deduped.append(s)
        if len(deduped) >= max_strings:
            break
    return deduped, per_category


def floss_extract(sample_path: str, max_strings: int = 80) -> dict:
    # floss refuses to deobfuscate files > 16MB. Fall back to strings(1) +
    # manual XOR scanning for over-limit samples so we still get value.
    import os as _os
    try:
        size = _os.path.getsize(sample_path)
    except OSError:
        size = 0
    floss_limit = 0x1000000  # 16 MiB — hard limit in floss 3.x
    try:
        if size > floss_limit:
            # Try with --only static (skip emulation that has the 16MB hard limit)
            proc = subprocess.run(
                ["floss", "--only", "static", "--json", sample_path],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                out = {"floss_ok": True, "static_only": True,
                       "size_bytes": size,
                       "size_exceeded_deobfuscate_limit": True}
                strings, per_category = _collect_floss_strings(data)
                out["string_count"] = len(strings)
                out["strings"] = strings[:max_strings]
                out["per_category"] = per_category
                return out
            # Both deobfuscate and static-only failed; fall back to plain strings(1)
            out = {"floss_ok": False, "static_only": True,
                   "size_bytes": size,
                   "size_exceeded_deobfuscate_limit": True,
                   "fallback": "strings(1) + xor_string_search",
                   "error": f"floss rc={proc.returncode}",
                   "stderr": proc.stderr[-500:]}
            try:
                sp = subprocess.run(
                    ["strings", "-a", "-n", "8", sample_path],
                    capture_output=True, text=True, timeout=120,
                )
                lines = [l.strip() for l in (sp.stdout or "").splitlines()
                         if 6 <= len(l.strip()) <= 300]
                out["static_strings"] = lines[:max_strings]
                out["static_string_count"] = len(lines)
            except Exception as e:
                out["static_strings_error"] = str(e)
            return out
        proc = subprocess.run(
            ["floss", "--json", sample_path],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if proc.returncode != 0:
            return {"error": f"floss rc={proc.returncode}", "stderr": proc.stderr[-500:]}
        data = json.loads(proc.stdout)
        deduped, per_category = _collect_floss_strings(data, max_strings)
        return {
            "string_count": len(deduped),
            "strings": deduped,
            "per_category": per_category,
            "raw_key_total": sum(per_category.values()),
        }
    except Exception as e:
        return {"error": str(e)}


def yara_scan(sample_path: str, rules_glob: str = YARA_RULES) -> dict:
    """Run yara-x (yr) against a sample using one or more rule files.

    The `rules_glob` argument can be:
      - a single file path: "/opt/.../rules.yar"
      - a shell glob:       "/opt/.../flat/*.yar"
      - a comma-separated list: "/path/a.yar,/path/b.yar"

    We expand the glob with Python's pathlib.Path.glob(), then scan
    in batches of 50 files to avoid argument-list overflow and keep
    the NDJSON parser stable.
    """
    import glob as _glob
    candidates = []
    for piece in rules_glob.replace(",", " ").split():
        if Path(piece).is_file():
            candidates.append(piece)
            continue
        for m in _glob.glob(piece):
            if Path(m).is_file():
                candidates.append(m)
    if not candidates:
        return {"error": f"no YARA rule files matched glob: {rules_glob!r}"}

    # Batch size: yr scan with 445 rules emits all output to stderr
    # because subprocess.run hits argument-length limits. Scanning
    # 50 files at a time keeps stdout/stderr clean.
    BATCH = 50
    all_matches = []
    errors = []
    for i in range(0, len(candidates), BATCH):
        batch = candidates[i : i + BATCH]
        try:
            proc = subprocess.run(
                ["yr", "scan", "--output-format", "ndjson", "--print-strings",
                 *batch, sample_path],
                capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            errors.append(f"batch[{i}]: timeout")
            continue
        except Exception as e:
            errors.append(f"batch[{i}]: {e}")
            continue
        # yr may write matches to stderr when argument list is large.
        # Try stdout first; if empty, parse stderr.
        text = proc.stdout or proc.stderr
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            for rule in obj.get("rules", []) or []:
                str_hits = [
                    {
                        "id": s.get("identifier"),
                        "offset": s.get("offset"),
                        "match": (s.get("match") or "")[:120],
                    }
                    for s in (rule.get("strings") or [])[:8]
                ]
                all_matches.append(
                    {
                        "rule": rule.get("identifier", "?"),
                        "path": obj.get("path"),
                        "strings": str_hits,
                    }
                )

    # deduplicate by rule name
    seen: set[str] = set()
    deduped = []
    for m in all_matches:
        if m["rule"] in seen:
            continue
        seen.add(m["rule"])
        deduped.append(m)
    result: dict[str, Any] = {"rule_count": len(deduped), "matches": deduped[:30]}
    if errors:
        result["batch_errors"] = errors[:10]
    return result


def _unwrap_mcp_result(raw: Any) -> Any:
    if isinstance(raw, dict) and "content" in raw:
        content = raw["content"]
        if isinstance(content, list) and content:
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return text
    return raw


# MalCat feature profiles — what to fetch per pipeline phase
MALCAT_TRIAGE_VIEWS = [
    "anomalies", "yara_hits", "strings", "imports",
    "functions", "constants", "anomaly_locations", "entropy", "sections",
]
MALCAT_TRIAGE_LIMITS = {
    "strings_max": 100, "imports_max": 100, "functions_max": 10,
    "anomaly_locations_max": 5, "decompile_top_n": 1,
}
MALCAT_DEEP_VIEWS = [
    "anomalies", "yara_hits", "strings", "imports", "sections", "entropy",
    "functions", "constants", "anomaly_locations", "carved", "virtual_files",
    "structures", "decompile", "script_decompile", "unpack_donut",
]
MALCAT_DEEP_LIMITS = {
    "strings_max": 300, "imports_max": 300, "functions_max": 30,
    "anomaly_locations_max": 50, "decompile_top_n": 3,
}


def malcat_analyze(sample_path: str, views: list[str] | None = None,
                   profile: str = "deep", limits: dict | None = None) -> dict:
    """Comprehensive MalCat analysis — uses the full MCP toolset.

    Profile = "triage" (fast, signal-only) or "deep" (full).
    Pass `views` to override profile; pass `limits` to override caps.

    Calls (in order): analyse_file, analyse_infos, anomalies_list, yara_list,
    strings_top_list, symbols_search, fns_top_list, constants_list,
    file_list_carved, file_list_virtual_files, structs_list, script_decompile,
    unpack_donut (if .NET), anomaly_list_locations (for each high-signal
    anomaly), and fn_decompile for the top-N functions.

    Returns a dict with keys: analysis_id, path, file_summary, profile, limits,
    views (per-view raw results), functions (top-N), constants (URLs/IPs/
    registry), anomalies (with locations), carved_files, virtual_files,
    structures, decompilations, script_decompile, unpack_result, errors.
    """
    if profile == "triage":
        if views is None:
            views = list(MALCAT_TRIAGE_VIEWS)
        if limits is None:
            limits = dict(MALCAT_TRIAGE_LIMITS)
    elif profile == "deep":
        if views is None:
            views = list(MALCAT_DEEP_VIEWS)
        if limits is None:
            limits = dict(MALCAT_DEEP_LIMITS)
    elif profile == "minimal":
        if views is None:
            views = ["anomalies", "yara_hits", "imports"]
        if limits is None:
            limits = dict(MALCAT_TRIAGE_LIMITS)
    else:
        return {"error": f"unknown profile: {profile}"}

    allowed = {
        "anomalies", "strings", "imports", "sections", "yara_hits",
        "entropy", "capa_summary", "functions", "constants", "carved",
        "virtual_files", "structures", "script_decompile", "unpack_donut",
        "decompile", "anomaly_locations",
    }
    bad = [v for v in views if v not in allowed]
    if bad:
        return {"error": f"unknown views: {bad}", "allowed": sorted(allowed)}

    cli = McpJsonClient(
        MCP_MALCAT,
        extra_args=["--num_analyses", "5"],
        name="malcat",
        scopes=list(DEFAULT_MCP_SCOPES.values()),
    )
    out: dict[str, Any] = {
        "analysis_id": None,
        "path": sample_path,
        "profile": profile,
        "limits": limits,
        "file_summary": None,
        "views": {},
        "functions": [],
        "constants": [],
        "anomalies": [],
        "carved_files": [],
        "virtual_files": [],
        "structures": [],
        "decompilations": {},
        "script_decompile": None,
        "unpack_result": None,
        "errors": [],
    }
    try:
        # 1. Open the file
        info = cli.call_tool("analyse_file", {"path": sample_path})
        if not isinstance(info, dict):
            return {"error": "analyse_file returned non-dict", "raw": info}
        analysis_id = info.get("analysis_id")
        if analysis_id is None:
            return {"error": "analyse_file returned no analysis_id", "raw": info}
        out["analysis_id"] = analysis_id

        # 2. File summary (always — for all views)
        try:
            out["file_summary"] = cli.call_tool("analyse_infos", {"analysis_id": analysis_id})
        except Exception as e:
            out["errors"].append(f"analyse_infos: {e}")

        # 3. Anomalies (with locations for high-signal ones)
        if "anomalies" in views or "anomaly_locations" in views:
            try:
                anoms = cli.call_tool("anomalies_list", {"analysis_id": analysis_id})
                if isinstance(anoms, list):
                    out["anomalies"] = anoms
                    out["views"]["anomalies"] = anoms
            except Exception as e:
                out["errors"].append(f"anomalies_list: {e}")
            if "anomaly_locations" in views:
                locations: dict = {}
                loc_max = limits.get("anomaly_locations_max", 5)
                loc_count = 0
                for anom in (out["anomalies"] or []):
                    if loc_count >= loc_max:
                        break
                    name = anom.get("name") if isinstance(anom, dict) else None
                    if not name or name not in _HIGH_SIGNAL_ANOMALIES:
                        continue
                    try:
                        locs = cli.call_tool(
                            "anomaly_list_locations",
                            {"analysis_id": analysis_id, "anomaly_name": name},
                        )
                        if locs:
                            sample = []
                            for loc in (locs if isinstance(locs, list) else [])[:5]:
                                if isinstance(loc, dict):
                                    sample.append({
                                        "ea": loc.get("ea"),
                                        "context": str(loc.get("context") or loc.get("description") or "")[:200],
                                    })
                            if sample:
                                locations[name] = sample
                                loc_count += 1
                    except Exception as e:
                        out["errors"].append(f"anomaly_list_locations({name}): {e}")
                out["views"]["anomaly_locations"] = locations

        # 4. YARA matches
        if "yara_hits" in views:
            try:
                yara = cli.call_tool("yara_list", {"analysis_id": analysis_id})
                out["views"]["yara_hits"] = yara
            except Exception as e:
                out["errors"].append(f"yara_list: {e}")

        # 5. Strings (top by length, capped per profile)
        if "strings" in views:
            strs_max = limits.get("strings_max", 100)
            try:
                strs = cli.call_tool("strings_top_list", {"analysis_id": analysis_id, "maximum_number_of_strings": strs_max})
                out["views"]["strings"] = strs
            except Exception as e:
                out["errors"].append(f"strings_top_list: {e}")

        # 6. Imports (via symbols_search, capped per profile)
        if "imports" in views:
            imps_max = limits.get("imports_max", 100)
            try:
                syms = cli.call_tool("symbols_search", {"analysis_id": analysis_id, "maximum_number_of_symbols": imps_max, "contains": ""})
                out["views"]["imports"] = syms
            except Exception as e:
                out["errors"].append(f"symbols_search: {e}")

        # 7. Sections + entropy (from file_summary.layout)
        if ("sections" in views or "entropy" in views) and isinstance(out["file_summary"], dict):
            layout = out["file_summary"].get("layout") or []
            if "sections" in views:
                out["views"]["sections"] = layout[:50]
            if "entropy" in views:
                out["views"]["entropy"] = {
                    "file_entropy": out["file_summary"].get("entropy"),
                    "regions": [
                        {"name": r.get("name"), "entropy": r.get("entropy"), "size": r.get("size")}
                        for r in (layout or [])[:50] if isinstance(r, dict)
                    ],
                }

        # 8. Functions (top, capped per profile)
        if "functions" in views or "capa_summary" in views:
            fns_max = limits.get("functions_max", 10)
            try:
                fns = cli.call_tool("fns_top_list", {"analysis_id": analysis_id, "maximum_number_of_functions": fns_max})
                if isinstance(fns, list):
                    out["functions"] = fns
                    out["views"]["functions"] = fns
            except Exception as e:
                out["errors"].append(f"fns_top_list: {e}")

        # 9. Constants (URLs, IPs, registry keys, suspicious immediates in code)
        if "constants" in views:
            try:
                consts = cli.call_tool("constants_list", {"analysis_id": analysis_id})
                if isinstance(consts, list):
                    out["constants"] = consts
                    out["views"]["constants"] = consts
            except Exception as e:
                out["errors"].append(f"constants_list: {e}")

        # 10. Carved files (only in deep profile)
        if "carved" in views:
            try:
                carved = cli.call_tool("file_list_carved", {"analysis_id": analysis_id})
                if isinstance(carved, list):
                    out["carved_files"] = carved
                    out["views"]["carved"] = carved
            except Exception as e:
                out["errors"].append(f"file_list_carved: {e}")

        # 11. Virtual files (only in deep profile)
        if "virtual_files" in views:
            try:
                vfiles = cli.call_tool("file_list_virtual_files", {"analysis_id": analysis_id})
                if isinstance(vfiles, list):
                    out["virtual_files"] = vfiles
                    out["views"]["virtual_files"] = vfiles
            except Exception as e:
                out["errors"].append(f"file_list_virtual_files: {e}")

        # 12. Structures (only in deep profile)
        if "structures" in views:
            try:
                structs = cli.call_tool("structs_list", {"analysis_id": analysis_id})
                if isinstance(structs, list):
                    out["structures"] = structs
                    out["views"]["structures"] = structs
            except Exception as e:
                out["errors"].append(f"structs_list: {e}")

        # 13. Decompile top-N functions (N per profile)
        if "decompile" in views:
            top_n = limits.get("decompile_top_n", 1)
            for fn in (out["functions"] or [])[:top_n]:
                if not isinstance(fn, dict):
                    continue
                ea = fn.get("ea") or fn.get("address")
                if ea is None:
                    continue
                try:
                    decomp = cli.call_tool("fn_decompile", {"analysis_id": analysis_id, "ea": ea})
                    if decomp:
                        out["decompilations"][str(ea)] = {
                            "name": fn.get("name", ""),
                            "decompilation": str(decomp)[:4000],
                        }
                except Exception as e:
                    out["errors"].append(f"fn_decompile({ea}): {e}")

        # 14. Script decompile (VBS, VBA, JS, PS1, Python, AutoIT — MalCat detects script engines)
        if "script_decompile" in views:
            try:
                scripts_in_file = any(
                    isinstance(v, dict) and (
                        "script" in str(v.get("kind", "")).lower() or
                        v.get("extension") in ("vbs", "vba", "js", "ps1", "py", "au3")
                    )
                    for v in (out["virtual_files"] or [])
                )
                if scripts_in_file:
                    out["script_decompile"] = cli.call_tool(
                        "script_decompile",
                        {"analysis_id": analysis_id, "output_path": "/tmp/script_decomp.txt"},
                    )
            except Exception as e:
                out["errors"].append(f"script_decompile: {e}")

        # 15. Donut unpack (for .NET samples — MalCat knows the Donut loader format)
        if "unpack_donut" in views:
            file_type = (out["file_summary"] or {}).get("type", "").lower() if isinstance(out["file_summary"], dict) else ""
            if "dotnet" in file_type or "msil" in file_type:
                try:
                    out["unpack_result"] = cli.call_tool(
                        "unpack_donut", {"analysis_id": analysis_id}
                    )
                except Exception as e:
                    out["errors"].append(f"unpack_donut: {e}")

        return out
    except Exception as e:
        out["error"] = f"malcat_analyze top-level: {e}"
        return out
    finally:
        cli.close()


def ghidra_decompile(session_id: str, function: str) -> dict:
    """Decompile one function via ghidra-rpc MCP (v2 thin tool)."""
    session = load_session(
        session_id.replace("ghidra-", "") if session_id.startswith("ghidra-") else session_id
    )
    sha = session["sha256"]
    binary = Path(session["sample_path"]).name

    cli = McpJsonClient(
        GHIDRA_RPC_MCP,
        name="ghidra_rpc",
        scopes=list(DEFAULT_MCP_SCOPES.values()),
    )
    try:
        load = cli.call_tool("load_binary", {"path": session["sample_path"]})
        if isinstance(load, dict) and load.get("binary"):
            binary = load["binary"]
        result = cli.call_tool(
            "decompile_function",
            {"binary": binary, "function": function},
        )
        return {
            "session_id": session_id,
            "sha256": sha,
            "function": function,
            "decompilation": result,
        }
    finally:
        try:
            cli.call_tool("save_project", {"binary": binary})
        except Exception:
            pass
        cli.close()


def cap_rows_for_prompt(evidence_table: dict) -> str:
    result = evidence_table.get("result") or {}
    rows = result.get("rows", []) or []
    rows = rows[:MAX_ROWS_DEFAULT]
    engine = evidence_table.get("engine", "?")
    out = [f"engine: {engine}", f"label: {evidence_table.get('label', '?')}"]
    out.append(f"sql: {evidence_table.get('sql', '')}")
    if evidence_table.get("error"):
        out.append(f"error: {evidence_table['error']}")
    elif not rows:
        out.append("rows: (empty)")
    else:
        keys = list(rows[0].keys())
        out.append("columns: " + ", ".join(keys))
        for r in rows:
            out.append("  " + " | ".join(str(r.get(k, "")) for k in keys))
    return "\n".join(out)


def synthesize_verdict_v1(evidence: dict) -> dict:
    score = 0
    findings = []
    yara = evidence.get("yara", {})
    if yara.get("rule_count", 0) > 0:
        score += 50 * min(yara["rule_count"], 5)
        findings.append(f"yara: {yara['rule_count']} matches")
    capa = evidence.get("capa", {})
    if capa.get("rule_count", 0) > 0:
        score += 40
        findings.append(f"capa: {capa['rule_count']} rules")
    if score >= 50:
        verdict = "malicious"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {
        "verdict": verdict,
        "score": score,
        "findings": findings,
        "source": "fallback_v1",
    }


# --- T4 helpers: emulation, HITL, sandbox, goodware, report template ---

SPEAKEASY_TIMEOUT = 60
GOODWARE_DIR = Path("/opt/samples/goodware")
HITL_DIR = Path("/tmp/cadre-hitl")
REPORT_MASTER_SECTIONS = [
    "Executive Summary",
    "1. Sample Identification",
    "2. Classification",
    "3. Initial Triage (15 minutes)",
    "4. Static Analysis",
    "5. Behavioral Analysis",
    "6. Network Analysis",
    "7. Capability Assessment",
    "8. MITRE ATT&CK Mapping",
    "9. Comparison with Known Families",
    "10. Attribution",
    "11. Indicators of Compromise",
    "12. Detection Rules",
    "13. Containment, Eradication, Recovery",
    "14. Recommendations",
    "15. Appendices",
    "16. Author + Sign-off",
]

TECHNICAL_REPORT_SECTIONS = [
    "1. Executive Summary",
    "2. Sample Metadata",
    "3. File Layout & Structural Analysis",
    "4. Malcat Triage Summary",
    "5. Static Code Analysis",
    "6. Behavioral & Dynamic Analysis",
    "7. Network Indicators & C2",
    "8. Capabilities & MITRE ATT&CK Mapping",
    "9. Indicators of Compromise",
    "10. Detection Engineering",
    "11. What We Don't Know",
    "12. Appendix: Analysis Environment",
]


def format_malcat_evidence(
    malcat_result: dict | None,
    *,
    max_strings: int = 25,
    max_anomalies: int = 15,
    max_yara: int = 15,
    max_imports: int = 25,
    max_constants: int = 25,
    max_sections: int = 12,
    max_decomp: int = 2,
    max_carved: int = 10,
    max_virtual: int = 10,
    max_structs: int = 10,
) -> str:
    """Render a Malcat-style structured triage report from malcat_analyze output.

    Mirrors Malcat's Summary view: file layout, basic info, YARA, anomalies,
    strings, constants, imports, decompilations, and embedded files. The
    result is markdown tables and snippets, not a raw JSON dump.
    """
    if not malcat_result:
        return "(no Malcat analysis available)"
    if isinstance(malcat_result, dict) and malcat_result.get("error"):
        return f"(Malcat analysis error: {malcat_result.get('error')})"

    mc = malcat_result
    lines: list[str] = []
    out = lines.append

    # --- Basic file information ---
    out("### Malcat File Summary")
    fs = mc.get("file_summary") or {}
    if not fs:
        out("(no file summary)")
    else:
        info = []
        for k in (
            "md5", "sha1", "sha256", "size", "type", "format", "architecture",
            "compiler", "linker", "entrypoint", "subsystem", "is_dll", "is_driver",
            "is_packed", "entropy", "overlay_size",
        ):
            v = fs.get(k)
            if v not in (None, "", 0, False):
                if isinstance(v, (bytes, bytearray)):
                    v = v.decode("ascii", errors="ignore").rstrip("\x00")
                info.append(f"{k}: {v}")
        if info:
            out("```")
            for item in info:
                out(item)
            out("```")
        out("")

    # --- File layout / sections ---
    layout = fs.get("layout") or []
    if layout:
        out("### File Layout (sections/regions)")
        out("| Name | Size | Entropy | Rights |")
        out("|---|---|---|---|")
        for r in layout[:max_sections]:
            if not isinstance(r, dict):
                continue
            name = r.get("name", r.get("struct_name", "?"))
            size = r.get("phys_size", r.get("size", "?"))
            ent = r.get("entropy", "?")
            rights = []
            if r.get("read"):
                rights.append("R")
            if r.get("write"):
                rights.append("W")
            if r.get("execute"):
                rights.append("X")
            out(f"| {name} | {size} | {ent} | {''.join(rights) or '-'} |")
        out("")

    # --- YARA ---
    yara = (mc.get("views") or {}).get("yara_hits") or []
    if yara:
        out(f"### YARA Matches ({len(yara)})")
        out("| Rule | Category | Danger |")
        out("|---|---|---|")
        for y in yara[:max_yara]:
            if not isinstance(y, dict):
                continue
            rule = y.get("rule", y.get("name", "?"))
            cat = y.get("category", y.get("tags", "?"))
            danger = y.get("danger", y.get("level", "?"))
            out(f"| {rule} | {cat} | {danger} |")
        out("")

    # --- Anomalies ---
    anoms = mc.get("anomalies") or []
    if anoms:
        out(f"### Anomalies ({len(anoms)})")
        out("| Name | Level | Category | Hits |")
        out("|---|---|---|---|")
        for a in anoms[:max_anomalies]:
            if not isinstance(a, dict):
                continue
            name = a.get("name", "?")
            level = a.get("level", "?")
            cat = a.get("category", "?")
            hits = a.get("num_hits", 1)
            out(f"| {name} | {level} | {cat} | {hits} |")
        out("")

    # --- High-signal anomaly locations ---
    locs = (mc.get("views") or {}).get("anomaly_locations") or {}
    if locs:
        out("### Anomaly Locations (high-signal)")
        for name, samples in list(locs.items())[:5]:
            out(f"- **{name}**")
            for s in samples[:3]:
                if isinstance(s, dict):
                    ea = s.get("ea", "?")
                    ctx = (s.get("context") or "")[:120]
                    out(f"  - `{ea}`: {ctx}")
        out("")

    # --- Strings ---
    strs = (mc.get("views") or {}).get("strings") or []
    if strs:
        out(f"### Top Strings ({len(strs)} extracted)")
        out("| Address | Type | Tag | Score | String |")
        out("|---|---|---|---|---|")
        for s in strs[:max_strings]:
            if not isinstance(s, dict):
                continue
            addr = s.get("address", s.get("ea", "?"))
            typ = s.get("type", "?")
            tag = s.get("tag", s.get("tags", "-"))
            score = s.get("score", "-")
            summary = (s.get("summary") or s.get("string") or "")[:120]
            out(f"| {addr} | {typ} | {tag} | {score} | `{summary}` |")
        out("")

    # --- Constants ---
    consts = mc.get("constants") or []
    if consts:
        out(f"### Constants / Known Patterns ({len(consts)})")
        out("| Category | Value |")
        out("|---|---|")
        for c in consts[:max_constants]:
            if not isinstance(c, dict):
                continue
            cat = c.get("category", c.get("type", "?"))
            val = c.get("id", c.get("value", c.get("name", "?")))
            out(f"| {cat} | `{val}` |")
        out("")

    # --- Imports ---
    imps = (mc.get("views") or {}).get("imports") or []
    if imps:
        out(f"### Imports ({len(imps)})")
        out("| Address | Name | Type |")
        out("|---|---|---|")
        for imp in imps[:max_imports]:
            if not isinstance(imp, dict):
                continue
            name = imp.get("name", "?")
            typ = imp.get("type", "?")
            addr = imp.get("address", imp.get("ea", "?"))
            out(f"| {addr} | {name} | {typ} |")
        out("")

    # --- Decompilations ---
    decs = mc.get("decompilations") or {}
    if decs:
        out(f"### Decompilations (top {max_decomp})")
        for addr, info in list(decs.items())[:max_decomp]:
            if not isinstance(info, dict):
                continue
            nm = info.get("name", "?")
            out(f"#### {addr} — {nm}")
            out("```c")
            out((info.get("decompilation") or "")[:2500])
            out("```")
        out("")

    # --- Carved / virtual files / structures ---
    carved = mc.get("carved_files") or []
    if carved:
        out(f"### Carved Files ({len(carved)})")
        out("| Name | Type | Size |")
        out("|---|---|---|")
        for f in carved[:max_carved]:
            if not isinstance(f, dict):
                continue
            out(f"| {f.get('name', '?')} | {f.get('type', f.get('kind', '?'))} | {f.get('size', '?')} |")
        out("")

    vfiles = mc.get("virtual_files") or []
    if vfiles:
        out(f"### Virtual Files ({len(vfiles)})")
        out("| Name | Type | Extension |")
        out("|---|---|---|")
        for f in vfiles[:max_virtual]:
            if not isinstance(f, dict):
                continue
            out(f"| {f.get('name', '?')} | {f.get('type', f.get('kind', '?'))} | {f.get('extension', '?')} |")
        out("")

    structs = mc.get("structures") or []
    if structs:
        out(f"### Structures ({len(structs)})")
        names = [s.get("name", s.get("struct_name", str(s))) for s in structs[:max_structs] if isinstance(s, dict)]
        out(", ".join(names))
        out("")

    # --- Errors ---
    errs = mc.get("errors") or []
    if errs:
        out("### Malcat Errors")
        for e in errs[:5]:
            out(f"- {e}")

    return "\n".join(lines)


def build_technical_evidence_block(
    session: dict,
    verdict: dict | None,
    deep: dict | None,
    yara_meta: dict | None,
    tools_results: dict,
    audit: list,
    dotnet_result: dict | None = None,
    r2_decomp: dict | None = None,
    r2_ai: dict | None = None,
    frida_trace: dict | None = None,
    upx: dict | None = None,
    xor_hits: dict | None = None,
    olevba: dict | None = None,
    peepdf: dict | None = None,
    malcat_result: dict | None = None,
    rag_block: str = "",
) -> str:
    """Assemble a structured, evidence-rich markdown block for a technical report."""
    lines: list[str] = ["# Technical Evidence Pack", ""]
    lines.append(f"**sha256:** {session.get('sha256', '?')}  ")
    lines.append(f"**sample_path:** {session.get('sample_path', '?')}  ")
    lines.append(f"**project_name:** {session.get('project_name', '?')}")
    lines.append("")

    if verdict:
        lines.append("## Verdict")
        for k in ("verdict", "family_guess", "confidence", "agreement", "numeric_score", "cross_engine_notes"):
            v = verdict.get(k)
            if v not in (None, ""):
                lines.append(f"- **{k}**: {v}")
        lines.append("")

    lines.append("## Malcat Structured Analysis")
    lines.append(format_malcat_evidence(malcat_result))
    lines.append("")

    capa = tools_results.get("capa") or {}
    if capa:
        lines.append("## capa Capability Rules")
        rules = capa.get("top_rules") or []
        lines.append(f"Total rules: {capa.get('rule_count', len(rules))}")
        lines.append("")
        lines.append("| Rule | ATT&CK | MBC |")
        lines.append("|---|---|---|")
        for r in rules[:20]:
            if isinstance(r, dict):
                attack = ", ".join(r.get("attack") or [])[:40]
                mbc = ", ".join(r.get("mbc") or [])[:40]
                lines.append(f"| {r.get('name', '?')} | {attack} | {mbc} |")
        lines.append("")

    yara = tools_results.get("yara") or {}
    if yara and yara.get("matches"):
        lines.append("## YARA Matches")
        matches = yara.get("matches") or []
        lines.append(f"Total matches: {yara.get('rule_count', len(matches))}")
        lines.append("")
        lines.append("| Rule | Namespace | Strings |")
        lines.append("|---|---|---|")
        for m in matches[:15]:
            if isinstance(m, dict):
                lines.append(f"| {m.get('rule', '?')} | {m.get('namespace', '?')} | {m.get('strings', '?')} |")
        lines.append("")

    floss = tools_results.get("floss") or {}
    if floss and floss.get("strings"):
        lines.append("## FLOSS Strings")
        strings = floss.get("strings") or []
        lines.append(f"Total strings: {floss.get('string_count', len(strings))}")
        lines.append("")
        for s in strings[:10]:
            if isinstance(s, dict):
                lines.append(f"- `{s.get('string', s.get('value', '?'))}` (type: {s.get('type', '?')})")
        lines.append("")

    if dotnet_result and dotnet_result.get("is_dotnet"):
        lines.append("## .NET Analysis")
        lines.append(f"- runtime: {dotnet_result.get('runtime_version', '?')}")
        lines.append(f"- module: {dotnet_result.get('module_name', '?')}")
        lines.append(f"- language: {dotnet_result.get('language_hint', '?')}")
        if dotnet_result.get("suspicious_native_refs"):
            lines.append(f"- native_refs: {dotnet_result['suspicious_native_refs']}")
        if dotnet_result.get("pinvoke_imports"):
            lines.append(f"- pinvoke: {dotnet_result['pinvoke_imports'][:15]}")
        if dotnet_result.get("has_suppress_ildasm"):
            lines.append("- ⚠ SuppressIldasmAttribute present")
        lines.append("")

    if r2_decomp and r2_decomp.get("disassembly"):
        lines.append("## radare2 Disassembly")
        for addr, body in list(r2_decomp["disassembly"].items())[:3]:
            lines.append(f"### {addr}")
            lines.append("```asm")
            lines.append(str(body)[:2000])
            lines.append("```")
        lines.append("")

    if r2_ai and r2_ai.get("explanations"):
        lines.append("## r2ai / decai Explanations")
        for addr, body in list(r2_ai["explanations"].items())[:2]:
            lines.append(f"### {addr}")
            lines.append(str(body)[:2000])
        lines.append("")

    if upx:
        lines.append("## UPX Unpack")
        lines.append(json.dumps(upx, indent=2, default=str)[:1500])
        lines.append("")

    if xor_hits:
        lines.append("## XOR Search")
        lines.append(json.dumps(xor_hits, indent=2, default=str)[:1500])
        lines.append("")

    if olevba:
        lines.append("## olevba")
        lines.append(json.dumps(olevba, indent=2, default=str)[:2000])
        lines.append("")

    if peepdf:
        lines.append("## peepdf")
        lines.append(json.dumps(peepdf, indent=2, default=str)[:2000])
        lines.append("")

    if frida_trace and frida_trace.get("frida_stdout"):
        lines.append("## Frida Trace")
        lines.append("```")
        lines.append((frida_trace.get("frida_stdout") or "")[:2000])
        lines.append("```")
        lines.append("")

    if audit:
        lines.append("## Audit Trail")
        for entry in audit[-20:]:
            slim = {k: entry[k] for k in ("source", "sql", "phase", "ts") if k in entry}
            lines.append(json.dumps(slim))
        lines.append("")

    if rag_block:
        lines.append("## Threat-Intel Context (RAG)")
        lines.append(rag_block)
        lines.append("")

    return "\n".join(lines)


# ============================================================================
# Section-based report publisher (industry pattern: Map-Reduce)
# ============================================================================
# Each section has:
#   - description: what this section covers (for the LLM)
#   - query_terms: terms used to retrieve relevant RAG hits
#   - gather_evidence(tools_results): filters tool data into the section's evidence
#   - prompt_template: focused prompt for this section (small, ~1-3K chars)
#   - output_format: expected JSON shape
#   - requires_llm: whether to call LLM (False for sections we build locally)
# This pattern is from:
#   - Anthropic context engineering: chunked generation > one mega-prompt
#   - LangChain Map-Reduce documents chain
#   - Microsoft "Divide-and-Conquer Summarization" (Liu 2023)
#   - HuggingFace production RAG: per-query focused retrieval + LLM
#   - Wisdm framework (Microsoft Research 2024): section-aware RAG
#   - LangGraph Map-Reduce agent: explicit per-section state


def _sec_identity_evidence(tools_results: dict) -> str:
    """Section 1: Sample Identification — sha256, file size, format."""
    fs = (tools_results.get("malcat", {}) or {}).get("file_summary") or {}
    if not fs:
        return "(no MalCat file summary available)"
    lines = [f"  path: {tools_results.get('sample_path', '?')}"]
    for k in ("md5", "sha1", "sha256", "size", "format", "type",
              "architecture", "compiler", "linker", "entrypoint",
              "subsystem", "is_dll", "is_driver", "is_packed",
              "entropy", "dos_name", "overlay_size"):
        if k in fs and fs[k] not in (None, "", 0, False):
            v = fs[k]
            if isinstance(v, (bytes, bytearray)):
                v = v.decode("ascii", errors="ignore").rstrip("\x00")
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


def _sec_classification_evidence(tools_results: dict) -> str:
    """Section 2: Classification — family, verdict, confidence."""
    verdict = tools_results.get("verdict") or {}
    deep = tools_results.get("deep") or {}
    lines = []
    if verdict:
        lines.append(f"  verdict: {verdict.get('verdict', '?')}")
        lines.append(f"  family_guess: {verdict.get('family_guess', '?')}")
        lines.append(f"  agreement: {verdict.get('agreement', '?')}")
        lines.append(f"  v1_summary: {verdict.get('v1_summary', {})}")
    if deep:
        lines.append(f"  deep_confidence: {deep.get('confidence', '?')}")
        lines.append(f"  deep_source: {deep.get('source', '?')}")
    return "\n".join(lines) if lines else "(no verdict available)"


def _sec_triage_evidence(tools_results: dict) -> str:
    """Section 3: Initial Triage — capa rules + YARA + floss sample."""
    lines = []
    capa = tools_results.get("capa") or {}
    if capa:
        rules = capa.get("top_rules") or []
        if rules:
            lines.append(f"  capa ({capa.get('rule_count', len(rules))} rules):")
            for r in rules[:8]:
                if isinstance(r, dict):
                    lines.append(f"    - {r.get('name', '?')}")
    yara = tools_results.get("yara") or {}
    if yara:
        matches = yara.get("matches") or []
        if matches:
            lines.append(f"  YARA ({len(matches)} matches):")
            for m in matches[:5]:
                if isinstance(m, dict):
                    lines.append(f"    - {m.get('rule', '?')}")
    floss = tools_results.get("floss") or {}
    if floss:
        sc = floss.get("string_count", 0)
        lines.append(f"  FLOSS: {sc} strings extracted")
    return "\n".join(lines) if lines else "(no triage data)"


def _sec_static_evidence(tools_results: dict) -> str:
    """Section 4: Static Analysis — malcat cards + dotnet + r2 decompilations."""
    lines = []
    # MalCat top decompilations (real malware code)
    mc = tools_results.get("malcat") or {}
    decs = mc.get("decompilations") or {}
    if decs:
        lines.append("  Function decompilations (MalCat):")
        for addr, info in list(decs.items())[:2]:
            if isinstance(info, dict):
                nm = info.get("name", "?")
                body = (info.get("decompilation") or "").strip()[:1500]
                lines.append(f"    ### {addr} ({nm})")
                lines.append("```c")
                lines.append(body)
                lines.append("```")
    # MalCat structures
    structs = mc.get("structures") or []
    if structs:
        names = [s.get("name", s.get("struct_name", "?")) if isinstance(s, dict) else str(s) for s in structs[:20]]
        lines.append(f"  Recovered structures ({len(structs)}): {', '.join(names)}")
    # .NET
    dotnet = tools_results.get("dotnet") or {}
    if isinstance(dotnet, dict) and dotnet.get("is_dotnet"):
        lines.append("  .NET analysis:")
        lines.append(f"    language: {dotnet.get('language_hint', '?')}")
        lines.append(f"    runtime: {dotnet.get('runtime_version', '?')}")
        lines.append(f"    module: {dotnet.get('module_name', '?')}")
        if dotnet.get("suspicious_native_refs"):
            lines.append(f"    ⚠ native_refs: {dotnet['suspicious_native_refs']}")
        if dotnet.get("pinvoke_imports"):
            lines.append(f"    P/Invoke: {dotnet['pinvoke_imports'][:15]}")
        if dotnet.get("has_suppress_ildasm"):
            lines.append("    ⚠ SuppressIldasmAttribute")
    # r2 disassembly (3 functions)
    r2 = tools_results.get("r2_decomp") or {}
    if r2.get("disassembly"):
        lines.append("  radare2 disassembly:")
        for addr, body in list(r2["disassembly"].items())[:2]:
            lines.append(f"    {addr}: {str(body)[:300]}")
    return "\n".join(lines) if lines else "(no static analysis data)"


def _sec_behavioral_evidence(tools_results: dict) -> str:
    """Section 5: Behavioral — speakeasy + frida + malcat anomalies."""
    lines = []
    deep = tools_results.get("deep") or {}
    behavioral = deep.get("behavioral") or {}
    se = behavioral.get("speakeasy") or {}
    if se:
        lines.append(f"  Speakeasy: {se.get('total_api_calls', '?')} API calls")
        for api in (se.get('api_calls') or [])[:5]:
            if isinstance(api, dict):
                lines.append(f"    - {api.get('dll', '?')}.{api.get('name', '?')}: {api.get('count', 0)} calls")
    fp = behavioral.get("frida_probe") or {}
    if fp:
        lines.append(f"  Frida probe: {len(fp.get('hooked_calls', []))} hooked calls")
    mc = tools_results.get("malcat") or {}
    anoms = mc.get("anomalies") or []
    if anoms:
        lines.append(f"  MalCat anomalies ({len(anoms)}):")
        for a in anoms[:10]:
            if isinstance(a, dict):
                name = a.get("name", "?")
                num = a.get("num_hits", 0)
                lines.append(f"    - {name}×{num}" if num > 1 else f"    - {name}")
    return "\n".join(lines) if lines else "(no behavioral data)"


def _sec_network_evidence(tools_results: dict) -> str:
    """Section 6: Network — URLs, IPs, mutexes, sockets."""
    lines = []
    mc = tools_results.get("malcat") or {}
    consts = mc.get("constants") or []
    url_c, ip_c, mutex_c, port_c = [], [], [], []
    for c in consts:
        if not isinstance(c, dict):
            continue
        cat = str(c.get("category", "")).lower()
        cid = str(c.get("id", ""))
        if "url" in cat or cid.startswith("http"):
            url_c.append(cid)
        elif "ip" in cat or "ip_port" in cat:
            ip_c.append(cid)
        elif "mutex" in cat:
            mutex_c.append(cid)
    if url_c:
        lines.append(f"  ⚠ URLs in code: {', '.join(url_c[:10])}")
    if ip_c:
        lines.append(f"  ⚠ IPs in code: {', '.join(ip_c[:10])}")
    if mutex_c:
        lines.append(f"  Mutexes: {', '.join(mutex_c[:5])}")
    # Also check floss/malcat strings for URLs
    strings = (mc.get("views") or {}).get("strings") or []
    seen_urls = set()
    for s in strings[:200]:
        if not isinstance(s, dict):
            continue
        summary = str(s.get("summary") or "")
        if "http" in summary.lower():
            seen_urls.add(summary.strip())
    if seen_urls:
        lines.append(f"  String URLs: {', '.join(list(seen_urls)[:10])}")
    return "\n".join(lines) if lines else "(no network indicators)"


def _sec_capability_evidence(tools_results: dict) -> str:
    """Section 7: Capability — what the malware can do."""
    lines = []
    # High-signal imports = capabilities
    mc = tools_results.get("malcat") or {}
    imps = (mc.get("views") or {}).get("imports") or []
    if isinstance(imps, list):
        for imp in imps[:50]:
            if isinstance(imp, dict) and imp.get("type") == "IMPORT":
                name = imp.get("name", "")
                if name and "." in name:
                    sc = _score_api(name)
                    if sc >= 8:
                        lines.append(f"  [{sc}] {name}")
    # capa rules = capabilities
    capa = tools_results.get("capa") or {}
    rules = capa.get("top_rules") or []
    if rules:
        lines.append(f"  capa capabilities ({len(rules)}):")
        for r in rules[:15]:
            if isinstance(r, dict):
                lines.append(f"    - {r.get('name', '?')}")
    return "\n".join(lines) if lines else "(no capability data)"


def _sec_attack_evidence(tools_results: dict) -> str:
    """Section 8: MITRE ATT&CK — techniques observed."""
    lines = []
    capa = tools_results.get("capa") or {}
    rules = capa.get("top_rules") or []
    by_attack: dict = {}
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = r.get("name", "?")
        attack = r.get("attack") or []
        if isinstance(attack, list) and attack:
            for a in attack:
                by_attack.setdefault(str(a), []).append(name)
    if by_attack:
        for atk, names in sorted(by_attack.items(), key=lambda x: -len(x[1]))[:15]:
            lines.append(f"  {atk} ({len(names)}): {', '.join(names[:5])}")
    return "\n".join(lines) if lines else "(no ATT&CK mapping)"


def _sec_family_evidence(tools_results: dict) -> str:
    """Section 9: Family comparison — RAG-driven."""
    verdict = tools_results.get("verdict") or {}
    return f"  family_guess: {verdict.get('family_guess', '?')}\n  verdict: {verdict.get('verdict', '?')}\n  cross_engine_notes: {verdict.get('cross_engine_notes', '?')}"


def _sec_attribution_evidence(tools_results: dict) -> str:
    """Section 10: Attribution — threat actor / campaign."""
    verdict = tools_results.get("verdict") or {}
    return f"  family: {verdict.get('family_guess', '?')}\n  (use RAG to search for actor + campaign intel)"


def _sec_iocs_evidence(tools_results: dict) -> str:
    """Section 11: IOCs — all indicators in one place."""
    lines = []
    mc = tools_results.get("malcat") or {}
    consts = mc.get("constants") or []
    seen = set()
    for c in consts:
        if not isinstance(c, dict):
            continue
        cat = str(c.get("category", "")).lower()
        cid = str(c.get("id", ""))
        if cid and cid not in seen:
            seen.add(cid)
            lines.append(f"  [{cat}] {cid}")
    # file hashes
    fs = mc.get("file_summary") or {}
    for h in ("md5", "sha1", "sha256"):
        if h in fs:
            lines.append(f"  hash.{h}: {fs[h]}")
    return "\n".join(lines[:40]) if lines else "(no IOCs)"


def _sec_detection_evidence(tools_results: dict) -> str:
    """Section 12: Detection rules — YARA + suggestions."""
    yara = tools_results.get("yara") or {}
    matches = yara.get("matches") or []
    lines = []
    if matches:
        lines.append(f"  Active YARA matches ({len(matches)}):")
        for m in matches[:10]:
            if isinstance(m, dict):
                rule = m.get("rule", "?")
                lines.append(f"    - {rule}")
    return "\n".join(lines) if lines else "(no detection rules)"


def _sec_containment_evidence(tools_results: dict) -> str:
    """Section 13: Containment — based on file paths, mutexes, registry."""
    mc = tools_results.get("malcat") or {}
    consts = mc.get("constants") or []
    lines = []
    seen = set()
    for c in consts:
        if not isinstance(c, dict):
            continue
        cat = str(c.get("category", ""))
        cid = str(c.get("id", ""))
        if cid in seen:
            continue
        if cat in ("filename", "path", "service", "registry", "mutex"):
            seen.add(cid)
            lines.append(f"  [{cat}] {cid}")
    return "\n".join(lines[:30]) if lines else "(no containment signals)"


def _sec_recommendations_evidence(tools_results: dict) -> str:
    """Section 14: Recommendations — strategic."""
    verdict = tools_results.get("verdict") or {}
    return f"  family: {verdict.get('family_guess', '?')}\n  (recommend prioritized actions for this family)"


# Section specs: name → (description, query_terms, gather_fn, requires_llm)
REPORT_SECTION_SPECS = {
    "Executive Summary": (
        "Top-line verdict: malicious/clean, family, confidence, and a 2-sentence summary.",
        ["verdict", "family", "ransomware", "trojan", "backdoor", "rat", "stealer"],
        _sec_classification_evidence, True,
    ),
    "1. Sample Identification": (
        "Sample identifiers: sha256, file size, format, type, architecture, hashes.",
        ["file", "sha256", "md5", "size", "type"],
        _sec_identity_evidence, True,
    ),
    "2. Classification": (
        "Verdict + family + confidence + agreement + cross-engine notes.",
        ["family", "verdict", "classification"],
        _sec_classification_evidence, True,
    ),
    "3. Initial Triage (15 minutes)": (
        "What an analyst can determine in 15 min: capa rules, YARA matches, FLOSS highlights.",
        ["triage", "yara", "capa", "quick"],
        _sec_triage_evidence, True,
    ),
    "4. Static Analysis": (
        "PE structure, sections, decompilations, .NET analysis, imports, signatures.",
        ["static analysis", "pe structure", "imports", "sections", "dotnet"],
        _sec_static_evidence, True,
    ),
    "5. Behavioral Analysis": (
        "Runtime behavior from Speakeasy + Frida probe + MalCat anomalies.",
        ["behavioral analysis", "speakeasy", "frida", "anomalies"],
        _sec_behavioral_evidence, True,
    ),
    "6. Network Analysis": (
        "C2 indicators: URLs, IPs, mutexes, sockets, DNS.",
        ["network indicators", "c2", "url", "ip", "mutex", "socket"],
        _sec_network_evidence, True,
    ),
    "7. Capability Assessment": (
        "What the malware can do: encryption, network, persistence, anti-analysis.",
        ["capability", "encryption", "persistence", "anti-analysis", "evasion"],
        _sec_capability_evidence, True,
    ),
    "8. MITRE ATT&CK Mapping": (
        "Specific MITRE ATT&CK techniques observed (T-codes with rule names).",
        ["mitre", "attack", "technique", "t1059", "t1486", "t1055"],
        _sec_attack_evidence, True,
    ),
    "9. Comparison with Known Families": (
        "Which known family this matches; variant analysis; references.",
        ["family", "variant", "comparison", "known sample"],
        _sec_family_evidence, True,
    ),
    "10. Attribution": (
        "Threat actor, campaign, suspected origin (RAG-driven).",
        ["attribution", "threat actor", "campaign", "apt"],
        _sec_attribution_evidence, True,
    ),
    "11. Indicators of Compromise": (
        "All IOCs: hashes, IPs, URLs, mutexes, registry keys, file paths.",
        ["ioc", "indicator", "hash", "ip", "url", "mutex", "registry", "filename"],
        _sec_iocs_evidence, True,
    ),
    "12. Detection Rules": (
        "YARA rules that match + suggested Sigma/Snort rules for detection.",
        ["detection", "yara", "sigma", "snort", "rule"],
        _sec_detection_evidence, True,
    ),
    "13. Containment, Eradication, Recovery": (
        "IR steps based on observed file paths, mutexes, registry keys, services.",
        ["containment", "eradication", "recovery", "incident response", "playbook"],
        _sec_containment_evidence, True,
    ),
    "14. Recommendations": (
        "Strategic guidance: patch priorities, monitoring, training.",
        ["recommendation", "best practice", "prevention", "hygiene"],
        _sec_recommendations_evidence, True,
    ),
    "15. Appendices": (
        "Raw tool output for transparency + learning.",
        [], lambda x: "", False,
    ),
    "16. Author + Sign-off": (
        "Metadata: timestamps, analyst, model, sources. No LLM call needed.",
        [], lambda x: "", False,
    ),
}
SANDBOX_WRAPPER = Path("/opt/scripts/run_agent_sandbox.sh")


def speakeasy_emulate(sample_path: str, timeout: int = SPEAKEASY_TIMEOUT) -> dict:
    """Windows PE emulation without VM detonation (Mandiant Speakeasy)."""
    out: dict[str, Any] = {"speakeasy_ok": False, "sample": sample_path}
    # Real Speakeasy API is load_module() + run_module() + get_json_report().
    # Old code called se.run_binary() which was removed in speakeasy 3.x.
    # Also: speakeasy depends on unicorn which on Python 3.12 needs distutils
    # (removed in 3.12+). Detect this and report cleanly.
    script = f"""
import json
from pathlib import Path
p = Path({sample_path!r})
if not p.is_file():
    print(json.dumps({{"speakeasy_ok": False, "error": "file missing"}}))
    raise SystemExit(0)
try:
    from speakeasy import Speakeasy
    se = Speakeasy()
    module = se.load_module(str(p))
    se.run_module(module)
    report = se.get_json_report()
    if not isinstance(report, dict):
        report = {{"raw": str(report)[:4000]}}
    summary = {{
        "speakeasy_ok": True,
        "module_base": report.get("module_base"),
        "entry_point": report.get("entry_point"),
        "key_events": (report.get("key_events") or [])[:20],
        "api_calls": (report.get("api_calls") or [])[:20],
        "strings": (report.get("strings") or [])[:20],
    }}
    print(json.dumps(summary, default=str)[:8000])
except ModuleNotFoundError as e:
    # Python 3.12+ removed distutils; unicorn/speakeasy need it.
    print(json.dumps({{
        "speakeasy_ok": False,
        "error": f"module not found: {{e}}",
        "hint": "install setuptools<81 or python3-distutils; speakeasy is unsupported on Python 3.12+"
    }}))
except Exception as e:
    print(json.dumps({{"speakeasy_ok": False, "error": str(e)[:500]}}))
"""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.stdout.strip():
            try:
                parsed = json.loads(proc.stdout.strip().splitlines()[-1])
                out.update(parsed)
            except json.JSONDecodeError:
                out["stdout"] = proc.stdout[:2000]
        if proc.stderr:
            out["stderr"] = proc.stderr[:500]
        out["speakeasy_ok"] = out.get("speakeasy_ok", proc.returncode == 0)
    except subprocess.TimeoutExpired:
        out["error"] = "speakeasy: timeout"
    except Exception as e:
        out["error"] = str(e)
    return out


def frida_static_probe(sample_path: str) -> dict:
    """Lightweight Frida availability + PE import probe (no live injection)."""
    out: dict[str, Any] = {"frida_available": False}
    try:
        proc = subprocess.run(
            ["frida-ps", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        out["frida_available"] = proc.returncode == 0
        out["frida_version"] = (proc.stdout or proc.stderr).strip()[:80]
    except FileNotFoundError:
        out["error"] = "frida-tools not installed"
        return out
    except Exception as e:
        out["error"] = str(e)
        return out

    script = f"""
import json
from pathlib import Path
p = Path({sample_path!r})
info = {{"path": str(p), "exists": p.is_file()}}
if p.suffix.lower() in (".exe", ".dll", "") and p.is_file():
    try:
        import pefile
        pe = pefile.PE(str(p), fast_load=True)
        pe.parse_data_directories()
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:12]:
                dll = entry.dll.decode(errors="replace")
                for imp in entry.imports[:5]:
                    if imp.name:
                        imports.append(f"{{dll}}!{{imp.name.decode(errors='replace')}}")
        info["hook_candidates"] = imports[:30]
    except Exception as e:
        info["pe_error"] = str(e)[:200]
print(json.dumps(info))
"""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.stdout.strip():
            out["pe_probe"] = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as e:
        out["pe_probe_error"] = str(e)
    return out


def hitl_checkpoint(agent: str, step: str, payload: dict, auto_approve: bool | None = None) -> dict:
    """
  HITL gate — writes /tmp/cadre-hitl/<agent>-<step>.json and (when
  CADRE_HITL_WAIT=1) polls until a human flips `approved` to true.

  Env vars:
    CADRE_HITL_WAIT=1      pause for human review before returning
    CADRE_HITL_TIMEOUT=N    fail-safe timeout in seconds (default 3600)
    CADRE_HITL_AUTO=1      force auto-approve (overrides CADRE_HITL_WAIT)

  Behavior:
    - CADRE_HITL_WAIT=1 + CADRE_HITL_AUTO unset: write `approved: False`,
      poll every 2s for `approved: True`, raise TimeoutError on expiry.
    - CADRE_HITL_AUTO=1 (or env unset): write `approved: True`, return
      immediately (fire-and-forget checkpoint for audit only).
    - The `auto_approve` arg defaults to None and is overridden by
      CADRE_HITL_AUTO/CADRE_HITL_WAIT. Pass True/False explicitly to
      force override either way (useful for tests).
  """
    HITL_DIR.mkdir(parents=True, exist_ok=True)
    path = HITL_DIR / f"{agent}-{step}.json"

    wait = os.environ.get("CADRE_HITL_WAIT") == "1"
    auto = os.environ.get("CADRE_HITL_AUTO") == "1"

    if auto_approve is None:
        approved = auto or (not wait)
    else:
        approved = auto_approve

    record = {
        "agent": agent,
        "step": step,
        "ts": time.time(),
        "payload": payload,
        "approved": bool(approved),
        "wait_mode": wait,
        "auto_mode": auto,
    }
    path.write_text(json.dumps(record, indent=2))

    if wait and not auto:
        deadline = time.time() + int(os.environ.get("CADRE_HITL_TIMEOUT", "3600"))
        while time.time() < deadline:
            try:
                data = json.loads(path.read_text())
                if data.get("approved"):
                    return data
            except Exception:
                pass
            time.sleep(2)
        raise TimeoutError(f"HITL timeout waiting for approval: {path}")
    return record


def agentic_recover(sha256: str, pro: bool = False, dry_run: bool = False,
                    no_writeback: bool = False) -> dict:
    """Run the v4 agentic function-recovery stage for `sha256`.

    The stage is gated by ENABLE_AGENTIC_RECOVERY=1. If disabled, this
    returns immediately with {'skipped': True}.

    Returns the parsed function_recovery.json dict, or a fallback dict
    with 'skipped' / 'error' on failure.
    """
    if os.environ.get("ENABLE_AGENTIC_RECOVERY", "0") != "1":
        return {"skipped": True, "reason": "ENABLE_AGENTIC_RECOVERY is not set"}
    script = Path("/opt/cadre-v4-tools/agentic_recover_v4.py")
    if not script.is_file():
        return {"skipped": True, "reason": f"{script} not found"}
    cmd = [sys.executable, str(script), sha256]
    if pro:
        cmd.append("--pro")
    if dry_run:
        cmd.append("--dry-run")
    if no_writeback:
        cmd.append("--no-writeback")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if proc.returncode != 0:
            return {
                "skipped": True,
                "reason": "agentic_recover_v4 returned non-zero",
                "stderr": proc.stderr[-500:],
                "stdout": proc.stdout[-500:],
            }
        recovery_path = Path(f"/opt/samples/logs/{sha256}/function_recovery.json")
        if recovery_path.is_file():
            return json.loads(recovery_path.read_text())
        return {
            "skipped": True,
            "reason": "function_recovery.json not produced",
            "stdout_tail": proc.stdout[-500:],
        }
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "agentic_recover_v4 timed out after 3600s"}
    except Exception as e:
        return {"skipped": True, "reason": f"{type(e).__name__}: {e}"}


def run_sandboxed(argv: list[str], use_sandbox: bool | None = None) -> None:
    """Run agent via bwrap when CADRE_USE_SANDBOX=1 or use_sandbox=True."""
    if use_sandbox is None:
        use_sandbox = os.environ.get("CADRE_USE_SANDBOX", "1") == "1"
    if use_sandbox and SANDBOX_WRAPPER.is_file():
        subprocess.check_call(["bash", str(SANDBOX_WRAPPER), *argv])
    else:
        subprocess.check_call([sys.executable, *argv])


def goodware_fp_scan(yar_path: Path, goodware_dir: Path | None = None) -> dict:
    """Scan generated YARA rule against goodware corpus; flag if any match."""
    gw = goodware_dir or GOODWARE_DIR
    out: dict[str, Any] = {"goodware_dir": str(gw), "fp_count": 0, "fp_samples": []}
    if not yar_path.is_file():
        out["error"] = "missing rule"
        return out
    if not gw.is_dir():
        out["skipped"] = "goodware corpus not staged"
        return out
    try:
        proc = subprocess.run(
            ["yr", "scan", "--output-format", "ndjson", str(yar_path), str(gw)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        for line in (proc.stdout or "").splitlines():
            if not line.strip().startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("rules"):
                out["fp_count"] += 1
                out["fp_samples"].append(obj.get("path", "?"))
                if len(out["fp_samples"]) >= 10:
                    break
    except FileNotFoundError:
        out["error"] = "yara-x (yr) not installed"
    except Exception as e:
        out["error"] = str(e)
    return out


def yara_rule_validate(yar_path: Path) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["yara-x", "check", str(yar_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0:
            return True, "ok"
        return False, (proc.stderr or proc.stdout or "check failed")[:200]
    except FileNotFoundError:
        return True, "yara-x check skipped (not installed)"
    except Exception as e:
        return False, str(e)


GOODWARE_DIR = Path("/opt/samples/goodware")


def _sha256_of(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_known_goodware(sample_path: str | Path) -> tuple[bool, str | None]:
    """Return (True, name) if sample_path's sha256 matches a staged goodware
    fingerprint under /opt/samples/goodware/<sha256>.json with key 'name'.

    Used by quick_scan_v2 to short-circuit on legitimate utility software
    (busybox, openssl, system DLLs) and avoid LLM false-positives.
    """
    try:
        sha = _sha256_of(sample_path)
    except (OSError, FileNotFoundError):
        return False, None
    fp_path = GOODWARE_DIR / f"{sha}.json"
    if not fp_path.is_file():
        return False, None
    try:
        data = json.loads(fp_path.read_text())
    except (OSError, json.JSONDecodeError):
        return False, None
    name = data.get("name") if isinstance(data, dict) else None
    if not name:
        return False, None
    return True, name



def dotnet_analyze(sample_path: str, il_max_lines: int = 275) -> dict:
    """Analyze a .NET (Mono/CoreCLR) assembly: runtime, language, P/Invoke, anti-RE markers.

    Uses dnfile (Python dnlib port) for PE/CLI header metadata and monodis for IL
    disassembly. Returns a dict with is_dotnet, runtime_version, assembly_name,
    module_name, language_hint, external_assembly_refs, suspicious_native_refs,
    suspicious_methods, interesting_pinvoke, has_suppress_ildasm,
    shellcode_embed_hint, il_total_lines, il_excerpt. Fail-safe: returns
    is_dotnet=False on any non-PE / non-CLI file.
    """
    import os, subprocess
    out: dict = {
        "is_dotnet": False,
        "runtime_version": None,
        "assembly_name": None,
        "module_name": None,
        "language_hint": None,
        "external_assembly_refs": [],
        "suspicious_native_refs": [],
        "suspicious_methods": [],
        "interesting_pinvoke": [],
        "has_suppress_ildasm": False,
        "shellcode_embed_hint": False,
        "il_total_lines": 0,
        "il_excerpt": "",
    }
    if not sample_path or not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        import dnfile  # type: ignore
    except Exception:
        out["error"] = "dnfile not installed (pip install dnfile)"
        return out
    try:
        pe = dnfile.dnPE(sample_path)
    except Exception as e:
        out["error"] = f"dnfile open failed: {e}"
        return out
    if not pe.net or not getattr(pe.net, "metadata", None):
        return out
    out["is_dotnet"] = True
    md = pe.net.metadata
    try:
        if md.struct:
            # Version is a bytes string like b'v4.0.30319\x00\x00'
            ver = md.struct.Version
            if isinstance(ver, (bytes, bytearray)):
                out["runtime_version"] = ver.decode("ascii", errors="ignore").rstrip("\x00")
            else:
                out["runtime_version"] = str(ver)
    except Exception:
        pass
    # Access the #~ (MetaDataTables) stream for table rows
    tables_stream = None
    try:
        for s in md.streams_list:
            if s.struct.Name == b"#~":
                tables_stream = s
                break
    except Exception:
        pass
    if tables_stream is not None:
        try:
            mod_rows = tables_stream.Module.rows
            if mod_rows:
                name = getattr(mod_rows[0], "Name", None)
                if name:
                    if isinstance(name, (bytes, bytearray)):
                        name = name.decode("ascii", errors="ignore").rstrip("\x00")
                    out["module_name"] = str(name)
        except Exception:
            pass
        try:
            asmref_rows = tables_stream.AssemblyRef.rows
            for ref in asmref_rows:
                name = getattr(ref, "Name", None)
                if name:
                    if isinstance(name, (bytes, bytearray)):
                        name = name.decode("ascii", errors="ignore").rstrip("\x00")
                    name = str(name).strip()
                    if name:
                        out["external_assembly_refs"].append(name)
                        if "Microsoft.VisualBasic" in name:
                            out["language_hint"] = "VB.NET"
                        if out["language_hint"] is None and name.startswith("System"):
                            out["language_hint"] = "C#"
        except Exception:
            pass
        # P/Invoke: walk ImplMap rows (DllImport directives)
        # ImportScope is a ModuleRef table index; dereference to get the DLL name
        # Also collect ImportName (the function name) for full P/Invoke picture
        try:
            implmap_rows = tables_stream.ImplMap.rows
            moduleref_rows = tables_stream.ModuleRef.rows
            for im in implmap_rows[:50]:
                scope = getattr(im, "ImportScope", None)
                dll = None
                if scope is not None and hasattr(scope, "row_index"):
                    idx = scope.row_index
                    if 0 <= idx < len(moduleref_rows):
                        dll = getattr(moduleref_rows[idx], "Name", None)
                if dll:
                    if isinstance(dll, (bytes, bytearray)):
                        dll = dll.decode("ascii", errors="ignore").rstrip("\x00")
                    dll = str(dll).strip()
                    # only include if it looks like a DLL (ends in .dll) or has a path
                    if dll and (dll.lower().endswith(".dll") or "\\" in dll or "/" in dll):
                        if dll not in out["interesting_pinvoke"]:
                            out["interesting_pinvoke"].append(dll)
                # Also track the imported function name (ImportName)
                fn = getattr(im, "ImportName", None)
                if fn:
                    if isinstance(fn, (bytes, bytearray)):
                        fn = fn.decode("ascii", errors="ignore").rstrip("\x00")
                    fn = str(fn).strip()
                    if fn and "pinvoke_imports" not in out:
                        out["pinvoke_imports"] = []
                    if fn and fn not in out.get("pinvoke_imports", []):
                        out.setdefault("pinvoke_imports", []).append(fn)
        except Exception:
            pass
        # CustomAttribute scan for SuppressIldasmAttribute
        try:
            ca_rows = tables_stream.CustomAttribute.rows
            # TypeRef indices used by CAs - just check for SuppressIldasm string in member names
            typeref_rows = tables_stream.TypeRef.rows
            for tr in typeref_rows:
                tn = getattr(tr, "TypeName", None) or ""
                if isinstance(tn, (bytes, bytearray)):
                    tn = tn.decode("ascii", errors="ignore")
                if "SuppressIldasm" in str(tn):
                    out["has_suppress_ildasm"] = True
                    break
        except Exception:
            pass
    suspicious_native = {"avicap32", "winmm", "urlmon", "wininet", "ws2_32", "dnsapi"}
    try:
        with open(sample_path, "rb") as _f:
            raw = _f.read()
        for needle in suspicious_native:
            if needle.encode() in raw and needle not in out["suspicious_native_refs"]:
                out["suspicious_native_refs"].append(needle)
    except Exception:
        pass
    try:
        # monodis prints to stdout by default (no --output flag)
        r = subprocess.run(
            ["monodis", sample_path],
            capture_output=True, text=True, timeout=30,
        )
        il_text = r.stdout or ""
        out["il_total_lines"] = il_text.count("\n")
        if il_text:
            out["il_excerpt"] = "\n".join(il_text.splitlines()[:il_max_lines])
        if "ldc.i4" in il_text and "newarr" in il_text and any(
            tok in il_text for tok in ("InitializeArray", "stelem.i1", "stelem.i2", "stelem.i4")
        ):
            out["shellcode_embed_hint"] = True
        for needle in ("Download", "ShellExecute", "CreateRemote", "VirtualAlloc",
                       "WriteProcess", "Inject", "Keylog", "Persist", "Schedule",
                       "Capture", "Webcam", "Microphone", "Screenshot", "Steal",
                       "Decrypt", "Base64Decode", "Aes", "RC4", "RC2", "DES",
                       "HttpClient", "WebClient", "TcpClient", "UdpClient",
                       "Process", "Thread", "Mutex", "Registry", "Crypto",
                       "RegCreate", "RegSet", "RegDelete", "ServiceController",
                       "Assembly", "Reflection", "DynamicMethod", "InvokeMember",
                       "Async", "Task", "Socket", "Stream", "FileSystem"):
            if needle in il_text and needle not in out["suspicious_methods"]:
                out["suspicious_methods"].append(needle)
        for line in il_text.splitlines():
            s = line.strip()
            if s.startswith(".module") and "vba" in s.lower():
                if not out["language_hint"]:
                    out["language_hint"] = "VB.NET"
            if ("DllImport" in s or "DllImportAttribute" in s) and '"' in s:
                parts = s.split('"')
                if len(parts) >= 2 and parts[1] not in out["interesting_pinvoke"]:
                    out["interesting_pinvoke"].append(parts[1])
    except FileNotFoundError:
        out["monodis_warning"] = "monodis not on PATH (apt install mono-utils)"
    except Exception as e:
        out["monodis_error"] = f"monodis failed: {e}"
    return out



def upx_unpack(sample_path: str, timeout: int = 30) -> dict:
    """Detect and unpack UPX-packed binaries. Writes unpacked to .unpacked suffix."""
    import os, subprocess
    out: dict = {"upx_ok": False, "is_packed": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        probe = subprocess.run(["upx", "-t", sample_path], capture_output=True, text=True, timeout=timeout)
        is_packed = (probe.returncode == 0)
        out["is_packed"] = is_packed
        out["upx_probe_stdout"] = probe.stdout[:200]
        if not is_packed:
            return out
        unpacked = sample_path + ".unpacked"
        r = subprocess.run(
            ["upx", "-d", sample_path, "-o", unpacked], capture_output=True, text=True, timeout=timeout
        )
        out["upx_returncode"] = r.returncode
        out["upx_stdout"] = r.stdout[:500]
        out["upx_stderr"] = r.stderr[:500]
        if r.returncode == 0 and os.path.isfile(unpacked) and os.path.getsize(unpacked) > 0:
            out["unpacked_path"] = unpacked
            out["upx_ok"] = True
        return out
    except Exception as e:
        out["error"] = f"upx_unpack failed: {e}"
        return out


def xor_string_search(sample_path: str, max_results: int = 30) -> dict:
    """Find XOR/ROL/ROT/SHIFT/ADD encoded strings using xorsearch (Mandiant/FireEye).

    Uses -S to print all strings, -p for PE-aware decoding. -i means "ignore case"
    (not input file — the file path is the positional arg). Returns parsed candidates.
    """
    import os, subprocess
    out: dict = {"xorsearch_ok": False, "sample": sample_path, "candidates": []}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        r = subprocess.run(
            ["xorsearch", "-S", "-p", str(sample_path)],
            capture_output=True, text=True, timeout=60,
        )
        out["xorsearch_stdout"] = r.stdout[:3000]
        out["xorsearch_stderr"] = r.stderr[:200]
        out["xorsearch_returncode"] = r.returncode
        # Parse candidate lines (xorsearch output format: "Found \\xNN encoded string at offset ... : <text>")
        for line in (r.stdout or "").splitlines()[:max_results * 2]:
            if line.startswith("Found") or "encoded" in line.lower():
                stripped = line.strip()[:300]
                if stripped and stripped not in out["candidates"]:
                    out["candidates"].append(stripped)
                    if len(out["candidates"]) >= max_results:
                        break
        out["xorsearch_ok"] = (r.returncode == 0 and bool(out["candidates"]))
        return out
    except Exception as e:
        out["error"] = f"xorsearch failed: {e}"
        return out


def olevba_analyze(sample_path: str, timeout: int = 30) -> dict:
    """Extract VBA macros from Office documents (oletools/olevba)."""
    import os, subprocess
    out: dict = {"olevba_ok": False, "sample": sample_path, "is_office_doc": False, "macros": []}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        with open(sample_path, "rb") as f:
            magic = f.read(16)
        is_ole2 = magic[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        is_zip = magic[:4] == b"PK"
        out["is_ole2"] = is_ole2
        out["is_zip"] = is_zip
        if not (is_ole2 or is_zip):
            return out
        out["is_office_doc"] = True
        r = subprocess.run(
            ["olevba", "--decode", "-c", sample_path],
            capture_output=True, text=True, timeout=timeout
        )
        out["olevba_returncode"] = r.returncode
        out["olevba_stdout"] = r.stdout[:8000]
        out["olevba_stderr"] = r.stderr[:500]
        for line in r.stdout.splitlines()[:200]:
            if any(k in line.lower() for k in [
                "autoexec", "document_open", "auto_open", "shell",
                "createobject", "wscript", "powershell", "auto_", "document_"
            ]):
                if line.strip() and not line.startswith("+"):
                    out["macros"].append(line.strip()[:200])
        out["olevba_ok"] = (r.returncode == 0)
        return out
    except Exception as e:
        out["error"] = f"olevba failed: {e}"
        return out


def peepdf_analyze(sample_path: str, timeout: int = 30) -> dict:
    """Analyze PDF for malicious objects / JavaScript / embedded files."""
    import os, subprocess
    out: dict = {"peepdf_ok": False, "sample": sample_path, "is_pdf": False, "suspicious": []}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        with open(sample_path, "rb") as f:
            magic = f.read(5)
        if not magic.startswith(b"%PDF"):
            return out
        out["is_pdf"] = True
        r = subprocess.run(
            ["peepdf", "-f", sample_path], capture_output=True, text=True, timeout=timeout
        )
        out["peepdf_returncode"] = r.returncode
        out["peepdf_stdout"] = r.stdout[:6000]
        out["peepdf_stderr"] = r.stderr[:500]
        for line in r.stdout.splitlines()[:200]:
            ll = line.lower()
            if any(k in ll for k in [
                "/js", "javascript", "embeddedfile", "openaction", "uri",
                "launch", "action", "submitform", "xfa", "richmedia", "geticon"
            ]):
                if line.strip() and not line.startswith("PPDF"):
                    out["suspicious"].append(line.strip()[:200])
        out["peepdf_ok"] = (r.returncode == 0)
        return out
    except Exception as e:
        out["error"] = f"peepdf failed: {e}"
        return out


def r2_decompile(sample_path: str, function_addrs: list | None = None, timeout: int = 60) -> dict:
    """Disassemble functions using radare2 (asm-only, 2nd decompiler alongside Ghidra).

    Tries pdg (Ghidra decompiler plugin for r2) when available; otherwise falls back
    to pdf (asm tree). NOTE: output is asm text, not pseudo-C. Field is named
    `disassembly` (not `decompilations`) so downstream code does not mislabel it.
    One r2 invocation per function for clean output capture.
    """
    import os, subprocess
    out: dict = {"r2_ok": False, "sample": sample_path, "disassembly": {},
                 "engine": "pdf (disasm)", "fallback": True}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    # Auto-discover function addresses if not provided
    if not function_addrs:
        try:
            disc = subprocess.run(
                ["r2", "-q", "-c", "aaa; afl~[0,3]", sample_path],
                capture_output=True, text=True, timeout=30,
            )
            function_addrs = []
            for line in (disc.stdout or "").splitlines():
                line = line.strip()
                # r2 afl output: 0x401000  32  sub.foo
                parts = line.split()
                if parts and parts[0].startswith("0x"):
                    try:
                        int(parts[0], 16)
                        function_addrs.append(parts[0])
                    except ValueError:
                        pass
                if len(function_addrs) >= 5:
                    break
            if not function_addrs:
                out["error"] = "could not auto-discover function addresses"
                return out
        except Exception as e:
            out["error"] = f"function address discovery failed: {e}"
            return out
    # Probe for pdg (Ghidra decompiler plugin)
    pdg_available = False
    try:
        help_probe = subprocess.run(
            ["r2", "-h"], capture_output=True, text=True, timeout=10,
        )
        if "pdg" in (help_probe.stdout or "").lower():
            pdg_available = True
            out["engine"] = "pdg (Ghidra decompiler)"
            out["fallback"] = False
    except Exception:
        pass
    decomp_cmd = "pdg" if pdg_available else "pdf"
    try:
        for addr in function_addrs[:5]:
            r2_script = f"aa; s {addr}; af; {decomp_cmd} @ {addr}"
            cmd = ["r2", "-q", "-c", r2_script, sample_path]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                body = (r.stdout or "").strip()
                if body:
                    import re
                    body = re.sub(r"\x1b\[[0-9;]*m", "", body)
                    out["disassembly"][addr] = body[:3000]
            except subprocess.TimeoutExpired:
                out["disassembly"][addr] = f"r2 timeout ({timeout}s) for {addr}"
            except Exception as e:
                out["disassembly"][addr] = f"r2 error: {e}"
        out["r2_ok"] = bool(out["disassembly"])
        out["functions_attempted"] = function_addrs[:5]
        return out
    except Exception as e:
        out["error"] = f"r2_decompile failed: {e}"
        return out


def r2_ai_decompile(sample_path: str, function_addrs: list, ollama_url: str = "http://localhost:11434", timeout: int = 90) -> dict:
    """AI-assisted decompilation using r2ai / decai plugins (r2 with Ollama LLM)."""
    import os, subprocess
    out: dict = {"r2ai_ok": False, "sample": sample_path, "explanations": {}}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        r = None
        for addr in function_addrs[:2]:
            cmd = [
                "r2", "-q", "-A", "-c",
                f"pdg @{addr}; r2ai Explain this function in detail; q",
                sample_path
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.stdout.strip():
                out["explanations"][addr] = r.stdout[:3000]
        out["r2ai_ok"] = bool(out["explanations"])
        if not out["r2ai_ok"]:
            out["r2ai_stderr"] = (r.stderr[:500] if r and r.stderr else "")
        return out
    except Exception as e:
        out["error"] = f"r2_ai_decompile failed: {e}"
        return out


def frida_trace_runtime(sample_path: str, function_names: list | None = None, timeout: int = 60) -> dict:
    """Full Frida instrumentation: hook functions, trace API calls at runtime.

    When `function_names` is empty (the default in TOOL_MANIFEST), auto-discovers
    high-signal Windows API names from the PE import table using pefile. This
    fixes the "no function names to hook" failure that occurred on every sample.
    """
    import os, subprocess
    out: dict = {"frida_ok": False, "sample": sample_path, "traced": [], "api_calls": {}}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    # Auto-discover from PE imports if not provided
    if not function_names:
        try:
            import pefile
            pe = pefile.PE(sample_path, fast_load=True)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                names = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports[:200]:
                        if imp.name:
                            names.append(imp.name.decode("utf-8", "replace"))
                if not names:
                    out["skipped"] = "PE has no imports (packed or stripped); no hook targets"
                    out["frida_ok"] = False
                    return out
                # Prioritize high-signal APIs
                high_signal = ("CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
                               "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA",
                               "CreateProcessA", "CreateProcessW", "CreateServiceA",
                               "InternetOpenA", "InternetOpenUrlA", "WinHttpOpen",
                               "CryptEncrypt", "CryptDecrypt", "VirtualAlloc",
                               "VirtualProtect", "LoadLibraryA", "GetProcAddress",
                               "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA",
                               "IsDebuggerPresent", "NtCreateThreadEx")
                picked = [n for n in names if n in high_signal][:5]
                function_names = picked if picked else names[:5]
                out["auto_discovered"] = function_names
                out["total_imports"] = len(names)
            else:
                out["skipped"] = "PE has no DIRECTORY_ENTRY_IMPORT; cannot auto-discover"
                out["frida_ok"] = False
                return out
        except ImportError:
            out["error"] = "pefile not installed; cannot auto-discover function names"
            return out
        except Exception as e:
            out["error"] = f"auto-discover failed: {e}"
            return out
    if not function_names:
        out["skipped"] = "no hookable function names found"
        out["frida_ok"] = False
        return out
    try:
        hooks_js = "; ".join(
            f"Interceptor.attach(Module.findExportByName(null, '{fn}'), {{ onEnter: function(a) {{ send({{fn:'{fn}', args:a.length}}); }}, onLeave: function(r) {{ send({{fn:'{fn}', ret:r}}); }} }});"
            for fn in function_names[:5]
        )
        r = subprocess.run(
            ["frida", "-H", "127.0.0.1", "-f", sample_path,
             "-l", "/dev/stdin", "--runtime=v14", "-q"],
            input=hooks_js, capture_output=True, text=True, timeout=timeout
        )
        out["frida_stdout"] = r.stdout[:3000]
        out["frida_stderr"] = r.stderr[:500]
        out["frida_returncode"] = r.returncode
        out["frida_ok"] = (r.returncode == 0 and r.stdout.strip() != "")
        return out
    except Exception as e:
        out["error"] = f"frida_trace_runtime failed: {e}"
        return out


# ============================================================================
# Evidence card system — converts raw tool output into LLM-optimized cards
# ============================================================================
# Each tool exposes a `to_card(result, budget)` that produces a compact,
# signal-prioritized string representation. EvidenceAssembler orchestrates
# them under a total budget so we never blow the LLM context window.

# Windows API signal score (higher = more malware-relevant)
_API_SIGNAL_KEYWORDS = [
    # crypto (10)
    ("Crypt", 10), ("BCrypt", 10), ("AES", 10), ("RC4", 10), ("DES", 10),
    # network (9)
    ("Internet", 9), ("WinHttp", 9), ("URLDownload", 9), ("HttpSend", 9),
    ("WSAStartup", 9), ("connect", 8), ("send", 7), ("recv", 7),
    # process injection (10)
    ("CreateRemote", 10), ("WriteProcessMemory", 10), ("VirtualAllocEx", 10),
    ("NtUnmapViewOfSection", 10), ("QueueUserAPC", 9), ("SetThreadContext", 9),
    # persistence (9)
    ("RegCreateKey", 9), ("RegSetValue", 9), ("CreateService", 9),
    ("StartService", 8), ("CreateToolhelp32Snapshot", 8),
    # dynamic loading (6)
    ("LoadLibrary", 6), ("GetProcAddress", 6), ("GetModuleHandle", 5),
    # file I/O (5)
    ("CreateFile", 5), ("WriteFile", 4), ("DeleteFile", 6),
    # anti-debug (10)
    ("IsDebuggerPresent", 10), ("CheckRemoteDebuggerPresent", 10),
    ("NtQueryInformationProcess", 9), ("QueryPerformanceCounter", 7),
    # process (7)
    ("CreateProcess", 7), ("TerminateProcess", 7), ("OpenProcess", 7),
    ("CreateThread", 7),
    # registry (5)
    ("RegOpenKey", 5), ("RegCloseKey", 4), ("RegQueryValue", 5),
    # IPC (6)
    ("CreatePipe", 6), ("CreateNamedPipe", 6), ("DuplicateHandle", 5),
    # memory (4)
    ("VirtualAlloc", 8), ("VirtualProtect", 8), ("HeapAlloc", 3),
    # service / token (8)
    ("OpenSCManager", 8), ("AdjustTokenPrivileges", 8), ("LookupPrivilege", 8),
]

# String IOC categories
_URL_RE = __import__("re").compile(r"https?://[^\s\"']{4,200}")
_REG_RE = __import__("re").compile(r"(?:HK[EL]M|HKEY_[A-Z_]+|Software\\[A-Za-z0-9_. \\\\]+|CurrentControlSet\\[A-Za-z0-9_. \\\\]+)", __import__("re").IGNORECASE)
_MUTEX_RE = __import__("re").compile(r"(?:Global|Local|AppInit)\\[A-Za-z0-9_\\. -]{3,80}")
_IPV4_RE = __import__("re").compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FILEPATH_RE = __import__("re").compile(r"(?:[A-Z]:\\[A-Za-z0-9_. \\\\-]{3,80}|\\\\[A-Za-z0-9_.\\-]{3,80})")
_BASE64_RE = __import__("re").compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_SUSPICIOUS_KEYWORDS = ("powershell", "cmd.exe", "wscript", "cscript",
                        "rundll32", "regsvr32", "mshta", "bitsadmin",
                        "schtasks", "taskkill", "vssadmin", "wbadmin",
                        "bcdedit", "wevtutil", "net user", "net localgroup",
                        "winrm", "psexec", "wmic", "wmiprvse")


def _score_api(name: str) -> int:
    """Return signal score 0-10 for a Windows API name."""
    if not name:
        return 0
    n = name.lower()
    score = 0
    for kw, s in _API_SIGNAL_KEYWORDS:
        if kw.lower() in n:
            score = max(score, s)
    return score


def _categorize_string(s: str) -> str:
    """Return IOC category for a string, or 'misc'."""
    if not s or len(s) < 3:
        return "misc"
    if _URL_RE.search(s):
        return "urls"
    if _IPV4_RE.search(s):
        return "ips"
    # Registry keys (handle truncated "oftware\\..." too — sometimes stripped by binary loaders)
    if _REG_RE.search(s) or s.lower().startswith("oftware\\") or s.lower().startswith("software\\"):
        return "registry"
    if _MUTEX_RE.search(s) or s.startswith("Global\\") or s.startswith("Local\\"):
        return "mutex"
    if _FILEPATH_RE.search(s):
        return "paths"
    if _BASE64_RE.search(s):
        return "base64"
    # Windows API function names (CloseHandle, CreateProcessA, etc.) — high signal
    # Pattern: PascalCase or UpperCase with optional A/W suffix and version digits
    api_pat = __import__("re").compile(r"^[A-Z][a-z]+(?:[A-Z][a-z]+)+[AW]?$|^[A-Z]{4,}[0-9]?[AW]?$")
    if api_pat.match(s) and any(api in s for api in [
        "Handle", "Process", "Thread", "File", "Service", "Library", "Memory",
        "Alloc", "Protect", "Read", "Write", "Create", "Open", "Close",
        "Reg", "Crypt", "Socket", "Connect", "Send", "Recv", "Window",
        "Pipe", "Mutex", "Event", "Wait", "Signal", "Hook", "Query",
        "Set", "Get", "Load", "Free", "Call", "Exec", "Run", "Start",
        "Stop", "Delete", "Find", "Init", "Term", "Virtual",
    ]):
        return "apis"
    low = s.lower()
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in low:
            return "suspicious"
    return "misc"


def _malcat_to_card(result: dict) -> str:
    """Convert MalCat raw output → compact evidence card (uses full MCP toolset).

    Sections, in order: file_summary → anomalies (+locations for high-signal) →
    yara_hits → functions (top by score) → imports (top by signal) → constants
    (URLs/IPs/registry as code immediates) → strings (grouped IOCs) → carved
    files → virtual files → structures → decompilations → script_decompile →
    unpack_result → errors.
    """
    if not isinstance(result, dict) or result.get("error"):
        return f"## MalCat\n  error: {result.get('error', 'unknown')}\n"
    lines = ["## MalCat evidence"]
    fs = result.get("file_summary") or {}

    # 1. File summary
    if isinstance(fs, dict) and fs:
        keys_of_interest = ("format", "type", "architecture", "compiler", "linker",
                            "entrypoint", "subsystem", "is_dll", "is_driver",
                            "is_packed", "entropy", "size", "md5", "sha1", "sha256",
                            "dos_name", "overlay_size")
        parts = []
        for k in keys_of_interest:
            if k in fs and fs[k] not in (None, "", 0, False):
                v = fs[k]
                if isinstance(v, (bytes, bytearray)):
                    v = v.decode("ascii", errors="ignore").rstrip("\x00")
                parts.append(f"{k}={v}")
        if parts:
            lines.append(f"  File: {', '.join(parts[:15])}")

    # 2. Anomalies (curated + locations for high-signal)
    anomalies = result.get("anomalies") or result.get("views", {}).get("anomalies") or []
    if anomalies:
        items = []
        for a in anomalies:
            if not isinstance(a, dict):
                continue
            name = a.get("name", "?")
            num = a.get("num_hits", 0)
            cat = a.get("category", "")
            if num and num > 1:
                items.append(f"{name}×{num}" + (f" ({cat})" if cat else ""))
            else:
                items.append(name + (f" ({cat})" if cat else ""))
        lines.append(f"  Anomalies ({len(anomalies)}): {', '.join(items[:30])}")
        # Locations for high-signal anomalies (proves they're real)
        locs = result.get("views", {}).get("anomaly_locations") or {}
        if locs:
            loc_lines = []
            for anom_name, hits in list(locs.items())[:10]:
                if not isinstance(hits, list):
                    continue
                eas = [str(h.get("ea")) for h in hits[:3] if isinstance(h, dict) and h.get("ea")]
                if eas:
                    loc_lines.append(f"{anom_name}@{','.join(eas)}")
            if loc_lines:
                lines.append(f"  High-signal anomaly locations: {'; '.join(loc_lines)}")

    # 3. YARA matches (signal vs info)
    yh = result.get("views", {}).get("yara_hits") or []
    if isinstance(yh, list) and yh:
        sig = []
        info = []
        for y in yh:
            if not isinstance(y, dict):
                continue
            yid = y.get("id") or y.get("rule") or y.get("name") or "?"
            t = (y.get("type") or y.get("category") or "INFO").upper()
            if t in ("MALWARE", "SUSPICIOUS", "WARNING", "RAT", "BACKDOOR", "TROJAN",
                     "RANSOMWARE", "DOWNLOADER", "STEALER", "KEYLOGGER", "ROOTKIT"):
                sig.append(yid)
            else:
                info.append(yid)
        if sig:
            lines.append(f"  YARA (signal): {', '.join(sig[:20])}")
        if info:
            lines.append(f"  YARA (info, {len(info)} total): {', '.join(info[:10])}{'…' if len(info) > 10 else ''}")

    # 4. Functions (top by MalCat — note: fns_top_list doesn't return scores, so show top by size if available)
    functions = result.get("functions") or []
    if isinstance(functions, list) and functions:
        # Try to get size via fn_infos for the top 5
        annotated = []
        for f in functions[:15]:
            if not isinstance(f, dict):
                continue
            name = f.get("name") or "?"
            ea = f.get("ea") or f.get("address") or "?"
            sz = f.get("size") or 0
            annotated.append((sz, name, ea))
        # Sort by size desc (MalCat returns in some order; size is the best signal)
        annotated.sort(key=lambda x: -(x[0] or 0))
        if annotated:
            sample = [f"{n}@{ea} (size={sz})" for sz, n, ea in annotated[:15] if (sz or 0) > 0]
            if sample:
                lines.append(f"  Top functions by size: {', '.join(sample)}")
            else:
                lines.append(f"  Functions ({len(annotated)}): {', '.join(f'{n}@{ea}' for sz, n, ea in annotated[:15])}")

    # 5. Imports (top by signal score)
    imports = result.get("views", {}).get("imports") or []
    if isinstance(imports, list) and imports:
        scored = []
        for imp in imports:
            if not isinstance(imp, dict):
                continue
            if imp.get("type") and imp.get("type") != "IMPORT":
                continue
            name = imp.get("name", "")
            if not name or "." not in name:
                continue
            score = _score_api(name)
            scored.append((score, name, imp.get("num_refs", 0)))
        scored.sort(key=lambda x: (-x[0], -x[2], x[1]))
        total = len(scored)
        high = [s for s in scored if s[0] >= 8]
        mid = [s for s in scored if 5 <= s[0] < 8]
        if high:
            lines.append(f"  Top high-signal imports (score≥8, {len(high)} of {total}):")
            for sc, name, refs in high[:30]:
                ref_str = f" ×{refs}" if refs > 1 else ""
                lines.append(f"    [{sc}] {name}{ref_str}")
        if mid:
            names = ", ".join(n for _, n, _ in mid[:25])
            lines.append(f"  Mid-signal imports: {names}{'…' if len(mid) > 25 else ''}")
        if total > len(high) + len(mid):
            lines.append(f"  (low-signal/noise imports: {total - len(high) - len(mid)} omitted)")

    # 6. Constants (URLs / IPs / registry keys / crypto algorithms found as code immediates)
    constants = result.get("constants") or []
    if isinstance(constants, list) and constants:
        # Constants come as {id, category, type, num_hits} — group by category
        by_cat: dict = {}
        for c in constants:
            if not isinstance(c, dict):
                continue
            cid = c.get("id") or c.get("value") or c.get("constant") or ""
            cat = c.get("category") or "misc"
            if not cid:
                continue
            by_cat.setdefault(str(cat), []).append((str(cid), c.get("num_hits", 0) or 0))
        # Emit the high-signal categories first
        cat_order = ("registry", "crypto", "url", "ip", "ip_port", "mutex",
                     "filename", "process", "service", "pipe", "credential",
                     "interesting")
        for cat in cat_order:
            items = by_cat.get(cat)
            if not items:
                continue
            seen = set()
            dedup = []
            for v, nh in items:
                if v in seen:
                    continue
                seen.add(v)
                dedup.append(f"{v}×{nh}" if nh > 1 else v)
                if len(dedup) >= 12:
                    break
            icon = "⚠" if cat in ("registry", "crypto", "url", "ip", "ip_port",
                                    "mutex", "credential", "service") else "  "
            lines.append(f"  {icon} Constants/{cat} ({len(items)}): {', '.join(dedup)}")
        # Other categories
        for cat, items in by_cat.items():
            if cat in cat_order:
                continue
            seen = set()
            dedup = []
            for v, nh in items:
                if v in seen:
                    continue
                seen.add(v)
                dedup.append(v)
                if len(dedup) >= 8:
                    break
            if dedup:
                lines.append(f"    Constants/{cat} ({len(items)}): {', '.join(dedup)}")

    # 7. Strings (grouped by IOC category)
    strings = result.get("views", {}).get("strings") or []
    if isinstance(strings, list) and strings:
        groups: dict = {}
        misc_count = 0
        for s in strings:
            if not isinstance(s, dict):
                continue
            summary = s.get("summary") or s.get("text") or s.get("value") or ""
            if not summary:
                continue
            cat = _categorize_string(summary)
            if cat == "misc":
                misc_count += 1
            else:
                groups.setdefault(cat, []).append(summary)
        for cat in ("urls", "ips", "registry", "mutex", "paths", "suspicious", "base64", "apis"):
            items = groups.get(cat) or []
            if not items:
                continue
            seen = set()
            deduped = []
            for s in items:
                key = s.strip()
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(key)
                if len(deduped) >= 15:
                    break
            lines.append(f"  Strings/{cat} ({len(items)} total): {', '.join(deduped)}")
        if misc_count:
            lines.append(f"  Strings (other, {misc_count} items, omitted)")

    # 8. Carved files (binaries MalCat extracted from this file)
    carved = result.get("carved_files") or []
    if carved:
        items = []
        for c in carved[:10]:
            if isinstance(c, dict):
                tp = c.get("type") or c.get("type_category") or "?"
                sz = c.get("size") or 0
                ea = c.get("ea") or c.get("offset") or "?"
                items.append(f"{tp}@{ea} ({sz} bytes)")
            else:
                items.append(str(c)[:100])
        lines.append(f"  Carved files ({len(carved)}): {', '.join(items)}")

    # 9. Virtual files (scripts inside Office docs, payloads in installers)
    vfiles = result.get("virtual_files") or []
    if vfiles:
        items = []
        for v in vfiles[:10]:
            if isinstance(v, dict):
                p = v.get("path") or v.get("name") or "?"
                ext = v.get("extension") or ""
                items.append(f"{p}{(' [' + ext + ']') if ext else ''}")
            else:
                items.append(str(v)[:100])
        lines.append(f"  Virtual files ({len(vfiles)}): {', '.join(items)}")

    # 10. Structures (recovered C structs)
    structs = result.get("structures") or []
    if structs:
        items = []
        for s in structs[:15]:
            if isinstance(s, dict):
                n = s.get("name") or s.get("struct_name") or "?"
                items.append(n)
            else:
                items.append(str(s)[:100])
        lines.append(f"  Recovered structures ({len(structs)}): {', '.join(items)}")

    # 11. Decompilations (top-3 functions)
    decs = result.get("decompilations") or {}
    if decs:
        lines.append(f"  Decompilations ({len(decs)} top functions):")
        for addr, info in list(decs.items())[:3]:
            if isinstance(info, dict):
                nm = info.get("name", "?")
                sc = info.get("score", "?")
                body = (info.get("decompilation") or "").strip()
                if body:
                    import re as _re
                    body = _re.sub(r"\x1b\[[0-9;]*m", "", body)
                    lines.append(f"    ### {addr} ({nm}, score={sc})")
                    lines.append("```c")
                    lines.append(body[:2000])
                    lines.append("```")

    # 12. Script decompile (VBS, VBA, JS, PS1)
    sd = result.get("script_decompile")
    if sd:
        lines.append(f"  Script decompile: {str(sd)[:1000]}")

    # 13. Unpack (Donut loader)
    unp = result.get("unpack_result")
    if unp:
        lines.append(f"  Unpack (Donut): {str(unp)[:500]}")

    # 14. Errors (if any)
    errs = result.get("errors") or []
    if errs:
        lines.append(f"  ⚠ {len(errs)} errors: {errs[:3]}")
    return "\n".join(lines)


def _capa_to_card(result) -> str:
    """Convert capa output → compact evidence card."""
    if not isinstance(result, dict):
        return f"## capa\n  error: {result}\n"
    if "error" in result and not (result.get("top_rules") or result.get("rules") or result.get("matches")):
        return f"## capa\n  error: {result.get('error')}\n"
    rules = result.get("top_rules") or result.get("rules") or result.get("matches") or []
    if not rules:
        return "## capa\n  (no rules matched)\n"
    total = result.get("rule_count") or len(rules)
    lines = [f"## capa evidence ({total} total, showing top {len(rules)})"]
    by_attack: dict = {}
    no_attack = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = r.get("name") or r.get("rule") or r.get("id") or "?"
        attack = r.get("attack") or []
        if isinstance(attack, list) and attack:
            for a in attack:
                by_attack.setdefault(str(a), []).append(name)
        elif isinstance(attack, str) and attack:
            by_attack.setdefault(attack, []).append(name)
        else:
            no_attack.append(name)
    if by_attack:
        for attack, names in sorted(by_attack.items(), key=lambda x: -len(x[1]))[:12]:
            lines.append(f"  ATT&CK {attack} ({len(names)}): {', '.join(names[:6])}")
    if no_attack:
        lines.append(f"  All rules ({len(no_attack)}): {', '.join(no_attack[:20])}")
    return "\n".join(lines)


def _yara_to_card(result) -> str:
    """Convert YARA scan → compact card."""
    if not isinstance(result, dict):
        return f"## yara\n  error: {result}\n"
    if "error" in result and not result.get("matches"):
        return f"## yara\n  error: {result.get('error')}\n"
    matches = result.get("matches") or []
    if not matches:
        return "## yara\n  (no matches)\n"
    total = result.get("rule_count") or len(matches)
    lines = [f"## YARA matches ({total})"]
    rules = []
    for m in matches:
        if isinstance(m, dict):
            rule = m.get("rule") or m.get("name") or m.get("id") or "?"
        else:
            rule = str(m)
        if rule not in rules:
            rules.append(rule)
    lines.append(f"  Rules: {', '.join(rules[:25])}")
    return "\n".join(lines)


def _floss_to_card(result) -> str:
    """Convert FLOSS strings → compact IOC-grouped card.

    FLOSS returns strings as a plain list of strings (or dicts with 'string' key).
    """
    if not isinstance(result, dict):
        return f"## floss\n  error: {result}\n"
    if "error" in result and not result.get("strings"):
        return f"## floss\n  error: {result.get('error')}\n"
    raw = result.get("strings") or result.get("decoded_strings") or []
    if not raw:
        return "## floss\n  (no strings extracted)\n"
    # FLOSS returns plain strings OR dicts {string:..., ...}
    flat = []
    for s in raw:
        if isinstance(s, dict):
            txt = s.get("string") or s.get("text") or s.get("value") or s.get("summary")
            if txt:
                flat.append(str(txt))
        else:
            flat.append(str(s))
    total = result.get("string_count") or len(flat)
    groups: dict = {}
    misc = 0
    for s in flat:
        cat = _categorize_string(s)
        if cat == "misc":
            misc += 1
        else:
            groups.setdefault(cat, []).append(s)
    lines = [f"## FLOSS strings ({total} total)"]
    for cat in ("urls", "ips", "registry", "mutex", "paths", "suspicious", "base64", "apis"):
        items = groups.get(cat) or []
        if not items:
            continue
        seen = set()
        deduped = []
        for s in items:
            key = s.strip()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(key)
            if len(deduped) >= 12:
                break
        lines.append(f"  {cat} ({len(items)}): {', '.join(deduped)}")
    if misc:
        lines.append(f"  (other strings, {misc} items omitted)")
    return "\n".join(lines)


def _upx_to_card(result) -> str:
    if not isinstance(result, dict):
        return f"## upx\n  error: {result}\n"
    if not result.get("is_packed"):
        return "## UPX\n  (not packed)\n"
    path = result.get("unpacked_path", "?")
    return f"## UPX\n  packed=True, unpacked={path}\n"


def _xor_to_card(result) -> str:
    if not isinstance(result, dict):
        return f"## xorsearch\n  error: {result}\n"
    cands = result.get("candidates") or []
    if not cands:
        return "## xorsearch\n  (no XOR-encoded strings found)\n"
    lines = [f"## xorsearch ({len(cands)} candidates)"]
    for c in cands[:8]:
        lines.append(f"  {c[:200]}")
    if len(cands) > 8:
        lines.append(f"  (and {len(cands) - 8} more…)")
    return "\n".join(lines)


def _olevba_to_card(result) -> str:
    if not isinstance(result, dict):
        return f"## olevba\n  error: {result}\n"
    if not result.get("is_office_doc"):
        return "## olevba\n  (not an Office document)\n"
    macros = result.get("macros") or []
    if not macros:
        return "## olevba\n  (Office document, no macros)\n"
    lines = [f"## olevba ({len(macros)} macros)"]
    for m in macros[:8]:
        if isinstance(m, dict):
            name = m.get("name") or m.get("macro_name") or "?"
            vba_type = m.get("type") or m.get("vba_type") or ""
            lines.append(f"  {name} ({vba_type})" if vba_type else f"  {name}")
        else:
            lines.append(f"  {str(m)[:120]}")
    return "\n".join(lines)


def _peepdf_to_card(result) -> str:
    if not isinstance(result, dict):
        return f"## peepdf\n  error: {result}\n"
    if not result.get("is_pdf"):
        return "## peepdf\n  (not a PDF)\n"
    susp = result.get("suspicious") or []
    obj_count = result.get("pdf_obj_count")
    lines = ["## peepdf"]
    if obj_count:
        lines.append(f"  objects={obj_count}")
    if susp:
        # dedup
        seen = set()
        deduped = []
        for s in susp:
            if s in seen:
                continue
            seen.add(s)
            deduped.append(s)
            if len(deduped) >= 15:
                break
        lines.append(f"  suspicious ({len(susp)}): {', '.join(deduped)}")
    else:
        lines.append("  (no suspicious objects / JS / embedded files detected)")
    return "\n".join(lines)


def _dotnet_to_card(result) -> str:
    if not isinstance(result, dict):
        return f"## dotnet\n  error: {result}\n"
    if not result.get("is_dotnet"):
        return "## dotnet_analyze\n  (not a .NET assembly)\n"
    lines = ["## .NET analysis"]
    if result.get("language_hint"):
        lines.append(f"  language: {result['language_hint']}")
    if result.get("runtime_version"):
        lines.append(f"  runtime: {result['runtime_version']}")
    if result.get("module_name"):
        lines.append(f"  module: {result['module_name']}")
    ext = result.get("external_assembly_refs") or []
    if ext:
        lines.append(f"  external_refs: {', '.join(ext[:10])}")
    native = result.get("suspicious_native_refs") or []
    if native:
        lines.append(f"  ⚠ native_refs: {', '.join(native)}")
    pinv = result.get("interesting_pinvoke") or []
    if pinv:
        lines.append(f"  P/Invoke DLLs: {', '.join(pinv)}")
    pfuncs = result.get("pinvoke_imports") or []
    if pfuncs:
        lines.append(f"  P/Invoke funcs: {', '.join(pfuncs[:15])}")
    sm = result.get("suspicious_methods") or []
    if sm:
        lines.append(f"  methods-of-interest: {', '.join(sm)}")
    if result.get("has_suppress_ildasm"):
        lines.append("  ⚠ SuppressIldasmAttribute (anti-RE)")
    if result.get("shellcode_embed_hint"):
        lines.append("  ⚠ shellcode-embed pattern (ldc.i4 + newarr + InitializeArray)")
    il = result.get("il_excerpt") or ""
    if il:
        lines.append(f"  IL excerpt (first 2000 of {result.get('il_total_lines', '?')} lines):")
        lines.append("```il")
        lines.append(il[:2000])
        lines.append("```")
    return "\n".join(lines)


def _r2_to_card(result) -> str:
    if not isinstance(result, dict):
        return f"## r2\n  error: {result}\n"
    engine = result.get("engine", "r2")
    decs = result.get("disassembly") or {}
    if not decs:
        return f"## radare2 ({engine})\n  (no disassembly)\n"
    lines = [f"## radare2 ({engine}) — {len(decs)} functions (asm)"]
    import re as _re
    for addr, body in list(decs.items())[:5]:
        lines.append(f"  ### {addr}")
        clean = _re.sub(r"\x1b\[[0-9;]*m", "", str(body))
        lines.append("```c")
        lines.append(clean[:2500])
        lines.append("```")
    return "\n".join(lines)


def _sql_evidence_to_card(evidence_list, engine_label: str) -> str:
    """Convert a list of Ghidra/IDA SQL evidence dicts → compact card.

    Each evidence entry: {engine, key, label, sql, result, error}
    We group by table, show row counts + a few sample rows for each.
    """
    if not evidence_list:
        return f"## {engine_label} SQL\n  (no SQL queries run)\n"
    lines = [f"## {engine_label} SQL evidence"]
    for ev in evidence_list:
        if not isinstance(ev, dict):
            continue
        label = ev.get("label") or ev.get("key") or "?"
        if ev.get("error"):
            lines.append(f"  {label}: ERROR {str(ev['error'])[:200]}")
            continue
        result = ev.get("result") or {}
        if not isinstance(result, dict):
            lines.append(f"  {label}: no result")
            continue
        rows = result.get("rows") or []
        cols = result.get("columns") or []
        # Get the row count
        total = result.get("row_count")
        if total is None:
            total = len(rows)
        if not rows:
            lines.append(f"  {label} (SQL `{ev.get('sql','')[:80]}`): 0 rows")
            continue
        # Compact: show first 5 rows
        lines.append(f"  {label} ({total} rows):")
        # Column headers
        if cols:
            lines.append(f"    cols: {', '.join(str(c) for c in cols[:8])}")
        for r in rows[:5]:
            if isinstance(r, dict):
                vals = [str(r.get(c, ""))[:80] for c in (cols or list(r.keys()))[:6]]
                lines.append(f"    | {' | '.join(vals)}")
            else:
                lines.append(f"    | {str(r)[:200]}")
        if total > 5:
            lines.append(f"    (and {total - 5} more rows)")
    return "\n".join(lines)


class EvidenceAssembler:
    """Orchestrate tool outputs into a token-budgeted evidence pack.

    Each tool has a `to_card(result)` that produces a compact representation.
    This class calls them in priority order until the budget is exhausted.
    Tools not yet seen are summarized as "not run / unavailable".
    """

    TOOL_CARDS = {
        "malcat": _malcat_to_card,
        "capa": _capa_to_card,
        "yara": _yara_to_card,
        "floss": _floss_to_card,
        "upx": _upx_to_card,
        "xor": _xor_to_card,
        "olevba": _olevba_to_card,
        "peepdf": _peepdf_to_card,
        "dotnet": _dotnet_to_card,
        "r2": _r2_to_card,
    }

    # Priority order: high-signal first, RAG last (it gets remaining budget)
    PRIORITY = (
        "malcat", "capa", "yara", "floss", "dotnet",
        "r2", "upx", "xor", "olevba", "peepdf",
    )

    def __init__(self, budget_chars: int = 50000):
        self.budget = budget_chars
        self.used = 0
        self.cards = []

    def add(self, tool: str, result, force: bool = False) -> bool:
        """Add a tool's card if it fits in the budget. Returns True if added."""
        if tool not in self.TOOL_CARDS:
            return False
        if result is None:
            return False
        card = self.TOOL_CARDS[tool](result)
        if not force and self.used + len(card) > self.budget:
            return False
        self.cards.append((tool, card))
        self.used += len(card)
        return True

    def add_rag(self, rag_block: str) -> int:
        """Add RAG block using all remaining budget. Returns chars added."""
        if not rag_block:
            return 0
        room = self.budget - self.used
        if room <= 100:
            return 0
        chunk = rag_block[:room]
        self.cards.append(("rag", chunk))
        self.used += len(chunk)
        return len(chunk)

    def render(self, header: str = "## Tool evidence (signal-prioritized)") -> str:
        if not self.cards:
            return f"{header}\n  (no tool results)\n"
        out = [header]
        for tool, card in self.cards:
            out.append("")
            out.append(card)
        out.append("")
        out.append(f"<!-- evidence_assembler: used {self.used}/{self.budget} chars across {len(self.cards)} tools -->")
        return "\n".join(out)


