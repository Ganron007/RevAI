#!/usr/bin/env python3
"""
v2_lib.py — shared helpers for pipeline agents and MCP façades on REMnux.

Session registry, audit logging, ghidra/ida SQL clients, subprocess tools
(capa, floss, yara), malcat_analyze façade, ghidra_decompile helper.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

SESSIONS_DIR = Path("/opt/samples/sessions")
LOGS_DIR = Path("/opt/samples/logs")
CADRE_ENV = Path("/opt/secrets/cadre.env")
PIPELINE_CONFIG_PATH = Path("/opt/samples/pipeline-config.json")

# LLM config — clean RevAI runtime home only.
LLM_ENV_PATH = Path("/opt/revai/config/llm.env")
# RevAI runtime home (config / bin / hitl / extensions).
REVAI_HOME = Path(os.environ.get("REVAI_HOME") or "/opt/revai")


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ (setdefault)."""
    if not path.exists():
        return
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def ensure_pipeline_runtime_env() -> dict:
    """Ensure CLI runs match Flask: load online LLM env.

    Loads llm.env / cadre.env so CLI stages share the Flask LLM config.

    Returns a small dict of what was applied (for logging).
    """
    load_env_file(LLM_ENV_PATH)
    load_env_file(CADRE_ENV)
    return {"applied": {}}


def revai_provenance() -> dict:
    """Report provenance stamp — which pipeline commit + config produced an artifact.

    Commit comes from /opt/revai/config/REVAI_COMMIT (written at sync time) or the
    REVAI_COMMIT env var; unknown locally. Records engine mode and the agent-loop
    feature flags so future audits can tell instantly which pipeline made a report.
    """
    commit = os.environ.get("REVAI_COMMIT", "")
    if not commit:
        try:
            commit = Path("/opt/revai/config/REVAI_COMMIT").read_text(
                encoding="utf-8"
            ).strip()
        except Exception:
            pass
    if not commit:
        commit = "unknown"

    def _flag(name: str) -> bool:
        return os.environ.get(name, "1").strip().lower() not in ("0", "false", "no")

    return {
        "project": "RevAI",
        "commit": commit,
        "engine": os.environ.get("REVAI_AGENTIC_ENGINE", "langgraph"),
        "flags": {
            "budget_warnings": _flag("REVAI_BUDGET_WARNINGS"),
            "redundant_nudge": _flag("REVAI_REDUNDANT_NUDGE"),
            "hallucination_check": _flag("REVAI_HALLUCINATION_CHECK"),
            "failure_taxonomy": _flag("REVAI_FAILURE_TAXONOMY"),
        },
        "utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def provenance_block() -> str:
    """Markdown provenance banner for the top of generated reports."""
    p = revai_provenance()
    fl = p["flags"]
    return (
        f"> **RevAI provenance** — commit `{p['commit']}` · engine `{p['engine']}` "
        f"· agent-loop flags: budget={fl['budget_warnings']} "
        f"redundant={fl['redundant_nudge']} hallucination={fl['hallucination_check']} "
        f"taxonomy={fl['failure_taxonomy']} · generated {p['utc']}\n\n"
    )


def run_profile() -> dict:
    """Resolve the active run profile + per-knob overrides.

    Profiles calibrate the agentic loop: stage retries, recursion budget,
    deep-dive max steps, and tool timeouts. `unlimited` is the lab profile
    (budget must never block retries). Explicit REVAI_* knobs override the
    profile. Returns a plain dict for provenance/trace.
    """
    profile = (os.environ.get("REVAI_RUN_PROFILE") or "standard").strip().lower()
    base = {
        "standard": {
            "recursion_limit": 40, "deep_max_steps": 16,
            "timeout_scale": 1.0, "stage_retries": 1, "tool_retries": 1,
        },
        "generous": {
            "recursion_limit": 80, "deep_max_steps": 32,
            "timeout_scale": 1.5, "stage_retries": 2, "tool_retries": 2,
        },
        "unlimited": {
            "recursion_limit": 200, "deep_max_steps": 64,
            "timeout_scale": 3.0, "stage_retries": 5, "tool_retries": 5,
        },
    }
    if profile not in base:
        profile = "standard"
    cfg = dict(base[profile])

    def _int(name: str, key: str) -> None:
        v = os.environ.get(name, "").strip()
        if v:
            try:
                cfg[key] = max(0, int(v))
            except ValueError:
                pass

    def _float(name: str, key: str) -> None:
        v = os.environ.get(name, "").strip()
        if v:
            try:
                cfg[key] = max(0.1, float(v))
            except ValueError:
                pass

    _int("REVAI_ORCH_RECURSION_LIMIT", "recursion_limit")
    _int("REVAI_DEEP_MAX_STEPS", "deep_max_steps")
    _int("REVAI_STAGE_RETRIES", "stage_retries")
    _int("REVAI_TOOL_RETRIES", "tool_retries")
    _float("REVAI_TOOL_TIMEOUT_SCALE", "timeout_scale")
    cfg["profile"] = profile
    cfg["retry_transient_only"] = (
        os.environ.get("REVAI_RETRY_TRANSIENT_ONLY", "1").strip().lower()
        not in ("0", "false", "no")
    )
    return cfg


_TRANSIENT_MARKERS = (
    "timeout", "timed out", "mcp", "connection", "refused", "reset by peer",
    "server died", "not running", "socket", "transport", "closed",
    "segmentation", "memoryerror", "killed", "oom",
)


def is_transient_failure(text: str | None) -> bool:
    """Classify a stage/tool failure as transient (retryable) or not.

    Transient = infra flakiness that a bounded retry can legitimately fix
    (tool timeout, MCP/server connection loss, OOM kill). Everything else
    (bad rule, missing artifact, permission, LLM quality) is NOT transient —
    retrying would burn budget, not fix the cause.
    """
    t = (text or "").lower()
    if not t:
        return False
    return any(m in t for m in _TRANSIENT_MARKERS)


# --- Deep-dive completeness protocol (plan #7 — depth gate) ---
# Each capability domain must be ADDRESSED: either evidenced or explicitly
# stated as not observed. An entirely unmentioned domain = thin analysis.
_DEPTH_DOMAINS = {
    "persistence": (
        "persistence, registry run, startup, scheduled task, service, autorun, "
        "boot persistence, cron"
    ),
    "c2_network": (
        "c2, command and control, beacon, http, url, ip address, socket, "
        "network, domain, connect, dns"
    ),
    "evasion_anti_analysis": (
        "anti-debug, anti-vm, evasion, obfuscation, packing, isdebuggerpresent, "
        "sandbox, anti-analysis, anti-instrumentation, virtualprotect"
    ),
    "exfiltration": (
        "exfiltrat, upload, data theft, steal, exfil, send data, data exfil"
    ),
    "defense_impairment": (
        "disable defender, amsi, etw, patch guard, kill process, disable av, "
        "uac, defender, security product, edr, security tool, security tools, "
        "antivirus, disable protection, bypass security"
    ),
    "credential_access": (
        "credential, keylog, password, token theft, logon, lsass, sam, ntds, "
        "credential dump"
    ),
    "encryption_obfuscation": (
        "encrypt, xor, rc4, aes, crypto, cipher, encode, obfuscate, mba, "
        "opaque predicate"
    ),
}
_DEPTH_STRUCTURAL = {
    "entry_point": "entry point, ep, start, main, entry, first instruction",
    "imports": "imports, import table, imports,",
    "strings": "strings, string,",
}
_DEPTH_NEGATIONS = (
    "not observed", "no evidence", "no indication", "none", "absent",
    "not found", "did not find", "no ", "none observed", "unavailable",
    "not present",
)


def evaluate_deep_coverage(deep: dict) -> dict:
    """Depth gate (plan #7): every capability domain must be ADDRESSED.

    Scans the deep-dive summary + key_evidence + findings for each domain's
    signal words OR an explicit "not observed"-style negation. A domain that
    is entirely unmentioned => thin analysis => gate fails. Returns
    {ok, missing, covered, domain_scan} for audit transparency.
    """
    parts = [
        str(deep.get("summary") or ""),
        json.dumps(deep.get("key_evidence") or [], default=str),
        json.dumps(deep.get("findings") or {}, default=str)[:6000],
        str(deep.get("cross_engine_notes") or ""),
    ]
    text = " ".join(parts).lower()
    covered: dict[str, bool] = {}
    for domain, signals in {**_DEPTH_DOMAINS, **_DEPTH_STRUCTURAL}.items():
        # Signals are comma-separated vocabulary; strip each so " etw" never
        # requires a preceding space (full-campaign finding: a summary with
        # "ETW hooks" at sentence start missed the defense_impairment domain
        # despite the correction turn addressing the others).
        sigs = [s.strip() for s in signals.split(",") if s.strip()]
        has_signal = any(s in text for s in sigs)
        has_negation = any(n in text for n in _DEPTH_NEGATIONS)
        # A domain is "addressed" if its signal words appear OR a negation is
        # present (the analysis explicitly considered and dismissed it).
        covered[domain] = has_signal or has_negation
    missing = [d for d, ok in covered.items() if not ok]
    return {
        "ok": not missing,
        "missing": missing,
        "covered": covered,
        "domain_count": len(covered),
    }


def compact_json_for_prompt(
    obj: Any,
    *,
    max_chars: int = 8000,
    keep_keys: list[str] | None = None,
) -> str:
    """Serialize evidence for LLM prompts without mid-JSON blind crops.

    Prefer a field whitelist; if still too large, truncate at a newline boundary
    and append an explicit marker (never a half-key JSON slice as the only form).
    """
    if obj is None:
        return "{}"
    if keep_keys and isinstance(obj, dict):
        slim = {k: obj.get(k) for k in keep_keys if k in obj}
    else:
        slim = obj
    try:
        text = json.dumps(slim, indent=2, default=str)
    except Exception:
        text = str(slim)
    if len(text) <= max_chars:
        return text
    cut = text[: max_chars - 80]
    nl = cut.rfind("\n")
    if nl > max_chars // 2:
        cut = cut[:nl]
    return cut + f"\n… [truncated {len(text) - len(cut)} chars; use tool cards for full signal]"


def normalize_verdict_label(label: str | None) -> str:
    """Map free-text verdict to coarse class: malicious|suspicious|benign|unknown."""
    s = (label or "").strip().lower()
    if not s:
        return "unknown"
    if any(x in s for x in ("malicious", "malware", "trojan", "ransomware", "backdoor")):
        return "malicious"
    if any(x in s for x in ("suspicious", "pua", "adware", "grayware")):
        return "suspicious"
    if any(x in s for x in ("benign", "clean", "legitimate", "goodware")):
        return "benign"
    return "unknown"


def strip_accuracy_hold_banner(markdown: str) -> str:
    """Remove leading V5.12 ACCURACY HOLD blockquote so it cannot poison verdict scrape."""
    text = markdown or ""
    if "ACCURACY HOLD" not in text[:800]:
        return text
    # Drop leading blockquote lines / hold paragraph
    parts = text.split("\n\n", 1)
    if len(parts) == 2 and "ACCURACY HOLD" in parts[0]:
        return parts[1]
    lines = []
    skipping = True
    for line in text.splitlines():
        if skipping:
            if line.startswith(">") or not line.strip() or "ACCURACY HOLD" in line:
                continue
            skipping = False
        lines.append(line)
    return "\n".join(lines)


def surface_verdict_sources_panel(
    *,
    final_verdict: str,
    triage_verdict: str | None = None,
    quick_verdict: str | None = None,
    deep_verdict: str | None = None,
    publish_llm_verdict: str | None = None,
    locked: bool = False,
) -> str:
    """Always-on multi-source verdict table for REPORT-v2 (honest product surface)."""
    triage = (triage_verdict or final_verdict or "unknown").strip() or "unknown"
    quick = (quick_verdict or "unknown").strip() or "unknown"
    deep = (deep_verdict or "unknown").strip() or "unknown"
    pub = (publish_llm_verdict or "unknown").strip() or "unknown"
    final = (final_verdict or "unknown").strip() or "unknown"
    lock_note = "yes — publish LLM contradicted triage" if locked else "no"
    return (
        "# Verdict sources (multi-source)\n\n"
        "| Source | Verdict |\n"
        "|--------|--------|\n"
        f"| **Final** | **{final}** |\n"
        f"| Triage upstream (quick ∪ deep) | {triage} |\n"
        f"| Quick scan | {quick} |\n"
        f"| Deep dive | {deep} |\n"
        f"| Publish LLM (claimed) | {pub} |\n\n"
        f"- **Locked over publish LLM:** {lock_note}\n\n"
    )


def align_publish_markdown_to_upstream(
    markdown: str,
    *,
    upstream: str,
    family: str | None = None,
    yara_rules: list | None = None,
    publish_claimed: str | None = None,
    quick_verdict: str | None = None,
    deep_verdict: str | None = None,
) -> str:
    """Honest multi-source verdict panel when publish LLM contradicts triage.

    Does **not** rewrite the LLM prose to look unanimous. Final/machine verdict
    stays locked to upstream; the publish narrative is preserved under an
    explicit "Publish LLM narrative" section for audit.
    """
    body = strip_accuracy_hold_banner(markdown or "")
    fam = (family or "").strip() or "unknown"
    rules = ", ".join(str(r) for r in (yara_rules or [])[:8]) or "upstream triage"
    claimed = (publish_claimed or "unknown").strip() or "unknown"
    quick = (quick_verdict or "unknown").strip() or "unknown"
    deep = (deep_verdict or "unknown").strip() or "unknown"
    lock_block = (
        "# Classification (multi-source — V5.12)\n\n"
        "| Source | Verdict |\n"
        "|--------|--------|\n"
        f"| **Final (locked)** | **{upstream}** |\n"
        f"| Triage upstream (quick ∪ deep) | {upstream} |\n"
        f"| Quick scan | {quick} |\n"
        f"| Deep dive | {deep} |\n"
        f"| Publish LLM (claimed) | {claimed} |\n\n"
        f"- **Lock reason:** publish LLM claimed `{claimed}` but upstream triage "
        f"is `{upstream}` (YARA / tool-backed: {rules}). "
        "Final verdict follows triage; dual-use branding does not clear the sample.\n"
        f"- **Family (triage):** {fam}\n"
        "- **Honesty:** the publish narrative below is **preserved unedited** so "
        "analysts can see what the report LLM argued. It is **not** a clearance.\n\n"
        "---\n\n"
        "### Publish LLM narrative (unedited)\n\n"
    )
    return lock_block + body


def infer_publish_verdict_from_markdown(markdown: str) -> str | None:
    """Infer publish-claimed verdict from report body (never from hold banner)."""
    import re as _re

    body = strip_accuracy_hold_banner(markdown or "").lower()
    head = body[:2500]
    clearance = any(
        x in head
        for x in (
            "legitimate",
            "not malware",
            "benign",
            "goodware",
            "potentially unwanted",
            "legitimate tool",
            "remote administration tool",
            "not malicious",
            "no malicious",
        )
    )
    # True malicious claims — exclude "no/not malicious"
    mal_hits = _re.findall(r"(?<!\bno\s)(?<!\bnot\s)malicious", head)
    # Dual-use clearance (NetSupport etc.): treat as benign for lock purposes
    if clearance and not mal_hits:
        return "benign"
    if clearance and mal_hits and any(
        x in head for x in ("legitimate", "potentially unwanted", "not malware")
    ):
        return "benign"
    if mal_hits:
        return "malicious"
    if "suspicious" in head or "potentially unwanted" in head:
        return "suspicious"
    if "benign" in head or "clean" in head:
        return "benign"
    return None


def cross_stage_verdict_lock(
    publish_verdict: str | None,
    *,
    quick_verdict: str | None = None,
    deep_verdict: str | None = None,
) -> dict:
    """Fail when publish contradicts an earlier malicious/suspicious finding.

    A publish verdict that DOWNGRADES the upstream triage (malicious →
    suspicious/benign, suspicious → benign) is a contradiction: the report
    would under-report what the evidence chain established. This covers the
    #8a finding — a publish claiming "suspicious, legitimate NSudo" while the
    deep dive said "malicious" slipped through the old benign-only check.

    Returns {ok, conflict, upstream, publish, reason}.
    """
    _SEV = {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}
    pub = normalize_verdict_label(publish_verdict)
    upstream_labels = [
        normalize_verdict_label(quick_verdict),
        normalize_verdict_label(deep_verdict),
    ]
    upstream = "unknown"
    for u in upstream_labels:
        if u == "malicious":
            upstream = "malicious"
            break
        if u == "suspicious" and upstream != "malicious":
            upstream = "suspicious"
        elif u == "benign" and upstream == "unknown":
            upstream = "benign"
    conflict = False
    reason = ""
    if _SEV.get(pub, 0) < _SEV.get(upstream, 0):
        conflict = True
        reason = f"publish={pub} downgrades upstream={upstream}"
    return {
        "ok": not conflict,
        "conflict": conflict,
        "upstream": upstream,
        "publish": pub,
        "reason": reason,
    }


def normalize_verdict_score(llm_verdict: dict) -> None:
    """Normalize an LLM verdict's score to a consistent 0-100 scale (in place).

    The LLM sometimes emits 0-10 ("9/10") despite the prompt; a value <= 10 on
    a verdict would silently under-report confidence. Marks rescaled scores with
    `score_was` so the audit can distinguish rescaling from native 0-100 output.
    """
    try:
        sc = float(llm_verdict.get("score") or 0)
        if sc <= 10 and sc > 0:
            llm_verdict["score"] = int(round(sc * 10))
            llm_verdict["score_was"] = "rescaled_0_10_to_0_100"
        elif sc:
            llm_verdict["score"] = int(round(sc))
    except (TypeError, ValueError):
        llm_verdict["score"] = 0


def sql_deep_honest(
    has_sql: bool,
    sql_deep_ok: Any,
    sql_deep_unavailable: Any,
) -> bool:
    """SQL deep RE gate: pass if SQL/decompile succeeded, OR if SQL was attempted
    but failed on documented infrastructure. Only a complete non-attempt fails."""
    return bool(
        has_sql
        or sql_deep_ok
        or sql_deep_unavailable in ("ghidrasql_server_died", "idasql_missing", "sql_failed")
    )


def agentic_confidence_sane(ag: dict) -> bool:
    """Confidence gate: a complete dive may never report confidence 0."""
    ag_conf = ag.get("confidence")
    ag_complete = not ag.get("incomplete_tooling") and bool(ag.get("verdict") or ag.get("summary"))
    return not (ag_complete and ag_conf in (0, "0", 0.0))


def verify_key_evidence_grounding(
    verdict_or_deep: dict,
    tool_blobs: dict,
) -> dict:
    """Check key_evidence tokens appear in tool JSON (V5.12.8 / ex-V5.6).

    Returns {ok, checked, hits, misses, hit_examples, reason}.
    ok = ≥50% of evidence items grounded when evidence present.
    """
    import re as _re

    evidence = (verdict_or_deep or {}).get("key_evidence") or []
    if not evidence:
        return {
            "ok": False,
            "reason": "no key_evidence",
            "checked": 0,
            "hits": 0,
            "misses": [],
            "hit_examples": [],
        }
    hay = json.dumps(tool_blobs, default=str).lower()
    # Alias LLM source labels → tokens that appear in tool/SQL blobs.
    _SOURCE_ALIASES = {
        "radare2": "r2_decomp r2 radare",
        "r2": "r2_decomp radare2",
        "ghidra_decompile": "ghidra decompile decompilation",
        "malcat_constants": "malcat constants rijndael",
        "pe_imports": "pe_imports imports pe_import",
    }
    hits, misses = [], []
    for item in evidence:
        if isinstance(item, dict):
            # Deep LLM uses source+evidence; triage uses row_or_rule/why.
            frag = " ".join(
                str(item.get(k) or "")
                for k in (
                    "row_or_rule", "query_or_table", "why", "source",
                    "evidence", "value", "evidence_type",
                )
            )
            src = str(item.get("source") or "").strip().lower()
            if src in _SOURCE_ALIASES:
                frag = f"{frag} {_SOURCE_ALIASES[src]}"
        else:
            frag = str(item)
        tokens = [t for t in _re.split(r"\W+", frag.lower()) if len(t) >= 5][:10]
        if not tokens:
            continue
        if any(t in hay for t in tokens):
            hits.append(frag[:120])
        else:
            misses.append(frag[:120])
    checked = len(hits) + len(misses)
    ok = checked > 0 and (len(hits) / checked) >= 0.5
    return {
        "ok": ok,
        "checked": checked,
        "hits": len(hits),
        "misses": misses[:8],
        "hit_examples": hits[:5],
        "reason": "" if ok else ("ungrounded" if checked else "no_checkable_tokens"),
    }


# Engines that must not be falsely attributed (V5.16.3).
_STRICT_ENGINES = (
    "ida", "ghidra", "malcat", "capa", "floss", "yara", "pe_imports", "r2", "upx",
)
_ENGINE_SOURCE_ALIASES = {
    "ida": ("ida", "idasql", "ida_sql", "ida pro", "ida-pro"),
    "ghidra": ("ghidra", "ghidrasql", "ghidra_sql"),
    "malcat": ("malcat",),
    "capa": ("capa", "malcat-capa", "malcat capa"),
    "floss": ("floss",),
    "yara": ("yara", "yara_matches", "yara-rules"),
    "pe_imports": ("pe_imports", "pe imports", "pe_import"),
    "r2": ("r2", "radare", "radare2", "r2_decomp"),
    "upx": ("upx",),
    "speakeasy": ("speakeasy",),
    "frida": ("frida", "frida_probe"),
}


def _normalize_claimed_engines(source) -> list[str]:
    """Extract canonical engine names from key_evidence source field(s).

    Word-boundary matching (2026-08-07, full-campaign finding): substring
    matching made "capa" match inside "capability", so any evidence row with
    query_or_table="Malicious capability indicators" was claimed as source=capa
    and flagged as a false engine citation (video/lumma-class audit fails).
    "capa" must match only as a standalone token.
    """
    import re as _re

    parts: list[str] = []
    if isinstance(source, list):
        for s in source:
            parts.extend(_normalize_claimed_engines(s))
        return list(dict.fromkeys(parts))
    text = str(source or "").strip().lower()
    if not text:
        return []
    # "ghidra:memory_blocks" / "capa:packed_with_UPX"
    head = text.split(":", 1)[0].strip()
    claimed: list[str] = []
    has_head = any(head == eng or head in aliases
                    for eng, aliases in _ENGINE_SOURCE_ALIASES.items())
    for eng, aliases in _ENGINE_SOURCE_ALIASES.items():
        if head == eng or head in aliases:
            claimed.append(eng)
            continue
        if has_head:
            # Explicit "engine:..." prefix is authoritative — do not infer
            # extra engines from the rest of the label (e.g. a capa rule named
            # "packed_with_UPX" must not claim the upx engine).
            continue
        # Word-boundary token match for aliases inside longer descriptive
        # labels (e.g. "yara_scan_findings", "malcat capa", "pe imports").
        # `_` and `-` count as separators (not word chars), so "yara" matches
        # in "yara_scan_findings" but "capa" does NOT match in "capability".
        for a in aliases:
            if _re.search(rf"(?<![a-z0-9]){_re.escape(a)}(?![a-z0-9])", text):
                claimed.append(eng)
                break
    return list(dict.fromkeys(claimed))


def _evidence_needle(item) -> str:
    """High-signal fragment used to locate which engine owns the claim."""
    if not isinstance(item, dict):
        s = str(item or "").strip()
        return s[:120]
    for key in ("row_or_rule", "evidence", "value", "detail"):
        v = str(item.get(key) or "").strip()
        if len(v) >= 6:
            return v[:120]
    return ""


def build_per_engine_haystacks(tool_blobs: dict) -> dict[str, str]:
    """Lowercased JSON per engine for attribution checks."""
    tools = tool_blobs.get("tools") if isinstance(tool_blobs.get("tools"), dict) else tool_blobs
    if not isinstance(tools, dict):
        tools = {}
    sql = tool_blobs.get("sql") if isinstance(tool_blobs.get("sql"), dict) else {}
    hay: dict[str, str] = {}

    def _dump(*objs) -> str:
        return json.dumps(objs, default=str).lower()

    hay["malcat"] = _dump(tools.get("malcat"))
    hay["capa"] = _dump(tools.get("capa"), (tools.get("malcat") or {}).get("capa") if isinstance(tools.get("malcat"), dict) else None)
    hay["floss"] = _dump(tools.get("floss"))
    hay["yara"] = _dump(tools.get("yara"))
    hay["pe_imports"] = _dump(tools.get("pe_imports"), tools.get("pe_import_signals"))
    hay["r2"] = _dump(tools.get("r2_decomp"), tools.get("r2"), tools.get("r2_ai_decompile"))
    hay["upx"] = _dump(tools.get("upx"), tools.get("upx_second_pass"))
    hay["speakeasy"] = _dump(tools.get("speakeasy"), tool_blobs.get("behavioral"))
    hay["frida"] = _dump(tools.get("frida_probe"))
    # SQL engines — prefer nested ida/ghidra keys; fall back to whole sql blob split by name
    ida_sql = sql.get("ida") or sql.get("ida_sql") or sql.get("idasql")
    ghidra_sql = sql.get("ghidra") or sql.get("ghidra_sql") or sql.get("ghidrasql")
    if ida_sql is None and sql:
        # Some packs store flat {queries: {ida_*: ...}}
        ida_sql = {k: v for k, v in sql.items() if "ida" in str(k).lower()}
    if ghidra_sql is None and sql:
        ghidra_sql = {k: v for k, v in sql.items() if "ghidra" in str(k).lower()}
    hay["ida"] = _dump(ida_sql, tools.get("ida"))
    hay["ghidra"] = _dump(ghidra_sql, tools.get("ghidra"))
    return hay


def verify_engine_citation_honesty(
    verdict_or_deep: dict,
    tool_blobs: dict,
    *,
    report_md: str | None = None,
) -> dict:
    """Hard gate: claimed engine must own the cited fragment (V5.16.3).

    Catches Rook-class bugs: source=\"ida\" + row_or_rule=\"FILES ENCRYPTED\"
    when the string only exists under Malcat.
    ok=False ⇒ audit must fail (false_engine_citations).
    """
    import re as _re

    evidence = (verdict_or_deep or {}).get("key_evidence") or []
    haystacks = build_per_engine_haystacks(tool_blobs or {})
    false: list[dict] = []
    checked = 0

    for item in evidence:
        if not isinstance(item, dict):
            continue
        claimed = _normalize_claimed_engines(item.get("source"))
        # Also parse query_or_table like "Suspicious strings (IDA)"
        claimed.extend(_normalize_claimed_engines(item.get("query_or_table")))
        claimed = [c for c in dict.fromkeys(claimed) if c in _STRICT_ENGINES]
        needle = _evidence_needle(item)
        if not claimed or not needle or len(needle) < 6:
            continue
        needle_l = needle.lower()
        # Distinctive tokens only (≥8 chars) — avoids "Packed"/"Virtual" FP noise
        tokens = [t for t in _re.split(r"\W+", needle_l) if len(t) >= 8][:4]
        if not tokens:
            continue
        for eng in claimed:
            checked += 1
            eng_hay = haystacks.get(eng) or ""
            in_claimed = any(t in eng_hay for t in tokens)
            if in_claimed:
                continue
            elsewhere = [
                e for e, h in haystacks.items()
                if e != eng and e in _STRICT_ENGINES and any(t in (h or "") for t in tokens)
            ]
            if elsewhere:
                false.append({
                    "claimed": eng,
                    "actual": elsewhere,
                    "needle": needle[:100],
                    "source": item.get("source"),
                })

    # Secondary: markdown "(Source: IDA …)" near a distinctive fragment owned elsewhere.
    # Off by default — prose/HTML windows produced Remcos-class false fails
    # (needles like ' target=' / short XOR phrases). Enable with
    # REVAI_STRICT_MD_ENGINE_CITE=1 for research audits.
    md_false = []
    if report_md and os.environ.get("REVAI_STRICT_MD_ENGINE_CITE", "").strip() in (
        "1", "true", "TRUE", "yes", "YES",
    ):
        for m in _re.finditer(
            r"(?is)(?:source|engine)\s*[:=]\s*[*`\"]?(ida|ghidra|malcat|capa|floss|yara)",
            report_md,
        ):
            eng = m.group(1).lower()
            window = report_md[max(0, m.start() - 160): m.end() + 160]
            frags = _re.findall(r"[`\"']([^`\"']{12,80})[`\"']", window)
            for frag in frags[:3]:
                alnum = sum(1 for c in frag if c.isalnum())
                if alnum < 10 or (alnum / max(len(frag), 1)) < 0.55:
                    continue
                tokens = [t for t in _re.split(r"\W+", frag.lower()) if len(t) >= 8][:3]
                if not tokens:
                    continue
                eng_hay = haystacks.get(eng) or ""
                if any(t in eng_hay for t in tokens):
                    continue
                elsewhere = [
                    e for e, h in haystacks.items()
                    if e != eng and e in _STRICT_ENGINES and any(t in (h or "") for t in tokens)
                ]
                if elsewhere:
                    md_false.append({
                        "claimed": eng,
                        "actual": elsewhere,
                        "needle": frag[:100],
                        "source": "report_md",
                    })
                    checked += 1

    all_false = (false + md_false)[:12]
    ok = len(all_false) == 0
    return {
        "ok": ok,
        "checked": checked,
        "false_engine_citations": all_false,
        "reason": "" if ok else "false_engine_attribution",
    }


# Prefer specific static owners when multiple haystacks contain the needle.
_ENGINE_OWNER_PRIORITY = (
    "pe_imports",
    "ghidra",
    "ida",
    "malcat",
    "yara",
    "capa",
    "floss",
    "r2",
    "upx",
    "speakeasy",
    "frida",
)


def _needle_tokens(needle: str, *, min_len: int = 8) -> list[str]:
    import re as _re

    return [t for t in _re.split(r"\W+", (needle or "").lower()) if len(t) >= min_len][:4]


def _engines_owning_tokens(haystacks: dict[str, str], tokens: list[str]) -> list[str]:
    if not tokens:
        return []
    owners = [
        e for e in _ENGINE_OWNER_PRIORITY
        if e in _STRICT_ENGINES and any(t in (haystacks.get(e) or "") for t in tokens)
    ]
    # Include any other strict engines not in priority list
    for e in _STRICT_ENGINES:
        if e in owners:
            continue
        if any(t in (haystacks.get(e) or "") for t in tokens):
            owners.append(e)
    return owners


def correct_key_evidence_engines(analysis: dict, tool_blobs: dict) -> dict:
    """Rewrite wrong key_evidence.source to the engine that owns the fragment (V5.16.8).

    Detection-only (V5.16.3) made the pipeline untrustworthy in practice — reports
    still carried false IDA/Malcat labels. This mutates key_evidence in place so
    verdict/deep-dive artifacts and downstream publish cite the real owner.

    Returns {corrected: int, corrections: [{from, to, needle, ...}]}.
    """
    out: dict = {"corrected": 0, "corrections": []}
    if not isinstance(analysis, dict):
        return out
    evidence = analysis.get("key_evidence")
    if not isinstance(evidence, list) or not evidence:
        return out
    haystacks = build_per_engine_haystacks(tool_blobs or {})
    for item in evidence:
        if not isinstance(item, dict):
            continue
        claimed_list = _normalize_claimed_engines(item.get("source"))
        claimed_list.extend(_normalize_claimed_engines(item.get("query_or_table")))
        claimed_list = [c for c in dict.fromkeys(claimed_list) if c in _STRICT_ENGINES]
        needle = _evidence_needle(item)
        tokens = _needle_tokens(needle)
        if not tokens:
            continue
        owners = _engines_owning_tokens(haystacks, tokens)
        if not owners:
            continue
        # Already honest if any claimed strict engine owns the tokens
        if claimed_list and any(c in owners for c in claimed_list):
            continue
        old_src = item.get("source")
        # Only rewrite when LLM named a strict engine incorrectly (ida/ghidra/…).
        # Leave non-strict labels (cff, goodware_fingerprint, …) alone.
        if not claimed_list:
            continue
        new_eng = owners[0]
        item["source"] = new_eng
        # Drop misleading query labels like "all_imports (via hook candidates)"
        # when they name a wrong engine; keep factual table hints when possible.
        q = str(item.get("query_or_table") or "")
        if any(c in q.lower() for c in claimed_list):
            item["query_or_table"] = f"{new_eng}_evidence"
        item["source_corrected_from"] = old_src
        out["corrections"].append({
            "from": old_src,
            "to": new_eng,
            "needle": (needle or "")[:100],
            "owners": owners[:6],
        })
        out["corrected"] += 1
    return out


def rewrite_report_md_engine_citations(report_md: str, corrections: list[dict]) -> str:
    """Best-effort fix of '(source: ida)' style labels near a corrected needle."""
    import re as _re

    if not report_md or not corrections:
        return report_md or ""
    text = report_md
    for corr in corrections:
        needle = str(corr.get("needle") or "").strip()
        old = str(corr.get("from") or "").strip()
        new = str(corr.get("to") or "").strip()
        if len(needle) < 6 or not old or not new:
            continue
        # Case-insensitive needle window: rewrite source/engine labels nearby
        pattern = _re.compile(
            _re.escape(needle[:80]),
            _re.IGNORECASE,
        )
        for m in list(pattern.finditer(text))[:8]:
            start = max(0, m.start() - 180)
            end = min(len(text), m.end() + 180)
            window = text[start:end]
            fixed = _re.sub(
                rf"(?i)(\b(?:source|engine)\s*[:=]\s*[*`\"]?)({_re.escape(old)})\b",
                rf"\1{new}",
                window,
            )
            if fixed != window:
                text = text[:start] + fixed + text[end:]
    return text


POST_UPX_SECOND_PASS_TOOLS = ("capa", "yara", "floss", "malcat", "pe_imports")


def run_post_upx_second_pass(
    unpacked_path: str,
    *,
    profile: str = "deep",
    parallel: bool = True,
    max_workers: int = 5,
) -> dict:
    """Re-run high-value static tools on UPX-unpacked payload (V5.16.5).

    Does not re-bootstrap Ghidra/IDA (expensive). capa/yara/floss/malcat/pe_imports
    on the unpacked image closes the Rook gap where only the stub was analyzed.
    """
    out: dict = {
        "unpacked_path": unpacked_path,
        "ok": False,
        "tools": {},
        "tool_ok": {},
        "skipped_reason": "",
    }
    if not unpacked_path or not os.path.isfile(unpacked_path):
        out["skipped_reason"] = "missing_unpacked_path"
        return out
    try:
        fmt = _detect_format_for_tools(unpacked_path)
    except Exception:
        fmt = "pe"
    tools_filter = [
        n for n in POST_UPX_SECOND_PASS_TOOLS
        if tool_applies_to_format(n, fmt)
    ]
    if not tools_filter:
        out["skipped_reason"] = f"no_applicable_tools:{fmt}"
        return out
    try:
        fresh = run_all_tools(
            unpacked_path,
            profile=profile,
            tools_filter=list(tools_filter),
            parallel=parallel,
            max_workers=max_workers,
        )
    except Exception as e:
        out["skipped_reason"] = f"run_failed:{e}"
        out["error"] = str(e)
        return out
    tools = {k: v for k, v in fresh.items() if not str(k).startswith("_")}
    out["tools"] = tools
    out["_format"] = fresh.get("_format") or fmt
    out["_timings"] = fresh.get("_timings") or {}
    any_ok = False
    for name in tools_filter:
        ok, why = tool_result_ok(tools.get(name), name)
        out["tool_ok"][name] = {"ok": ok, "why": why}
        if ok:
            any_ok = True
    out["ok"] = any_ok
    if not any_ok:
        out["skipped_reason"] = "all_second_pass_tools_failed"
    return out


_YARA_NOISE_RULES = {
    "domain", "ip", "url", "contains_base64", "base64", "http", "https",
    "email", "md5", "sha1", "sha256",
}
_YARA_FAMILY_HINTS = (
    "rat", "stealer", "trojan", "backdoor", "ransomware", "loader", "botnet",
    "worm", "rootkit", "spyware", "keylogger", "banker", "infostealer",
)


def high_signal_yara_matches(yara: dict | None) -> list[str]:
    """Return non-noise YARA rule names (family / CADRE lab rules)."""
    yara = yara if isinstance(yara, dict) else {}
    out: list[str] = []
    for h in (yara.get("matches") or yara.get("hits") or []):
        if isinstance(h, dict):
            rule = str(h.get("rule") or h.get("name") or "").strip()
        else:
            rule = str(h).strip()
        if not rule:
            continue
        low = rule.lower()
        if low in _YARA_NOISE_RULES:
            continue
        out.append(rule)
    return out


def apply_yara_family_verdict_gate(verdict: dict, yara: dict | None) -> dict:
    """Block clean/benign when high-signal YARA family rules fired.

    Dual-use RATs (NetSupport, etc.) are often branded 'legitimate' by LLMs.
    CADRE lab + family rules must not be cleared solely on signing/PDB branding.
    """
    if not isinstance(verdict, dict):
        return verdict
    if (verdict.get("source") or "") == "goodware_fingerprint":
        return verdict
    rules = high_signal_yara_matches(yara)
    if not rules:
        return verdict
    # Prefer CADRE_* and explicit malware-family tokens
    strong = [
        r for r in rules
        if r.upper().startswith("CADRE_")
        or any(h in r.lower() for h in _YARA_FAMILY_HINTS)
    ]
    if not strong:
        strong = rules  # any non-noise rule still blocks clean
    v_label = (verdict.get("verdict") or "").strip().lower()
    benignish = any(x in v_label for x in ("benign", "clean", "legitimate"))
    if not benignish:
        verdict["yara_family_hits"] = strong
        return verdict
    hold = dict(verdict.get("accuracy_hold") or {})
    hold["yara_family_block"] = True
    hold["yara_rules"] = strong[:12]
    hold["original_verdict"] = verdict.get("verdict")
    hold["original_score"] = verdict.get("score")
    verdict["accuracy_hold"] = hold
    verdict["yara_family_hits"] = strong
    verdict["verdict"] = "malicious" if any(
        r.upper().startswith("CADRE_") or "rat" in r.lower() or "stealer" in r.lower()
        for r in strong
    ) else "suspicious"
    try:
        score = float(verdict.get("score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    verdict["score"] = max(score, 70.0) if "malicious" in verdict["verdict"] else max(score, 50.0)
    if verdict.get("confidence") is not None:
        try:
            verdict["confidence"] = max(int(verdict.get("confidence") or 0), 60)
        except (TypeError, ValueError):
            pass
    verdict["agreement"] = verdict.get("agreement") or "yara_family_override"
    return verdict


def ti_hash_enrich(sha256: str, *, timeout: int = 20) -> dict:
    """Optional VirusTotal + Hybrid Analysis *hash lookup* (no sample download).

    Opt-in: REVAI_TI_ENRICH=1 (default off). Uses VT_API_KEY / HA_API_KEY from
    cadre.env. Fail-safe: never raises; returns {enabled, ok, providers...}.

    Policy: TI is prior-art context only. It must NEVER clear a high-signal local
    YARA hit or incomplete-tool accuracy hold.
    """
    load_env_file(CADRE_ENV)
    out: dict[str, Any] = {
        "enabled": False,
        "ok": False,
        "sha256": sha256,
        "policy": "enrichment_only_never_clears_local_yara_or_tool_gates",
        "providers": {},
    }
    if (os.environ.get("REVAI_TI_ENRICH") or "").strip() not in ("1", "true", "yes", "on"):
        out["reason"] = "REVAI_TI_ENRICH not set"
        return out
    out["enabled"] = True
    import urllib.error
    import urllib.request

    vt_key = (os.environ.get("VT_API_KEY") or "").strip()
    ha_key = (os.environ.get("HA_API_KEY") or "").strip()

    def _get(url: str, headers: dict) -> tuple[bool, Any]:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return True, json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                detail = ""
            return False, f"HTTP {e.code}: {detail}"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    # --- VirusTotal file report (lookup only) ---
    if vt_key:
        ok, payload = _get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            {
                "x-apikey": vt_key,
                "Accept": "application/json",
                "User-Agent": "RevAI-ti-enrich/1.0",
            },
        )
        if ok and isinstance(payload, dict):
            attrs = ((payload.get("data") or {}).get("attributes") or {})
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            harmless = int(stats.get("harmless") or 0)
            undetected = int(stats.get("undetected") or 0)
            names = attrs.get("names") or []
            tags = attrs.get("tags") or []
            out["providers"]["virustotal"] = {
                "ok": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "reputation": attrs.get("reputation"),
                "popular_threat_classification": attrs.get("popular_threat_classification"),
                "names": names[:8],
                "tags": tags[:12],
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        else:
            out["providers"]["virustotal"] = {"ok": False, "error": str(payload)[:240]}
    else:
        out["providers"]["virustotal"] = {"ok": False, "error": "VT_API_KEY not set"}

    # --- Hybrid Analysis hash search (lookup only) ---
    if ha_key:
        ok, payload = _get(
            f"https://www.hybrid-analysis.com/api/v2/search/hash?hash={sha256}",
            {
                "api-key": ha_key,
                "Accept": "application/json",
                "User-Agent": "RevAI-ti-enrich/1.0",
            },
        )
        if ok and isinstance(payload, list):
            if not payload:
                out["providers"]["hybrid_analysis"] = {
                    "ok": False,
                    "error": "no_prior_reports",
                    "result_count": 0,
                    "link": f"https://www.hybrid-analysis.com/sample/{sha256}",
                }
            else:
                top = payload[0] if isinstance(payload[0], dict) else {}
                out["providers"]["hybrid_analysis"] = {
                    "ok": True,
                    "result_count": len(payload),
                    "verdict": top.get("verdict") or top.get("threat_level"),
                    "threat_score": top.get("threat_score"),
                    "type_short": top.get("type_short"),
                    "submit_name": top.get("submit_name"),
                    "vx_family": top.get("vx_family"),
                    "tags": (top.get("tags") or [])[:12],
                    "link": f"https://www.hybrid-analysis.com/sample/{sha256}",
                }
        elif ok and isinstance(payload, dict):
            out["providers"]["hybrid_analysis"] = {
                "ok": True,
                "raw_keys": list(payload.keys())[:12],
                "link": f"https://www.hybrid-analysis.com/sample/{sha256}",
            }
        else:
            out["providers"]["hybrid_analysis"] = {"ok": False, "error": str(payload)[:240]}
    else:
        out["providers"]["hybrid_analysis"] = {"ok": False, "error": "HA_API_KEY not set"}

    out["ok"] = any(
        isinstance(p, dict) and p.get("ok") for p in out["providers"].values()
    )
    # Compact card for LLM prompts
    lines = [
        "### External TI hash enrich (OPTIONAL — prior art only)",
        "POLICY: Local tools + high-signal YARA win. VT/HA clean/unknown MUST NOT "
        "clear malicious/suspicious local evidence. Dual-use RATs stay malicious when CADRE_* YARA fires.",
    ]
    vt = out["providers"].get("virustotal") or {}
    if vt.get("ok"):
        lines.append(
            f"- VirusTotal: malicious={vt.get('malicious')} suspicious={vt.get('suspicious')} "
            f"harmless={vt.get('harmless')} undetected={vt.get('undetected')} "
            f"names={vt.get('names')} tags={vt.get('tags')}"
        )
        ptc = vt.get("popular_threat_classification")
        if ptc:
            lines.append(f"  threat_class={json.dumps(ptc, default=str)[:300]}")
        lines.append(f"  link={vt.get('link')}")
    else:
        lines.append(f"- VirusTotal: unavailable ({vt.get('error')})")
    ha = out["providers"].get("hybrid_analysis") or {}
    if ha.get("ok"):
        lines.append(
            f"- Hybrid Analysis: verdict={ha.get('verdict')} score={ha.get('threat_score')} "
            f"family={ha.get('vx_family')} type={ha.get('type_short')} "
            f"name={ha.get('submit_name')} tags={ha.get('tags')}"
        )
        lines.append(f"  link={ha.get('link')}")
    else:
        lines.append(f"- Hybrid Analysis: unavailable ({ha.get('error')})")
    out["prompt_card"] = "\n".join(lines)
    return out


def apply_citation_confidence_gate(
    analysis: dict,
    tool_blobs: dict,
    *,
    high_conf_threshold: int = 70,
    cap_to: int = 40,
    report_md: str | None = None,
) -> dict:
    """Cap high confidence when key_evidence is missing or ungrounded.

    V5.16.8: auto-correct false engine labels in key_evidence before honesty
    check so standard reports stay trustworthy (wrong source → rewrite to owner).
    Remaining false attributions after correction still hard-fail (V5.16.3).

    Mutates and returns analysis. Skips goodware_fingerprint deterministic path.
    """
    if not isinstance(analysis, dict):
        return analysis
    if (analysis.get("source") or "") == "goodware_fingerprint":
        return analysis
    # Fix wrong source labels first (Remcos/Rook class: claim IDA, fact in Ghidra/Malcat)
    corrections = correct_key_evidence_engines(analysis, tool_blobs)
    analysis["engine_citation_corrections"] = corrections
    md_for_verify = report_md
    if report_md and corrections.get("corrections"):
        md_for_verify = rewrite_report_md_engine_citations(
            report_md, corrections.get("corrections") or [],
        )
        analysis["_report_md_citation_rewritten"] = md_for_verify != report_md
    grounding = verify_key_evidence_grounding(analysis, tool_blobs)
    analysis["citation_grounding"] = grounding
    engine = verify_engine_citation_honesty(
        analysis, tool_blobs, report_md=md_for_verify,
    )
    analysis["engine_citation"] = engine
    try:
        conf = int(analysis.get("confidence") if analysis.get("confidence") is not None
                   else analysis.get("score") or 0)
    except (TypeError, ValueError):
        conf = 0
    hold = dict(analysis.get("accuracy_hold") or {})
    if conf >= high_conf_threshold and not grounding.get("ok"):
        analysis["confidence_capped_from"] = conf
        analysis["confidence"] = min(conf, cap_to)
        if analysis.get("score") is not None:
            try:
                analysis["score"] = min(float(analysis.get("score") or 0), float(cap_to))
            except (TypeError, ValueError):
                pass
        analysis["citations_ungrounded"] = True
        hold["citations_ungrounded"] = True
        hold["citation_reason"] = grounding.get("reason") or "ungrounded"
    if not engine.get("ok"):
        analysis["false_engine_citations"] = True
        hold["false_engine_citations"] = True
        hold["engine_citation_reason"] = engine.get("reason") or "false_engine_attribution"
        # Always cap when engine lies — even below high-conf threshold
        try:
            conf2 = int(analysis.get("confidence") if analysis.get("confidence") is not None
                        else analysis.get("score") or 0)
        except (TypeError, ValueError):
            conf2 = 0
        if conf2 > cap_to:
            analysis["confidence_capped_from"] = analysis.get("confidence_capped_from") or conf2
            analysis["confidence"] = min(conf2, cap_to)
            if analysis.get("score") is not None:
                try:
                    analysis["score"] = min(float(analysis.get("score") or 0), float(cap_to))
                except (TypeError, ValueError):
                    pass
    else:
        # Cleared after auto-correct — do not leave stale hold flags
        analysis.pop("false_engine_citations", None)
        hold.pop("false_engine_citations", None)
        hold.pop("engine_citation_reason", None)
        if corrections.get("corrected"):
            hold["engine_sources_auto_corrected"] = corrections.get("corrected")
    if hold:
        analysis["accuracy_hold"] = hold
    elif "accuracy_hold" in analysis and not analysis.get("accuracy_hold"):
        analysis.pop("accuracy_hold", None)
    return analysis
# MCP_GHIDRA constant removed 2026-07-03: Ghidra now uses the direct
# ghidrasql HTTP client in ghidra_sql_client.py. The MCP transport
# (mcp-ghidra/mcp_ghidra.py) is no longer spawned.
MCP_MALCAT = "/opt/malcat/bin/malcat.mcp.py"
MALCAT_CAPA = os.environ.get("CADRE_MALCAT_CAPA", "/opt/malcat/bin/malcat.capa.py")
GHIDRA_RPC_MCP = "/opt/scripts/ghidra_rpc_mcp.py"
# YARA rules: scan the full flat/ directory by default (440+ rules including
# APT/RANSOM/MALW/RAT/EK families from rule-sets.yar + the 9 case-study
# rules under case-studies/). The 5 hand-curated CADRE_custom.yar rules are
# also in flat/, so the v2 pipeline picks them up automatically.
# Set CADRE_YARA_RULES env var to override (e.g. a single rule file for
# deterministic reproduction).
import os as _os
YARA_RULES = _os.environ.get("CADRE_YARA_RULES", "/opt/samples/rules/flat/*.yar")
# Mandiant/capa-rs rules tree. Includes Malcat 0.9.15 extras merged under
# anti-analysis/, communication/, linking/ (+ _malcat_0915/ marker).
# Malcat native capa still uses /opt/malcat/data/capa/ (not this path).
CAPA_RULES = os.environ.get("CADRE_CAPA_RULES", "/opt/capa-rules")
CAPA_SIGS = os.environ.get("CADRE_CAPA_SIGS", "/opt/capa-signatures")

MAX_ROWS_DEFAULT = 25
# IDA SQL queries run locally on Remnux via idasql (v0.0.17).
# On a raw binary, the first query triggers idalib analysis (~30-60s);
# subsequent queries on the same session are fast (cached in idasql).
IDA_QUERY_TIMEOUT = int(os.environ.get("REVAI_IDA_QUERY_TIMEOUT", "120"))

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
        "timeout": 300,
    },
    # PE import signals — separate analysis (NOT capa). High-signal API map via pefile.
    "pe_imports": {
        "fn": "pe_import_signals",
        "kwargs": {},
        "applies_to": ["pe", "dotnet"],
        "timeout": 30,
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
        "timeout": 180,
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
    # Speakeasy — Unicorn native PE only. Never route .NET/CLI here.
    "speakeasy": {
        "fn": "speakeasy_emulate",
        "kwargs": {},
        "applies_to": ["pe"],
        "timeout": 180,
    },
    # Frida static probe — IAT / availability (works on PE containers incl. .NET)
    "frida_probe": {
        "fn": "frida_static_probe",
        "kwargs": {},
        "applies_to": ["pe", "dotnet"],
        "timeout": 60,
    },
    # Frida full runtime trace — sandbox + native PE only
    "frida_trace": {
        "fn": "frida_trace_runtime",
        "kwargs": {"function_names": []},
        "applies_to": ["pe"],
        "timeout": 120,
    },
    # LIEF — rich binary structure analysis (sections, entropy, imports, overlay, TLS, imphash)
    "lief": {
        "fn": "lief_analyze",
        "kwargs": {},
        "applies_to": ["pe", "elf", "macho", "dotnet"],
        "timeout": 30,
    },
    # pdfid — PDF structure analysis (counts suspicious elements: JS, OpenAction, Launch, etc.)
    "pdfid": {
        "fn": "pdfid_analyze",
        "kwargs": {},
        "applies_to": ["pdf"],
        "timeout": 30,
    },
    # findcrypt — crypto constant detection via Ghidra FindCrypt (AES, SHA, RC4, ChaCha20, RSA, etc.)
    "findcrypt": {
        "fn": "findcrypt_headless",
        "kwargs": {},
        "applies_to": ["pe", "elf", "dotnet"],
        "timeout": 300,
    },
    # diec — packer/compiler/language identification (Detect It Easy CLI)
    "diec": {
        "fn": "diec_analyze",
        "kwargs": {},
        "applies_to": ["pe", "elf", "macho", "dotnet"],
        "timeout": 60,
    },
    # goresym — Go binary symbol recovery (Mandiant GoReSym)
    "goresym": {
        "fn": "goresym_analyze",
        "kwargs": {},
        "applies_to": ["pe", "elf"],
        "timeout": 120,
    },
    # ilspy — .NET C# decompilation (headless ILSpy)
    "ilspy": {
        "fn": "ilspy_decompile",
        "kwargs": {},
        "applies_to": ["dotnet"],
        "timeout": 120,
    },
    # rift — Rust binary analysis (RIFT: Rust version, crates, architecture, compiler)
    "rift": {
        "fn": "rift_analyze",
        "kwargs": {},
        "applies_to": ["pe", "elf"],
        "timeout": 120,
    },
    # pycdc — Python bytecode decompilation (Decompyle++)
    "pycdc": {
        "fn": "pycdc_decompile",
        "kwargs": {},
        "applies_to": ["unknown"],
        "timeout": 60,
    },
    # elf — ELF structural analysis (readelf/objdump/nm)
    "elf": {
        "fn": "elf_analyze",
        "kwargs": {},
        "applies_to": ["elf"],
        "timeout": 30,
    },
    # shellcode — extract shellcode sections from PE + emulate with scdbg
    "shellcode": {
        "fn": "shellcode_extract",
        "kwargs": {},
        "applies_to": ["pe"],
        "timeout": 30,
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
        wall = int(spec.get("timeout", 120) or 120)
        # Honor TOOL_MANIFEST wall time for tools that accept a timeout kwarg
        # (previously ignored — speakeasy always used SPEAKEASY_TIMEOUT=60).
        try:
            import inspect as _inspect
            if "timeout" in _inspect.signature(fn).parameters:
                kwargs.setdefault("timeout", wall)
        except (TypeError, ValueError):
            pass
        tasks.append((tool_name, fn, kwargs, wall))

    def _run_one(name, fn, kwargs, timeout):
        import time as _t
        t0 = _t.time()
        try:
            r = fn(sample_path, **kwargs)
            return name, r, round(_t.time() - t0, 2), None
        except Exception as e:
            return name, {"error": f"{type(e).__name__}: {e}"}, round(_t.time() - t0, 2), str(e)

    results.setdefault("_timings", {})
    if parallel and len(tasks) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_run_one, n, f, k, t): n for n, f, k, t in tasks}
            for fut in futures:
                name, result, dt, err = fut.result()
                if isinstance(result, dict):
                    result.setdefault("duration_s", dt)
                results[name] = result
                results["_timings"][name] = dt
                if err:
                    results["_errors"][name] = err
    else:
        for name, fn, kwargs, timeout in tasks:
            n, r, dt, err = _run_one(name, fn, kwargs, timeout)
            if isinstance(r, dict):
                r.setdefault("duration_s", dt)
            results[n] = r
            results["_timings"][n] = dt
            if err:
                results["_errors"][n] = err
    return results


# Candidate deep-profile tools (filtered by TOOL_MANIFEST applies_to + format).
REQUIRED_DEEP_TOOLS_PE = [
    "malcat", "capa", "pe_imports", "yara", "floss", "dotnet", "r2_decomp",
    "upx", "xor", "speakeasy", "frida_probe",
]
# Allowed to skip without failing the stage (sandbox / format gaps).
OPTIONAL_DEEP_TOOLS = {"frida_trace", "olevba", "peepdf", "malcat"}
# On large samples, capa may honestly fail — do not invent capa; continue with
# malcat / ghidra / ida / pe_imports. Still recorded as soft_failure (not green).
SOFT_FAIL_ON_LARGE = frozenset({"capa"})

# Triage tools that quick_scan already runs — deep must reuse, not re-pay.
CACHEABLE_TRIAGE_TOOLS = frozenset({"malcat", "capa", "pe_imports", "yara", "floss"})


def tool_result_reusable(info: dict | None) -> bool:
    """True if a cached tool result is good enough to skip re-running."""
    if not isinstance(info, dict):
        return False
    if info.get("error"):
        # Accept fail-open salvage (e.g. FLOSS → strings(1)) — do not re-burn timeout.
        return bool(info.get("fail_open") and (info.get("salvaged") or info.get("skipped")))
    if info.get("skipped") and not info.get("fail_open"):
        # Soft skip with no work done — deep may still want to try (rare).
        return False
    return True


def load_quick_tools_cache(sha256: str) -> dict:
    """Load quick_scan/00-tools-raw.json if present."""
    path = Path(LOGS_DIR) / sha256 / "quick_scan" / "00-tools-raw.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def merge_cached_triage_tools(
    tools_results: dict,
    cached: dict,
    *,
    cache_source: str = "quick_scan",
) -> dict:
    """Overlay reusable triage tools from cache; annotate `_cached_from`."""
    if not cached:
        return tools_results
    out = dict(tools_results)
    timings = dict(out.get("_timings") or {})
    cached_list = []
    for name in CACHEABLE_TRIAGE_TOOLS:
        info = cached.get(name)
        if not tool_result_reusable(info):
            continue
        merged = dict(info)
        merged["_cached_from"] = cache_source
        # Keep original duration_s from quick if present; mark reuse as 0 new cost.
        if "duration_s" in merged:
            timings[f"{name}_cached"] = merged["duration_s"]
        timings[name] = 0.0
        out[name] = merged
        cached_list.append(name)
    out["_timings"] = timings
    out["_cache"] = {
        "source": cache_source,
        "reused": cached_list,
        "skipped_rerun": cached_list,
    }
    return out


def run_deep_tools_with_cache(
    sample_path: str,
    sha256: str,
    *,
    profile: str = "deep",
    parallel: bool = True,
    max_workers: int = 10,
) -> dict:
    """Run deep tools once: reuse quick_scan triage cache for capa/floss/yara/malcat."""
    cached = load_quick_tools_cache(sha256)
    reuse_names = [
        n for n in CACHEABLE_TRIAGE_TOOLS
        if tool_result_reusable(cached.get(n))
    ]
    # Run everything applicable except tools we will reuse from cache.
    fmt = _detect_format_for_tools(sample_path)
    to_run = [
        n for n in TOOL_MANIFEST
        if tool_applies_to_format(n, fmt) and n not in reuse_names
    ]
    if to_run:
        fresh = run_all_tools(
            sample_path,
            profile=profile,
            tools_filter=to_run,
            parallel=parallel,
            max_workers=max_workers,
        )
    else:
        fresh = {
            "_format": fmt,
            "_sample_path": sample_path,
            "_errors": {},
            "_timings": {},
        }
    return merge_cached_triage_tools(fresh, cached, cache_source="quick_scan")


def tool_applies_to_format(tool_name: str, fmt: str) -> bool:
    """True if TOOL_MANIFEST says this tool should run for fmt."""
    spec = TOOL_MANIFEST.get(tool_name)
    if not spec:
        return True
    applies = spec.get("applies_to")
    if not applies:
        return True
    return fmt in applies or "unknown" in applies


def required_deep_tools_for(fmt: str) -> list[str]:
    """Required deep tools for a format — only tools that apply (never Speakeasy on .NET)."""
    out: list[str] = []
    for name in REQUIRED_DEEP_TOOLS_PE:
        if name in OPTIONAL_DEEP_TOOLS:
            continue
        if tool_applies_to_format(name, fmt):
            out.append(name)
    return out


def tool_result_ok(result: Any, tool_name: str | None = None) -> tuple[bool, str]:
    """Return (ok, why) for a single tool result dict.

    Format not-applicable skips still pass. CAPA/FLOSS fail_open without real
    signal fails (V5.11 accuracy) — other tools may still fail_open documentedly.
    """
    if result is None:
        return False, "missing"
    if not isinstance(result, dict):
        return True, "non-dict"

    reason = str(result.get("reason") or result.get("error") or "")
    not_applicable = result.get("skipped") and (
        reason.startswith("not_applicable") or "supports PE only" in reason
    )
    if not_applicable:
        return True, f"skipped:{reason or 'not_applicable'}"

    name = (tool_name or "").lower()
    looks_capa = name == "capa" or (
        "rule_count" in result
        and result.get("engine") in (
            "capa", "capa-rs", "capa-pefile", "capa-ghidra", "malcat-capa",
        )
    )
    looks_floss = name == "floss" or "floss_ok" in result or "floss_profile" in result
    looks_pe_imports = name in ("pe_imports", "pe_import_signals") or result.get("engine") == "pe_imports"

    if looks_capa:
        # Never treat import-bridge / pe_imports as capa success.
        if result.get("bridge") or result.get("engine") in ("import_bridge", "pe_imports"):
            return False, "capa_incomplete:not_real_capa"
        rules = result.get("top_rules") or []
        count = int(result.get("rule_count") or (len(rules) if isinstance(rules, list) else 0))
        if result.get("error") or result.get("fail_open") or result.get("skipped") or result.get("incomplete"):
            return False, f"capa_incomplete:{result.get('error') or result.get('reason') or 'fail_open'}"
        if count <= 0 and not rules:
            return False, "capa_empty"
        return True, "ok"

    if looks_pe_imports:
        if result.get("error") or result.get("fail_open"):
            return False, f"pe_imports_incomplete:{result.get('error') or result.get('reason')}"
        # Zero high-signal APIs is still a successful scan (common for thin .NET).
        if "import_count" in result or "signals" in result:
            return True, "ok"
        return False, "pe_imports_empty"

    if name == "yara" or result.get("engine") in ("yara", "yara-x", "yara_x"):
        # YARA gate: a scan that never ran is NOT ok. Zero matches from a
        # completed scan is a valid, honest result — but batch_errors means
        # the scanner engine failed and no rules were actually run.
        if result.get("error") or result.get("fail_open"):
            return False, f"yara_incomplete:{result.get('error') or result.get('reason') or 'fail_open'}"
        if result.get("batch_errors"):
            return False, f"yara_incomplete:batch_errors={len(result['batch_errors'])}"
        if result.get("skipped") and str(result.get("reason") or result.get("skipped")).startswith("not_applicable"):
            return True, "skipped:not_applicable"
        return True, "ok"

    if looks_floss:
        if result.get("floss_ok") and int(result.get("string_count") or 0) > 0:
            return True, "ok"
        if result.get("fail_open") or result.get("error") or result.get("skipped"):
            return False, f"floss_incomplete:{result.get('error') or result.get('reason') or 'fail_open'}"
        if int(result.get("string_count") or 0) <= 0:
            return False, "floss_empty"
        return True, "ok"

    if result.get("fail_open"):
        return True, f"fail_open:{result.get('error') or result.get('reason') or 'ok'}"
    if result.get("error"):
        if result.get("skipped"):
            return True, f"skipped:{result.get('error')}"
        return False, f"error:{str(result.get('error'))[:160]}"
    if result.get("skipped"):
        return True, f"skipped:{result.get('reason') or result.get('skipped')}"
    return True, "ok"


def _tools_sample_is_large(tools_results: dict) -> bool:
    """True if any tool result carries a ≥ LARGE_SIZE_BYTES sample size."""
    for name in ("capa", "floss", "pe_imports", "malcat"):
        r = tools_results.get(name)
        if not isinstance(r, dict):
            continue
        sz = int(r.get("sample_size") or r.get("size_bytes") or 0)
        if sz >= LARGE_SIZE_BYTES:
            return True
    return False


def evaluate_tool_checklist(
    tools_results: dict | None,
    required: list[str] | None = None,
) -> dict:
    """Hard-gate: every *format-applicable* required tool must be ok.

    Uses tools_results['_format'] (set by run_all_tools) so Speakeasy is not
    required — and must not be invoked — for format=dotnet.

    Large-sample policy: capa may soft-fail (recorded, not green) when primary
    tools malcat + pe_imports are ok — so one capa timeout does not kill the
    pipeline. Never invent capa success.

    Returns:
        {
          "ok": bool,
          "format": str,
          "required": [name, ...],
          "tools": {name: {"ok": bool, "why": str}},
          "hard_failures": [name, ...],
          "soft_failures": [name, ...],
          "missing": [name, ...],
          "not_applicable": [name, ...],
        }
    """
    tools_results = tools_results or {}
    fmt = str(tools_results.get("_format") or "unknown")
    if required is None:
        req = required_deep_tools_for(fmt)
        not_applicable = [
            n for n in REQUIRED_DEEP_TOOLS_PE
            if n not in OPTIONAL_DEEP_TOOLS and n not in req
        ]
    else:
        # Still drop tools that do not apply to this format (e.g. FLOSS on ELF).
        req = [n for n in required if tool_applies_to_format(n, fmt)]
        not_applicable = [
            n for n in required if n not in req and n not in OPTIONAL_DEEP_TOOLS
        ]
    tools_meta: dict[str, dict] = {}
    hard: list[str] = []
    soft: list[str] = []
    missing: list[str] = []
    large = _tools_sample_is_large(tools_results)
    for name in req:
        if name in OPTIONAL_DEEP_TOOLS:
            continue
        if name not in tools_results:
            missing.append(name)
            tools_meta[name] = {"ok": False, "why": "missing"}
            hard.append(name)
            continue
        ok, why = tool_result_ok(tools_results.get(name), tool_name=name)
        tools_meta[name] = {"ok": ok, "why": why}
        if not ok:
            hard.append(name)
    # Soft-fail capa on large when primary RE/triage tools are green.
    if large and hard:
        malcat_ok = tool_result_ok(tools_results.get("malcat"), "malcat")[0]
        pe_ok = (
            tool_result_ok(tools_results.get("pe_imports"), "pe_imports")[0]
            if "pe_imports" in tools_results or "pe_imports" in req
            else True
        )
        if malcat_ok and pe_ok:
            still_hard = []
            for name in hard:
                if name in SOFT_FAIL_ON_LARGE:
                    soft.append(name)
                    tools_meta[name] = {
                        "ok": False,
                        "why": f"soft_fail_large:{tools_meta.get(name, {}).get('why')}",
                        "soft": True,
                    }
                else:
                    still_hard.append(name)
            hard = still_hard
    for name in not_applicable:
        tools_meta[name] = {"ok": True, "why": f"not_applicable:{fmt}"}
    return {
        "ok": len(hard) == 0,
        "format": fmt,
        "required": req,
        "tools": tools_meta,
        "hard_failures": hard,
        "soft_failures": soft,
        "missing": missing,
        "not_applicable": not_applicable,
        "large_sample": large,
    }


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


# --- Pipeline modes (standard vs large) ------------------------------------
# See docs/PIPELINE-MODES.md
PIPELINE_MODE_STANDARD = "standard"
PIPELINE_MODE_LARGE = "large"
LARGE_SIZE_BYTES = int(os.environ.get("CADRE_LARGE_SIZE_BYTES", str(30 * 1024 * 1024)))
LARGE_FUNC_COUNT = int(os.environ.get("CADRE_LARGE_FUNC_COUNT", "8000"))
LARGE_EMBEDDED_PE = int(os.environ.get("CADRE_LARGE_EMBEDDED_PE", "3"))


def update_session(sha256: str, fields: dict) -> dict:
    """Merge fields into the session JSON and rewrite the registry file."""
    session = load_session(sha256)
    session.update(fields)
    path = SESSIONS_DIR / f"{sha256}.json"
    path.write_text(json.dumps(session, indent=2, default=str))
    return session


def classify_pipeline_mode(
    session: dict,
    intake_validation: dict | None = None,
) -> dict:
    """Decide standard vs large from size / binder / func-count signals.

    Returns:
        {"mode": "standard"|"large", "reasons": [...], "signals": {...}}
    """
    reasons: list[str] = []
    sample_path = session.get("sample_path") or ""
    size = 0
    if sample_path and os.path.exists(sample_path):
        try:
            size = os.path.getsize(sample_path)
        except OSError:
            size = 0

    ft = session.get("file_type") or {}
    compound = ft.get("compound")
    embedded = int(ft.get("embedded_pe_count") or 0)

    ghidra_funcs = 0
    ida_funcs = 0
    if intake_validation:
        summaries = intake_validation.get("tool_summaries") or {}
        g = summaries.get("ghidra") or intake_validation.get("ghidra") or {}
        i = summaries.get("ida") or intake_validation.get("ida") or {}
        # intake_v2 labels: functions / imports / strings (see validate_engine_outputs)
        for key in ("functions", "funcs", "func_count", "function_count"):
            if ghidra_funcs == 0 and isinstance(g.get(key), int):
                ghidra_funcs = g[key]
            if ida_funcs == 0 and isinstance(i.get(key), int):
                ida_funcs = i[key]

    max_funcs = max(ghidra_funcs, ida_funcs)

    if size >= LARGE_SIZE_BYTES:
        reasons.append(f"size {size} >= {LARGE_SIZE_BYTES} ({size / (1024 * 1024):.1f} MB)")
    if compound:
        reasons.append(f"compound={compound}")
    if embedded >= LARGE_EMBEDDED_PE:
        reasons.append(f"embedded_pe_count {embedded} >= {LARGE_EMBEDDED_PE}")
    if max_funcs >= LARGE_FUNC_COUNT:
        reasons.append(f"func_count {max_funcs} >= {LARGE_FUNC_COUNT}")

    mode = PIPELINE_MODE_LARGE if reasons else PIPELINE_MODE_STANDARD
    return {
        "mode": mode,
        "reasons": reasons,
        "signals": {
            "size_bytes": size,
            "compound": compound,
            "embedded_pe_count": embedded,
            "ghidra_funcs": ghidra_funcs,
            "ida_funcs": ida_funcs,
        },
    }


def resolve_pipeline_mode(
    session: dict,
    intake_validation: dict | None = None,
    override: str | None = None,
) -> dict:
    """Resolve mode with precedence: CLI/env override > session > auto-classify."""
    forced = (override or os.environ.get("CADRE_PIPELINE_MODE") or "").strip().lower()
    if forced in (PIPELINE_MODE_STANDARD, PIPELINE_MODE_LARGE):
        return {
            "mode": forced,
            "reasons": [f"override={forced}"],
            "signals": {},
            "source": "override",
        }
    existing = (session.get("pipeline_mode") or "").strip().lower()
    if existing in (PIPELINE_MODE_STANDARD, PIPELINE_MODE_LARGE):
        return {
            "mode": existing,
            "reasons": session.get("pipeline_mode_reasons") or ["from session"],
            "signals": session.get("pipeline_mode_signals") or {},
            "source": "session",
        }
    classified = classify_pipeline_mode(session, intake_validation)
    classified["source"] = "auto"
    return classified


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
      1. REVAI_LLM_API_KEY
      2. REVAI_LLM_API_KEY inside CADRE_ENV file

    For public deployments, set REVAI_LLM_API_KEY in the environment so no
    file-based secret path is required.
    """
    v = os.environ.get("REVAI_LLM_API_KEY")
    if v:
        return v.strip().strip('"').strip("'")
    if not CADRE_ENV.exists():
        raise RuntimeError(
            "LLM API key not configured. Set REVAI_LLM_API_KEY "
            f"in the environment, or place it in {CADRE_ENV}"
        )
    for line in CADRE_ENV.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == "REVAI_LLM_API_KEY":
            return v.strip().strip('"').strip("'")
    raise RuntimeError(
        "LLM API key not configured. Set REVAI_LLM_API_KEY "
        f"in the environment, or place REVAI_LLM_API_KEY in {CADRE_ENV}"
    )


_DEFAULT_MODEL = os.environ.get("REVAI_LLM_MODEL", "")


def get_planner_model() -> str:
    """Agentic RE planner / tool loop (fast, low-latency)."""
    return (
        os.environ.get("REVAI_LLM_PLANNER_MODEL") or _DEFAULT_MODEL
    ).strip() or _DEFAULT_MODEL


def get_verdict_model() -> str:
    """Verdict / validation / report judges (highest quality available).

    Env priority:
      REVAI_LLM_VERDICT_MODEL → REVAI_LLM_MODEL (if not flash) → REVAI_LLM_MODEL
    Flash pins are never used for judgment.
    """
    explicit = (os.environ.get("REVAI_LLM_VERDICT_MODEL") or "").strip()
    if explicit:
        return explicit
    env_model = (os.environ.get("REVAI_LLM_MODEL") or "").strip()
    if env_model and "flash" not in env_model.lower():
        return env_model
    return _DEFAULT_MODEL


def get_llm_model() -> str:
    """Default judgment model for pipeline LLM calls → Pro (not agentic planner)."""
    return get_verdict_model()


def get_llm_api_url() -> str:
    """Return the LLM API base URL from env, and ensure it points to the
    chat-completions endpoint. No hardcoded default.

    Some providers configure the FULL endpoint (…/chat/completions) and
    others a base URL (…/v1 or …/step_plan/v1). Append the OpenAI-compatible
    path only when the configured URL does not already end with it.
    """
    url = os.environ.get("REVAI_LLM_API_URL")
    if not url:
        raise ValueError("REVAI_LLM_API_URL is not set in the environment")
    url = url.rstrip("/")
    if url.endswith("/chat/completions"):
        return url
    return f"{url}/chat/completions"


def get_llm_reasoning() -> str | None:
    """Return the requested reasoning/thinking effort from env, or None.

    Some models support reasoning with effort values such as 'high' or 'max'.
    Set REVAI_LLM_REASONING=max to request the highest reasoning effort.
    Set it to 'disabled' or 'none' to disable thinking.
    """
    return os.environ.get("REVAI_LLM_REASONING")


def _build_reasoning_body(reasoning: str | None) -> dict:
    """Build the reasoning/thinking control parameters for the LLM body.

    Returns a dict that can be merged into the chat-completions request body.
    """
    if not reasoning:
        return {}
    r = reasoning.strip().lower()
    if r in ("disabled", "none", "off"):
        return {"thinking": {"type": "disabled"}}
    # OpenAI-format reasoning_effort: values include 'max' and 'high'.
    return {
        "thinking": {"type": "enabled"},
        "reasoning_effort": r,
    }


def llm_judge(prompt: str, model: str | None = None, max_retries: int = 3) -> dict:
    """Call the configured LLM chat API with retries. Returns the FULL response dict.

    Configuration is read from environment at runtime (no hardcoded defaults):
      - REVAI_LLM_MODEL    (required)
      - REVAI_LLM_API_URL  (required)
      - REVAI_LLM_API_KEY  (required; falls back to REVAI_LLM_API_KEY in cadre.env)
      - REVAI_LLM_REASONING (optional: 'max', 'high', 'low', 'disabled', etc.)
    """
    import time
    import urllib.request
    import urllib.error

    api_key = load_api_key()
    effective_model = (model or get_llm_model()).strip()
    api_url = get_llm_api_url()
    # Pro judgment: use REVAI_LLM_REASONING (max/high). Flash agentic: no Pro reasoning
    # unless REVAI_LLM_PLANNER_REASONING is set.
    if "flash" in effective_model.lower():
        reasoning = os.environ.get("REVAI_LLM_PLANNER_REASONING") or "disabled"
    else:
        reasoning = get_llm_reasoning() or "max"

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
        "max_tokens": 65536,
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
                data = json.loads(resp.read().decode())
                llm_usage_journal(model=effective_model, response=data,
                                  note=f"attempt={attempt}")
                return data
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


_LLM_USAGE_LOCK = __import__("threading").Lock()


def llm_usage_journal(
    *,
    model: str,
    response: dict,
    stage: str = "",
    note: str = "",
) -> None:
    """Append one LLM call's usage (tokens + cost) to a JSONL journal.

    Env `REVAI_LLM_USAGE_JOURNAL` (path) enables it — used by the provider
    benchmark (#9) for documented per-model evidence. Records OpenRouter's
    real `usage.cost` (USD) when present, reasoning tokens, response model.
    Never raises: journaling must not break the pipeline.
    """
    try:
        journal = os.environ.get("REVAI_LLM_USAGE_JOURNAL") or ""
        if not journal:
            return
        usage = (response or {}).get("usage") or {}
        details = usage.get("completion_tokens_details") or {}
        entry = {
            "ts": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "stage": stage or os.path.basename(sys.argv[0] or ""),
            "request_model": model,
            "response_model": (response or {}).get("model"),
            "generation_id": (response or {}).get("id"),
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "reasoning_tokens": details.get("reasoning_tokens"),
            "cached_tokens": (usage.get("prompt_tokens_details") or {}).get("cached_tokens"),
            "cost_usd": usage.get("cost"),  # OpenRouter native field
            "cost_details": usage.get("cost_details"),
            "note": note,
        }
        with _LLM_USAGE_LOCK:
            with open(journal, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


# Content keys LLMs may use for the markdown body. Providers / gateways differ:
#   openai-style: markdown · some providers: mark · generic: content/body/text
LLM_CONTENT_KEYS = ("markdown", "mark", "content", "body", "text", "report", "output")


def normalize_llm_content(data: dict | None) -> str:
    """Extract markdown body from a parsed LLM JSON dict, tolerating key variants.

    Accepts any of LLM_CONTENT_KEYS as the report body. If none present and the
    dict carries only scalar fields, returns "". Callers fall back to raw text.
    """
    if not isinstance(data, dict):
        return ""
    for k in LLM_CONTENT_KEYS:
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            return v
    # Nested variants: {"report": {"markdown": ...}} or {"data": {"mark": ...}}
    for k in ("report", "data", "result", "response"):
        nested = data.get(k)
        if isinstance(nested, dict):
            for k2 in LLM_CONTENT_KEYS:
                v = nested.get(k2)
                if isinstance(v, str) and v.strip():
                    return v
    return ""


def normalize_llm_json(content: str) -> dict:
    """Parse LLM content into a dict, tolerating fences, prose wrap, and key variants.

    Guarantees the returned dict has a 'markdown' key if any content key existed.
    Falls back to {'markdown': content} for raw-markdown output.
    """
    s = (content or "").strip()
    # Strip markdown fences
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    data: dict | None = None
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            data = parsed
    except json.JSONDecodeError:
        pass
    if data is None:
        start, end = s.find("{"), s.rfind("}")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(s[start : end + 1])
                if isinstance(parsed, dict):
                    data = parsed
            except json.JSONDecodeError:
                pass
    if data is None:
        # Raw markdown output
        return {"title": "RE Report", "markdown": s, "source": "llm_raw_markdown"}
    md = normalize_llm_content(data)
    if md:
        data["markdown"] = md
    data.setdefault("source", "llm_judge")
    return data



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
    in 2026-07-03 (see ghidra_sql_client.py). This
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


def _resolve_malcat_capa() -> str | None:
    """Return path to Malcat native capa CLI if present (0.9.15+)."""
    cand = (os.environ.get("CADRE_MALCAT_CAPA") or MALCAT_CAPA or "").strip()
    if cand and os.path.isfile(cand):
        return cand
    for p in (
        "/opt/malcat/bin/malcat.capa.py",
        str(Path("/opt/malcat/bin") / "malcat.capa.py"),
    ):
        if os.path.isfile(p):
            return p
    which = shutil.which("malcat.capa.py")
    return which


def _resolve_capa_bin() -> tuple[str, str]:
    """Pick legacy capa binary (capa-rs / Mandiant). Malcat is separate.

    Returns (binary_path_or_name, engine_label).
    Env:
      CADRE_CAPA_BIN=/path/to/capa-rs|capa
      CADRE_CAPA_ENGINE=auto|malcat|capa-rs|capa  (default auto)
    """
    explicit = (os.environ.get("CADRE_CAPA_BIN") or "").strip()
    if explicit:
        if "malcat" in explicit.lower():
            return explicit, "malcat-capa"
        label = "capa-rs" if "capa-rs" in explicit or "capars" in explicit else "capa"
        return explicit, label
    engine = (os.environ.get("CADRE_CAPA_ENGINE") or "auto").strip().lower()
    rs_candidates = [
        "/opt/revai/bin/capa-rs",
        "/usr/local/bin/capa-rs",
        str(Path.home() / ".local/bin/capa-rs"),
        "capa-rs",
    ]
    if engine in ("malcat", "malcat-capa", "malcat_capa"):
        mc = _resolve_malcat_capa()
        return (mc or MALCAT_CAPA), "malcat-capa"
    if engine in ("capa-rs", "capars", "rs"):
        for cand in rs_candidates:
            if os.path.isfile(cand) or shutil.which(cand):
                return cand, "capa-rs"
        return "capa-rs", "capa-rs"
    if engine in ("capa", "python", "mandiant"):
        return "capa", "capa"
    # auto → prefer capa-rs binary for legacy fallback chain
    for cand in rs_candidates:
        if os.path.isfile(cand) or shutil.which(cand):
            return cand, "capa-rs"
    return "capa", "capa"


def _capa_rule_fields(v: dict) -> tuple[list, list, str | None]:
    """Pull attack/mbc/namespace from flat or Malcat nested meta."""
    meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
    attack = v.get("attack") if v.get("attack") is not None else v.get("attacks")
    if attack is None:
        attack = meta.get("attack") if meta.get("attack") is not None else meta.get("attacks")
    mbc = v.get("mbc") if v.get("mbc") is not None else meta.get("mbc")
    ns = v.get("namespace") or meta.get("namespace")
    return (attack or []), (mbc or []), ns


def _normalize_capa_rules(payload: dict) -> dict:
    """Normalize capa / capa-rs / malcat-capa JSON into {name: {attack, mbc}}."""
    rules = payload.get("rules")
    if isinstance(rules, dict) and rules:
        out = {}
        for k, v in rules.items():
            if not isinstance(v, dict):
                out[str(k)] = {"attack": [], "mbc": []}
                continue
            attack, mbc, ns = _capa_rule_fields(v)
            out[str(k)] = {
                "attack": attack,
                "mbc": mbc,
                "namespace": ns,
            }
        return out
    # Some capa-rs builds emit a list
    if isinstance(rules, list):
        out = {}
        for item in rules:
            if not isinstance(item, dict):
                continue
            name = item.get("meta", {}).get("name") if isinstance(item.get("meta"), dict) else None
            name = name or item.get("name") or item.get("rule")
            if not name:
                continue
            attack, mbc, ns = _capa_rule_fields(item)
            out[str(name)] = {
                "attack": attack,
                "mbc": mbc,
                "namespace": ns,
            }
        return out
    matches = payload.get("matches") or payload.get("capabilities")
    if isinstance(matches, list):
        out = {}
        for item in matches:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("rule") or item.get("capability")
            if not name:
                continue
            attack, mbc, ns = _capa_rule_fields(item)
            out[str(name)] = {
                "attack": attack,
                "mbc": mbc,
                "namespace": ns,
            }
        return out
    return {}


def _capa_rules_payload(payload: dict) -> dict:
    """Normalize capa / capa-rs JSON to rules dict (name → meta)."""
    rules = _normalize_capa_rules(payload)
    if not rules and isinstance(payload.get("capability_namespaces"), dict):
        rules = {
            str(name): {"attack": [], "mbc": [], "namespace": ns}
            for name, ns in payload["capability_namespaces"].items()
        }
    return rules


def _capa_success(rules: dict, *, timeout: int, size: int, dt: float,
                  engine: str, capa_bin: str, **extra) -> dict:
    return {
        "rule_count": len(rules),
        "top_rules": sorted(
            [
                {
                    "name": k,
                    "attack": (v.get("attack", []) if isinstance(v, dict) else []),
                    "mbc": (v.get("mbc", []) if isinstance(v, dict) else []),
                }
                for k, v in rules.items()
            ],
            key=lambda x: -len(x.get("attack", [])) - len(x.get("mbc", [])),
        )[:15],
        "timeout_s": timeout,
        "sample_size": size,
        "duration_s": dt,
        "engine": engine,
        "capa_bin": capa_bin,
        **extra,
    }


def _capa_mandiant_timeout(size: int) -> int:
    """Wall budget for Mandiant capa (accuracy path)."""
    env_t = os.environ.get("CADRE_CAPA_TIMEOUT")
    if env_t and env_t.isdigit():
        return int(env_t)
    if size >= LARGE_SIZE_BYTES:
        # Full Mandiant on ≥30MB Rust/binders routinely exceeds 15m — use bridge.
        return 180
    if size >= 2 * 1024 * 1024:
        return 300
    return 900


# High-signal WinAPI → analyst labels (pe_imports tool — NOT capa).
_PE_IMPORT_SIGNALS = (
    ("VirtualAllocEx", "allocate_memory", ["T1055"]),
    ("WriteProcessMemory", "write_process_memory", ["T1055"]),
    ("CreateRemoteThread", "create_remote_thread", ["T1055"]),
    ("NtUnmapViewOfSection", "unmap_section_view", ["T1055"]),
    ("QueueUserAPC", "queue_apc", ["T1055"]),
    ("SetThreadContext", "set_thread_context", ["T1055"]),
    ("IsDebuggerPresent", "check_debugger", ["T1622"]),
    ("CheckRemoteDebuggerPresent", "check_remote_debugger", ["T1622"]),
    ("CryptEncrypt", "crypto_encrypt", ["T1573"]),
    ("BCryptEncrypt", "bcrypt_encrypt", ["T1573"]),
    ("InternetOpen", "http_client", ["T1071.001"]),
    ("WinHttpOpen", "winhttp_client", ["T1071.001"]),
    ("URLDownloadToFile", "download_file", ["T1105"]),
    ("CreateService", "create_service", ["T1543.003"]),
    ("RegSetValue", "set_registry_value", ["T1112"]),
    ("CreateProcess", "create_process", ["T1106"]),
    ("ShellExecute", "shell_execute", ["T1106"]),
    ("LoadLibrary", "load_library", ["T1129"]),
    ("GetProcAddress", "get_proc_address", ["T1129"]),
    ("VirtualProtect", "change_memory_protection", ["T1055"]),
    ("VirtualAlloc", "allocate_memory", ["T1055"]),
)


def pe_import_signals(sample_path: str) -> dict:
    """Separate pipeline tool: PE import table → high-signal API map.

    This is NOT capa and must never be labeled as capa success. Runs for PE/dotnet
    alongside capa so large samples still get structured import evidence when
    Mandiant capa cannot finish.
    """
    t0 = time.time()
    try:
        size = os.path.getsize(sample_path) if sample_path and os.path.exists(sample_path) else 0
    except OSError:
        size = 0
    imports_seen: list[str] = []
    try:
        import pefile  # type: ignore
        pe = pefile.PE(sample_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in getattr(entry, "imports", []) or []:
                name = (imp.name.decode("utf-8", "ignore") if imp.name else "") or ""
                if name:
                    imports_seen.append(name)
        pe.close()
    except Exception as e:
        return {
            "error": f"pe_import_signals failed: {e}",
            "engine": "pe_imports",
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "signal_count": 0,
            "signals": [],
        }
    lower_keys = [n.lower() for n in imports_seen]
    signals: list[dict] = []
    seen_labels: set[str] = set()
    for api, label, tactics in _PE_IMPORT_SIGNALS:
        if any(api.lower() in k for k in lower_keys):
            if label in seen_labels:
                continue
            seen_labels.add(label)
            signals.append({
                "label": label,
                "api_match": api,
                "attack": tactics,
            })
    return {
        "engine": "pe_imports",
        "sample_size": size,
        "duration_s": round(time.time() - t0, 2),
        "import_count": len(imports_seen),
        "signal_count": len(signals),
        "signals": signals,
        "hint": "PE import high-signal map (pefile). Not capa.",
    }


def _capa_mandiant_backend(
    sample_path: str, *, backend: str, timeout: int, size: int, t0: float,
    fallback_from: str = "",
) -> dict:
    """Run Mandiant capa with an explicit -b backend (pefile/ghidra/…)."""
    try:
        proc = subprocess.run(
            ["capa", "-j", "-b", backend, "-r", CAPA_RULES, "-s", CAPA_SIGS, sample_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        dt = round(time.time() - t0, 2)
        if proc.returncode == 0 and (proc.stdout or "").strip():
            j = json.loads(proc.stdout or "{}")
            rules = _capa_rules_payload(j if isinstance(j, dict) else {})
            if rules:
                extra = {"engine_fallback_from": fallback_from} if fallback_from else {}
                return _capa_success(
                    rules, timeout=timeout, size=size, dt=dt,
                    engine=f"capa-{backend}", capa_bin="capa", **extra,
                )
        return {
            "error": f"capa -b {backend} rc={proc.returncode}:{(proc.stderr or '')[-300:]}",
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": dt,
            "engine": f"capa-{backend}",
            "incomplete": True,
        }
    except subprocess.TimeoutExpired:
        return {
            "error": f"capa -b {backend} timed out after {timeout}s",
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "engine": f"capa-{backend}",
            "incomplete": True,
        }
    except Exception as e:
        return {
            "error": str(e),
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "engine": f"capa-{backend}",
            "incomplete": True,
        }


def _capa_mandiant_only(
    sample_path: str, *, timeout: int, size: int, t0: float, fallback_from: str = ""
) -> dict:
    """Run Mandiant capa with its own timeout budget."""
    try:
        proc = subprocess.run(
            ["capa", "-j", "-r", CAPA_RULES, "-s", CAPA_SIGS, sample_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        dt = round(time.time() - t0, 2)
        if proc.returncode == 0:
            j = json.loads(proc.stdout or "{}")
            rules = _capa_rules_payload(j if isinstance(j, dict) else {})
            if rules:
                extra = {"engine_fallback_from": fallback_from} if fallback_from else {}
                return _capa_success(
                    rules, timeout=timeout, size=size, dt=dt,
                    engine="capa", capa_bin="capa", **extra,
                )
            return {
                "error": "capa returned empty rules",
                "timeout_s": timeout,
                "sample_size": size,
                "duration_s": dt,
                "engine": "capa",
            }
        return {
            "error": f"capa rc={proc.returncode}",
            "stderr": (proc.stderr or "")[-500:],
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": dt,
            "engine": "capa",
        }
    except subprocess.TimeoutExpired:
        return {
            "error": f"capa timed out after {timeout}s",
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "engine": "capa",
            "hint": "Increase CADRE_CAPA_TIMEOUT; capa is required for accuracy.",
        }
    except Exception as e:
        return {
            "error": str(e),
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "engine": "capa",
        }


def _capa_malcat_timeout(size: int) -> int:
    """Wall budget for Malcat native capa (orders of magnitude faster)."""
    env_t = os.environ.get("CADRE_MALCAT_CAPA_TIMEOUT")
    if env_t and env_t.isdigit():
        return int(env_t)
    if size >= LARGE_SIZE_BYTES:
        return 180
    if size >= 2 * 1024 * 1024:
        return 90
    return 60


def _capa_malcat_only(
    sample_path: str, *, timeout: int, size: int, t0: float | None = None,
    fallback_from: str | None = None,
) -> dict:
    """Run Malcat 0.9.15+ native capa CLI (`malcat.capa.py -j`)."""
    t0 = t0 if t0 is not None else time.time()
    capa_py = _resolve_malcat_capa()
    if not capa_py:
        return {
            "error": "malcat.capa.py not found",
            "incomplete": True,
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "engine": "malcat-capa",
        }
    try:
        proc = subprocess.run(
            [sys.executable, capa_py, "-j", sample_path],
            capture_output=True, text=True, timeout=timeout,
        )
        dt = round(time.time() - t0, 2)
        payload = None
        stdout = (proc.stdout or "").strip()
        if proc.returncode == 0 and stdout:
            try:
                payload = json.loads(stdout)
            except Exception:
                payload = None
        if isinstance(payload, dict):
            rules = _capa_rules_payload(payload)
            if rules:
                extra = {"fallback_from": fallback_from} if fallback_from else {}
                return _capa_success(
                    rules, timeout=timeout, size=size, dt=dt,
                    engine="malcat-capa", capa_bin=capa_py, **extra,
                )
        return {
            "error": "malcat-capa empty/no rules",
            "incomplete": True,
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": dt,
            "engine": "malcat-capa",
            "capa_bin": capa_py,
            "returncode": proc.returncode,
            "stderr": (proc.stderr or "")[:400],
        }
    except subprocess.TimeoutExpired:
        return {
            "error": "malcat-capa timeout",
            "incomplete": True,
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "engine": "malcat-capa",
            "capa_bin": capa_py,
        }
    except Exception as e:
        return {
            "error": str(e),
            "incomplete": True,
            "timeout_s": timeout,
            "sample_size": size,
            "duration_s": round(time.time() - t0, 2),
            "engine": "malcat-capa",
            "capa_bin": capa_py,
        }


def capa_analyze(sample_path: str, timeout: int | None = None) -> dict:
    """Run capa with accuracy-first engine selection (V5.11 + Malcat 0.9.15).

    Policy (CADRE_CAPA_ENGINE=auto default):
      - Prefer Malcat native capa (`malcat.capa.py`) when installed — fast + real rules
      - Else / on miss: <2MB → Mandiant; ≥2MB → capa-rs → Mandiant (± pefile on large)
      - Forced: malcat | capa-rs | capa/mandiant
      - Never invent capa via pe_imports; never treat empty/timeout as checklist green
    """
    try:
        size = os.path.getsize(sample_path) if sample_path and os.path.exists(sample_path) else 0
    except OSError:
        size = 0

    mandiant_timeout = timeout if timeout is not None else _capa_mandiant_timeout(size)
    malcat_timeout = timeout if timeout is not None else _capa_malcat_timeout(size)
    engine_env = (os.environ.get("CADRE_CAPA_ENGINE") or "auto").strip().lower()
    large = size >= LARGE_SIZE_BYTES

    def _capa_incomplete(reason: str, *, tried: list[str]) -> dict:
        return {
            "error": f"capa incomplete: {reason}",
            "incomplete": True,
            "timeout_s": mandiant_timeout,
            "sample_size": size,
            "duration_s": 0,
            "engine": "capa",
            "tried": tried,
            "hint": (
                "Use pe_imports + malcat + ghidra/ida for evidence. "
                "Install Malcat ≥0.9.15 for native capa (malcat.capa.py)."
            ),
        }

    def _after_rs_miss(reason: str) -> dict:
        tried = [reason]
        if large:
            brief = _capa_mandiant_only(
                sample_path, timeout=min(90, mandiant_timeout), size=size,
                t0=time.time(), fallback_from=reason,
            )
            tried.append("mandiant-brief")
            if int(brief.get("rule_count") or 0) > 0:
                return brief
            pe_feat = _capa_mandiant_backend(
                sample_path, backend="pefile", timeout=90, size=size,
                t0=time.time(), fallback_from=f"{reason}+mandiant_miss",
            )
            tried.append("capa-pefile")
            if int(pe_feat.get("rule_count") or 0) > 0:
                return pe_feat
            return _capa_incomplete(
                f"{reason}; mandiant+pefile backends failed",
                tried=tried,
            )
        return _capa_mandiant_only(
            sample_path, timeout=mandiant_timeout, size=size,
            t0=time.time(), fallback_from=reason,
        )

    def _try_capa_rs() -> dict:
        t0 = time.time()
        out_path = None
        rs_timeout = min(60, mandiant_timeout)
        rs_bin = None
        for cand in (
            "/opt/revai/bin/capa-rs",
            "/usr/local/bin/capa-rs",
            str(Path.home() / ".local/bin/capa-rs"),
            "capa-rs",
        ):
            if os.path.isfile(cand) or shutil.which(cand):
                rs_bin = cand
                break
        if not rs_bin:
            return _after_rs_miss("no-capa-rs")
        try:
            import tempfile
            fd, out_path = tempfile.mkstemp(prefix="capa-rs-", suffix=".json")
            os.close(fd)
            argv = [rs_bin, "--rules-path", CAPA_RULES, "-o", out_path, sample_path]
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=rs_timeout,
            )
            dt = round(time.time() - t0, 2)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            smda_fail = "SMDAError" in stdout or "SMDAError" in stderr
            payload = None
            out_bytes = Path(out_path).stat().st_size if out_path and os.path.isfile(out_path) else 0
            if proc.returncode == 0 and out_bytes > 0 and not smda_fail:
                try:
                    payload = json.loads(Path(out_path).read_text())
                except Exception:
                    payload = None
            if isinstance(payload, dict):
                rules = _capa_rules_payload(payload)
                if rules:
                    return _capa_success(
                        rules, timeout=rs_timeout, size=size, dt=dt,
                        engine="capa-rs", capa_bin=rs_bin,
                    )
            return _after_rs_miss("capa-rs-smda" if smda_fail else "capa-rs-empty")
        except subprocess.TimeoutExpired:
            return _after_rs_miss("capa-rs-timeout")
        except FileNotFoundError:
            return _after_rs_miss("capa-rs-missing")
        except Exception as e:
            return {
                "error": str(e),
                "timeout_s": mandiant_timeout,
                "sample_size": size,
                "duration_s": round(time.time() - t0, 2),
                "engine": "capa-rs",
                "capa_bin": rs_bin,
            }
        finally:
            if out_path:
                try:
                    os.unlink(out_path)
                except OSError:
                    pass

    # Forced Mandiant
    if engine_env in ("capa", "python", "mandiant"):
        if large:
            return _after_rs_miss("mandiant-forced-large")
        return _capa_mandiant_only(
            sample_path, timeout=mandiant_timeout, size=size, t0=time.time()
        )

    # Forced capa-rs (skip malcat)
    if engine_env in ("capa-rs", "capars", "rs"):
        return _try_capa_rs()

    # Forced malcat only
    if engine_env in ("malcat", "malcat-capa", "malcat_capa"):
        hit = _capa_malcat_only(
            sample_path, timeout=malcat_timeout, size=size, t0=time.time()
        )
        if int(hit.get("rule_count") or 0) > 0:
            return hit
        return _capa_incomplete(
            hit.get("error") or "malcat-capa miss",
            tried=["malcat-capa"],
        )

    # auto: Malcat native first (0.9.15+), then legacy chain
    if _resolve_malcat_capa():
        hit = _capa_malcat_only(
            sample_path, timeout=malcat_timeout, size=size, t0=time.time()
        )
        if int(hit.get("rule_count") or 0) > 0:
            return hit
        # fall through with reason recorded by next stage
        miss_reason = hit.get("error") or "malcat-capa-miss"
    else:
        miss_reason = "malcat-capa-missing"

    if size < 2 * 1024 * 1024:
        return _capa_mandiant_only(
            sample_path, timeout=mandiant_timeout, size=size,
            t0=time.time(), fallback_from=miss_reason,
        )

    return _try_capa_rs()


def _collect_floss_strings(
    data: dict, max_strings: int = 80
) -> tuple[list[str], dict[str, int], int]:
    """Flatten floss --json → (sample strings, per-category counts, total count).

    ``max_strings`` caps the returned sample for LLM/cards.
    ``total`` sums category lengths (accuracy signal; avoids full unique-set
    on 100k+ string dumps).
    """
    def _iter_strings(items):
        for item in items or []:
            if isinstance(item, dict):
                s = item.get("string") or item.get("s") or ""
            else:
                s = str(item)
            s = s.strip()
            if len(s) >= 6:
                yield s[:200]

    per_category: dict[str, int] = {}
    sample: list[str] = []
    seen_sample: set[str] = set()
    total = 0

    priority_categories = (
        "decoded_strings",
        "stack_strings",
        "tight_strings",
        "language_strings",
        "language_strings_missed",
        "static_strings",
    )

    def _consume(cat: str, items) -> None:
        nonlocal total
        n = 0
        for s in _iter_strings(items):
            n += 1
            total += 1
            if len(sample) < max_strings and s not in seen_sample:
                seen_sample.add(s)
                sample.append(s)
        per_category[cat] = n

    inner = data.get("strings")
    if isinstance(inner, dict):
        for cat in priority_categories:
            _consume(cat, inner.get(cat) or [])
        for cat in inner.keys():
            if cat not in priority_categories:
                _consume(cat, inner.get(cat) or [])
    else:
        for cat in priority_categories:
            _consume(cat, data.get(cat) or [])

    return sample, per_category, total


def floss_extract(sample_path: str, max_strings: int = 80, timeout: int | None = None) -> dict:
    """Run FLOSS string extraction (V5.11).

    Always pass ``--language none`` so Rust/Go language extractors cannot hang
    large binaries (FLOSS 3.1 still auto-runs Rust under ``--only static``).

    ``timeout`` caps the size-based default so callers (e.g. quick_scan) can
    enforce the TOOL_MANIFEST wall budget.
    """
    import os as _os
    fmt = _detect_format_for_tools(sample_path)
    if fmt not in ("pe", "dotnet"):
        return {
            "skipped": True,
            "fail_open": True,
            "reason": f"not_applicable:{fmt}",
            "error": f"FLOSS supports PE only (got {fmt})",
            "string_count": 0,
            "strings": [],
            "floss_profile": "skipped",
            "duration_s": 0.0,
        }
    try:
        size = _os.path.getsize(sample_path)
    except OSError:
        size = 0
    floss_limit = 0x1000000  # 16 MiB — hard limit in floss 3.x for decode
    profile = (_os.environ.get("CADRE_FLOSS_PROFILE") or "auto").strip().lower()
    if profile == "auto":
        if size >= LARGE_SIZE_BYTES or size > floss_limit:
            profile = "static"
        elif size >= 2 * 1024 * 1024:
            profile = "static_stack"
        else:
            profile = "full"
    # --language none: required for Rust/large PEs (hangs otherwise).
    lang_args = ["--language", "none"]
    if profile == "full" and size <= floss_limit:
        floss_timeout = 600
        only_args: list[str] = []
    elif profile == "static_stack" and size <= floss_limit:
        floss_timeout = 180
        only_args = ["--only", "static", "stack", "tight"]
    else:
        profile = "static"
        floss_timeout = 180
        only_args = ["--only", "static"]
    if size >= 2 * 1024 * 1024 and profile == "full":
        floss_timeout = min(floss_timeout, 180)
    if timeout is not None:
        floss_timeout = min(floss_timeout, int(timeout))

    def _strings_fallback(reason: str) -> dict:
        out = {
            "floss_ok": False,
            "static_only": True,
            "size_bytes": size,
            "size_exceeded_deobfuscate_limit": size > floss_limit,
            "fallback": "strings(1)",
            "fail_open": True,
            "reason": reason,
            "error": reason,
            "floss_profile": profile,
        }
        try:
            sp = subprocess.run(
                ["strings", "-a", "-n", "8", sample_path],
                capture_output=True, text=True, timeout=120,
            )
            lines = [l.strip() for l in (sp.stdout or "").splitlines()
                     if 6 <= len(l.strip()) <= 300]
            out["static_strings"] = lines[:max_strings]
            out["static_string_count"] = len(lines)
            out["strings"] = lines[:max_strings]
            out["string_count"] = len(lines)
            if lines:
                out["salvaged"] = True
        except Exception as e:
            out["static_strings_error"] = str(e)
            out["fail_open"] = True
        return out

    t0 = time.time()
    cmd = ["floss", *lang_args, *only_args, "--json", sample_path]
    proc = None
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=floss_timeout,
        )
    except subprocess.TimeoutExpired:
        # Full/decoded extraction can stall on installers/packers. Degrade to
        # static-only (fast, high-value) and retry before giving up. stack/tight
        # can still be pathological on installer-packed samples, so skip them.
        print(f"[floss_extract] {profile} timed out; retrying with --only static", flush=True)
        try:
            proc = subprocess.run(
                ["floss", "--language", "none", "--only", "static", "--json", sample_path],
                capture_output=True, text=True, timeout=min(floss_timeout, 120),
            )
            if proc.returncode == 0 and (proc.stdout or "").strip():
                profile = "static"
        except subprocess.TimeoutExpired:
            proc = None
        if proc is None:
            return _strings_fallback(f"floss timed out after {floss_timeout}s")
    except Exception as e:
        return _strings_fallback(f"floss error: {e}")

    dt = round(time.time() - t0, 2)
    if proc.returncode == 0 and (proc.stdout or "").strip():
        try:
            data = json.loads(proc.stdout)
        except Exception as e:
            return _strings_fallback(f"floss json parse failed: {e}")
        strings, per_category, total = _collect_floss_strings(
            data, max_strings=max_strings
        )
        if total <= 0:
            return _strings_fallback("floss returned zero strings")
        return {
            "floss_ok": True,
            "string_count": total,
            "strings_sampled": len(strings),
            "strings": strings,
            "per_category": per_category,
            "raw_key_total": len(data) if isinstance(data, dict) else 0,
            "floss_profile": profile,
            "floss_language": "none",
            "duration_s": dt,
            "size_bytes": size,
            "static_only": profile == "static" or size > floss_limit,
            "size_exceeded_deobfuscate_limit": size > floss_limit,
        }
    return _strings_fallback(
        f"floss rc={proc.returncode}:{(proc.stderr or '')[-200:]}"
    )


def yara_scan(sample_path: str, rules_glob: str = YARA_RULES) -> dict:
    """Scan a sample with YARA rules via the in-process yara-x engine.

    The `rules_glob` argument can be:
      - a single file path: "/opt/.../rules.yar"
      - a shell glob:       "/opt/.../flat/*.yar"
      - a comma-separated list: "/path/a.yar,/path/b.yar"

    Uses the `yara_x` Python module (installed with requirements.txt) — no
    external `yr` binary required. A scan that never runs (module missing, no
    rules matched the glob, zero rules compiled) returns `error` + `fail_open`
    so the tool gate hard-fails instead of pretending a zero-match scan.
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
        return {
            "error": f"no YARA rule files matched glob: {rules_glob!r}",
            "fail_open": True, "rule_count": 0, "matches": [], "engine": "yara-x",
        }
    try:
        from yara_x import Compiler, Scanner
    except ImportError:
        return {
            "error": "yara_x python module not installed (pip install yara-x)",
            "fail_open": True, "rule_count": 0, "matches": [], "engine": "yara-x",
        }

    compiler = Compiler()
    compiler.enable_includes(True)
    compile_errors: list[str] = []
    ok_files = 0
    for r in candidates:
        try:
            with open(r, encoding="utf-8", errors="replace") as fh:
                compiler.add_source(fh.read(), origin=r)
            ok_files += 1
        except Exception as e:
            compile_errors.append(f"{r}: {e}")
    if ok_files == 0:
        return {
            "error": f"yara: 0/{len(candidates)} rule files compiled: {compile_errors[0] if compile_errors else 'unknown'}",
            "fail_open": True, "rule_count": 0, "matches": [], "engine": "yara-x",
        }
    try:
        rules = compiler.build()
    except Exception as e:
        return {
            "error": f"yara compile failed: {e}", "fail_open": True,
            "rule_count": 0, "matches": [], "engine": "yara-x",
        }

    scanner = Scanner(rules)
    scanner.set_timeout(120)
    try:
        res = scanner.scan_file(sample_path)
    except Exception as e:
        return {
            "error": f"yara scan failed: {e}", "fail_open": True,
            "rule_count": 0, "matches": [], "engine": "yara-x",
        }

    all_matches: list[dict] = []
    for mr in res.matching_rules:
        str_hits = []
        for p in list(mr.patterns)[:8]:
            for m in list(p.matches)[:1]:
                str_hits.append({
                    "id": p.identifier,
                    "offset": int(m.offset),
                    "length": int(m.length),
                    "xor_key": int(m.xor_key) if m.xor_key is not None else None,
                })
        all_matches.append({
            "rule": mr.identifier,
            "path": sample_path,
            "strings": str_hits,
        })

    result: dict[str, Any] = {
        "rule_count": len(all_matches),
        "matches": all_matches[:30],
        "engine": "yara-x",
        "rules_compiled": ok_files,
    }
    if compile_errors:
        result["compile_errors"] = compile_errors[:10]
        result["incomplete"] = True
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
    # MCP handshake can race (server prints PERSONAL-use WARNING then
    # closes before initialize). Retry once before failing the stage.
    last: dict | None = None
    for attempt in range(1, 3):
        last = _malcat_analyze_once(sample_path, views=views, profile=profile, limits=limits)
        err = str((last or {}).get("error") or "")
        if not err.startswith("malcat_analyze top-level: MCP malcat closed"):
            return last
        print(
            f"[malcat_analyze] MCP closed on attempt {attempt}/2 — retrying",
            flush=True,
        )
    return last or {"error": "malcat_analyze failed with no result"}


def _malcat_analyze_once(sample_path: str, views: list[str] | None = None,
                         profile: str = "deep", limits: dict | None = None) -> dict:
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

    try:
        cli = McpJsonClient(
            MCP_MALCAT,
            extra_args=["--num_analyses", "5"],
            name="malcat",
            scopes=list(DEFAULT_MCP_SCOPES.values()),
        )
    except Exception as e:
        return {"error": f"malcat_analyze top-level: {e}"}
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


# --- Verdict calibration (plan #5, from keygenme false-positive findings) ---
# Malicious REQUIRES behavioral intent. Obfuscation/protection/packing/entropy
# are NEUTRAL signals — they appear identically in crackmes, games, and
# commercial protectors. The intent list is deliberately conservative (only
# active malicious behavior); the protection list is broad.
_BEHAVIORAL_INTENT_SIGNALS = (
    # capability / prose vocabulary
    "file encrypt", "encrypt file", "ransomware", "cryptolocker", "delete file",
    "overwrite file", "destroy file", "c2", "command and control", "beacon",
    "exfiltrat", "credential", "keylog", "password dump", "token theft",
    "persistence", "registry run", "startup", "scheduled task",
    "service install", "lateral", "wmi exec", "disable defender", "disable av",
    "kill process", "patch amsi", "etw", "network share", "data theft",
    "infosteal", "drop payload", "mail theft", "spyware",
    # tool rule-name vocabulary (YARA rule names / capa rule names as emitted
    # by the tools — behavioral, NOT neutral protection)
    "win_token", "escalate_priv", "screenshot", "win_registry", "anti_dbg",
    "adjusttokenprivileges", "token manipulation", "token theft",
    "screenshot capture", "screen capture", "create remote thread",
    "process injection", "inject", "injection", "keylogg", "getkeystate",
    "isdebuggerpresent", "outputdebugstring", "setthreadcontext",
    "writeprocessmemory", "virtualallocex", "createremotethread",
    "modify access privileges", "delete registry key", "set registry value",
    "keylogging", "dump credential", "lsass", "sam dump", "ntds",
    "persistence mechanism", "run key", "registry persistence",
    "steal", "exfil", "upload", "data exfiltration",
    "internetopen", "winhttp", "urlmon", "socket", "connect to",
    "command execution", "shellcode", "loader", "dropper", "downloader",
)
_PROTECTION_SIGNALS = (
    "obfuscat", "packed", "packer", "xor", "entropy", "anti-debug", "anti-vm",
    "vm protect", "themid", "custom vm", "spaghetti", "encode data",
    "encrypt data", "high entropy", "import table", "packing", "crypter",
)


def calibrate_verdict(verdict: dict, evidence_text: str) -> dict:
    """Verdict calibration gate — symmetric, evidence-owned (2026-08-07).

    CEILING: malicious → suspicious when evidence is protection/obfuscation
    only with NO behavioral-intent signal (keygenme fix).

    FLOOR: benign/legitimate → suspicious when behavioral-intent signals ARE
    present in the tool evidence (vidar fix). A binary whose deterministic
    tools fire behavioral rules (token manipulation, screenshot, privilege
    escalation, anti-debug, C2, credential, persistence, exfiltration) can
    never be reported benign/legitimate — that is the evidence floor, and a
    real reverse engineer would never clear it on brand metadata alone.
    Suspicious vs malicious stays the LLM's interpretation; the floor only
    removes the impossible "clean" verdict.

    Both directions are recorded (`verdict_calibrated`/`verdict_raised` +
    reason) for audit transparency. Returns a NEW dict when changed.
    """
    if not isinstance(verdict, dict):
        return verdict
    label = str(verdict.get("verdict") or "").strip().lower()
    text = str(evidence_text or "").lower()
    has_intent = any(s in text for s in _BEHAVIORAL_INTENT_SIGNALS)
    # CEILING: malicious claimed but no behavioral intent anywhere in evidence
    if "malicious" in label:
        if has_intent:
            return verdict
        has_protection = any(s in text for s in _PROTECTION_SIGNALS)
        if not has_protection:
            return verdict
        out = dict(verdict)
        out["verdict"] = "suspicious"
        try:
            out["score"] = min(int(out.get("score") or 0), 50)
        except (TypeError, ValueError):
            out["score"] = 50
        out["verdict_calibrated"] = True
        out["calibration_reason"] = (
            "protection/obfuscation signals present but no behavioral-intent "
            "evidence; malicious capped to suspicious (obfuscation is neutral)"
        )
        return out
    # FLOOR: benign/legitimate claimed but behavioral-intent evidence exists
    if label in ("benign", "clean", "legitimate", "likely_legitimate") and has_intent:
        out = dict(verdict)
        out["verdict"] = "suspicious"
        try:
            out["score"] = max(int(out.get("score") or 0), 50)
        except (TypeError, ValueError):
            out["score"] = 50
        out["verdict_raised"] = True
        out["calibration_reason"] = (
            "behavioral-intent signals present in tool evidence (YARA/capa/"
            "imports); benign/legitimate cannot stand — raised to suspicious "
            "(evidence floor); dual-use branding does not clear the sample"
        )
        return out
    return verdict


# --- T4 helpers: emulation, HITL, sandbox, goodware, report template ---

SPEAKEASY_TIMEOUT = int(os.environ.get("CADRE_SPEAKEASY_TIMEOUT", "180"))
GOODWARE_DIR = Path("/opt/samples/goodware")
HITL_DIR = Path("/tmp/cadre-hitl")
REPORT_MASTER_SECTIONS = [
    "Executive Summary",
    "1. Sample Identification",
    "2. Classification",
    "3. Background & Family Lineage",
    "4. Static Analysis",
    "5. Behavioral Analysis",
    "6. Network Analysis & C2",
    "7. Capability Assessment",
    "8. Attribution",
    "9. Indicators of Compromise",
    "10. Detection Rules",
    "11. MITRE ATT&CK Mapping",
    "12. Containment, Eradication, Recovery",
    "13. Recommendations",
    "14. Appendix A: Evidence Trail",
    "15. Appendix B: Module Inventory",
    "16. Author + Sign-off",
]

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


_HIGH_SIGNAL_STRING_RE = re.compile(
    r"encrypt|ransom|pubkey|crypt|http|https|mutex|bitcoin|onion|wallet|"
    r"virtualprotect|loadlibrary|getproc|kernel32|files?\s*encrypt|"
    r"upx|cmd\.exe|powershell|schtasks|\\\\|://",
    re.I,
)


def _rights_cell(row: dict) -> str:
    """Normalize section rights from Malcat layout (string or bool flags)."""
    rights = row.get("rights")
    if isinstance(rights, str) and rights.strip():
        return rights.strip()
    flags = []
    if row.get("read") or row.get("is_read"):
        flags.append("R")
    if row.get("write") or row.get("is_write"):
        flags.append("W")
    if row.get("execute") or row.get("is_exec") or row.get("exec"):
        flags.append("X")
    return "".join(flags) or "-"


def _layout_phys_size(row: dict):
    return row.get("physical_size", row.get("phys_size", row.get("size", "?")))


def _layout_virt_size(row: dict):
    return row.get("virtual_size", row.get("virt_size", row.get("vsize", "-")))


def format_sql_evidence_brief(sql_evidence: dict | None, *, max_rows: int = 40) -> str:
    """Render Ghidra/IDA SQL result sets for technical reports."""
    if not sql_evidence or not isinstance(sql_evidence, dict):
        return "(no SQL evidence pack)"
    lines: list[str] = []
    for eng in ("ghidra", "ida"):
        items = sql_evidence.get(eng)
        if not isinstance(items, list) or not items:
            continue
        lines.append(f"### {eng.upper()} SQL")
        for item in items:
            if not isinstance(item, dict):
                continue
            label = item.get("label") or "?"
            res = item.get("result") or {}
            rows = res.get("rows") or []
            cols = res.get("columns") or []
            if label in (
                "db_info",
                "all_imports_fallback",
                "exports",
                "string_refs",
                "crypto_net_xrefs",
                "suspicious_imports_data_items",
            ) and label != "all_imports":
                if label == "db_info" and rows:
                    lines.append(f"- **{label}**: {len(rows)} row(s)")
                    for row in rows[:8]:
                        if isinstance(row, dict):
                            lines.append(f"  - {json.dumps(row, default=str)[:200]}")
                continue
            interesting = label in (
                "all_imports",
                "suspicious_imports",
                "function_metrics",
                "top_complexity",
                "top_size",
                "memory_blocks",
                "segments",
                "entries",
                "ioc_strings",
                "all_strings",
                "callgraph_hot",
            )
            if not interesting and not rows:
                continue
            lines.append(f"- **{label}** (n={len(rows)})")
            show = rows[:max_rows] if interesting else rows[:5]
            for row in show:
                if not isinstance(row, dict):
                    continue
                if cols:
                    slim = {k: row.get(k) for k in cols[:8]}
                else:
                    slim = row
                lines.append(f"  - `{json.dumps(slim, default=str)[:220]}`")
        lines.append("")
    return "\n".join(lines) if lines else "(no SQL rows)"


def append_technical_evidence_appendix(narrative_md: str, technical_evidence: str) -> str:
    """Always attach the full evidence pack so reports cannot be theory-only."""
    marker = "\n## Appendix: Full Structured Evidence Pack\n"
    body = (narrative_md or "").strip()
    if marker.strip() in body:
        body = body.split(marker.strip())[0].rstrip()
    evidence = (technical_evidence or "").strip()
    if not evidence:
        return body + "\n"
    return f"{body}{marker}\n{evidence}\n"


def load_dynamic_pack(sha: str, logs_dir: Path | None = None) -> dict | None:
    """Load Flare/ELF dynamic pack from logs/<sha>/dynamic/ (research helpers).

    NOT used by core publish/section spine (2026-07-23). Analyst-optional tooling
    under the dynamic helpers may still call this. Returns None when missing.
    """
    root = Path(logs_dir) if logs_dir else LOGS_DIR
    dyn = root / sha / "dynamic"
    if not dyn.is_dir():
        return None

    def _j(name: str):
        p = dyn / name
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8-sig"))
        except Exception:
            return None

    mem_dir = dyn / "memory"
    mem_files: list[str] = []
    if mem_dir.is_dir():
        mem_files = sorted(
            str(p.relative_to(dyn)).replace("\\", "/")
            for p in mem_dir.rglob("*")
            if p.is_file()
        )[:80]

    analyst_md = ""
    an_path = dyn / "ANALYST-NEXT.md"
    if an_path.is_file():
        try:
            analyst_md = an_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            analyst_md = ""

    pcap_dir = dyn / "network_raw"
    pcaps = sorted(p.name for p in pcap_dir.glob("*.pcap")) if pcap_dir.is_dir() else []

    return {
        "path": str(dyn),
        "present": True,
        "meta": _j("META.json") or {},
        "job_meta": _j("META.job.json") or {},
        "frida_summary": _j("frida_summary.json"),
        "procmon_summary": _j("procmon_summary.json"),
        "network": _j("network.json"),
        "network_intel": _j("network_intel.json"),
        "process_snapshot": _j("process_snapshot.json"),
        "analyst_next": _j("analyst_next.json"),
        "analyst_next_md": analyst_md,
        "memory_files": mem_files,
        "pcaps": pcaps,
        "has_procmon_csv": (dyn / "procmon.csv").is_file(),
        "has_frida_trace": (dyn / "frida_trace.json").is_file()
        or (dyn / "frida_trace.jsonl").is_file(),
    }


def format_flare_dynamic_evidence(pack: dict | None) -> str:
    """Markdown card for Flare/ELF dynamic artifacts (research — not core publish)."""
    if not pack or not pack.get("present"):
        return "(no Flare/ELF dynamic pack — run dynamic_run_v2 or skip)"

    lines: list[str] = ["## Flare / Sandbox Dynamic (analyst-optional)", ""]
    meta = pack.get("meta") or {}
    job = pack.get("job_meta") or {}
    lines.append(f"- **ok**: {meta.get('ok', job.get('ok', '?'))}")
    lines.append(f"- **schema**: {meta.get('schema_version', '?')}")
    lines.append(f"- **skipped**: {meta.get('skipped', False)}")
    if meta.get("error"):
        lines.append(f"- **error**: {meta.get('error')}")
    lines.append(
        f"- **pe_sieve_requested**: {meta.get('pe_sieve_requested', job.get('pe_sieve_enabled', False))}"
    )
    lines.append(f"- **pe_sieve_ran**: {meta.get('pe_sieve_ran', job.get('pe_sieve_ran', False))}")
    lines.append(
        f"- **snapshot_restore_required**: "
        f"{meta.get('snapshot_restore_required', job.get('snapshot_restore_required', True))}"
    )
    lines.append(
        "- **policy**: Dynamic is analyst-optional — not merged into core RE reports"
    )
    lines.append("")

    fs = pack.get("frida_summary")
    if isinstance(fs, dict):
        lines.append("### Frida summary")
        for k in ("status", "api_count", "unique_apis", "call_count", "top_apis", "error"):
            if k in fs and fs[k] not in (None, "", [], {}):
                lines.append(f"- **{k}**: `{json.dumps(fs[k], default=str)[:300]}`")
        # common alternate shapes
        apis = fs.get("apis") or fs.get("top_calls") or fs.get("by_api")
        if apis and "top_apis" not in fs:
            lines.append(f"- **apis**: `{json.dumps(apis, default=str)[:800]}`")
        lines.append("")

    ps = pack.get("procmon_summary")
    if isinstance(ps, dict):
        lines.append("### Procmon summary")
        for k in ("status", "row_count", "process_count", "top_operations", "interesting", "error"):
            if k in ps and ps[k] not in (None, "", [], {}):
                lines.append(f"- **{k}**: `{json.dumps(ps[k], default=str)[:400]}`")
        lines.append(f"- **procmon.csv present**: {pack.get('has_procmon_csv')}")
        lines.append("")

    net = pack.get("network")
    if isinstance(net, dict):
        lines.append("### Network (FakeNet / capture summary)")
        lines.append(f"```json\n{json.dumps(net, indent=2, default=str)[:2500]}\n```")
        lines.append("")

    ni = pack.get("network_intel")
    if isinstance(ni, dict):
        lines.append("### network_intel (tshark enrich)")
        for k in ("dns", "http_hosts", "tls_sni", "pcap_count", "note", "status"):
            if k in ni and ni[k] not in (None, "", [], {}):
                lines.append(f"- **{k}**: `{json.dumps(ni[k], default=str)[:500]}`")
        lines.append("")

    if pack.get("pcaps"):
        lines.append(f"- **pcaps**: {', '.join(pack['pcaps'][:10])}")
    if pack.get("memory_files"):
        lines.append(f"- **memory dumps** ({len(pack['memory_files'])}):")
        for mf in pack["memory_files"][:25]:
            lines.append(f"  - `{mf}`")
    else:
        lines.append("- **memory dumps**: none (see ANALYST-NEXT Memory To-Do)")
    lines.append("")
    return "\n".join(lines)


def append_analyst_next_appendix(narrative_md: str, pack: dict | None) -> str:
    """Append ANALYST-NEXT.md (research helper — not core publish)."""
    marker = "\n## Appendix: Analyst next actions\n"
    body = (narrative_md or "").rstrip()
    if marker.strip() in body:
        body = body.split(marker.strip())[0].rstrip()
    if not pack or not pack.get("present"):
        return body + "\n"
    md = (pack.get("analyst_next_md") or "").strip()
    if not md:
        an = pack.get("analyst_next") or {}
        items = an.get("items") or []
        if not items:
            return body + "\n"
        lines = [
            marker,
            "",
            "_Generated from `analyst_next.json` (ANALYST-NEXT.md missing)._",
            "",
            "> Agents must not mark analyst_only items complete unless an analyst ran them.",
            "",
        ]
        for it in items:
            who = "ANALYST" if it.get("analyst_only") else "script-or-analyst"
            lines.append(f"### P{it.get('priority')} — {it.get('title')} `[{who}]`")
            lines.append("")
            lines.append(f"**Why:** {it.get('why')}")
            lines.append("")
        return body + "\n".join(lines) + "\n"
    return f"{body}{marker}\n{md}\n"


def format_malcat_evidence(
    malcat_result: dict | None,
    *,
    max_strings: int = 80,
    max_anomalies: int = 40,
    max_yara: int = 30,
    max_imports: int = 80,
    max_constants: int = 40,
    max_sections: int = 24,
    max_decomp: int = 6,
    max_carved: int = 20,
    max_virtual: int = 20,
    max_structs: int = 30,
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
    views = mc.get("views") or {}
    lines: list[str] = []
    out = lines.append

    # --- Basic file information ---
    out("### Malcat File Summary")
    fs = mc.get("file_summary") or {}
    if not fs:
        out("(no file summary)")
    else:
        info = []
        # Support both legacy and current Malcat field names
        aliases = [
            ("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"),
            ("size", "file_size"), ("file_size", "file_size"),
            ("type", "type"), ("format", "format"), ("architecture", "architecture"),
            ("compiler", "compiler"), ("linker", "linker"),
            ("entrypoint", "entrypoint"), ("entrypoint_ea", "entrypoint_ea"),
            ("subsystem", "subsystem"), ("is_dll", "is_dll"), ("is_driver", "is_driver"),
            ("is_packed", "is_packed"), ("entropy", "entropy"), ("overlay_size", "overlay_size"),
            ("file_name", "file_name"),
        ]
        seen = set()
        for label, key in aliases:
            if key in seen:
                continue
            v = fs.get(key)
            if v not in (None, "", 0, False):
                if isinstance(v, (bytes, bytearray)):
                    v = v.decode("ascii", errors="ignore").rstrip("\x00")
                info.append(f"{label}: {v}")
                seen.add(key)
        if info:
            out("```")
            for item in info:
                out(item)
            out("```")
        out("")

    # --- File layout / sections ---
    layout = fs.get("layout") or views.get("sections") or []
    if layout:
        out("### File Layout (sections/regions)")
        out("| Name | EA | Physical | Virtual | Entropy | Rights |")
        out("|---|---|---|---|---|---|")
        for r in layout[:max_sections]:
            if not isinstance(r, dict):
                continue
            name = r.get("name", r.get("struct_name", "?"))
            ea = r.get("effective_address", r.get("ea", r.get("start", "-")))
            out(
                f"| {name} | {ea} | {_layout_phys_size(r)} | {_layout_virt_size(r)} | "
                f"{r.get('entropy', '?')} | {_rights_cell(r)} |"
            )
        out("")

    # --- YARA (Malcat) ---
    yara = views.get("yara_hits") or mc.get("yara_hits") or []
    if yara:
        out(f"### Malcat YARA / Signatures ({len(yara)})")
        out("| Rule | Category | Type | Reliability | Description |")
        out("|---|---|---|---|---|")
        for y in yara[:max_yara]:
            if not isinstance(y, dict):
                continue
            rule = y.get("id") or y.get("rule") or y.get("name") or "?"
            cat = y.get("category") or y.get("tags") or "-"
            typ = y.get("type") or y.get("danger") or y.get("level") or "-"
            rel = y.get("reliability", "-")
            desc = (y.get("description") or "")[:80]
            out(f"| {rule} | {cat} | {typ} | {rel} | {desc} |")
        out("")

    # --- Anomalies (top-level or views) ---
    anoms = mc.get("anomalies") or views.get("anomalies") or []
    if anoms:
        out(f"### Anomalies ({len(anoms)})")
        out("| Name | Level | Category | Hits | Description |")
        out("|---|---|---|---|---|")
        # Sort high level first when possible
        def _lvl(a):
            try:
                return -int(a.get("level") or 0)
            except Exception:
                return 0
        for a in sorted([x for x in anoms if isinstance(x, dict)], key=_lvl)[:max_anomalies]:
            name = a.get("name", "?")
            level = a.get("level", "?")
            cat = a.get("category", "?")
            hits = a.get("num_hits", a.get("hits", 1))
            desc = (a.get("desc") or a.get("description") or "")[:100]
            out(f"| {name} | {level} | {cat} | {hits} | {desc} |")
        out("")

    # --- High-signal anomaly locations ---
    locs = views.get("anomaly_locations") or {}
    if locs:
        out("### Anomaly Locations (high-signal)")
        for name, samples in list(locs.items())[:12]:
            out(f"- **{name}**")
            for s in (samples or [])[:5]:
                if isinstance(s, dict):
                    ea = s.get("ea", "?")
                    ctx = (s.get("context") or "")[:160]
                    out(f"  - `{ea}`: {ctx}")
                else:
                    out(f"  - `{s}`")
        out("")

    # --- High-signal strings first ---
    strs = views.get("strings") or []
    high = []
    for s in strs:
        if not isinstance(s, dict):
            continue
        summary = (s.get("summary") or s.get("string") or s.get("value") or "")
        if summary and _HIGH_SIGNAL_STRING_RE.search(summary):
            high.append(s)
    if high:
        out(f"### High-Signal Strings ({len(high)} matched keywords; engine=malcat)")
        out("| EA | String |")
        out("|---|---|")
        for s in high[:60]:
            addr = s.get("address", s.get("ea", "?"))
            summary = (s.get("summary") or s.get("string") or "")[:160]
            out(f"| {addr} | `{summary}` |")
        out("")

    if strs:
        out(f"### Top Strings ({len(strs)} extracted; showing {min(max_strings, len(strs))})")
        out("| EA | String |")
        out("|---|---|")
        for s in strs[:max_strings]:
            if not isinstance(s, dict):
                continue
            addr = s.get("address", s.get("ea", "?"))
            summary = (s.get("summary") or s.get("string") or "")[:160]
            out(f"| {addr} | `{summary}` |")
        out("")

    # --- Constants ---
    consts = mc.get("constants") or views.get("constants") or []
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
    imps = views.get("imports") or mc.get("imports") or []
    if imps:
        out(f"### Imports ({len(imps)})")
        out("| EA | Name | Type | Refs |")
        out("|---|---|---|---|")
        for imp in imps[:max_imports]:
            if not isinstance(imp, dict):
                continue
            name = imp.get("name", "?")
            typ = imp.get("type", "?")
            addr = imp.get("address", imp.get("ea", "?"))
            refs = imp.get("num_refs", "-")
            out(f"| {addr} | {name} | {typ} | {refs} |")
        out("")

    # --- Functions ---
    funcs = views.get("functions") or mc.get("functions") or []
    if isinstance(funcs, list) and funcs:
        out(f"### Functions ({len(funcs)})")
        out("| EA | Name |")
        out("|---|---|")
        for f in funcs[:40]:
            if isinstance(f, dict):
                out(f"| {f.get('ea', f.get('address', '?'))} | {f.get('name', '?')} |")
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
            out((info.get("decompilation") or "")[:4000])
            out("```")
        out("")

    # --- Carved / virtual files / structures ---
    carved = mc.get("carved_files") or views.get("carved") or []
    if carved:
        out(f"### Carved Files ({len(carved)})")
        out("| Name | Type | Size |")
        out("|---|---|---|")
        for f in carved[:max_carved]:
            if not isinstance(f, dict):
                continue
            out(f"| {f.get('name', f.get('path', '?'))} | {f.get('type', f.get('kind', '?'))} | {f.get('size', f.get('unpacked_size', '?'))} |")
        out("")

    vfiles = mc.get("virtual_files") or views.get("virtual_files") or []
    if vfiles:
        out(f"### Virtual Files ({len(vfiles)})")
        out("| Path / Name | Unpacked Size | Type |")
        out("|---|---|---|")
        for f in vfiles[:max_virtual]:
            if not isinstance(f, dict):
                continue
            out(
                f"| {f.get('path', f.get('name', '?'))} | "
                f"{f.get('unpacked_size', f.get('size', '?'))} | "
                f"{f.get('type', f.get('kind', '-'))} |"
            )
        out("")

    structs = mc.get("structures") or views.get("structures") or []
    if structs:
        out(f"### Structures ({len(structs)})")
        out("| Name | EA |")
        out("|---|---|")
        for s in structs[:max_structs]:
            if isinstance(s, dict):
                out(f"| {s.get('name', s.get('struct_name', '?'))} | {s.get('ea', '-')} |")
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
    sql_evidence: dict | None = None,
    speakeasy: dict | None = None,
    frida_probe: dict | None = None,
) -> str:
    """Assemble a structured, evidence-rich markdown block for a technical report."""
    lines: list[str] = ["# Technical Evidence Pack", ""]
    lines.append(f"**sha256:** {session.get('sha256', '?')}  ")
    lines.append(f"**sample_path:** {session.get('sample_path', '?')}  ")
    lines.append(f"**project_name:** {session.get('project_name', '?')}")
    lines.append("")
    lines.append(
        "> Every table below is copied from stage JSON. Technical narrative must cite "
        "these rows (engine + address/rule), not invent evidence."
    )
    lines.append("")

    if verdict:
        lines.append("## Verdict")
        for k in (
            "verdict", "score", "family_guess", "confidence", "agreement",
            "numeric_score", "cross_engine_notes", "summary", "source", "model",
        ):
            v = verdict.get(k)
            if v not in (None, ""):
                lines.append(f"- **{k}**: {v}")
        ke = verdict.get("key_evidence") or []
        if ke:
            lines.append("")
            lines.append("### key_evidence (triage) — cite source field exactly")
            lines.append("| source | query_or_table | row_or_rule | why |")
            lines.append("|---|---|---|---|")
            for item in ke[:25]:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"| {item.get('source', '?')} | {item.get('query_or_table', '-')} | "
                    f"`{str(item.get('row_or_rule', ''))[:80]}` | {(item.get('why') or '')[:120]} |"
                )
        lines.append("")

    if deep:
        lines.append("## Deep-Dive Summary Evidence")
        lines.append(f"- **source**: {deep.get('source', '?')}")
        lines.append(f"- **confidence**: {deep.get('confidence', '?')}")
        if deep.get("summary"):
            lines.append(f"- **summary**: {deep.get('summary')}")
        behaviors = deep.get("behaviors") or []
        if behaviors:
            lines.append("- **behaviors**:")
            for b in behaviors[:30]:
                lines.append(f"  - {b}")
        iocs = deep.get("iocs") or []
        if iocs:
            lines.append("- **iocs**:")
            for i in iocs[:30]:
                lines.append(f"  - `{json.dumps(i, default=str)[:200]}`")
        dke = deep.get("key_evidence") or []
        if dke:
            lines.append("")
            lines.append("### deep key_evidence")
            for item in dke[:20]:
                lines.append(f"- `{json.dumps(item, default=str)[:400]}`")
        lines.append("")

    lines.append("## Malcat Structured Analysis")
    lines.append(format_malcat_evidence(malcat_result or tools_results.get("malcat")))
    lines.append("")

    def _capa_tag_cell(items, limit=120) -> str:
        """Format capa ATT&CK/MBC cells (str or Malcat-style dict entries)."""
        parts: list[str] = []
        for it in items or []:
            if isinstance(it, str):
                parts.append(it)
            elif isinstance(it, dict):
                tid = it.get("id") or ""
                tech = it.get("technique") or it.get("behavior") or ""
                if tid and tech:
                    parts.append(f"{tid}:{tech}")
                elif tid:
                    parts.append(str(tid))
                elif tech:
                    parts.append(str(tech))
                else:
                    joined = " / ".join(str(x) for x in (it.get("parts") or []) if x)
                    if joined:
                        parts.append(joined)
            elif it is not None:
                parts.append(str(it))
        return ", ".join(parts)[:limit]

    capa = tools_results.get("capa") or {}
    if capa:
        lines.append("## capa Capability Rules")
        rules = capa.get("top_rules") or capa.get("rules") or []
        lines.append(
            f"engine: `{capa.get('engine', '?')}` · Total rules: "
            f"{capa.get('rule_count', len(rules))} · duration_s: {capa.get('duration_s', '?')}"
        )
        lines.append("")
        lines.append("| Rule | ATT&CK | MBC |")
        lines.append("|---|---|---|")
        for r in rules[:80]:
            if isinstance(r, dict):
                attack = _capa_tag_cell(r.get("attack"))
                mbc = _capa_tag_cell(r.get("mbc"))
                lines.append(f"| {r.get('name', '?')} | {attack} | {mbc} |")
            else:
                lines.append(f"| {r} |  |  |")
        lines.append("")

    pe_imp = tools_results.get("pe_imports") or {}
    if pe_imp:
        lines.append("## PE Imports / Signals")
        lines.append(f"import_count: {pe_imp.get('import_count', '?')}")
        signals = pe_imp.get("signals") or []
        if signals:
            lines.append("")
            lines.append("| label | api_match | ATT&CK |")
            lines.append("|---|---|---|")
            for s in signals[:40]:
                if isinstance(s, dict):
                    att = ", ".join(s.get("attack") or [])
                    lines.append(f"| {s.get('label', '?')} | {s.get('api_match', '?')} | {att} |")
        imports = pe_imp.get("imports") or pe_imp.get("entries") or []
        if imports:
            lines.append("")
            lines.append("### Import list")
            for imp in imports[:80]:
                lines.append(f"- `{imp if not isinstance(imp, dict) else json.dumps(imp, default=str)[:160]}`")
        lines.append("")

    yara = tools_results.get("yara") or {}
    if yara and yara.get("matches"):
        lines.append("## YARA Matches (pipeline)")
        matches = yara.get("matches") or []
        lines.append(f"Total matches: {yara.get('rule_count', len(matches))}")
        lines.append("")
        lines.append("| Rule | Namespace | Match strings (trimmed) |")
        lines.append("|---|---|---|")
        for m in matches[:40]:
            if isinstance(m, dict):
                strs = m.get("strings")
                if isinstance(strs, list):
                    shown = []
                    for hit in strs[:8]:
                        if isinstance(hit, dict):
                            extra = ""
                            if hit.get("length") is not None:
                                extra = f" len={hit.get('length')}"
                            if hit.get("xor_key") is not None:
                                extra += f" xor={hit.get('xor_key')}"
                            shown.append(f"{hit.get('id', '')}@{hit.get('offset', '')}{extra}")
                        else:
                            shown.append(str(hit)[:40])
                    scell = "; ".join(shown)[:160]
                else:
                    scell = str(strs)[:160]
                lines.append(f"| {m.get('rule', '?')} | {m.get('namespace', '-')} | {scell} |")
        lines.append("")

    if yara_meta:
        lines.append("## Generated YARA Meta")
        lines.append(f"```json\n{json.dumps(yara_meta, indent=2, default=str)[:4000]}\n```")
        lines.append("")

    floss = tools_results.get("floss") or {}
    if floss:
        lines.append("## FLOSS Strings")
        strings = floss.get("strings") or []
        lines.append(
            f"Total strings: {floss.get('string_count', len(strings))} · "
            f"per_category: `{json.dumps(floss.get('per_category') or {}, default=str)[:300]}`"
        )
        lines.append("")
        high = []
        for s in strings:
            text = s.get("string", s.get("value", s)) if isinstance(s, dict) else s
            if isinstance(text, str) and _HIGH_SIGNAL_STRING_RE.search(text):
                high.append(s)
        if high:
            lines.append("### High-signal FLOSS")
            for s in high[:40]:
                if isinstance(s, dict):
                    lines.append(f"- `{s.get('string', s.get('value', '?'))}` (type: {s.get('type', '?')})")
                else:
                    lines.append(f"- `{s}`")
            lines.append("")
        lines.append("### FLOSS sample")
        for s in strings[:40]:
            if isinstance(s, dict):
                lines.append(f"- `{s.get('string', s.get('value', '?'))}` (type: {s.get('type', '?')})")
            else:
                lines.append(f"- `{s}`")
        lines.append("")

    sql_blob = sql_evidence or tools_results.get("sql_evidence")
    if sql_blob:
        lines.append("## Ghidra / IDA SQL Evidence")
        lines.append(format_sql_evidence_brief(sql_blob))
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
    elif dotnet_result is not None:
        lines.append("## .NET Analysis")
        lines.append("- is_dotnet: false (not observed)")
        lines.append("")

    if r2_decomp and r2_decomp.get("disassembly"):
        lines.append("## radare2 Disassembly (attach in Static Code Analysis)")
        for addr, body in list(r2_decomp["disassembly"].items())[:6]:
            lines.append(f"### {addr}")
            lines.append("```asm")
            lines.append(str(body)[:6000])
            lines.append("```")
        lines.append("")

    if r2_ai and r2_ai.get("explanations"):
        lines.append("## r2ai / decai Explanations")
        for addr, body in list(r2_ai["explanations"].items())[:4]:
            lines.append(f"### {addr}")
            lines.append(str(body)[:4000])
        lines.append("")

    if upx:
        lines.append("## UPX Unpack")
        lines.append(f"- upx_ok: {upx.get('upx_ok')}")
        lines.append(f"- is_packed: {upx.get('is_packed')}")
        lines.append(f"- returncode: {upx.get('upx_returncode')}")
        lines.append(f"- unpacked_path: `{upx.get('unpacked_path', '')}`")
        stdout = (upx.get("upx_stdout") or "")[:2000]
        if stdout:
            lines.append("```")
            lines.append(stdout)
            lines.append("```")
        lines.append("")

    # V5.16.5 — second-pass results on unpacked payload (may be nested under tools)
    upx_sp = None
    if isinstance(tools_results, dict):
        upx_sp = tools_results.get("upx_second_pass")
    if isinstance(upx_sp, dict) and (upx_sp.get("tools") or upx_sp.get("ok") is not None):
        lines.append("## UPX Second-Pass (unpacked payload)")
        lines.append(f"- ok: {upx_sp.get('ok')}")
        lines.append(f"- unpacked_path: `{upx_sp.get('unpacked_path', '')}`")
        if upx_sp.get("skipped_reason"):
            lines.append(f"- skipped_reason: {upx_sp.get('skipped_reason')}")
        tok = upx_sp.get("tool_ok") or {}
        if tok:
            lines.append("| Tool | ok | why |")
            lines.append("|---|---|---|")
            for name, st in tok.items():
                if isinstance(st, dict):
                    lines.append(f"| {name} | {st.get('ok')} | {st.get('why', '')} |")
                else:
                    lines.append(f"| {name} | {st} | |")
        sp_tools = upx_sp.get("tools") or {}
        capa2 = sp_tools.get("capa") if isinstance(sp_tools.get("capa"), dict) else {}
        if capa2:
            lines.append(
                f"- capa (unpacked): engine={capa2.get('engine')} "
                f"rule_count={capa2.get('rule_count')}"
            )
        yara2 = sp_tools.get("yara") if isinstance(sp_tools.get("yara"), dict) else {}
        if yara2:
            matches = yara2.get("matches") or yara2.get("hits") or []
            lines.append(f"- yara (unpacked): match_count={len(matches) if isinstance(matches, list) else '?'}")
        lines.append("")

    if xor_hits:
        lines.append("## XOR Search")
        cands = xor_hits.get("candidates") or []
        if cands:
            for c in cands[:20]:
                lines.append(f"- {c}")
        else:
            lines.append(json.dumps(xor_hits, indent=2, default=str)[:2500])
        lines.append("")

    sp = speakeasy if speakeasy is not None else tools_results.get("speakeasy")
    if sp is not None:
        lines.append("## Speakeasy (dynamic)")
        n_api = len(sp.get("api_calls") or [])
        n_ev = len(sp.get("key_events") or [])
        lines.append(f"- speakeasy_ok: {sp.get('speakeasy_ok')}")
        lines.append(f"- api_calls: {n_api}")
        lines.append(f"- key_events: {n_ev}")
        lines.append(f"- duration_s: {sp.get('duration_s')}")
        if n_api == 0 and n_ev == 0:
            lines.append("- **not observed**: no API calls/events recorded — do not invent runtime behavior")
        else:
            for ev in (sp.get("key_events") or [])[:30]:
                lines.append(f"- event: `{json.dumps(ev, default=str)[:200]}`")
            for api in (sp.get("api_calls") or [])[:40]:
                lines.append(f"- api: `{json.dumps(api, default=str)[:200]}`")
        lines.append("")

    fp = frida_probe if frida_probe is not None else tools_results.get("frida_probe")
    if fp:
        lines.append("## Frida Probe")
        lines.append(f"- frida_available: {fp.get('frida_available')}")
        lines.append(f"- version: {fp.get('frida_version')}")
        probe = fp.get("pe_probe") or {}
        hooks = probe.get("hook_candidates") or []
        if hooks:
            lines.append("- hook_candidates:")
            for h in hooks[:40]:
                lines.append(f"  - `{h}`")
        lines.append("")

    if olevba:
        lines.append("## olevba")
        lines.append(json.dumps(olevba, indent=2, default=str)[:4000])
        lines.append("")

    if peepdf:
        lines.append("## peepdf")
        lines.append(json.dumps(peepdf, indent=2, default=str)[:4000])
        lines.append("")

    if frida_trace and frida_trace.get("frida_stdout"):
        lines.append("## Frida Trace")
        lines.append("```")
        lines.append((frida_trace.get("frida_stdout") or "")[:4000])
        lines.append("```")
        lines.append("")

    if audit:
        lines.append("## Audit Trail (recent)")
        for entry in audit[-30:]:
            slim = {k: entry[k] for k in ("source", "sql", "phase", "ts") if k in entry}
            lines.append(f"- `{json.dumps(slim, default=str)[:300]}`")
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
    """Quick-triage evidence (capa rules + YARA + floss sample) — feeds Static Analysis."""
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
    """Section 5: Behavioral — speakeasy + frida probe + malcat anomalies."""
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
    """Section 6: Network — URLs, IPs, mutexes, sockets from static tooling."""
    lines = []
    mc = tools_results.get("malcat") or {}
    consts = mc.get("constants") or []
    url_c, ip_c, mutex_c = [], [], []
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
        lines.append(f"  Mutexes: {', '.join(mutex_c[:10])}")
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
    "3. Background & Family Lineage": (
        "Prior research anchor: family history, earlier vendor reports, variant "
        "lineage, naming. Quick-triage artifacts (capa rules, YARA matches, "
        "FLOSS highlights) fold into Static Analysis.",
        ["family", "history", "prior", "variant", "lineage", "known family"],
        _sec_family_evidence, True,
    ),
    "4. Static Analysis": (
        "PE structure, sections, decompilations, .NET analysis, imports, "
        "signatures; quick-triage artifacts (capa rules, YARA matches, FLOSS "
        "highlights) live here. Explain each artifact: what it is, why it "
        "matters, what behavior it implies.",
        ["static analysis", "pe structure", "imports", "sections", "dotnet", "triage", "yara", "capa"],
        _sec_static_evidence, True,
    ),
    "5. Behavioral Analysis": (
        "Runtime behavior from Speakeasy + Frida probe + MalCat anomalies. "
        "Separate observed behavior from latent capability.",
        ["behavioral analysis", "speakeasy", "frida", "anomalies"],
        _sec_behavioral_evidence, True,
    ),
    "6. Network Analysis & C2": (
        "C2 / infrastructure indicators: URLs, IPs, mutexes, sockets, domains, "
        "registration patterns from static tooling.",
        ["network indicators", "c2", "url", "ip", "mutex", "socket", "domain", "infrastructure"],
        _sec_network_evidence, True,
    ),
    "7. Capability Assessment": (
        "What the malware can do: encryption, network, persistence, anti-analysis. "
        "Annotate observed-vs-latent where possible.",
        ["capability", "encryption", "persistence", "anti-analysis", "evasion"],
        _sec_capability_evidence, True,
    ),
    "8. Attribution": (
        "Threat actor, campaign, suspected origin — hedged: state confidence "
        "and what evidence it rests on.",
        ["attribution", "threat actor", "campaign", "apt"],
        _sec_attribution_evidence, True,
    ),
    "9. Indicators of Compromise": (
        "All IOCs: hashes, IPs, URLs, mutexes, registry keys, file paths.",
        ["ioc", "indicator", "hash", "ip", "url", "mutex", "registry", "filename"],
        _sec_iocs_evidence, True,
    ),
    "10. Detection Rules": (
        "Query-first detection: Sigma/Snort/KQL where possible + YARA rules "
        "that match. Detection content lives at the end with IoCs.",
        ["detection", "yara", "sigma", "snort", "rule", "kql"],
        _sec_detection_evidence, True,
    ),
    "11. MITRE ATT&CK Mapping": (
        "Specific MITRE ATT&CK techniques observed (T-codes with rule names), "
        "tabulated at the end near detection content.",
        ["mitre", "attack", "technique", "t1059", "t1486", "t1055"],
        _sec_attack_evidence, True,
    ),
    "12. Containment, Eradication, Recovery": (
        "IR steps based on observed file paths, mutexes, registry keys, services.",
        ["containment", "eradication", "recovery", "incident response", "playbook"],
        _sec_containment_evidence, True,
    ),
    "13. Recommendations": (
        "Strategic guidance: patch priorities, monitoring, training.",
        ["recommendation", "best practice", "prevention", "hygiene"],
        _sec_recommendations_evidence, True,
    ),
    "14. Appendix A: Evidence Trail": (
        "Raw tool output for transparency: how each claim maps to evidence "
        "(engine + artifact). No LLM call needed.",
        [], lambda x: "", False,
    ),
    "15. Appendix B: Module Inventory": (
        "Structured module/function inventory: addresses, names, roles.",
        [], lambda x: "", False,
    ),
    "16. Author + Sign-off": (
        "Metadata: timestamps, analyst, model, sources. No LLM call needed.",
        [], lambda x: "", False,
    ),
}
SANDBOX_WRAPPER = Path("/opt/scripts/run_agent_sandbox.sh")


def speakeasy_emulate(sample_path: str, timeout: int = SPEAKEASY_TIMEOUT) -> dict:
    """Windows native PE emulation (Mandiant Speakeasy / Unicorn).

    Callers must route via TOOL_MANIFEST (applies_to=["pe"] only). If invoked
    on .NET by mistake, refuse without loading Speakeasy — do not "try and fail".
    """
    out: dict[str, Any] = {"speakeasy_ok": False, "sample": sample_path}
    fmt = _detect_format_for_tools(sample_path)
    if fmt != "pe":
        # Defense in depth — routing should have skipped this entirely.
        out.update({
            "skipped": True,
            "reason": f"not_applicable:{fmt}",
        })
        return out
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
    def _write_checkpoint(path: Path, rec: dict) -> bool:
        try:
            path.write_text(json.dumps(rec, indent=2))
            return True
        except PermissionError:
            return False

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
    if _write_checkpoint(path, record):
        pass
    elif wait and not auto:
        # Human gate REQUIRES the shared dir — fail loudly with a clear cause.
        raise PermissionError(
            f"HITL wait-mode requires writable {path} (fix ownership: "
            f"sudo chown -R $(id -un):$(id -gn) /tmp/cadre-hitl)"
        )
    else:
        # Telemetry write must NEVER kill a stage. Degrade to a per-user dir,
        # then to in-memory-only if even that fails.
        alt_dir = Path(
            f"/tmp/cadre-hitl-{getattr(os, 'getuid', lambda: 0)()}"
        )
        try:
            alt_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            alt_dir = None
        if alt_dir is not None and _write_checkpoint(
            alt_dir / f"{agent}-{step}.json", record
        ):
            pass
        else:
            record["checkpoint_write_failed"] = True
            return record

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


def run_sandboxed(argv: list[str], use_sandbox: bool | None = None) -> None:
    """Run agent via bwrap when CADRE_USE_SANDBOX=1 or use_sandbox=True."""
    if use_sandbox is None:
        use_sandbox = os.environ.get("CADRE_USE_SANDBOX", "1") == "1"
    if use_sandbox and SANDBOX_WRAPPER.is_file():
        subprocess.check_call(["bash", str(SANDBOX_WRAPPER), *argv])
    else:
        subprocess.check_call([sys.executable, *argv])


def goodware_fp_scan(yar_path: Path, goodware_dir: Path | None = None) -> dict:
    """Scan generated YARA rule against goodware corpus; flag if any match.

    Uses the in-process yara-x Python engine (no external `yr` binary).
    """
    gw = goodware_dir or GOODWARE_DIR
    out: dict[str, Any] = {"goodware_dir": str(gw), "fp_count": 0, "fp_samples": []}
    if not yar_path.is_file():
        out["error"] = "missing rule"
        return out
    if not gw.is_dir():
        out["skipped"] = "goodware corpus not staged"
        return out
    try:
        from yara_x import Compiler, Scanner
    except ImportError:
        out["error"] = "yara_x python module not installed (pip install yara-x)"
        return out
    try:
        with open(yar_path, encoding="utf-8", errors="replace") as fh:
            compiler = Compiler()
            compiler.enable_includes(True)
            compiler.add_source(fh.read(), origin=str(yar_path))
            rules = compiler.build()
    except Exception as e:
        out["error"] = f"rule compile failed: {e}"
        return out
    scanner = Scanner(rules)
    scanner.set_timeout(120)
    for p in sorted(gw.glob("*")):
        if not p.is_file():
            continue
        try:
            res = scanner.scan_file(str(p))
        except Exception:
            continue
        if res.matching_rules:
            out["fp_count"] += 1
            out["fp_samples"].append(str(p))
            if len(out["fp_samples"]) >= 10:
                break
    return out


def yara_rule_validate(yar_path: Path) -> tuple[bool, str]:
    """Validate a YARA rule file using the in-process yara-x compiler.

    A rule that fails to compile is a hard failure — never silently skipped.
    """
    try:
        from yara_x import Compiler
    except ImportError:
        return False, "yara_x python module not installed (pip install yara-x)"
    try:
        with open(yar_path, encoding="utf-8", errors="replace") as fh:
            compiler = Compiler()
            compiler.enable_includes(True)
            compiler.add_source(fh.read(), origin=str(yar_path))
            compiler.build()
        return True, "ok"
    except Exception as e:
        return False, str(e)[:200]


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


def lief_analyze(sample_path: str) -> dict:
    """Rich binary structure analysis using LIEF. Works on PE/ELF/Mach-O.

    Returns: sections (name, entropy, size, characteristics), imports, exports,
    overlay, TLS callbacks, Authenticode status, imphash, resources.
    """
    import os
    import math
    out: dict = {"lief_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        import lief as _lief
    except ImportError:
        out["error"] = "lief not installed"
        return out
    try:
        binary = _lief.parse(sample_path)
        if binary is None:
            out["error"] = "lief could not parse file"
            return out

        out["format"] = binary.format.name if hasattr(binary.format, "name") else str(binary.format)

        # Sections
        sections = []
        for s in binary.sections:
            sec = {
                "name": s.name,
                "size": s.size,
                "offset": s.offset,
            }
            if hasattr(s, "virtual_size"):
                sec["virtual_size"] = s.virtual_size
            # Entropy
            try:
                data = bytes(s.content)
                if data:
                    import collections
                    counts = collections.Counter(data)
                    total = len(data)
                    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
                    sec["entropy"] = round(entropy, 4)
            except Exception:
                pass
            # Characteristics (PE)
            if hasattr(s, "characteristics"):
                try:
                    sec["characteristics"] = hex(int(s.characteristics))
                except Exception:
                    pass
            sections.append(sec)
        out["sections"] = sections

        # Imports
        imports = []
        if hasattr(binary, "imports"):
            for entry in binary.imports:
                imp = {"name": entry.name or ""}
                if hasattr(entry, "library") and entry.library:
                    imp["library"] = entry.library.name
                imports.append(imp)
        out["imports"] = imports[:200]
        out["import_count"] = len(imports)

        # Exports
        exports = []
        if hasattr(binary, "exported_functions"):
            for fn in binary.exported_functions:
                exports.append({"name": fn.name if hasattr(fn, "name") else str(fn), "address": fn.address if hasattr(fn, "address") else 0})
        out["exports"] = exports[:100]
        out["export_count"] = len(exports)

        # Imphash (PE)
        if hasattr(binary, "imphash"):
            try:
                out["imphash"] = binary.imphash()
            except Exception:
                pass

        # Overlay
        if hasattr(binary, "overlay"):
            try:
                overlay = binary.overlay
                if overlay and len(overlay) > 0:
                    out["overlay"] = {"size": len(overlay), "offset": binary.overlay_offset if hasattr(binary, "overlay_offset") else 0}
            except Exception:
                pass

        # TLS callbacks (PE)
        if hasattr(binary, "tls") and binary.tls:
            try:
                tls = binary.tls
                callbacks = []
                if hasattr(tls, "callbacks"):
                    for cb in tls.callbacks:
                        callbacks.append(hex(cb))
                out["tls_callbacks"] = callbacks
            except Exception:
                pass

        # Authenticode (PE)
        if hasattr(binary, "verify_signature"):
            try:
                sig = binary.verify_signature
                out["authenticode"] = {"signed": bool(sig)}
            except Exception:
                pass

        # Resources (PE)
        if hasattr(binary, "resources"):
            try:
                resources = []
                for r in binary.resources[:20]:
                    res = {"type": str(r.type) if hasattr(r, "type") else "unknown"}
                    if hasattr(r, "name"):
                        res["name"] = str(r.name)
                    if hasattr(r, "size"):
                        res["size"] = r.size
                    resources.append(res)
                out["resources"] = resources
                out["resource_count"] = len(binary.resources)
            except Exception:
                pass

        # Entry point
        if hasattr(binary, "entrypoint"):
            out["entrypoint"] = hex(binary.entrypoint)

        # Imagebase
        if hasattr(binary, "imagebase"):
            out["imagebase"] = hex(binary.imagebase)

        out["lief_ok"] = True
        return out
    except Exception as e:
        out["error"] = f"lief_analyze failed: {e}"
        return out


def shellcode_extract(sample_path: str, timeout: int = 30) -> dict:
    """Extract shellcode sections from PE files and emulate with scdbg.

    Finds sections with high entropy + executable flags, extracts them,
    and feeds to scdbg for emulation.
    """
    import os, subprocess, tempfile, math, collections
    out: dict = {"shellcode_ok": False, "sample": sample_path, "sections_analyzed": []}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        import lief as _lief
    except ImportError:
        out["error"] = "lief not installed"
        return out
    try:
        binary = _lief.parse(sample_path)
        if binary is None:
            out["error"] = "lief could not parse file"
            return out

        # Find executable sections with high entropy
        candidates = []
        for s in binary.sections:
            if s.size < 16:
                continue
            data = bytes(s.content)
            if not data:
                continue
            # Calculate entropy
            counts = collections.Counter(data)
            total = len(data)
            entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
            # Check if section is executable
            is_exec = False
            if hasattr(s, "characteristics"):
                try:
                    chars = int(s.characteristics)
                    is_exec = bool(chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
                except Exception:
                    pass
            sec_info = {"name": s.name, "size": s.size, "entropy": round(entropy, 4), "executable": is_exec}
            out["sections_analyzed"].append(sec_info)
            if is_exec and entropy > 5.0:
                candidates.append((s, entropy))

        if not candidates:
            out["error"] = "no high-entropy executable sections found"
            return out

        # Try the highest-entropy executable section
        candidates.sort(key=lambda x: -x[1])
        best_section, best_entropy = candidates[0]
        shellcode_data = bytes(best_section.content)

        # Write to temp file
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(shellcode_data)
            shellcode_path = f.name

        out["shellcode_section"] = best_section.name
        out["shellcode_size"] = len(shellcode_data)
        out["shellcode_entropy"] = best_entropy

        # Run scdbg on extracted shellcode
        scdbg_exe = "/opt/scdbg/scdbg.exe"
        if not os.path.isfile(scdbg_exe):
            out["error"] = "scdbg.exe not found"
            return out
        env = os.environ.copy()
        env["WINEDEBUG"] = "-all"
        r = subprocess.run(
            ["wine", scdbg_exe, "-f", shellcode_path],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        out["scdbg_stdout"] = (r.stdout or "")[:3000]
        out["scdbg_stderr"] = (r.stderr or "")[:500]
        out["scdbg_returncode"] = r.returncode

        # Parse scdbg output
        for line in (r.stdout or "").splitlines():
            if "Stepcount" in line.strip():
                try:
                    out["step_count"] = int(line.strip().split()[-1])
                except Exception:
                    pass

        out["shellcode_ok"] = (out.get("step_count", 0) > 0)
        return out
    except Exception as e:
        out["error"] = f"shellcode_extract failed: {e}"
        return out


def elf_analyze(sample_path: str, timeout: int = 30) -> dict:
    """ELF structural analysis using readelf/objdump/nm. Returns sections, symbols, imports."""
    import os, subprocess, re
    out: dict = {"elf_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        # readelf -S (sections)
        r = subprocess.run(["readelf", "-S", sample_path], capture_output=True, text=True, timeout=timeout)
        sections = []
        for line in (r.stdout or "").splitlines():
            m = re.match(r'\s+\[\s*\d+\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
            if m:
                sections.append({"name": m.group(1), "type": m.group(2), "addr": m.group(3), "offset": m.group(4), "size": m.group(5)})
        out["sections"] = sections[:50]

        # readelf -s (symbols)
        r2 = subprocess.run(["readelf", "-s", sample_path], capture_output=True, text=True, timeout=timeout)
        symbols = []
        for line in (r2.stdout or "").splitlines():
            m = re.match(r'\s+\d+:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)', line)
            if m:
                symbols.append({"addr": m.group(1), "size": m.group(2), "type": m.group(3), "bind": m.group(4), "name": m.group(7).strip()})
        out["symbols"] = symbols[:200]
        out["symbol_count"] = len(symbols)

        # nm -D --defined-only (dynamic symbols)
        r3 = subprocess.run(["nm", "-D", "--defined-only", sample_path], capture_output=True, text=True, timeout=timeout)
        dyn_exports = []
        for line in (r3.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                dyn_exports.append({"addr": parts[0], "type": parts[1], "name": " ".join(parts[2:])})
        out["dynamic_exports"] = dyn_exports[:100]
        out["dynamic_export_count"] = len(dyn_exports)

        # readelf -h (header)
        r4 = subprocess.run(["readelf", "-h", sample_path], capture_output=True, text=True, timeout=timeout)
        for line in (r4.stdout or "").splitlines():
            if "Entry point" in line:
                out["entrypoint"] = line.split(":")[-1].strip()
            if "Class:" in line:
                out["elf_class"] = line.split(":")[-1].strip()
            if "Machine:" in line:
                out["machine"] = line.split(":")[-1].strip()

        out["elf_ok"] = bool(sections or symbols)
        return out
    except Exception as e:
        out["error"] = f"elf_analyze failed: {e}"
        return out


def pycdc_decompile(sample_path: str, timeout: int = 60) -> dict:
    """Decompile Python bytecode (.pyc) files using pycdc (Decompyle++)."""
    import os, subprocess
    out: dict = {"pycdc_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        r = subprocess.run(
            ["pycdc", sample_path],
            capture_output=True, text=True, timeout=timeout,
        )
        stdout = r.stdout or ""
        stderr = r.stderr or ""
        out["pycdc_stdout"] = stdout[:20000]
        out["pycdc_stderr"] = stderr[:1000]
        out["pycdc_returncode"] = r.returncode
        out["decompiled_length"] = len(stdout)
        out["pycdc_ok"] = (r.returncode == 0 and len(stdout) > 50)
        return out
    except subprocess.TimeoutExpired:
        out["error"] = f"pycdc timed out after {timeout}s"
        return out
    except Exception as e:
        out["error"] = f"pycdc_decompile failed: {e}"
        return out


def rift_analyze(sample_path: str, timeout: int = 120) -> dict:
    """Rust binary analysis using RIFT. Extracts Rust version, crates, architecture, compiler."""
    import os, subprocess, re
    out: dict = {"rift_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    rift_cli = "/opt/rift/rift_cli.py"
    rift_cfg = "/opt/rift/rift_config_linux.cfg"
    if not os.path.isfile(rift_cli):
        out["error"] = "rift_cli.py not found"
        return out
    # Ensure output dirs exist
    os.makedirs(os.path.expanduser("~/Output"), exist_ok=True)
    try:
        cmd = ["python3", rift_cli, "-f", sample_path, "--only-meta", "-o", os.path.expanduser("~/Output")]
        if os.path.isfile(rift_cfg):
            cmd.extend(["-c", rift_cfg])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = r.stdout or ""
        stderr = r.stderr or ""
        out["rift_stderr"] = stderr[:2000]
        out["rift_returncode"] = r.returncode

        # Parse metadata from combined output (RIFT prints metadata to stdout, logs to stderr)
        combined = stdout + "\n" + stderr
        for line in combined.splitlines():
            line_s = line.strip()
            if line_s.startswith("Rust Version:"):
                out["rust_version"] = line_s.split(":", 1)[1].strip()
            elif line_s.startswith("Version Short:"):
                out["version_short"] = line_s.split(":", 1)[1].strip()
            elif line_s.startswith("Commit Hash:"):
                out["commit_hash"] = line_s.split(":", 1)[1].strip()
            elif line_s.startswith("Architecture:"):
                out["architecture"] = line_s.split(":", 1)[1].strip()
            elif line_s.startswith("File Type:"):
                out["file_type"] = line_s.split(":", 1)[1].strip()
            elif line_s.startswith("Compiler:"):
                out["compiler"] = line_s.split(":", 1)[1].strip()
            elif line_s.startswith("Target Triple:"):
                out["target_triple"] = line_s.split(":", 1)[1].strip()

        # Parse crates
        crates = []
        in_crates = False
        for line in stdout.splitlines():
            if "Crates (" in line:
                in_crates = True
                continue
            if in_crates:
                line_s = line.strip()
                if line_s.startswith("- "):
                    crates.append(line_s[2:])
                elif line_s and not line_s.startswith("-"):
                    in_crates = False
        out["crates"] = crates[:100]
        out["crate_count"] = len(crates)
        out["is_rust"] = bool(out.get("rust_version"))
        out["rift_ok"] = out["is_rust"]  # Metadata extraction succeeds even without pcf/sigmake
        return out
    except subprocess.TimeoutExpired:
        out["error"] = f"rift timed out after {timeout}s"
        return out
    except Exception as e:
        out["error"] = f"rift_analyze failed: {e}"
        return out


def ilspy_decompile(sample_path: str, timeout: int = 120) -> dict:
    """Decompile .NET assemblies to C# source using ilspycmd (headless ILSpy)."""
    import os, subprocess
    out: dict = {"ilspy_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        r = subprocess.run(
            ["ilspycmd", sample_path],
            capture_output=True, text=True, timeout=timeout,
        )
        stdout = r.stdout or ""
        stderr = r.stderr or ""
        out["ilspy_stdout"] = stdout[:20000]
        out["ilspy_stderr"] = stderr[:2000]
        out["ilspy_returncode"] = r.returncode
        out["decompiled_length"] = len(stdout)
        out["ilspy_ok"] = (r.returncode == 0 and len(stdout) > 100)
        return out
    except subprocess.TimeoutExpired:
        out["error"] = f"ilspycmd timed out after {timeout}s"
        return out
    except Exception as e:
        out["error"] = f"ilspy_decompile failed: {e}"
        return out


def goresym_analyze(sample_path: str, timeout: int = 120) -> dict:
    """Go binary symbol recovery using GoReSym (Mandiant). Extracts Go version, modules, functions."""
    import os, subprocess, json as _json
    out: dict = {"goresym_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    goresym_bin = "/opt/goresym/GoReSym"
    if not os.path.isfile(goresym_bin):
        out["error"] = "GoReSym not found at /opt/goresym/GoReSym"
        return out
    try:
        r = subprocess.run(
            [goresym_bin, sample_path],
            capture_output=True, text=True, timeout=timeout,
        )
        stdout = r.stdout or ""
        stderr = r.stderr or ""
        out["goresym_stderr"] = stderr[:500]
        out["goresym_returncode"] = r.returncode

        # Parse JSON output
        try:
            data = _json.loads(stdout)
        except _json.JSONDecodeError:
            out["error"] = "GoReSym output not valid JSON"
            out["goresym_stdout"] = stdout[:2000]
            return out

        # Extract key fields
        out["goversion"] = data.get("GoVersion", "")
        out["modules"] = data.get("Modules", [])[:50]
        out["user_functions"] = [
            {"name": f.get("FullName", ""), "addr": f.get("StartAddr", ""), "size": f.get("End", 0) - f.get("Start", 0)}
            for f in (data.get("UserFunctions") or [])[:100]
        ]
        out["stdlib_functions"] = [
            {"name": f.get("FullName", ""), "addr": f.get("StartAddr", "")}
            for f in (data.get("StdFunctions") or [])[:50]
        ]
        out["user_function_count"] = len(data.get("UserFunctions") or [])
        out["stdlib_function_count"] = len(data.get("StdFunctions") or [])
        out["is_go"] = bool(out["goversion"] or out["user_function_count"] > 0)
        out["goresym_ok"] = (r.returncode == 0 and out["is_go"])
        return out
    except subprocess.TimeoutExpired:
        out["error"] = f"GoReSym timed out after {timeout}s"
        return out
    except Exception as e:
        out["error"] = f"goresym_analyze failed: {e}"
        return out


def diec_analyze(sample_path: str, timeout: int = 60) -> dict:
    """Packer/compiler/language identification using diec (Detect It Easy CLI).

    Returns detected packers, compilers, languages, tools, and linkers as structured JSON.
    """
    import os, subprocess, json as _json
    out: dict = {"diec_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        r = subprocess.run(
            ["diec", "-j", sample_path],
            capture_output=True, text=True, timeout=timeout,
        )
        stdout = r.stdout or ""
        stderr = r.stderr or ""
        out["diec_stderr"] = stderr[:500]
        out["diec_returncode"] = r.returncode

        # Parse JSON output (skip warning lines before JSON)
        try:
            json_start = stdout.find("{")
            if json_start < 0:
                out["error"] = "diec output contains no JSON"
                out["diec_stdout"] = stdout[:2000]
                return out
            data = _json.loads(stdout[json_start:])
        except _json.JSONDecodeError:
            out["error"] = "diec output not valid JSON"
            out["diec_stdout"] = stdout[:2000]
            return out

        detects = data.get("detects", [])
        out["filetype"] = detects[0].get("filetype", "") if detects else ""

        # Extract all values across detects
        all_values = []
        for d in detects:
            for v in d.get("values", []):
                all_values.append({
                    "type": v.get("type", ""),
                    "name": v.get("name", ""),
                    "version": v.get("version", ""),
                    "info": v.get("info", ""),
                    "string": v.get("string", ""),
                })
        out["detects"] = all_values

        # Categorize
        out["compilers"] = [v for v in all_values if v["type"] == "Compiler"]
        out["packers"] = [v for v in all_values if v["type"] == "Packer"]
        out["linkers"] = [v for v in all_values if v["type"] == "Linker"]
        out["tools"] = [v for v in all_values if v["type"] == "Tool"]
        out["languages"] = [v for v in all_values if v["type"] == "Language"]
        out["installers"] = [v for v in all_values if v["type"] == "Installer"]

        out["diec_ok"] = (r.returncode == 0 and bool(all_values))
        return out
    except Exception as e:
        out["error"] = f"diec_analyze failed: {e}"
        return out


def findcrypt_headless(sample_path: str, timeout: int = 300) -> dict:
    """Detect crypto constants (AES, SHA, RC4, ChaCha20, RSA, etc.) using FindCrypt GhidraScript.

    Runs Ghidra headless with FindCrypt.java as a postScript. Parses output for
    detected crypto algorithms and addresses.
    """
    import os, subprocess, re
    out: dict = {"findcrypt_ok": False, "sample": sample_path, "crypto_found": []}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    ghidra_home = "/opt/ghidra"
    script_path = "/opt/ghidra/Ghidra/Features/BytePatterns/ghidra_scripts/FindCrypt.java"
    if not os.path.isfile(script_path):
        out["error"] = "FindCrypt.java not found in Ghidra scripts dir"
        return out
    project_dir = "/tmp/findcrypt_headless"
    os.makedirs(project_dir, exist_ok=True)
    try:
        cmd = [
            f"{ghidra_home}/support/analyzeHeadless",
            project_dir, "findcrypt_run",
            "-import", sample_path,
            "-postScript", "FindCrypt.java",
            "-scriptPath", "/opt/ghidra/Ghidra/Features/BytePatterns/ghidra_scripts",
            "-deleteProject",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = r.stdout or ""
        stderr = r.stderr or ""
        out["findcrypt_stdout"] = stdout[-8000:]
        out["findcrypt_stderr"] = stderr[-2000:]
        out["findcrypt_returncode"] = r.returncode

        # Parse FindCrypt output lines
        crypto_found = []
        for line in stdout.splitlines():
            m = re.search(r"Found:\s*(\S+)\s+at\s+(0x[0-9a-fA-F]+)", line)
            if m:
                crypto_found.append({"algorithm": m.group(1), "address": m.group(2)})
            m2 = re.search(r"Loaded\s+(\d+)\s+signatures", line)
            if m2:
                out["signatures_loaded"] = int(m2.group(1))
        out["crypto_found"] = crypto_found
        out["crypto_count"] = len(crypto_found)
        out["findcrypt_ok"] = (r.returncode == 0 and len(crypto_found) > 0)
        return out
    except subprocess.TimeoutExpired:
        out["error"] = f"findcrypt timed out after {timeout}s"
        return out
    except Exception as e:
        out["error"] = f"findcrypt_headless failed: {e}"
        return out


def signature_match(func_name: str, imports: list | None = None,
                    strings: list | None = None, constants: list | None = None,
                    size: int = 0) -> dict:
    """Match a function against signature DBs (crypto/stdlib/winapi).

    Args:
        func_name: function name or address
        imports: list of import/external symbol names referenced by the function
        strings: list of string contents referenced by the function
        constants: list of int constants referenced by the function
        size: function size in bytes

    Returns:
        {'matched': bool, 'name': str, 'score': float, 'matched_rules': [str], 'notes': str}
        or {'matched': False} if no match above threshold.
    """
    import json as _json
    from pathlib import Path

    sig_dirs = [
        Path("/opt/revai/signatures"),
        Path(__file__).resolve().parent.parent / "v4-deploy" / "signatures",
    ]

    entries = []
    for d in sig_dirs:
        if not d.exists():
            continue
        for path in sorted(d.glob("*.json")):
            try:
                data = _json.loads(path.read_text())
                entries.extend(data.get("signatures", []))
            except Exception:
                continue

    if not entries:
        return {"matched": False, "error": "no signature DBs found"}

    imports_set = {i for i in (imports or [])}
    strings_set = {s.lower() for s in (strings or [])}
    constants_set = set(constants or [])
    threshold = 0.80

    best = None
    for entry in entries:
        ind = entry.get("indicators", {})
        heur = entry.get("heuristics", {})
        score = 0.0
        hits = []

        # Structural bounds
        min_size = ind.get("min_size")
        max_size = ind.get("max_size")
        if min_size is not None and size < min_size:
            continue
        if max_size is not None and size > max_size:
            continue

        # Import matching
        ext = ind.get("external_symbol_contains", [])
        if ext and any(any(p.lower() in imp.lower() for p in ext) for imp in imports_set):
            score += 0.45
            hits.append("external_symbol")

        # String matching
        want_strings = {s.lower() for s in ind.get("string_refs", [])}
        if want_strings and strings_set & want_strings:
            score += 0.35
            hits.append("string_ref")

        # Constant matching
        want_hex = ind.get("constants_hex", [])
        for h in want_hex:
            try:
                val = int(h, 16)
                if val in constants_set:
                    score += 0.20
                    hits.append(f"constant_{h}")
                    break
            except ValueError:
                continue

        # Heuristic adjustments
        h_cc_max = heur.get("cyclomatic_max")
        if h_cc_max is not None:
            score += 0.10
        h_out_max = heur.get("call_out_max")
        if h_out_max is not None:
            score += 0.10
        h_str = {s.lower() for s in heur.get("string_hints", [])}
        if h_str and strings_set & h_str:
            score += 0.10

        score = min(score, entry.get("score", 0.85))
        if score >= threshold:
            import re as _re
            canonical = _re.sub(r"[^A-Za-z0-9_]", "_", entry["name"])
            if best is None or score > best["score"]:
                best = {
                    "matched": True,
                    "name": canonical,
                    "score": round(score, 3),
                    "matched_rules": hits,
                    "notes": ind.get("notes", ""),
                    "source_db": path.stem if 'path' in dir() else "unknown",
                }

    return best or {"matched": False}


def pdfid_analyze(sample_path: str, timeout: int = 30) -> dict:
    """PDF structure analysis using pdfid (Didier Stevens). Counts suspicious elements."""
    import os, subprocess
    out: dict = {"pdfid_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    pdfid_script = "/usr/local/bin/pdfid.py"
    if not os.path.isfile(pdfid_script):
        out["error"] = "pdfid.py not found"
        return out
    try:
        r = subprocess.run(
            ["python3", pdfid_script, sample_path],
            capture_output=True, text=True, timeout=timeout,
        )
        stdout = r.stdout or ""
        out["pdfid_stdout"] = stdout[:5000]
        out["pdfid_stderr"] = (r.stderr or "")[:500]
        out["pdfid_returncode"] = r.returncode

        # Parse counts from pdfid output
        suspicious = {}
        for line in stdout.splitlines():
            line_s = line.strip()
            if line_s.startswith("/") and ":" in line_s:
                parts = line_s.split()
                if len(parts) >= 2:
                    name = parts[0]
                    try:
                        count = int(parts[-1])
                        suspicious[name] = count
                    except ValueError:
                        pass
        out["suspicious_elements"] = suspicious

        # Flag high-signal elements
        flags = []
        if suspicious.get("/JS", 0) > 0:
            flags.append("JavaScript")
        if suspicious.get("/JavaScript", 0) > 0:
            flags.append("JavaScript")
        if suspicious.get("/JS", 0) > 0 and suspicious.get("/OpenAction", 0) > 0:
            flags.append("JS+OpenAction")
        if suspicious.get("/Launch", 0) > 0:
            flags.append("Launch")
        if suspicious.get("/EmbeddedFile", 0) > 0:
            flags.append("EmbeddedFile")
        if suspicious.get("/AcroForm", 0) > 0:
            flags.append("AcroForm")
        if suspicious.get("/RichMedia", 0) > 0:
            flags.append("RichMedia")
        if suspicious.get("/ObjStm", 0) > 0:
            flags.append("ObjStm")
        out["flags"] = flags
        out["is_suspicious"] = len(flags) > 0
        out["pdfid_ok"] = (r.returncode == 0)
        return out
    except Exception as e:
        out["error"] = f"pdfid_analyze failed: {e}"
        return out


def scdbg_emulate(sample_path: str, timeout: int = 30) -> dict:
    """Emulate x86 shellcode using scdbg (libemu-based). Reports API calls and behavior.

    Calls wine /opt/scdbg/scdbg.exe (console version) headlessly.
    Works on raw shellcode files or extracted shellcode sections.
    """
    import os, subprocess
    out: dict = {"scdbg_ok": False, "sample": sample_path}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    scdbg_exe = "/opt/scdbg/scdbg.exe"
    if not os.path.isfile(scdbg_exe):
        out["error"] = "scdbg.exe not found at /opt/scdbg/"
        return out
    try:
        env = os.environ.copy()
        env["WINEDEBUG"] = "-all"
        r = subprocess.run(
            ["wine", scdbg_exe, "-f", sample_path],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        stdout = r.stdout or ""
        stderr = r.stderr or ""
        out["scdbg_stdout"] = stdout[:5000]
        out["scdbg_stderr"] = stderr[:1000]
        out["scdbg_returncode"] = r.returncode

        # Parse output
        lines = stdout.splitlines()
        api_calls = []
        step_count = None
        errors = []
        for line in lines:
            line_s = line.strip()
            if "Stepcount" in line_s:
                try:
                    step_count = int(line_s.split()[-1])
                except Exception:
                    pass
            if "error" in line_s.lower() and "accessing" in line_s.lower():
                errors.append(line_s[:200])
            if any(api in line_s for api in ["GetProcAddress", "LoadLibrary", "WinExec", "URLDownload",
                                              "CreateProcess", "VirtualAlloc", "WriteProcessMemory",
                                              "CreateFile", "RegOpenKey", "InternetOpen", "HttpOpen",
                                              "connect", "send", "recv", "socket", "bind"]):
                api_calls.append(line_s[:300])

        out["step_count"] = step_count
        out["api_calls"] = api_calls[:50]
        out["errors"] = errors[:10]
        out["scdbg_ok"] = (r.returncode == 0 and step_count is not None and step_count > 0)
        return out
    except subprocess.TimeoutExpired:
        out["error"] = f"scdbg timed out after {timeout}s"
        return out
    except Exception as e:
        out["error"] = f"scdbg_emulate failed: {e}"
        return out


def r2_decompile(sample_path: str, function_addrs: list | None = None, timeout: int = 60) -> dict:
    """Disassemble functions using radare2 (asm-only, 2nd decompiler alongside Ghidra).

    Tries pdg (Ghidra decompiler plugin for r2) when available; otherwise falls back
    to pdf (asm tree). NOTE: output is asm text, not pseudo-C. Field is named
    `disassembly` (not `decompilations`) so downstream code does not mislabel it.
    One r2 invocation per function for clean output capture.

    Large binders (≥30MB): skip r2 `aaa` discovery (hangs/timeouts). Documented
    fail_open — Ghidra/IDA SQL decompile owns deep RE in large mode.
    """
    import os, subprocess
    out: dict = {"r2_ok": False, "sample": sample_path, "disassembly": {},
                 "engine": "pdf (disasm)", "fallback": True}
    if not os.path.isfile(sample_path):
        out["error"] = "file not found"
        return out
    try:
        size = os.path.getsize(sample_path)
    except OSError:
        size = 0
    # Auto-discover function addresses if not provided
    if not function_addrs:
        if size >= LARGE_SIZE_BYTES:
            return {
                "r2_ok": False,
                "sample": sample_path,
                "disassembly": {},
                "size_bytes": size,
                "fail_open": True,
                "skipped": True,
                "reason": (
                    f"r2 aaa discovery skipped for large sample "
                    f"({size} bytes ≥ {LARGE_SIZE_BYTES}); use ghidra/ida SQL decompile"
                ),
                "error": "r2 skipped on large sample",
            }
        try:
            disc = subprocess.run(
                ["r2", "-q", "-c", "aa; afl~[0,3]", sample_path],
                capture_output=True, text=True, timeout=60,
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
            if size >= LARGE_SIZE_BYTES:
                return {
                    "r2_ok": False,
                    "sample": sample_path,
                    "disassembly": {},
                    "size_bytes": size,
                    "fail_open": True,
                    "reason": f"r2 discovery failed on large sample: {e}",
                    "error": str(e),
                }
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


def r2_ai_decompile(sample_path: str, function_addrs: list, ollama_url: str | None = None, timeout: int = 90) -> dict:
    """AI-assisted decompilation using r2ai / decai plugins (r2 with Ollama LLM)."""
    import os, subprocess
    if ollama_url is None:
        ollama_url = os.environ.get("REVAI_OLLAMA_URL", "http://127.0.0.1:11434")
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


def _pe_imports_to_card(result) -> str:
    """Convert pe_imports tool → compact card (not capa)."""
    if not isinstance(result, dict):
        return f"## pe_imports\n  error: {result}\n"
    if result.get("error"):
        return f"## pe_imports\n  error: {result.get('error')}\n"
    signals = result.get("signals") or []
    lines = [
        f"## pe_imports ({int(result.get('import_count') or 0)} imports, "
        f"{int(result.get('signal_count') or len(signals))} high-signal)"
    ]
    for s in signals[:15]:
        if isinstance(s, dict):
            lab = s.get("label") or "?"
            api = s.get("api_match") or ""
            att = ",".join(s.get("attack") or [])
            lines.append(f"  {lab} ({api})" + (f" [{att}]" if att else ""))
        else:
            lines.append(f"  {s}")
    if not signals:
        lines.append("  (no high-signal APIs matched)")
    return "\n".join(lines)


def _capa_to_card(result) -> str:
    """Convert capa output → compact evidence card."""
    if not isinstance(result, dict):
        return f"## capa\n  error: {result}\n"
    if result.get("incomplete") or (
        "error" in result and not (result.get("top_rules") or result.get("rules") or result.get("matches"))
    ):
        return f"## capa\n  incomplete: {result.get('error') or 'no rules'}\n"
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
        "pe_imports": _pe_imports_to_card,
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
        "malcat", "capa", "pe_imports", "yara", "floss", "dotnet",
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


def package_stage_evidence(
    stage: str,
    tools: dict | None = None,
    *,
    budget_chars: int = 50000,
    sha: str = "",
    persist: bool = True,
) -> str:
    """Ranked stage-tagged tool evidence pack (no KB passages).

    Builds an EvidenceAssembler card set with provenance header
    ``<!-- stage: <stage> -->``. Optionally persists under
    ``logs/<sha>/<stage>/evidence-pack.md``.
    """
    tools = tools or {}
    asm = EvidenceAssembler(budget_chars=budget_chars)
    for tool in EvidenceAssembler.PRIORITY:
        if tool in tools:
            asm.add(tool, tools.get(tool))
    # Include any extra known cards not in PRIORITY order
    for tool, result in tools.items():
        if tool in EvidenceAssembler.TOOL_CARDS and tool not in {t for t, _ in asm.cards}:
            asm.add(tool, result)
    header = (
        f"## Tool evidence (stage={stage}, signal-prioritized)\n"
        f"<!-- stage: {stage} | sha={sha[:16] if sha else '-'} | "
        f"packaging=v6.1 -->"
    )
    pack = asm.render(header=header)
    if persist and sha:
        stage_dir = LOGS_DIR / sha / stage
        stage_dir.mkdir(parents=True, exist_ok=True)
        (stage_dir / "evidence-pack.md").write_text(pack, encoding="utf-8")
    return pack



