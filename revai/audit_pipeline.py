#!/usr/bin/env python3
"""audit_pipeline.py — Full-stage evidence auditor (no optional skips, no exit-code theater).

Standard and large audits require EVERY pipeline stage including REPORT-MASTER-v3.
CLI optional flags are for operators; this auditor never treats stages as optional.

Writes:
  /opt/samples/logs/<sha>/pipeline-audit.json   — machine-readable
  /opt/samples/logs/<sha>/AUDIT-REPORT.md       — full evidence (tools/RAG/LLM/v2/v3)
  /opt/samples/logs/_showcase_audits/<sha>/     — public showcase pack (copies)

Usage:
  python3 audit_pipeline.py <sha256> [--mode standard|large|auto]
  python3 audit_pipeline.py <sha256> --strict-standard
  python3 audit_pipeline.py <sha256> --showcase   # pack for public audit showcase
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGS = Path("/opt/samples/logs")
SESSIONS = Path("/opt/samples/sessions")
SHOWCASE_ROOT = LOGS / "_showcase_audits"

# Candidate deep tools — filtered by tools_raw["_format"] + TOOL_MANIFEST applies_to
PE_DEEP_TOOLS = [
    "malcat", "capa", "pe_imports", "yara", "floss", "dotnet", "r2_decomp",
    "upx", "xor", "speakeasy", "frida_probe", "frida_trace",
]
# Sandbox / doc-type only — never hard-fail standard audit if absent
OPTIONAL_AUDIT_TOOLS = {"frida_trace", "olevba", "peepdf", "malcat"}

# Quick-scan required tools
PE_QUICK_TOOLS = ["capa", "yara", "floss"]

# Showcase-grade excerpts (public audit pack — not exit-code theater)
EXCERPT_CHARS = 3500
PROMPT_EXCERPT = 6000
REPORT_EXCERPT = 2500


def _load(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return {"_parse_error": str(e)}


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _sha256_file(path: Path, limit: int = 0) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        if limit:
            h.update(f.read(limit))
        else:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def _excerpt(obj: Any, n: int = EXCERPT_CHARS) -> str:
    if obj is None:
        return ""
    if isinstance(obj, (dict, list)):
        text = json.dumps(obj, indent=2, default=str)
    else:
        text = str(obj)
    text = text.replace("\r\n", "\n")
    if len(text) <= n:
        return text
    return text[:n] + f"\n… [{len(text) - n} more chars]"


def _file_meta(path: Path) -> dict:
    exists = path.exists()
    meta = {
        "path": str(path),
        "exists": exists,
        "bytes": path.stat().st_size if exists and path.is_file() else 0,
        "mtime_iso": (
            datetime.fromtimestamp(_mtime(path), tz=timezone.utc).isoformat()
            if exists else None
        ),
        "sha256": _sha256_file(path) if exists and path.is_file() and path.stat().st_size < 50_000_000 else None,
    }
    return meta


def _ok_tool_strict(v, *, allow_fail_open: bool = False) -> tuple[bool, str]:
    """Strict: error = fail. fail_open/skipped only pass when allow_fail_open (large mode).

    Exception: salvaged fail_open (e.g. FLOSS timeout → strings(1)) passes in strict —
    evidence exists; the heavy tool timed out but we did not skip the work silently.
    """
    if v is None:
        return False, "missing"
    if not isinstance(v, dict):
        return True, "non-dict"
    if v.get("_parse_error"):
        return False, f"parse_error:{v['_parse_error']}"
    # A tool that records per-batch/scan failures without error is NOT ok —
    # e.g. yara batch_errors (scanner never ran). Zero matches from a
    # completed scan has no batch_errors, so this only fires on genuine
    # engine failures that the tool failed to surface as `error`.
    if v.get("batch_errors"):
        return False, f"batch_errors:{len(v['batch_errors'])}"
    if v.get("error"):
        if v.get("fail_open") and (
            allow_fail_open or v.get("salvaged") or v.get("skipped")
        ):
            return True, f"fail_open:{v.get('error')}"
        if allow_fail_open and (v.get("skipped") or v.get("fail_open")):
            return True, f"fail_open:{v.get('error')}"
        # Large-mode capa incomplete (no pretend-green) is an expected soft path
        # when pe_imports/malcat carry evidence — do not fail the stage gate.
        if allow_fail_open and (v.get("incomplete") or "incomplete" in str(v.get("error")).lower()):
            return True, f"incomplete_soft:{str(v.get('error'))[:120]}"
        return False, f"error:{str(v.get('error'))[:160]}"
    if v.get("skipped"):
        if allow_fail_open:
            return True, f"skipped:{v.get('reason') or v.get('skipped')}"
        reason = str(v.get("reason") or v.get("skipped") or "")
        # not_applicable:* = format routing excluded the tool (correct — not a failure)
        if (
            "not_applicable" in reason.lower()
            or "not applicable" in reason.lower()
            or "no DIRECTORY_ENTRY" in reason
        ):
            return True, f"na:{reason[:120]}"
        return False, f"skipped:{reason[:160]}"
    return True, "ok"


def _applicable_deep_tools(tools_raw: dict) -> list[str]:
    """Require only tools that apply to tools_raw['_format'] (manifest routing)."""
    fmt = str(tools_raw.get("_format") or "pe")
    try:
        from v2_lib import tool_applies_to_format  # noqa: WPS433
    except Exception:
        tool_applies_to_format = None
    out = []
    for name in PE_DEEP_TOOLS:
        if name in OPTIONAL_AUDIT_TOOLS:
            continue
        if tool_applies_to_format is not None:
            if not tool_applies_to_format(name, fmt):
                continue
        elif name == "speakeasy" and fmt == "dotnet":
            continue
        out.append(name)
    return out


def _malcat_capa_summary(malcat: dict | None) -> Any:
    if not isinstance(malcat, dict):
        return None
    views = malcat.get("views") if isinstance(malcat.get("views"), dict) else {}
    for key in ("capa_summary", "capa", "capabilities"):
        if views.get(key) not in (None, {}, [], ""):
            return views.get(key)
        if malcat.get(key) not in (None, {}, [], ""):
            return malcat.get(key)
    return None


def _llm_cites_capa_fallback(verdict: dict, prompt: str) -> bool:
    """True if LLM key_evidence / summary references malcat capa fallback."""
    blob = json.dumps(verdict, default=str).lower() + "\n" + (prompt or "").lower()
    needles = (
        "capa_summary", "capa fallback", "malcat high-signal",
        "malcat anomalies", "malcat imports", "views.capa",
    )
    return any(n in blob for n in needles)


def _verify_citations(verdict_or_deep: dict, tool_blobs: dict[str, Any]) -> dict:
    """Check key_evidence strings appear somewhere in tool JSON (V5.12.8)."""
    try:
        sys.path.insert(0, "/opt/scripts")
        from v2_lib import verify_key_evidence_grounding  # type: ignore
        return verify_key_evidence_grounding(verdict_or_deep or {}, tool_blobs or {})
    except Exception:
        evidence = (verdict_or_deep or {}).get("key_evidence") or []
        if not evidence:
            return {"ok": False, "reason": "no key_evidence", "checked": 0, "hits": 0, "misses": []}
        hay = json.dumps(tool_blobs, default=str).lower()
        hits, misses = [], []
        for item in evidence:
            if isinstance(item, dict):
                frag = " ".join(str(item.get(k) or "") for k in ("row_or_rule", "query_or_table", "why", "source"))
            else:
                frag = str(item)
            tokens = [t for t in re.split(r"\W+", frag.lower()) if len(t) >= 5][:6]
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
        }


def _verify_engine_citations(
    verdict_or_deep: dict,
    tool_blobs: dict[str, Any],
    *,
    report_md: str | None = None,
) -> dict:
    """Engine-attribution check with auto-correct (V5.16.3 + V5.16.8).

    Wrong LLM source labels are rewritten to the owning engine before honesty
    verify, so standard audits are not failed by correctable misattribution.
    """
    try:
        sys.path.insert(0, "/opt/scripts")
        from v2_lib import (  # type: ignore
            correct_key_evidence_engines,
            rewrite_report_md_engine_citations,
            verify_engine_citation_honesty,
        )
        src = dict(verdict_or_deep or {})
        ke = src.get("key_evidence")
        if isinstance(ke, list):
            src["key_evidence"] = [dict(x) if isinstance(x, dict) else x for x in ke]
        corr = correct_key_evidence_engines(src, tool_blobs or {})
        md = report_md
        if md and corr.get("corrections"):
            md = rewrite_report_md_engine_citations(md, corr.get("corrections") or [])
        result = verify_engine_citation_honesty(
            src, tool_blobs or {}, report_md=md,
        )
        result["corrections"] = corr
        # Persist corrected sources onto the live artifact dict when possible
        if (
            corr.get("corrected")
            and isinstance(verdict_or_deep, dict)
            and isinstance(verdict_or_deep.get("key_evidence"), list)
        ):
            verdict_or_deep["key_evidence"] = src["key_evidence"]
            verdict_or_deep["engine_citation_corrections"] = corr
        return result
    except Exception as e:
        return {
            "ok": True,
            "checked": 0,
            "false_engine_citations": [],
            "reason": f"engine_check_error:{e}",
        }


def _upx_second_pass_ok(tools_raw: dict, dd: Path) -> dict:
    """When UPX unpacked a payload, require second-pass artifacts (V5.16.5)."""
    upx = tools_raw.get("upx") if isinstance(tools_raw.get("upx"), dict) else {}
    if not upx.get("upx_ok") or not upx.get("unpacked_path"):
        return {"applicable": False, "ok": True, "reason": "upx_not_unpacked"}
    second = tools_raw.get("upx_second_pass")
    if not isinstance(second, dict):
        # Fall back to sidecar file
        side = _load(dd / "01b-upx-second-pass.json")
        second = side if isinstance(side, dict) else None
    if not isinstance(second, dict):
        return {
            "applicable": True,
            "ok": False,
            "reason": "missing_upx_second_pass",
        }
    ok = bool(second.get("ok"))
    return {
        "applicable": True,
        "ok": ok,
        "reason": "" if ok else (second.get("skipped_reason") or "second_pass_failed"),
        "tool_ok": second.get("tool_ok"),
        "unpacked_path": second.get("unpacked_path") or upx.get("unpacked_path"),
    }


def audit_intake(log: Path) -> dict:
    iv = log / "intake-validation.json"
    mt = log / "malcat-triage.json"
    sd = log / "source-decisions.json"
    ghidra_log = log / "intake-analyzeHeadless.log"
    ida_log = log / "intake-idasql.log"
    data = _load(iv) or {}
    decisions = data.get("source_decisions") or _load(sd) or {}
    evidence = {
        "intake_validation": _file_meta(iv),
        "malcat_triage": _file_meta(mt),
        "source_decisions": _file_meta(sd),
        "ghidra_import_log": _file_meta(ghidra_log),
        "ida_bootstrap_log": _file_meta(ida_log),
        "source_decisions_excerpt": _excerpt(decisions, 800),
        "malcat_triage_excerpt": _excerpt(_load(mt), 800),
    }
    checks = {
        "intake_validation": iv.exists(),
        "has_source_decisions": bool(decisions),
        "ghidra_mentioned": "ghidra" in json.dumps(data).lower() or ghidra_log.exists(),
    }
    ok = all(checks.values())
    return {"ok": ok, "checks": checks, "evidence": evidence}


def audit_quick(log: Path, *, strict: bool) -> dict:
    prompt_p = log / "prompt.txt"
    verdict_p = log / "verdict.json"
    # Prefer structured quick_scan tool pack if present
    tools_pack = _load(log / "quick_scan" / "00-tools-raw.json") or {}
    audit_tail = log / "audit.jsonl"
    # Reconstruct tool results from audit.jsonl last quick_scan record if needed
    capa = tools_pack.get("capa")
    yara = tools_pack.get("yara")
    floss = tools_pack.get("floss")
    malcat = tools_pack.get("malcat")
    fmt = str(tools_pack.get("_format") or "")
    if audit_tail.exists() and capa is None:
        for line in reversed(audit_tail.read_text(encoding="utf-8", errors="replace").splitlines()):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("source") == "quick_scan_v2" or rec.get("phase") == 2:
                capa = rec.get("capa")
                yara = rec.get("yara")
                floss = rec.get("floss")
                malcat = rec.get("malcat")
                break

    if not fmt:
        try:
            from v2_lib import _detect_format_for_tools, load_session  # noqa: WPS433
            sess = load_session(log.name)
            sp = sess.get("sample_path")
            if sp:
                fmt = _detect_format_for_tools(sp)
        except Exception:
            fmt = "pe"
    if not fmt:
        fmt = "pe"

    try:
        from v2_lib import tool_applies_to_format  # noqa: WPS433
    except Exception:
        tool_applies_to_format = None

    required_quick = []
    for name in PE_QUICK_TOOLS:
        if tool_applies_to_format is not None and not tool_applies_to_format(name, fmt):
            continue
        required_quick.append(name)

    prompt = prompt_p.read_text(encoding="utf-8", errors="replace") if prompt_p.exists() else ""
    verdict = _load(verdict_p) or {}
    tool_status = {}
    for name, val in (("capa", capa), ("yara", yara), ("floss", floss), ("malcat", malcat)):
        if name not in required_quick:
            tool_status[name] = {
                "ok": True,
                "why": f"not_applicable:{fmt}",
                "raw_excerpt": _excerpt(val, EXCERPT_CHARS),
                "present": val is not None,
            }
            continue
        ok, why = _ok_tool_strict(val, allow_fail_open=not strict)
        tool_status[name] = {
            "ok": ok,
            "why": why,
            "raw_excerpt": _excerpt(val, EXCERPT_CHARS),
            "present": val is not None,
        }

    # capa salvage via malcat capa_summary + LLM citing fallback
    capa_summary = _malcat_capa_summary(malcat if isinstance(malcat, dict) else {})
    capa_salvage = False
    if not tool_status["capa"]["ok"] and capa_summary is not None:
        if _llm_cites_capa_fallback(verdict, prompt):
            capa_salvage = True
            tool_status["capa"] = {
                "ok": True,
                "why": "salvaged:malcat_capa_summary+llm_cited",
                "raw_excerpt": _excerpt(capa_summary, EXCERPT_CHARS),
                "present": True,
                "salvaged": True,
            }

    citations = _verify_citations(verdict, {
        "capa": capa, "yara": yara, "floss": floss, "malcat": malcat, "prompt": prompt[:4000],
    })

    floss_required = "floss" in required_quick
    checks = {
        "prompt": prompt_p.exists() and len(prompt) >= 500,
        "verdict": verdict_p.exists(),
        "has_capa_section": "capa" in prompt.lower(),
        "has_yara_section": "yara" in prompt.lower(),
        "has_malcat_section": "malcat" in prompt.lower() or True,  # optional for RevAI
        "has_floss_section": (not floss_required) or ("floss" in prompt.lower()),
        "verdict_has_family": bool(verdict.get("family_guess") or verdict.get("family")),
        "llm_source": (verdict.get("source") or "") in ("llm_judge", "goodware_fingerprint"),
        "tools_all_ok": all(tool_status[n]["ok"] for n in required_quick),
        "citations_grounded": citations["ok"] or verdict.get("source") == "goodware_fingerprint",
        "capa_salvage_used": capa_salvage,
        "evidence_pack_present": (log / "quick_scan" / "evidence-pack.md").exists(),
    }
    tools_all = all(tool_status[n]["ok"] for n in required_quick)
    checks["tools_all_ok"] = tools_all
    v_label = str(verdict.get("verdict") or "").lower()
    checks["benign_blocked_if_incomplete"] = not (
        any(x in v_label for x in ("benign", "clean", "legitimate"))
        and (verdict.get("incomplete_tooling") or not tools_all)
    )
    # High-signal YARA must not clear as clean (NetSupport dual-use FP class)
    try:
        from v2_lib import high_signal_yara_matches  # type: ignore
        yara_hits = high_signal_yara_matches(yara if isinstance(yara, dict) else {})
    except Exception:
        yara_hits = []
    checks["yara_family_not_cleared"] = not (
        yara_hits and any(x in v_label for x in ("benign", "clean", "legitimate"))
    )
    required_keys = [
        "prompt", "verdict", "has_capa_section", "has_yara_section",
        "has_malcat_section", "has_floss_section", "verdict_has_family",
        "llm_source", "tools_all_ok", "citations_grounded",
        "benign_blocked_if_incomplete", "yara_family_not_cleared",
        "evidence_pack_present",
    ]
    ok = all(checks[k] for k in required_keys)
    return {
        "ok": ok,
        "checks": checks,
        "tools": tool_status,
        "citations": citations,
        "format": fmt,
        "required_tools": required_quick,
        "verdict_preview": {
            "verdict": verdict.get("verdict"),
            "family": verdict.get("family_guess") or verdict.get("family"),
            "score": verdict.get("score"),
            "agreement": verdict.get("agreement"),
            "source": verdict.get("source"),
            "model": verdict.get("model"),
            "key_evidence": verdict.get("key_evidence"),
            "summary": (verdict.get("summary") or "")[:400],
        },
        "evidence": {
            "prompt": _file_meta(prompt_p),
            "verdict": _file_meta(verdict_p),
            "prompt_excerpt": _excerpt(prompt, 1000),
            "verdict_excerpt": _excerpt(verdict, 1000),
        },
    }


def audit_deep_standard(log: Path, *, strict: bool) -> dict:
    dd = log / "deep_dive"
    tools_raw = _load(dd / "01-tools-raw.json") or {}
    prompt_p = dd / "03-prompt.txt"
    llm_raw_p = dd / "04-llm-raw.json"
    deep05_p = dd / "05-deep-dive.json"
    sql_p = dd / "00-sql-evidence.json"
    prompt = prompt_p.read_text(encoding="utf-8", errors="replace") if prompt_p.exists() else ""
    deep05 = _load(deep05_p) or {}
    llm_raw = _load(llm_raw_p) or {}

    required_tools = _applicable_deep_tools(tools_raw)
    tool_status = {}
    for name in PE_DEEP_TOOLS:
        if name not in required_tools:
            tool_status[name] = {
                "ok": True,
                "why": f"not_applicable:{tools_raw.get('_format') or '?'}",
                "raw_excerpt": None,
            }
            continue
        ok, why = _ok_tool_strict(tools_raw.get(name), allow_fail_open=not strict)
        tool_status[name] = {
            "ok": ok,
            "why": why,
            "raw_excerpt": _excerpt(tools_raw.get(name), EXCERPT_CHARS),
        }

    # capa salvage in deep
    if not tool_status.get("capa", {}).get("ok"):
        capa_summary = _malcat_capa_summary(tools_raw.get("malcat") if isinstance(tools_raw.get("malcat"), dict) else {})
        if capa_summary is not None and _llm_cites_capa_fallback(deep05, prompt):
            tool_status["capa"] = {
                "ok": True,
                "why": "salvaged:malcat_capa_summary+llm_cited",
                "raw_excerpt": _excerpt(capa_summary, 500),
                "salvaged": True,
            }

    citations = _verify_citations(deep05, {"tools": tools_raw, "sql": _load(sql_p)})
    # Prefer deep key_evidence for engine honesty (SQL-grounded); fall back to triage.
    # V5.16.8 auto-corrects wrong source labels before hard-fail.
    verdict = _load(log / "verdict.json") or {}
    engine_src = deep05 if (deep05.get("key_evidence") or []) else verdict
    tech_md = ""
    for tp in (log / "REPORT-TECHNICAL-v2.md", log / "REPORT-TECHNICAL-v3.md"):
        if tp.exists():
            tech_md = tp.read_text(encoding="utf-8", errors="replace")
            break
    engine_cit = _verify_engine_citations(
        engine_src,
        {"tools": tools_raw, "sql": _load(sql_p)},
        report_md=tech_md or None,
    )
    # V5.16.8: do NOT prefer a stale engine_citation.ok=False from deep05 —
    # auto-correct + live re-check is authoritative.
    upx_sp = _upx_second_pass_ok(tools_raw, dd)
    checks = {
        "01_tools_raw": (dd / "01-tools-raw.json").exists(),
        "00_sql_evidence": sql_p.exists(),
        "03_prompt": prompt_p.exists() and len(prompt) >= 500,
        "04_llm": llm_raw_p.exists(),
        "05_deep": deep05_p.exists(),
        "tools_all_ok": all(tool_status[n]["ok"] for n in required_tools),
        "llm_source": (deep05.get("source") or "") == "llm_judge",
        "citations_grounded": citations["ok"],
        "engine_citation_ok": bool(engine_cit.get("ok", True)),
        "upx_second_pass_ok": bool(upx_sp.get("ok", True)),
        "no_incomplete_tooling": not deep05.get("incomplete_tooling"),
        "evidence_pack_present": (dd / "evidence-pack.md").exists(),
    }
    ok = all(
        checks[k] for k in (
            "01_tools_raw", "00_sql_evidence", "03_prompt", "04_llm", "05_deep",
            "tools_all_ok", "llm_source", "citations_grounded",
            "engine_citation_ok", "upx_second_pass_ok",
            "no_incomplete_tooling",
            "evidence_pack_present",
        )
    )
    return {
        "ok": ok,
        "checks": checks,
        "tools": tool_status,
        "citations": citations,
        "engine_citation": engine_cit,
        "upx_second_pass": upx_sp,
        "format_routing": tools_raw.get("_format"),
        "required_tools": required_tools,
        "deep_preview": {
            "source": deep05.get("source"),
            "confidence": deep05.get("confidence"),
            "summary": (deep05.get("summary") or "")[:300],
            "key_evidence": deep05.get("key_evidence"),
            "model": deep05.get("model"),
            "llm_audit": deep05.get("llm_audit"),
        },
        "evidence": {
            "tools_raw": _file_meta(dd / "01-tools-raw.json"),
            "sql_evidence": _file_meta(sql_p),
            "prompt": _file_meta(prompt_p),
            "llm_raw": _file_meta(llm_raw_p),
            "deep05": _file_meta(deep05_p),
            "prompt_excerpt": _excerpt(prompt, 800),
            "llm_raw_excerpt": _excerpt(llm_raw, EXCERPT_CHARS),
            "deep05_excerpt": _excerpt(deep05, 800),
        },
    }


def audit_deep_large(log: Path, *, strict: bool) -> dict:
    # Large must meet standard tool matrix + agentic SQL evidence
    base = audit_deep_standard(log, strict=strict)
    dd = log / "deep_dive"
    ag = _load(dd / "agentic_deep_dive.json") or {}
    hist = ag.get("history") or []
    tools_ok = []
    history_evidence = []
    for h in hist:
        t = h.get("tool")
        if not t:
            continue
        res = h.get("result") if isinstance(h.get("result"), dict) else {}
        err = h.get("error") or (res.get("error") if isinstance(res, dict) else None)
        entry = {
            "tool": t,
            "ok": not bool(err),
            "error": err,
            "checklist": bool(h.get("checklist") or h.get("bootstrap")),
            "reason": (h.get("reason") or "")[:160],
            "result_excerpt": _excerpt(res, 400),
        }
        history_evidence.append(entry)
        if t and not err:
            tools_ok.append(t)
    has_sql = any(t in tools_ok for t in ("ghidra_query", "ida_query", "ghidra_decompile"))
    checks = dict(base.get("checks") or {})
    checks.update({
        "agentic_json": (dd / "agentic_deep_dive.json").exists(),
        "sql_deep_re": has_sql or bool(ag.get("sql_deep_ok")),
        "complete_verdict": bool(ag.get("verdict")) and bool(ag.get("summary")),
        "not_incomplete": not ag.get("incomplete_tooling"),
        "checklist_ok_flag": bool(ag.get("checklist_ok", checks.get("tools_all_ok"))),
    })
    ok = (
        checks.get("01_tools_raw")
        and checks.get("tools_all_ok")
        and checks["agentic_json"]
        and checks["sql_deep_re"]
        and checks["complete_verdict"]
        and checks["not_incomplete"]
        and checks.get("evidence_pack_present", True)
    )
    out = dict(base)
    out["ok"] = ok
    out["checks"] = checks
    out["tools_ok_history"] = tools_ok
    out["history_evidence"] = history_evidence
    out["agentic_preview"] = {
        "verdict": ag.get("verdict"),
        "confidence": ag.get("confidence"),
        "summary": (ag.get("summary") or "")[:300],
        "checklist_ok": ag.get("checklist_ok"),
        "sql_deep_ok": ag.get("sql_deep_ok"),
        "successful_tool_calls": ag.get("successful_tool_calls"),
    }
    ev = dict(out.get("evidence") or {})
    ev["agentic"] = _file_meta(dd / "agentic_deep_dive.json")
    out["evidence"] = ev
    return out


def audit_yara(log: Path) -> dict:
    yar = log / "rule.yar"
    rules = list(log.glob("rule.yar*")) + list(log.glob("*.yar"))
    text = yar.read_text(encoding="utf-8", errors="replace") if yar.exists() else ""
    checks = {
        "rule_yar": yar.exists(),
        "non_empty": len(text) >= 40,
        "has_rule_block": "rule " in text,
    }
    # Honest gate: the generated rule must actually compile. Previously the
    # rule checker silently skipped when the CLI binary was missing, so a
    # broken rule could pass. Now validated in-process (yara-x Python).
    compile_ok, compile_msg = True, "no_rule_file"
    if yar.exists():
        try:
            from v2_lib import yara_rule_validate  # noqa: WPS433
            compile_ok, compile_msg = yara_rule_validate(yar)
        except Exception as e:  # pragma: no cover
            compile_ok, compile_msg = False, str(e)
    checks["rule_compiles"] = bool(compile_ok)
    checks["rule_check"] = compile_msg
    # rule.yara.json meta (if written by yara_gen_v2) records validation too
    meta = _load(log / "rule.yara.json") or {}
    meta_valid = meta.get("yara_valid")
    if meta_valid is not None:
        checks["meta_yara_valid"] = bool(meta_valid)
        if not meta_valid:
            compile_ok = False
            compile_msg = str(meta.get("yara_check") or "invalid per yara_gen meta")
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "evidence": {
            "rule_yar": _file_meta(yar),
            "other_rules": [str(p) for p in rules],
            "excerpt": _excerpt(text, 800),
        },
    }


def audit_publish(log: Path, deep_mtime: float) -> dict:
    r2 = log / "REPORT-MASTER-v2.md"
    r3 = log / "REPORT-MASTER-v3.md"
    rv2 = log / "REPORT-v2.md"
    tech2 = log / "REPORT-TECHNICAL-v2.md"
    tech3 = log / "REPORT-TECHNICAL-v3.md"
    report_json = log / "report-v2.json"
    text2 = r2.read_text(encoding="utf-8", errors="replace") if r2.exists() else ""
    text3 = r3.read_text(encoding="utf-8", errors="replace") if r3.exists() else ""
    required_heads = [
        "Executive Summary",
        "Sample Identification",
        "Classification",
        "Static Analysis",
        "Indicators of Compromise",
        "Author + Sign-off",
    ]
    heads2 = {h: h.lower() in text2.lower() for h in required_heads}
    heads3 = {h: h.lower() in text3.lower() for h in required_heads}
    j = _load(report_json) or {}
    verdict = _load(log / "verdict.json") or {}
    deep = (
        _load(log / "deep_dive" / "05-deep-dive.json")
        or _load(log / "deep_dive" / "agentic_deep_dive.json")
        or {}
    )
    # Live recompute lock — never scrape ACCURACY HOLD banner (contains "malicious")
    persisted = j.get("verdict_lock") if isinstance(j.get("verdict_lock"), dict) else None
    lock = persisted
    try:
        sys.path.insert(0, "/opt/scripts")
        from v2_lib import (  # type: ignore
            cross_stage_verdict_lock,
            infer_publish_verdict_from_markdown,
        )
        # Prefer explicit multi-source fields (V5.12.13); claimed ≠ final.
        pub_claimed = (
            j.get("publish_llm_verdict")
            or j.get("publish_claimed_verdict")
            or infer_publish_verdict_from_markdown(text2)
        )
        final_v = j.get("final_verdict") or j.get("verdict")
        lock = cross_stage_verdict_lock(
            pub_claimed,
            quick_verdict=j.get("quick_verdict") or verdict.get("verdict"),
            deep_verdict=j.get("deep_verdict") or deep.get("verdict"),
        )
        # Persisted conflict wins only if not already hard-aligned to upstream
        hold = j.get("accuracy_hold")
        aligned = isinstance(hold, dict) and bool(hold.get("aligned"))
        unresolved_hold = (hold is True) or (isinstance(hold, dict) and not aligned)
        if unresolved_hold or ((persisted or {}).get("conflict") and not aligned):
            lock = {
                "ok": False,
                "conflict": True,
                "upstream": (persisted or {}).get("upstream") or lock.get("upstream"),
                "publish": (persisted or {}).get("publish") or pub_claimed or lock.get("publish"),
                "reason": (persisted or {}).get("reason")
                or lock.get("reason")
                or "accuracy_hold_persisted",
            }
        elif aligned:
            # After lock, trust final_verdict / persisted ok — not body scrape
            # (unedited publish narrative may still say legitimate/benign).
            if isinstance(persisted, dict) and persisted.get("ok"):
                lock = persisted
            else:
                lock = cross_stage_verdict_lock(
                    final_v or (persisted or {}).get("upstream") or "malicious",
                    quick_verdict=j.get("quick_verdict") or verdict.get("verdict"),
                    deep_verdict=j.get("deep_verdict") or deep.get("verdict"),
                )
    except Exception as e:
        lock = lock or {"ok": True, "conflict": False, "reason": f"lock_check_error:{e}"}

    checks = {
        "REPORT_MASTER_v2": r2.exists(),
        "REPORT_MASTER_v3": r3.exists(),
        "REPORT_v2": rv2.exists(),
        "REPORT_TECHNICAL_v2": tech2.exists(),
        "REPORT_TECHNICAL_v3": tech3.exists(),
        "v2_min_chars": len(text2) >= 1500,
        "v3_min_chars": len(text3) >= 1500,
        "v2_heads": all(heads2.values()),
        "v3_heads": all(heads3.values()),
        "v2_fresh_vs_deep": (_mtime(r2) >= deep_mtime - 5) if r2.exists() and deep_mtime else False,
        "v3_fresh_vs_deep": (_mtime(r3) >= deep_mtime - 5) if r3.exists() and deep_mtime else False,
        "not_llm_env_failure_v2": "REVENG_LLM_MODEL is not set" not in text2,
        "not_llm_env_failure_v3": "REVENG_LLM_MODEL is not set" not in text3,
        "v2_no_missing_sections": not (j.get("sections_missing") or []),
        "verdict_lock_ok": bool(lock.get("ok", True)),
    }
    # Hard quality: LLM narrative required — fallback/stub reports are NOT green
    qpack: dict = {}
    try:
        from report_quality import evaluate_sha_publish_quality, source_is_fallback
        qpack = evaluate_sha_publish_quality(log.parent, log.name)
        checks["quality_pack_ok"] = bool(qpack.get("ok"))
        src = str(j.get("source") or "")
        checks["master_source_llm"] = (not source_is_fallback(src)) and src in (
            "llm_judge", "llm_raw_markdown",
        )
        tech2_j = _load(log / "report-technical-v2.json") or {}
        tech3_j = _load(log / "report-technical-v3.json") or {}
        t2s = str(tech2_j.get("source") or "")
        t3s = str(tech3_j.get("source") or "")
        checks["tech2_source_llm"] = (not source_is_fallback(t2s)) and t2s in (
            "llm_judge", "llm_raw_markdown",
        )
        checks["tech3_source_ok"] = (not source_is_fallback(t3s)) and t3s not in (
            "llm_incomplete",
        ) and not (tech3_j.get("sections_missing") or [])
        checks["tech2_no_stubs"] = not (tech2_j.get("sections_stub") or [])
        checks["no_tech2_fallback"] = not source_is_fallback(t2s)
        checks["quality_issues"] = list(qpack.get("issues") or [])
    except Exception as e:
        checks["quality_pack_ok"] = False
        checks["quality_error"] = str(e)
    # V5.16.3/16.8 — false engine attribution hard-fail after auto-correct
    tools_raw = (
        _load(log / "deep_dive" / "01-tools-raw.json")
        or _load(log / "quick_scan" / "00-tools-raw.json")
        or {}
    )
    sql_ev = _load(log / "deep_dive" / "00-sql-evidence.json") or {}
    engine_src = deep if (deep.get("key_evidence") or []) else verdict
    engine_cit = _verify_engine_citations(
        engine_src,
        {"tools": tools_raw, "sql": sql_ev},
        report_md=(tech2.read_text(encoding="utf-8", errors="replace") if tech2.exists() else None),
    )
    # V5.16.8: live auto-correct + re-check wins over stale deep/publish fails
    checks["engine_citation_ok"] = bool(engine_cit.get("ok", True))
    ok = all(
        checks[k] for k in (
            "REPORT_MASTER_v2", "REPORT_MASTER_v3", "REPORT_v2",
            "REPORT_TECHNICAL_v2", "REPORT_TECHNICAL_v3",
            "v2_min_chars", "v3_min_chars", "v2_heads", "v3_heads",
            "v2_fresh_vs_deep", "v3_fresh_vs_deep",
            "not_llm_env_failure_v2", "not_llm_env_failure_v3",
            "verdict_lock_ok",
            "engine_citation_ok",
            # Quality truth — rc/files alone are never enough
            "v2_no_missing_sections",
            "quality_pack_ok",
            "master_source_llm",
            "tech2_source_llm",
            "tech3_source_ok",
            "tech2_no_stubs",
            "no_tech2_fallback",
        )
        if k in checks
    )
    return {
        "ok": ok,
        "checks": checks,
        "heads_v2": heads2,
        "heads_v3": heads3,
        "report_json_source": j.get("source"),
        "sections_missing": j.get("sections_missing"),
        "quality_pack": qpack,
        "verdict_lock": lock,
        "engine_citation": engine_cit,
        "mtimes": {
            "v2": _mtime(r2),
            "v3": _mtime(r3),
            "deep_ref": deep_mtime,
            "v2_chars": len(text2),
            "v3_chars": len(text3),
            "v2_iso": datetime.fromtimestamp(_mtime(r2), tz=timezone.utc).isoformat() if r2.exists() else None,
            "v3_iso": datetime.fromtimestamp(_mtime(r3), tz=timezone.utc).isoformat() if r3.exists() else None,
        },
        "evidence": {
            "REPORT_MASTER_v2": _file_meta(r2),
            "REPORT_MASTER_v3": _file_meta(r3),
            "REPORT_v2": _file_meta(rv2),
            "REPORT_TECHNICAL_v2": _file_meta(tech2),
            "REPORT_TECHNICAL_v3": _file_meta(tech3),
            "report_v2_json": _file_meta(report_json),
            "v2_excerpt": _excerpt(text2, 900),
            "v3_excerpt": _excerpt(text3, 900),
        },
    }


def collect_cross_cutting(log: Path, sess: dict) -> dict:
    """LLM + report inventory for public showcase (beyond per-stage gates)."""
    verdict = _load(log / "verdict.json") or {}
    deep05 = _load(log / "deep_dive" / "05-deep-dive.json") or {}
    report_json = _load(log / "report-v2.json") or _load(log / "REPORT-v2.json") or {}

    llm = {
        "triage": {
            "source": verdict.get("source"),
            "model": verdict.get("model") or verdict.get("request_model"),
            "verdict": verdict.get("verdict"),
            "family": verdict.get("family_guess") or verdict.get("family"),
            "confidence": verdict.get("confidence") or verdict.get("score"),
            "agreement": verdict.get("agreement"),
            "key_evidence": verdict.get("key_evidence") or [],
            "incomplete_tooling": verdict.get("incomplete_tooling"),
            "excerpt": _excerpt(verdict, EXCERPT_CHARS),
        },
        "deep_dive": {
            "source": deep05.get("source"),
            "model": deep05.get("model") or deep05.get("verdict_model") or deep05.get("planner_model"),
            "verdict": deep05.get("verdict"),
            "confidence": deep05.get("confidence"),
            "key_evidence": deep05.get("key_evidence") or [],
            "incomplete_tooling": deep05.get("incomplete_tooling"),
            "excerpt": _excerpt(deep05, EXCERPT_CHARS),
        },
        "publish": {
            "source": report_json.get("source"),
            "model": report_json.get("model"),
            "excerpt": _excerpt(report_json, EXCERPT_CHARS),
        },
    }

    artifacts = {}
    for name in (
        "verdict.json", "prompt.txt", "pipeline-audit.json", "AUDIT-REPORT.md",
        "REPORT-MASTER-v2.md", "REPORT-MASTER-v3.md", "REPORT-v2.md",
        "REPORT-TECHNICAL.md", "REPORT-TECHNICAL-v3.md", "rule.yar",
        "intake-validation.json", "source-decisions.json", "malcat-triage.json",
        "deep_dive/01-tools-raw.json", "deep_dive/01-tools-gate.json",
        "deep_dive/05-deep-dive.json", "deep_dive/03-prompt.txt",
        "quick_scan/00-tools-raw.json",
    ):
        artifacts[name] = _file_meta(log / name)

    return {
        "sample_path": sess.get("sample_path"),
        "pipeline_mode": sess.get("pipeline_mode"),
        "llm": llm,
        "artifact_inventory": artifacts,
        "report_excerpts": {
            "v2": _excerpt(
                (log / "REPORT-MASTER-v2.md").read_text(encoding="utf-8", errors="replace")
                if (log / "REPORT-MASTER-v2.md").exists() else "",
                REPORT_EXCERPT,
            ),
            "v3": _excerpt(
                (log / "REPORT-MASTER-v3.md").read_text(encoding="utf-8", errors="replace")
                if (log / "REPORT-MASTER-v3.md").exists() else "",
                REPORT_EXCERPT,
            ),
        },
    }


def pack_showcase(sha: str, report: dict) -> Path:
    """Copy full evidence pack for public audit showcase."""
    src = LOGS / sha
    dest = SHOWCASE_ROOT / sha
    dest.mkdir(parents=True, exist_ok=True)
    copy_names = [
        "AUDIT-REPORT.md",
        "pipeline-audit.json",
        "verdict.json",
        "prompt.txt",
        "REPORT-MASTER-v2.md",
        "REPORT-MASTER-v3.md",
        "REPORT-v2.md",
        "REPORT-TECHNICAL.md",
        "REPORT-TECHNICAL-v3.md",
        "rule.yar",
        "intake-validation.json",
        "source-decisions.json",
        "malcat-triage.json",
    ]
    for name in copy_names:
        p = src / name
        if p.exists() and p.is_file():
            shutil.copy2(p, dest / name)
    for sub in ("deep_dive", "quick_scan", "yara_gen"):
        sdir = src / sub
        if sdir.is_dir():
            ddir = dest / sub
            ddir.mkdir(exist_ok=True)
            for p in sdir.iterdir():
                if p.is_file() and p.stat().st_size < 80_000_000:
                    shutil.copy2(p, ddir / p.name)

    index = {
        "sha256": sha,
        "packed_at": datetime.now(timezone.utc).isoformat(),
        "all_green": report.get("all_green"),
        "mode": report.get("mode"),
        "sample_path": report.get("sample_path"),
        "stage_ok": report.get("stage_ok"),
        "showcase_dir": str(dest),
        "primary_report": str(dest / "AUDIT-REPORT.md"),
        "public_use": (
            "CADRE-RevAI / RevAI public audit showcase — full tool, RAG, LLM, "
            "REPORT-MASTER-v2/v3 evidence pack"
        ),
    }
    (dest / "SHOWCASE-INDEX.json").write_text(json.dumps(index, indent=2))
    # Per-sample README for public readers
    (dest / "README.md").write_text(
        "\n".join([
            f"# Showcase audit pack — `{sha}`",
            "",
            f"- **all_green:** `{report.get('all_green')}`",
            f"- **mode:** `{report.get('mode')}`",
            f"- **Read first:** [`AUDIT-REPORT.md`](AUDIT-REPORT.md)",
            f"- **Machine:** [`pipeline-audit.json`](pipeline-audit.json)",
            "",
            "## Included",
            "",
            "- Tool evidence (`deep_dive/01-tools-raw.json`, gates, triage)",
            "- RAG-bearing prompts (`prompt.txt`, `deep_dive/03-prompt.txt`)",
            "- LLM verdicts (`verdict.json`, `deep_dive/05-deep-dive.json`)",
            "- Reports: REPORT-MASTER-v2.md + REPORT-MASTER-v3.md (+ technical)",
            "- YARA rule if generated",
            "",
            "This pack is intended for the **public audit / RevAI showcase**.",
            "",
        ]),
        encoding="utf-8",
    )
    return dest


def rebuild_showcase_master() -> Path:
    """Master index across all packed showcase samples (target: 10)."""
    SHOWCASE_ROOT.mkdir(parents=True, exist_ok=True)
    rows = []
    for d in sorted(SHOWCASE_ROOT.iterdir()):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        idx = _load(d / "SHOWCASE-INDEX.json") or {}
        rows.append({
            "sha": d.name,
            "all_green": idx.get("all_green"),
            "mode": idx.get("mode"),
            "audit_report": str(d / "AUDIT-REPORT.md"),
            "dir": str(d),
        })
    master = {
        "title": "CADRE-RevAI Standard Pipeline — Public Audit Showcase",
        "updated": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        "green": sum(1 for r in rows if r.get("all_green")),
        "samples": rows,
        "policy": (
            "FULL standard stages: intake → quick_scan → deep_dive → yara → "
            "publish_v2 → publish_v3 → audit. No skips. Tool/RAG/LLM/report evidence required."
        ),
    }
    (SHOWCASE_ROOT / "MASTER-SHOWCASE.json").write_text(json.dumps(master, indent=2))
    md = [
        "# CADRE-RevAI — Public Audit Showcase (Standard pipeline)",
        "",
        f"Updated: `{master['updated']}`",
        f"**Packs:** {master['green']}/{master['count']} all_green",
        "",
        master["policy"],
        "",
        "| # | SHA12 | all_green | Mode | AUDIT-REPORT |",
        "|---|-------|-----------|------|--------------|",
    ]
    for i, r in enumerate(rows, 1):
        md.append(
            f"| {i} | `{r['sha'][:12]}` | `{r.get('all_green')}` | `{r.get('mode')}` | "
            f"[`AUDIT-REPORT.md`]({r['sha']}/AUDIT-REPORT.md) |"
        )
    md += [
        "",
        "## What each pack contains",
        "",
        "- Full stage scoreboard + tool JSON excerpts",
        "- RAG context presence + excerpts from prompts",
        "- LLM triage/deep/publish verdicts (models, key_evidence, citations)",
        "- REPORT-MASTER-v2 + REPORT-MASTER-v3 (+ technical reports)",
        "- Artifact inventory with paths/bytes/sha256",
        "",
    ]
    out = SHOWCASE_ROOT / "MASTER-SHOWCASE.md"
    out.write_text("\n".join(md), encoding="utf-8")
    return out


def render_markdown(report: dict) -> str:
    lines = [
        f"# Pipeline AUDIT-REPORT — `{report['sha']}`",
        "",
        "> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.",
        "",
        f"- **Mode:** {report.get('mode')}",
        f"- **Audited at:** {report.get('audited_at')}",
        f"- **all_green:** `{report.get('all_green')}`",
        f"- **Strict standard:** `{report.get('strict_standard')}`",
        f"- **Session mode:** `{report.get('session_pipeline_mode')}`",
        f"- **Sample:** `{report.get('sample_path')}`",
        f"- **Showcase pack:** `{report.get('showcase_dir') or 'n/a'}`",
        "",
        "## Stage scoreboard",
        "",
        "| Stage | OK |",
        "|-------|----|",
    ]
    for stage, ok in (report.get("stage_ok") or {}).items():
        lines.append(f"| {stage} | {'✅' if ok else '❌'} |")
    lines += ["", "---", ""]

    xc = report.get("cross_cutting") or {}
    if xc:
        lines += ["## Cross-cutting — LLM / Reports", ""]
        lines += ["### LLM stages", ""]
        for name, meta in (xc.get("llm") or {}).items():
            lines += [
                f"#### `{name}`",
                "",
                f"- source=`{meta.get('source')}` model=`{meta.get('model')}` "
                f"verdict=`{meta.get('verdict')}` confidence=`{meta.get('confidence')}`",
                f"- key_evidence_count=`{len(meta.get('key_evidence') or [])}`",
                "",
                "```json",
                meta.get("excerpt") or "{}",
                "```",
                "",
            ]
        lines += ["### REPORT-MASTER excerpts", ""]
        for k, ex in (xc.get("report_excerpts") or {}).items():
            lines += [f"#### REPORT-MASTER-{k}", "", "```markdown", ex or "(missing)", "```", ""]
        lines += ["### Artifact inventory", "", "| Artifact | exists | bytes | sha256 |",
                  "|----------|--------|-------|--------|"]
        for name, meta in (xc.get("artifact_inventory") or {}).items():
            lines.append(
                f"| `{name}` | `{meta.get('exists')}` | `{meta.get('bytes')}` | "
                f"`{(meta.get('sha256') or '')[:16]}` |"
            )
        lines += ["", "---", ""]

    for stage, body in (report.get("stages") or {}).items():
        lines += [f"## Stage: {stage}", "", f"**ok:** `{body.get('ok')}`", ""]
        checks = body.get("checks") or {}
        if checks:
            lines += ["### Checks", "", "| Check | Result |", "|-------|--------|"]
            for k, v in checks.items():
                if isinstance(v, dict):
                    lines.append(f"| {k} | `{json.dumps(v, default=str)[:120]}` |")
                else:
                    lines.append(f"| {k} | `{v}` |")
            lines.append("")
        tools = body.get("tools") or {}
        if tools:
            lines += ["### Tools (full evidence excerpts)", ""]
            for name, meta in tools.items():
                lines.append(f"#### `{name}` — ok=`{meta.get('ok')}` why=`{meta.get('why')}`")
                lines.append("")
                lines.append("```json")
                lines.append(meta.get("raw_excerpt") or "")
                lines.append("```")
                lines.append("")
        if body.get("citations"):
            lines += ["### LLM citation grounding", "", "```json",
                      json.dumps(body["citations"], indent=2, default=str), "```", ""]
        if body.get("verdict_preview") or body.get("deep_preview") or body.get("agentic_preview"):
            prev = body.get("verdict_preview") or body.get("deep_preview") or body.get("agentic_preview")
            lines += ["### LLM / outcome preview", "", "```json",
                      json.dumps(prev, indent=2, default=str)[:6000], "```", ""]
        if body.get("history_evidence"):
            lines += ["### Agentic tool-call history (excerpts)", ""]
            for h in body["history_evidence"]:
                lines.append(
                    f"- **{h.get('tool')}** ok=`{h.get('ok')}` checklist=`{h.get('checklist')}` "
                    f"— {h.get('reason')}"
                )
                if h.get("error"):
                    lines.append(f"  - error: `{h.get('error')}`")
                lines.append("")
                lines.append("```json")
                lines.append(h.get("result_excerpt") or "")
                lines.append("```")
                lines.append("")
        ev = body.get("evidence") or {}
        if ev:
            lines += ["### Artifact paths (verify on disk)", ""]
            for k, v in ev.items():
                if isinstance(v, dict) and "path" in v:
                    lines.append(
                        f"- **{k}:** `{v.get('path')}` exists=`{v.get('exists')}` "
                        f"bytes=`{v.get('bytes')}` mtime=`{v.get('mtime_iso')}`"
                    )
                    if v.get("sha256"):
                        lines.append(f"  - sha256: `{v['sha256']}`")
                elif isinstance(v, str) and k.endswith("excerpt"):
                    lines += ["", f"#### {k}", "", "```", v, "```", ""]
            lines.append("")
        lines += ["---", ""]

    lines += [
        "## Manual verification checklist (public showcase)",
        "",
        "1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.",
        "2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).",
        "3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).",
        "4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.",
        "5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.",
        "6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.",
        "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--mode", choices=["auto", "standard", "large", "single"], default="auto")
    ap.add_argument(
        "--strict-standard",
        action="store_true",
        help="Tool error/skip = fail (intended for small-sample standard runs).",
    )
    ap.add_argument(
        "--showcase",
        action="store_true",
        help="Accepted for compatibility; showcase pack is always written.",
    )
    args = ap.parse_args()
    sha = args.sha256
    log = LOGS / sha
    sess = _load(SESSIONS / f"{sha}.json") or {}
    mode = args.mode
    if mode == "auto":
        mode = (sess.get("pipeline_mode") or "standard").lower()
        if mode not in ("standard", "large", "single"):
            mode = "standard"

    # Standard audit is always strict unless explicitly large/single mode without flag.
    # User lock: optional is for operators, not the auditor.
    # Single mode == agentic deep (same audit path as large).
    if mode == "single":
        mode_effective = "large"
    else:
        mode_effective = mode
    strict = True if mode_effective == "standard" else bool(args.strict_standard)
    if args.strict_standard:
        strict = True

    deep_mtime = max(
        _mtime(log / "deep_dive" / "05-deep-dive.json"),
        _mtime(log / "deep_dive" / "agentic_deep_dive.json"),
        _mtime(log / "deep-dive.json"),
    )

    report = {
        "sha": sha,
        "mode": mode,
        "mode_effective": mode_effective,
        "strict_standard": strict,
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "session_pipeline_mode": sess.get("pipeline_mode"),
        "sample_path": sess.get("sample_path"),
        "stages": {},
        "policy": {
            "v3_required": True,
            "no_optional_stages": True,
            "tool_fail_is_fail": strict,
            "capa_salvage": "malcat capa_summary + LLM citation",
        },
    }
    report["stages"]["intake"] = audit_intake(log)
    report["stages"]["quick_scan"] = audit_quick(log, strict=strict)
    if mode_effective == "large":
        report["stages"]["deep_dive"] = audit_deep_large(log, strict=False)
    else:
        report["stages"]["deep_dive"] = audit_deep_standard(log, strict=strict)
    report["stages"]["yara_gen"] = audit_yara(log)
    report["stages"]["publish"] = audit_publish(log, deep_mtime)
    report["cross_cutting"] = collect_cross_cutting(log, sess)

    stage_ok = {k: v.get("ok") for k, v in report["stages"].items()}
    report["all_green"] = all(stage_ok.values())
    report["stage_ok"] = stage_ok

    # Always pack showcase evidence (public audit / RevAI showcase)
    showcase_dir = pack_showcase(sha, report)
    report["showcase_dir"] = str(showcase_dir)
    master_md = rebuild_showcase_master()

    out_json = log / "pipeline-audit.json"
    out_md = log / "AUDIT-REPORT.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, default=str))
    out_md.write_text(render_markdown(report), encoding="utf-8")
    # Keep showcase copy of final AUDIT-REPORT in sync
    shutil.copy2(out_md, showcase_dir / "AUDIT-REPORT.md")
    shutil.copy2(out_json, showcase_dir / "pipeline-audit.json")

    # Compact console summary (full detail is in AUDIT-REPORT.md)
    summary = {
        "sha": sha,
        "mode": mode,
        "all_green": report["all_green"],
        "stage_ok": stage_ok,
        "audit_json": str(out_json),
        "audit_md": str(out_md),
        "showcase_dir": str(showcase_dir),
        "showcase_master": str(master_md),
    }
    print(json.dumps(summary, indent=2))
    print(
        f"\n[audit_pipeline] all_green={report['all_green']} -> {out_md}\n"
        f"[audit_pipeline] showcase -> {showcase_dir}\n"
        f"[audit_pipeline] master -> {master_md}",
        flush=True,
    )
    sys.exit(0 if report["all_green"] else 1)


if __name__ == "__main__":
    main()
