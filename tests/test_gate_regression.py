#!/usr/bin/env python3
"""test_gate_regression.py — honest-gate regression tests for RevAI.

Every gate bug we hit in production was found by a real sample, not by a test:
the yr-binary YARA false-green, the 0-10 score scale, confidence-0-on-complete,
engine mis-attribution (Rook-class), and the SQL-deep complete-non-attempt.
This suite injects the bad data and asserts the gates HARD-FAIL, so a future
refactor that silently weakens a gate fails CI-style before a campaign runs.

Pure-logic tests only — no VM, no samples, no LLM, no yara_x (which is absent
on the Windows dev box). Run from anywhere:

    python3 tests/test_gate_regression.py        # on a POSIX box
    python3 test_gate_regression.py              # from tests/ dir
    python tests/test_gate_regression.py         # on Windows dev box

Exit 0 on pass, 1 on fail.
"""
from __future__ import annotations

import os
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from v2_lib import (  # noqa: E402
    agentic_confidence_sane,
    cross_stage_verdict_lock,
    hitl_checkpoint,
    is_transient_failure,
    normalize_verdict_score,
    run_profile,
    sql_deep_honest,
    tool_result_ok,
    verify_engine_citation_honesty,
)
from report_quality import (  # noqa: E402
    evaluate_report_markdown,
    missing_sections,
    source_is_fallback,
    stub_sections,
)

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  PASS {name}")
    else:
        msg = f"  FAIL {name}" + (f" — {detail}" if detail else "")
        print(msg)
        FAILURES.append(name)


# ---------------------------------------------------------------------------
# 1. Score normalization — the 0-10 scale bug (R1-R15 reports showed scores
#    like 8/9 instead of 80/90). Rescaling must be deterministic and marked.
# ---------------------------------------------------------------------------
def test_score_normalization() -> None:
    print("[score] 0-10 scale must rescale to 0-100 and be marked")
    v = {"score": 9}
    normalize_verdict_score(v)
    check("9 -> 90", v.get("score") == 90, str(v))
    check("marker set", v.get("score_was") == "rescaled_0_10_to_0_100", str(v))

    v = {"score": 95}
    normalize_verdict_score(v)
    check("95 stays 95", v.get("score") == 95 and "score_was" not in v, str(v))

    v = {"score": 10}
    normalize_verdict_score(v)
    check("10 -> 100 (edge)", v.get("score") == 100, str(v))

    v = {"score": 0}
    normalize_verdict_score(v)
    check("0 stays 0", v.get("score") == 0, str(v))

    v = {"score": "abc"}
    normalize_verdict_score(v)
    check("garbage -> 0", v.get("score") == 0, str(v))

    v = {"score": "8"}
    normalize_verdict_score(v)
    check("string 8 -> 80", v.get("score") == 80, str(v))


# ---------------------------------------------------------------------------
# 2. Verdict lock — a publish that contradicts upstream MUST hard-fail.
# ---------------------------------------------------------------------------
def test_verdict_lock() -> None:
    print("[verdict_lock] publish must not contradict upstream")

    r = cross_stage_verdict_lock("benign", quick_verdict="malicious")
    check("benign vs quick=malicious -> conflict", bool(r.get("conflict")) and not r.get("ok"), str(r))

    r = cross_stage_verdict_lock("benign", deep_verdict="malicious")
    check("benign vs deep=malicious -> conflict", bool(r.get("conflict")) and not r.get("ok"), str(r))

    r = cross_stage_verdict_lock("benign", quick_verdict="suspicious")
    check("benign vs suspicious -> conflict", bool(r.get("conflict")) and not r.get("ok"), str(r))

    r = cross_stage_verdict_lock("suspicious", quick_verdict="malicious")
    check("suspicious vs malicious -> ok", bool(r.get("ok")) and not r.get("conflict"), str(r))

    r = cross_stage_verdict_lock("malicious", quick_verdict="malicious", deep_verdict="malicious")
    check("malicious vs malicious -> ok", bool(r.get("ok")), str(r))

    r = cross_stage_verdict_lock("malicious")
    check("no upstream -> ok/unknown", bool(r.get("ok")) and r.get("upstream") == "unknown", str(r))

    # Verdict label normalization — prose must reduce to the core label
    r = cross_stage_verdict_lock("benign", quick_verdict="MALWARE — packed loader")
    check("prose 'MALWARE — packed loader' = malicious", bool(r.get("conflict")), str(r))
    r = cross_stage_verdict_lock("benign", quick_verdict="suspicious: likely X")
    check("prose 'suspicious: likely X' = suspicious", bool(r.get("conflict")), str(r))


# ---------------------------------------------------------------------------
# 3. Engine-citation honesty — the Rook-class mis-attribution bug: source=ida
#    claiming a fragment only Malcat owns. Must be caught, not passed.
# ---------------------------------------------------------------------------
def test_engine_citation_honesty() -> None:
    print("[engine_citation] claimed engine must own the cited fragment")

    tool_blobs = {
        "tools": {
            "malcat": {"strings": [{"s": "FILES ENCRYPTED HERE PLEASE RUN"}]},
            "capa": {"top_rules": [{"name": "obfuscated"}]},
        },
        "sql": {"ghidra": {"strings": [{"s": "some ordinary string"}]}},
    }
    deep = {
        "key_evidence": [
            {"source": "ida", "value": "FILES ENCRYPTED HERE PLEASE RUN"},
        ]
    }
    res = verify_engine_citation_honesty(deep, tool_blobs)
    check("ida claim owned by malcat -> FAIL", not res.get("ok"), str(res))
    false_entries = res.get("false_engine_citations") or res.get("false") or []
    check("misattribution recorded", bool(false_entries), str(res))

    # Honest: the same fragment genuinely under IDA SQL
    tool_blobs2 = {
        "tools": {"malcat": {"strings": []}},
        "sql": {"ida": {"strings": [{"s": "FILES ENCRYPTED HERE PLEASE RUN"}]}},
    }
    res = verify_engine_citation_honesty(deep, tool_blobs2)
    check("ida claim owned by ida -> PASS", bool(res.get("ok")), str(res))

    # Short needle (<6 chars) is skipped — never a false fail
    deep_short = {"key_evidence": [{"source": "ida", "value": "x y z"}]}
    res = verify_engine_citation_honesty(deep_short, tool_blobs)
    check("short needle -> PASS (skipped)", bool(res.get("ok")), str(res))

    # No strict-engine claim -> PASS
    deep_none = {"key_evidence": [{"value": "FILES ENCRYPTED HERE PLEASE RUN"}]}
    res = verify_engine_citation_honesty(deep_none, tool_blobs)
    check("no engine claim -> PASS", bool(res.get("ok")), str(res))

    # Fragment present in BOTH engines -> PASS (no false positive)
    tool_blobs3 = {
        "tools": {"malcat": {"strings": [{"s": "FILES ENCRYPTED HERE PLEASE RUN"}]}},
        "sql": {"ida": {"strings": [{"s": "FILES ENCRYPTED HERE PLEASE RUN"}]}},
    }
    res = verify_engine_citation_honesty(deep, tool_blobs3)
    check("fragment in both -> PASS", bool(res.get("ok")), str(res))


# ---------------------------------------------------------------------------
# 4. tool_result_ok — the YARA yr-binary bug: batch_errors meant the scanner
#    failed but the gate still passed. A failed scan must FAIL the gate;
#    a completed zero-match scan is an honest PASS.
# ---------------------------------------------------------------------------
def test_tool_result_ok() -> None:
    print("[tool_result_ok] failed scans fail, honest zeros pass")

    yara_failed = {"error": "No module named 'yr'", "batch_errors": ["x"]}
    check("yara error -> FAIL", not tool_result_ok(yara_failed, "yara")[0])
    yara_batch = {"batch_errors": ["rule parse error"], "matches": []}
    check("yara batch_errors -> FAIL", not tool_result_ok(yara_batch, "yara")[0])
    yara_zero = {"matches": [], "rule_count": 0}
    check("yara honest zero matches -> PASS", tool_result_ok(yara_zero, "yara")[0])
    yara_napp = {"skipped": "not_applicable", "reason": "not_applicable: ELF"}
    check("yara not_applicable -> PASS", tool_result_ok(yara_napp, "yara")[0])

    capa_empty = {"rule_count": 0, "top_rules": []}
    check("capa empty -> FAIL", not tool_result_ok(capa_empty, "capa")[0])
    capa_bridge = {"rule_count": 3, "bridge": True}
    check("capa via import bridge -> FAIL", not tool_result_ok(capa_bridge, "capa")[0])
    capa_ok = {"rule_count": 3, "top_rules": [{"name": "a"}]}
    check("capa real rules -> PASS", tool_result_ok(capa_ok, "capa")[0])

    floss_empty = {"floss_ok": True, "string_count": 0}
    check("floss empty -> FAIL", not tool_result_ok(floss_empty, "floss")[0])
    floss_ok = {"floss_ok": True, "string_count": 42}
    check("floss strings -> PASS", tool_result_ok(floss_ok, "floss")[0])

    check("None result -> FAIL", not tool_result_ok(None, "yara")[0])


# ---------------------------------------------------------------------------
# 5. Report quality — missing/stub sections and fallback sources must fail.
# ---------------------------------------------------------------------------
def test_report_quality() -> None:
    print("[report_quality] incomplete markdown must not pass")

    required = ["1. Executive Summary", "2. Sample Metadata"]
    md_ok = "# 1. Executive Summary\n\nbody here\n\n# 2. Sample Metadata\n\nbody here"
    md_missing = "# 1. Executive Summary\n\nbody here"
    check("missing section detected", missing_sections(md_missing, required) == ["2. Sample Metadata"])
    check("complete md clean", missing_sections(md_ok, required) == [])

    md_stub = "# 1. Executive Summary\n\nhi\n\n# 2. Sample Metadata\n\n" + "x" * 300
    check("stub section detected", "1. Executive Summary" in stub_sections(md_stub, required))

    check("fallback source detected", source_is_fallback("deterministic_fallback"))
    check("fallback_after_incomplete detected", source_is_fallback("deterministic_fallback_after_incomplete_llm"))
    check("llm_incomplete NOT fallback", not source_is_fallback("llm_incomplete"))
    check("llm_judge NOT fallback", not source_is_fallback("llm_judge"))

    q = evaluate_report_markdown(
        "tiny",
        required_sections=required,
        source="llm_judge",
        min_total_chars=8000,
        label="test",
    )
    check("tiny report -> not ok", not q.get("ok"), json.dumps(q)[:200])


# ---------------------------------------------------------------------------
# 6. SQL-deep honesty — only a complete non-attempt fails the gate; documented
#    infra failures (ghidrasql server died, no IDA) are honest records.
# ---------------------------------------------------------------------------
def test_sql_deep_honest() -> None:
    print("[sql_deep] infra failure != non-attempt")

    check("has_sql -> pass", sql_deep_honest(True, False, None))
    check("sql_deep_ok -> pass", sql_deep_honest(False, True, None))
    check("ghidrasql died -> pass (documented)", sql_deep_honest(False, False, "ghidrasql_server_died"))
    check("idasql missing -> pass (documented)", sql_deep_honest(False, False, "idasql_missing"))
    check("sql_failed -> pass (documented)", sql_deep_honest(False, False, "sql_failed"))
    check("complete non-attempt -> FAIL", not sql_deep_honest(False, False, None))
    check("unknown reason -> FAIL", not sql_deep_honest(False, False, "something_else"))


# ---------------------------------------------------------------------------
# 7. Confidence gate — a complete dive reporting confidence 0 must fail.
# ---------------------------------------------------------------------------
def test_agentic_confidence_sane() -> None:
    print("[confidence] complete dive never reports 0")

    check("complete + confidence 0 -> FAIL", not agentic_confidence_sane(
        {"verdict": "malicious", "summary": "x", "confidence": 0}))
    check("complete + confidence 50 -> PASS", agentic_confidence_sane(
        {"verdict": "malicious", "summary": "x", "confidence": 50}))
    check("incomplete tooling + 0 -> PASS (not complete)", agentic_confidence_sane(
        {"incomplete_tooling": True, "verdict": "malicious", "summary": "x", "confidence": 0}))
    check("no verdict/summary + 0 -> PASS (not complete)", agentic_confidence_sane(
        {"confidence": 0}))


# ---------------------------------------------------------------------------
# 8. Retry policy — transient classification + run profiles (darkgate #13:
#    capa timeout + malcat MCP closed must be RETRYABLE; rule/permission
#    failures must NOT burn a retry).
# ---------------------------------------------------------------------------
def test_transient_classification() -> None:
    print("[retry] transient vs non-transient classification")

    check("capa timed out -> transient", is_transient_failure("capa timed out after 300s"))
    check("MCP malcat closed -> transient", is_transient_failure("MCP malcat closed"))
    check("connection refused -> transient", is_transient_failure("Connection refused"))
    check("server died -> transient", is_transient_failure("ghidrasql server died"))
    check("OOM killed -> transient", is_transient_failure("killed (oom)"))

    check("permission denied -> NOT transient", not is_transient_failure("Permission denied"))
    check("rule parse error -> NOT transient", not is_transient_failure("rule parse error at line 3"))
    check("missing artifact -> NOT transient", not is_transient_failure("rule.yar not found"))
    check("llm incomplete -> NOT transient", not is_transient_failure("llm_incomplete"))
    check("empty text -> NOT transient", not is_transient_failure(""))
    check("None -> NOT transient", not is_transient_failure(None))


def test_run_profile() -> None:
    print("[retry] run profile resolution + overrides")
    import os as _os

    for key in (
        "REVAI_RUN_PROFILE", "REVAI_STAGE_RETRIES", "REVAI_TOOL_RETRIES",
        "REVAI_TOOL_TIMEOUT_SCALE", "REVAI_ORCH_RECURSION_LIMIT",
        "REVAI_DEEP_MAX_STEPS", "REVAI_RETRY_TRANSIENT_ONLY",
    ):
        _os.environ.pop(key, None)

    std = run_profile()
    check("standard default profile", std.get("profile") == "standard", str(std))
    check("standard retries >= 1 (agentic default)", std.get("stage_retries") >= 1, str(std))
    check("standard tool_retries 1", std.get("tool_retries") == 1, str(std))
    check("standard recursion 40", std.get("recursion_limit") == 40, str(std))
    check("standard max_steps 16", std.get("deep_max_steps") == 16, str(std))
    check("standard timeout_scale 1.0", std.get("timeout_scale") == 1.0, str(std))
    check("transient-only default ON", std.get("retry_transient_only") is True, str(std))

    _os.environ["REVAI_RUN_PROFILE"] = "unlimited"
    unl = run_profile()
    check("unlimited profile", unl.get("profile") == "unlimited", str(unl))
    check("unlimited retries 5", unl.get("stage_retries") == 5, str(unl))
    check("unlimited tool_retries 5", unl.get("tool_retries") == 5, str(unl))
    check("unlimited recursion 200", unl.get("recursion_limit") == 200, str(unl))
    check("unlimited max_steps 64", unl.get("deep_max_steps") == 64, str(unl))
    check("unlimited timeout_scale 3.0", unl.get("timeout_scale") == 3.0, str(unl))

    _os.environ["REVAI_RUN_PROFILE"] = "standard"
    _os.environ["REVAI_STAGE_RETRIES"] = "3"
    _os.environ["REVAI_TOOL_RETRIES"] = "0"
    _os.environ["REVAI_TOOL_TIMEOUT_SCALE"] = "2.5"
    _os.environ["REVAI_RETRY_TRANSIENT_ONLY"] = "0"
    ovr = run_profile()
    check("env override retries 3", ovr.get("stage_retries") == 3, str(ovr))
    check("env override tool_retries 0", ovr.get("tool_retries") == 0, str(ovr))
    check("env override timeout_scale 2.5", ovr.get("timeout_scale") == 2.5, str(ovr))
    check("env override transient-only OFF", ovr.get("retry_transient_only") is False, str(ovr))
    check("env override recursion stays 40", ovr.get("recursion_limit") == 40, str(ovr))

    for key in (
        "REVAI_RUN_PROFILE", "REVAI_STAGE_RETRIES", "REVAI_TOOL_RETRIES",
        "REVAI_TOOL_TIMEOUT_SCALE", "REVAI_ORCH_RECURSION_LIMIT",
        "REVAI_DEEP_MAX_STEPS", "REVAI_RETRY_TRANSIENT_ONLY",
    ):
        _os.environ.pop(key, None)


# ---------------------------------------------------------------------------
# 9. hitl_checkpoint resilience — a telemetry write failure must NEVER kill a
#    stage (the #13b darkgate root cause: root-owned /tmp/cadre-hitl).
# ---------------------------------------------------------------------------
def test_hitl_checkpoint_resilience() -> None:
    print("[hitl_checkpoint] telemetry write failure must not kill a stage")
    import os as _os

    _os.environ.pop("CADRE_HITL_WAIT", None)
    _os.environ.pop("CADRE_HITL_AUTO", None)
    try:
        rec = hitl_checkpoint("test_gate_regression", "resilience", {"k": "v"})
        check("checkpoint returns record", isinstance(rec, dict) and rec.get("agent") == "test_gate_regression", str(rec)[:120])
        check("checkpoint approved (fire-and-forget)", bool(rec.get("approved")) is True, str(rec)[:120])
    finally:
        _os.environ.pop("CADRE_HITL_WAIT", None)
        _os.environ.pop("CADRE_HITL_AUTO", None)


# ---------------------------------------------------------------------------
# 10. Report style gates — dump-detection (Phase B: explain-don't-dump).
# ---------------------------------------------------------------------------
def test_report_style_gates() -> None:
    print("[report_style] dump-style and citation-coverage gates")

    required = ["1. Executive Summary", "2. Sample Metadata"]
    dump_md = (
        "# 1. Executive Summary\n\n"
        "# 2. Sample Metadata\n\n"
        "```asm\npush ebp\nmov ebp, esp\ncall 0x401000\nret\n```\n"
        "```asm\nmov eax, 0\ncall 0x401010\nret\n```\n"
        "```asm\npush esi\ncall 0x401020\npop esi\nret\n```\n"
        "| addr | name |\n|------|------|\n| 0x401000 | sub_401000 |\n"
        "| 0x401010 | sub_401010 |\n| 0x401020 | sub_401020 |\n"
    )
    q = evaluate_report_markdown(
        dump_md, required_sections=required, source="llm_judge",
        min_total_chars=10, label="technical_test",
    )
    check("dump style detected", any("dump_style" in i for i in q.get("issues", [])), str(q.get("issues"))[:200])
    check("no byline detected", any("no_byline" in i for i in q.get("issues", [])), str(q.get("issues"))[:200])
    check("low citations detected", any("low_citations" in i for i in q.get("issues", [])), str(q.get("issues"))[:200])

    good_md = (
        "> **RevAI provenance** — commit abc · engine langgraph\n\n"
        "# 1. Executive Summary\n\nWe observed the sample resolving APIs "
        "dynamically (source: capa, top_rules), which indicates packed "
        "execution flow (source: pe_imports). The import table is minimal "
        "(source: pe_imports, imports), consistent with a loader that "
        "resolves the real API surface at runtime (source: floss, strings). "
        "This classification is consistent with upstream triage "
        "(source: verdict.json).\n\n"
        "# 2. Sample Metadata\n\nThe binary is a 32-bit PE with a suspicious "
        "import table (source: pe_imports, imports). This matters because "
        "delay-imports are typical of packers (source: malcat, anomalies). "
        "The section layout shows a single writable+executable section "
        "(source: malcat, static_profile), which the unpacking stub targets "
        "(source: ghidra_query, sections).\n\n"
        "```asm\npush ebp\nmov ebp, esp\n```\n\nThe stub above is the "
        "standard prologue; the unusual part is the call to 0x401000, which "
        "resolves to the unpacking loop (source: ghidra_query, functions). "
        "We assess this loop writes the second-stage payload in memory "
        "(source: capa, anti-analysis), though we could not confirm the "
        "dropped artifact on disk (likely stage is memory-only)."
    )
    q = evaluate_report_markdown(
        good_md, required_sections=required, source="llm_judge",
        min_total_chars=10, label="technical_test",
    )
    check("good report passes style gates", q.get("ok"), str(q.get("issues"))[:200])
    check("good report byline ok", q.get("style", {}).get("byline_ok") is True, str(q.get("style"))[:150])
    check("good report citations ok", q.get("style", {}).get("citation_coverage_ok") is True, str(q.get("style"))[:150])

    fb = evaluate_report_markdown(
        dump_md, required_sections=required, source="deterministic_fallback",
        min_total_chars=10, label="technical_test",
    )
    check("fallback exempt from style gates", not any("dump_style" in i or "no_byline" in i for i in fb.get("issues", [])), str(fb.get("issues"))[:200])


# ---------------------------------------------------------------------------
# 11. G2 — deep-dive transparent tool retry (fake registry, both directions).
# ---------------------------------------------------------------------------
def test_deep_dive_tool_retry() -> None:
    print("[G2] deep-dive transparent tool retry")
    import os as _os
    import sys as _sys

    _sys.path.insert(0, str(ROOT / "revai"))
    from deep_dive_agentic import _call_with_tool_retry  # noqa: E402

    class FakeRegistry:
        def __init__(self, results):
            self.results = results
            self.calls = 0

        def call(self, name, args, session):
            r = self.results[min(self.calls, len(self.results) - 1)]
            self.calls += 1
            return dict(r)

    # transient fail -> success: retried once, LLM never saw the error
    _os.environ["REVAI_TOOL_RETRIES"] = "2"
    reg = FakeRegistry([{"error": "capa timed out after 300s"}, {"ok": True}])
    out = _call_with_tool_retry(reg, "capa_analyze", {}, None)
    check("transient failure retried", out.get("retried") is True, str(out))
    check("retry_count 1", out.get("retry_count") == 1, str(out))
    check("first_error recorded", "timed out" in str(out.get("first_error")), str(out))
    check("final result is the success", out.get("ok") is True, str(out))
    check("registry called twice", reg.calls == 2, str(reg.calls))

    # non-transient failure: never retried
    reg2 = FakeRegistry([{"error": "rule parse error"}])
    out2 = _call_with_tool_retry(reg2, "yara_scan", {}, None)
    check("non-transient not retried", out2.get("retried") is None, str(out2))
    check("single call", reg2.calls == 1, str(reg2.calls))

    # tool_retries=0: no retry at all
    _os.environ["REVAI_TOOL_RETRIES"] = "0"
    reg3 = FakeRegistry([{"error": "capa timed out after 300s"}])
    out3 = _call_with_tool_retry(reg3, "capa_analyze", {}, None)
    check("tool_retries=0 -> no retry", out3.get("retried") is None, str(out3))
    check("single call when disabled", reg3.calls == 1, str(reg3.calls))

    # still transient after max retries: error surfaces to LLM (marked)
    _os.environ["REVAI_TOOL_RETRIES"] = "2"
    reg4 = FakeRegistry([{"error": "MCP malcat closed"}, {"error": "MCP malcat closed"}, {"error": "MCP malcat closed"}])
    out4 = _call_with_tool_retry(reg4, "malcat_analyze", {}, None)
    check("exhausted retries still errors", out4.get("error") == "MCP malcat closed", str(out4))
    check("retry_count 2", out4.get("retry_count") == 2, str(out4))
    check("three calls total", reg4.calls == 3, str(reg4.calls))

    for key in ("REVAI_TOOL_RETRIES",):
        _os.environ.pop(key, None)


# ---------------------------------------------------------------------------
# 12. G5 — retry visibility collector (audit surface).
# ---------------------------------------------------------------------------
def test_retry_visibility_collector() -> None:
    print("[G5] retry visibility collector")
    import json as _json
    import sys as _sys
    import tempfile as _tmp
    from pathlib import Path as _Path

    _sys.path.insert(0, str(ROOT / "revai"))
    from audit_pipeline import collect_retry_visibility  # noqa: E402

    with _tmp.TemporaryDirectory() as td:
        log = _Path(td)
        (log / "quick_scan").mkdir()
        (log / "deep_dive").mkdir()
        (log / "quick_scan" / "00-tools-raw.json").write_text(_json.dumps({
            "capa": {"ok": True, "retried": True, "retry_count": 1, "first_error": "capa timed out"},
            "yara": {"ok": True},
        }))
        (log / "deep_dive" / "01-tools-raw.json").write_text(_json.dumps({
            "ghidra_query": {"ok": True, "retried": True, "retry_count": 2, "first_error": "MCP malcat closed"},
        }))
        (log / "deep_dive" / "05-deep-dive.json").write_text(_json.dumps({
            "history": [{"tool": "capa_analyze", "result": {"ok": True, "retried": True, "retry_count": 1, "first_error": "timeout"}}],
        }))
        (log / "deep_dive" / "agentic_deep_dive.json").write_text(_json.dumps({"history": []}))

        out = collect_retry_visibility(log)
        check("count 3", out.get("count") == 3, str(out))
        check("quick_scan entry", any(e["tool"] == "capa" for e in out["quick_scan"]), str(out["quick_scan"]))
        check("deep_dive entry", any(e["tool"] == "ghidra_query" for e in out["deep_dive"]), str(out["deep_dive"]))
        check("history entry found", any(e["tool"] == "capa_analyze" for e in out["deep_dive"]), str(out["deep_dive"]))
        check("layers tagged", all(e.get("layer") for e in out["quick_scan"] + out["deep_dive"]), str(out))


def main() -> int:
    tests = [
        test_score_normalization,
        test_verdict_lock,
        test_engine_citation_honesty,
        test_tool_result_ok,
        test_report_quality,
        test_sql_deep_honest,
        test_agentic_confidence_sane,
        test_transient_classification,
        test_run_profile,
        test_hitl_checkpoint_resilience,
        test_report_style_gates,
        test_deep_dive_tool_retry,
        test_retry_visibility_collector,
    ]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} regression checks: {', '.join(FAILURES)}")
        return 1
    print("ALL GATE REGRESSION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
