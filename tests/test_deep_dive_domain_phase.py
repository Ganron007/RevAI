"""RC-53 (plan #20): the flag-gated domain-graph deep-dive phase.

REVAI_DEEP_DIVE_GRAPH=1 replaces the flat ReAct planner loop with the #26
depth substrate (agentic_langgraph.run_langgraph_deep_dive) — one bounded
tool-calling node per capability domain. Default OFF: production byte-
identical. A failed or empty graph pass falls back to the flat loop.
"""
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import deep_dive_agentic as DDA  # noqa: E402
import v2_lib  # noqa: E402



def _make_case(tmp_path):
    """A minimal case dir that satisfies the execution-context write gate."""
    case = tmp_path / "case" / ("a" * 64) / "scripted"
    case.mkdir(parents=True, exist_ok=True)
    (case / "execution-context.json").write_text(json.dumps(
        {"sha256": "a" * 64, "mode": "scripted", "run_id": "b" * 32}))
    return case

class _FakeRegistry:
    def __init__(self):
        self.calls = []

    def call(self, name, args, session):
        self.calls.append((name, args))
        return {"ok": True, "result": {"fake": name}}


def _session():
    return {"sha256": "a" * 64, "file_type": {"format": "PE"},
            "ghidra_session_id": None, "ida_session_id": None,
            "sample_path": "/tmp/fake.bin"}


def _graph_result():
    doms = {"surface": "understood", "persistence": "understood",
            "c2_network": "partial"}
    hist = [{"tool": f"domain:{k}",
             "result": {"status": s, "answer": f"{k} answer",
                        "evidence": [f"ghidra_query imports: evidence {k}"]}}
            for k, s in doms.items()]
    return {"findings": {"domain_graph": {"domains": doms},
                         "domain_findings": "domain pass findings"},
            "history": hist}


def test_default_off_keeps_the_flat_loop(monkeypatch, tmp_path):
    monkeypatch.delenv("REVAI_DEEP_DIVE_GRAPH", raising=False)
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "case")
    _make_case(tmp_path)
    called = []
    monkeypatch.setattr(DDA, "load_session", lambda sha: _session())
    monkeypatch.setattr(DDA, "load_intake_validation", lambda sha: {})
    monkeypatch.setattr(DDA, "ToolRegistry", _FakeRegistry)
    monkeypatch.setattr(DDA, "_run_standard_checklist",
                        lambda reg, sess, sha: ([], {}, {}, {"ok": True}))
    monkeypatch.setattr(DDA, "get_planner_model", lambda: "m")
    monkeypatch.setattr(DDA, "get_verdict_model", lambda: "m")
    # The planner loop runs when the flag is off; make one planner call fail
    # closed quickly so the loop terminates without an LLM.
    def _no_llm(prompt, **kw):
        called.append(prompt)
        raise RuntimeError("no llm in test")
    monkeypatch.setattr(DDA, "llm_judge", _no_llm)
    monkeypatch.setattr(DDA, "MAX_STEPS", 1, raising=False)
    out = DDA._custom_loop_body("a" * 64, max_steps=1)
    assert called, "the flat planner loop must still run when the flag is off"
    assert not (out.get("findings") or {}).get("domain_graph")


def test_flag_on_merges_the_domain_graph_and_skips_the_planner(monkeypatch,
                                                               tmp_path):
    monkeypatch.setenv("REVAI_DEEP_DIVE_GRAPH", "1")
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "case")
    _make_case(tmp_path)
    planner_called = []
    graph_called = []

    monkeypatch.setattr(DDA, "load_session", lambda sha: _session())
    monkeypatch.setattr(DDA, "load_intake_validation", lambda sha: {})
    monkeypatch.setattr(DDA, "ToolRegistry", _FakeRegistry)
    monkeypatch.setattr(DDA, "_run_standard_checklist",
                        lambda reg, sess, sha: ([], {}, {}, {"ok": True}))
    monkeypatch.setattr(DDA, "get_planner_model", lambda: "m")
    monkeypatch.setattr(DDA, "get_verdict_model", lambda: "m")

    def _fake_graph(sha, max_steps=16):
        graph_called.append(max_steps)
        return _graph_result()

    fake_mod = type(sys)("agentic_langgraph")
    fake_mod.run_langgraph_deep_dive = _fake_graph
    monkeypatch.setitem(sys.modules, "agentic_langgraph", fake_mod)

    def _no_llm(prompt, **kw):
        planner_called.append(prompt)
        raise RuntimeError("no llm in test")

    monkeypatch.setattr(DDA, "llm_judge", _no_llm)
    out = DDA._custom_loop_body("a" * 64, max_steps=3)
    assert graph_called, "the domain-graph phase must run when the flag is on"
    findings = out.get("findings") or {}
    assert findings.get("domain_graph", {}).get("domains"), findings
    assert findings.get("domain_findings") == "domain pass findings"
    domain_tools = [h["tool"] for h in out.get("history") or []
                    if str(h.get("tool") or "").startswith("domain:")]
    assert len(domain_tools) == 3, out.get("history")
    # The planner LOOP must be skipped; the final-verdict call (a different
    # prompt shape, "JSON object with keys: verdict, confidence, ...") still
    # runs and is expected.
    loop_calls = [p for p in planner_called if "Step: 1/" in p]
    assert not loop_calls, (
        f"the flat planner loop must be skipped after a successful graph "
        f"pass; got {len(loop_calls)} loop call(s)")


def test_a_failed_graph_pass_falls_back_to_the_flat_loop(monkeypatch,
                                                         tmp_path):
    monkeypatch.setenv("REVAI_DEEP_DIVE_GRAPH", "1")
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "case")
    _make_case(tmp_path)
    planner_called = []
    monkeypatch.setattr(DDA, "load_session", lambda sha: _session())
    monkeypatch.setattr(DDA, "load_intake_validation", lambda sha: {})
    monkeypatch.setattr(DDA, "ToolRegistry", _FakeRegistry)
    monkeypatch.setattr(DDA, "_run_standard_checklist",
                        lambda reg, sess, sha: ([], {}, {}, {"ok": True}))
    monkeypatch.setattr(DDA, "get_planner_model", lambda: "m")
    monkeypatch.setattr(DDA, "get_verdict_model", lambda: "m")

    def _boom(sha, max_steps=16):
        raise RuntimeError("provider down")

    fake_mod = type(sys)("agentic_langgraph")
    fake_mod.run_langgraph_deep_dive = _boom
    monkeypatch.setitem(sys.modules, "agentic_langgraph", fake_mod)

    def _no_llm(prompt, **kw):
        planner_called.append(prompt)
        raise RuntimeError("no llm in test")

    monkeypatch.setattr(DDA, "llm_judge", _no_llm)
    out = DDA._custom_loop_body("a" * 64, max_steps=1)
    assert not (out.get("findings") or {}).get("domain_graph")
    assert planner_called, (
        "a failed graph pass must fall back to the flat planner loop")


def test_an_empty_graph_record_also_falls_back(monkeypatch, tmp_path):
    monkeypatch.setenv("REVAI_DEEP_DIVE_GRAPH", "1")
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "case")
    _make_case(tmp_path)
    planner_called = []
    monkeypatch.setattr(DDA, "load_session", lambda sha: _session())
    monkeypatch.setattr(DDA, "load_intake_validation", lambda sha: {})
    monkeypatch.setattr(DDA, "ToolRegistry", _FakeRegistry)
    monkeypatch.setattr(DDA, "_run_standard_checklist",
                        lambda reg, sess, sha: ([], {}, {}, {"ok": True}))
    monkeypatch.setattr(DDA, "get_planner_model", lambda: "m")
    monkeypatch.setattr(DDA, "get_verdict_model", lambda: "m")

    fake_mod = type(sys)("agentic_langgraph")
    fake_mod.run_langgraph_deep_dive = lambda sha, max_steps=16: {
        "findings": {}, "history": []}
    monkeypatch.setitem(sys.modules, "agentic_langgraph", fake_mod)

    def _no_llm(prompt, **kw):
        planner_called.append(prompt)
        raise RuntimeError("no llm in test")

    monkeypatch.setattr(DDA, "llm_judge", _no_llm)
    out = DDA._custom_loop_body("a" * 64, max_steps=1)
    assert not (out.get("findings") or {}).get("domain_graph")
    assert planner_called, "an empty graph record must fall back to the flat loop"


# The PRODUCTION langgraph path: REVAI_DEEP_DIVE_GRAPH=1 forces the
# DOMAIN-NODE mode of the same substrate (REVAI_DOMAIN_GRAPH), which the #26
# depth run proved live. setdefault semantics: an operator's explicit
# REVAI_DOMAIN_GRAPH value still wins.
def test_langgraph_path_forces_the_domain_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("REVAI_DEEP_DIVE_GRAPH", "1")
    monkeypatch.delenv("REVAI_DOMAIN_GRAPH", raising=False)
    captured = {}

    fake_mod = type(sys)("agentic_langgraph")

    def _fake(sha, max_steps=16, helpers=None):
        captured["domain_graph_env"] = os.environ.get("REVAI_DOMAIN_GRAPH")
        return {"findings": {}, "history": []}

    fake_mod.run_langgraph_deep_dive = _fake
    monkeypatch.setitem(sys.modules, "agentic_langgraph", fake_mod)
    monkeypatch.setattr(DDA, "langgraph_helpers", lambda: {})
    out = DDA.agentic_deep_dive("a" * 64)
    assert captured.get("domain_graph_env") == "1", captured
    assert out == {"findings": {}, "history": []}


def test_langgraph_path_respects_an_explicit_domain_graph_value(monkeypatch):
    monkeypatch.setenv("REVAI_DEEP_DIVE_GRAPH", "1")
    monkeypatch.setenv("REVAI_DOMAIN_GRAPH", "0")
    captured = {}

    fake_mod = type(sys)("agentic_langgraph")

    def _fake(sha, max_steps=16, helpers=None):
        captured["domain_graph_env"] = os.environ.get("REVAI_DOMAIN_GRAPH")
        return {"findings": {}, "history": []}

    fake_mod.run_langgraph_deep_dive = _fake
    monkeypatch.setitem(sys.modules, "agentic_langgraph", fake_mod)
    monkeypatch.setattr(DDA, "langgraph_helpers", lambda: {})
    DDA.agentic_deep_dive("a" * 64)
    assert captured.get("domain_graph_env") == "0", (
        "an operator's explicit REVAI_DOMAIN_GRAPH must win over the forcing")
