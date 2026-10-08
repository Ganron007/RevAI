"""The domain graph: skeleton rules AND the real integration.

Two rules govern this file, both learned the hard way:

  1. A test may stub the MODEL. It may not stub the function under test. The
     first version of the domain graph passed six tests that replaced `run_node`
     with a stub, which is why `_coerce_final_answer` being unbound -- a defect
     that made every node fail and returned a fabricated verdict -- shipped
     green. Every integration test below drives the shipped `_node`, the shipped
     graph and the shipped synthesis with a canned model reply.
  2. A test's NAME must assert what its body checks. `test_an_unknown_status_
     counts_as_not_understood` used to pass an absent entry, which defaults to
     the one status the code special-cased -- the name asserted the exact
     property the code violated.
"""
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/domain_graph.py").parent))
import domain_graph as dg  # noqa: E402
import agentic_langgraph as A  # noqa: E402

GOOD = json.dumps({
    "status": "understood",
    "answer": "Run key written under HKCU\\...\\Run; cited FLOSS offset 108144.",
    "evidence": ["FLOSS: HKCU Run", "capa: persistence/create-reg-key"],
    "reason": "",
})


class FakeAgent:
    """Stands in for the model. Records what it was asked to enforce."""

    def __init__(self, reply=GOOD, tool_calls=0):
        self._reply = reply
        self._tool_calls = tool_calls

    def invoke(self, payload, config=None):
        self.config = config or {}
        msgs = []
        for i in range(self._tool_calls):
            msgs.append(SimpleNamespace(
                content="", tool_calls=[{"name": "ghidra_query", "args": {}}],
                tool_call_id=f"t{i}"))
        msgs.append(SimpleNamespace(content=self._reply, tool_calls=[]))
        return {"messages": msgs}


def _fake_react(reply=GOOD, tool_calls=0, seen=None):
    def _build(llm, tools=None, prompt=None, **kw):
        agent = FakeAgent(reply, tool_calls)
        if seen is not None:
            seen.append(agent)
        return agent
    return _build


def _coerce(raw):
    """Stand-in for the real `_coerce_final_answer`, honouring its contract.

    The real one takes whatever `llm_judge` returned -- a JSON STRING -- and
    yields a dict. An earlier version of this file passed a lambda that only
    accepted dicts, so every correct answer was coerced to {} and the test
    blamed the code under test. A stub that lies about the contract is worse
    than no stub.
    """
    if isinstance(raw, dict):
        return raw
    try:
        out = json.loads(raw)
    except Exception:
        return {}
    return out if isinstance(out, dict) else {}


HELPERS = {"_coerce_final_answer": _coerce}


def _run(monkeypatch, reply=GOOD, tool_calls=0, seen=None, helpers=None,
         judge=None, budget=None):
    if budget is not None:
        monkeypatch.setenv("REVAI_DOMAIN_STEP_BUDGET", str(budget))
    monkeypatch.setattr(A, "create_react_agent", _fake_react(reply, tool_calls, seen))
    monkeypatch.setattr(A, "llm_judge", judge or (lambda prompt, model=None: json.dumps({
        "verdict": "malicious", "confidence": 80,
        "summary": "persistence observed", "key_evidence": ["FLOSS"]})))
    hist, finds = [], {}
    out = A.run_domain_deep_dive(
        "a" * 64, 10, helpers if helpers is not None else HELPERS, {},
        {"sample_path": "sample.exe"}, "PE32", hist, finds, [], None, "SYSTEM")
    return out, hist, finds


# ---------------------------------------------------------------- integration
def test_a_correct_model_answer_survives_the_wiring(monkeypatch):
    """The R3 regression.

    Every node used to raise NameError on `_coerce_final_answer`, degrade to
    not-reconstructed, and synthesis returned a truthy
    `{"verdict": "unknown", "confidence": 0}` that SUPPRESSED the flat-engine
    fallback. With a model that answers correctly, the answer must arrive.
    """
    out, hist, finds = _run(monkeypatch)
    assert out.get("verdict") == "malicious", (
        f"a correct domain answer was lost; got {out!r}")
    assert out.get("confidence") == 80
    statuses = set((finds["domain_graph"]["domains"] or {}).values())
    assert statuses == {"understood"}, (
        f"every node should have been understood, got {statuses}")
    assert finds["domain_graph"]["honest"] is True
    assert not any("not-reconstructed" in json.dumps(h) for h in hist)


def test_every_node_is_given_a_hard_step_ceiling(monkeypatch):
    """The budget must be enforced by the runtime, not requested in the prompt."""
    seen = []
    _run(monkeypatch, seen=seen, budget=3)
    assert len(seen) == len(dg.DOMAIN_KEYS), (
        f"only {len(seen)} nodes ran; expected {len(dg.DOMAIN_KEYS)}")
    for agent in seen:
        limit = agent.config.get("recursion_limit")
        assert limit, "no recursion_limit reached the node"
        assert limit == A._domain_recursion_limit(3) == 8


def test_actual_tool_spend_is_recorded_and_over_budget_is_flagged(monkeypatch):
    """What the node spent, recorded -- so the budget is auditable."""
    _, hist, finds = _run(monkeypatch, tool_calls=2, budget=3)
    assert finds["domain_graph"]["tool_calls_used"] == 2 * len(dg.DOMAIN_KEYS)
    entries = [h["result"] for h in hist if h.get("tool") != "domain:summary"]
    assert len(entries) == len(dg.DOMAIN_KEYS)
    assert all(e["tool_calls_used"] == 2 and e["step_budget"] == 3
               for e in entries)
    assert not any(e.get("over_budget") for e in entries), \
        "2 of 3 must not be flagged as over budget"

    _, over_hist, over = _run(monkeypatch, tool_calls=5, budget=3)
    over_entries = [h["result"] for h in over_hist if h.get("tool") != "domain:summary"]
    assert all(e.get("over_budget") is True for e in over_entries), \
        "5 of 3 must be flagged, not silently accepted"
    assert over["domain_graph"]["tool_calls_used"] == 5 * len(dg.DOMAIN_KEYS)


def test_a_missing_helper_aborts_before_any_node_runs(monkeypatch):
    """A helper the domain path needs must fail at the boundary, once.

    Not nine times as a swallowed NameError inside the graph.
    """
    seen = []
    out, hist, finds = _run(monkeypatch, seen=seen, helpers={})
    assert out == {}, f"a missing helper must be falsy so the caller falls back, got {out!r}"
    assert seen == [], f"{len(seen)} nodes ran without the helper they need"
    assert any("helper" in str(h.get("error", "")) for h in hist), hist


def test_when_no_domain_answers_the_run_falls_back_instead_of_faking(monkeypatch):
    """All nodes unusable -> falsy, so the caller runs the flat engine.

    A shaped `unknown` verdict here is a fabricated result, not a fallback.
    """
    out, hist, finds = _run(monkeypatch, reply="I'm not sure, sorry.")
    assert out == {}, f"expected a falsy result to trigger the fallback, got {out!r}"
    assert any("falling back" in str(h.get("error", "")) for h in hist), hist
    assert finds["domain_graph"]["honest"] is False


def test_a_failed_synthesis_is_falsy_not_unknown(monkeypatch):
    def boom(prompt, model=None, **kw):
        raise RuntimeError("provider down")
    out, _, _ = _run(monkeypatch, judge=boom)
    assert out == {}, f"a failed synthesis must not return a verdict shape: {out!r}"


def test_unparseable_prose_is_partial_with_the_raw_text_kept(monkeypatch):
    """Prose where JSON was asked for is 'looked, could not conclude'.

    It must not become an answer, and the text must survive for diagnosis.
    """
    _, hist, _ = _run(monkeypatch, reply="Looking at this, it seems to persist.")
    entries = {h["tool"]: h["result"] for h in hist
               if str(h.get("tool", "")).startswith("domain:") and "result" in h}
    dom = entries["domain:persistence"]
    assert dom["status"] == dg.STATUS_PARTIAL
    assert dom["answer"] == "", "prose must not become a fabricated answer"
    assert dom["raw_excerpt"].startswith("Looking at this")


def test_the_synthesis_prompt_names_the_unusable_domains(monkeypatch):
    """Coverage honesty has to reach the judgment, not just the artifact.

    A synthesis prompt listing nine bullets invites the model to read nine
    investigations. The domain that failed has to be named as failed.
    """
    prompts = []

    def judge(prompt, model=None, **kw):
        prompts.append(prompt)
        return json.dumps({"verdict": "malicious", "confidence": 50,
                           "summary": "s", "key_evidence": []})

    monkeypatch.setattr(A, "llm_judge", judge)
    per_domain = {k: {"status": dg.STATUS_UNDERSTOOD, "answer": "ok",
                      "evidence": ["e"]} for k in dg.DOMAIN_KEYS}
    per_domain["crypto"] = {"status": dg.STATUS_NOT_RECONSTRUCTED,
                            "answer": "", "reason": "node died"}
    A._domain_final_answer(per_domain, HELPERS, None)
    assert prompts, "synthesis never ran"
    assert "COVERAGE HONESTY" in prompts[0]
    assert "crypto" in prompts[0].split("COVERAGE HONESTY")[1]
    assert "nine bullets" not in prompts[0]


# ------------------------------------------------------------------ coverage
def test_all_nodes_failing_is_not_complete():
    allfail = {k: {"status": dg.STATUS_NOT_RECONSTRUCTED} for k in dg.DOMAIN_KEYS}
    cov = dg.domain_coverage(allfail)
    assert cov["complete"] is False, "nine failed nodes reported complete"
    assert len(cov["failed"]) == len(dg.DOMAIN_KEYS)
    assert len(cov["unusable"]) == len(dg.DOMAIN_KEYS)
    s = dg.summarise(allfail)
    assert s["complete"] is False and s["honest"] is False
    assert s["tool_calls_used"] == 0


def test_an_unrecognised_status_is_a_failure_not_progress():
    """The name of this test is the property the old code violated."""
    cov = dg.domain_coverage({"persistence": {"status": "totally-fine"}})
    assert cov["unknown_status"] == ["totally-fine"], (
        "an unrecognised status must be reported, not silently treated as ok")
    assert "persistence" in cov["unusable"], (
        "an unrecognised status is unusable, not progress")
    assert cov["complete"] is False
    assert dg.coverage_is_honest(cov) is False
    assert dg.summarise({"persistence": {"status": "totally-fine"}})["honest"] is False


def test_an_absent_domain_counts_as_missing():
    cov = dg.domain_coverage({"persistence": {"status": "understood"}})
    assert cov["missing"] and cov["complete"] is False


def test_partial_is_a_result_but_not_an_understanding():
    """`partial` was investigated, so coverage holds; it is not `understood`.

    Three separate facts, kept separate: visited, answered, understood.
    """
    d = {k: {"status": dg.STATUS_UNDERSTOOD, "answer": "a", "evidence": ["e"]}
         for k in dg.DOMAIN_KEYS}
    d["crypto"] = {"status": dg.STATUS_PARTIAL, "answer": "unclear", "evidence": []}
    cov = dg.domain_coverage(d)
    assert "crypto" in cov["visited"] and "crypto" in cov["answered"]
    assert "crypto" not in cov["understood"]
    assert cov["complete"] is True, "partial was investigated, so coverage holds"
    assert cov["understood_complete"] is False
    assert len(cov["substantive"]) == len(dg.DOMAIN_KEYS)


def test_nine_partials_with_nothing_in_them_is_not_a_dive():
    """Every status passes, none of them says anything -- the hollow case.

    `complete` is True here and it still must not be presented as a finished
    dive: that combination is exactly how a total failure gets reported green.
    """
    d = {k: {"status": dg.STATUS_PARTIAL, "answer": "", "evidence": []}
         for k in dg.DOMAIN_KEYS}
    cov = dg.domain_coverage(d)
    assert cov["complete"] is True, "every domain was investigated"
    assert cov["substantive"] == [], "none of them said anything"
    assert dg.coverage_is_honest(cov) is False
    assert dg.summarise(d)["honest"] is False


def test_not_observed_in_the_answer_text_is_an_answer():
    """'not observed' with what was checked is a determination, not a gap."""
    d = {k: {"status": dg.STATUS_UNDERSTOOD,
             "answer": "no persistence: no run-key strings in FLOSS"}
        for k in dg.DOMAIN_KEYS}
    cov = dg.domain_coverage(d)
    assert cov["complete"] and cov["understood_complete"]
    assert dg.coverage_is_honest(cov)


def test_coverage_is_honest_rejects_an_empty_or_absent_record():
    assert dg.coverage_is_honest({}) is False
    assert dg.coverage_is_honest({"domains_total": 0, "complete": True}) is False
    assert dg.coverage_is_honest({
        "domains_total": len(dg.DOMAIN_KEYS), "complete": True,
        "unknown_status": [], "substantive": ["persistence"]}) is True, \
        "an honest record needs SOMETHING substantive, not just a count"
    assert dg.coverage_is_honest({
        "domains_total": len(dg.DOMAIN_KEYS), "complete": True,
        "unknown_status": [], "substantive": []}) is False


def test_findings_text_marks_an_unusable_domain_loudly():
    txt = dg.domain_findings_text({"persistence": {"status": dg.STATUS_NOT_RECONSTRUCTED}})
    assert "no usable answer" in txt
    assert "NOT EXAMINED" in dg.domain_findings_text({})


# ------------------------------------------------------------------ skeleton
def _stub(state, domain):
    return {"status": dg.STATUS_UNDERSTOOD, "answer": f"{domain['key']} answer",
            "evidence": ["x"], "reason": ""}


def test_the_graph_covers_every_capability_domain():
    compiled = dg.build_domain_graph(_stub)
    state = compiled.invoke({"sha": "a" * 64, "session": {}, "file_type": "PE32"})
    domains = state.get("domains") or {}
    assert set(domains) == set(dg.DOMAIN_KEYS), (
        f"the graph produced {sorted(domains)}; expected {sorted(dg.DOMAIN_KEYS)}")
    assert dg.domain_coverage(domains)["complete"]


def test_a_failing_domain_does_not_end_the_dive():
    def boom(state, domain):
        if domain["key"] == "c2_network":
            raise RuntimeError("tool exploded")
        return _stub(state, domain)
    state = dg.build_domain_graph(boom).invoke(
        {"sha": "a" * 64, "session": {}, "file_type": "PE32"})
    d = state["domains"]
    assert d["c2_network"]["status"] == dg.STATUS_NOT_RECONSTRUCTED
    assert "tool exploded" in d["c2_network"]["reason"]
    assert d["persistence"]["status"] == dg.STATUS_UNDERSTOOD, (
        "a failure in one domain must not stop the others")


def test_the_graph_overrides_a_node_that_invents_a_status():
    state = dg.build_domain_graph(lambda s, d: {"nonsense": 1}).invoke(
        {"sha": "a" * 64, "session": {}, "file_type": "PE32"})
    assert all(e["status"] == dg.STATUS_PARTIAL for e in state["domains"].values())


def test_the_gate_is_off_by_default(monkeypatch):
    monkeypatch.delenv("REVAI_DOMAIN_GRAPH", raising=False)
    assert dg.domain_graph_enabled() is False
    monkeypatch.setenv("REVAI_DOMAIN_GRAPH", "1")
    assert dg.domain_graph_enabled() is True


def test_a_non_numeric_step_budget_falls_back(monkeypatch):
    monkeypatch.setenv("REVAI_DOMAIN_STEP_BUDGET", "abc")
    assert dg.domain_step_budget() == 3
    monkeypatch.setenv("REVAI_DOMAIN_STEP_BUDGET", "0")
    assert dg.domain_step_budget() == 3
    monkeypatch.setenv("REVAI_DOMAIN_STEP_BUDGET", "7")
    assert dg.domain_step_budget() == 7


def test_every_domain_declares_a_question():
    """A node with no question is a node that cannot be answered."""
    for d in dg.DOMAINS:
        assert d["key"] and d["title"] and d["question"].endswith("?"), d
    assert len(set(dg.DOMAIN_KEYS)) == len(dg.DOMAIN_KEYS)
