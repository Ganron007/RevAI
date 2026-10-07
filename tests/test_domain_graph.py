"""Test the domain graph with a stub node -- no model, no tools, no VM."""
import json
import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/domain_graph.py").parent))
import domain_graph as dg  # noqa: E402


def _stub(state, domain):
    return {"status": "understood", "answer": f"{domain['key']} answer",
            "evidence": ["x"], "reason": ""}


def test_the_graph_covers_every_capability_domain():
    compiled = dg.build_domain_graph(_stub)
    state = compiled.invoke({"sha": "a" * 64, "session": {}, "file_type": "PE32"})
    domains = state.get("domains") or {}
    assert set(domains) == set(dg.DOMAIN_KEYS), (
        f"the graph produced {sorted(domains)}; expected {sorted(dg.DOMAIN_KEYS)}")
    cov = dg.domain_coverage(domains)
    assert cov["complete"], cov["missing"]
    print("  nodes run:", sorted(domains))


def test_a_failing_domain_does_not_end_the_dive():
    def boom(state, domain):
        if domain["key"] == "c2_network":
            raise RuntimeError("tool exploded")
        return {"status": "understood", "answer": "ok", "evidence": [], "reason": ""}
    state = dg.build_domain_graph(boom).invoke(
        {"sha": "a" * 64, "session": {}, "file_type": "PE32"})
    d = state["domains"]
    assert d["c2_network"]["status"] == "not-reconstructed"
    assert "tool exploded" in d["c2_network"]["reason"]
    assert d["persistence"]["status"] == "understood", (
        "a failure in one domain must not stop the others")


def test_an_unknown_status_counts_as_not_understood():
    cov = dg.domain_coverage({"persistence": {"status": "understood"}})
    assert cov["missing"], "an unset domain must count as missing"
    assert cov["complete"] is False


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


def test_findings_text_mentions_every_domain():
    txt = dg.domain_findings_text({})
    for key in dg.DOMAIN_KEYS:
        assert f"**{key}**" in txt, key
    assert "not explored" in txt
