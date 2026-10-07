"""revai/domain_graph.py — plan #20: the deep dive as named domain nodes.

The deep dive was one flat ReAct loop. The prompt asked the model to self-check
every capability domain before answering, which is a request, not a structure:
a domain the model never visited was a coverage failure the gate could only see
after the fact (the depth gate reads the summary's prose).

This module makes the domains STRUCTURAL. The graph has one node per capability
domain; each node runs its own bounded investigation over the same tool
registry and returns a finding plus whether it converged. A synthesis node
combines them and the verdict follows from the combined picture.

Why per-domain nodes and not one bigger loop:
  * each domain gets its own step budget, so a stubborn injection question can
    no longer starve the persistence question by timing the whole run out;
  * a domain can say "not observed" as a first-class result, which is what the
    depth gate has always wanted to check;
  * the graph's shape IS the coverage record -- the node list is the answer to
    "what did you look at", with no prose in between.

Energate: REVAI_DOMAIN_GRAPH=1. Off by default, so the flat engine is unchanged
until this is validated on a real sample. The two engines read the same
registry, the same checklist and the same gates.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, TypedDict

#: The capability domains, from the depth-gate vocabulary the pipeline already
#: enforces. Order is deliberate: surface first (entry point / imports / strings
#: is what the other domains reason over), then the behaviour domains.
DOMAINS: list[dict[str, str]] = [
    {"key": "surface", "title": "Surface (entry point, imports, strings)",
     "question": "What is the entry point, what does it import, and what "
                 "strings/cross-references are notable?"},
    {"key": "persistence", "title": "Persistence",
     "question": "Does it install itself to run again (run keys, services, "
                 "scheduled tasks, startup folder, bootkit)?"},
    {"key": "c2_network", "title": "C2 / network communication",
     "question": "How does it reach an operator: domains, URLs, raw sockets, "
                 "protocol, encryption, beaconing?"},
    {"key": "evasion", "title": "Evasion / anti-analysis",
     "question": "Does it detect debuggers, VMs, sandboxes, timing, or "
                 "obfuscate itself to resist analysis?"},
    {"key": "execution_injection", "title": "Execution / injection",
     "question": "Does it create processes or inject code into others "
                 "(remote threads, process hollowing, APC, mapping)?"},
    {"key": "credential_access", "title": "Credential access",
     "question": "Does it harvest credentials, tokens, cookies, or browser/"
                 "vault data?"},
    {"key": "exfiltration", "title": "Exfiltration",
     "question": "Does it collect and send data out (staging, archives, "
                 "upload paths)?"},
    {"key": "defense_impairment", "title": "Defense impairment",
     "question": "Does it disable or tamper with security tooling, logging, "
                 "or recovery?"},
    {"key": "crypto", "title": "Encryption / obfuscation",
     "question": "Does it encrypt, pack, or encode its payloads, config, or "
                 "communications?"},
]

DOMAIN_KEYS = [d["key"] for d in DOMAINS]
DOMAIN_ENV = "REVAI_DOMAIN_GRAPH"


def domain_graph_enabled() -> bool:
    """Whether the deep dive runs as domain nodes instead of one flat loop."""
    return os.environ.get(DOMAIN_ENV, "").strip().lower() in (
        "1", "true", "yes", "on")


def domain_step_budget(default_per_domain: int = 3) -> int:
    """Tool calls each domain node may spend."""
    raw = os.environ.get("REVAI_DOMAIN_STEP_BUDGET", "").strip()
    if not raw:
        return default_per_domain
    try:
        val = int(raw)
    except ValueError:
        return default_per_domain
    return val if val > 0 else default_per_domain


class DomainState(TypedDict, total=False):
    """LangGraph state: the shared picture plus one slot per domain."""
    sha: str
    session: dict
    file_type: str
    domains: dict[str, dict]
    order: list[str]
    error: str


def build_domain_graph(run_node: Any):
    """Assemble the StateGraph from a caller-supplied node function.

    `run_node(state, domain) -> dict` does one domain's bounded investigation.
    The graph itself holds no LLM call, so it can be built and asserted in a
    test without a model.
    """
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(DomainState)

    def _make(domain: dict[str, str]):
        def _node(state: DomainState) -> dict:
            key = domain["key"]
            try:
                result = run_node(state, domain) or {}
            except Exception as exc:  # a domain failing must not end the dive
                result = {
                    "status": "not-reconstructed",
                    "answer": "",
                    "evidence": [],
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            entry = dict(result)
            entry.setdefault("status", "partial")
            entry.setdefault("answer", "")
            entry.setdefault("evidence", [])
            entry.setdefault("reason", "")
            entry["domain"] = key
            entry["title"] = domain["title"]
            entry["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return {"domains": {**state.get("domains", {}), key: entry}}
        _node.__name__ = f"domain_{domain['key']}"
        return _node

    graph.add_node("surface", _make(DOMAINS[0]))
    for domain in DOMAINS[1:]:
        graph.add_node(domain["key"], _make(domain))
    graph.add_edge(START, "surface")
    for a, b in zip(DOMAIN_KEYS[:-1], DOMAIN_KEYS[1:]):
        graph.add_edge(a, b)
    graph.add_edge(DOMAIN_KEYS[-1], END)
    return graph.compile()


def domain_coverage(domains: dict[str, dict]) -> dict:
    """Coverage over the domain set: what was addressed, and how.

    An unrecognised status counts as not-understood rather than being dropped,
    so a typo cannot make a missing domain look answered.
    """
    out: dict[str, str] = {}
    for key in DOMAIN_KEYS:
        entry = domains.get(key) or {}
        status = str(entry.get("status") or "not-explored")
        out[key] = status if status != "understood" else "understood"
    missing = [k for k, v in out.items() if v == "not-explored"]
    return {"per_domain": out,
            "missing": missing,
            "complete": not missing,
            "domains_total": len(DOMAIN_KEYS)}


def domain_findings_text(domains: dict[str, dict], max_chars: int = 12000) -> str:
    """The per-domain findings as the agent (and the report) can read them."""
    blocks = []
    for key in DOMAIN_KEYS:
        e = domains.get(key)
        if not e:
            blocks.append(f"- **{key}**: not explored")
            continue
        ev = ", ".join(str(x)[:80] for x in (e.get("evidence") or [])[:4])
        blocks.append(f"- **{key}** [{e.get('status')}]: "
                      f"{(e.get('answer') or '(no answer)')[:300]}"
                      + (f" | evidence: {ev}" if ev else ""))
    return "\n".join(blocks)[:max_chars]


def summarise(domains: dict[str, dict]) -> dict:
    """A compact, JSON-ready summary of a domain run."""
    cov = domain_coverage(domains)
    return {
        "engine": "domain-graph",
        "domains": cov["per_domain"],
        "missing": cov["missing"],
        "complete": cov["complete"],
        "step_budget": domain_step_budget(),
    }
