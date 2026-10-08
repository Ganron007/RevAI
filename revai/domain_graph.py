"""revai/domain_graph.py — plan #20: the deep dive as named domain nodes.

The deep dive was one flat ReAct loop. The prompt asked the model to self-check
every capability domain before answering, which is a request, not a structure:
a domain the model never visited was a coverage failure the gate could only see
after the fact (the depth gate reads the summary's prose).

This module makes the domains STRUCTURAL. The graph has one node per capability
domain; each node runs its own bounded investigation over the same tool
registry and returns a determination. The nodes run in sequence, then synthesis
combines them and the verdict follows from the combined picture.

Why per-domain nodes and not one bigger loop:
  * each domain gets its own step budget, ENFORCED by the runtime's recursion
    limit rather than requested in the prompt, so a stubborn injection question
    can no longer starve the persistence question by timing the whole run out;
  * a domain can say "not observed" as a first-class result, which is what the
    depth gate has always wanted to check;
  * the graph's shape IS the coverage record -- the node list is the answer to
    "what did you look at", with no prose in between.

There is no convergence loop here. Convergence (re-examining a domain until its
answer holds) is a separate concern and lives with the depth mode; this module
is the substrate it runs on, and it deliberately claims nothing about it.

Coverage is reported as four separate facts, because collapsing them is how a
total failure gets published as a success: `visited`, `answered`, `understood`
and `substantive`. `complete` means every domain was investigated to a real
determination; `honest` additionally requires that at least one domain actually
said something and that no status was unrecognised. Nine nodes that were visited
and answered but empty is `complete` and not `honest`, and the engine falls back
to the flat ReAct loop in that case rather than synthesising a verdict from nine
empty bullets.

Opt-in: REVAI_DOMAIN_GRAPH=1. Off by default, so the flat engine is unchanged
until this is validated on a real sample. The two engines read the same
registry, the same checklist and the same gates.
"""
from __future__ import annotations

import os
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

#: The only statuses a node may report. Anything else is treated as a FAILURE,
#: never as progress -- an unrecognised value must not be able to make an
#: unexamined domain look answered.
STATUS_UNDERSTOOD = "understood"      # investigated; behaviour determined
STATUS_PARTIAL = "partial"            # investigated; inconclusive
STATUS_NOT_RECONSTRUCTED = "not-reconstructed"  # the node could not run
STATUS_NOT_EXPLORED = "not-explored"  # never looked

KNOWN_STATUSES = (STATUS_UNDERSTOOD, STATUS_PARTIAL,
                  STATUS_NOT_RECONSTRUCTED, STATUS_NOT_EXPLORED)

#: Statuses that mean "this domain has no usable answer". These are errors or
#: absences, not findings, and they must keep `complete` false.
UNUSABLE_STATUSES = (STATUS_NOT_RECONSTRUCTED, STATUS_NOT_EXPLORED)


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


def _balanced_objects(s: str):
    """Yield every top-level {...} span in `s`, longest first.

    A model asked for JSON frequently wraps it: "Based on the 3 tool calls I
    have, here is the result: {...}". Taking `find("{")`..`rfind("}")` breaks on
    that when the prose contains a brace of its own, and taking the FIRST
    balanced object breaks when the model wrote a summary object before the
    answer. Trying each balanced span and keeping the first that parses as a dict
    handles both, and preferring the longest biases toward the answer rather than
    a nested fragment.
    """
    spans = []
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    spans.append(s[start:i + 1])
                    start = -1
    for span in sorted(spans, key=len, reverse=True):
        yield span


def parse_domain_reply(text: str) -> tuple[dict, str]:
    """Extract a domain node's structured answer. Returns (parsed, why).

    `why` is empty on success and otherwise names the failure, because a node
    that produced nothing must be diagnosable from the artifact alone. The first
    real run produced a correctly-formed answer wrapped in prose and recorded it
    as `partial` with no way to tell a parser problem from a model problem --
    which is the same unexamined-artifact failure this project keeps meeting.
    """
    import json as _json

    s = (text or "").strip()
    if not s:
        return {}, "empty reply"

    fenced = s
    if fenced.startswith("```"):
        lines = fenced.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        fenced = "\n".join(lines).strip()

    for candidate in (s, fenced):
        try:
            parsed = _json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed, ""
        except Exception:
            pass

    for span in _balanced_objects(s) or _balanced_objects(fenced):
        try:
            parsed = _json.loads(span)
            if isinstance(parsed, dict):
                return parsed, ""
        except Exception:
            continue

    # Nothing parsed. Say WHY, because the two causes need different fixes: a
    # truncated reply needs a bigger budget or a smaller ask, a prose reply needs
    # a better instruction.
    if "{" in s and "}" not in s:
        return {}, "reply appears truncated (no closing brace)"
    if "{" in s:
        return {}, "reply contains braces but no balanced object parsed"
    return {}, "reply contained no JSON object"


def domain_coverage(domains: dict[str, dict]) -> dict:
    """Coverage over the domain set: what was visited, what was answered.

    Three distinct questions, kept distinct because conflating them is how a
    total failure gets reported as success:

      * VISITED   -- a node ran and returned a result of any kind.
      * ANSWERED  -- that result is a real determination (`understood`, or
                     `partial`: looked, could not conclude). "not observed" is
                     an ANSWER; it is not a gap.
      * USABLE    -- neither `not-explored` (never looked) nor
                     `not-reconstructed` (the node itself failed), and not an
                     unrecognised status, which is counted as a failure rather
                     than dropped so a typo cannot look like progress.

    * `complete` requires every domain to be USABLE. A run in which all nine
    nodes raised is visited-but-not-usable, and must read as incomplete.

    A fourth distinction matters at the call site: SUBSTANTIVE. A node can be
    visited and answered yet produce nothing -- prose where JSON was asked for,
    or a status with an empty answer and no evidence. Nine such domains are not
    a dive, so the caller falls back to the flat engine rather than synthesise a
    verdict from nine empty bullets.
    """
    per_domain: dict[str, str] = {}
    visited: list[str] = []
    answered: list[str] = []
    understood: list[str] = []
    unusable: list[str] = []
    substantive: list[str] = []

    for key in DOMAIN_KEYS:
        entry = domains.get(key) or {}
        status = str(entry.get("status") or "").strip().lower()
        if not status:
            status = STATUS_NOT_EXPLORED
        per_domain[key] = status
        if status != STATUS_NOT_EXPLORED:
            visited.append(key)
        if status in (STATUS_UNDERSTOOD, STATUS_PARTIAL):
            answered.append(key)
        else:
            unusable.append(key)
        if status == STATUS_UNDERSTOOD:
            understood.append(key)
        if status in (STATUS_UNDERSTOOD, STATUS_PARTIAL) and (
                entry.get("answer") or entry.get("evidence")):
            substantive.append(key)

    return {
        "per_domain": per_domain,
        "visited": visited,
        "answered": answered,
        "understood": understood,
        "substantive": substantive,
        "unusable": unusable,
        "missing": [k for k in DOMAIN_KEYS
                    if per_domain[k] == STATUS_NOT_EXPLORED],
        "failed": [k for k in DOMAIN_KEYS
                   if per_domain[k] == STATUS_NOT_RECONSTRUCTED],
        # An unrecognised status is a defect in the node, not a domain result.
        "unknown_status": sorted({s for s in per_domain.values()
                                  if s not in KNOWN_STATUSES}),
        "complete": not unusable,
        "understood_complete": len(understood) == len(DOMAIN_KEYS),
        "domains_total": len(DOMAIN_KEYS),
    }


def coverage_is_honest(cov: dict) -> bool:
    """Whether a coverage record may be presented as a finished dive.

    Four ways to fail, each of which has shipped as green before:
      * the graph did not run (`domains_total` absent/zero);
      * a status the code does not recognise, which means the node contract and
        the coverage rule disagree and neither can be trusted;
      * a domain that was never investigated or whose node failed;
      * nothing substantive anywhere -- every domain visited, none of them
        saying anything, which is a total failure wearing a full set of nodes.
    """
    if not cov or int(cov.get("domains_total") or 0) != len(DOMAIN_KEYS):
        return False
    if cov.get("unknown_status"):
        return False
    if not cov.get("complete"):
        return False
    return bool(cov.get("substantive"))


def summarise(domains: dict[str, dict]) -> dict:
    """A compact, JSON-ready summary of a domain run."""
    cov = domain_coverage(domains)
    per_dom = domains.get(DOMAIN_KEYS[0]) if domains else None
    used = sum(int((domains.get(k) or {}).get("tool_calls_used") or 0)
               for k in DOMAIN_KEYS)
    return {
        "engine": "domain-graph",
        "domains": cov["per_domain"],
        "visited": cov["visited"],
        "answered": cov["answered"],
        "understood": cov["understood"],
        "substantive": cov["substantive"],
        "unusable": cov["unusable"],
        "missing": cov["missing"],
        "failed": cov["failed"],
        "unknown_status": cov["unknown_status"],
        "complete": cov["complete"],
        "understood_complete": cov["understood_complete"],
        # `honest` is the gate: coverage the audit and the report may cite.
        # `complete` alone can be true while nothing was actually said.
        "honest": coverage_is_honest(cov),
        "domains_total": cov["domains_total"],
        "step_budget": domain_step_budget(),
        "tool_calls_used": used,
    }


def domain_findings_text(domains: dict[str, dict], max_chars: int = 12000) -> str:
    """The per-domain findings as the agent (and the report) can read them."""
    blocks = []
    for key in DOMAIN_KEYS:
        e = domains.get(key)
        if not e:
            blocks.append(f"- **{key}**: NOT EXAMINED")
            continue
        status = str(e.get("status") or STATUS_NOT_EXPLORED)
        marker = "" if status in (STATUS_UNDERSTOOD, STATUS_PARTIAL) else \
                 "  (no usable answer -- treat this domain as uncovered)"
        ev = ", ".join(str(x)[:80] for x in (e.get("evidence") or [])[:4])
        used = e.get("tool_calls_used")
        spend = f" [{used}/{e.get('step_budget')} tools]" if used is not None else ""
        blocks.append(f"- **{key}** [{status}]{spend}: "
                      f"{(e.get('answer') or '(no answer)')[:300]}"
                      + (f" | evidence: {ev}" if ev else "") + marker)
    return "\n".join(blocks)[:max_chars]
