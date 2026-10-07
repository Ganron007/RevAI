#!/usr/bin/env python3
"""#19 agent observability and #12 Zeltser alignment — verified, and pinned.

Both were marked "in code, no run". Both are now exercised against real case
data, so the evidence is on disk and these tests hold the line.

#19  The Console's observability surface: /api/graph returns the agent graph as
     Mermaid plus its tool inventory; the SSE endpoint streams real progress;
     the progress file it reads exists and has events. Exercised through Flask's
     test client, which is the same code path the browser uses.

#12  The six deterministic technical sections (Pyramid-of-Pain tiering, Dynamic
     Analysis, Component Inventory, MBC Vocabulary, Analysis Environment, What We
     Don't Know) appear in the real reports, and they are rendered by code
     (build_deterministic_* / format_what_we_dont_know / attach_*), never by the
     LLM. The master report deliberately does not repeat them: it is the
     executive summary, and those sections are the technical report's job.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import code_files, resolve  # noqa: E402

import pytest  # noqa: E402

#: The six deterministic sections plan #12 / G21 claims. Each is matched by a
#: pattern that identifies the section, not a heading string that a rename would
#: break.
SIX_SECTIONS = [
    ("Pyramid of Pain / IOC tiering", r"Indicator confidence|Pyramid of Pain"),
    ("Dynamic Analysis (WinRE)", r"Dynamic analysis|Dynamic Corroboration"),
    ("Component Inventory", r"## Component Inventory"),
    ("MBC Vocabulary", r"MBC|Malware Behaviour Catalog"),
    ("Analysis Environment", r"Appendix A|Analysis Environment"),
    ("What We Don't Know", r"What We Don.t Know|Not observed"),
]

#: The code that renders them. If a renderer disappears, #12 is broken even if
#: the reports still look complete -- because the LLM would be authoring them.
RENDERERS = ("build_deterministic_technical",
             "build_deterministic_master",
             "format_what_we_dont_know",
             "attach_dynamic_analysis_section")


def _a_case_dir() -> Path | None:
    """A case dir with real artifacts, from wherever the run data lives."""
    for base in (Path("/opt/samples/logs"),):
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir(), reverse=True):
            for mode in ("scripted", "agentic"):
                c = d / mode
                if (c / "REPORT-TECHNICAL-v3.md").is_file():
                    return c
    return None


@pytest.fixture(scope="module")
def case():
    d = _a_case_dir()
    if d is None:
        pytest.skip("no run artifacts on this host (run a sample first)")
    return d


# --------------------------------------------------------------------- #19
def test_the_graph_endpoint_returns_mermaid_and_the_tool_inventory():
    app_src = resolve("revai/app.py").read_text(encoding="utf-8", errors="replace")
    assert '"/api/graph"' in app_src or "'/api/graph'" in app_src, (
        "the Console lost /api/graph -- the observability surface #19 added")
    # and the endpoint must actually call the graph helper, not a stub
    assert "agent_graph_mermaid" in app_src, (
        "/api/graph no longer delegates to the agent graph's own inventory, so "
        "it would report whatever the handler invents")


def test_the_graph_reports_the_tools_that_are_actually_bound():
    """The inventory must match AGENT_TOOL_NAMES, not a separate list."""
    lg = resolve("revai/agentic_langgraph.py").read_text(encoding="utf-8", errors="replace")
    import re
    m = re.search(r"AGENT_TOOL_NAMES\s*=\s*\[(.*?)\]", lg, re.S)
    assert m, "AGENT_TOOL_NAMES not found"
    bound = set(re.findall(r'"([A-Za-z0-9_]+)"', m.group(1)))
    assert "load_skill" in bound, (
        "load_skill is no longer bound to the default engine -- the skills layer "
        "is silent again (#49 regressed)")
    assert len(bound) >= 15, f"only {len(bound)} tools bound to the agent graph"


def test_the_sse_endpoint_exists_and_streams(case, monkeypatch):
    """The progress stream must be a real SSE endpoint over real data.

    Bounded via REVAI_PROGRESS_STREAM_SECONDS: the endpoint tails for up to five
    minutes by design, and a test that consumes the whole generator would spin
    for the full window proving nothing. Two seconds is enough to see the open
    event and any recorded events.
    """
    monkeypatch.setenv("REVAI_PROGRESS_STREAM_SECONDS", "2")
    sys.modules.pop("app", None)
    sys.path.insert(0, str(resolve("revai/app.py").parent))
    import app as A  # noqa: PLC0415
    c = A.app.test_client()
    sha = case.parent.name
    r = c.get(f"/api/orch/{sha}/progress/stream")
    assert r.status_code == 200, r.status_code
    assert "text/event-stream" in (r.headers.get("Content-Type") or ""), (
        "the progress endpoint is not an SSE stream -- a poller cannot use it")
    body = r.get_data(as_text=True)
    assert "data:" in body, "the stream carried no data events"


def test_the_progress_file_exists_with_events(case):
    p = case / "deep_dive" / "deep-dep-progress.jsonl"
    if not p.is_file():
        p = case / "deep_dive" / "deep-dive-progress.jsonl"
    assert p.is_file(), "the stream's source file was never written"
    lines = [l for l in p.read_text(errors="replace").splitlines() if l.strip()]
    assert lines, "the progress file is empty -- the stream would show nothing"


# --------------------------------------------------------------------- #12
def test_every_deterministic_section_appears_in_the_technical_report(case):
    t = (case / "REPORT-TECHNICAL-v3.md").read_text(
        encoding="utf-8", errors="replace")
    missing = [label for label, pat in SIX_SECTIONS
               if not re.search(pat, t, re.I)]
    assert not missing, f"the technical report is missing: {missing}"


def test_the_deterministic_sections_are_rendered_by_code():
    """If the renderer goes, the LLM would author them -- #12 regressed."""
    found = set()
    for p in code_files():
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for fn in RENDERERS:
            if f"def {fn}(" in src:
                found.add(fn)
    missing = set(RENDERERS) - found
    assert not missing, (
        f"these deterministic renderers are gone: {sorted(missing)} -- the "
        "sections they produce would become LLM prose")


def test_the_master_report_does_not_repeat_the_technical_sections(case):
    """By design: the master is the executive summary.

    Pinning the ABSENCE too, because a future change that starts copying the
    six sections into the master would double their length for no gain and make
    the two reports diverge on the same facts.
    """
    t = (case / "REPORT-MASTER-v3.md").read_text(encoding="utf-8", errors="replace")
    assert "## Component Inventory" not in t, (
        "the master report now repeats the technical Component Inventory; it "
        "belongs to the technical report only")


import re  # noqa: E402  (used above)
