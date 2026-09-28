#!/usr/bin/env python3
"""Context queries must be point lookups, not range joins into un-indexed tables.

Measured against the live ghidrasql server on winservices, 2.3 MB, 939
functions (2026-09-28):

    count(*) funcs                        7.4 s
    count(*) xrefs                        1.2 s
    count(*) strings                    > 60 s   (times out)
    count(*) pseudocode                 > 60 s   (times out)
    xrefs  WHERE from_addr BETWEEN ...    8.1 s
    xrefs  point lookup                   1.5 s
    strings WHERE addr IN (...)           1.5 s
    pseudocode WHERE func_addr = '...'    1.5 s
    xrefs JOIN strings (range)          > 40 s   (every width, +/- ORDER BY)

The old _string_refs was the range join, so every function's context cost two
timeouts plus a retry -- about 200 s per function, and the stage produced
nothing useful inside a run-length budget. The rewrite resolves xref targets
first and then looks strings up by key, both of which the server answers fast.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from recovery import context_builder as cbmod  # noqa: E402


class _FakeClient:
    """Answers only the queries the builder is supposed to issue."""

    def __init__(self):
        self.sql: list[str] = []
        self.timeouts: list[int | None] = []

    def ghidra_query(self, session_id, sql, max_rows=200, timeout=None):
        self.sql.append(" ".join(sql.split()))
        self.timeouts.append(timeout)
        s = self.sql[-1]
        if "SELECT DISTINCT x.to_addr" in s:
            return {"rows": [{"to_addr": "4258824"}, {"to_addr": "4278361"},
                             {"to_addr": "0"}]}
        if "FROM strings" in s:
            return {"rows": [{"content": "http://example.test/a"}]}
        return {"rows": []}


def _builder(client):
    return cbmod.ContextBuilder(client, "s1")


def test_string_refs_avoids_the_range_join():
    c = _FakeClient()
    out = _builder(c)._string_refs("4198400", 128)
    assert out == ["http://example.test/a"], out
    joined = " ".join(c.sql)
    assert "JOIN strings" not in joined, (
        f"the un-indexed range join is back: {c.sql}")
    # two point-lookup steps instead
    assert len(c.sql) == 2, c.sql
    assert "FROM xrefs" in c.sql[0] and "IN (" in c.sql[1], c.sql


def test_string_refs_filters_unusable_addresses():
    c = _FakeClient()
    _builder(c)._string_refs("4198400", 128)
    assert "'0'" not in c.sql[1].split("IN (")[1], c.sql[1]


def test_string_refs_skips_the_second_query_when_no_xrefs():
    c = _FakeClient()
    c.ghidra_query = lambda *a, **k: (c.sql.append(" ".join(
        str(k.get("sql", a[1] if len(a) > 1 else "")).split())),
        {"rows": []})[1]
    out = _builder(c)._string_refs("4198400", 0)
    assert out == []
    assert len(c.sql) == 0, c.sql      # size 0 short-circuits entirely


def test_every_context_query_carries_the_tight_bound():
    """A timeout must reach the client: the shim used to swallow it, and the
    symptom was a hollow success (110 unknown_* names, confidence 0.1)."""
    from v2_lib import McpGhidraClient
    import inspect
    sig = inspect.signature(McpGhidraClient.ghidra_query)
    assert "timeout" in sig.parameters, (
        "McpGhidraClient.ghidra_query must forward timeout")

    c = _FakeClient()
    cb = _builder(c)
    cb._pseudocode("4198400")
    cb._string_refs("4198400", 64)
    cb._data_xrefs("4198400", 64)
    cb._callee_records("4198400")
    cb._caller_records("4198400")
    cb._neighbors("4198400")
    assert c.timeouts, "no queries were issued"
    bound = cbmod.CONTEXT_QUERY_TIMEOUT_S
    for t in c.timeouts:
        assert t == bound, f"query issued with timeout={t}, want {bound}"


def test_one_stalled_query_costs_bounded_time_not_the_bulk_default():
    """Regression on cost, not just shape: the retry must not double a scan."""
    import ghidra_sql_client as gsql
    calls = {"n": 0}

    class _Stall:
        def ghidra_query(self, session_id, sql, max_rows=200, timeout=None):
            calls["n"] += 1
            raise RuntimeError("ghidrasql query timed out")

    cb = cbmod.ContextBuilder(_Stall(), "s1")
    t0 = time.time()
    rows = cb._query("SELECT 1", max_rows=1)
    assert rows and "error" in rows[0], rows
    assert calls["n"] == 2, f"{calls['n']} attempts; one retry is the budget"
    assert time.time() - t0 < 5
    assert gsql.QUERY_TIMEOUT >= cbmod.CONTEXT_QUERY_TIMEOUT_S * 4
