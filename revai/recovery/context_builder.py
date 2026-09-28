"""
context_builder.py — build rich per-function context for LLM recovery.
"""
from __future__ import annotations

import os
import sys
from typing import Any

from .normalizer import Normalizer


def _context_query_timeout() -> int:
    """Bound for the per-function context queries (seconds).

    These are small indexed lookups (pseudocode / xrefs / call edges for one
    function) and measured 2.4 s each on a 2.3 MB sample (2026-09-28). The 900 s
    bulk default in ghidra_sql_client is sized for whole-program queries like
    cfg_edges on 50MB+ samples; applying it per function meant one unanswered
    request stalled the stage for 15 minutes.

    Overridable because a very large sample can legitimately need longer for a
    single function's context - fail-open is the right trade for a small one and
    the wrong one for a huge binary.
    """
    try:
        return max(15, int(os.environ.get("REVAI_GHIDRA_CONTEXT_TIMEOUT_S",
                                          "120")))
    except ValueError:
        return 120


CONTEXT_QUERY_TIMEOUT_S = _context_query_timeout()


def _addr_key(addr: Any) -> str:
    return str(int(addr)) if addr is not None else ""


class ContextBuilder:
    """Builds a structured context window for one target function."""

    def __init__(self, client, session_id: str,
                 normalizer: Normalizer | None = None,
                 max_func_size: int = 8000,
                 max_context_funcs: int = 5):
        self.client = client
        self.session_id = session_id
        self.normalizer = normalizer or Normalizer()
        self.max_func_size = max_func_size
        self.max_context_funcs = max_context_funcs

    def build(self, func: dict, resolved: dict[str, dict],
              obfuscation_flags: dict | None = None) -> dict:
        """Return a dict with all prompt building blocks."""
        addr = _addr_key(func["address"])
        size = int(func.get("size") or 0)
        raw_pseudo = self._pseudocode(addr)
        normalized = self.normalizer.normalize(raw_pseudo or "")

        strings = self._string_refs(addr, size)
        xrefs = self._data_xrefs(addr, size)
        callees = self._callee_records(addr)
        callers = self._caller_records(addr)
        neighbors = self._neighbors(addr)

        return {
            "target_address": addr,
            "target_name": func.get("name"),
            "target_size": size,
            "normalized_pseudocode": normalized,
            "raw_pseudocode": raw_pseudo,
            "string_refs": strings,
            "data_xrefs": xrefs,
            "callees": self._resolved_signatures(callees, resolved),
            "callers": self._resolved_signatures(callers, resolved),
            "neighbors": neighbors,
            "obfuscation": obfuscation_flags or {},
        }

    def _query(self, sql: str, max_rows: int = 200) -> list[dict]:
        # Per-function queries, so they get a tight bound: one wedged ghidrasql
        # request must not cost the 900 s bulk default (observed 2026-09-28 on
        # winservices -- server idle, client blocked in poll the whole time).
        budget = _context_query_timeout()
        last = "unknown error"
        # One retry covers a transient stall; a server that is genuinely wedged
        # fails open as a data row rather than unwinding the whole stage.
        for attempt in (1, 2):
            try:
                r = self.client.ghidra_query(self.session_id, sql,
                                             max_rows=max_rows,
                                             timeout=budget)
            except Exception as e:
                last = str(e)
                continue
            rows = r.get("rows", []) or []
            if not (len(rows) == 1 and "error" in rows[0]):
                return rows
            # ghidrasql answered with a per-query error: worth one more try
            last = str(rows[0]["error"])
        return [{"error": last}]

    def _pseudocode(self, addr: str) -> str | None:
        rows = self._query(
            f"SELECT text FROM pseudocode WHERE func_addr = '{addr}' AND is_stale = '0' LIMIT 1",
            max_rows=1,
        )
        if rows and "text" in rows[0]:
            return rows[0]["text"]
        return None

    def _string_refs(self, addr: str, size: int) -> list[str]:
        """Strings referenced by this function.

        Two steps instead of one range join. The single
        `xrefs JOIN strings WHERE from_addr BETWEEN ...` query is unusable
        against ghidrasql (measured 2026-09-28 on a 2.3 MB sample: >40 s at
        every range width tried, with and without ORDER BY, while the same
        tables answer in 1-8 s when addressed by key):

            count(*) funcs        7.4 s     xrefs range, no join  8.1 s
            count(*) xrefs        1.2 s     xrefs point lookup  1.5 s
            count(*) strings    >60 s       strings WHERE addr IN  1.5 s
            count(*) pseudocode >60 s       pseudocode WHERE func_addr =  1.5 s

        So: take the xref targets out of `xrefs` (fast, that table is
        indexed), then resolve those addresses against `strings` with an
        `IN (...)` list (fast, that table is not). The range join forced a scan
        of the un-indexed side of both tables.
        """
        if size <= 0:
            return []
        start = int(addr)
        end = start + size
        targets = self._query(
            f"""
            SELECT DISTINCT x.to_addr
            FROM xrefs x
            WHERE x.from_addr >= '{start}' AND x.from_addr <= '{end}'
            LIMIT 60
            """,
            max_rows=60,
        )
        addrs = [str(r["to_addr"]) for r in targets
                 if isinstance(r, dict) and r.get("to_addr")
                 and str(r["to_addr"]) not in ("0", "None")]
        if not addrs:
            return []
        # ghidrasql has no bound-parameter form over HTTP; these are integers
        # that came out of Ghidra's own address space, and the client already
        # rejects multi-statement SQL, so the list form is safe here.
        literal = ",".join(f"'{a}'" for a in addrs[:60])
        rows = self._query(
            f"""
            SELECT content
            FROM strings
            WHERE addr IN ({literal}) AND length > 2
            LIMIT 20
            """,
            max_rows=20,
        )
        return [r["content"] for r in rows
                if isinstance(r, dict) and r.get("content")][:10]

    def _data_xrefs(self, addr: str, size: int) -> list[dict]:
        if size <= 0:
            return []
        start = int(addr)
        end = start + size
        rows = self._query(
            f"""
            SELECT DISTINCT x.from_addr, x.to_addr, x.kind
            FROM xrefs x
            WHERE x.from_addr >= '{start}' AND x.from_addr <= '{end}'
              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')
            LIMIT 30
            """,
            max_rows=30,
        )
        return [{k: v for k, v in r.items() if k != "error"} for r in rows]

    def _callee_records(self, addr: str) -> list[dict]:
        rows = self._query(
            f"""
            SELECT DISTINCT f.addr AS address, f.name, f.size
            FROM call_edges c
            JOIN funcs f ON f.addr = c.dst_func_addr
            WHERE c.src_func_addr = '{addr}' AND c.dst_func_addr != '0'
            LIMIT {self.max_context_funcs + 5}
            """,
            max_rows=self.max_context_funcs + 5,
        )
        return rows[: self.max_context_funcs]

    def _caller_records(self, addr: str) -> list[dict]:
        rows = self._query(
            f"""
            SELECT DISTINCT f.addr AS address, f.name, f.size
            FROM call_edges c
            JOIN funcs f ON f.addr = c.src_func_addr
            WHERE c.dst_func_addr = '{addr}' AND c.src_func_addr != '0'
            LIMIT {self.max_context_funcs + 5}
            """,
            max_rows=self.max_context_funcs + 5,
        )
        return rows[: self.max_context_funcs]

    def _neighbors(self, addr: str) -> list[dict]:
        rows = self._query(
            f"""
            SELECT addr AS address, name, size FROM funcs
            WHERE addr >= '{int(addr) - 0x2000}' AND addr <= '{int(addr) + 0x2000}'
            ORDER BY ABS(CAST(addr AS INTEGER) - {int(addr)}) ASC
            LIMIT 7
            """,
            max_rows=7,
        )
        return [r for r in rows if _addr_key(r.get("address")) != addr][:6]

    def _resolved_signatures(self, funcs: list[dict], resolved: dict[str, dict]) -> list[dict]:
        out = []
        for f in funcs:
            addr = _addr_key(f.get("address"))
            rec = resolved.get(addr)
            out.append({
                "address": addr,
                "name": rec["function_name"] if rec else f.get("name"),
                "confidence": rec.get("confidence") if rec else None,
                "return_type": rec.get("return_type") if rec else None,
            })
        return out
