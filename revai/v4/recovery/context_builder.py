"""
context_builder.py — build rich per-function context for LLM recovery.
"""
from __future__ import annotations

import sys
from typing import Any

from .normalizer import Normalizer


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
        try:
            r = self.client.ghidra_query(self.session_id, sql, max_rows=max_rows)
            return r.get("rows", []) or []
        except Exception as e:
            return [{"error": str(e)}]

    def _pseudocode(self, addr: str) -> str | None:
        rows = self._query(
            f"SELECT text FROM pseudocode WHERE func_addr = '{addr}' AND is_stale = '0' LIMIT 1",
            max_rows=1,
        )
        if rows and "text" in rows[0]:
            return rows[0]["text"]
        return None

    def _string_refs(self, addr: str, size: int) -> list[str]:
        if size <= 0:
            return []
        start = int(addr)
        end = start + size
        rows = self._query(
            f"""
            SELECT DISTINCT s.content
            FROM xrefs x
            JOIN strings s ON x.to_ea = s.address
            WHERE x.from_ea >= '{start}' AND x.from_ea <= '{end}'
              AND s.length > 2
            ORDER BY s.length DESC
            LIMIT 20
            """,
            max_rows=20,
        )
        return [r["content"] for r in rows if "content" in r][:10]

    def _data_xrefs(self, addr: str, size: int) -> list[dict]:
        if size <= 0:
            return []
        start = int(addr)
        end = start + size
        rows = self._query(
            f"""
            SELECT DISTINCT x.from_ea, x.to_ea, x.kind
            FROM xrefs x
            WHERE x.from_ea >= '{start}' AND x.from_ea <= '{end}'
              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')
            LIMIT 30
            """,
            max_rows=30,
        )
        return [{k: v for k, v in r.items() if k != "error"} for r in rows]

    def _callee_records(self, addr: str) -> list[dict]:
        rows = self._query(
            f"""
            SELECT DISTINCT f.address, f.name, f.size
            FROM call_edges c
            JOIN funcs f ON f.address = c.dst_func_addr
            WHERE c.src_func_addr = '{addr}' AND c.dst_func_addr != '0'
            LIMIT {self.max_context_funcs + 5}
            """,
            max_rows=self.max_context_funcs + 5,
        )
        return rows[: self.max_context_funcs]

    def _caller_records(self, addr: str) -> list[dict]:
        rows = self._query(
            f"""
            SELECT DISTINCT f.address, f.name, f.size
            FROM call_edges c
            JOIN funcs f ON f.address = c.src_func_addr
            WHERE c.dst_func_addr = '{addr}' AND c.src_func_addr != '0'
            LIMIT {self.max_context_funcs + 5}
            """,
            max_rows=self.max_context_funcs + 5,
        )
        return rows[: self.max_context_funcs]

    def _neighbors(self, addr: str) -> list[dict]:
        rows = self._query(
            f"""
            SELECT address, name, size FROM funcs
            WHERE address >= '{int(addr) - 0x2000}' AND address <= '{int(addr) + 0x2000}'
            ORDER BY ABS(CAST(address AS INTEGER) - {int(addr)}) ASC
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
