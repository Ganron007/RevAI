"""
call_graph.py — build call graph and bottom-up work ordering from Ghidra SQL.
"""
from __future__ import annotations

from typing import Any


class CallGraph:
    """Lightweight in-memory call graph built from Ghidra SQL tables."""

    def __init__(self, funcs: list[dict], call_edges: list[dict]):
        """
        Args:
            funcs: rows from the `funcs` table (must contain 'address', 'name').
            call_edges: rows from the `call_edges` table (must contain
                        'src_func_addr' and 'dst_func_addr'; '0' means unknown).
        """
        self.funcs = funcs
        self.addr_to_func = {self._addr_key(f["address"]): f for f in funcs}
        self.calls: dict[str, set[str]] = {}          # caller -> set(callee_addrs)
        self.callers: dict[str, set[str]] = {}        # callee -> set(caller_addrs)
        self._build(call_edges)

    @staticmethod
    def _addr_key(addr: Any) -> str:
        return str(int(addr)) if addr is not None else ""

    def _build(self, call_edges: list[dict]) -> None:
        for e in call_edges:
            src = self._addr_key(e.get("src_func_addr"))
            dst = self._addr_key(e.get("dst_func_addr"))
            if not src or not dst or dst == "0":
                continue
            if src not in self.addr_to_func or dst not in self.addr_to_func:
                continue
            self.calls.setdefault(src, set()).add(dst)
            self.callers.setdefault(dst, set()).add(src)

    def callees(self, addr: str | int) -> set[str]:
        return self.calls.get(self._addr_key(addr), set())

    def callers_of(self, addr: str | int) -> set[str]:
        return self.callers.get(self._addr_key(addr), set())

    def is_leaf(self, addr: str | int) -> bool:
        return len(self.callees(addr)) == 0

    def bottom_up_tiers(self) -> list[list[str]]:
        """Return a list of tiers; each tier contains function addresses that
        can be analyzed once all lower tiers (dependencies) are resolved."""
        resolved: set[str] = set()
        remaining = set(self.addr_to_func.keys())
        tiers: list[list[str]] = []
        while remaining:
            tier: list[str] = []
            for addr in list(remaining):
                deps = self.callees(addr) - resolved
                if not deps:
                    tier.append(addr)
            if not tier:
                # cycle remaining; break by processing remaining as a final tier
                tiers.append(sorted(remaining))
                break
            tiers.append(tier)
            resolved.update(tier)
            remaining -= set(tier)
        return tiers


def build_bottom_up_order(funcs: list[dict], call_edges: list[dict]) -> list[list[dict]]:
    """Convenience wrapper returning tiers of function *records*."""
    cg = CallGraph(funcs, call_edges)
    return [[cg.addr_to_func[a] for a in tier if a in cg.addr_to_func]
            for tier in cg.bottom_up_tiers()]
