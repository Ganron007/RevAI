"""
synthesizer.py — global semantic synthesis after per-function LLM recovery.

Responsibilities:
  * Name unification: if caller A says callee is `parse_url` and caller B says
    `url_parse`, pick one or flag inconsistency.
  * Struct recovery: scan decompilation for field-access patterns like
    `*(param_1 + 0x10)` and propose struct definitions.
  * Conflict reconciliation: duplicate claimed names get downgraded to
    `NEEDS_HUMAN_REVIEW`.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any


class Synthesizer:
    """Post-recovery consistency pass."""

    def __init__(self, min_confidence: float = 0.7):
        self.min_confidence = min_confidence

    def synthesize(self, results: list[dict]) -> dict:
        """Run all synthesis passes and return a report."""
        unified = self._unify_names(results)
        structs = self._recover_structs(results)
        conflicts = self._find_conflicts(results)
        for r in results:
            addr = r.get("function_address")
            if addr in conflicts:
                r["confidence"] = min(r.get("confidence", 1.0), 0.55)
                r["status"] = "NEEDS_HUMAN_REVIEW"
                r["conflict_reason"] = conflicts[addr]
        return {
            "function_results": results,
            "unified_names": unified,
            "proposed_structs": structs,
            "conflict_count": len(conflicts),
        }

    def _unify_names(self, results: list[dict]) -> dict[str, list[str]]:
        """Group function addresses by cleaned name; flag aliases."""
        name_to_addrs: dict[str, list[str]] = defaultdict(list)
        for r in results:
            name = r.get("function_name", "").strip()
            addr = r.get("function_address", "")
            if name and addr and not name.startswith("FUN_"):
                name_to_addrs[name].append(addr)
        return dict(name_to_addrs)

    def _find_conflicts(self, results: list[dict]) -> dict[str, str]:
        """Find duplicate claimed names and addresses with clashing names."""
        conflicts: dict[str, str] = {}
        name_to_addrs: dict[str, list[str]] = defaultdict(list)
        for r in results:
            name = r.get("function_name", "").strip()
            addr = r.get("function_address", "")
            if name and addr and not name.startswith("FUN_"):
                name_to_addrs[name].append(addr)
        for name, addrs in name_to_addrs.items():
            if len(addrs) > 1:
                for a in addrs:
                    conflicts[a] = f"name '{name}' claimed by {len(addrs)} addresses"
        return conflicts

    def _recover_structs(self, results: list[dict]) -> list[dict]:
        """Simple field-offset extraction from normalized pseudocode."""
        structs_by_base: dict[str, dict] = {}
        pattern = re.compile(
            r"\*\s*\(\s*(?:\w+\s*\*\s*)?\(?\s*(\w+)\s*\)?\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"
        )
        for r in results:
            text = (r.get("normalized_pseudocode") or "") + "\n" + (r.get("raw_pseudocode") or "")
            for m in pattern.finditer(text):
                base = m.group(1)
                offset = int(m.group(2), 0)
                if base not in structs_by_base:
                    structs_by_base[base] = {"base": base, "offsets": {}}
                offsets = structs_by_base[base]["offsets"]
                if offset not in offsets:
                    offsets[offset] = {"count": 0, "types": set()}
                offsets[offset]["count"] += 1
        structs = []
        for base, data in structs_by_base.items():
            offsets = data["offsets"]
            if len(offsets) < 2:
                continue
            fields_out = [
                {"offset": off, "count": info["count"], "suggested_name": f"field_{off:x}"}
                for off, info in sorted(offsets.items())
            ]
            structs.append({
                "base_variable": base,
                "field_count": len(fields_out),
                "fields": fields_out,
            })
        structs.sort(key=lambda x: x["field_count"], reverse=True)
        return structs[:20]

    @staticmethod
    def choose_canonical(candidates: list[str]) -> str:
        """Pick the most common name; prefer names without underscores-as-prefix."""
        counts: dict[str, int] = defaultdict(int)
        for c in candidates:
            counts[c] += 1
        return max(counts.items(), key=lambda kv: (kv[1], -len(kv[0])))[0]
