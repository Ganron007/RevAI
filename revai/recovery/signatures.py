"""
signatures.py — load and match stdlib / crypto / Windows API signatures.

Signature DBs live in Tools/v4-deploy/signatures/*.json. Each entry describes
how strongly a function should be considered a known symbol. Matching uses:

  * import / external symbol names (substring match)
  * string references found in the function's address range
  * hard-coded constants (hex or decimal)
  * structural heuristics (size, cyclomatic complexity, call counts)

A function whose cumulative score reaches the configured threshold bypasses
LLM inference and is renamed directly.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

DEFAULT_THRESHOLD = 0.80


def _canonical_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


class SignatureDB:
    """In-memory signature database with additive scoring."""

    def __init__(self, signature_dirs: list[Path] | None = None,
                 threshold: float = DEFAULT_THRESHOLD):
        self.threshold = threshold
        self.entries: list[dict] = []
        dirs = signature_dirs or [Path(__file__).parent.parent / "signatures"]
        for d in dirs:
            if not d.exists():
                continue
            for path in sorted(d.glob("*.json")):
                try:
                    data = json.loads(path.read_text())
                    self.entries.extend(data.get("signatures", []))
                except Exception:
                    continue

    def match(self, func: dict, context: dict) -> dict | None:
        """Score `func` against all signatures and return the best match
        above threshold, or None.

        Args:
            func: funcs table row with at least 'address', 'name', 'size'.
            context: dict with keys:
                - 'strings': list of string contents referenced by the function
                - 'imports': list of import/external symbol names referenced
                - 'constants': list of int constants referenced
                - 'cyclomatic_complexity': int
                - 'call_in_count': int
                - 'call_out_count': int
        Returns:
            {'name': str, 'score': float, 'matched_rules': [str], 'notes': str}
            or None.
        """
        best: dict | None = None
        size = int(func.get("size") or 0)
        cc = int(context.get("cyclomatic_complexity") or 0)
        out_count = int(context.get("call_out_count") or 0)
        strings = {s.lower() for s in (context.get("strings") or [])}
        imports = {i for i in (context.get("imports") or [])}
        constants = set(context.get("constants") or [])

        for entry in self.entries:
            ind = entry.get("indicators", {})
            heur = entry.get("heuristics", {})
            score = 0.0
            hits: list[str] = []

            # Structural bounds
            min_size = ind.get("min_size")
            max_size = ind.get("max_size")
            if min_size is not None and size < min_size:
                continue
            if max_size is not None and size > max_size:
                continue

            # Import / external symbol matching
            ext = ind.get("external_symbol_contains", [])
            if ext and any(any(p.lower() in imp.lower() for p in ext) for imp in imports):
                score += 0.45
                hits.append("external_symbol")

            # String reference matching
            want_strings = {s.lower() for s in ind.get("string_refs", [])}
            if want_strings and strings & want_strings:
                score += 0.35
                hits.append("string_ref")

            # Constant matching
            want_hex = ind.get("constants_hex", [])
            for h in want_hex:
                try:
                    val = int(h, 16)
                    if val in constants:
                        score += 0.20
                        hits.append(f"constant_{h}")
                        break
                except ValueError:
                    continue

            # Heuristic adjustments
            h_cc_max = heur.get("cyclomatic_max")
            if h_cc_max is not None and cc <= h_cc_max:
                score += 0.10
            h_out_max = heur.get("call_out_max")
            if h_out_max is not None and out_count <= h_out_max:
                score += 0.10
            h_str = {s.lower() for s in heur.get("string_hints", [])}
            if h_str and strings & h_str:
                score += 0.10

            # Clamp and compare to threshold
            score = min(score, entry.get("score", 0.85))
            if score >= self.threshold:
                if best is None or score > best["score"]:
                    best = {
                        "name": _canonical_name(entry["name"]),
                        "score": round(score, 3),
                        "matched_rules": hits,
                        "notes": ind.get("notes", ""),
                    }
        return best

    def match_by_name(self, name: str) -> dict | None:
        """Direct name lookup (used when a function already has a non-FUN name)."""
        for entry in self.entries:
            if entry["name"].lower() == name.lower():
                return {
                    "name": _canonical_name(entry["name"]),
                    "score": entry.get("score", 0.85),
                    "matched_rules": ["exact_name"],
                    "notes": entry.get("indicators", {}).get("notes", ""),
                }
        return None
