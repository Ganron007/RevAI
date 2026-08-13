"""
ghidra_writeback.py — apply recovered symbols/types to the Ghidra program DB.

All writes go through ghidra_sql_client.py so they are audited in
audit.jsonl. The module never deletes data; it only renames functions,
sets comments, and updates parameter names when safe to do so.
"""
from __future__ import annotations

from typing import Any


def _addr_key(addr: Any) -> str:
    return str(int(addr)) if addr is not None else ""


class GhidraWriteback:
    """Batch apply recovered symbols to one Ghidra session."""

    def __init__(self, client, session_id: str, sha256: str):
        self.client = client
        self.session_id = session_id
        self.sha256 = sha256

    def apply(self, results: list[dict], dry_run: bool = False) -> dict:
        """Apply renames and comments for functions with confidence >= 0.7.

        Returns a summary dict with counts and per-function results.
        """
        applied: list[dict] = []
        skipped: list[dict] = []
        errors: list[dict] = []
        for r in results:
            addr = _addr_key(r.get("function_address"))
            name = r.get("function_name", "").strip()
            conf = float(r.get("confidence") or 0)
            status = r.get("status", "")
            if not addr or not name or name.startswith("FUN_"):
                skipped.append({"address": addr, "reason": "no usable name"})
                continue
            if status == "NEEDS_HUMAN_REVIEW" or conf < 0.7:
                skipped.append({"address": addr, "reason": f"confidence {conf} or status {status}"})
                continue
            try:
                if not dry_run:
                    self._rename(addr, name)
                    self._comment(addr, r.get("notes", ""))
                    self._params(addr, r.get("parameters", []))
                applied.append({"address": addr, "name": name, "confidence": conf})
            except Exception as e:
                errors.append({"address": addr, "name": name, "error": str(e)})
        return {
            "dry_run": dry_run,
            "applied": applied,
            "skipped": skipped,
            "errors": errors,
            "applied_count": len(applied),
            "skipped_count": len(skipped),
            "error_count": len(errors),
        }

    def _rename(self, addr: str, name: str) -> None:
        safe_name = name.replace("'", "''")[:255]
        sql = f"UPDATE funcs SET name = '{safe_name}' WHERE addr = '{addr}'"
        self.client.ghidra_query(self.session_id, sql, max_rows=1)

    def _comment(self, addr: str, text: str) -> None:
        if not text:
            return
        safe = text.replace("'", "''")[:2000]
        sql = (
            f"INSERT OR REPLACE INTO comments (address, comment, repeatable, source) "
            f"VALUES ('{addr}', '{safe}', 0, 'agentic_recovery_v4')"
        )
        self.client.ghidra_query(self.session_id, sql, max_rows=1)

    def _params(self, addr: str, params: list[dict]) -> None:
        """Update parameter names when they are user-meaningful."""
        if not params:
            return
        for i, p in enumerate(params):
            pname = str(p.get("name", "")).strip()
            if not pname or pname.startswith("param_") or pname.startswith("arg_"):
                continue
            safe = pname.replace("'", "''")[:128]
            sql = (
                f"UPDATE function_params SET param_name = '{safe}' "
                f"WHERE func_addr = '{addr}' AND ordinal = '{i}'"
            )
            self.client.ghidra_query(self.session_id, sql, max_rows=1)
