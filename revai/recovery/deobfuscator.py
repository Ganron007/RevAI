"""
deobfuscator.py — agentic deobfuscation dispatcher for function recovery.

Reuses existing v3 components:
  * cff_deflatten.py (GhidraScript via subprocess)
  * invoke_z3_or_angr.py (Z3/angr wrappers)

This module flags functions that look obfuscated and records which pass ran.
It does NOT attempt full deobfuscation inside the recovery pipeline; instead it
produces an 'obfuscation_flags' object that the context builder includes in the
LLM prompt and that the orchestrator records in function_recovery.json.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

CFF_DEFLATTEN_PY = os.environ.get(
    "CFF_DEFLATTEN_PY", "/opt/revai/cff-deflatten/cff_deflatten.py"
)
CFF_DETECTOR_LOG = Path("/opt/samples/logs/cff-detector/cff_detector.log")


class DeobfuscatorPass:
    """Lightweight per-function obfuscation triage."""

    def __init__(self, sample_path: str, cff_candidates: list[dict] | None = None):
        self.sample_path = sample_path
        self.cff_candidates = cff_candidates or self._load_cff_candidates()
        self.cff_addrs: set[str] = set()
        for cand in self.cff_candidates:
            entry = cand.get("function_entry") or ""
            if entry:
                try:
                    self.cff_addrs.add(str(int(entry, 0)))
                except ValueError:
                    pass

    @classmethod
    def _load_cff_candidates(cls) -> list[dict]:
        """Load prior cff_deflatten output from the detector log if available."""
        if not CFF_DETECTOR_LOG.exists():
            return []
        out = []
        for line in CFF_DETECTOR_LOG.read_text().splitlines():
            if not line.startswith("function="):
                continue
            kv = {}
            for tok in line.split():
                k, _, v = tok.partition("=")
                kv[k] = v
            out.append(kv)
        return out

    def analyze(self, func: dict, pseudocode: str | None) -> dict:
        addr = str(int(func["address"])) if func.get("address") is not None else ""
        flags: dict[str, Any] = {
            "is_cff_dispatcher": addr in self.cff_addrs,
            "bogus_flow_score": self._bogus_flow_score(pseudocode or ""),
            "string_encryption_score": self._string_encryption_score(pseudocode or ""),
            "vm_stub_hint": self._vm_stub_hint(pseudocode or ""),
        }
        flags["needs_deobfuscation"] = (
            flags["is_cff_dispatcher"]
            or flags["bogus_flow_score"] >= 0.6
            or flags["string_encryption_score"] >= 0.6
            or flags["vm_stub_hint"]
        )
        return flags

    @staticmethod
    def _bogus_flow_score(text: str) -> float:
        """Heuristic for opaque predicates and dead branches."""
        if not text:
            return 0.0
        score = 0.0
        # Lots of bitwise on condition temps
        if text.count("if (") > 8:
            score += 0.2
        # Many `while( true )` loops with state vars
        if text.count("while( true )") > 0 or "while (true)" in text:
            score += 0.2
        # Opaque predicate patterns: x * x >= 0, (x|1) > 0, etc.
        opaque = len(re.findall(r"\(\s*[\w_]+\s*[\*\|\^\+\-]\s*[\w_]+\s*[\)<>=]", text))
        if opaque > 3:
            score += min(0.3, opaque * 0.05)
        # Heavy constant arithmetic on condition temps
        if text.count("CONCAT") > 2 or text.count("SUB") > 5:
            score += 0.2
        return min(score, 1.0)

    @staticmethod
    def _string_encryption_score(text: str) -> float:
        """Heuristic for string-decoding loops."""
        if not text:
            return 0.0
        score = 0.0
        # XOR loop on byte array
        if re.search(r"\^\s*0x[0-9a-fA-F]{1,2}", text):
            score += 0.3
        # Byte array indexing in a loop
        if len(re.findall(r"\[\s*[\w_]+\s*\]", text)) > 8:
            score += 0.2
        # Rot/add/sub small constants
        if len(re.findall(r"[\+\-]\s*0x[0-9a-fA-F]{1,2}\b", text)) > 5:
            score += 0.2
        # Strings referenced inside look like garbage/high-entropy
        if re.search(r"\\x[0-9a-fA-F]{2}", text):
            score += 0.2
        return min(score, 1.0)

    @staticmethod
    def _vm_stub_hint(text: str) -> bool:
        """Detect bytecode-dispatch stubs."""
        if not text:
            return False
        patterns = [
            "vm", "bytecode", "dispatcher", "handler_table", "opcode",
            "instruction_pointer", "program_counter", "VM_",
        ]
        low = text.lower()
        return any(p in low for p in patterns) and "switch" in low

    def run_cff_deflatten(self, timeout: int = 120) -> dict:
        """Run cff_deflatten.py on the whole binary and return JSON."""
        if not Path(CFF_DEFLATTEN_PY).is_file():
            return {"error": f"cff_deflatten.py not found at {CFF_DEFLATTEN_PY}"}
        if not Path(self.sample_path).is_file():
            return {"error": f"sample not found: {self.sample_path}"}
        try:
            proc = subprocess.run(
                [sys.executable, CFF_DEFLATTEN_PY, "--input", self.sample_path, "--json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
                return json.loads(proc.stdout)
            return {"error": proc.stderr[:300] or proc.stdout[:300], "rc": proc.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "cff_deflatten timed out", "timeout": timeout}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    def run_z3_or_angr(self, claim_type: str, timeout: int = 30, **kwargs: Any) -> dict:
        """Invoke the wrapper via `python -c` so recovery does not import it."""
        wrapper_path = "/opt/revai/deobfuscation/invoke_z3_or_angr.py"
        if not Path(wrapper_path).is_file():
            return {"error": f"invoke_z3_or_angr.py not found at {wrapper_path}"}

        claim_text = kwargs.get("claim_text", "")
        find_addr = kwargs.get("find_addr")
        avoid = kwargs.get("avoid_addrs", [])
        inline = f'''
import json, sys
sys.path.insert(0, "/opt/revai/deobfuscation")
import invoke_z3_or_angr as iza
iza.ENABLE_DEOBFUSCATION_PASS_DEFAULT = True
r = iza.invoke_z3_or_angr(
    {claim_type!r},
    {self.sample_path!r},
    timeout={timeout},
    claim_text={claim_text!r} or None,
    find_addr={find_addr!r},
    avoid_addrs={avoid!r},
)
print(json.dumps(r, default=str))
'''
        try:
            proc = subprocess.run(
                [sys.executable, "-c", inline],
                capture_output=True, text=True, timeout=timeout + 30,
            )
            last = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
            if last.startswith("{"):
                return json.loads(last)
            return {"error": proc.stderr[:300] or last[:300], "rc": proc.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "z3/angr wrapper timed out", "timeout": timeout}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
