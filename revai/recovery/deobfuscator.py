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

#: How much of a captured stream to keep when there is no useful reason in it.
_STDERR_CLIP = 300

#: Traceback frames, when a reason cannot be found. Kept so the reader can see
#: that the failure was an exception rather than a silent empty return.
_TB_FRAME_RE = re.compile(r'^\s*File "', re.MULTILINE)


def _clip(text: str | None, limit: int = _STDERR_CLIP) -> str:
    """Bounded fallback text. Empty in, empty out -- never the string 'None'."""
    return (text or "").strip()[:limit]


def _reason_from_stderr(stderr: str | None) -> str:
    """The one line that says what actually went wrong.

    A Python traceback puts the cause on its LAST line, so a leading clip keeps
    `Traceback (most recent call last):` plus frames and discards the cause.
    That clip is the old behaviour.

    To be accurate about what it cost: it did NOT cost us this bug. All nine
    recorded `deobfuscation.error` values are 258 chars and every one of them
    ends in `ModuleNotFoundError: No module named 'pyghidra'` -- the cause was
    recorded in plain text the whole time. What actually happened is worse for
    the process: the answer sat in the artifact on every run and nobody read
    it, because nothing in the pipeline flagged the leg as dead. Hence
    `deobfuscation_status()` and the advisory, which are the real fix.

    The clip is kept because the truncation is latent, not absent: any tool
    whose traceback runs past 300 chars of frames loses the cause entirely, and
    the deeper the stack the more certain that is. Cheap to get right.

    Returns the cause line when there is one, otherwise the deepest frame (so
    the location survives), otherwise a bounded clip of whatever was there.
    """
    text = (stderr or "").strip()
    if not text:
        return ""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""

    # Real exception line: "SomeError: detail" (not a bare class name).
    for ln in reversed(lines):
        if ln.startswith(("Traceback (", '  File "', "During handling", "The above")):
            continue
        if _TB_FRAME_RE.match(ln):
            continue
        if ":" in ln:
            return _clip(ln, 400)
        return _clip(ln, 400)

    # Only frames: keep the deepest one so the location is not lost.
    frames = [ln for ln in lines if _TB_FRAME_RE.match(ln)]
    if frames:
        return _clip(f"exception in {_clip(frames[-1].strip(), 260)}", 400)
    return _clip(lines[-1], 400)


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
        """Run cff_deflatten.py on the whole binary and return JSON.

        Fail-open by contract -- deobfuscation is a depth aid, and the caller
        has already recorded the leg as unavailable rather than failing the
        stage. The `unavailable` key says which of the three ways this went
        wrong it was, so the artifact is not just "it errored".
        """
        if not Path(CFF_DEFLATTEN_PY).is_file():
            return {"error": f"cff_deflatten.py not found at {CFF_DEFLATTEN_PY}",
                    "unavailable": "missing_tool"}
        if not Path(self.sample_path).is_file():
            return {"error": f"sample not found: {self.sample_path}",
                    "unavailable": "missing_sample"}
        try:
            proc = subprocess.run(
                [sys.executable, CFF_DEFLATTEN_PY, "--input", self.sample_path, "--json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
                return json.loads(proc.stdout)
            return {"error": _reason_from_stderr(proc.stderr) or _clip(proc.stdout),
                    "rc": proc.returncode,
                    **({"unavailable": "tool_failed"}
                       if not proc.stdout.strip().startswith("{") else {})}
        except subprocess.TimeoutExpired:
            return {"error": f"cff_deflatten timed out after {timeout}s",
                    "timeout": timeout, "unavailable": "timeout"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}",
                    "unavailable": "dispatch_failed"}

    def deobfuscation_status(self) -> dict:
        """Whether the deobfuscation leg can run at all, before spending 120s.

        The leg has been a silent no-op on every run since 2026-09-28:
        cff_deflatten.py imports pyghidra, which is not importable from the
        interpreter recovery uses. The cause was recorded correctly every time
        (`ModuleNotFoundError: No module named 'pyghidra'`, 258 chars, nine
        artifacts checked) -- nothing was hidden. What was missing is any
        signal that the leg had not contributed: the stage exited rc=0, the
        stage-level gates saw a well-formed `deobfuscation.error` field, and no
        downstream consumer asked whether control flow had been flattened.

        So this probe exists to convert "it errored, we moved on" into a stated
        capability, and to avoid spending 120 s to learn something a 0.2 s
        import check already knows.
        """
        if not Path(CFF_DEFLATTEN_PY).is_file():
            return {"available": False, "reason": "cff_deflatten.py missing"}
        try:
            proc = subprocess.run(
                [sys.executable, "-c", "import pyghidra"],
                capture_output=True, text=True, timeout=30)
        except Exception as exc:
            return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}
        if proc.returncode == 0:
            return {"available": True}
        return {"available": False,
                "reason": _reason_from_stderr(proc.stderr)
                          or "pyghidra import failed"}

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
