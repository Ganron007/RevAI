"""radare2 backend adapter for the DisasmBackend interface.

One r2 session per batch: analysis (aaa) is run once, then imports,
functions, and per-target xrefs are collected with `?e` marker lines between
sections so the output stays parseable. Disassembly is batched separately.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .backend import DisasmBackend, Function, Instruction

M1 = "REVAI_MARK_FUNCS"
M2 = "REVAI_MARK_IMPORTS"
M3 = "REVAI_MARK_XREFS"
M4 = "REVAI_MARK_DISASM"

_FUNC_RE = re.compile(r"^0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\S+)$")
_IMPORT_RE = re.compile(r"^\s*\d+\s+0x([0-9a-f]+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)$")
_XREF_RE = re.compile(r"^(\S+)\s+0x([0-9a-f]+)\s+\[([^\]]+)\]")
_INSN_RE = re.compile(r"^\s*0x([0-9a-f]+)\s+([0-9a-f ]+)\s+(\S+)(?:\s+(.*))?$")
_BOX_RE = re.compile(r"^[\s│┌└┐┘├┤─]+")


def _clean(line: str) -> str:
    return _BOX_RE.sub("", line)


class R2Backend(DisasmBackend):

    def __init__(self, binary: str = "/usr/bin/r2", timeout: int = 240) -> None:
        self.binary = binary
        self.timeout = timeout

    def _run(self, path: str, script: str) -> str:
        proc = subprocess.run(
            [self.binary, "-q", "-e", "scr.color=0", "-c", script, path],
            capture_output=True, text=True, timeout=self.timeout,
        )
        return proc.stdout or ""

    def _sections(self, out: str) -> dict[str, str]:
        parts: dict[str, str] = {}
        current = ""
        for line in out.splitlines():
            if line.startswith("REVAI_MARK_"):
                current = line.split()[0]
                parts[current] = ""
            elif current:
                parts[current] += line + "\n"
        return parts

    def analyze(self, path: str, xref_targets: list[int]) -> dict[str, Any]:
        """One session: functions, imports, xrefs for each target."""
        xref_cmds = "; ".join(f"?e {M3}:{t:x}; axt @ 0x{t:x}" for t in xref_targets)
        script = (f"aaa; ?e {M2}; ii; ?e {M1}; afl; {xref_cmds}")
        out = self._run(path, script)
        parts = self._sections(out)

        funcs: list[Function] = []
        for line in (parts.get(M1) or "").splitlines():
            m = _FUNC_RE.match(line.strip())
            if m:
                funcs.append(Function(int(m.group(1), 16), int(m.group(3)),
                                      m.group(4), [], []))

        imports: list[dict[str, Any]] = []
        for line in (parts.get(M2) or "").splitlines():
            m = _IMPORT_RE.match(line.strip())
            if m:
                imports.append({"vaddr": int(m.group(1), 16),
                                "lib": m.group(2), "name": m.group(3)})

        xrefs: dict[int, list[int]] = {}
        cur_target: int | None = None
        for line in out.splitlines():
            if line.startswith(f"{M3}:"):
                cur_target = int(line.split(":")[1], 16)
                xrefs.setdefault(cur_target, [])
                continue
            if cur_target is not None:
                m = _XREF_RE.match(line.strip())
                if m:
                    xrefs[cur_target].append(int(m.group(2), 16))
        return {"functions": funcs, "imports": imports, "xrefs": xrefs}

    def disasm(self, path: str, sites: list[int], window: int = 48) -> dict[int, list[Instruction]]:
        """Linear disasm windows covering the instructions BEFORE each site
        (backward provenance walk needs them)."""
        cmds = "; ".join(
            f"?e {M4}:{s:x}; pd {window} @ 0x{max(0, s - window * 6):x}"
            for s in sites
        )
        out = self._run(path, f"aaa; {cmds}")
        result: dict[int, list[Instruction]] = {}
        cur: int | None = None
        for line in out.splitlines():
            if line.startswith(f"{M4}:"):
                cur = int(line.split(":")[1], 16)
                result[cur] = []
                continue
            if cur is None:
                continue
            m = _INSN_RE.match(_clean(line))
            if m:
                result[cur].append(Instruction(
                    int(m.group(1), 16), 0, m.group(3), m.group(4) or "", b""))
        return result

    def linear_disasm(self, path: str, vaddr: int, count: int = 8) -> list[Instruction]:
        out = self._run(path, f"aaa; pd {count} @ 0x{vaddr:x}")
        insns: list[Instruction] = []
        for line in out.splitlines():
            m = _INSN_RE.match(_clean(line))
            if m:
                insns.append(Instruction(int(m.group(1), 16), 0, m.group(3),
                                         m.group(4) or "", b""))
        return insns

    def functions(self, path: str) -> list[Function]:
        return self.analyze(path, [])["functions"]

    def xrefs(self, path: str, target: int | str) -> list[int]:
        t = int(target, 16) if isinstance(target, str) else target
        return self.analyze(path, [t])["xrefs"].get(t, [])

    def calls(self, path: str, fn: int) -> list[int]:
        out = self._run(path, f"aaa; axt @ 0x{fn:x}")
        calls: list[int] = []
        for line in out.splitlines():
            m = _XREF_RE.match(line.strip())
            if m and "CALL" in m.group(3):
                calls.append(int(m.group(2), 16))
        return calls
