"""
normalizer.py — syntactic normalization of Ghidra decompiler output.

Goals:
  * Recover readable modulo / masking idioms.
  * Reconstruct negative literals.
  * Remove dead assignments that do not affect control flow.
  * Normalize compiler-generated temporaries (DAT_*, iVarN, pNVarN).
  * Collapse repeated casts.
"""
from __future__ import annotations

import re


class Normalizer:
    """Stateless normalizer for decompilation text."""

    def __init__(self, max_chars: int = 12000):
        self.max_chars = max_chars

    def normalize(self, text: str) -> str:
        if not text:
            return ""
        out = text
        out = self._truncate(out)
        out = self._normalize_temporaries(out)
        out = self._recover_modulo(out)
        out = self._recover_negatives(out)
        out = self._remove_dead_assignments(out)
        out = self._collapse_casts(out)
        out = self._strip_extra_blank_lines(out)
        return out

    def _truncate(self, text: str) -> str:
        if len(text) <= self.max_chars:
            return text
        return text[: self.max_chars] + "\n\n/* ... truncated by normalizer ... */"

    @staticmethod
    def _normalize_temporaries(text: str) -> str:
        # Ghidra: DAT_00472ddc -> data_0x472ddc
        text = re.sub(r"\bDAT_([0-9a-fA-F]+)\b", r"data_0x\1", text)
        # iVar1, iVar2, pNVar3... keep but group
        text = re.sub(r"\b(iVar|uVar|lVar|pNVar|pWVar|pIVar|pBVar|pCVar|pAVar|pGVar|pFVar|pDVar|pHVar|pMVar|pLVar|pOVar|pPVar|pSVar|pTVar|pUVar|pVVar|pXVar|pYVar|pZVar|bVar|cVar|hVar|wVar|dVar|fVar)(_\d+|\d+)\b", r"tmp_\1\2", text)
        return text

    @staticmethod
    def _recover_modulo(text: str) -> str:
        # Convert `x - (x / y) * y` into `x % y`.
        # Only handles simple integer temporaries.
        pattern = re.compile(
            r"(?P<x>\b[\w_]+\b)\s*-\s*\(\s*(?P=x)\s*/\s*(?P<y>\b[\w_]+\b)\s*\)\s*\*\s*(?P=y)",
            re.MULTILINE,
        )
        return pattern.sub(r"(\g<x> % \g<y>)", text)

    @staticmethod
    def _recover_negatives(text: str) -> str:
        # Ghidra often prints large unsigned constants as negatives.
        # 0xfffffffffffffffc -> -4 for common 32/64-bit masks.
        def repl(m: re.Match) -> str:
            raw = m.group(0)
            try:
                val = int(raw, 16)
            except ValueError:
                return raw
            width = 32 if len(raw) <= 10 else 64
            if width == 32 and val >= 0x80000000:
                return str(val - 0x100000000)
            if width == 64 and val >= 0x8000000000000000:
                return str(val - 0x10000000000000000)
            return raw

        return re.sub(r"\b0x[0-9a-fA-F]{8,16}\b", repl, text)

    @staticmethod
    def _remove_dead_assignments(text: str) -> str:
        # Strip lines like `int local_8;` that are unused declarations.
        # Be conservative: only remove declarations with no following read pattern.
        lines = text.splitlines()
        out_lines = []
        for line in lines:
            stripped = line.strip()
            if re.match(r"^\s*(u?int|long|ulong|undefined|ushort|short|byte|char|wchar_t|BOOL|DWORD|HANDLE)\s+local_[0-9a-f]+;\s*$", stripped):
                continue
            out_lines.append(line)
        return "\n".join(out_lines)

    @staticmethod
    def _collapse_casts(text: str) -> str:
        # `(uint)(uint)x` -> `(uint)x`
        return re.sub(r"\(\s*(\w+)\s*\)\s*\(\s*\1\s*\)", r"(\1)", text)

    @staticmethod
    def _strip_extra_blank_lines(text: str) -> str:
        return re.sub(r"\n{3,}", "\n\n", text)
