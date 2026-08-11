"""Disassembly backend — engine-agnostic interface.

Milestone 2: implement an adapter over a local linear/call-graph disassembler
(radare2/rizin on the REMnux VM, or a from-scratch linear decoder). The
analysis modules (sinks, audit, paths, xrefs, funcs, dis) depend only on this
interface, never on a specific engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    operands: str
    raw: bytes


@dataclass
class Function:
    address: int
    size: int
    name: str
    call_targets: list[int]
    referenced_from: list[int]


class DisasmBackend(ABC):

    @abstractmethod
    def linear_disasm(self, path: str, vaddr: int, count: int = 8) -> list[Instruction]:
        """Disassemble `count` instructions linearly from vaddr."""

    @abstractmethod
    def functions(self, path: str) -> list[Function]:
        """Recover functions via control-flow analysis."""

    @abstractmethod
    def xrefs(self, path: str, target: int | str) -> list[int]:
        """Addresses referencing a target (address or symbol name)."""

    @abstractmethod
    def calls(self, path: str, fn: int) -> list[int]:
        """Call targets made from within function at `fn`."""

    def analyze(self, path: str, xref_targets: list[int]) -> dict:
        """Batch: functions + imports + xrefs per target (one session)."""
        raise NotImplementedError

    def disasm(self, path: str, sites: list[int], window: int = 24) -> dict[int, list[Instruction]]:
        """Batch linear disasm windows around sites."""
        raise NotImplementedError
