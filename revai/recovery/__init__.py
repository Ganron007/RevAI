"""
CADRE-RevEng v4 agentic function-recovery library.

This package implements the stages described in
Tools/v4-deploy/v4-agentic-recovery-addendum.md:

    call_graph      - build call graph and bottom-up work ordering
    signatures      - signature DB loading and matching
    context_builder - rich per-function prompt context
    normalizer      - syntactic decompiler-output normalization
    deobfuscator    - agentic CFF / bogus-flow / string-encryption pass
    synthesizer     - global name unification + struct recovery
    ghidra_writeback- apply recovered symbols to the Ghidra DB
"""

from __future__ import annotations

__version__ = "1.0.0"

from .call_graph import CallGraph, build_bottom_up_order
from .context_builder import ContextBuilder
from .deobfuscator import DeobfuscatorPass
from .ghidra_writeback import GhidraWriteback
from .normalizer import Normalizer
from .signatures import SignatureDB
from .synthesizer import Synthesizer

__all__ = [
    "CallGraph",
    "build_bottom_up_order",
    "ContextBuilder",
    "DeobfuscatorPass",
    "GhidraWriteback",
    "Normalizer",
    "SignatureDB",
    "Synthesizer",
]
