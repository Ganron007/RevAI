"""ELF / Mach-O parsing — planned (milestone 2).

The CLI reports these formats as recognized-but-unparsed until implemented.
Interface mirrors formats.pe: a `parse_<fmt>(path) -> obj` with a `to_dict()`.
"""

from __future__ import annotations


class FormatNotImplemented(NotImplementedError):
    pass
