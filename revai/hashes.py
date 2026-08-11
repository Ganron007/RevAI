"""Hash computation incl. imphash (pefile-style, our own implementation)."""

from __future__ import annotations

import hashlib
from typing import Any


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def imphash(imports: list[dict[str, Any]]) -> str:
    """PEFile-style imphash: sorted dll.function pairs, comma-joined, md5.

    Accepts the imports structure produced by formats.pe (list of
    {"dll": str, "functions": [str, ...]}).
    """
    pairs: list[str] = []
    for imp in imports:
        dll = (imp.get("dll") or "").lower().replace(".dll", "")
        funcs = imp.get("functions") or []
        for fn in funcs:
            if fn.startswith("ordinal_"):
                continue
            pairs.append(f"{dll}.{fn.lower()}")
    return hashlib.md5(",".join(sorted(pairs)).encode("utf-8")).hexdigest()
