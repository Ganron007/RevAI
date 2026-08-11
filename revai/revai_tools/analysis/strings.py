"""ASCII + UTF-16LE string extraction with offsets."""

from __future__ import annotations

import re

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_strings(data: bytes, min_len: int = 4) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for m in _ASCII_RE.finditer(data):
        if len(m.group()) >= min_len:
            out.append({"offset": m.start(), "encoding": "ascii",
                        "string": m.group().decode("ascii")})
    for m in _UTF16_RE.finditer(data):
        if len(m.group()) // 2 >= min_len:
            out.append({"offset": m.start(), "encoding": "utf16le",
                        "string": m.group().decode("utf-16le")})
    out.sort(key=lambda s: int(s["offset"]))  # type: ignore[arg-type]
    return out
