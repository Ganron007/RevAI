"""Whole-file entropy profile with packed-region flags."""

from __future__ import annotations

import math
from typing import Any

from .sections import shannon_entropy

BLOCK = 4096


def entropy_map(data: bytes) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    high = 0
    total = max(1, (len(data) + BLOCK - 1) // BLOCK)
    for off in range(0, len(data), BLOCK):
        e = shannon_entropy(data[off:off + BLOCK])
        if e >= 7.0:
            high += 1
        blocks.append({"offset": off, "size": min(BLOCK, len(data) - off),
                       "entropy": round(e, 3)})
    return {
        "block_size": BLOCK,
        "blocks": blocks,
        "high_entropy_blocks": high,
        "high_entropy_ratio": round(high / total, 4),
        "packed_likely": high / total >= 0.5,
    }
