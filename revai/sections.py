"""Per-section entropy + packed-region heuristics."""

from __future__ import annotations

import math
from collections import Counter

ENTROPY_HIGH = 7.0


def shannon_entropy(block: bytes) -> float:
    if not block:
        return 0.0
    n = len(block)
    counts = Counter(block)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def section_entropy(section_raw: bytes) -> float:
    return shannon_entropy(section_raw)


def flag_memory_only(raw_size: int, virtual_size: int) -> bool:
    return raw_size == 0 and virtual_size > 0
