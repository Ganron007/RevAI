"""JSON / text rendering for revai-tools output."""

from __future__ import annotations

import json
from typing import Any


def render(data: Any, as_json: bool) -> str:
    if as_json:
        return json.dumps(data, indent=2, default=str)
    return _render_text(data)


def _render_text(data: Any) -> str:
    if isinstance(data, dict):
        lines: list[str] = []
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                lines.append(f"{k}:")
                for item in v:
                    lines.append(f"  {_one_line(item)}")
            elif isinstance(v, dict):
                lines.append(f"{k}:")
                lines.append(_render_text(v).replace("\n", "\n  "))
            else:
                lines.append(f"{k}: {v}")
        return "\n".join(lines)
    return str(data)


def _one_line(item: dict) -> str:
    return " | ".join(f"{k}={v}" for k, v in item.items() if v not in (None, [], {}))
