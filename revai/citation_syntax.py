"""Parse RevAI's inline evidence citations without treating locator text as syntax.

Citation values are analyst evidence locators. They may contain commas and
balanced parentheses, so a delimiter-free regular expression cannot safely
decide where a field or citation ends.
"""
from __future__ import annotations

import re
from typing import Any


_OPEN_TO_CLOSE = {"(": ")", "{": "}", "[": "]"}
_CITATION_START = re.compile(r"[({\[]\s*source\s*:", re.IGNORECASE)
_FIELD = re.compile(r"^\s*(source|query_or_table|row_or_rule|why)\s*:\s*(.*)$",
                    re.IGNORECASE | re.DOTALL)


def _opens_quote(text: str, index: int, annotation_start: int) -> bool:
    """Recognize quoted field values while leaving ordinary apostrophes alone."""
    previous = text[index - 1] if index > annotation_start else " "
    return previous.isspace() or previous in ":=([{,"


def _annotation_end(text: str, start: int) -> int | None:
    """Return the exclusive end of a balanced source annotation."""
    first = text[start]
    if first not in _OPEN_TO_CLOSE:
        return None
    stack = [_OPEN_TO_CLOSE[first]]
    quote: str | None = None
    escaped = False
    for index in range(start + 1, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'" and _opens_quote(text, index, start):
            quote = char
        elif char in _OPEN_TO_CLOSE:
            stack.append(_OPEN_TO_CLOSE[char])
        elif char in ")]}":
            if not stack or char != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return index + 1
    return None


def _split_fields(body: str) -> dict[str, str]:
    """Split citation fields at top-level commas, preserving commas in values."""
    segments: list[str] = []
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    start = 0
    for index, char in enumerate(body):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'" and _opens_quote(body, index, -1):
            quote = char
        elif char in _OPEN_TO_CLOSE:
            stack.append(_OPEN_TO_CLOSE[char])
        elif char in ")]}":
            if stack and char == stack[-1]:
                stack.pop()
        elif char == "," and not stack:
            segments.append(body[start:index].strip())
            start = index + 1
    segments.append(body[start:].strip())

    fields: dict[str, str] = {}
    current: str | None = None
    for segment in segments:
        match = _FIELD.match(segment)
        if match:
            current = match.group(1).lower()
            fields[current] = match.group(2).strip()
        elif current and segment:
            # Locator values often list several observed rows without quoting
            # them. Keep those comma-separated values with their field.
            fields[current] = f"{fields[current]}, {segment}".strip(", ")
    return fields


def parse_citation_annotations(text: str) -> list[dict[str, Any]]:
    """Return balanced ``source:`` annotations and their parsed fields.

    A source-only annotation is still returned; callers decide whether a row
    locator is required for their gate.
    """
    if not text:
        return []
    out: list[dict[str, Any]] = []
    occupied_until = -1
    for match in _CITATION_START.finditer(text):
        start = match.start()
        if start < occupied_until:
            continue
        end = _annotation_end(text, start)
        if end is None:
            continue
        body = text[start + 1:end - 1]
        fields = _split_fields(body)
        if fields.get("source"):
            out.append({"start": start, "end": end, **fields})
            occupied_until = end
    # Some report responses place the same explicit citation fields in a
    # dedicated Markdown table cell but omit the surrounding parentheses,
    # e.g. `| source: procmon, query_or_table: procmon.csv, row_or_rule: 42 |`.
    # Treat that cell as citation syntax so it still goes through source
    # resolution and semantic claim review. Do not accept bare source labels in
    # prose or partial table metadata as evidence.
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            cursor = 0
            for cell in line.split("|"):
                cell_start = line.find(cell, cursor)
                cursor = cell_start + len(cell)
                leading = len(cell) - len(cell.lstrip())
                value = cell.strip()
                start = offset + cell_start + leading
                if not value.lower().startswith("source:"):
                    continue
                fields = _split_fields(value)
                if not (fields.get("source") and fields.get("query_or_table")
                        and fields.get("row_or_rule")):
                    continue
                end = start + len(value)
                if any(start < item["end"] and end > item["start"] for item in out):
                    continue
                out.append({"start": start, "end": end, **fields})
                occupied_until = max(occupied_until, end)
        offset += len(line)
    out.sort(key=lambda item: (item["start"], item["end"]))
    return out


def strip_citation_annotations(text: str) -> str:
    """Remove citation metadata before prose-only semantic checks."""
    citations = parse_citation_annotations(text)
    for citation in reversed(citations):
        text = text[:citation["start"]] + " " + text[citation["end"]:]
    return text


def has_citation_locator(text: str) -> bool:
    """Whether the text contains a source citation with a non-empty row locator."""
    return any(str(citation.get("row_or_rule") or "").strip()
               for citation in parse_citation_annotations(text))
