"""Parse RevAI's inline evidence citations without treating locator text as syntax.

Citation values are analyst evidence locators. They may contain commas and
balanced parentheses, so a delimiter-free regular expression cannot safely
decide where a field or citation ends.
"""
from __future__ import annotations

import re
from typing import Any


_OPEN_TO_CLOSE = {"(": ")", "{": "}", "[": "]"}
_SOURCE_FIELD = re.compile(r"(?<![\w])source\s*:", re.IGNORECASE)
_FIELD = re.compile(r"(source|query_or_table|row_or_rule|why)\s*:\s*(.*)$",
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
        match = _FIELD.search(segment)
        if match:
            current = match.group(1).lower()
            fields[current] = match.group(2).strip()
        elif current and segment:
            # Locator values often list several observed rows without quoting
            # them. Keep those comma-separated values with their field.
            fields[current] = f"{fields[current]}, {segment}".strip(", ")
    return fields


def _enclosing_openers(text: str, index: int) -> list[int]:
    """Return opening delimiters that can enclose `index`, nearest first.

    This is the fallback for mismatched nesting. The common case uses
    ``_enclosing_map``, which is linear in the report length; scanning backwards
    from every ``source:`` token made a 360 KB technical report take seconds.
    """
    depth = 0
    out: list[int] = []
    for i in range(index - 1, -1, -1):
        char = text[i]
        if char in ")]}":
            depth += 1
        elif char in _OPEN_TO_CLOSE:
            if depth:
                depth -= 1
            else:
                out.append(i)
    return out


def _enclosing_map(text: str) -> list[int | None]:
    """Map each character position to its nearest unmatched opening delimiter.

    A single forward pass replaces one backwards scan per citation. The map is
    intentionally bracket-only: citation fields may contain quoted text, but a
    bracket inside a quoted locator is rare and the parser validates the body
    before accepting it.
    """
    stack: list[int] = []
    out: list[int | None] = [None] * len(text)
    for index, char in enumerate(text):
        if char in ")]}":
            if stack:
                stack.pop()
        out[index] = stack[-1] if stack else None
        if char in _OPEN_TO_CLOSE:
            stack.append(index)
    return out


def parse_citation_annotations(text: str) -> list[dict[str, Any]]:
    """Return balanced ``source:`` annotations and their parsed fields.

    A source-only annotation is still returned; callers decide whether a row
    locator is required for their gate.
    """
    if not text:
        return []
    out: list[dict[str, Any]] = []
    occupied_until = -1
    enclosing = _enclosing_map(text)
    for match in _SOURCE_FIELD.finditer(text):
        source_pos = match.start()
        if source_pos < occupied_until:
            continue
        start = enclosing[source_pos]
        if start is None or start < occupied_until:
            continue
        end = _annotation_end(text, start)
        fields: dict[str, str] = {}
        if end is not None and end > source_pos:
            fields = _split_fields(text[start + 1:end - 1])
        if fields.get("source"):
            out.append({"start": start, "end": end, **fields})
            occupied_until = end
            continue
        # Mismatched nesting: the nearest opener did not form a valid citation,
        # but a farther opener can still enclose the source (e.g.
        # ``(outer [source: value)``). This path is rare and stays quadratic
        # only for malformed text.
        for alt in _enclosing_openers(text, source_pos):
            if alt >= start or alt < occupied_until:
                continue
            end = _annotation_end(text, alt)
            if end is None or end <= source_pos:
                continue
            fields = _split_fields(text[alt + 1:end - 1])
            if not fields.get("source"):
                continue
            out.append({"start": alt, "end": end, **fields})
            occupied_until = end
            break
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


#: RC-18: a disassembly listing line that leaked OUTSIDE a code fence. Run
#: 65be0144 emitted radare2 output as plain indented lines and the narrative
#: extractor counted every line as an uncited factual claim (12
#: `missing-citation` entries, all listing lines). Two shapes are recognised:
#: a box-drawing prefix (r2's `│ 0x0042419b 60 pushal`, `┌ 37: entry0 ()`),
#: and an address followed by optional byte/ordinal tokens and a mnemonic
#: (`0x0042419b 60 pushal`, objdump's `401000: 60 e0`). The mnemonic list
#: keeps prose like "0x401000 is the entry point" from matching.
_DISASSEMBLY_LISTING_RE = re.compile(
    r"^\s*(?:[\u2500-\u257f]"
    r"|0x[0-9a-fA-F]{4,16}\s+(?:[0-9a-fA-F]{1,8}\s+){0,3}"
    r"(?:push|pop|mov|lea|call|jmp|j[a-z]{1,2}|ret|add|sub|xor|and|or|test|cmp|"
    r"inc|dec|neg|nop|int|shl|shr|sar|imul|mul|div|pushal|pushad|popal|popad|"
    r"leave|enter|loop|endbr(?:64|32)|cdq|cdqe|stos|lods|scas|repe?|repne|hlt|"
    r"out|in|syscall|sysenter|rol|ror|rcl|rcr|shld|shrd|setn?[a-z]|cmov[a-z]{1,3}|"
    r"fld|fst|fnst|movsxd|movzx|movsx|xz|tz|lzcnt|bswap|cpuid|rdtsc|"
    r"xchg|cmpxchg|xadd|bound|iret|icebp)(?:[lqwbz])?\b"
    r"|[0-9a-fA-F]{6,16}:\s+(?:[0-9a-fA-F]{2}\s+){1,8}\S)",
    re.IGNORECASE,
)


def is_disassembly_listing_line(line: str) -> bool:
    """Whether a rendered line is a disassembly/hex listing, not prose."""
    return bool(_DISASSEMBLY_LISTING_RE.match(line or ""))
