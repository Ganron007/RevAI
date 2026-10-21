"""Claim-level report schema and deterministic Markdown renderer.

The report writer returns observations, assessments, recommendations, tables and
code blocks as structured JSON. The renderer is the only producer of the
published Markdown, so an observation or table row cannot reach the report
without its source, query/table and row/rule locator.

Assessment, recommendation and note blocks are explicitly non-factual. They are
rendered with a fixed marker and the citation-coverage gate skips those marked
lines; the claimed-indicator checker still scans their text. This is the
structural distinction the free-form report contract could not enforce.
"""
from __future__ import annotations

import re
from typing import Any

from citation_syntax import strip_citation_annotations

BLOCK_KINDS = (
    "observation",
    "assessment",
    "recommendation",
    "table",
    "code",
    "note",
)
CITATION_FIELDS = ("source", "query_or_table", "row_or_rule")
NON_FACTUAL_KINDS = ("assessment", "recommendation", "note")

ASSESSMENT_MARKER = "**[Assessment]**"
RECOMMENDATION_MARKER = "**[Recommendation]**"
NOTE_MARKER = "**[Note]**"
_NON_FACTUAL_MARKER_RE = re.compile(
    r"^\s*(?:[-*+]\s+|>\s*)?\*\*\[(?:Assessment|Recommendation|Note)\]\*\*",
    re.IGNORECASE,
)
_HEADING_PREFIX_RE = re.compile(r"^#+\s*")
_EVIDENCE_COLUMN_NAMES = {"evidence", "source", "citation", "sources"}
_SAFE_FENCE_LANG_RE = re.compile(r"[^A-Za-z0-9_+.#-]+")


class ReportSchemaError(ValueError):
    """A structured report failed validation before rendering."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors[:20]))


def is_non_factual_markdown_line(line: str) -> bool:
    """Whether a rendered line is an explicitly labelled non-factual block."""
    return bool(_NON_FACTUAL_MARKER_RE.match(line or ""))


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _balanced(value: str) -> bool:
    """Whether a citation value has balanced brackets.

    Unbalanced brackets would make the citation parser treat the rest of the
    report as locator text, so the schema rejects them before rendering.
    """
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for char in value:
        if char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                return False
    return not stack


def _citation_fields(block: dict[str, Any], where: str,
                     errors: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for field in CITATION_FIELDS:
        value = _text(block.get(field))
        if not value:
            errors.append(f"{where}: {field} must be a non-empty string")
            continue
        if not _balanced(value):
            errors.append(f"{where}: {field} has unbalanced brackets")
            continue
        out[field] = value
    return out


def validate_report_document(document: Any) -> list[str]:
    """Return every schema violation in a report document, or an empty list."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document must be an object"]
    sections = document.get("sections")
    if not isinstance(sections, list) or not sections:
        return ["document.sections must be a non-empty array"]
    for si, section in enumerate(sections):
        where = f"sections[{si}]"
        if not isinstance(section, dict):
            errors.append(f"{where}: section must be an object")
            continue
        heading = _text(section.get("heading"))
        if not heading:
            errors.append(f"{where}: heading must be a non-empty string")
        if "\n" in heading or "\r" in heading:
            errors.append(f"{where}: heading must be a single line")
        blocks = section.get("blocks")
        if not isinstance(blocks, list) or not blocks:
            errors.append(f"{where}: blocks must be a non-empty array")
            continue
        for bi, block in enumerate(blocks):
            bwhere = f"{where}.blocks[{bi}]"
            if not isinstance(block, dict):
                errors.append(f"{bwhere}: block must be an object")
                continue
            kind = _text(block.get("kind")).lower()
            if kind not in BLOCK_KINDS:
                errors.append(f"{bwhere}: kind must be one of {', '.join(BLOCK_KINDS)}")
                continue
            if kind == "observation":
                text = _text(block.get("text"))
                if not text:
                    errors.append(f"{bwhere}: observation text must be non-empty")
                elif not strip_citation_annotations(text).strip():
                    errors.append(f"{bwhere}: observation text is only a citation")
                _citation_fields(block, bwhere, errors)
            elif kind in ("assessment", "recommendation", "note"):
                if not _text(block.get("text")):
                    errors.append(f"{bwhere}: {kind} text must be non-empty")
            elif kind == "code":
                if not _text(block.get("text")):
                    errors.append(f"{bwhere}: code text must be non-empty")
            elif kind == "table":
                if "intro" in block:
                    errors.append(
                        f"{bwhere}: table intro is not supported; write it as an "
                        "observation block before the table"
                    )
                columns = block.get("columns")
                if not isinstance(columns, list) or not columns:
                    errors.append(f"{bwhere}: table columns must be a non-empty array")
                    continue
                clean_columns = [_text(column) for column in columns]
                if any(not column for column in clean_columns):
                    errors.append(f"{bwhere}: table column names must be non-empty")
                if any(column.lower() in _EVIDENCE_COLUMN_NAMES
                       for column in clean_columns):
                    errors.append(
                        f"{bwhere}: do not add an Evidence/Source column; "
                        "the renderer adds it"
                    )
                rows = block.get("rows")
                if not isinstance(rows, list) or not rows:
                    errors.append(f"{bwhere}: table rows must be a non-empty array")
                    continue
                for ri, row in enumerate(rows):
                    rwhere = f"{bwhere}.rows[{ri}]"
                    if not isinstance(row, dict):
                        errors.append(f"{rwhere}: row must be an object")
                        continue
                    cells = row.get("cells")
                    if not isinstance(cells, list) or len(cells) != len(clean_columns):
                        errors.append(
                            f"{rwhere}: cells must contain exactly "
                            f"{len(clean_columns)} values"
                        )
                    _citation_fields(row, rwhere, errors)
    return errors


def _split_observation_sentences(text: str) -> list[str]:
    """Split one observation into the sentences the gate will check.

    The renderer puts the citation after each sentence, so a multi-sentence
    observation remains covered. The gate's splitter is reused when available
    because it understands citations; the local fallback is deliberately small.
    """
    try:
        from report_quality import _split_report_sentences  # lazy, avoids a cycle

        parts = _split_report_sentences(text)
        if parts:
            return parts
    except Exception:
        pass
    return [part for part in re.split(r"(?<=[.!?])\s+", text) if part.strip()]


def _citation_text(fields: dict[str, str]) -> str:
    return (
        f"(source: {fields['source']}, "
        f"query_or_table: {fields['query_or_table']}, "
        f"row_or_rule: {fields['row_or_rule']})"
    )


def _cell(value: Any) -> str:
    text = _text(value)
    text = text.replace("|", "&#124;")
    return re.sub(r"\r?\n", "<br>", text)


def _fence(text: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)),
                  default=0)
    return "`" * max(3, longest + 1)


def _render_block(block: dict[str, Any]) -> str:
    kind = _text(block.get("kind")).lower()
    if kind == "observation":
        text = strip_citation_annotations(_text(block.get("text"))).strip()
        citation = _citation_text(block)
        sentences = _split_observation_sentences(text)
        if not sentences:
            sentences = [text] if text else []
        return "- " + " ".join(
            f"{sentence.rstrip()} {citation}" for sentence in sentences
        )
    if kind == "assessment":
        text = re.sub(r"\s+", " ", _text(block.get("text")))
        return f"- {ASSESSMENT_MARKER} {text}"
    if kind == "recommendation":
        text = re.sub(r"\s+", " ", _text(block.get("text")))
        return f"- {RECOMMENDATION_MARKER} {text}"
    if kind == "note":
        text = re.sub(r"\s+", " ", _text(block.get("text")))
        return f"- {NOTE_MARKER} {text}"
    if kind == "code":
        language = _SAFE_FENCE_LANG_RE.sub("", _text(block.get("language")))
        fence = _fence(_text(block.get("text")))
        header = f"{fence}{language}" if language else fence
        return f"{header}\n{_text(block.get('text'))}\n{fence}"
    if kind == "table":
        columns = [_cell(column) for column in block.get("columns") or []]
        lines: list[str] = []
        lines.append("| " + " | ".join(columns + ["Evidence"]) + " |")
        lines.append("| " + " | ".join(["---"] * (len(columns) + 1)) + " |")
        for row in block.get("rows") or []:
            cells = [_cell(cell) for cell in (row.get("cells") or [])]
            citation = _cell(_citation_text(row))
            lines.append("| " + " | ".join(cells + [citation]) + " |")
        return "\n".join(lines)
    return ""


def render_report_document(
    document: dict[str, Any],
    *,
    heading_level: int = 2,
    section_only: bool = True,
    include_title: bool = False,
) -> str:
    """Render a validated report document to Markdown.

    `section_only` is the normal mode for the master/technical writers: each
    response carries the requested sections and no document title. The heading
    level is 1 for the master report (its sections are level-1 headings) and 2
    for the technical report and section publisher.
    """
    errors = validate_report_document(document)
    if errors:
        raise ReportSchemaError(errors)
    level = max(1, min(6, int(heading_level)))
    prefix = "#" * level
    parts: list[str] = []
    if include_title and not section_only:
        title = _text(document.get("title"))
        if title:
            parts.append(f"# {title}")
    for section in document.get("sections") or []:
        heading = _HEADING_PREFIX_RE.sub("", _text(section.get("heading")))
        parts.append(f"{prefix} {heading}")
        for block in section.get("blocks") or []:
            rendered = _render_block(block)
            if rendered:
                parts.append(rendered)
    return ("\n\n".join(parts).strip() + "\n") if parts else ""


def render_section(section: dict[str, Any], *, heading_level: int = 2) -> str:
    """Render one section object (used by the section publisher)."""
    return render_report_document(
        {"sections": [section]},
        heading_level=heading_level,
        section_only=True,
    )


def report_writer_tool_schema() -> dict[str, Any]:
    """The OpenAI-compatible function schema for `submit_report`."""
    citation_properties = {
        "source": {"type": "string"},
        "query_or_table": {"type": "string"},
        "row_or_rule": {"type": "string"},
    }
    row_schema = {
        "type": "object",
        "properties": {
            "cells": {"type": "array", "items": {"type": "string"}},
            **citation_properties,
        },
        "required": ["cells", "source", "query_or_table", "row_or_rule"],
        "additionalProperties": False,
    }
    block_schema = {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": list(BLOCK_KINDS)},
            "text": {"type": "string"},
            "source": {"type": "string"},
            "query_or_table": {"type": "string"},
            "row_or_rule": {"type": "string"},
            "language": {"type": "string"},
            "columns": {"type": "array", "items": {"type": "string"}},
            "rows": {"type": "array", "items": row_schema},
        },
        "required": ["kind"],
        "additionalProperties": False,
    }
    section_schema = {
        "type": "object",
        "properties": {
            "heading": {"type": "string"},
            "blocks": {"type": "array", "items": block_schema},
        },
        "required": ["heading", "blocks"],
        "additionalProperties": False,
    }
    return {
        "type": "function",
        "function": {
            "name": "submit_report",
            "description": (
                "Return the report as claim-level sections. Every observation "
                "and table row MUST carry source, query_or_table and row_or_rule. "
                "Use assessment/recommendation blocks only for analysis and "
                "actions; never put a factual claim in them."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "sections": {
                        "type": "array",
                        "minItems": 1,
                        "items": section_schema,
                    },
                },
                "required": ["sections"],
                "additionalProperties": False,
            },
        },
    }


STRUCTURED_REPORT_CONTRACT = """
## CLAIM-LEVEL REPORT SCHEMA (mandatory)

Call `submit_report` exactly once and return `sections`, not Markdown. Do not put
the report in message text.

Each section is `{"heading": "<exact checklist heading>", "blocks": [...]}`.
Each block has a `kind`:

- `observation` — one or more factual sentences plus `source`,
  `query_or_table`, `row_or_rule`. All three citation fields are mandatory. The
  renderer appends the citation to every sentence. Do not write the citation in
  `text` yourself.
- `assessment` — interpretation, judgement, or limitation. No citation is
  required, and the text is explicitly marked as non-factual. Use this for
  "why it matters", "likely", "we assess", and negative findings. Never put an
  observed fact here.
- `recommendation` — an action or disposition. No citation is required.
- `table` — `columns` (do not include an Evidence/Source column; the renderer
  adds it) and `rows` (each row is `{"cells": [...], "source": "...",
  "query_or_table": "...", "row_or_rule": "..."}`). Put any table
  introduction in a preceding `observation` block; table `intro` is rejected
  because it would be uncited prose.
- `code` — a fenced code/evidence block. Optional `language`.
- `note` — methodology or a limitation, explicitly non-factual.

Rules:
1. Every factual statement is an `observation`; every table row is a claim and
   needs its own citation. Do not use one citation for several observations.
2. `source` is the original observing tool; `query_or_table` is the exact
   run-bound artifact path; `row_or_rule` is the exact JSONPath, address, rule
   or row. Never cite LLM summaries, earlier report prose, or verdict prose.
3. Assessment and recommendation blocks must not introduce a new indicator,
   observed behaviour, address, hash, path or domain. Put the observation in an
   `observation` block and interpret it in an `assessment` block.
4. Use the exact section headings requested in the checklist. ASCII apostrophe
   only. Use `## 11. What We Don't Know`, not a curly apostrophe.
5. If a fact cannot be tied to one source row, omit it or state the limitation
   in an `assessment`/`note` block. Never invent a locator.
""".strip()
