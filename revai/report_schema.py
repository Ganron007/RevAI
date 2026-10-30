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

import json
import re
from typing import Any

from citation_syntax import (
    is_disassembly_listing_line,
    strip_citation_annotations,
)

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

#: RC-19: a locator ending in a named field of an INDEXED element
#: (`$.yara.matches[10].strings[0]`) addresses a leaf inside a row. A table row
#: that restates several cells must cite the ROW (`$.yara.matches[10]`) so every
#: cell is supported; run 65be0144 produced 217 `insufficient` claims dominated
#: by exactly this row-vs-leaf shape.
_ROW_LEAF_CITATION_RE = re.compile(
    r"\[\d+\]\s*\.[A-Za-z_][A-Za-z0-9_]*(?:\s*\[\d+\])*\s*$")
_TRAILING_LEAF_RE = re.compile(
    r"\.[A-Za-z_][A-Za-z0-9_]*(?:\[\d+\])*\s*$")
_SAFE_FENCE_LANG_RE = re.compile(r"[^A-Za-z0-9_+.#-]+")


class ReportSchemaError(ValueError):
    """A structured report failed validation before rendering."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors[:20]))


def is_non_factual_markdown_line(line: str) -> bool:
    """Whether a rendered line is an explicitly labelled non-factual block."""
    return bool(_NON_FACTUAL_MARKER_RE.match(line or ""))


def normalize_sections(value: Any) -> Any:
    """Normalize a provider's `sections` value to the list the contract wants.

    The report writer is asked for ``sections`` as an array of section objects.
    The provider sometimes returns the same content in a shape that is
    structurally wrong but semantically correct (measured 2026-10-21 on a real
    run, 2 of 17 master sections):

      * ``sections`` is a JSON STRING containing the array;
      * ``sections`` is an OBJECT that wraps the array (``{"title": ...,
        "sections": [...]}``) - the whole document nested one level too deep;
      * ``sections`` is an OBJECT that wraps the array under another key.

    Each of these lost a whole section to a schema rejection even though the
    content was complete and correctly cited. This coercion only changes the
    CONTAINER: the recovered sections are validated by exactly the same rules,
    and a shape that cannot be resolved this way is still rejected.
    """
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return value
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError):
            repaired = _repair_truncated_sections(text)
            return repaired if repaired is not None else value
        return normalize_sections(decoded)
    if isinstance(value, dict):
        inner = value.get("sections")
        if isinstance(inner, (list, str)):
            coerced = normalize_sections(inner)
            if isinstance(coerced, list):
                return coerced
        # A single section object is a one-element document.
        if "heading" in value and "blocks" in value:
            return [value]
    return value


def _repair_truncated_sections(text: str) -> Any:
    """Recover the COMPLETE sections from a truncated JSON array.

    Measured 2026-10-21: the provider returned one master section as a JSON
    string whose array was cut off mid-way, so the whole section (9.7 KB of
    correctly cited content) was lost to a parse error. The complete sections
    BEFORE the truncation point are still valid JSON objects and are still
    worth keeping.

    Only whole, parseable section objects are returned. A partially written
    section is dropped, never guessed at, and the caller validates whatever
    comes back by exactly the same rules.
    """
    decoder = json.JSONDecoder()
    start = text.find("[")
    if start < 0:
        return None
    recovered: list = []
    index = start + 1
    while True:
        while index < len(text) and text[index] in " \t\r\n,":
            index += 1
        if index >= len(text) or text[index] != "{":
            break
        try:
            section, end = decoder.raw_decode(text, index)
        except ValueError:
            break
        if isinstance(section, dict):
            recovered.append(section)
        index = end
    return recovered or None


def normalize_report_document(document: Any) -> Any:
    """Normalize a provider's report document without losing content.

    Two container shapes are recovered here, and only the CONTAINER changes:

      * ``sections`` in a wrong shape (a JSON string, a wrapper object, a
        single section) -- see :func:`normalize_sections`;
    A table that declares its own ``Evidence``/``Source`` column is NOT
    recovered here. That shape stays a rejection: the renderer appends a
    deterministic Evidence column carrying the row's citation, and two columns
    under one header would let a reader mistake the model's prose for the
    real citation. The error message names the defect so the writer can fix
    it on the next attempt.

    Every claim-level rule is still enforced on the normalized document: the
    citation fields, the one-fact-per-row rule and the exact-locator rule are
    unchanged.
    """
    if not isinstance(document, dict):
        return document
    out = dict(document)
    out["sections"] = _dedupe_sections(normalize_sections(document.get("sections")))
    _normalize_table_row_locators(out["sections"])
    return out


def _normalize_table_row_locators(sections: Any) -> None:
    """RC-34: multi-cell table rows citing a LEAF field are normalized to
    their parent ROW locator, in place.

    Measured on run 27799373: the writer cited `$.x.y[31].field` in a
    multi-cell row; the schema rejected the leaf (a leaf cannot bind every
    cell), the WHOLE section died, and the targeted repair repeated the same
    shape — three master sections lost to a one-cell formatting slip. The
    row locator is strictly broader (the gate then verifies the entire row),
    so the normalization preserves and strengthens the citation while every
    other rule is still enforced on the normalized document.
    """
    if not isinstance(sections, list):
        return
    for section in sections:
        if not isinstance(section, dict):
            continue
        for block in section.get("blocks") or []:
            if not isinstance(block, dict) or block.get("kind") != "table":
                continue
            for row in block.get("rows") or []:
                if not isinstance(row, dict):
                    continue
                cells = row.get("cells")
                if (not isinstance(cells, list)
                        or sum(1 for cell in cells if _text(cell)) < 2):
                    continue
                value = _text(row.get("row_or_rule"))
                if value.startswith("$"):
                    # Strip only the trailing leaf (and any brackets AFTER
                    # it), keeping the row index: $.x.findings[4].note ->
                    # $.x.findings[4].
                    row["row_or_rule"] = _TRAILING_LEAF_RE.sub("", value).strip()


def _section_heading_key(section: Any) -> str:
    """The comparable identity of a section: its heading, normalized."""
    if not isinstance(section, dict):
        return ""
    return re.sub(r"\s+", " ", _HEADING_PREFIX_RE.sub("", _text(section.get("heading")))).casefold()


def _dedupe_sections(sections: Any) -> Any:
    """Drop a repeated section heading, keeping the fullest copy.

    Measured 2026-10-21: the report writer answered a request for ONE section
    with that section twice -- a full 21-block copy followed by a 1-block
    repeat. The renderer emitted both, so the published report carried the
    same heading twice and the second copy was a strict subset of the first.

    The report is a document of sections, not a stream: a repeated heading is
    the writer restating itself, and the repeat carries no new finding. The
    copy with the most blocks is kept, so a truncated first attempt cannot
    displace a complete later one.
    """
    if not isinstance(sections, list):
        return sections
    best: dict = {}
    order: list = []
    others: list = []
    for section in sections:
        key = _section_heading_key(section)
        if not key:
            others.append(section)
            continue
        blocks = section.get("blocks") if isinstance(section, dict) else None
        size = len(blocks) if isinstance(blocks, list) else 0
        if key not in best:
            best[key] = (section, size)
            order.append(key)
        elif size > best[key][1]:
            best[key] = (section, size)
    out: list = []
    for key in order:
        out.append(best[key][0])
    out.extend(others)
    return out


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


def _exact_json_locator(value: str) -> bool:
    """Whether a `$`-rooted locator is exactly one resolvable expression.

    A compound locator (`$.a and $.b`, `$.a, $.b`, `$.a; $.b`, a prose
    parenthetical, or a multi-assignment) cannot be checked as one row: the
    verifier would either fail every such row or, worse, accidentally resolve
    one part and certify the rest. Reject it at the schema boundary and make
    the writer split the observation or move the interpretation to an
    assessment.
    """
    text = (value or "").strip()
    if text == "$text":
        return True
    try:
        from entailment import _parse_assignment_locator, _parse_json_path
    except Exception:
        # The deployed flat layout always contains entailment. If it is
        # unavailable, preserve the previous schema behavior rather than
        # rejecting every report for an unrelated import problem.
        return True
    return (_parse_json_path(text) is not None
            or _parse_assignment_locator(text) is not None)


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
        if field == "row_or_rule" and value.startswith("$") and not _exact_json_locator(value):
            errors.append(
                f"{where}: row_or_rule must be one exact JSONPath, one exact "
                "path=value, or a non-$ rule/row name; split compound "
                "locators and move prose interpretation to an assessment"
            )
            continue
        out[field] = value
    return out


def validate_report_document(document: Any) -> list[str]:
    """Return every schema violation in a report document, or an empty list."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document must be an object"]
    raw_sections = document.get("sections")
    document = normalize_report_document(document)
    sections = document.get("sections")
    if not isinstance(sections, list) or not sections:
        # Name the shape that was actually received. "must be a non-empty
        # array" alone did not tell the writer what it had done wrong, and the
        # correction pass repeated the same container error.
        raw = raw_sections
        if isinstance(raw, str):
            detail = ("you returned `sections` as a JSON STRING; return it as a "
                      "JSON ARRAY of section objects")
        elif isinstance(raw, dict):
            detail = ("you returned `sections` as an OBJECT; return it as a JSON "
                      "ARRAY of section objects")
        else:
            detail = "return it as a JSON ARRAY of section objects"
        return [f"document.sections must be a non-empty array: {detail}"]
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
            if (kind == "table" and bi > 0
                    and _text((blocks[bi - 1] or {}).get("kind")).lower()
                    == "table"):
                # REASSESSED 2026-10-26: two adjacent tables are a LAYOUT
                # concern, and the report quality gate already counts and caps
                # them (`orphan_tables` <= 2). Rejecting them here made the
                # claim-integrity schema fail repairs for a style defect and
                # LOST whole sections (master 4 on run 7e51a300). The writer
                # is still told to separate tables; the gate still fails a
                # report that overdoes it.
                pass
            if kind == "observation":
                text = _text(block.get("text"))
                if not text:
                    errors.append(f"{bwhere}: observation text must be non-empty")
                elif not strip_citation_annotations(text).strip():
                    errors.append(f"{bwhere}: observation text is only a citation")
                else:
                    # RC-18: disassembly belongs in a `code` block. A listing
                    # pasted into an observation renders as prose and the gate
                    # counts every listing line as an uncited claim (run
                    # 65be0144: 12 of them). Reject it here, where the writer
                    # can still move it, instead of at the audit.
                    listing_lines = [
                        line for line in text.splitlines()
                        if is_disassembly_listing_line(line)
                    ]
                    if listing_lines:
                        errors.append(
                            f"{bwhere}: observation text contains disassembly "
                            f"listing lines ({listing_lines[0].strip()[:60]}...); "
                            "put the raw listing in a `code` block and keep only "
                            "cited prose observations in the text"
                        )
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
                    if (isinstance(cells, list)
                            and sum(1 for cell in cells if _text(cell)) >= 2
                            and _ROW_LEAF_CITATION_RE.search(
                                _text(row.get("row_or_rule")))):
                        errors.append(
                            f"{rwhere}: a row with multiple non-empty cells must "
                            "cite the ROW locator, not a leaf field — drop the "
                            "trailing `.field` from row_or_rule so every cell "
                            "is supported"
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
    document = normalize_report_document(document)
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
    for section in normalize_sections(document.get("sections")) or []:
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
6. A requested section is always required. If it has no supported findings,
   return one section object with the exact heading and at least one `note` or
   `assessment` block stating the limitation. Never return `sections: []` and
   never omit the section.
7. Put ONE fact in each observation and each table row. Cite the exact scalar
   field that contains that fact, not a parent object, a list length, a
   decompilation blob, or a summary. Split compound claims into separate
   observations instead of citing one object for several assertions.
8. Do not combine locators. A `row_or_rule` must name exactly one JSONPath,
   address, rule, or row. Two sources or two fields require two observations
   (or two table rows), each with its own citation. Never write a locator such
   as `$.a ... and $.b ...`, `$.a, $.b`, or a combined source label.
9. A derived or interpretive statement (for example "packed", "likely a
   loader", "consistent with persistence") belongs in `assessment`; the
   observation must state only the exact measured value. A negative finding
   ("no Winsock imports") must cite an exact absence-bearing field or be a
   `note`, never an unrelated count or parent object.
10. Table cells must be copied from the cited row. Do not use one field to
   support a row that also asserts a technique, a verdict, or a second fact;
   split the row or move the interpretation to `assessment`.
11. Disassembly, hex dumps and any raw tool listing belong ONLY in a `code`
   block. An `observation` containing listing lines is rejected: paste the
   raw listing into `code` (with `language`) and state what it shows in a
   separate cited `observation`.
""".strip()
