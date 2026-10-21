"""Test-only helpers for the claim-level report writer contract.

Report-stage tests used to fabricate a Markdown body. The production writer now
returns structured `sections`; these helpers convert the same fixture Markdown
into a valid schema document so the tests keep exercising ordering, retries and
section assembly rather than the schema itself.
"""
from __future__ import annotations

import json
import re


def markdown_to_sections(markdown: str) -> list[dict]:
    sections: list[dict] = []
    current: dict | None = None
    body: list[str] = []

    def flush() -> None:
        if current is None:
            return
        text = "\n".join(body).strip()
        blocks = []
        if text:
            blocks.append({
                "kind": "observation",
                "text": text,
                "source": "test",
                "query_or_table": "test-artifact.json",
                "row_or_rule": "test-row",
            })
        if blocks:
            sections.append({"heading": current["heading"], "blocks": blocks})

    for raw in (markdown or "").splitlines():
        match = re.match(r"^#{1,2}\s+(.+?)\s*$", raw)
        if match:
            flush()
            current = {"heading": match.group(1).strip()}
            body = []
            continue
        if current is not None:
            body.append(raw)
    flush()
    if not sections and (markdown or "").strip():
        sections.append({
            "heading": "Section",
            "blocks": [{
                "kind": "observation",
                "text": markdown.strip(),
                "source": "test",
                "query_or_table": "test-artifact.json",
                "row_or_rule": "test-row",
            }],
        })
    return sections


def structured_tool_response(markdown: str, title: str = "Test report") -> dict:
    return {
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {"tool_calls": [{
                "type": "function",
                "id": "test-report",
                "function": {
                    "name": "submit_report",
                    "arguments": json.dumps({
                        "title": title,
                        "sections": markdown_to_sections(markdown),
                    }),
                },
            }]},
        }]
    }


def structured_arguments(sections: list[dict], title: str = "Test report") -> dict:
    return {
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {"tool_calls": [{
                "type": "function",
                "id": "test-report",
                "function": {
                    "name": "submit_report",
                    "arguments": json.dumps({"title": title, "sections": sections}),
                },
            }]},
        }]
    }
