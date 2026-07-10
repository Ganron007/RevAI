#!/usr/bin/env python3
"""mcp-yara — single tool: yara_scan(path, rules_glob)."""
import asyncio
import json
import sys

sys.path.insert(0, "/opt/scripts")
from v2_lib import YARA_RULES, yara_scan  # noqa: E402

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("mcp-yara")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="yara_scan",
            description="Scan sample with yara-x; returns deduplicated rule matches JSON.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Sample file path"},
                    "rules_glob": {
                        "type": "string",
                        "description": "Rules file or glob",
                        "default": YARA_RULES,
                    },
                },
                "required": ["path"],
            },
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "yara_scan":
        raise ValueError(f"unknown tool: {name}")
    rules = arguments.get("rules_glob", YARA_RULES)
    result = yara_scan(arguments["path"], rules_glob=rules)
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
