#!/usr/bin/env python3
"""mcp-malcat — single tool: malcat_analyze(path, views[]). Not SQL."""
import asyncio
import json
import sys

sys.path.insert(0, "/opt/scripts")
from v2_lib import malcat_analyze  # noqa: E402

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

ALLOWED_VIEWS = [
    "anomalies",
    "strings",
    "imports",
    "sections",
    "yara_hits",
    "entropy",
    "capa_summary",
    "functions",
    "constants",
    "carved",
    "virtual_files",
    "structures",
    "script_decompile",
    "unpack_donut",
    "decompile",
    "anomaly_locations",
    "all",
]

app = Server("mcp-malcat")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="malcat_analyze",
            description="Malcat structured triage JSON per view (not SQL).",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Sample file path"},
                    "views": {
                        "type": "array",
                        "items": {"type": "string", "enum": ALLOWED_VIEWS},
                        "description": "Views to fetch",
                    },
                },
                "required": ["path"],
            },
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "malcat_analyze":
        raise ValueError(f"unknown tool: {name}")
    views = arguments.get("views") or ["anomalies", "strings", "imports"]
    result = malcat_analyze(arguments["path"], views=views)
    return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
