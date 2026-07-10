#!/usr/bin/env python3
"""mcp-capa — single tool: capa_analyze(path)."""
import asyncio
import json
import sys

sys.path.insert(0, "/opt/scripts")
from v2_lib import capa_analyze  # noqa: E402

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("mcp-capa")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="capa_analyze",
            description="Run capa with Mandiant rules; returns ATT&CK/MBC rule summary JSON.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Sample file path"}},
                "required": ["path"],
            },
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "capa_analyze":
        raise ValueError(f"unknown tool: {name}")
    result = capa_analyze(arguments["path"])
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
