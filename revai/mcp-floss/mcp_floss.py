#!/usr/bin/env python3
"""mcp-floss — single tool: floss_extract(path)."""
import asyncio
import json
import sys

sys.path.insert(0, "/opt/scripts")
from v2_lib import floss_extract  # noqa: E402

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("mcp-floss")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="floss_extract",
            description="Extract obfuscated/stack strings via floss; returns capped string list JSON.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Sample file path"}},
                "required": ["path"],
            },
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "floss_extract":
        raise ValueError(f"unknown tool: {name}")
    result = floss_extract(arguments["path"])
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
