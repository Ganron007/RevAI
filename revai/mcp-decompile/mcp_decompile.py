#!/usr/bin/env python3
"""mcp-decompile — single tool: ghidra_decompile(session_id, function)."""
import asyncio
import json
import sys

sys.path.insert(0, "/opt/scripts")
from v2_lib import ghidra_decompile  # noqa: E402

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("mcp-decompile")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ghidra_decompile",
            description="Decompile one Ghidra function after session load (ghidrasql-backed).",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "ghidra-<sha256> or sha256"},
                    "function": {
                        "type": "string",
                        "description": "Function name or address (0x...)",
                    },
                },
                "required": ["session_id", "function"],
            },
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "ghidra_decompile":
        raise ValueError(f"unknown tool: {name}")
    result = ghidra_decompile(arguments["session_id"], arguments["function"])
    return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
