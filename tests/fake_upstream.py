"""A small MCP server for the proxy to sit in front of during tests.

Everything here is synthetic. The tools do nothing except report what they
were called with, which is what lets a test tell a call that was forwarded
from one that was only claimed to be.

    python fake_upstream.py [--call-log PATH] [--pid-file PATH]

With --call-log, every tools/call that reaches this server is appended to
PATH as one JSON line, before the tool runs. With --pid-file, the server
writes its pid to PATH at startup so a test can kill it.

Tools listed (across two pages, so a client that stops at the first page
sees only half of them):

    get_status      read-only; also reports $FAKE_UPSTREAM_MARKER as seen here.
                    With format="long" its structured result omits a field its
                    own output schema requires.
    send_email      write; echoes its arguments back
    delete_record   write, destructive; a JSON-RPC error if record_id is missing
    slow_write      write; sleeps for `seconds` before answering
    plain_tool      no annotations at all

`late_addition` is callable but never listed. It stands in for a tool the
upstream gained after the proxy had already read the list.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, Optional

import anyio
from mcp import MCPError, types
from mcp.server import Server
from mcp.server.stdio import stdio_server

CALL_LOG: Optional[str] = None

# The schemas go beyond what a signature-derived schema would produce (enum,
# nested objects, additionalProperties, a vendor keyword) so that "re-exposed
# unchanged" is tested against something that could plausibly be mangled.
TOOLS = [
    types.Tool(
        name="get_status",
        title="Get Status",
        description="Report the fake service's status. Changes nothing.",
        input_schema={
            "type": "object",
            "properties": {
                "verbose": {"type": "boolean", "description": "Include extra detail.", "default": False},
                "format": {"type": "string", "enum": ["short", "long"], "x-example-vendor-hint": "kept"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"status": {"type": "string"}, "marker": {"type": ["string", "null"]}},
            "required": ["status", "marker"],
        },
        annotations=types.ToolAnnotations(
            title="Get Status",
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        _meta={"example.test/owner": "fake-upstream"},
    ),
    types.Tool(
        name="send_email",
        description="Pretend to send an email. Echoes the arguments it received.",
        input_schema={
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient address."},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "smtp": {
                    "type": "object",
                    "description": "Connection details.",
                    "properties": {
                        "host": {"type": "string"},
                        "password": {"type": "string"},
                        "headers": {
                            "type": "array",
                            "items": {"type": "object", "properties": {"api_key": {"type": "string"}}},
                        },
                    },
                },
            },
            "required": ["to"],
        },
        annotations=types.ToolAnnotations(
            title="Send Email", read_only_hint=False, destructive_hint=False, open_world_hint=True
        ),
    ),
    types.Tool(
        name="delete_record",
        description="Pretend to delete a record.",
        input_schema={
            "type": "object",
            "properties": {"record_id": {"type": "string", "description": "Record to delete."}},
        },
        annotations=types.ToolAnnotations(read_only_hint=False, destructive_hint=True),
    ),
    types.Tool(
        name="slow_write",
        description="Sleep, then answer. For tests that need a call in flight.",
        input_schema={"type": "object", "properties": {"seconds": {"type": "number"}}},
        annotations=types.ToolAnnotations(read_only_hint=False),
    ),
    types.Tool(
        name="plain_tool",
        description="A tool whose author supplied no annotations.",
        input_schema={"type": "object"},
    ),
]
FIRST_PAGE = 2


def _text(text: str, **kwargs: Any) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], **kwargs)


async def list_tools(ctx: Any, params: Optional[types.PaginatedRequestParams]) -> types.ListToolsResult:
    if params is not None and params.cursor == "page-2":
        return types.ListToolsResult(tools=TOOLS[FIRST_PAGE:])
    return types.ListToolsResult(tools=TOOLS[:FIRST_PAGE], next_cursor="page-2")


async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    arguments = params.arguments or {}
    if CALL_LOG:
        with open(CALL_LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"tool": params.name, "arguments": params.arguments}) + "\n")

    if params.name == "get_status":
        status = {"status": "ok", "marker": os.environ.get("FAKE_UPSTREAM_MARKER")}
        if arguments.get("format") == "long":
            del status["marker"]
        return _text(
            json.dumps(status),
            structured_content=status,
            _meta={"example.test/served-by": "fake-upstream"},
        )
    if params.name == "send_email":
        if "to" not in arguments:
            return _text("Error: 'to' is required.", is_error=True)
        return _text("sent: " + json.dumps(arguments, sort_keys=True))
    if params.name == "delete_record":
        if "record_id" not in arguments:
            raise MCPError(code=types.INVALID_PARAMS, message="record_id is required", data={"field": "record_id"})
        return _text(f"deleted {arguments.get('record_id')}")
    if params.name == "slow_write":
        await anyio.sleep(float(arguments.get("seconds", 30)))
        return _text("slow_write finished")
    if params.name == "plain_tool":
        return _text("plain_tool ran")
    if params.name == "late_addition":
        return _text("late_addition ran")
    raise ValueError(f"Unknown tool: {params.name}")


async def main() -> None:
    server = Server(
        "fake_upstream",
        version="9.9.9",
        title="Fake Upstream",
        instructions="Synthetic server used by the mcp-guardrail-proxy tests.",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--call-log")
    parser.add_argument("--pid-file")
    options = parser.parse_args()
    CALL_LOG = options.call_log
    if options.pid_file:
        with open(options.pid_file, "w", encoding="utf-8") as pid_file:
            pid_file.write(str(os.getpid()))
    anyio.run(main)
