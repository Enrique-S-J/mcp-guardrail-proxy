"""Client side of the proxy: the connection to the upstream MCP server.

Spawns the upstream as a subprocess, speaks MCP to it over stdio, lists its
tools once, and forwards tool calls. Also notices when the upstream goes away,
which the SDK's client session otherwise only reveals on the next request.
"""

from __future__ import annotations

import os
import shlex
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, AsyncIterator, Optional, Sequence, TextIO

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client, types

from . import __version__


class UpstreamError(Exception):
    """The upstream could not be started or did not complete the MCP handshake."""


class _WatchedReadStream:
    """Passes the upstream's messages through and records when they stop.

    The session's dispatcher reads the transport by iterating it. When the
    upstream exits, its stdout reaches EOF and the iteration ends; that is the
    earliest reliable sign the process is gone, so it is flagged here instead
    of waiting for some later call to fail.
    """

    def __init__(self, inner: Any, closed: anyio.Event) -> None:
        self._inner = inner
        self._closed = closed

    async def receive(self) -> Any:
        try:
            return await self._inner.receive()
        except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
            self._closed.set()
            raise

    def __aiter__(self) -> "_WatchedReadStream":
        return self

    async def __anext__(self) -> Any:
        try:
            return await self.receive()
        except anyio.EndOfStream:
            raise StopAsyncIteration from None

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> "_WatchedReadStream":
        return self

    async def __aexit__(self, *exc_info: Any) -> Optional[bool]:
        await self.aclose()
        return None

    def __getattr__(self, name: str) -> Any:
        # The SDK reads optional attributes off the stream (the sender's
        # context snapshot); hand those through to the real one.
        return getattr(self._inner, name)


class Upstream:
    """A live, initialized session with the upstream server."""

    def __init__(self, session: ClientSession, init: types.InitializeResult, closed: anyio.Event) -> None:
        self._session = session
        self.server_info = init.server_info
        self.instructions = init.instructions
        self.protocol_version = init.protocol_version
        self.closed = closed
        """Set when the upstream's side of the connection has ended."""
        self._closing = False

    @property
    def exited_unexpectedly(self) -> bool:
        return self.closed.is_set() and not self._closing

    async def list_tools(self) -> list[types.Tool]:
        """Every tool the upstream advertises, across all result pages."""
        tools: list[types.Tool] = []
        cursor: Optional[str] = None
        while True:
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            page = await self._session.list_tools(params=params)
            tools.extend(page.tools)
            cursor = page.next_cursor
            if not cursor:
                return tools

    async def call_tool(self, name: str, arguments: Optional[dict[str, Any]]) -> types.CallToolResult:
        """Forward a tool call and return the upstream's result as received.

        Sent with `send_request` rather than `ClientSession.call_tool`, which
        also validates the result against the tool's output schema and raises
        on a mismatch. Judging the upstream's output is the client's business;
        a proxy that rejected results on its own would not be transparent.
        """
        return await self._session.send_request(
            types.CallToolRequest(params=types.CallToolRequestParams(name=name, arguments=arguments)),
            types.CallToolResult,
        )


@asynccontextmanager
async def open_upstream(
    command: Sequence[str],
    *,
    startup_timeout: float = 30.0,
    errlog: TextIO = sys.stderr,
) -> AsyncIterator[Upstream]:
    """Spawn the upstream, complete the MCP handshake, and yield the session.

    The upstream is started with the proxy's whole environment. The SDK's
    stdio client passes only a short allow-list by default, but a client
    config that sets credentials for the upstream sets them on the process it
    launches, which is now the proxy; dropping them would break the upstream
    in a way that looks unrelated to the proxy.
    """
    if not command:
        raise UpstreamError("the upstream command is empty")
    # Values starting with "()" are exported shell functions; the SDK declines
    # to pass those to a child and the same precaution is kept here.
    env = {key: value for key, value in os.environ.items() if not value.startswith("()")}
    params = StdioServerParameters(command=command[0], args=list(command[1:]), env=env)
    closed = anyio.Event()
    shown = shlex.join(command)
    async with AsyncExitStack() as stack:
        try:
            read_stream, write_stream = await stack.enter_async_context(stdio_client(params, errlog=errlog))
        except (OSError, ValueError) as exc:
            raise UpstreamError(f"could not start the upstream command ({shown}): {exc}") from exc
        session = await stack.enter_async_context(
            ClientSession(
                _WatchedReadStream(read_stream, closed),
                write_stream,
                client_info=types.Implementation(name="mcp-guardrail-proxy", version=__version__),
            )
        )
        try:
            with anyio.fail_after(startup_timeout):
                init = await session.initialize()
        except TimeoutError:
            raise UpstreamError(
                f"the upstream did not answer the MCP handshake within {startup_timeout:g}s ({shown})"
            ) from None
        except Exception as exc:
            raise UpstreamError(
                f"the upstream did not complete the MCP handshake ({shown}): {exc}. "
                "If it exited, its own error output is above; the usual causes are a wrong "
                "path or an interpreter without the upstream's dependencies installed."
            ) from exc
        upstream = Upstream(session, init, closed)
        try:
            yield upstream
        finally:
            upstream._closing = True
