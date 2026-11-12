"""Shared plumbing for tests that run the proxy as a real subprocess.

Two ways in, both over the proxy's actual stdin/stdout:

- `connect` / `connect_modern`: an SDK client session, for behaviour.
- `RawPeer`: hand-written JSON-RPC lines, for what is literally on the wire
  and for the process's exit status, neither of which the SDK client exposes.

The fixtures built on these live in conftest.py.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import anyio
from mcp import Client, ClientSession, StdioServerParameters, stdio_client

FAKE_UPSTREAM = Path(__file__).resolve().parent / "fake_upstream.py"

# Generous: a test that needs this long is hung, not slow.
STEP_TIMEOUT = 30.0


@dataclass
class Workspace:
    """A temp directory holding one proxy run's policy, audit log, and evidence."""

    dir: Path
    policy_text: Optional[str]

    def __post_init__(self) -> None:
        self.policy_path = self.dir / "policy.yaml"
        self.audit_path = self.dir / "audit.jsonl"
        self.calls_path = self.dir / "upstream-calls.jsonl"
        self.pid_path = self.dir / "upstream.pid"
        self.stderr_path = self.dir / "proxy-stderr.log"
        self.approvals_dir = self.dir / "approvals"
        if self.policy_text is not None:
            self.policy_path.write_text(self.policy_text)

    def upstream_argv(self, script: Path = FAKE_UPSTREAM) -> list[str]:
        return [sys.executable, str(script), "--call-log", str(self.calls_path), "--pid-file", str(self.pid_path)]

    def proxy_argv(self, *, upstream: Optional[list[str]] = None, separator_form: bool = False) -> list[str]:
        """Arguments for `python -m mcp_guardrail_proxy`."""
        upstream = upstream if upstream is not None else self.upstream_argv()
        argv = ["--audit", str(self.audit_path)]
        if self.policy_text is not None:
            argv += ["--policy", str(self.policy_path)]
        if separator_form:
            return argv + ["--", *upstream]
        return argv + ["--upstream", shlex.join(upstream)]

    def audit(self) -> list[dict[str, Any]]:
        """Every audit record so far. Fails if any line is not JSON."""
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]

    def upstream_calls(self) -> list[dict[str, Any]]:
        """Every tools/call the fake upstream actually received."""
        if not self.calls_path.exists():
            return []
        return [json.loads(line) for line in self.calls_path.read_text().splitlines()]

    def stderr(self) -> str:
        return self.stderr_path.read_text() if self.stderr_path.exists() else ""

    def upstream_pid(self) -> int:
        return int(self.pid_path.read_text())


def _proxy_params(ws: Workspace, **argv_options: Any) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable, args=["-m", "mcp_guardrail_proxy", *ws.proxy_argv(**argv_options)]
    )


@asynccontextmanager
async def connect(ws: Workspace, *, elicitation_callback: Any = None, **argv_options: Any):
    """An initialized SDK session with the proxy, using the initialize handshake."""
    with open(ws.stderr_path, "a") as errlog:
        with anyio.fail_after(STEP_TIMEOUT * 2):
            async with stdio_client(_proxy_params(ws, **argv_options), errlog=errlog) as (read, write):
                async with ClientSession(read, write, elicitation_callback=elicitation_callback) as session:
                    await session.initialize()
                    yield session


@asynccontextmanager
async def connect_modern(ws: Workspace, *, elicitation_callback: Any = None):
    """The SDK's high-level client, which negotiates protocol 2026-07-28 with the proxy."""
    with open(ws.stderr_path, "a") as errlog:
        with anyio.fail_after(STEP_TIMEOUT * 2):
            transport = stdio_client(_proxy_params(ws), errlog=errlog)
            async with Client(transport, mode="auto", elicitation_callback=elicitation_callback) as client:
                yield client


class RawPeer:
    """Speaks newline-delimited JSON-RPC to a subprocess, by hand."""

    def __init__(self, argv: list[str], stderr_path: Path, env: Optional[dict[str, str]] = None) -> None:
        self._stderr = open(stderr_path, "a")
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            env={**os.environ, **env} if env else None,
        )
        self._lines: "queue.Queue[Optional[bytes]]" = queue.Queue()
        self._next_id = 0
        threading.Thread(target=self._pump, daemon=True).start()

    @classmethod
    def proxy(
        cls,
        ws: Workspace,
        *,
        launcher: Optional[Path] = None,
        env: Optional[dict[str, str]] = None,
        **argv_options: Any,
    ) -> "RawPeer":
        """The proxy as `python -m mcp_guardrail_proxy`, or through a `launcher` script that wraps it."""
        entry = [str(launcher)] if launcher is not None else ["-m", "mcp_guardrail_proxy"]
        return cls([sys.executable, *entry, *ws.proxy_argv(**argv_options)], ws.stderr_path, env)

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()

    def send_request(self, method: str, params: Optional[dict[str, Any]] = None) -> int:
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        return self._next_id

    def _read_until(self, wanted, what: str, timeout: float) -> dict[str, Any]:
        """The next message for which `wanted(message)` holds, skipping anything else the peer says first."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                line = self._lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                raise AssertionError(f"no {what} within {timeout}s") from None
            if line is None:
                raise AssertionError(f"peer closed stdout before sending {what}")
            message = json.loads(line)
            if wanted(message):
                return message

    def read_response(self, request_id: int, timeout: float = STEP_TIMEOUT) -> dict[str, Any]:
        """The response to `request_id`."""
        return self._read_until(
            lambda message: message.get("id") == request_id and "method" not in message,
            f"response to request {request_id}",
            timeout,
        )

    def read_request(self, method: str, timeout: float = STEP_TIMEOUT) -> dict[str, Any]:
        """The next request the peer sends us with this method."""
        return self._read_until(
            lambda message: message.get("method") == method and "id" in message, f"'{method}' request", timeout
        )

    def request(self, method: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        return self.read_response(self.send_request(method, params))

    def initialize(self, capabilities: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        response = self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": capabilities or {},
                "clientInfo": {"name": "raw-test-client", "version": "0"},
            },
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response

    def list_all_tools(self) -> tuple[list[dict[str, Any]], int]:
        """Follow nextCursor to the end. Returns (tools, number of pages)."""
        tools: list[dict[str, Any]] = []
        pages = 0
        cursor: Optional[str] = None
        while True:
            result = self.request("tools/list", {"cursor": cursor} if cursor else None)["result"]
            tools += result["tools"]
            pages += 1
            cursor = result.get("nextCursor")
            if not cursor:
                return tools, pages

    def wait(self, timeout: float = STEP_TIMEOUT) -> int:
        """Exit status, without closing stdin first: the peer must exit on its own."""
        return self.proc.wait(timeout=timeout)

    def close(self) -> int:
        """Close stdin (the stdio shutdown signal) and return the exit status."""
        try:
            if self.proc.stdin is not None and not self.proc.stdin.closed:
                self.proc.stdin.close()
            return self.proc.wait(timeout=STEP_TIMEOUT)
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            if self.proc.stdout is not None:
                self.proc.stdout.close()
            self._stderr.close()


async def wait_for(predicate, *, timeout: float = STEP_TIMEOUT, interval: float = 0.02):
    """Poll until `predicate()` returns something truthy, and return it."""
    with anyio.fail_after(timeout):
        while True:
            value = predicate()
            if value:
                return value
            await anyio.sleep(interval)
