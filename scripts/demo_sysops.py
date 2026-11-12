"""End-to-end demo: mcp-guardrail-proxy in front of sysops-mcp.

Starts the proxy as a subprocess, with a sysops-mcp checkout as its upstream
and a policy that denies nothing, then acts as an MCP client over the proxy's
stdio: initialize, tools/list, and one tools/call (get_host_summary). Prints
the tool count next to what sysops-mcp lists when asked directly, and the
audit line the call produced.

    python scripts/demo_sysops.py                      # expects ../sysops-mcp
    python scripts/demo_sysops.py --sysops-dir /path/to/sysops-mcp
    SYSOPS_MCP_DIR=/path/to/sysops-mcp python scripts/demo_sysops.py

sysops-mcp must have its own virtualenv (see its README); the upstream is run
with that interpreter, not this one, because that is where its dependencies
are installed.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shlex
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

REPO = Path(__file__).resolve().parent.parent


def _venv_python(checkout: Path) -> Path:
    if os.name == "nt":
        return checkout / ".venv" / "Scripts" / "python.exe"
    return checkout / ".venv" / "bin" / "python"


async def _list_tools(params: StdioServerParameters) -> list[dict]:
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            return [tool.model_dump(by_alias=True, mode="json", exclude_none=True) for tool in tools]


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--sysops-dir",
        type=Path,
        default=Path(os.environ.get("SYSOPS_MCP_DIR", REPO.parent / "sysops-mcp")),
        help="sysops-mcp checkout (default: $SYSOPS_MCP_DIR, else ../sysops-mcp next to this repo)",
    )
    args = parser.parse_args()

    checkout = args.sysops_dir.expanduser().resolve()
    server = checkout / "server.py"
    python = _venv_python(checkout)
    if not server.is_file():
        print(f"Error: no server.py in '{checkout}'. Pass --sysops-dir or set SYSOPS_MCP_DIR.", file=sys.stderr)
        return 2
    if not python.is_file():
        print(
            f"Error: '{python}' does not exist. Create sysops-mcp's virtualenv first "
            "(python3 -m venv .venv && .venv/bin/pip install -e . in that checkout).",
            file=sys.stderr,
        )
        return 2
    upstream = [str(python), str(server)]

    with tempfile.TemporaryDirectory(prefix="guardrail-demo-") as tmp:
        policy = Path(tmp) / "policy.yaml"
        audit = Path(tmp) / "audit.jsonl"
        policy.write_text("# Demo policy: nothing is denied.\ndefault: allow\n", encoding="utf-8")

        proxy = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "mcp_guardrail_proxy",
                "--upstream",
                shlex.join(upstream),
                "--policy",
                str(policy),
                "--audit",
                str(audit),
            ],
        )

        direct_tools = await _list_tools(StdioServerParameters(command=upstream[0], args=upstream[1:]))

        async with stdio_client(proxy) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                listed = (await session.list_tools()).tools
                proxy_tools = [tool.model_dump(by_alias=True, mode="json", exclude_none=True) for tool in listed]
                result = await session.call_tool("get_host_summary", {})

        print(f"connected to: {init.server_info.name} {init.server_info.version} ({init.server_info.title})")
        print(f"protocol version: {init.protocol_version}")
        print(f"tools listed by sysops-mcp directly: {len(direct_tools)}")
        print(f"tools listed through the proxy:      {len(proxy_tools)}")
        print(f"identical (name, description, schema, annotations): {proxy_tools == direct_tools}")
        for tool in proxy_tools:
            hint = (tool.get("annotations") or {}).get("readOnlyHint")
            print(f"  - {tool['name']} (readOnlyHint: {hint})")
        print()
        print(f"get_host_summary through the proxy (isError: {result.is_error}):")
        for line in result.content[0].text.splitlines():
            print(f"  {line}")
        print()
        print("audit log:")
        print(audit.read_text(encoding="utf-8").rstrip())

        ok = proxy_tools == direct_tools and not result.is_error and audit.read_text().count("\n") == 1
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
