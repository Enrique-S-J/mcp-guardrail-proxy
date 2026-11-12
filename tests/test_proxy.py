"""The proxy over the real protocol: discovery, forwarding, policy, audit.

Every test here starts the proxy as a subprocess in front of
tests/fake_upstream.py and talks to it over stdio, either with an SDK client
session or with raw JSON-RPC lines. Nothing calls the proxy's functions
directly: a handler that works when called from Python says little about what
a client receives.

The fake upstream logs each tools/call it receives. "Blocked" is asserted
against that log, not against the proxy's own account of what it did.
"""

import sys

import pytest
from mcp import ClientSession, MCPError, StdioServerParameters, stdio_client

from harness import FAKE_UPSTREAM, RawPeer, connect, connect_modern

ALLOW_NOTHING_BUT_READS = "default: deny\n"


def _text(result) -> str:
    return result.content[0].text


def _wire(model) -> dict:
    return model.model_dump(by_alias=True, mode="json", exclude_none=True)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_tools_are_re_exposed_exactly_as_the_upstream_lists_them(workspace, raw_peers):
    """Names, descriptions, input schemas, and annotations survive, compared as raw JSON.

    Compared on the wire rather than through SDK models on the test's side, so
    that a field both ends quietly dropped could not make this pass.
    """
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    direct = raw_peers(RawPeer([sys.executable, str(FAKE_UPSTREAM)], ws.stderr_path))
    direct.initialize()
    proxied = raw_peers(RawPeer.proxy(ws))
    proxied.initialize()

    upstream_tools, upstream_pages = direct.list_all_tools()
    proxy_tools, proxy_pages = proxied.list_all_tools()

    # The upstream pages its list. A proxy that read only the first page would
    # expose two tools and leave the rest unreachable.
    assert upstream_pages == 2
    assert proxy_pages == 1
    assert [tool["name"] for tool in proxy_tools] == [
        "get_status",
        "send_email",
        "delete_record",
        "slow_write",
        "plain_tool",
    ]
    assert proxy_tools == upstream_tools

    # Guard against the comparison being equal because both sides are empty
    # of the interesting parts.
    by_name = {tool["name"]: tool for tool in proxy_tools}
    status = by_name["get_status"]
    assert status["description"] == "Report the fake service's status. Changes nothing."
    assert status["title"] == "Get Status"
    assert status["annotations"] == {
        "title": "Get Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    assert status["inputSchema"]["additionalProperties"] is False
    assert status["inputSchema"]["properties"]["format"] == {
        "type": "string",
        "enum": ["short", "long"],
        "x-example-vendor-hint": "kept",
    }
    assert status["outputSchema"]["required"] == ["status", "marker"]
    assert status["_meta"] == {"example.test/owner": "fake-upstream"}
    assert by_name["delete_record"]["annotations"] == {"readOnlyHint": False, "destructiveHint": True}
    assert "annotations" not in by_name["plain_tool"]
    nested = by_name["send_email"]["inputSchema"]["properties"]["smtp"]["properties"]["headers"]
    assert nested["items"]["properties"]["api_key"] == {"type": "string"}


RAW_UPSTREAM = r'''
import json, sys

TOOL = {
    "name": "odd",
    "description": "A tool carrying keys the MCP SDK has no field for.",
    "inputSchema": {"type": "object", "x-inside-schema": 1},
    "annotations": {"readOnlyHint": True, "x-inside-annotations": 2},
    "x-top-level": 3,
}
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "raw_upstream", "version": "0"},
        }
    else:
        result = {"tools": [TOOL]}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\n")
    sys.stdout.flush()
'''


def test_what_survives_when_the_upstream_sends_keys_the_sdk_does_not_model(workspace, raw_peers):
    """Pins a documented limit, so the README cannot drift from the behaviour.

    Tools pass through the SDK's models on the way in and out. A schema is an
    open dict and survives whole; a key the models have no field for, on the
    tool itself or inside its annotations, does not.
    """
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    script = ws.dir / "raw_upstream.py"
    script.write_text(RAW_UPSTREAM)
    proxied = raw_peers(RawPeer.proxy(ws, upstream=[sys.executable, str(script)]))
    proxied.initialize()
    (tool,), _ = proxied.list_all_tools()
    assert tool == {
        "name": "odd",
        "description": "A tool carrying keys the MCP SDK has no field for.",
        "inputSchema": {"type": "object", "x-inside-schema": 1},
        "annotations": {"readOnlyHint": True},
    }


async def test_tools_are_the_same_at_both_protocol_versions(workspace):
    """A 2026-07-28 client sees the same tools as one using the initialize handshake."""
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    async with connect(ws) as session:
        assert session.protocol_version == "2025-11-25"
        legacy = [_wire(tool) for tool in (await session.list_tools()).tools]
    async with connect_modern(ws) as client:
        assert client.protocol_version == "2026-07-28"
        modern = [_wire(tool) for tool in (await client.list_tools()).tools]
    assert len(legacy) == 5
    assert modern == legacy


async def test_the_proxy_names_itself_and_passes_on_the_upstream_instructions(workspace):
    """Honest about being in the path; the upstream's guidance to the model still arrives."""
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    async with connect(ws) as session:
        info = session.server_info
        assert info.name == "mcp-guardrail-proxy"
        assert info.title == "Fake Upstream (via mcp-guardrail-proxy)"
        assert session.instructions == "Synthetic server used by the mcp-guardrail-proxy tests."
    assert "upstream 'fake_upstream' 9.9.9: 5 tools (1 allow, 0 require approval, 4 deny)" in ws.stderr()


# ---------------------------------------------------------------------------
# Forwarding
# ---------------------------------------------------------------------------


def test_a_read_only_call_returns_the_upstream_result_unchanged(workspace, raw_peers):
    """Compared as raw JSON against the same call made straight to the upstream."""
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    direct = raw_peers(RawPeer([sys.executable, str(FAKE_UPSTREAM)], ws.stderr_path))
    direct.initialize()
    proxied = raw_peers(RawPeer.proxy(ws))
    proxied.initialize()
    call = {"name": "get_status", "arguments": {"verbose": True}}

    from_upstream = direct.request("tools/call", call)["result"]
    through_proxy = proxied.request("tools/call", call)["result"]

    assert through_proxy == from_upstream
    assert through_proxy["structuredContent"] == {"status": "ok", "marker": None}
    assert through_proxy["_meta"] == {"example.test/served-by": "fake-upstream"}
    assert through_proxy["isError"] is False

    (entry,) = ws.audit()
    assert entry["tool"] == "get_status"
    assert entry["arguments"] == {"verbose": True}
    assert entry["decision"] == "allow"
    assert entry["rule"] == "read_only_passthrough"
    assert entry["upstream_status"] == "ok"
    assert entry["approver"] is None
    assert entry["latency_ms"] >= 0
    assert ws.upstream_calls() == [{"tool": "get_status", "arguments": {"verbose": True}}]


def test_a_result_that_breaks_the_upstreams_own_output_schema_is_still_passed_on(workspace, raw_peers):
    """Whether the upstream's output is acceptable is for the client to decide, as it would without a proxy.

    The SDK's ClientSession.call_tool validates results against the tool's
    output schema and raises; a proxy built on it would turn this result into
    an error of its own.
    """
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    direct = raw_peers(RawPeer([sys.executable, str(FAKE_UPSTREAM)], ws.stderr_path))
    direct.initialize()
    proxied = raw_peers(RawPeer.proxy(ws))
    proxied.initialize()
    call = {"name": "get_status", "arguments": {"format": "long"}}

    from_upstream = direct.request("tools/call", call)["result"]
    through_proxy = proxied.request("tools/call", call)["result"]

    assert from_upstream["structuredContent"] == {"status": "ok"}  # "marker" is required by the schema
    assert through_proxy == from_upstream
    assert ws.audit()[0]["upstream_status"] == "ok"


async def test_an_upstream_tool_error_is_passed_through_as_is(workspace):
    """isError from the tool is the tool's answer, not a proxy decision."""
    ws = workspace("default: allow\n")
    async with connect(ws) as session:
        result = await session.call_tool("send_email", {"subject": "no recipient"})
    assert result.is_error is True
    assert _text(result) == "Error: 'to' is required."
    (entry,) = ws.audit()
    assert (entry["decision"], entry["upstream_status"]) == ("allow", "error")


async def test_an_upstream_protocol_error_reaches_the_client_unchanged(workspace):
    """Same JSON-RPC error code, message, and data the upstream sent."""
    ws = workspace("default: allow\n")
    async with connect(ws) as session:
        with pytest.raises(MCPError) as exc:
            await session.call_tool("delete_record", {})
    assert exc.value.error.code == -32602
    assert exc.value.error.message == "record_id is required"
    assert exc.value.error.data == {"field": "record_id"}
    (entry,) = ws.audit()
    assert (entry["decision"], entry["upstream_status"]) == ("allow", "protocol_error")
    assert "record_id is required" in entry["reason"]


async def test_the_upstream_inherits_the_proxys_environment(workspace):
    """Credentials a client config sets for the upstream land on the proxy, and must be handed on."""
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_guardrail_proxy", *ws.proxy_argv()],
        env={"FAKE_UPSTREAM_MARKER": "set-on-the-proxy"},
    )
    with open(ws.stderr_path, "a") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("get_status", {})
    assert result.structured_content == {"status": "ok", "marker": "set-on-the-proxy"}


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------


async def test_a_write_tool_is_blocked_by_default_deny_and_audited(workspace):
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    async with connect(ws) as session:
        result = await session.call_tool("send_email", {"to": "nobody@example.test"})

    assert result.is_error is True
    assert _text(result) == (
        "Blocked by mcp-guardrail-proxy: policy rule 'default: deny' denies calls to 'send_email'."
    )
    assert ws.upstream_calls() == []
    (entry,) = ws.audit()
    assert entry["tool"] == "send_email"
    assert entry["decision"] == "deny"
    assert entry["rule"] == "default: deny"
    assert entry["upstream_status"] == "not_called"
    assert entry["arguments"] == {"to": "nobody@example.test"}


async def test_an_explicit_allow_forwards_a_write_tool(workspace):
    ws = workspace("default: deny\ntools:\n  send_email: allow\n")
    async with connect(ws) as session:
        result = await session.call_tool("send_email", {"to": "nobody@example.test"})
        blocked = await session.call_tool("delete_record", {"record_id": "r-1"})

    assert result.is_error is False
    assert _text(result) == 'sent: {"to": "nobody@example.test"}'
    assert blocked.is_error is True
    assert ws.upstream_calls() == [{"tool": "send_email", "arguments": {"to": "nobody@example.test"}}]
    allowed, denied = ws.audit()
    assert (allowed["decision"], allowed["rule"], allowed["upstream_status"]) == (
        "allow",
        "tools.send_email: allow",
        "ok",
    )
    assert (denied["decision"], denied["rule"]) == ("deny", "default: deny")


async def test_an_explicit_deny_blocks_even_a_read_only_tool(workspace):
    """Explicit rule beats passthrough, and the message names that rule."""
    ws = workspace("default: allow\ntools:\n  get_status: deny\n")
    async with connect(ws) as session:
        result = await session.call_tool("get_status", {})
    assert result.is_error is True
    assert "policy rule 'tools.get_status: deny'" in _text(result)
    assert ws.upstream_calls() == []


async def test_a_tool_without_annotations_is_treated_as_a_write(workspace):
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    async with connect(ws) as session:
        result = await session.call_tool("plain_tool", {})
    assert result.is_error is True
    assert ws.upstream_calls() == []
    assert ws.audit()[0]["rule"] == "default: deny"


async def test_without_a_policy_file_reads_pass_and_writes_are_refused(workspace):
    """The built-in default: require approval, with nobody configured to give it."""
    ws = workspace(None)
    async with connect(ws) as session:
        read = await session.call_tool("get_status", {})
        write = await session.call_tool("send_email", {"to": "nobody@example.test"})

    assert read.is_error is False
    assert write.is_error is True
    assert _text(write) == (
        "Blocked by mcp-guardrail-proxy: policy rule 'default: require_approval' requires approval for "
        "'send_email', and approval.mode is 'deny', so there is nobody to ask."
    )
    assert [call["tool"] for call in ws.upstream_calls()] == ["get_status"]
    assert [(e["decision"], e["rule"]) for e in ws.audit()] == [
        ("allow", "read_only_passthrough"),
        ("deny", "default: require_approval (approval.mode: deny)"),
    ]


async def test_a_tool_the_upstream_did_not_list_at_startup_is_denied(workspace):
    """Even under default: allow, and even though the upstream would run it.

    `late_addition` is callable on the fake upstream but absent from its
    tools/list, like a tool added after the proxy had started.
    """
    ws = workspace("default: allow\n")
    async with connect(ws) as session:
        result = await session.call_tool("late_addition", {})

    assert result.is_error is True
    assert "was not among the tools the upstream server listed when the proxy started" in _text(result)
    assert "restart the proxy" in _text(result)
    assert ws.upstream_calls() == []
    (entry,) = ws.audit()
    assert (entry["decision"], entry["rule"], entry["upstream_status"]) == ("deny", "unknown_tool", "not_called")


async def test_a_policy_rule_for_a_tool_the_upstream_lacks_is_flagged_at_startup(workspace):
    """A misspelt tool name in the policy protects nothing; say so."""
    ws = workspace("default: allow\ntools:\n  delete_recrod: deny\n")
    async with connect(ws):
        pass
    assert "the policy has a rule for 'delete_recrod', but the upstream has no tool by that name" in ws.stderr()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


async def test_secrets_are_redacted_in_the_log_but_not_in_the_forwarded_call(workspace):
    ws = workspace("default: allow\nredact_fields: [password, api_key]\n")
    arguments = {
        "to": "nobody@example.test",
        "smtp": {
            "host": "mail.example.test",
            "password": "nested-secret-1",
            "headers": [{"api_key": "nested-secret-2"}],
        },
    }
    async with connect(ws) as session:
        result = await session.call_tool("send_email", arguments)

    # The upstream got the real values: by its own log, and in what it echoed.
    assert ws.upstream_calls() == [{"tool": "send_email", "arguments": arguments}]
    assert "nested-secret-1" in _text(result) and "nested-secret-2" in _text(result)

    raw_log = ws.audit_path.read_text()
    assert "nested-secret" not in raw_log
    (entry,) = ws.audit()
    assert entry["arguments"] == {
        "to": "nobody@example.test",
        "smtp": {
            "host": "mail.example.test",
            "password": "[REDACTED]",
            "headers": [{"api_key": "[REDACTED]"}],
        },
    }


async def test_blocked_calls_are_redacted_in_the_log_too(workspace):
    ws = workspace("default: deny\nredact_fields: [password]\n")
    async with connect(ws) as session:
        await session.call_tool("send_email", {"to": "x@example.test", "smtp": {"password": "nested-secret"}})
    assert "nested-secret" not in ws.audit_path.read_text()


async def test_one_valid_json_line_per_call_appended_in_order(workspace):
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    async with connect(ws) as session:
        await session.call_tool("get_status", {})
        after_one = ws.audit_path.read_bytes()
        await session.call_tool("send_email", {"to": "nobody@example.test"})
        after_two = ws.audit_path.read_bytes()

    assert after_one.count(b"\n") == 1
    assert after_two.count(b"\n") == 2
    assert after_two.startswith(after_one)
    first, second = ws.audit()  # json.loads on every line
    assert [first["tool"], second["tool"]] == ["get_status", "send_email"]
    assert first["call_id"] != second["call_id"]

    # A second run of the proxy adds to the same file.
    async with connect(ws) as session:
        await session.call_tool("get_status", {})
    assert ws.audit_path.read_bytes().startswith(after_two)
    assert len(ws.audit()) == 3


async def test_the_log_can_be_rotated_while_the_proxy_runs(workspace):
    """Move the file away mid-session; the next record starts a new file at the same path."""
    ws = workspace(ALLOW_NOTHING_BUT_READS)
    rotated = ws.dir / "audit.jsonl.1"
    async with connect(ws) as session:
        await session.call_tool("get_status", {"verbose": True})
        ws.audit_path.rename(rotated)
        await session.call_tool("get_status", {"verbose": False})

    assert rotated.read_text().count("\n") == 1
    (entry,) = ws.audit()
    assert entry["arguments"] == {"verbose": False}
