"""Server side of the proxy: what the MCP client talks to.

Re-exposes the upstream's tools exactly as the upstream described them, and
puts the policy between each `tools/call` and the upstream.

The tools are served through the SDK's low-level `Server`, whose handlers
receive and return protocol objects directly. The decorator API on
`MCPServer` derives a tool's schema from a Python function signature; here
the schemas already exist and belong to someone else, so they are handed back
as received.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence, Union

import anyio
from mcp import MCPError, types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from . import __version__
from .approval import (
    ELICITATION_KEY,
    ApprovalOutcome,
    FileApprover,
    elicitation_params,
    outcome_from_elicitation,
)
from .audit import AuditError, AuditLog
from .policy import UNKNOWN_TOOL_RULE, Action, Policy
from .upstream import Upstream, UpstreamError, open_upstream

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_UPSTREAM_START = 3
EXIT_UPSTREAM_LOST = 4
EXIT_AUDIT = 5

# How long in-flight calls get to send their error result to the client after
# a fatal condition, before the proxy stops serving.
_SHUTDOWN_GRACE_SECONDS = 1.0

NOT_CALLED = "not_called"
_WITHDRAWN = "the call was withdrawn while approval was pending (cancelled by the client, or the proxy was stopping)"

CallResult = Union[types.CallToolResult, types.InputRequiredResult]


def log(message: str) -> None:
    """Operator-facing diagnostics. stderr only: stdout is the MCP wire."""
    print(f"mcp-guardrail-proxy: {message}", file=sys.stderr, flush=True)


class _WireInput:
    """The proxy's stdin, as lines, with a read that can be walked away from.

    `stdio_server` reads stdin on a worker thread and, left to itself, waits
    for that read to return before it will shut down. That is fine when the
    client hangs up first. It is not fine when the proxy has to stop on its
    own account, with the client still connected and saying nothing: the read
    never returns and the proxy would sit there, dead upstream and all, until
    the client noticed. Reading here with `abandon_on_cancel` lets a
    cancelled proxy leave the blocked thread behind.

    `stdio_server` only ever iterates its `stdin` argument, which is all this
    supports.
    """

    def __aiter__(self) -> "_WireInput":
        return self

    async def __anext__(self) -> str:
        line = await anyio.to_thread.run_sync(sys.stdin.buffer.readline, abandon_on_cancel=True)
        if not line:
            raise StopAsyncIteration
        return line.decode("utf-8", errors="replace")


def _error_result(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


def _arguments_digest(tool: str, arguments: Any) -> str:
    canonical = json.dumps([tool, arguments], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _find_exception(exc: BaseException, kind: type) -> Optional[BaseException]:
    """Find an exception of `kind` inside (possibly nested) exception groups."""
    if isinstance(exc, kind):
        return exc
    for inner in getattr(exc, "exceptions", ()):
        found = _find_exception(inner, kind)
        if found is not None:
            return found
    return None


@dataclass
class _PendingElicitation:
    """An approval question that went out in an `input_required` result."""

    digest: str
    tool: str
    redacted_arguments: Any
    rule: str
    started: float
    expires: float


class GuardrailProxy:
    """Applies the policy to tool calls and forwards the ones that pass."""

    def __init__(
        self,
        *,
        upstream: Upstream,
        tools: Sequence[types.Tool],
        policy: Policy,
        audit: AuditLog,
        redact: Callable[[Any], Any],
    ) -> None:
        self._upstream = upstream
        self._policy = policy
        self._audit = audit
        self._redact = redact
        # The tool list is fixed here, at startup. Policy decisions use the
        # annotations captured now, so an upstream cannot add a tool or
        # relabel one as read-only part-way through a session.
        self._tool_list = list(tools)
        self._tools = {tool.name: tool for tool in self._tool_list}
        self._file_approver: Optional[FileApprover] = None
        if policy.approval.mode == "file":
            self._file_approver = FileApprover(
                policy.approval.directory,
                timeout_seconds=policy.approval.timeout_seconds,
                poll_interval_seconds=policy.approval.poll_interval_seconds,
            )
            FileApprover.prepare_directory(self._file_approver.directory)
        self._pending_elicitations: dict[str, _PendingElicitation] = {}
        self._in_flight = 0
        self._stop = anyio.Event()
        self._fatal: Optional[tuple[int, str]] = None

    # -- startup -----------------------------------------------------------

    def describe(self) -> list[str]:
        """Startup summary for the operator: what the policy does to these tools."""
        counts = {action: 0 for action in Action}
        for tool in self._tool_list:
            counts[self._policy.decide(tool.name, tool.annotations).action] += 1
        info = self._upstream.server_info
        lines = [
            f"upstream '{info.name}' {info.version}: {len(self._tool_list)} tools "
            f"({counts[Action.ALLOW]} allow, {counts[Action.REQUIRE_APPROVAL]} require approval, "
            f"{counts[Action.DENY]} deny); approval mode: {self._policy.approval.mode}"
        ]
        for name in self._policy.tools:
            if name not in self._tools:
                lines.append(
                    f"warning: the policy has a rule for '{name}', but the upstream has no tool by that name"
                )
        return lines

    def build_server(self) -> Server:
        info = self._upstream.server_info
        return Server(
            "mcp-guardrail-proxy",
            version=__version__,
            title=f"{info.title or info.name} (via mcp-guardrail-proxy)",
            instructions=self._upstream.instructions,
            on_list_tools=self._on_list_tools,
            on_call_tool=self._on_call_tool,
        )

    async def serve(self) -> int:
        """Serve the client over stdio until it disconnects or something fatal happens."""
        server = self.build_server()
        async with anyio.create_task_group() as tg:
            tg.start_soon(self._watch_upstream)
            tg.start_soon(self._stop_when_fatal, tg.cancel_scope)
            async with stdio_server(stdin=_WireInput()) as (read_stream, write_stream):  # type: ignore[arg-type]
                await server.run(read_stream, write_stream, server.create_initialization_options())
            tg.cancel_scope.cancel()
        if self._fatal is None:
            return EXIT_OK
        code, message = self._fatal
        log(f"{message}; exiting with status {code}")
        return code

    async def _watch_upstream(self) -> None:
        await self._upstream.closed.wait()
        self._fail(
            EXIT_UPSTREAM_LOST,
            "the upstream server exited or closed its connection (its own error output, if any, is above)",
        )

    async def _stop_when_fatal(self, scope: anyio.CancelScope) -> None:
        await self._stop.wait()
        # Calls that were in flight fail fast once the cause is known; let
        # their error results reach the client before the wire goes away.
        with anyio.move_on_after(_SHUTDOWN_GRACE_SECONDS):
            while self._in_flight:
                await anyio.sleep(0.01)
            await anyio.sleep(0.05)
        scope.cancel()

    def _fail(self, code: int, message: str) -> None:
        if self._fatal is None:
            self._fatal = (code, message)
        self._stop.set()

    # -- handlers ----------------------------------------------------------

    async def _on_list_tools(
        self, ctx: ServerRequestContext, params: Optional[types.PaginatedRequestParams]
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=self._tool_list)

    async def _on_call_tool(self, ctx: ServerRequestContext, params: types.CallToolRequestParams) -> CallResult:
        self._in_flight += 1
        try:
            return await self._handle_call(ctx, params)
        except AuditError as exc:
            # A call that cannot be recorded is not one this proxy will stand
            # behind, and neither is any call after it.
            self._fail(EXIT_AUDIT, str(exc))
            return _error_result(
                "mcp-guardrail-proxy could not write its audit log and is shutting down "
                "rather than continue unaudited. The result of this call is withheld."
            )
        finally:
            self._in_flight -= 1

    async def _handle_call(self, ctx: ServerRequestContext, params: types.CallToolRequestParams) -> CallResult:
        started = time.monotonic()
        name = params.name
        arguments = params.arguments
        call_id = uuid.uuid4().hex
        self._expire_elicitations()

        tool = self._tools.get(name)
        if tool is None:
            return self._refuse(
                call_id,
                name,
                arguments,
                started,
                rule=UNKNOWN_TOOL_RULE,
                reason=(
                    f"Blocked by mcp-guardrail-proxy: '{name}' was not among the tools the upstream "
                    "server listed when the proxy started, so no policy decision exists for it. "
                    "If the upstream's tools have changed, restart the proxy to pick them up."
                ),
            )

        decision = self._policy.decide(name, tool.annotations)
        if decision.action is Action.ALLOW:
            return await self._forward(call_id, name, arguments, started, decision="allow", rule=decision.rule)
        if decision.action is Action.DENY:
            return self._refuse(
                call_id,
                name,
                arguments,
                started,
                rule=decision.rule,
                reason=f"Blocked by mcp-guardrail-proxy: policy rule '{decision.rule}' denies calls to '{name}'.",
            )

        mode = self._policy.approval.mode
        if mode == "deny":
            return self._refuse(
                call_id,
                name,
                arguments,
                started,
                rule=f"{decision.rule} (approval.mode: deny)",
                reason=(
                    f"Blocked by mcp-guardrail-proxy: policy rule '{decision.rule}' requires approval for "
                    f"'{name}', and approval.mode is 'deny', so there is nobody to ask."
                ),
            )
        if mode == "file":
            assert self._file_approver is not None
            self._record(call_id, name, arguments, started, decision="approval_requested", rule=decision.rule)
            log(f"approval needed for '{name}' (request {call_id}); waiting on {self._file_approver.directory}")
            try:
                outcome = await self._file_approver.request(
                    call_id=call_id, tool=name, arguments=self._redact(arguments)
                )
            except anyio.get_cancelled_exc_class():
                self._record(
                    call_id,
                    name,
                    arguments,
                    started,
                    decision="cancelled",
                    rule=decision.rule,
                    reason=_WITHDRAWN,
                )
                raise
            return await self._conclude(call_id, name, arguments, started, decision.rule, outcome)
        return await self._elicit(ctx, params, call_id, started, decision.rule)

    # -- elicitation -------------------------------------------------------

    async def _elicit(
        self,
        ctx: ServerRequestContext,
        params: types.CallToolRequestParams,
        call_id: str,
        started: float,
        rule: str,
    ) -> CallResult:
        """Ask for approval through the client.

        How depends on what the connection speaks. Up to protocol 2025-11-25
        the server sends an `elicitation/create` request and waits. From
        2026-07-28 servers may not send requests; the question is returned
        inside an `input_required` result and the client calls again with the
        answer.
        """
        name, arguments = params.name, params.arguments
        capabilities = ctx.session.client_capabilities
        elicitation = capabilities.elicitation if capabilities is not None else None
        # A bare `elicitation: {}` predates the form/url split and means form.
        if elicitation is None or (elicitation.form is None and elicitation.url is not None):
            return self._refuse(
                call_id,
                name,
                arguments,
                started,
                rule=f"{rule} (approval.mode: elicitation, unsupported by client)",
                reason=(
                    f"Blocked by mcp-guardrail-proxy: policy rule '{rule}' requires approval for '{name}', "
                    "approval.mode is 'elicitation', and this client did not declare support for "
                    "form elicitation. Use approval.mode 'file' with this client."
                ),
            )
        client_params = ctx.session.client_params
        client_name = client_params.client_info.name if client_params is not None else None
        timeout = self._policy.approval.timeout_seconds

        if ctx.session.can_send_request:
            self._record(call_id, name, arguments, started, decision="approval_requested", rule=rule)
            question = elicitation_params(name, self._redact(arguments))
            try:
                with anyio.fail_after(timeout):
                    answer = await ctx.session.elicit_form(
                        question.message, question.requested_schema, related_request_id=ctx.request_id
                    )
                outcome = outcome_from_elicitation(answer, client_name)
            except TimeoutError:
                outcome = ApprovalOutcome("timeout")
            except MCPError as exc:
                outcome = ApprovalOutcome("denied", None, f"the client rejected the approval prompt: {exc}")
            except anyio.get_cancelled_exc_class():
                self._record(
                    call_id,
                    name,
                    arguments,
                    started,
                    decision="cancelled",
                    rule=rule,
                    reason=_WITHDRAWN,
                )
                raise
            return await self._conclude(call_id, name, arguments, started, rule, outcome)

        # Multi-round-trip. The state sent to the client is only the random
        # id of an entry held here; the entry carries what was asked about,
        # and it is removed when used. So an answer cannot be replayed for a
        # second call, attached to different arguments, or invented without a
        # question having gone out.
        digest = _arguments_digest(name, arguments)
        answer = (params.input_responses or {}).get(ELICITATION_KEY)
        pending = self._pending_elicitations.get(params.request_state or "")
        if pending is not None and pending.digest == digest and isinstance(answer, types.ElicitResult):
            asked_id = params.request_state
            assert asked_id is not None
            del self._pending_elicitations[asked_id]
            outcome = outcome_from_elicitation(answer, client_name)
            return await self._conclude(asked_id, name, arguments, pending.started, rule, outcome)

        self._record(call_id, name, arguments, started, decision="approval_requested", rule=rule)
        redacted = self._redact(arguments)
        self._pending_elicitations[call_id] = _PendingElicitation(
            digest=digest,
            tool=name,
            redacted_arguments=redacted,
            rule=rule,
            started=started,
            expires=started + timeout,
        )
        return types.InputRequiredResult(
            input_requests={ELICITATION_KEY: types.ElicitRequest(params=elicitation_params(name, redacted))},
            request_state=call_id,
        )

    def _expire_elicitations(self) -> None:
        """Close out approval questions that were never answered in time."""
        now = time.monotonic()
        for asked_id, pending in list(self._pending_elicitations.items()):
            if pending.expires <= now:
                del self._pending_elicitations[asked_id]
                # Already redacted when the question was built.
                self._audit.record(
                    call_id=asked_id,
                    tool=pending.tool,
                    arguments=pending.redacted_arguments,
                    decision="timeout",
                    rule=pending.rule,
                    reason="no answer to the approval prompt arrived before the timeout",
                    upstream_status=NOT_CALLED,
                    latency_ms=(now - pending.started) * 1000,
                )

    # -- outcomes ----------------------------------------------------------

    async def _conclude(
        self,
        call_id: str,
        name: str,
        arguments: Optional[dict[str, Any]],
        started: float,
        rule: str,
        outcome: ApprovalOutcome,
    ) -> types.CallToolResult:
        """Act on an approval outcome: forward the call, or refuse it."""
        if outcome.approved:
            return await self._forward(
                call_id,
                name,
                arguments,
                started,
                decision="approved",
                rule=rule,
                approver=outcome.approver,
                reason=outcome.reason,
            )
        if outcome.decision == "timeout":
            reason = (
                f"Blocked by mcp-guardrail-proxy: policy rule '{rule}' requires approval for '{name}', and "
                f"none arrived within {self._policy.approval.timeout_seconds:g}s (request {call_id})."
            )
        else:
            detail = f": {outcome.reason}" if outcome.reason else ""
            by = f" by {outcome.approver}" if outcome.approver else ""
            reason = (
                f"Blocked by mcp-guardrail-proxy: policy rule '{rule}' requires approval for '{name}', and "
                f"the request was denied{by}{detail} (request {call_id})."
            )
        self._record(
            call_id,
            name,
            arguments,
            started,
            decision=outcome.decision,
            rule=rule,
            reason=outcome.reason,
            approver=outcome.approver,
        )
        return _error_result(reason)

    def _refuse(
        self,
        call_id: str,
        name: str,
        arguments: Optional[dict[str, Any]],
        started: float,
        *,
        rule: str,
        reason: str,
    ) -> types.CallToolResult:
        self._record(call_id, name, arguments, started, decision="deny", rule=rule, reason=reason)
        return _error_result(reason)

    async def _forward(
        self,
        call_id: str,
        name: str,
        arguments: Optional[dict[str, Any]],
        started: float,
        *,
        decision: str,
        rule: str,
        approver: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> types.CallToolResult:
        """Send the call upstream, record how it went, and return the result untouched."""

        def record(status: str, note: Optional[str] = reason) -> None:
            self._record(
                call_id,
                name,
                arguments,
                started,
                decision=decision,
                rule=rule,
                reason=note,
                approver=approver,
                upstream_status=status,
            )

        # Checked before the call leaves, not only after: once forwarded, a
        # write cannot be taken back for want of somewhere to record it.
        self._audit.ensure_writable()
        try:
            result = await self._upstream.call_tool(name, arguments)
        except MCPError as exc:
            if exc.error.code == types.CONNECTION_CLOSED or self._upstream.closed.is_set():
                record("connection_lost", "the upstream server exited before answering")
                self._fail(
                    EXIT_UPSTREAM_LOST,
                    "the upstream server exited or closed its connection (its own error output, if any, is above)",
                )
                return _error_result(
                    f"The upstream MCP server exited before answering the call to '{name}'. "
                    "mcp-guardrail-proxy is shutting down; whether the call took effect is unknown. "
                    "Restart the server to continue."
                )
            # A protocol-level error from the upstream (bad arguments, a tool
            # it no longer has). Passed on as the same error the client would
            # have received from the upstream directly.
            record("protocol_error", f"upstream error {exc.error.code}: {exc.error.message}")
            raise
        except anyio.get_cancelled_exc_class():
            record("cancelled", "the call was cancelled after it was forwarded; its effect is unknown")
            raise
        except Exception as exc:
            record("invalid_response", f"{type(exc).__name__}: the upstream's answer was not a valid tool result")
            return _error_result(
                f"The upstream MCP server answered the call to '{name}' with something that is not a "
                "valid tool result, so mcp-guardrail-proxy could not pass it on."
            )
        record("error" if result.is_error else "ok")
        return result

    def _record(
        self,
        call_id: str,
        name: str,
        arguments: Any,
        started: float,
        *,
        decision: str,
        rule: str,
        reason: Optional[str] = None,
        approver: Optional[str] = None,
        upstream_status: str = NOT_CALLED,
    ) -> None:
        self._audit.record(
            call_id=call_id,
            tool=name,
            arguments=arguments,
            decision=decision,
            rule=rule,
            reason=reason,
            approver=approver,
            upstream_status=upstream_status,
            latency_ms=(time.monotonic() - started) * 1000,
        )


async def run_proxy(
    command: Sequence[str],
    policy: Policy,
    audit: AuditLog,
    redact: Callable[[Any], Any],
    *,
    startup_timeout: float = 30.0,
) -> int:
    """Start the upstream, discover its tools, and serve until done. Returns the exit status."""
    try:
        async with open_upstream(command, startup_timeout=startup_timeout) as upstream:
            try:
                with anyio.fail_after(startup_timeout):
                    tools = await upstream.list_tools()
            except TimeoutError:
                raise UpstreamError(f"the upstream did not answer tools/list within {startup_timeout:g}s") from None
            except MCPError as exc:
                raise UpstreamError(f"the upstream failed tools/list: {exc}") from exc
            proxy = GuardrailProxy(upstream=upstream, tools=tools, policy=policy, audit=audit, redact=redact)
            for line in proxy.describe():
                log(line)
            return await proxy.serve()
    except Exception as exc:
        failure = _find_exception(exc, UpstreamError)
        if failure is None:
            raise
        log(f"error: {failure}")
        return EXIT_UPSTREAM_START
