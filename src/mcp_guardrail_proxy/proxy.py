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
from typing import Any, Awaitable, Callable, Optional, Sequence, Union

import anyio
from anyio.abc import TaskGroup
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
# The upstream_status of the line written just before a call is sent.
PENDING = "pending"
_UPSTREAM_LOST = "the upstream server exited or closed its connection"
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


class _OutcomeNotRecorded(AuditError):
    """The audit log failed after the call had already gone to the upstream."""


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
        self._tasks: Optional[TaskGroup] = None
        # One scope per call currently waiting on a human.
        self._approval_waits: set[anyio.CancelScope] = set()
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
        try:
            async with anyio.create_task_group() as tg:
                self._tasks = tg
                tg.start_soon(self._watch_upstream)
                tg.start_soon(self._stop_when_fatal, tg.cancel_scope)
                async with stdio_server(stdin=_WireInput()) as (read_stream, write_stream):  # type: ignore[arg-type]
                    await server.run(read_stream, write_stream, server.create_initialization_options())
                tg.cancel_scope.cancel()
        finally:
            self._tasks = None
            self._abandon_elicitations()
        if self._fatal is None:
            return EXIT_OK
        code, message = self._fatal
        hint = " (its own error output, if any, is above)" if code == EXIT_UPSTREAM_LOST else ""
        log(f"{message}{hint}; exiting with status {code}")
        return code

    async def _watch_upstream(self) -> None:
        await self._upstream.closed.wait()
        self._fail(EXIT_UPSTREAM_LOST, _UPSTREAM_LOST)

    async def _stop_when_fatal(self, scope: anyio.CancelScope) -> None:
        await self._stop.wait()
        # A call held for approval would otherwise sit out the grace period
        # and be cut off without an answer.
        for wait in list(self._approval_waits):
            wait.cancel()
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
            if isinstance(exc, _OutcomeNotRecorded):
                return _error_result(
                    "mcp-guardrail-proxy could not write its audit log and is shutting down rather "
                    f"than continue unaudited. The call to '{params.name}' was forwarded to the upstream "
                    "before the log failed and may have taken effect; its result is withheld."
                )
            return _error_result(
                "mcp-guardrail-proxy could not write its audit log and is shutting down "
                "rather than continue unaudited. The call was not forwarded."
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
            approver = self._file_approver
            assert approver is not None

            async def ask_in_directory() -> ApprovalOutcome:
                log(f"approval needed for '{name}' (request {call_id}); waiting on {approver.directory}")
                return await approver.request(call_id=call_id, tool=name, arguments=self._redact(arguments))

            return await self._hold(call_id, name, arguments, started, decision.rule, ask_in_directory)
        return await self._elicit(ctx, params, call_id, started, decision.rule)

    async def _hold(
        self,
        call_id: str,
        name: str,
        arguments: Optional[dict[str, Any]],
        started: float,
        rule: str,
        ask: Callable[[], Awaitable[ApprovalOutcome]],
    ) -> types.CallToolResult:
        """Hold a call until `ask` comes back with an answer, then act on it.

        The wait ends early in two ways, and they are told apart. The client
        withdrawing the call arrives as cancellation from outside and is
        re-raised. The proxy starting to stop cancels only this wait (see
        `_stop_when_fatal`), so the handler is still running and can answer
        the call: a held call is in flight as much as a forwarded one, and it
        is owed a reason instead of a dropped connection.
        """
        self._record(call_id, name, arguments, started, decision="approval_requested", rule=rule)
        outcome: Optional[ApprovalOutcome] = None
        try:
            with anyio.CancelScope() as wait:
                self._approval_waits.add(wait)
                if self._stop.is_set():
                    wait.cancel()
                try:
                    outcome = await ask()
                except Exception as exc:
                    outcome = self._approval_failed(name, call_id, exc)
                finally:
                    self._approval_waits.discard(wait)
        except anyio.get_cancelled_exc_class():
            self._record(call_id, name, arguments, started, decision="cancelled", rule=rule, reason=_WITHDRAWN)
            raise
        if outcome is None:
            return self._stopped_while_held(call_id, name, arguments, started, rule)
        return await self._conclude(call_id, name, arguments, started, rule, outcome)

    def _stopped_while_held(
        self, call_id: str, name: str, arguments: Optional[dict[str, Any]], started: float, rule: str
    ) -> types.CallToolResult:
        code, cause = self._fatal if self._fatal is not None else (EXIT_OK, "the proxy is stopping")
        self._record(
            call_id,
            name,
            arguments,
            started,
            decision="cancelled",
            rule=rule,
            reason=f"approval was still pending when the proxy began to stop: {cause}",
        )
        if code == EXIT_UPSTREAM_LOST:
            return _error_result(
                f"The upstream MCP server exited while the call to '{name}' was waiting for approval, so "
                "the call was not forwarded. mcp-guardrail-proxy is shutting down. Restart the server to continue."
            )
        return _error_result(
            f"mcp-guardrail-proxy is shutting down ({cause}). The call to '{name}' was waiting for "
            "approval and was not forwarded."
        )

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

            async def ask_through_client() -> ApprovalOutcome:
                question = elicitation_params(name, self._redact(arguments))
                try:
                    with anyio.fail_after(timeout):
                        answer = await ctx.session.elicit_form(
                            question.message, question.requested_schema, related_request_id=ctx.request_id
                        )
                except TimeoutError:
                    return ApprovalOutcome("timeout")
                except MCPError as exc:
                    # The code only, for the same reason as an upstream error's
                    # message: the text belongs to the other side.
                    return ApprovalOutcome(
                        "denied",
                        None,
                        f"the client answered the approval prompt with JSON-RPC error {exc.error.code}",
                    )
                # An answer that is not an elicitation result at all raises
                # out of elicit_form, and is a failed request to `_hold`.
                return outcome_from_elicitation(answer, client_name)

            return await self._hold(call_id, name, arguments, started, rule, ask_through_client)

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
        # Nothing obliges the client to call again, so the question's timeout
        # cannot wait for a request to hang it on.
        assert self._tasks is not None
        self._tasks.start_soon(self._expire_elicitations_after, timeout)
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

    async def _expire_elicitations_after(self, delay: float) -> None:
        await anyio.sleep(delay)
        try:
            self._expire_elicitations()
        except AuditError as exc:
            self._fail(EXIT_AUDIT, str(exc))

    def _abandon_elicitations(self) -> None:
        """On the way out: give every question still open a closing line."""
        now = time.monotonic()
        try:
            for asked_id, pending in list(self._pending_elicitations.items()):
                del self._pending_elicitations[asked_id]
                self._audit.record(
                    call_id=asked_id,
                    tool=pending.tool,
                    arguments=pending.redacted_arguments,
                    decision="cancelled",
                    rule=pending.rule,
                    reason="the session ended before the approval prompt was answered",
                    upstream_status=NOT_CALLED,
                    latency_ms=(now - pending.started) * 1000,
                )
        except AuditError as exc:
            self._fail(EXIT_AUDIT, str(exc))

    # -- outcomes ----------------------------------------------------------

    def _approval_failed(self, name: str, call_id: str, exc: Exception) -> ApprovalOutcome:
        """Asking for approval broke. That is a denial with a closing line, not a crashed call.

        Left alone, the exception would end the call as a protocol error
        carrying its raw text (a local path, for a missing approvals
        directory) and leave the log at `approval_requested`. The detail goes
        to stderr for the operator; the client and the log get the kind of
        failure only.
        """
        log(f"approval for '{name}' (request {call_id}) could not be obtained: {type(exc).__name__}: {exc}")
        return ApprovalOutcome("denied", None, f"approval could not be obtained ({type(exc).__name__})")

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
        """Send the call upstream, record how it went, and return the result untouched.

        Two lines per forwarded call: `pending` before it leaves, then the
        outcome. The first is the only one that can be relied on to exist. A
        proxy that is killed, or whose disk fills, while the upstream is
        working cannot write anything afterwards, and by then the call cannot
        be taken back. Checking that the log can be opened is not enough,
        because a full disk still opens files, so the guard is the write
        itself: if it fails, nothing has been sent.
        """

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

        def record_outcome(status: str, note: Optional[str] = reason) -> None:
            try:
                record(status, note)
            except AuditError as exc:
                raise _OutcomeNotRecorded(str(exc)) from exc

        record(PENDING)
        try:
            result = await self._upstream.call_tool(name, arguments)
        except MCPError as exc:
            if exc.error.code == types.CONNECTION_CLOSED or self._upstream.closed.is_set():
                record_outcome("connection_lost", "the upstream server exited before answering")
                self._fail(EXIT_UPSTREAM_LOST, _UPSTREAM_LOST)
                return _error_result(
                    f"The upstream MCP server exited before answering the call to '{name}'. "
                    "mcp-guardrail-proxy is shutting down; whether the call took effect is unknown. "
                    "Restart the server to continue."
                )
            # A protocol-level error from the upstream (bad arguments, a tool
            # it no longer has). Passed on as the same error the client would
            # have received from the upstream directly. Only the code is
            # logged: the message is the upstream's own text, and a validator
            # that quotes the input it rejected would carry a redacted
            # argument into the log through this field.
            record_outcome("protocol_error", f"the upstream answered with JSON-RPC error {exc.error.code}")
            raise
        except anyio.get_cancelled_exc_class():
            try:
                record("cancelled", "the call was cancelled after it was forwarded; its effect is unknown")
            except AuditError as exc:
                # The cancellation still has to propagate; there is no result
                # left to carry the news, so it goes to the exit status.
                self._fail(EXIT_AUDIT, str(exc))
            raise
        except Exception as exc:
            record_outcome(
                "invalid_response", f"{type(exc).__name__}: the upstream's answer was not a valid tool result"
            )
            return _error_result(
                f"The upstream MCP server answered the call to '{name}' with something that is not a "
                "valid tool result, so mcp-guardrail-proxy could not pass it on."
            )
        record_outcome("error" if result.is_error else "ok")
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
