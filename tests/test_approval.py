"""Approval: the file backend, the mcp-guardrail-approve command, and elicitation.

All over the real protocol, against the proxy as a subprocess. For the file
backend the test plays the human: it waits for the pending request to appear
in the approvals directory, then answers it, while the tool call is in flight.
"""

import getpass
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import anyio
import pytest
from mcp import types

from harness import STEP_TIMEOUT, connect, connect_modern, wait_for

FILE_POLICY = """
default: require_approval
redact_fields: [password]
approval:
  mode: file
  directory: approvals
  timeout_seconds: {timeout}
  poll_interval_seconds: 0.05
"""

ELICIT_POLICY = """
default: require_approval
redact_fields: [password]
approval:
  mode: elicitation
  timeout_seconds: {timeout}
"""

EMAIL = {"to": "nobody@example.test", "smtp": {"host": "mail.example.test", "password": "nested-secret"}}


def _text(result) -> str:
    return result.content[0].text


def _approve_script() -> str:
    """The installed console script, next to the interpreter running the tests."""
    script = Path(sys.executable).parent / ("mcp-guardrail-approve" + (".exe" if os.name == "nt" else ""))
    assert script.exists(), f"{script} is missing; install the package (pip install -e '.[dev]')"
    return str(script)


async def _pending_request(ws) -> dict:
    """Wait for the proxy to write a pending request, and return its contents."""
    (path,) = await wait_for(lambda: list(ws.approvals_dir.glob("*.json")))
    return json.loads(path.read_text())


async def _call_and_answer(session, ws, answer, name="send_email", arguments=EMAIL):
    """Start a tool call, let `answer(pending_request)` respond once it is waiting, return the result."""
    results = []

    async def call():
        results.append(await session.call_tool(name, arguments))

    async with anyio.create_task_group() as tg:
        tg.start_soon(call)
        pending = await _pending_request(ws)
        # The call must still be waiting: nothing forwarded, no result yet.
        assert results == [] and ws.upstream_calls() == []
        await anyio.to_thread.run_sync(answer, pending)
    return results[0], pending


# ---------------------------------------------------------------------------
# File backend
# ---------------------------------------------------------------------------


async def test_file_approval_approved_forwards_the_call(workspace):
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))

    modes = {}

    def approve(pending):
        modes["directory"] = stat.S_IMODE(ws.approvals_dir.stat().st_mode)
        modes["request"] = stat.S_IMODE((ws.approvals_dir / f"{pending['id']}.json").stat().st_mode)
        (ws.approvals_dir / f"{pending['id']}.approved").write_text(json.dumps({"approver": "test-operator"}))

    async with connect(ws) as session:
        result, pending = await _call_and_answer(session, ws, approve)

    if os.name != "nt":
        # Private to the user running the proxy.
        assert modes == {"directory": 0o700, "request": 0o600}

    assert result.is_error is False
    assert _text(result).startswith("sent: ")
    assert ws.upstream_calls() == [{"tool": "send_email", "arguments": EMAIL}]

    requested, sent, approved = ws.audit()
    assert requested["decision"] == "approval_requested"
    assert requested["upstream_status"] == "not_called"
    # The approval is on record before the call leaves, and again with its outcome.
    assert (sent["decision"], sent["approver"], sent["upstream_status"]) == ("approved", "test-operator", "pending")
    assert approved["decision"] == "approved"
    assert approved["approver"] == "test-operator"
    assert approved["upstream_status"] == "ok"
    assert approved["rule"] == "default: require_approval"
    # One id ties the request file, the audit lines, and the call together.
    assert requested["call_id"] == sent["call_id"] == approved["call_id"] == pending["id"]
    # The request and the answer are cleaned up once used.
    assert list(ws.approvals_dir.iterdir()) == []


async def test_file_approval_denied_blocks_the_call(workspace):
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))

    def deny(pending):
        (ws.approvals_dir / f"{pending['id']}.denied").write_text(
            json.dumps({"approver": "test-operator", "reason": "not during the freeze"})
        )

    async with connect(ws) as session:
        result, pending = await _call_and_answer(session, ws, deny)

    assert result.is_error is True
    assert _text(result) == (
        "Blocked by mcp-guardrail-proxy: policy rule 'default: require_approval' requires approval for "
        f"'send_email', and the request was denied by test-operator: not during the freeze (request {pending['id']})."
    )
    assert ws.upstream_calls() == []
    requested, denied = ws.audit()
    assert requested["decision"] == "approval_requested"
    assert (denied["decision"], denied["approver"], denied["reason"], denied["upstream_status"]) == (
        "denied",
        "test-operator",
        "not during the freeze",
        "not_called",
    )


async def test_file_approval_times_out_and_blocks_the_call(workspace):
    ws = workspace(FILE_POLICY.format(timeout=0.4))
    async with connect(ws) as session:
        result = await session.call_tool("send_email", EMAIL)

    assert result.is_error is True
    assert "requires approval for 'send_email', and none arrived within 0.4s" in _text(result)
    assert ws.upstream_calls() == []
    requested, timed_out = ws.audit()
    assert requested["decision"] == "approval_requested"
    assert (timed_out["decision"], timed_out["upstream_status"]) == ("timeout", "not_called")
    assert timed_out["latency_ms"] >= 400
    # The expired request is gone, so a late approval has nothing to attach to.
    assert list(ws.approvals_dir.iterdir()) == []


async def test_a_denial_wins_when_both_answers_exist(workspace):
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))

    def both(pending):
        # Staged elsewhere and renamed in. The denial goes first, so no poll can
        # land between the two renames and see an approval alone.
        for suffix in ("denied", "approved"):
            staged = ws.dir / f"staged.{suffix}"
            staged.write_text("{}")
            staged.rename(ws.approvals_dir / f"{pending['id']}.{suffix}")

    async with connect(ws) as session:
        result, _ = await _call_and_answer(session, ws, both)
    assert result.is_error is True
    assert ws.upstream_calls() == []
    assert ws.audit()[-1]["decision"] == "denied"


async def test_an_empty_approval_file_is_enough(workspace):
    """`touch <id>.approved` works; there is just no approver to record."""
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))

    def touch(pending):
        (ws.approvals_dir / f"{pending['id']}.approved").touch()

    async with connect(ws) as session:
        result, _ = await _call_and_answer(session, ws, touch)
    assert result.is_error is False
    assert ws.audit()[-1]["decision"] == "approved"
    assert ws.audit()[-1]["approver"] is None


async def test_the_pending_request_on_disk_is_redacted(workspace):
    """The request file is another place arguments are written down; same rule as the log."""
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))
    seen = {}

    def inspect_then_deny(pending):
        seen["raw"] = (ws.approvals_dir / f"{pending['id']}.json").read_text()
        (ws.approvals_dir / f"{pending['id']}.denied").touch()

    async with connect(ws) as session:
        _, pending = await _call_and_answer(session, ws, inspect_then_deny)

    assert "nested-secret" not in seen["raw"]
    assert pending["tool"] == "send_email"
    assert pending["arguments"] == {
        "to": "nobody@example.test",
        "smtp": {"host": "mail.example.test", "password": "[REDACTED]"},
    }
    assert set(pending) == {"id", "tool", "arguments", "requested_at", "expires_at"}
    assert "nested-secret" not in ws.audit_path.read_text()


async def test_read_only_tools_do_not_wait_for_approval(workspace):
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))
    async with connect(ws) as session:
        result = await session.call_tool("get_status", {})
    assert result.is_error is False
    assert [(entry["decision"], entry["upstream_status"]) for entry in ws.audit()] == [
        ("allow", "pending"),
        ("allow", "ok"),
    ]


async def test_cancelling_a_call_that_is_awaiting_approval_is_recorded(workspace):
    """The client gives up first. The wait ends, the request is withdrawn, and the log says why."""
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))
    async with connect(ws) as session:
        async with anyio.create_task_group() as tg:
            tg.start_soon(session.call_tool, "send_email", EMAIL)
            await _pending_request(ws)
            tg.cancel_scope.cancel()
        await wait_for(lambda: len(ws.audit()) == 2)

    requested, cancelled = ws.audit()
    assert requested["decision"] == "approval_requested"
    assert cancelled["decision"] == "cancelled"
    assert cancelled["call_id"] == requested["call_id"]
    assert ws.upstream_calls() == []
    assert list(ws.approvals_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# mcp-guardrail-approve
# ---------------------------------------------------------------------------


def _run_approve(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([_approve_script(), *args], capture_output=True, text=True, timeout=STEP_TIMEOUT)


async def test_the_approve_command_approves_a_pending_call(workspace):
    """The installed console script, run the way an operator would run it."""
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))
    outputs = {}

    def approve(pending):
        outputs["list"] = _run_approve("--dir", str(ws.approvals_dir), "--list")
        outputs["approve"] = _run_approve("--dir", str(ws.approvals_dir), pending["id"][:8])

    async with connect(ws) as session:
        result, pending = await _call_and_answer(session, ws, approve)

    assert outputs["list"].returncode == 0
    assert pending["id"] in outputs["list"].stdout
    assert "send_email" in outputs["list"].stdout
    assert "[REDACTED]" in outputs["list"].stdout and "nested-secret" not in outputs["list"].stdout
    assert outputs["approve"].returncode == 0
    assert outputs["approve"].stdout.strip() == f"Approved {pending['id']}"

    assert result.is_error is False
    assert ws.upstream_calls() == [{"tool": "send_email", "arguments": EMAIL}]
    assert ws.audit()[-1]["decision"] == "approved"
    assert ws.audit()[-1]["approver"] == getpass.getuser()


async def test_the_approve_command_can_deny_and_finds_the_directory_from_the_policy(workspace):
    ws = workspace(FILE_POLICY.format(timeout=STEP_TIMEOUT))
    outputs = {}

    def deny(pending):
        outputs["deny"] = _run_approve(
            "--policy", str(ws.policy_path), "--deny", "--reason", "wrong recipient", "--approver", "ops", pending["id"]
        )

    async with connect(ws) as session:
        result, pending = await _call_and_answer(session, ws, deny)

    assert outputs["deny"].returncode == 0, outputs["deny"].stderr
    assert outputs["deny"].stdout.strip() == f"Denied {pending['id']}"
    assert result.is_error is True
    assert "denied by ops: wrong recipient" in _text(result)
    assert ws.upstream_calls() == []
    assert (ws.audit()[-1]["decision"], ws.audit()[-1]["approver"]) == ("denied", "ops")


@pytest.mark.parametrize(
    "request_id",
    ["../../escaped", "..%2f..%2fescaped", "/tmp/escaped", "abc", "ZZZZZZZZ", "0123456789abcdef0123456789abcdef/../x"],
)
def test_the_approve_command_rejects_ids_that_are_not_ids(tmp_path, request_id):
    """Nothing is written anywhere for an id that could be read as a path."""
    approvals = tmp_path / "dir with spaces" / "approvals"
    approvals.mkdir(parents=True)
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    result = _run_approve("--dir", str(approvals), "--", request_id)
    assert result.returncode == 2
    assert "is not a request id" in result.stderr
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


def test_the_approve_command_reports_unknown_and_ambiguous_ids(tmp_path):
    approvals = tmp_path / "approvals"
    approvals.mkdir()
    for request_id in ("abcdef" + "0" * 26, "abcdef" + "1" * 26):
        (approvals / f"{request_id}.json").write_text(json.dumps({"id": request_id, "tool": "send_email"}))

    unknown = _run_approve("--dir", str(approvals), "123456")
    assert unknown.returncode == 1
    assert "no pending request matching '123456'" in unknown.stderr

    ambiguous = _run_approve("--dir", str(approvals), "abcdef")
    assert ambiguous.returncode == 1
    assert "matches 2 pending requests" in ambiguous.stderr

    exact = _run_approve("--dir", str(approvals), "abcdef0")
    assert exact.returncode == 0
    assert sorted(p.name for p in approvals.iterdir() if not p.name.endswith(".json")) == [
        "abcdef" + "0" * 26 + ".approved"
    ]


def test_the_approve_command_works_through_a_symlinked_directory(tmp_path):
    """The directory is resolved before the containment check, so a symlinked path is not mistaken for an escape."""
    real = tmp_path / "real approvals"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    request_id = "f" * 32
    (real / f"{request_id}.json").write_text(json.dumps({"id": request_id, "tool": "send_email"}))

    result = _run_approve("--dir", str(link), request_id)
    assert result.returncode == 0, result.stderr
    assert (real / f"{request_id}.approved").exists()


# ---------------------------------------------------------------------------
# Elicitation, protocol 2025-11-25: the proxy sends elicitation/create
# ---------------------------------------------------------------------------


def _answering(action, content=None):
    """An elicitation callback that gives a fixed answer and keeps what it was asked."""
    asked = []

    async def callback(context, params):
        asked.append(params)
        return types.ElicitResult(action=action, content=content)

    return callback, asked


async def test_elicitation_accepted_forwards_the_call(workspace):
    ws = workspace(ELICIT_POLICY.format(timeout=STEP_TIMEOUT))
    callback, asked = _answering("accept", {"approve": True})
    async with connect(ws, elicitation_callback=callback) as session:
        result = await session.call_tool("send_email", EMAIL)

    assert result.is_error is False
    assert ws.upstream_calls() == [{"tool": "send_email", "arguments": EMAIL}]
    (question,) = asked
    assert "'send_email'" in question.message
    assert "[REDACTED]" in question.message and "nested-secret" not in question.message
    assert question.requested_schema["properties"]["approve"]["type"] == "boolean"

    requested, sent, approved = ws.audit()
    assert requested["decision"] == "approval_requested"
    assert (sent["decision"], sent["upstream_status"]) == ("approved", "pending")
    assert approved["decision"] == "approved"
    assert approved["call_id"] == sent["call_id"] == requested["call_id"]
    # The client that relayed the answer; the proxy cannot see past it.
    assert approved["approver"] == "elicitation:mcp"
    assert approved["upstream_status"] == "ok"


@pytest.mark.parametrize(
    "action,content",
    [("decline", None), ("cancel", None), ("accept", {"approve": False}), ("accept", {}), ("accept", {"approve": "yes"})],
    ids=["decline", "cancel", "accept-false", "accept-empty", "accept-non-boolean"],
)
async def test_elicitation_anything_but_an_explicit_yes_blocks_the_call(workspace, action, content):
    ws = workspace(ELICIT_POLICY.format(timeout=STEP_TIMEOUT))
    callback, asked = _answering(action, content)
    async with connect(ws, elicitation_callback=callback) as session:
        result = await session.call_tool("send_email", EMAIL)

    assert len(asked) == 1
    assert result.is_error is True
    assert "the request was denied" in _text(result)
    assert ws.upstream_calls() == []
    assert [entry["decision"] for entry in ws.audit()] == ["approval_requested", "denied"]


async def test_elicitation_with_a_client_that_cannot_elicit_blocks_the_call(workspace):
    ws = workspace(ELICIT_POLICY.format(timeout=STEP_TIMEOUT))
    async with connect(ws) as session:  # no elicitation callback, so no capability declared
        result = await session.call_tool("send_email", EMAIL)

    assert result.is_error is True
    assert "this client did not declare support for form elicitation" in _text(result)
    assert ws.upstream_calls() == []
    (entry,) = ws.audit()
    assert entry["decision"] == "deny"
    assert entry["rule"] == "default: require_approval (approval.mode: elicitation, unsupported by client)"


async def test_elicitation_times_out_if_the_client_never_answers(workspace):
    ws = workspace(ELICIT_POLICY.format(timeout=0.4))

    async def never(context, params):
        await anyio.sleep(STEP_TIMEOUT)
        return types.ElicitResult(action="accept", content={"approve": True})

    async with connect(ws, elicitation_callback=never) as session:
        result = await session.call_tool("send_email", EMAIL)

    assert result.is_error is True
    assert "none arrived within 0.4s" in _text(result)
    assert ws.upstream_calls() == []
    assert [entry["decision"] for entry in ws.audit()] == ["approval_requested", "timeout"]


async def test_cancelling_a_call_during_elicitation_is_recorded(workspace):
    ws = workspace(ELICIT_POLICY.format(timeout=STEP_TIMEOUT))
    asked = anyio.Event()

    async def slow(context, params):
        asked.set()
        await anyio.sleep(STEP_TIMEOUT)
        return types.ElicitResult(action="accept", content={"approve": True})

    async with connect(ws, elicitation_callback=slow) as session:
        async with anyio.create_task_group() as tg:
            tg.start_soon(session.call_tool, "send_email", EMAIL)
            await asked.wait()
            tg.cancel_scope.cancel()
        await wait_for(lambda: len(ws.audit()) == 2)

    assert [entry["decision"] for entry in ws.audit()] == ["approval_requested", "cancelled"]
    assert ws.upstream_calls() == []


# ---------------------------------------------------------------------------
# Elicitation, protocol 2026-07-28: the question rides in an input_required
# result and the client calls again with the answer
# ---------------------------------------------------------------------------


async def test_elicitation_over_the_2026_protocol_forwards_an_approved_call(workspace):
    ws = workspace(ELICIT_POLICY.format(timeout=STEP_TIMEOUT))
    callback, asked = _answering("accept", {"approve": True})
    async with connect_modern(ws, elicitation_callback=callback) as client:
        assert client.protocol_version == "2026-07-28"
        result = await client.call_tool("send_email", EMAIL)

    assert result.is_error is False
    assert len(asked) == 1
    assert ws.upstream_calls() == [{"tool": "send_email", "arguments": EMAIL}]
    requested, sent, approved = ws.audit()
    assert [(entry["decision"], entry["upstream_status"]) for entry in (requested, sent, approved)] == [
        ("approval_requested", "not_called"),
        ("approved", "pending"),
        ("approved", "ok"),
    ]
    assert approved["call_id"] == sent["call_id"] == requested["call_id"]


async def test_elicitation_over_the_2026_protocol_blocks_a_declined_call(workspace):
    ws = workspace(ELICIT_POLICY.format(timeout=STEP_TIMEOUT))
    callback, _ = _answering("decline")
    async with connect_modern(ws, elicitation_callback=callback) as client:
        result = await client.call_tool("send_email", EMAIL)
    assert result.is_error is True
    assert ws.upstream_calls() == []
    assert [entry["decision"] for entry in ws.audit()] == ["approval_requested", "denied"]


async def test_an_approval_cannot_be_replayed_moved_or_invented(workspace):
    """Drive the two round trips by hand and try to get more out of one approval than one call.

    On this protocol version the approval comes back as arguments to a second
    tools/call, so the client holds everything it would need to try again.
    """
    ws = workspace(ELICIT_POLICY.format(timeout=STEP_TIMEOUT))
    yes = {"approval": types.ElicitResult(action="accept", content={"approve": True})}
    other = {"to": "someone-else@example.test"}

    async def noop(context, params):  # declares the capability; the test answers by hand
        raise AssertionError("not used")

    async with connect_modern(ws, elicitation_callback=noop) as client:
        session = client.session

        async def call(arguments, **extra):
            return await session.call_tool("send_email", arguments, allow_input_required=True, **extra)

        # An answer with no question behind it.
        invented = await call(EMAIL, input_responses=yes, request_state="0" * 32)
        assert isinstance(invented, types.InputRequiredResult)
        unasked = await call(EMAIL, input_responses=yes)
        assert isinstance(unasked, types.InputRequiredResult)
        assert ws.upstream_calls() == []

        # A real question, answered, but for different arguments than were shown.
        question = await call(EMAIL)
        assert isinstance(question, types.InputRequiredResult)
        moved = await call(other, input_responses=yes, request_state=question.request_state)
        assert isinstance(moved, types.InputRequiredResult)
        assert ws.upstream_calls() == []

        # Used as intended: forwarded once.
        approved = await call(EMAIL, input_responses=yes, request_state=question.request_state)
        assert isinstance(approved, types.CallToolResult) and approved.is_error is False
        assert ws.upstream_calls() == [{"tool": "send_email", "arguments": EMAIL}]

        # The same approval again.
        replayed = await call(EMAIL, input_responses=yes, request_state=question.request_state)
        assert isinstance(replayed, types.InputRequiredResult)
        assert ws.upstream_calls() == [{"tool": "send_email", "arguments": EMAIL}]

    # One approval, one forwarded call: the line before it left and the line with its outcome.
    assert [entry["upstream_status"] for entry in ws.audit() if entry["decision"] == "approved"] == ["pending", "ok"]


async def test_an_unanswered_question_over_the_2026_protocol_is_closed_out_as_a_timeout(workspace):
    """No second call ever arrives, so the timeout is recorded when the proxy next handles a call."""
    ws = workspace(ELICIT_POLICY.format(timeout=0.3))

    async def noop(context, params):
        raise AssertionError("not used")

    async with connect_modern(ws, elicitation_callback=noop) as client:
        question = await client.session.call_tool("send_email", EMAIL, allow_input_required=True)
        assert isinstance(question, types.InputRequiredResult)
        await anyio.sleep(0.4)
        late = await client.session.call_tool(
            "send_email",
            EMAIL,
            allow_input_required=True,
            input_responses={"approval": types.ElicitResult(action="accept", content={"approve": True})},
            request_state=question.request_state,
        )
        # Too late: the answer is not honoured, and a fresh question goes out.
        assert isinstance(late, types.InputRequiredResult)

    assert ws.upstream_calls() == []
    decisions = [(entry["decision"], entry["call_id"]) for entry in ws.audit()]
    assert decisions[0] == ("approval_requested", question.request_state)
    assert decisions[1] == ("timeout", question.request_state)
    assert decisions[2][0] == "approval_requested"
