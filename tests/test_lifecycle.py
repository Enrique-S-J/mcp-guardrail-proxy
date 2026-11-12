"""Starting, failing, and stopping: the command line and the process's exit status.

These drive the proxy with raw JSON-RPC over a subprocess's pipes, because
the things under test are the ones an SDK client hides: how the process was
invoked, what it printed on stderr, and the status it exited with.

Exit statuses: 0 client disconnected, 2 bad configuration, 3 upstream did not
start, 4 upstream went away mid-session, 5 audit log could not be written,
128 + N stopped by signal N.
"""

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from harness import FAKE_UPSTREAM, STEP_TIMEOUT, RawPeer

FAULTY_DISK_PROXY = Path(__file__).resolve().parent / "faulty_disk_proxy.py"

KILL = getattr(signal, "SIGKILL", signal.SIGTERM)


def _wait_until(predicate, timeout: float = STEP_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


def _run_proxy(*args: str) -> subprocess.CompletedProcess:
    """Run the proxy to completion with stdin already closed."""
    return subprocess.run(
        [sys.executable, "-m", "mcp_guardrail_proxy", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=STEP_TIMEOUT,
    )


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def test_console_scripts_are_installed_and_run():
    """The entry points declared in pyproject.toml, not just `python -m`."""
    bin_dir = Path(sys.executable).parent
    suffix = ".exe" if os.name == "nt" else ""
    proxy = subprocess.run(
        [str(bin_dir / f"mcp-guardrail-proxy{suffix}"), "--version"], capture_output=True, text=True, timeout=STEP_TIMEOUT
    )
    assert proxy.returncode == 0
    assert proxy.stdout.startswith("mcp-guardrail-proxy 0.")
    approve = subprocess.run(
        [str(bin_dir / f"mcp-guardrail-approve{suffix}"), "--help"], capture_output=True, text=True, timeout=STEP_TIMEOUT
    )
    assert approve.returncode == 0
    assert "Approve or deny a tool call" in approve.stdout


@pytest.mark.parametrize("separator_form", [False, True], ids=["--upstream string", "after --"])
def test_upstream_paths_with_spaces_work(workspace, raw_peers, tmp_path, separator_form):
    """Every path involved contains a space: the upstream script, its arguments, the policy, the log.

    With --upstream the command is one string and has to be split the way a
    shell would; a naive split on whitespace turns one path into two words.
    """
    spaced = tmp_path / "dir with spaces" / "more spaces"
    spaced.mkdir(parents=True)
    script = spaced / "fake upstream.py"
    shutil.copy(FAKE_UPSTREAM, script)
    ws = workspace("default: deny\n")
    ws.audit_path = spaced / "audit log.jsonl"
    ws.calls_path = spaced / "upstream calls.jsonl"
    ws.pid_path = spaced / "upstream pid"
    policy = spaced / "the policy.yaml"
    shutil.copy(ws.policy_path, policy)
    ws.policy_path = policy

    proxy = raw_peers(RawPeer.proxy(ws, upstream=ws.upstream_argv(script), separator_form=separator_form))
    proxy.initialize()
    tools, _ = proxy.list_all_tools()
    assert len(tools) == 5
    result = proxy.request("tools/call", {"name": "get_status", "arguments": {}})["result"]
    assert result["isError"] is False

    assert ws.upstream_calls() == [{"tool": "get_status", "arguments": {}}]
    assert [(entry["decision"], entry["upstream_status"]) for entry in ws.audit()] == [
        ("allow", "pending"),
        ("allow", "ok"),
    ]
    assert proxy.close() == 0


def test_a_clean_disconnect_exits_zero_and_stops_the_upstream(workspace, raw_peers):
    ws = workspace("default: deny\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    pid = ws.upstream_pid()
    assert proxy.close() == 0

    def gone():
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        return False

    _wait_until(gone)


@pytest.mark.parametrize(
    "args,message",
    [
        (["--audit", "a.jsonl"], "an upstream command is required"),
        (["--upstream", "x", "--audit", "a.jsonl", "--", "y"], "not both"),
        (["--upstream", "'unterminated", "--audit", "a.jsonl"], "not a valid command line"),
        (["--upstream", "x"], "--audit"),
    ],
    ids=["no-upstream", "both-forms", "bad-quoting", "no-audit"],
)
def test_usage_errors_exit_2(tmp_path, args, message):
    result = _run_proxy(*args)
    assert result.returncode == 2
    assert message in result.stderr


# ---------------------------------------------------------------------------
# Configuration errors
# ---------------------------------------------------------------------------


def test_an_invalid_policy_stops_the_proxy_before_the_upstream_starts(workspace):
    ws = workspace("defualt: allow\n")
    result = _run_proxy(*ws.proxy_argv())
    assert result.returncode == 2
    assert "invalid policy file" in result.stderr and "defualt" in result.stderr
    assert not ws.pid_path.exists()


def test_a_missing_policy_file_exits_2(workspace):
    ws = workspace(None)
    result = _run_proxy("--policy", str(ws.dir / "missing.yaml"), *ws.proxy_argv())
    assert result.returncode == 2
    assert "cannot read policy file" in result.stderr


def test_audit_and_policy_must_not_be_the_same_file(workspace):
    """Compared after resolving both, so a symlink to the policy is caught too."""
    ws = workspace("default: deny\n")
    alias = ws.dir / "alias.jsonl"
    alias.symlink_to(ws.policy_path)
    ws.audit_path = alias
    before = ws.policy_path.read_text()
    result = _run_proxy(*ws.proxy_argv())
    assert result.returncode == 2
    assert "--audit and --policy point at the same file" in result.stderr
    assert ws.policy_path.read_text() == before
    assert not ws.pid_path.exists()


def test_an_unwritable_audit_path_stops_the_proxy_at_startup(workspace):
    ws = workspace("default: deny\n")
    ws.audit_path.mkdir()
    result = _run_proxy(*ws.proxy_argv())
    assert result.returncode == 2
    assert "cannot write audit log" in result.stderr
    assert not ws.pid_path.exists()


def test_an_unusable_approvals_directory_stops_the_proxy_at_startup(workspace):
    """Found at startup, not when the first write tool is called."""
    ws = workspace("approval:\n  mode: file\n  directory: approvals\n")
    ws.approvals_dir.write_text("a file where the directory should be")
    result = _run_proxy(*ws.proxy_argv())
    assert result.returncode == 2
    assert "cannot use approvals directory" in result.stderr
    assert not ws.pid_path.exists()


# ---------------------------------------------------------------------------
# Upstream failures
# ---------------------------------------------------------------------------


def test_an_upstream_command_that_does_not_exist_exits_3(workspace):
    ws = workspace("default: deny\n")
    missing = str(ws.dir / "no such program")
    result = _run_proxy(*ws.proxy_argv(upstream=[missing, "--flag"]))
    assert result.returncode == 3
    assert "could not start the upstream command" in result.stderr
    # Echoed with its quoting, so a path with spaces still reads as one word.
    assert f"({shlex.quote(missing)} --flag)" in result.stderr


def test_an_upstream_that_exits_during_startup_exits_3(workspace):
    """The common mistake: an interpreter that cannot import the server's dependencies."""
    ws = workspace("default: deny\n")
    broken = [sys.executable, "-c", "import sys; sys.stderr.write('ImportError: synthetic\\n'); sys.exit(1)"]
    result = _run_proxy(*ws.proxy_argv(upstream=broken))
    assert result.returncode == 3
    assert "the upstream did not complete the MCP handshake" in result.stderr
    # The upstream's own stderr is passed through, so the real cause is visible.
    assert "ImportError: synthetic" in result.stderr


def test_an_upstream_that_never_answers_exits_3_after_the_startup_timeout(workspace):
    ws = workspace("default: deny\n")
    silent = [sys.executable, "-c", "import time; time.sleep(60)"]
    started = time.monotonic()
    result = _run_proxy("--startup-timeout", "0.5", *ws.proxy_argv(upstream=silent))
    assert result.returncode == 3
    assert "did not answer the MCP handshake within 0.5s" in result.stderr
    assert time.monotonic() - started < 20


def test_the_upstream_dying_while_idle_stops_the_proxy_with_status_4(workspace, raw_peers):
    """Killed between calls, with the client still connected and its stdin still open."""
    ws = workspace("default: deny\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    assert proxy.request("tools/call", {"name": "get_status", "arguments": {}})["result"]["isError"] is False

    os.kill(ws.upstream_pid(), KILL)

    assert proxy.wait() == 4
    assert "the upstream server exited or closed its connection" in ws.stderr()
    assert "exiting with status 4" in ws.stderr()


def test_the_upstream_dying_mid_call_fails_that_call_clearly(workspace, raw_peers):
    ws = workspace("default: allow\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    request_id = proxy.send_request("tools/call", {"name": "slow_write", "arguments": {"seconds": 60}})
    # Wait until the upstream has actually received the call before killing it.
    _wait_until(lambda: ws.upstream_calls() == [{"tool": "slow_write", "arguments": {"seconds": 60}}])

    os.kill(ws.upstream_pid(), KILL)

    result = proxy.read_response(request_id)["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "The upstream MCP server exited before answering the call to 'slow_write'" in text
    assert "whether the call took effect is unknown" in text
    assert proxy.wait() == 4

    sent, lost = ws.audit()
    assert (sent["decision"], sent["upstream_status"]) == ("allow", "pending")
    assert (lost["decision"], lost["upstream_status"]) == ("allow", "connection_lost")
    assert lost["call_id"] == sent["call_id"]


FILE_APPROVAL = "approval:\n  mode: file\n  directory: approvals\n  timeout_seconds: 60\n  poll_interval_seconds: 0.05\n"
ELICITATION_APPROVAL = "approval:\n  mode: elicitation\n  timeout_seconds: 60\n"
EMAIL = {"to": "nobody@example.test"}


def _hold_a_call(ws, proxy, mode: str) -> int:
    """Send a write call and return its request id once the proxy is waiting on a human for it."""
    proxy.initialize(capabilities={"elicitation": {}} if mode == "elicitation" else None)
    request_id = proxy.send_request("tools/call", {"name": "send_email", "arguments": EMAIL})
    if mode == "elicitation":
        proxy.read_request("elicitation/create")
    else:
        _wait_until(lambda: list(ws.approvals_dir.glob("*.json")))
    return request_id


@pytest.mark.parametrize("mode", ["file", "elicitation"])
def test_the_upstream_dying_while_a_call_awaits_approval_answers_that_call(workspace, raw_peers, mode):
    """A held call is in flight too. It gets told why it will never run, instead of a dropped connection."""
    ws = workspace(FILE_APPROVAL if mode == "file" else ELICITATION_APPROVAL)
    proxy = raw_peers(RawPeer.proxy(ws))
    request_id = _hold_a_call(ws, proxy, mode)

    os.kill(ws.upstream_pid(), KILL)

    result = proxy.read_response(request_id)["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "The upstream MCP server exited while the call to 'send_email' was waiting for approval" in text
    assert "was not forwarded" in text
    assert proxy.wait() == 4

    requested, cancelled = ws.audit()
    assert (requested["decision"], cancelled["decision"]) == ("approval_requested", "cancelled")
    assert cancelled["call_id"] == requested["call_id"]
    assert cancelled["upstream_status"] == "not_called"
    assert "the upstream server exited or closed its connection" in cancelled["reason"]
    assert ws.upstream_calls() == []
    if mode == "file":
        assert list(ws.approvals_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
STOP_SIGNALS = pytest.mark.parametrize(
    "signum,status", [(signal.SIGINT, 130), (signal.SIGTERM, 143)], ids=["SIGINT", "SIGTERM"]
)


def _process_is_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


@posix_only
@STOP_SIGNALS
def test_a_stop_signal_ends_the_proxy_promptly_and_takes_the_upstream_with_it(workspace, raw_peers, signum, status):
    """Ctrl-C or a `kill`, with the client still connected and its stdin still open."""
    ws = workspace("default: deny\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    upstream_pid = ws.upstream_pid()

    proxy.proc.send_signal(signum)

    assert proxy.wait(timeout=10) == status
    assert f"received {signum.name}; exiting with status {status}" in ws.stderr()
    assert "Traceback" not in ws.stderr()
    _wait_until(lambda: _process_is_gone(upstream_pid))


@posix_only
@STOP_SIGNALS
def test_a_stop_signal_answers_and_closes_out_a_call_awaiting_approval(workspace, raw_peers, signum, status):
    """The request must not be left in the approvals directory for someone to approve into the void."""
    ws = workspace(FILE_APPROVAL)
    proxy = raw_peers(RawPeer.proxy(ws))
    request_id = _hold_a_call(ws, proxy, "file")

    proxy.proc.send_signal(signum)

    result = proxy.read_response(request_id)["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert f"mcp-guardrail-proxy is shutting down (received {signum.name})" in text
    assert "was not forwarded" in text
    assert proxy.wait(timeout=10) == status

    requested, cancelled = ws.audit()
    assert (requested["decision"], cancelled["decision"]) == ("approval_requested", "cancelled")
    assert cancelled["call_id"] == requested["call_id"]
    assert f"received {signum.name}" in cancelled["reason"]
    assert ws.upstream_calls() == []
    assert list(ws.approvals_dir.iterdir()) == []


@posix_only
def test_a_stop_signal_closes_the_record_of_a_call_already_at_the_upstream(workspace, raw_peers):
    ws = workspace("default: allow\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    proxy.send_request("tools/call", {"name": "slow_write", "arguments": {"seconds": 60}})
    _wait_until(lambda: ws.upstream_calls() == [{"tool": "slow_write", "arguments": {"seconds": 60}}])

    proxy.proc.send_signal(signal.SIGTERM)

    assert proxy.wait(timeout=10) == 143
    sent, cancelled = ws.audit()
    assert (sent["decision"], sent["upstream_status"]) == ("allow", "pending")
    assert (cancelled["decision"], cancelled["upstream_status"]) == ("allow", "cancelled")
    assert cancelled["call_id"] == sent["call_id"]
    assert "its effect is unknown" in cancelled["reason"]


@posix_only
def test_ctrl_c_while_the_upstream_is_still_starting_exits_130_without_a_traceback(workspace, raw_peers):
    """Before the proxy is serving there is nothing to close out, but it still has to leave cleanly."""
    ws = workspace("default: deny\n")
    marker = ws.dir / "upstream-started"
    silent = [sys.executable, "-c", f"import pathlib, time; pathlib.Path({str(marker)!r}).touch(); time.sleep(60)"]
    proxy = raw_peers(RawPeer.proxy(ws, upstream=silent))
    _wait_until(marker.exists)

    proxy.proc.send_signal(signal.SIGINT)

    assert proxy.wait(timeout=10) == 130
    assert "interrupted; exiting with status 130" in ws.stderr()
    assert "Traceback" not in ws.stderr()


# ---------------------------------------------------------------------------
# Audit failure
# ---------------------------------------------------------------------------


def test_losing_the_audit_log_stops_forwarding_and_exits_5(workspace, raw_peers):
    """No record, no call: the write tool is not forwarded once the log cannot be appended to."""
    ws = workspace("default: allow\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    assert proxy.request("tools/call", {"name": "get_status", "arguments": {}})["result"]["isError"] is False
    assert len(ws.audit()) == 2

    # Put a directory where the log file was. Appending now fails on any platform.
    ws.audit_path.rename(ws.dir / "audit-moved-away.jsonl")
    ws.audit_path.mkdir()

    result = proxy.request("tools/call", {"name": "send_email", "arguments": {"to": "nobody@example.test"}})["result"]
    assert result["isError"] is True
    assert "could not write its audit log and is shutting down" in result["content"][0]["text"]
    assert proxy.wait() == 5
    assert "cannot write audit log" in ws.stderr()
    assert [call["tool"] for call in ws.upstream_calls()] == ["get_status"]


def _proxy_on_a_disk_that_can_fill(ws, raw_peers):
    """The proxy plus a switch: `fill()` makes every later write to a file fail with ENOSPC."""
    flag = ws.dir / "disk-is-full"
    proxy = raw_peers(RawPeer.proxy(ws, launcher=FAULTY_DISK_PROXY, env={"FAULTY_DISK_FLAG": str(flag)}))
    return proxy, flag.touch


def test_a_full_disk_stops_a_call_before_it_is_forwarded(workspace, raw_peers):
    """The log still opens on a full disk; only the write fails.

    So the guard has to be a real record written before the call leaves, not
    a check that the file can be opened.
    """
    ws = workspace("default: allow\n")
    proxy, fill_disk = _proxy_on_a_disk_that_can_fill(ws, raw_peers)
    proxy.initialize()
    assert proxy.request("tools/call", {"name": "get_status", "arguments": {}})["result"]["isError"] is False
    logged_before = ws.audit_path.read_bytes()

    fill_disk()

    result = proxy.request("tools/call", {"name": "delete_record", "arguments": {"record_id": "r-1"}})["result"]
    assert result["isError"] is True
    # By the upstream's own account, the delete never arrived.
    assert [call["tool"] for call in ws.upstream_calls()] == ["get_status"]
    text = result["content"][0]["text"]
    assert "could not write its audit log and is shutting down" in text
    assert "The call was not forwarded" in text
    assert proxy.wait() == 5
    assert "No space left on device" in ws.stderr()
    assert ws.audit_path.read_bytes() == logged_before


def test_a_log_failure_after_forwarding_says_the_call_may_have_taken_effect(workspace, raw_peers):
    """The disk fills while a write is at the upstream. The call is on record as sent, and the client is not told it was stopped."""
    ws = workspace("default: allow\n")
    proxy, fill_disk = _proxy_on_a_disk_that_can_fill(ws, raw_peers)
    proxy.initialize()
    request_id = proxy.send_request("tools/call", {"name": "slow_write", "arguments": {"seconds": 1}})
    _wait_until(lambda: ws.upstream_calls() == [{"tool": "slow_write", "arguments": {"seconds": 1}}])

    fill_disk()

    result = proxy.read_response(request_id)["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "'slow_write' was forwarded to the upstream" in text
    assert "may have taken effect" in text
    assert "not forwarded" not in text
    assert proxy.wait() == 5

    (sent,) = ws.audit()
    assert (sent["tool"], sent["decision"], sent["upstream_status"]) == ("slow_write", "allow", "pending")


def test_a_call_in_flight_when_the_proxy_is_killed_is_already_on_record(workspace, raw_peers):
    """A proxy that dies mid-call cannot write anything afterwards, so the record has to exist before."""
    ws = workspace("default: allow\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    proxy.send_request("tools/call", {"name": "slow_write", "arguments": {"seconds": 60}})
    _wait_until(lambda: ws.upstream_calls() == [{"tool": "slow_write", "arguments": {"seconds": 60}}])

    proxy.proc.send_signal(KILL)
    proxy.proc.wait(timeout=STEP_TIMEOUT)

    (sent,) = ws.audit()
    assert (sent["tool"], sent["decision"], sent["upstream_status"]) == ("slow_write", "allow", "pending")
    assert sent["arguments"] == {"seconds": 60}
