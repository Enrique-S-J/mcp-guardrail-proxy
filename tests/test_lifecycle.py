"""Starting, failing, and stopping: the command line and the process's exit status.

These drive the proxy with raw JSON-RPC over a subprocess's pipes, because
the things under test are the ones an SDK client hides: how the process was
invoked, what it printed on stderr, and the status it exited with.

Exit statuses: 0 client disconnected, 2 bad configuration, 3 upstream did not
start, 4 upstream went away mid-session, 5 audit log could not be written.
"""

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from harness import FAKE_UPSTREAM, STEP_TIMEOUT, RawPeer

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
    assert [entry["decision"] for entry in ws.audit()] == ["allow"]
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


# ---------------------------------------------------------------------------
# Upstream failures
# ---------------------------------------------------------------------------


def test_an_upstream_command_that_does_not_exist_exits_3(workspace):
    ws = workspace("default: deny\n")
    result = _run_proxy(*ws.proxy_argv(upstream=[str(ws.dir / "no such program")]))
    assert result.returncode == 3
    assert "could not start the upstream command" in result.stderr


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

    (entry,) = ws.audit()
    assert (entry["decision"], entry["upstream_status"]) == ("allow", "connection_lost")


# ---------------------------------------------------------------------------
# Audit failure
# ---------------------------------------------------------------------------


def test_losing_the_audit_log_stops_forwarding_and_exits_5(workspace, raw_peers):
    """No record, no call: the write tool is not forwarded once the log cannot be appended to."""
    ws = workspace("default: allow\n")
    proxy = raw_peers(RawPeer.proxy(ws))
    proxy.initialize()
    assert proxy.request("tools/call", {"name": "get_status", "arguments": {}})["result"]["isError"] is False
    assert len(ws.audit()) == 1

    # Put a directory where the log file was. Appending now fails on any platform.
    ws.audit_path.rename(ws.dir / "audit-moved-away.jsonl")
    ws.audit_path.mkdir()

    result = proxy.request("tools/call", {"name": "send_email", "arguments": {"to": "nobody@example.test"}})["result"]
    assert result["isError"] is True
    assert "could not write its audit log and is shutting down" in result["content"][0]["text"]
    assert proxy.wait() == 5
    assert "cannot write audit log" in ws.stderr()
    assert [call["tool"] for call in ws.upstream_calls()] == ["get_status"]
