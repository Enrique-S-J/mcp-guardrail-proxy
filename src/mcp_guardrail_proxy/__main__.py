"""Command line entry point: `mcp-guardrail-proxy` / `python -m mcp_guardrail_proxy`.

    mcp-guardrail-proxy --upstream "python server.py" --policy policy.yaml --audit audit.jsonl
    mcp-guardrail-proxy --policy policy.yaml --audit audit.jsonl -- python server.py

The proxy speaks MCP on its own stdin/stdout and is meant to be launched by an
MCP client, with the real server's command passed to it as the upstream.
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path
from typing import Optional, Sequence

import anyio

from . import __version__
from .approval import FileApprover
from .audit import AuditError, AuditLog, make_redactor
from .policy import PolicyError, load_policy
from .proxy import EXIT_CONFIG, EXIT_INTERRUPTED, EXIT_OK, log, run_proxy


def _parse_args(argv: Sequence[str]) -> tuple[argparse.Namespace, list[str]]:
    """Parse options and work out the upstream command.

    The upstream is either one string given to --upstream, split the way a
    shell would split it, or everything after a bare `--`, taken as-is. The
    second form needs no nested quoting, which matters when a path has spaces
    and the whole thing is already inside a JSON config file.
    """
    argv = list(argv)
    trailing: list[str] = []
    if "--" in argv:
        split_at = argv.index("--")
        argv, trailing = argv[:split_at], argv[split_at + 1 :]

    parser = argparse.ArgumentParser(
        prog="mcp-guardrail-proxy",
        description="Policy and audit proxy for an MCP server. Launch it from an MCP client in place "
        "of the real server, and give it the real server's command as the upstream.",
        epilog="The upstream command can also follow a bare '--' instead of being quoted into --upstream.",
    )
    parser.add_argument(
        "--upstream",
        metavar='"CMD ARGS..."',
        help="command that starts the upstream MCP server (stdio), as one string; quote paths that contain spaces",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help="policy YAML file (default: forward read-only tools, refuse everything else)",
    )
    parser.add_argument("--audit", type=Path, required=True, help="JSONL audit log to append to")
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="how long to wait for the upstream to start and list its tools (default: 30)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if args.upstream is not None and trailing:
        parser.error("give the upstream command either with --upstream or after '--', not both")
    if args.upstream is not None:
        try:
            command = shlex.split(args.upstream)
        except ValueError as exc:
            parser.error(f"--upstream is not a valid command line: {exc}")
    else:
        command = trailing
    if not command:
        parser.error("an upstream command is required: --upstream \"CMD ARGS...\" or -- CMD ARGS...")
    if args.startup_timeout <= 0:
        parser.error("--startup-timeout must be positive")
    return args, command


def main(argv: Optional[Sequence[str]] = None) -> None:
    args, command = _parse_args(sys.argv[1:] if argv is None else argv)

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        log(f"error: {exc}")
        sys.exit(EXIT_CONFIG)

    redact = make_redactor(policy.redact_fields)
    audit = AuditLog(args.audit, redact)
    # Both sides resolved before comparing. Appending JSON lines to the policy
    # file would leave the next start with a policy that does not parse.
    if args.policy is not None and audit.path == args.policy.expanduser().resolve():
        log(f"error: --audit and --policy point at the same file ({audit.path})")
        sys.exit(EXIT_CONFIG)
    try:
        audit.ensure_writable()
    except AuditError as exc:
        log(f"error: {exc}")
        sys.exit(EXIT_CONFIG)
    if policy.approval.mode == "file":
        try:
            warnings = FileApprover.prepare_directory(policy.approval.directory)
            swept = FileApprover.sweep(policy.approval.directory)
        except OSError as exc:
            log(f"error: cannot use approvals directory '{policy.approval.directory}': {exc.strerror or exc}")
            sys.exit(EXIT_CONFIG)
        for warning in warnings:
            log(f"warning: {warning}")
        if swept:
            log(
                f"removed {swept} stale file{'s' if swept != 1 else ''} from the approvals directory "
                "(expired requests and answers to nothing, left by an earlier run)"
            )

    try:
        status = anyio.run(lambda: run_proxy(command, policy, audit, redact, startup_timeout=args.startup_timeout))
    except KeyboardInterrupt:
        # Ctrl-C while no signal receiver was listening: the upstream was
        # still starting, or the event loop has no signal support (Windows).
        # The event loop has already unwound and shut the upstream down.
        log(f"interrupted; exiting with status {EXIT_INTERRUPTED}")
        status = EXIT_INTERRUPTED
    if status == EXIT_OK:
        sys.exit(EXIT_OK)
    # A failure exit can come while the client still holds our stdin open, in
    # which case a worker thread is still parked in a blocking read of it (see
    # proxy._WireInput). Interpreter shutdown joins that thread, so a normal
    # exit would hang until the client noticed. Everything that needed closing
    # was closed on the way out of run_proxy.
    sys.stderr.flush()
    os._exit(status)


if __name__ == "__main__":
    main()
