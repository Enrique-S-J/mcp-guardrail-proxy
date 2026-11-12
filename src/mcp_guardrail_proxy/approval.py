"""Approval backends: how a `require_approval` decision gets an answer.

Three modes, selected by `approval.mode` in the policy:

- `deny`: there is nobody to ask, so the call is refused. Handled by the
  proxy directly; no request is ever created.
- `file`: a pending request is written to a directory and the proxy waits for
  a matching `<id>.approved` or `<id>.denied` file. Works with every client,
  because the answer never travels over MCP.
- `elicitation`: the question is put to the human through the MCP client.
  This module holds the question and how its answer is read; the proxy sends
  it, because how it is sent depends on the protocol version the client speaks.

This module also provides the `mcp-guardrail-approve` command.
"""

from __future__ import annotations

import argparse
import getpass
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

import anyio
from mcp import types

from .policy import PolicyError, load_policy

APPROVED_SUFFIX = ".approved"
DENIED_SUFFIX = ".denied"
PENDING_SUFFIX = ".json"

# Request ids are uuid4().hex. The helper accepts a unique prefix of one.
_ID_RE = re.compile(r"[0-9a-f]{32}")
_ID_PREFIX_RE = re.compile(r"[0-9a-f]{6,32}")


@dataclass(frozen=True)
class ApprovalOutcome:
    """The answer to an approval request."""

    decision: str  # "approved", "denied", or "timeout"
    approver: Optional[str] = None
    reason: Optional[str] = None

    @property
    def approved(self) -> bool:
        return self.decision == "approved"


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def _expiry(body: Any) -> Optional[float]:
    """When a pending request stops being waited on, as epoch seconds, if it says."""
    try:
        return datetime.fromisoformat(body["expires_at"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON so that a reader sees the whole file or no file."""
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    os.replace(tmp, path)


def _read_decision_file(path: Path) -> dict[str, Any]:
    """Read the optional JSON body of a decision file.

    The file's existence is the decision. A body is optional so that
    `touch <id>.approved` works; anything unreadable is treated as empty.
    """
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


def _optional_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


class FileApprover:
    """Approval by files in a directory.

    A request is `<id>.json`; the answer is `<id>.approved` or `<id>.denied`
    appearing next to it. Whoever can write to the directory can approve, so
    it must not be writable by the agent whose calls are being gated.
    """

    def __init__(self, directory: Path, *, timeout_seconds: float, poll_interval_seconds: float) -> None:
        self.directory = Path(directory).expanduser().resolve()
        self.timeout_seconds = timeout_seconds
        self.poll_interval_seconds = poll_interval_seconds

    @staticmethod
    def prepare_directory(directory: Path) -> None:
        """Create the approvals directory, private to the current user, and check it is usable."""
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not os.access(directory, os.W_OK | os.X_OK):
            raise PermissionError(13, "Permission denied", str(directory))

    @staticmethod
    def sweep(directory: Path) -> int:
        """Remove what an earlier run left behind, and return how many files went.

        A proxy that is killed cannot tidy up after itself. Two kinds of file
        are certainly dead: a request past its expiry, with any answer to it
        (a live proxy removes its request when the wait ends), and an answer
        with no request beside it (a waiting proxy's request is on disk for as
        long as it waits). Neither test depends on who wrote the file, so this
        is safe when several proxies share one directory. A request that has
        not expired yet is left alone: from here it looks the same as one a
        running proxy is waiting on.
        """
        now = time.time()
        dead: list[Path] = []
        for path in directory.iterdir():
            if not _ID_RE.fullmatch(path.stem):
                continue
            if path.suffix == PENDING_SUFFIX:
                try:
                    expiry = _expiry(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    continue
                if expiry is not None and expiry < now:
                    dead += [path, path.with_suffix(APPROVED_SUFFIX), path.with_suffix(DENIED_SUFFIX)]
            elif path.suffix in (APPROVED_SUFFIX, DENIED_SUFFIX) and not path.with_suffix(PENDING_SUFFIX).exists():
                dead.append(path)
        removed = 0
        for path in dict.fromkeys(dead):
            try:
                path.unlink()
            except OSError:
                continue
            removed += 1
        return removed

    def pending_path(self, call_id: str) -> Path:
        return self.directory / f"{call_id}{PENDING_SUFFIX}"

    async def request(self, *, call_id: str, tool: str, arguments: Any) -> ApprovalOutcome:
        """Write a pending request and wait for its answer.

        `arguments` must already be redacted: the request is written to disk
        for a human to read, under the same rule as the audit log.
        """
        now = time.time()
        pending = self.pending_path(call_id)
        approved = self.directory / f"{call_id}{APPROVED_SUFFIX}"
        denied = self.directory / f"{call_id}{DENIED_SUFFIX}"
        _write_atomic(
            pending,
            {
                "id": call_id,
                "tool": tool,
                "arguments": arguments,
                "requested_at": _utc(now),
                # Rounded up to the second it is written in. The approve
                # command refuses a request once this has passed, so it may
                # err late but must never be earlier than the real deadline.
                "expires_at": _utc(math.ceil(now + self.timeout_seconds)),
            },
        )
        try:
            with anyio.move_on_after(self.timeout_seconds):
                while True:
                    # A denial wins if both files exist.
                    if denied.exists():
                        body = _read_decision_file(denied)
                        return ApprovalOutcome(
                            "denied", _optional_str(body.get("approver")), _optional_str(body.get("reason"))
                        )
                    if approved.exists():
                        body = _read_decision_file(approved)
                        return ApprovalOutcome(
                            "approved", _optional_str(body.get("approver")), _optional_str(body.get("reason"))
                        )
                    await anyio.sleep(self.poll_interval_seconds)
            return ApprovalOutcome("timeout")
        finally:
            # Also runs when the client cancels the call mid-wait. Removing the
            # request means a late answer finds nothing to attach to.
            for leftover in (pending, approved, denied):
                try:
                    leftover.unlink()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Elicitation
# ---------------------------------------------------------------------------

# Key of the single input request in the multi-round-trip (2026-07-28) flow,
# and of the single field in the form.
ELICITATION_KEY = "approval"
ELICITATION_FIELD = "approve"

ELICITATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        ELICITATION_FIELD: {
            "type": "boolean",
            "title": "Approve this tool call",
            "description": "True forwards the call to the upstream server. Anything else blocks it.",
        }
    },
    "required": [ELICITATION_FIELD],
}


def elicitation_message(tool: str, redacted_arguments: Any) -> str:
    """The question shown to the human. Arguments are shown redacted."""
    shown = json.dumps(redacted_arguments, indent=2, ensure_ascii=True, default=str)
    return (
        f"The tool '{tool}' is not marked read-only and the proxy policy requires approval "
        f"before it runs.\n\nArguments:\n{shown}\n\nApprove this call?"
    )


def elicitation_params(tool: str, redacted_arguments: Any) -> types.ElicitRequestFormParams:
    return types.ElicitRequestFormParams(
        message=elicitation_message(tool, redacted_arguments),
        requested_schema=ELICITATION_SCHEMA,
    )


def outcome_from_elicitation(result: types.ElicitResult, client_name: Optional[str]) -> ApprovalOutcome:
    """Read an elicitation answer. Only an explicit accept with approve=true approves.

    The approver recorded is the client that relayed the answer. The proxy
    cannot see who, if anyone, was at the keyboard.
    """
    approver = f"elicitation:{client_name}" if client_name else "elicitation"
    if result.action == "accept" and result.content is not None and result.content.get(ELICITATION_FIELD) is True:
        return ApprovalOutcome("approved", approver)
    if result.action == "accept":
        return ApprovalOutcome("denied", approver, "the approval form was submitted without approve=true")
    return ApprovalOutcome("denied", approver, f"the approval prompt was answered with '{result.action}'")


# ---------------------------------------------------------------------------
# mcp-guardrail-approve
# ---------------------------------------------------------------------------


def _find_pending(directory: Path, prefix: str) -> list[Path]:
    return sorted(
        path
        for path in directory.glob(f"*{PENDING_SUFFIX}")
        if _ID_RE.fullmatch(path.stem) and path.stem.startswith(prefix)
    )


def _list_pending(directory: Path) -> int:
    pending = _find_pending(directory, "")
    if not pending:
        print(f"No pending approval requests in {directory}")
        return 0
    now = time.time()
    for path in pending:
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(body, dict):
            continue
        expiry = _expiry(body)
        if expiry is not None and expiry < now:
            when = f"EXPIRED {body['expires_at']} (left behind by a proxy that is no longer waiting)"
        else:
            when = f"expires {body.get('expires_at', '?')}"
        print(f"{body.get('id', path.stem)}  {body.get('tool', '?')}  {when}")
        print(f"    arguments: {json.dumps(body.get('arguments'), ensure_ascii=True)}")
    return 0


def approve_main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for `mcp-guardrail-approve`."""
    parser = argparse.ArgumentParser(
        prog="mcp-guardrail-approve",
        description="Approve or deny a tool call that mcp-guardrail-proxy is holding (approval.mode: file).",
    )
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--dir", type=Path, help="approvals directory (default: ./approvals)")
    where.add_argument("--policy", type=Path, help="read the approvals directory from this policy file")
    parser.add_argument("--list", action="store_true", help="list pending requests and exit")
    parser.add_argument("--deny", action="store_true", help="deny the request instead of approving it")
    parser.add_argument("--reason", help="free-text reason, recorded in the audit log")
    parser.add_argument("--approver", help="who is deciding (default: the current OS user)")
    parser.add_argument("id", nargs="?", help="request id, or a unique prefix of at least 6 characters")
    args = parser.parse_args(argv)

    if args.policy is not None:
        try:
            directory = load_policy(args.policy).approval.directory
        except PolicyError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
    else:
        directory = (args.dir or Path("approvals")).expanduser()
    # Resolved before anything is compared against it or joined onto it.
    directory = directory.resolve()
    if not directory.is_dir():
        print(f"Error: approvals directory '{directory}' does not exist.", file=sys.stderr)
        return 2

    if args.list:
        return _list_pending(directory)
    if args.id is None:
        parser.error("a request id is required (or use --list)")
    if not _ID_PREFIX_RE.fullmatch(args.id):
        # Also what keeps a crafted id from naming a path outside the directory.
        print(
            f"Error: '{args.id}' is not a request id. Ids are 32 hex characters; "
            "a unique prefix of at least 6 is accepted. Use --list to see pending requests.",
            file=sys.stderr,
        )
        return 2

    matches = _find_pending(directory, args.id)
    if not matches:
        print(
            f"Error: no pending request matching '{args.id}' in {directory}. "
            "It may have timed out or already been answered; use --list.",
            file=sys.stderr,
        )
        return 1
    if len(matches) > 1:
        print(f"Error: '{args.id}' matches {len(matches)} pending requests; give more of the id.", file=sys.stderr)
        return 1

    call_id = matches[0].stem
    # The proxy removes a request the moment it stops waiting on it. One that
    # is still here past its expiry was left by a proxy that was killed, and
    # answering it would report a decision on a call nobody is holding.
    try:
        expiry = _expiry(json.loads(matches[0].read_text(encoding="utf-8")))
    except (OSError, ValueError):
        expiry = None
    if expiry is not None and expiry < time.time():
        print(
            f"Error: request {call_id} expired at {_utc(expiry)}. The proxy that asked is no longer "
            "waiting, so there is nothing to answer; the call was not forwarded.",
            file=sys.stderr,
        )
        return 1
    suffix = DENIED_SUFFIX if args.deny else APPROVED_SUFFIX
    target = (directory / f"{call_id}{suffix}").resolve()
    if target.parent != directory:
        print(f"Error: refusing to write outside the approvals directory: {target}", file=sys.stderr)
        return 2
    try:
        approver = args.approver or getpass.getuser()
    except (OSError, KeyError):
        approver = None
    _write_atomic(
        target,
        {"approver": approver, "reason": args.reason, "decided_at": _utc(time.time())},
    )
    print(f"{'Denied' if args.deny else 'Approved'} {call_id}")
    return 0


if __name__ == "__main__":
    sys.exit(approve_main())
