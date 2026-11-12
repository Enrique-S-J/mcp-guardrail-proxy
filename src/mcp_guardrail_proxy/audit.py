"""Audit log: one JSON object per line, appended and never rewritten.

Redaction happens here, on the copy that is written to disk. The arguments
forwarded to the upstream are never touched: a tool that needs a password to
do its job still receives it.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

REDACTED = "[REDACTED]"

# Decisions a line can carry. A refused call produces one line. A forwarded
# call produces two that share a call_id: one before it is sent, one with how
# it went. A call that waits for approval has approval_requested before either.
DECISIONS = frozenset(
    {"allow", "deny", "approval_requested", "approved", "denied", "timeout", "cancelled"}
)

Redactor = Callable[[Any], Any]


class AuditError(Exception):
    """The audit log could not be written."""


def _normalise(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "")


def make_redactor(fields: Iterable[str]) -> Redactor:
    """Build a redaction hook for the given key names.

    Matching is on the key, at any depth, ignoring case, underscores, and
    hyphens, so `api_key` also covers `apiKey` and `API-KEY`. It is an exact
    match on the normalised name, not a substring test: listing `token` does
    not redact `max_tokens`, and does not redact `access_token` either.
    """
    targets = frozenset(_normalise(name) for name in fields)

    def redact(value: Any) -> Any:
        # Builds a new structure rather than editing in place: the caller's
        # object is the one about to be forwarded upstream.
        if isinstance(value, dict):
            return {
                key: REDACTED
                if isinstance(key, str) and _normalise(key) in targets
                else redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return redact


def _no_redaction(value: Any) -> Any:
    return value


class AuditLog:
    """Appends audit records to a JSONL file.

    Each record is one `write` on a descriptor opened with O_APPEND, so a line
    is either wholly in the file or not there, and nothing this class does can
    alter a line already written. The file is opened per record rather than
    held open, which lets it be rotated out from under a running proxy.
    """

    def __init__(self, path: Path, redact: Optional[Redactor] = None) -> None:
        self.path = Path(path).expanduser().resolve()
        self._redact = redact or _no_redaction

    def ensure_writable(self) -> None:
        """Create the file if needed and confirm it can be opened for appending.

        Called once at startup so that a bad path stops the proxy before it
        accepts a call. It writes nothing, so it cannot notice a full disk;
        what protects a forwarded call is the record written before it leaves.
        """
        self._append(b"")

    def record(
        self,
        *,
        call_id: str,
        tool: str,
        arguments: Any,
        decision: str,
        rule: str,
        reason: Optional[str] = None,
        approver: Optional[str] = None,
        upstream_status: str,
        latency_ms: float,
    ) -> dict[str, Any]:
        """Append one record and return it as written."""
        if decision not in DECISIONS:
            raise ValueError(f"unknown audit decision {decision!r}")
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "call_id": call_id,
            "tool": tool,
            "arguments": self._redact(arguments),
            "decision": decision,
            "rule": rule,
            "reason": reason,
            "approver": approver,
            "upstream_status": upstream_status,
            "latency_ms": round(latency_ms, 1),
        }
        # ensure_ascii keeps U+2028/U+2029 escaped; some line readers split on
        # them, and a record must never span lines.
        line = json.dumps(entry, ensure_ascii=True, default=str) + "\n"
        self._append(line.encode("ascii"))
        return entry

    def _append(self, data: bytes) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # 0600: the log holds tool arguments.
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                if data and os.write(fd, data) != len(data):
                    raise OSError("short write")
            finally:
                os.close(fd)
        except OSError as exc:
            raise AuditError(
                f"cannot write audit log '{self.path}': {exc.strerror or exc}"
            ) from exc
