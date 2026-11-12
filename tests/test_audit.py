"""The audit writer and the redaction hook, tested directly.

That the proxy writes the right record for each kind of call, and that
redaction never reaches the forwarded arguments, is asserted over the
protocol in test_proxy.py.
"""

import copy
import json
import os
import stat
import sys
from datetime import datetime

import pytest

from mcp_guardrail_proxy.audit import REDACTED, AuditError, AuditLog, make_redactor

FIELDS = {
    "timestamp",
    "call_id",
    "tool",
    "arguments",
    "decision",
    "rule",
    "reason",
    "approver",
    "upstream_status",
    "latency_ms",
}


def _record(log: AuditLog, **overrides):
    entry = {
        "call_id": "0" * 32,
        "tool": "send_email",
        "arguments": {"to": "nobody@example.test"},
        "decision": "allow",
        "rule": "default: allow",
        "upstream_status": "ok",
        "latency_ms": 12.345,
    }
    entry.update(overrides)
    return log.record(**entry)


def _lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_each_record_is_one_json_line_with_the_documented_fields(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _record(log)
    text = (tmp_path / "audit.jsonl").read_text()
    assert text.endswith("\n") and text.count("\n") == 1
    (entry,) = _lines(tmp_path / "audit.jsonl")
    assert set(entry) == FIELDS
    assert entry["latency_ms"] == 12.3
    assert entry["approver"] is None
    # Timezone-aware UTC, so lines from different hosts sort together.
    assert datetime.fromisoformat(entry["timestamp"]).utcoffset().total_seconds() == 0


def test_records_append_and_earlier_lines_are_not_rewritten(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _record(log, tool="first")
    after_one = path.read_bytes()
    _record(log, tool="second")
    after_two = path.read_bytes()
    assert after_two.startswith(after_one)
    assert [entry["tool"] for entry in _lines(path)] == ["first", "second"]


def test_a_second_writer_on_the_same_file_appends_too(tmp_path):
    """Restarting the proxy must add to an existing log, not start it over."""
    path = tmp_path / "audit.jsonl"
    _record(AuditLog(path), tool="before_restart")
    _record(AuditLog(path), tool="after_restart")
    assert [entry["tool"] for entry in _lines(path)] == ["before_restart", "after_restart"]


def test_a_record_cannot_span_lines(tmp_path):
    """Newlines and Unicode line separators inside values stay escaped."""
    path = tmp_path / "audit.jsonl"
    _record(AuditLog(path), arguments={"body": "line one\nline two line three\r\n"})
    assert len(path.read_text().splitlines()) == 1
    assert _lines(path)[0]["arguments"]["body"] == "line one\nline two line three\r\n"


def test_redaction_reaches_every_depth():
    redact = make_redactor(["password", "token", "api_key"])
    arguments = {
        "to": "nobody@example.test",
        "password": "top-level-secret",
        "smtp": {
            "host": "mail.example.test",
            "password": "nested-secret",
            "headers": [{"name": "x", "api_key": "list-secret"}, {"token": {"value": "whole-object"}}],
        },
    }
    redacted = redact(arguments)
    assert redacted == {
        "to": "nobody@example.test",
        "password": REDACTED,
        "smtp": {
            "host": "mail.example.test",
            "password": REDACTED,
            "headers": [{"name": "x", "api_key": REDACTED}, {"token": REDACTED}],
        },
    }
    assert "secret" not in json.dumps(redacted)


def test_redaction_does_not_touch_the_original():
    """The same object is forwarded upstream straight after it is logged."""
    redact = make_redactor(["password"])
    arguments = {"smtp": {"password": "nested-secret", "tags": ["a", {"password": "deep"}]}}
    before = copy.deepcopy(arguments)
    redact(arguments)
    assert arguments == before


@pytest.mark.parametrize("key", ["api_key", "apiKey", "API_KEY", "Api-Key", "APIKEY"])
def test_redaction_ignores_case_and_separators(key):
    assert make_redactor(["api_key"])({key: "s3cret"}) == {key: REDACTED}


@pytest.mark.parametrize("key", ["max_tokens", "token_count", "access_token", "passwords"])
def test_redaction_is_an_exact_key_match_not_a_substring(key):
    """Documented behaviour: `token` does not cover `access_token`. List each field."""
    assert make_redactor(["token", "password"])({key: "value"}) == {key: "value"}


def test_the_log_applies_the_redaction_hook(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, make_redactor(["password"]))
    arguments = {"user": "someone", "auth": {"password": "hunter2"}}
    _record(log, arguments=arguments)
    assert "hunter2" not in path.read_text()
    assert _lines(path)[0]["arguments"] == {"user": "someone", "auth": {"password": REDACTED}}
    assert arguments["auth"]["password"] == "hunter2"


def test_unknown_decisions_are_refused(tmp_path):
    with pytest.raises(ValueError):
        _record(AuditLog(tmp_path / "audit.jsonl"), decision="probably_fine")


def test_ensure_writable_creates_the_file_and_missing_directories(tmp_path):
    path = tmp_path / "logs with spaces" / "nested" / "audit.jsonl"
    AuditLog(path).ensure_writable()
    assert path.exists() and path.read_text() == ""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_log_is_created_private_to_the_user(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).ensure_writable()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_an_unwritable_path_raises_a_clear_error(tmp_path):
    """A directory where the file should be: cannot be opened for append on any platform."""
    path = tmp_path / "audit.jsonl"
    path.mkdir()
    with pytest.raises(AuditError) as exc:
        AuditLog(path).ensure_writable()
    assert "cannot write audit log" in str(exc.value)
    assert str(path.resolve()) in str(exc.value)


def test_the_path_is_stored_resolved(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    assert AuditLog(link / "audit.jsonl").path == real.resolve() / "audit.jsonl"
    assert os.path.isabs(AuditLog("relative.jsonl").path)
