"""Mutation check: break the source on purpose and confirm a test notices.

A test that has never failed proves nothing about the guard it is named
after. Each entry below is one deliberate breakage of the source (a denied
call forwarded anyway, a redacted value written to the log, a signal left
unhandled) paired with the tests that are supposed to catch it. The script
applies them one at a time, runs those tests, and expects a failure.

    python scripts/mutation_check.py              # all of them; several minutes
    python scripts/mutation_check.py --list
    python scripts/mutation_check.py --only redact

It edits files under src/ in place and restores each one straight after its
tests have run, including when interrupted. It refuses to start if src/ has
uncommitted changes, so that `git checkout src` is always a safe way back.

Exit status is 0 only if every mutation was caught. A mutation whose text no
longer appears in the source is reported as STALE and counts as a failure:
the list is meant to be kept in step with the code, not to shrink quietly.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "src" / "mcp_guardrail_proxy"

APPROVAL = "tests/test_approval.py::"
AUDIT = "tests/test_audit.py::"
LIFECYCLE = "tests/test_lifecycle.py::"
POLICY = "tests/test_policy.py::"
PROXY = "tests/test_proxy.py::"


@dataclass(frozen=True)
class Mutation:
    name: str
    file: str
    edits: tuple[tuple[str, str], ...]
    tests: tuple[str, ...]


def m(name: str, file: str, old: str, new: str, *tests: str, more: tuple[tuple[str, str], ...] = ()) -> Mutation:
    return Mutation(name, file, ((old, new), *more), tests)


MUTATIONS = [
    # -- policy ---------------------------------------------------------------
    m(
        "policy: a tool with no annotations is read as read-only",
        "policy.py",
        "annotations is not None and annotations.read_only_hint is True",
        "(annotations is None or annotations.read_only_hint is not False)",
        POLICY + "test_only_an_explicit_read_only_hint_passes_through",
        PROXY + "test_a_tool_without_annotations_is_treated_as_a_write",
    ),
    m(
        "policy: read-only passthrough beats an explicit rule",
        "policy.py",
        "        if explicit is not None:\n",
        "        if explicit is not None and not (annotations is not None and annotations.read_only_hint is True):\n",
        POLICY + "test_explicit_rule_beats_read_only_passthrough",
        PROXY + "test_an_explicit_deny_blocks_even_a_read_only_tool",
    ),
    m(
        "policy: duplicate keys accepted (last one wins)",
        "policy.py",
        "raw = yaml.load(text, Loader=_UniqueKeyLoader)",
        "raw = yaml.load(text, Loader=yaml.SafeLoader)",
        POLICY + "test_duplicate_keys_are_rejected",
    ),
    m(
        "policy: unknown keys ignored",
        "policy.py",
        'class Policy(BaseModel):\n    """The parsed policy file."""\n\n    model_config = ConfigDict(extra="forbid")',
        'class Policy(BaseModel):\n    """The parsed policy file."""\n\n    model_config = ConfigDict(extra="ignore")',
        POLICY + "test_invalid_policies_are_rejected_and_say_where",
        LIFECYCLE + "test_an_invalid_policy_stops_the_proxy_before_the_upstream_starts",
    ),
    m(
        "policy: relative approvals directory anchored to the working directory",
        "policy.py",
        "        directory = base_dir / directory",
        "        directory = Path.cwd() / directory",
        POLICY + "test_relative_approvals_directory_is_anchored_to_the_policy_file",
    ),
    m(
        "policy: unbounded approval timeout accepted",
        "policy.py",
        "timeout_seconds: float = Field(default=300.0, gt=0, le=86400, allow_inf_nan=False)",
        "timeout_seconds: float = Field(default=300.0, gt=0)",
        POLICY + "test_invalid_policies_are_rejected_and_say_where",
    ),
    # -- audit log ------------------------------------------------------------
    m(
        "audit: the log skips the redaction hook",
        "audit.py",
        '"arguments": self._redact(arguments),',
        '"arguments": arguments,',
        AUDIT + "test_the_log_applies_the_redaction_hook",
        PROXY + "test_secrets_are_redacted_in_the_log_but_not_in_the_forwarded_call",
        PROXY + "test_blocked_calls_are_redacted_in_the_log_too",
    ),
    m(
        "audit: redaction does not descend into lists",
        "audit.py",
        "            return [redact(item) for item in value]",
        "            return value",
        AUDIT + "test_redaction_reaches_every_depth",
        PROXY + "test_secrets_are_redacted_in_the_log_but_not_in_the_forwarded_call",
    ),
    m(
        "audit: redaction edits the caller's arguments in place",
        "audit.py",
        "            return {\n                key: REDACTED\n                if isinstance(key, str) and _normalise(key) in targets\n"
        "                else redact(item)\n                for key, item in value.items()\n            }",
        "            for key, item in list(value.items()):\n"
        "                value[key] = REDACTED if isinstance(key, str) and _normalise(key) in targets else redact(item)\n"
        "            return value",
        AUDIT + "test_redaction_does_not_touch_the_original",
        PROXY + "test_secrets_are_redacted_in_the_log_but_not_in_the_forwarded_call",
    ),
    m(
        "audit: the file is truncated on each write",
        "audit.py",
        "os.O_WRONLY | os.O_APPEND | os.O_CREAT",
        "os.O_WRONLY | os.O_TRUNC | os.O_CREAT",
        AUDIT + "test_records_append_and_earlier_lines_are_not_rewritten",
        PROXY + "test_every_line_is_valid_json_appended_in_order",
    ),
    m(
        "audit: the file is not opened for appending",
        "audit.py",
        "os.O_WRONLY | os.O_APPEND | os.O_CREAT",
        "os.O_WRONLY | os.O_CREAT",
        AUDIT + "test_records_append_and_earlier_lines_are_not_rewritten",
        AUDIT + "test_a_second_writer_on_the_same_file_appends_too",
    ),
    m(
        "audit: raw unicode line separators reach the log",
        "audit.py",
        "json.dumps(entry, ensure_ascii=True, default=str)",
        "json.dumps(entry, ensure_ascii=False, default=str)",
        AUDIT + "test_a_record_cannot_span_lines",
        more=(('line.encode("ascii")', 'line.encode("utf-8")'),),
    ),
    m(
        "audit: one descriptor held open across records",
        "audit.py",
        "            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)\n"
        "            try:\n"
        "                if data and os.write(fd, data) != len(data):\n"
        '                    raise OSError("short write")\n'
        "            finally:\n"
        "                os.close(fd)",
        '            if not hasattr(self, "_fd"):\n'
        "                self._fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)\n"
        "            if data and os.write(self._fd, data) != len(data):\n"
        '                raise OSError("short write")',
        PROXY + "test_the_log_can_be_rotated_while_the_proxy_runs",
    ),
    # -- discovery ------------------------------------------------------------
    m(
        "discovery: only the first tools/list page is read",
        "upstream.py",
        "            if not cursor:\n                return tools",
        "            if True:\n                return tools",
        PROXY + "test_tools_are_re_exposed_exactly_as_the_upstream_lists_them",
    ),
    m(
        "discovery: annotations dropped when re-exposing",
        "proxy.py",
        "return types.ListToolsResult(tools=self._tool_list)",
        'return types.ListToolsResult(tools=[t.model_copy(update={"annotations": None}) for t in self._tool_list])',
        PROXY + "test_tools_are_re_exposed_exactly_as_the_upstream_lists_them",
    ),
    m(
        "discovery: input schemas rebuilt from property types",
        "proxy.py",
        "return types.ListToolsResult(tools=self._tool_list)",
        'return types.ListToolsResult(tools=[t.model_copy(update={"input_schema": {"type": "object", "properties": '
        '{k: {"type": v.get("type", "string")} for k, v in t.input_schema.get("properties", {}).items()}}}) '
        "for t in self._tool_list])",
        PROXY + "test_tools_are_re_exposed_exactly_as_the_upstream_lists_them",
    ),
    m(
        "discovery: the unlisted-policy-rule warning is dropped",
        "proxy.py",
        "            if name not in self._tools:\n                lines.append(",
        "            if False:\n                lines.append(",
        PROXY + "test_a_policy_rule_for_a_tool_the_upstream_lacks_is_flagged_at_startup",
    ),
    m(
        "discovery: a tool name listed twice is accepted",
        "proxy.py",
        "            _require_unique_names(tools)\n",
        "",
        LIFECYCLE + "test_an_upstream_that_lists_one_tool_name_twice_exits_3",
    ),
    m(
        "discovery: an invalid tool list escapes as a traceback",
        "proxy.py",
        "            except ValidationError as exc:\n                # The SDK parses",
        "            except ZeroDivisionError as exc:\n                # The SDK parses",
        LIFECYCLE + "test_an_upstream_whose_tool_list_is_not_valid_mcp_exits_3",
    ),
    # -- policy enforcement ---------------------------------------------------
    m(
        "enforce: a denied call is forwarded anyway",
        "proxy.py",
        "        if decision.action is Action.ALLOW:\n",
        "        if decision.action in (Action.ALLOW, Action.DENY):\n",
        PROXY + "test_a_write_tool_is_blocked_by_default_deny_and_audited",
        PROXY + "test_an_explicit_deny_blocks_even_a_read_only_tool",
    ),
    m(
        "enforce: approval.mode deny forwards",
        "proxy.py",
        '        if mode == "deny":\n            return self._refuse(',
        '        if mode == "deny":\n'
        '            return await self._forward(call_id, name, arguments, started, decision="allow", rule=decision.rule)\n'
        '        if mode == "never":\n            return self._refuse(',
        PROXY + "test_without_a_policy_file_reads_pass_and_writes_are_refused",
    ),
    m(
        "enforce: an unknown tool falls through to the policy default",
        "proxy.py",
        "        if tool is None:\n            return self._refuse(",
        "        if tool is None and False:\n            return self._refuse(",
        PROXY + "test_a_tool_the_upstream_did_not_list_at_startup_is_denied",
        more=(
            (
                "decision = self._policy.decide(name, tool.annotations)\n",
                "decision = self._policy.decide(name, tool.annotations if tool else None)\n",
            ),
        ),
    ),
    m(
        "enforce: an explicit allow is honoured for a tool the upstream never listed",
        "proxy.py",
        "        tool = self._tools.get(name)\n        if tool is None:",
        "        tool = self._tools.get(name)\n        if tool is None and name in self._policy.tools:\n"
        "            tool = types.Tool(name=name, input_schema={})\n        if tool is None:",
        PROXY + "test_an_explicit_allow_does_not_reach_a_tool_the_upstream_did_not_list",
    ),
    # -- forwarding -----------------------------------------------------------
    m(
        "forward: redacted arguments are sent upstream",
        "proxy.py",
        "result = await self._upstream.call_tool(name, arguments)",
        "result = await self._upstream.call_tool(name, self._redact(arguments))",
        PROXY + "test_secrets_are_redacted_in_the_log_but_not_in_the_forwarded_call",
    ),
    m(
        "forward: the upstream's result is altered in transit",
        "proxy.py",
        '        record_outcome("error" if result.is_error else "ok")\n        return result',
        '        record_outcome("error" if result.is_error else "ok")\n        return result.model_copy(update={"meta": None})',
        PROXY + "test_a_read_only_call_returns_the_upstream_result_unchanged",
    ),
    m(
        "forward: results validated against the output schema by the proxy",
        "upstream.py",
        "        return await self._session.send_request(\n"
        "            types.CallToolRequest(params=types.CallToolRequestParams(name=name, arguments=arguments)),\n"
        "            types.CallToolResult,\n"
        "        )",
        "        return await self._session.call_tool(name, arguments)",
        PROXY + "test_a_result_that_breaks_the_upstreams_own_output_schema_is_still_passed_on",
    ),
    m(
        "forward: an upstream protocol error is rewritten as a tool result",
        "proxy.py",
        '            record_outcome("protocol_error", f"the upstream answered with JSON-RPC error {exc.error.code}")\n'
        "            raise",
        '            record_outcome("protocol_error", f"the upstream answered with JSON-RPC error {exc.error.code}")\n'
        "            return _error_result(str(exc))",
        PROXY + "test_an_upstream_protocol_error_reaches_the_client_unchanged",
    ),
    m(
        "forward: the upstream's error text is written to the log",
        "proxy.py",
        'f"the upstream answered with JSON-RPC error {exc.error.code}")',
        'f"upstream error {exc.error.code}: {exc.error.message}")',
        PROXY + "test_an_upstream_error_that_quotes_its_input_does_not_put_secrets_in_the_log",
    ),
    m(
        "forward: the upstream gets only the SDK's default environment",
        "upstream.py",
        "args=list(command[1:]), env=env)",
        "args=list(command[1:]), env=None)",
        PROXY + "test_the_upstream_inherits_the_proxys_environment",
    ),
    m(
        "forward: no record is written before the call leaves",
        "proxy.py",
        "        record(PENDING)\n",
        "",
        LIFECYCLE + "test_a_full_disk_stops_a_call_before_it_is_forwarded",
        LIFECYCLE + "test_a_call_in_flight_when_the_proxy_is_killed_is_already_on_record",
    ),
    m(
        "forward: the log is only checked for being openable before the call leaves",
        "proxy.py",
        "        record(PENDING)\n",
        "        self._audit.ensure_writable()\n",
        LIFECYCLE + "test_a_full_disk_stops_a_call_before_it_is_forwarded",
    ),
    m(
        "forward: a log failure after forwarding is reported as 'not forwarded'",
        "proxy.py",
        "                raise _OutcomeNotRecorded(str(exc)) from exc",
        "                raise",
        LIFECYCLE + "test_a_log_failure_after_forwarding_says_the_call_may_have_taken_effect",
    ),
    m(
        "forward: a call cancelled after it was forwarded gets no closing line",
        "proxy.py",
        '                record("cancelled", "the call was cancelled after it was forwarded; its effect is unknown")\n',
        "                pass\n",
        PROXY + "test_cancelling_a_call_after_it_was_forwarded_is_logged_as_cancelled",
        LIFECYCLE + "test_a_stop_signal_closes_the_record_of_a_call_already_at_the_upstream",
    ),
    m(
        "forward: an answer that is not a tool result gets no closing line",
        "proxy.py",
        "            record_outcome(\n"
        '                "invalid_response", f"{type(exc).__name__}: the upstream\'s answer was not a valid tool result"\n'
        "            )\n",
        "",
        PROXY + "test_an_upstream_answer_that_is_not_a_tool_result_is_reported_and_logged",
    ),
    # -- file approval --------------------------------------------------------
    m(
        "file approval: an approval beats a denial when both exist",
        "approval.py",
        "                    if denied.exists():",
        "                    if denied.exists() and not approved.exists():",
        APPROVAL + "test_a_denial_wins_when_both_answers_exist",
    ),
    m(
        "file approval: a denial file approves",
        "approval.py",
        '                        return ApprovalOutcome(\n                            "denied", _optional_str',
        '                        return ApprovalOutcome(\n                            "approved", _optional_str',
        APPROVAL + "test_file_approval_denied_blocks_the_call",
        APPROVAL + "test_the_approve_command_can_deny_and_finds_the_directory_from_the_policy",
    ),
    m(
        "file approval: a timeout approves",
        "proxy.py",
        "        if outcome.approved:\n",
        '        if outcome.approved or outcome.decision == "timeout":\n',
        APPROVAL + "test_file_approval_times_out_and_blocks_the_call",
        APPROVAL + "test_elicitation_times_out_if_the_client_never_answers",
    ),
    m(
        "file approval: the pending request is written unredacted",
        "proxy.py",
        "return await approver.request(call_id=call_id, tool=name, arguments=self._redact(arguments))",
        "return await approver.request(call_id=call_id, tool=name, arguments=arguments)",
        APPROVAL + "test_the_pending_request_on_disk_is_redacted",
        APPROVAL + "test_the_approve_command_approves_a_pending_call",
    ),
    m(
        "file approval: request files are left behind when the wait ends",
        "approval.py",
        "            for leftover in (pending, approved, denied):",
        "            for leftover in ():",
        APPROVAL + "test_file_approval_times_out_and_blocks_the_call",
        APPROVAL + "test_file_approval_approved_forwards_the_call",
    ),
    m(
        "file approval: the directory is created with default permissions",
        "approval.py",
        "        directory.mkdir(parents=True, exist_ok=True, mode=0o700)",
        "        directory.mkdir(parents=True, exist_ok=True)",
        APPROVAL + "test_file_approval_approved_forwards_the_call",
    ),
    m(
        "file approval: a directory every user can write to is accepted",
        "approval.py",
        "        if mode & stat.S_IWOTH:",
        "        if False:",
        LIFECYCLE + "test_an_approvals_directory_anyone_can_write_to_stops_the_proxy_at_startup",
    ),
    m(
        "file approval: a group-writable directory starts without a warning",
        "approval.py",
        "        if mode & stat.S_IWGRP:",
        "        if False:",
        LIFECYCLE + "test_an_approvals_directory_a_group_can_write_to_is_allowed_but_called_out",
    ),
    m(
        "file approval: expires_at is truncated, so it can precede the real deadline",
        "approval.py",
        "_utc(math.ceil(now + self.timeout_seconds))",
        "_utc(now + self.timeout_seconds)",
        APPROVAL + "test_a_pending_request_never_claims_to_expire_before_the_proxy_stops_waiting",
    ),
    m(
        "file approval: stale files are not cleared at startup",
        "__main__.py",
        "            swept = FileApprover.sweep(policy.approval.directory)\n",
        "            swept = 0\n",
        APPROVAL + "test_startup_clears_out_what_a_killed_proxy_left_behind",
    ),
    m(
        "file approval: the startup sweep removes requests that have not expired",
        "approval.py",
        "                if expiry is not None and expiry < now:\n                    dead +=",
        "                if True:\n                    dead +=",
        APPROVAL + "test_startup_clears_out_what_a_killed_proxy_left_behind",
    ),
    m(
        "file approval: the startup sweep touches files that are not request ids",
        "approval.py",
        "            if not _ID_RE.fullmatch(path.stem):\n                continue\n            if path.suffix == PENDING_SUFFIX:",
        "            if path.suffix == PENDING_SUFFIX:",
        APPROVAL + "test_startup_clears_out_what_a_killed_proxy_left_behind",
    ),
    # -- mcp-guardrail-approve ------------------------------------------------
    m(
        "approve command: any text is accepted as an id",
        "approval.py",
        '_ID_PREFIX_RE = re.compile(r"[0-9a-f]{6,32}")',
        '_ID_PREFIX_RE = re.compile(r".{1,64}")',
        APPROVAL + "test_the_approve_command_rejects_ids_that_are_not_ids",
    ),
    m(
        "approve command: containment checked against the unresolved directory",
        "approval.py",
        "    directory = directory.resolve()\n    if not directory.is_dir():",
        "    if not directory.is_dir():",
        APPROVAL + "test_the_approve_command_works_through_a_symlinked_directory",
    ),
    m(
        "approve command: an expired request is answered",
        "approval.py",
        "    if expiry is not None and expiry < time.time():\n        print(",
        "    if False:\n        print(",
        APPROVAL + "test_the_approve_command_refuses_a_request_that_has_expired",
    ),
    m(
        "approve command: --list shows an expired request as live",
        "approval.py",
        "        if expiry is not None and expiry < now:\n            when =",
        "        if False:\n            when =",
        APPROVAL + "test_the_approve_command_refuses_a_request_that_has_expired",
    ),
    # -- elicitation ----------------------------------------------------------
    m(
        "elicitation: any accept approves",
        "approval.py",
        'if result.action == "accept" and result.content is not None and result.content.get(ELICITATION_FIELD) is True:',
        'if result.action == "accept":',
        APPROVAL + "test_elicitation_anything_but_an_explicit_yes_blocks_the_call",
    ),
    m(
        "elicitation: a truthy non-boolean approve is accepted",
        "approval.py",
        "result.content.get(ELICITATION_FIELD) is True:",
        "result.content.get(ELICITATION_FIELD):",
        APPROVAL + "test_elicitation_anything_but_an_explicit_yes_blocks_the_call",
    ),
    m(
        "elicitation: decline approves",
        "approval.py",
        """    return ApprovalOutcome("denied", approver, f"the approval prompt was answered with '{result.action}'")""",
        """    return ApprovalOutcome("approved", approver, f"the approval prompt was answered with '{result.action}'")""",
        APPROVAL + "test_elicitation_anything_but_an_explicit_yes_blocks_the_call",
        APPROVAL + "test_elicitation_over_the_2026_protocol_blocks_a_declined_call",
    ),
    m(
        "elicitation: a client's JSON-RPC error in reply to the prompt approves",
        "proxy.py",
        '                    return ApprovalOutcome(\n                        "denied",\n                        None,\n'
        '                        f"the client answered',
        '                    return ApprovalOutcome(\n                        "approved",\n                        None,\n'
        '                        f"the client answered',
        APPROVAL + "test_a_client_that_answers_the_prompt_with_an_error_does_not_get_the_call_through",
    ),
    m(
        "elicitation: the client's error text is written to the log",
        "proxy.py",
        'f"the client answered the approval prompt with JSON-RPC error {exc.error.code}",',
        'f"the client rejected the approval prompt: {exc.error.message}",',
        APPROVAL + "test_a_client_that_answers_the_prompt_with_an_error_does_not_get_the_call_through",
    ),
    m(
        "elicitation: the client's capability is not checked",
        "proxy.py",
        "if elicitation is None or (elicitation.form is None and elicitation.url is not None):",
        "if False:",
        APPROVAL + "test_elicitation_with_a_client_that_cannot_elicit_blocks_the_call",
    ),
    m(
        "elicitation: a URL-only client is sent the form anyway",
        "proxy.py",
        "if elicitation is None or (elicitation.form is None and elicitation.url is not None):",
        "if elicitation is None:",
        APPROVAL + "test_a_client_that_only_offers_url_elicitation_is_refused",
    ),
    m(
        "elicitation: the prompt shows raw arguments (2025-11-25)",
        "proxy.py",
        "                question = elicitation_params(name, self._redact(arguments))",
        "                question = elicitation_params(name, arguments)",
        APPROVAL + "test_elicitation_accepted_forwards_the_call",
    ),
    m(
        "elicitation: the prompt shows raw arguments (2026-07-28)",
        "proxy.py",
        "types.ElicitRequest(params=elicitation_params(name, redacted))",
        "types.ElicitRequest(params=elicitation_params(name, arguments))",
        APPROVAL + "test_the_question_over_the_2026_protocol_shows_redacted_arguments",
    ),
    m(
        "elicitation: no timeout on the prompt (2025-11-25)",
        "proxy.py",
        "                    with anyio.fail_after(timeout):\n                        answer = await ctx.session.elicit_form(",
        "                    if True:\n                        answer = await ctx.session.elicit_form(",
        APPROVAL + "test_elicitation_times_out_if_the_client_never_answers",
    ),
    m(
        "elicitation: an approval can be used twice",
        "proxy.py",
        "            del self._pending_elicitations[asked_id]\n            outcome = outcome_from_elicitation",
        "            outcome = outcome_from_elicitation",
        APPROVAL + "test_an_approval_cannot_be_replayed_moved_or_invented",
    ),
    m(
        "elicitation: an approval is not bound to the arguments shown",
        "proxy.py",
        "if pending is not None and pending.digest == digest and isinstance(answer, types.ElicitResult):",
        "if pending is not None and isinstance(answer, types.ElicitResult):",
        APPROVAL + "test_an_approval_cannot_be_replayed_moved_or_invented",
    ),
    m(
        "elicitation: an approval is not bound to the tool",
        "proxy.py",
        "json.dumps([tool, arguments]",
        "json.dumps([arguments]",
        APPROVAL + "test_an_approval_cannot_be_replayed_moved_or_invented",
    ),
    m(
        "elicitation: an answer is accepted with no question behind it",
        "proxy.py",
        '        pending = self._pending_elicitations.get(params.request_state or "")\n',
        '        pending = self._pending_elicitations.get(params.request_state or "") or _PendingElicitation(\n'
        "            digest, name, None, rule, started, started + timeout\n        )\n",
        APPROVAL + "test_an_approval_cannot_be_replayed_moved_or_invented",
        more=(
            (
                "            del self._pending_elicitations[asked_id]\n            outcome = outcome_from_elicitation",
                "            self._pending_elicitations.pop(asked_id, None)\n            outcome = outcome_from_elicitation",
            ),
            (
                "            asked_id = params.request_state\n            assert asked_id is not None\n",
                "            asked_id = params.request_state or call_id\n",
            ),
        ),
    ),
    m(
        "elicitation: unanswered questions never expire",
        "proxy.py",
        "            if pending.expires <= now:",
        "            if False:",
        APPROVAL + "test_an_unanswered_question_over_the_2026_protocol_times_out_on_its_own",
    ),
    m(
        "elicitation: an unanswered question is only timed out by the next call",
        "proxy.py",
        "        self._tasks.start_soon(self._expire_elicitations_after, timeout)\n",
        "",
        APPROVAL + "test_an_unanswered_question_over_the_2026_protocol_times_out_on_its_own",
    ),
    m(
        "elicitation: an expired question gets no timeout line",
        "proxy.py",
        "                del self._pending_elicitations[asked_id]\n                # Already redacted",
        "                del self._pending_elicitations[asked_id]\n                continue\n                # Already redacted",
        APPROVAL + "test_an_unanswered_question_over_the_2026_protocol_times_out_on_its_own",
    ),
    m(
        "elicitation: questions still open at disconnect get no closing line",
        "proxy.py",
        "            self._abandon_elicitations()\n",
        "            pass\n",
        APPROVAL + "test_a_question_still_open_when_the_client_disconnects_is_closed_out",
    ),
    # -- held calls -----------------------------------------------------------
    m(
        "held call: a withdrawn call gets no closing line",
        "proxy.py",
        '            self._record(call_id, name, arguments, started, decision="cancelled", rule=rule, reason=_WITHDRAWN)\n',
        "",
        APPROVAL + "test_cancelling_a_call_that_is_awaiting_approval_is_recorded",
        APPROVAL + "test_cancelling_a_call_during_elicitation_is_recorded",
    ),
    m(
        "held call: a failed approval request escapes as a protocol error",
        "proxy.py",
        "                except Exception as exc:\n                    outcome = self._approval_failed(name, call_id, exc)\n",
        "                except ZeroDivisionError as exc:\n                    outcome = self._approval_failed(name, call_id, exc)\n",
        APPROVAL + "test_losing_the_approvals_directory_blocks_the_call_and_closes_the_record",
        APPROVAL + "test_a_malformed_answer_to_the_prompt_blocks_the_call_and_closes_the_record",
    ),
    m(
        "held call: not answered when the proxy has to stop",
        "proxy.py",
        "        for wait in list(self._approval_waits):\n            wait.cancel()\n",
        "",
        LIFECYCLE + "test_the_upstream_dying_while_a_call_awaits_approval_answers_that_call",
    ),
    # -- command line and lifecycle -------------------------------------------
    m(
        "cli: --upstream split on whitespace",
        "__main__.py",
        "        return shlex.split(text)\n",
        "        return text.split()\n",
        LIFECYCLE + "test_upstream_paths_with_spaces_work",
    ),
    m(
        "cli: the Windows rule drops backslashes like the POSIX one",
        "__main__.py",
        "    words = shlex.split(text, posix=False)\n",
        "    words = shlex.split(text)\n",
        LIFECYCLE + "test_the_windows_rule_for_splitting_upstream_keeps_backslashes",
    ),
    m(
        "cli: --audit and --policy compared without resolving",
        "__main__.py",
        "audit.path == args.policy.expanduser().resolve()",
        "args.audit == args.policy",
        LIFECYCLE + "test_audit_and_policy_must_not_be_the_same_file",
    ),
    m(
        "cli: the upstream command is echoed unquoted in a startup error",
        "upstream.py",
        "    shown = shlex.join(command)\n",
        "    shown = ' '.join(command)\n",
        LIFECYCLE + "test_an_upstream_command_that_does_not_exist_exits_3",
    ),
    m(
        "lifecycle: no timeout on the upstream handshake",
        "upstream.py",
        "            with anyio.fail_after(startup_timeout):\n                init = await session.initialize()",
        "            if True:\n                init = await session.initialize()",
        LIFECYCLE + "test_an_upstream_that_never_answers_exits_3_after_the_startup_timeout",
    ),
    m(
        "lifecycle: the upstream's death is not watched for",
        "proxy.py",
        "                tg.start_soon(self._watch_upstream)\n",
        "",
        LIFECYCLE + "test_the_upstream_dying_while_idle_stops_the_proxy_with_status_4",
    ),
    m(
        "lifecycle: the upstream dying mid-call surfaces as a bare protocol error",
        "proxy.py",
        "            if exc.error.code == types.CONNECTION_CLOSED or self._upstream.closed.is_set():",
        "            if False:",
        LIFECYCLE + "test_the_upstream_dying_mid_call_fails_that_call_clearly",
    ),
    m(
        "lifecycle: a failure exit goes through normal interpreter shutdown",
        "__main__.py",
        "    os._exit(status)",
        "    sys.exit(status)",
        LIFECYCLE + "test_the_upstream_dying_while_idle_stops_the_proxy_with_status_4",
    ),
    m(
        "lifecycle: the stdin read cannot be abandoned",
        "proxy.py",
        "sys.stdin.buffer.readline, abandon_on_cancel=True)",
        "sys.stdin.buffer.readline, abandon_on_cancel=False)",
        LIFECYCLE + "test_the_upstream_dying_while_idle_stops_the_proxy_with_status_4",
        LIFECYCLE + "test_losing_the_audit_log_stops_forwarding_and_exits_5",
    ),
    m(
        "lifecycle: stop signals are left to their default action",
        "proxy.py",
        "                tg.start_soon(self._watch_signals)\n",
        "",
        LIFECYCLE + "test_a_stop_signal_ends_the_proxy_promptly_and_takes_the_upstream_with_it",
        LIFECYCLE + "test_a_stop_signal_answers_and_closes_out_a_call_awaiting_approval",
    ),
    m(
        "lifecycle: Ctrl-C during startup is not caught",
        "__main__.py",
        "    except KeyboardInterrupt:\n",
        "    except ZeroDivisionError:\n",
        LIFECYCLE + "test_ctrl_c_while_the_upstream_is_still_starting_exits_130_without_a_traceback",
    ),
]


def _clear_bytecode() -> None:
    # A mutant and the original can share a size and a modification second,
    # which is all a cached .pyc is checked against.
    shutil.rmtree(PACKAGE / "__pycache__", ignore_errors=True)


def _uncommitted_source_changes() -> str:
    return subprocess.run(
        ["git", "status", "--porcelain", "--", "src"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


def _check(mutation: Mutation) -> tuple[str, str]:
    """Apply one mutation, run its tests, restore. Returns (verdict, detail)."""
    path = PACKAGE / mutation.file
    original = path.read_text(encoding="utf-8")
    mutated = original
    for old, new in mutation.edits:
        if mutated.count(old) != 1:
            return "STALE", f"expected this text once in {mutation.file}, found it {mutated.count(old)} times: {old[:70]!r}"
        mutated = mutated.replace(old, new)
    try:
        path.write_text(mutated, encoding="utf-8")
        _clear_bytecode()
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *mutation.tests],
            cwd=REPO,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=600,
        )
    finally:
        path.write_text(original, encoding="utf-8")
        _clear_bytecode()
    failed = [line for line in run.stdout.splitlines() if line.startswith(("FAILED", "ERROR"))]
    last = run.stdout.strip().splitlines()[-1] if run.stdout.strip() else run.stderr.strip()[-200:]
    # pytest exits 1 when tests ran and some failed. Anything else (a test id
    # that no longer exists, a usage error) is not evidence of a guard.
    if run.returncode == 1 and failed:
        return "caught", failed[0][:160]
    if run.returncode == 0:
        return "NOT CAUGHT", last
    return "ERROR", f"pytest exited {run.returncode}: {last}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print the mutations and exit")
    parser.add_argument("--only", metavar="TEXT", help="run only mutations whose name contains TEXT")
    args = parser.parse_args()

    chosen = [mutation for mutation in MUTATIONS if not args.only or args.only in mutation.name]
    if args.list:
        for mutation in chosen:
            print(mutation.name)
        print(f"\n{len(chosen)} mutations")
        return 0
    dirty = _uncommitted_source_changes()
    if dirty:
        print(f"Error: src/ has uncommitted changes; commit or stash them first.\n{dirty}", file=sys.stderr)
        return 2

    tally = {"caught": 0, "NOT CAUGHT": 0, "STALE": 0, "ERROR": 0}
    for mutation in chosen:
        verdict, detail = _check(mutation)
        tally[verdict] += 1
        print(f"{verdict:10}  {mutation.name}\n            {detail}", flush=True)

    print(
        f"\n{len(chosen)} mutations: {tally['caught']} caught, {tally['NOT CAUGHT']} not caught, "
        f"{tally['STALE']} stale, {tally['ERROR']} errors"
    )
    left_behind = _uncommitted_source_changes()
    if left_behind:
        print(f"Error: src/ was not restored cleanly:\n{left_behind}", file=sys.stderr)
        return 1
    return 0 if tally["caught"] == len(chosen) else 1


if __name__ == "__main__":
    sys.exit(main())
