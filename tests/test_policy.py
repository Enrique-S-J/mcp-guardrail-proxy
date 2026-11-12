"""Policy loading and decision order.

These are direct tests of the decision table. What a client actually
experiences when a rule fires is covered over the protocol in test_proxy.py.
"""

from pathlib import Path

import pytest
from mcp.types import ToolAnnotations

from mcp_guardrail_proxy.policy import Action, PolicyError, load_policy, parse_policy

READ_ONLY = ToolAnnotations(read_only_hint=True)
WRITE = ToolAnnotations(read_only_hint=False)

SPEC_EXAMPLE = """
default: require_approval
read_only_passthrough: true
tools:
  delete_record: deny
  send_email:   require_approval
  get_status:   allow
redact_fields: [password, token, api_key]
"""


def _policy(text: str, base_dir: Path = Path(".")):
    return parse_policy(text, base_dir=base_dir)


def test_explicit_rule_beats_read_only_passthrough():
    """A per-tool deny holds even when the tool claims to be read-only."""
    policy = _policy("default: allow\ntools:\n  get_status: deny\n")
    decision = policy.decide("get_status", READ_ONLY)
    assert decision.action is Action.DENY
    assert decision.rule == "tools.get_status: deny"


def test_read_only_passthrough_beats_default():
    policy = _policy("default: deny\n")
    decision = policy.decide("get_status", READ_ONLY)
    assert decision.action is Action.ALLOW
    assert decision.rule == "read_only_passthrough"


def test_default_applies_to_everything_else():
    policy = _policy(SPEC_EXAMPLE)
    assert policy.decide("update_thing", WRITE).action is Action.REQUIRE_APPROVAL
    assert policy.decide("update_thing", WRITE).rule == "default: require_approval"
    assert policy.decide("delete_record", WRITE).action is Action.DENY
    assert policy.decide("send_email", WRITE).action is Action.REQUIRE_APPROVAL
    assert policy.decide("get_status", WRITE).action is Action.ALLOW


@pytest.mark.parametrize(
    "annotations",
    [None, ToolAnnotations(), WRITE, ToolAnnotations(destructive_hint=False, idempotent_hint=True)],
    ids=["no-annotations", "empty-annotations", "read-only-false", "other-hints-only"],
)
def test_only_an_explicit_read_only_hint_passes_through(annotations):
    """Absent is not the same as read-only. Nothing short of readOnlyHint: true passes."""
    policy = _policy("default: deny\n")
    assert policy.decide("some_tool", annotations).action is Action.DENY


def test_passthrough_can_be_switched_off():
    policy = _policy("default: deny\nread_only_passthrough: false\n")
    assert policy.decide("get_status", READ_ONLY).action is Action.DENY


def test_empty_policy_is_the_safe_default():
    """No policy at all forwards read-only tools and holds the rest, with nobody to approve."""
    policy = _policy("")
    assert policy.default is Action.REQUIRE_APPROVAL
    assert policy.read_only_passthrough is True
    assert policy.approval.mode == "deny"
    assert policy.redact_fields == []


@pytest.mark.parametrize(
    "text,expected",
    [
        ("defualt: allow\n", "defualt"),
        ("default: permit\n", "default"),
        ("tools:\n  send_email: maybe\n", "tools.send_email"),
        ("approval:\n  mode: slack\n", "approval.mode"),
        ("approval:\n  mode: file\n  timeout_seconds: 0\n", "approval.timeout_seconds"),
        ("approval:\n  mode: file\n  timeout_seconds: .inf\n", "approval.timeout_seconds"),
        ("approval:\n  mode: file\n  timeout_seconds: 1.0e+300\n", "approval.timeout_seconds"),
        ("approval:\n  mode: file\n  poll_interval_seconds: .inf\n", "approval.poll_interval_seconds"),
        ("approval:\n  mode: file\n  timout_seconds: 5\n", "approval.timout_seconds"),
        ("- just\n- a list\n", "top level must be a mapping"),
        ("default: [unclosed\n", "not valid YAML"),
    ],
    ids=[
        "unknown-key",
        "bad-action",
        "bad-tool-action",
        "bad-mode",
        "zero-timeout",
        "infinite-timeout",
        "absurd-timeout",
        "infinite-poll-interval",
        "nested-typo",
        "not-a-mapping",
        "bad-yaml",
    ],
)
def test_invalid_policies_are_rejected_and_say_where(text, expected):
    """A typo must stop the proxy, not fall back to a default nobody chose."""
    with pytest.raises(PolicyError) as exc:
        _policy(text)
    assert expected in str(exc.value)


def test_duplicate_keys_are_rejected():
    """PyYAML alone would keep the last one, turning this deny into an allow."""
    with pytest.raises(PolicyError) as exc:
        _policy("tools:\n  send_email: deny\n  send_email: allow\n")
    assert "duplicate key 'send_email'" in str(exc.value)


def test_unquoted_yaml_keywords_as_tool_names_are_rejected():
    """YAML reads a bare `on` as a boolean; that must not become a rule for a tool called 'True'."""
    with pytest.raises(PolicyError) as exc:
        _policy("tools:\n  on: deny\n")
    assert "quote the tool name" in str(exc.value)
    assert _policy('tools:\n  "on": deny\n').tools == {"on": Action.DENY}


def test_relative_approvals_directory_is_anchored_to_the_policy_file(tmp_path):
    """Not to the working directory, which belongs to whatever launched the proxy."""
    config_dir = tmp_path / "dir with spaces"
    config_dir.mkdir()
    policy_file = config_dir / "policy.yaml"
    policy_file.write_text("approval:\n  mode: file\n  directory: pending\n")
    policy = load_policy(policy_file)
    assert policy.approval.directory == (config_dir / "pending").resolve()
    assert policy.approval.directory.is_absolute()


def test_approvals_directory_is_stored_resolved(tmp_path):
    """Symlinked parents are resolved up front, so later comparisons are like for like."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    policy = _policy(f"approval:\n  mode: file\n  directory: {link}/approvals\n", base_dir=tmp_path)
    assert policy.approval.directory == real.resolve() / "approvals"


def test_missing_policy_file_is_a_clear_error(tmp_path):
    with pytest.raises(PolicyError) as exc:
        load_policy(tmp_path / "nope.yaml")
    assert "cannot read policy file" in str(exc.value)
    assert "nope.yaml" in str(exc.value)


def test_shipped_example_policy_loads():
    """The example in the repo must stay a valid policy."""
    example = Path(__file__).resolve().parent.parent / "policy.example.yaml"
    policy = load_policy(example)
    assert policy.default is Action.REQUIRE_APPROVAL
