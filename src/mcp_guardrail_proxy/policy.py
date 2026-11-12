"""Policy: which tool calls are forwarded, refused, or held for approval.

The policy is a small YAML file. Loading is deliberately strict, because a
policy that silently means something other than what was written is worse than
one that refuses to load: unknown keys, duplicate keys, and unrecognised
actions are all errors.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class PolicyError(Exception):
    """The policy file is missing, unreadable, or invalid."""


class Action(str, Enum):
    """What the policy says to do with a tool call."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ApprovalConfig(BaseModel):
    """How a `require_approval` decision is resolved."""

    model_config = ConfigDict(extra="forbid")

    # `deny` is the default so that a policy which never mentions approval
    # cannot leave a call waiting on a human who is not there.
    mode: Literal["deny", "file", "elicitation"] = "deny"
    # Relative paths are resolved against the policy file's directory, not the
    # working directory: MCP clients launch servers from wherever they like.
    directory: Path = Path("approvals")
    # Bounded above as well as below. An infinite or astronomically large
    # timeout parses as a float and then fails on first use, when the request's
    # expiry time is computed, which is after the call has been held.
    timeout_seconds: float = Field(default=300.0, gt=0, le=86400, allow_inf_nan=False)
    poll_interval_seconds: float = Field(default=0.5, gt=0, le=60, allow_inf_nan=False)


class Policy(BaseModel):
    """The parsed policy file."""

    model_config = ConfigDict(extra="forbid")

    default: Action = Action.REQUIRE_APPROVAL
    read_only_passthrough: bool = True
    tools: dict[str, Action] = Field(default_factory=dict)
    redact_fields: list[str] = Field(default_factory=list)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)

    def decide(self, tool_name: str, annotations: Optional[ToolAnnotations]) -> "Decision":
        """Decide what to do with a call to a tool the upstream advertised.

        Order: an explicit per-tool rule, then read-only passthrough, then the
        default. The returned rule is the text quoted back to the client and
        written to the audit log, so it names the line of the policy that fired.
        """
        explicit = self.tools.get(tool_name)
        if explicit is not None:
            return Decision(explicit, f"tools.{tool_name}: {explicit.value}")
        # `is True`, not truthiness: the hint is optional, and an absent or
        # null hint must not be read as a claim of read-only.
        if self.read_only_passthrough and annotations is not None and annotations.read_only_hint is True:
            return Decision(Action.ALLOW, "read_only_passthrough")
        return Decision(self.default, f"default: {self.default.value}")


@dataclass(frozen=True)
class Decision:
    """A policy outcome and the rule that produced it."""

    action: Action
    rule: str


# Rule recorded when a call names a tool that was not in the upstream's
# tools/list at startup. It is not configurable: see GuardrailProxy.
UNKNOWN_TOOL_RULE = "unknown_tool"


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys.

    PyYAML keeps the last of two identical keys without complaint, so
    `send_email: deny` followed further down by `send_email: allow` would
    quietly allow. In a policy file that has to be an error.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def parse_policy(text: str, *, base_dir: Path) -> Policy:
    """Parse policy YAML. `base_dir` anchors a relative approvals directory."""
    try:
        raw = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass
    except yaml.YAMLError as exc:
        raise PolicyError(f"not valid YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"top level must be a mapping, got {type(raw).__name__}")
    tools = raw.get("tools")
    if isinstance(tools, dict):
        for name in tools:
            # YAML reads bare `on`, `yes`, `123` as non-strings. Coercing them
            # would make a rule for a tool nobody named.
            if not isinstance(name, str):
                raise PolicyError(
                    f"tools: key {name!r} is not a string (YAML parsed it as "
                    f"{type(name).__name__}); quote the tool name"
                )
    try:
        policy = Policy.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or '(top level)'}: {err['msg']}"
            for err in exc.errors()
        )
        raise PolicyError(problems) from exc
    directory = policy.approval.directory.expanduser()
    if not directory.is_absolute():
        directory = base_dir / directory
    # Resolved once, here, so every later comparison against this directory is
    # between two resolved paths (on macOS /var and /tmp are symlinks).
    policy.approval.directory = directory.resolve()
    return policy


def load_policy(path: Optional[Path]) -> Policy:
    """Load a policy file, or the built-in defaults when no path is given.

    The defaults forward tools annotated read-only and refuse everything else:
    `default: require_approval` with `approval.mode: deny`.
    """
    if path is None:
        return parse_policy("", base_dir=Path.cwd())
    path = path.expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file '{path}': {exc.strerror or exc}") from exc
    try:
        return parse_policy(text, base_dir=path.resolve().parent)
    except PolicyError as exc:
        raise PolicyError(f"invalid policy file '{path}': {exc}") from exc
