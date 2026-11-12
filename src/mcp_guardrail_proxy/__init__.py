"""mcp_guardrail_proxy: policy and audit middleware for MCP servers.

Sits between an MCP client and an upstream MCP server. Tools are re-exposed
unchanged; each call is checked against a policy before it is forwarded, and
every call, decision, and outcome is appended to a JSONL audit log.
"""

__version__ = "0.1.0"
