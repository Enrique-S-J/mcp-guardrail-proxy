# mcp-guardrail-proxy

Policy and audit middleware for [MCP](https://modelcontextprotocol.io): wraps any MCP server, passes read-only tools through, and gates write-capable tools behind an approval step with a full audit log.

An MCP client will call whatever tools its server offers, and most servers offer write tools next to read ones with nothing between them but the model's judgement. This proxy sits in that gap: it forwards what a policy allows, holds or refuses the rest, and records every call and what became of it.

```
MCP client ──stdio──▶ mcp-guardrail-proxy ──stdio──▶ upstream MCP server
(Claude Desktop,          │
 an agent, ...)           ├─ policy.yaml   allow / deny / require_approval, per tool
                          ├─ approvals/    held calls, answered by a human
                          └─ audit.jsonl   one line per decision
```

The client sees the upstream's tools under their own names, with their own descriptions, schemas, and annotations. The only visible difference is that some calls come back refused, with the policy rule that refused them:

```
Blocked by mcp-guardrail-proxy: policy rule 'tools.delete_record: deny' denies calls to 'delete_record'.
```

The pattern is a common one for agents with real access: read-only by default, human approval for write actions. This repo is that pattern as working code you can put in front of your own servers.

## Quickstart

Requires Python 3.10+ and the `mcp` SDK 2.x (developed and tested against 2.3.0).

```bash
git clone https://github.com/Enrique-S-J/mcp-guardrail-proxy.git
cd mcp-guardrail-proxy
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Demo: in front of sysops-mcp

[sysops-mcp](https://github.com/Enrique-S-J/sysops-mcp) is a read-only diagnostics server with eight tools. Check it out next to this repo and give it its own virtualenv:

```bash
git clone https://github.com/Enrique-S-J/sysops-mcp.git ../sysops-mcp
(cd ../sysops-mcp && python3 -m venv .venv && .venv/bin/pip install -e .)

python scripts/demo_sysops.py        # or: --sysops-dir /path/to/sysops-mcp
```

The script starts the proxy with sysops-mcp as its upstream and a policy that denies nothing, then acts as an MCP client: `initialize`, `tools/list`, and one `tools/call`. Output from a real run, abridged (the middle of the tool list and the host summary itself are left out):

```
mcp-guardrail-proxy: upstream 'sysops_mcp' 0.1.0: 8 tools (8 allow, 0 require approval, 0 deny); approval mode: deny
connected to: mcp-guardrail-proxy 0.1.0 (SysOps Diagnostics (via mcp-guardrail-proxy))
protocol version: 2025-11-25
tools listed by sysops-mcp directly: 8
tools listed through the proxy:      8
identical (name, description, schema, annotations): True
  - get_cpu_status (readOnlyHint: True)
  ...
  - tail_log (readOnlyHint: True)

audit log:
{"timestamp": "2026-11-12T06:56:46.284+00:00", "call_id": "2b7c726cabe347e2801ee0ed25165842", "tool": "get_host_summary", "arguments": {}, "decision": "allow", "rule": "read_only_passthrough", "reason": null, "approver": null, "upstream_status": "ok", "latency_ms": 506.9}
```

What the script runs is this command, with paths filled in:

```bash
mcp-guardrail-proxy \
  --upstream "../sysops-mcp/.venv/bin/python ../sysops-mcp/server.py" \
  --policy policy.yaml \
  --audit audit.jsonl
```

Two things to know about that command. The upstream has to be started with the interpreter from **its own** virtualenv; a bare `python3 ../sysops-mcp/server.py` starts and then fails on import, and the proxy exits with status 3 and the upstream's traceback. And like any stdio server, the proxy run by hand just waits for JSON-RPC on stdin. Point a client at it.

### Claude Desktop

Add the proxy as the server and give it the real server's command as its argument, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sysops-guarded": {
      "command": "/absolute/path/to/mcp-guardrail-proxy/.venv/bin/mcp-guardrail-proxy",
      "args": [
        "--upstream", "/absolute/path/to/sysops-mcp/.venv/bin/python /absolute/path/to/sysops-mcp/server.py",
        "--policy", "/absolute/path/to/policy.yaml",
        "--audit", "/absolute/path/to/audit.jsonl"
      ]
    }
  }
}
```

`--upstream` is one string, split the way a shell would split it, so a path containing spaces needs quotes inside that string. Inside JSON that gets ugly fast. The alternative is to put the upstream command after a bare `--`, one argument per element, with nothing to quote:

```json
"args": [
  "--policy", "/absolute/path/to/policy.yaml",
  "--audit", "/absolute/path/to/audit.jsonl",
  "--",
  "/path with spaces/sysops-mcp/.venv/bin/python",
  "/path with spaces/sysops-mcp/server.py"
]
```

Use absolute paths throughout: a client launches servers from whatever working directory it likes. Environment variables set for the server in the client config reach the upstream, because the proxy passes its whole environment on.

## Policy

Copy `policy.example.yaml` to `policy.yaml` and edit.

```yaml
default: require_approval          # for tools without readOnlyHint
read_only_passthrough: true        # trust readOnlyHint=true tools
tools:
  delete_record: deny              # never forward
  send_email:   require_approval
  get_status:   allow              # explicit override
redact_fields: [password, token, api_key]   # scrubbed from audit log args
approval:
  mode: file
  directory: approvals
  timeout_seconds: 300
```

For each call, the first of these that applies decides:

1. A rule under `tools:` for that tool name.
2. `read_only_passthrough`, if the upstream annotated the tool `readOnlyHint: true`.
3. `default`.

A call to a tool that was not in the upstream's `tools/list` when the proxy started is denied before any of that, with a message telling the client to restart the proxy.

| Key | Values | Default | Meaning |
|-----|--------|---------|---------|
| `default` | `allow`, `deny`, `require_approval` | `require_approval` | What happens to a tool with no rule that is not read-only. |
| `read_only_passthrough` | `true`, `false` | `true` | Forward tools annotated `readOnlyHint: true` without asking. Only an explicit `true` counts; a tool with no annotations is a write. |
| `tools` | map of tool name to action | `{}` | Per-tool rules. Always win. |
| `redact_fields` | list of key names | `[]` | Argument keys whose values are written as `"[REDACTED]"`, at any nesting depth. |
| `approval.mode` | `deny`, `file`, `elicitation` | `deny` | How `require_approval` gets its answer. See below. |
| `approval.directory` | path | `approvals` | Where `file` mode keeps requests. Relative paths are relative to the policy file. |
| `approval.timeout_seconds` | number > 0 | `300` | How long a held call waits before it is refused. |
| `approval.poll_interval_seconds` | number > 0 | `0.5` | How often `file` mode looks for an answer. |

Without `--policy`, the defaults above apply: read-only tools are forwarded and everything else is refused.

The file is parsed strictly. An unknown key, a duplicate key, an unrecognised action, or an unquoted YAML keyword used as a tool name (`on:`, `yes:`) stops the proxy at startup with status 2. A rule naming a tool the upstream does not have is not an error, since the same policy may front several servers, but it is reported on stderr at startup.

Redaction matches key names ignoring case, `_`, and `-`, so `api_key` also covers `apiKey` and `API-KEY`. It is an exact match, not a substring: `token` does not cover `access_token`. List each field.

## Approval modes

**`deny`** (default). `require_approval` behaves as `deny`. Nothing waits on a human who is not there. This is the right mode for unattended use.

**`file`**. The proxy writes the held call to `<directory>/<id>.json` (arguments redacted), says so on stderr, and waits for `<id>.approved` or `<id>.denied` to appear beside it. From another terminal:

```console
$ mcp-guardrail-approve --dir /path/to/approvals --list
c536458b289847328b792ee5d3671e74  send_email  expires 2026-11-12T06:58:19+00:00
    arguments: {"to": "ops@example.test", "subject": "Disk alert", "smtp": {"host": "mail.example.test", "password": "[REDACTED]"}}

$ mcp-guardrail-approve --dir /path/to/approvals c536458b
Approved c536458b289847328b792ee5d3671e74
```

`--deny` refuses instead, `--reason` and `--approver` are recorded in the audit log (the approver defaults to the OS user), and `--policy policy.yaml` finds the directory from the policy instead of `--dir`. A unique prefix of the id, six characters or more, is enough. The command is a convenience: any process that creates the file approves the call (`touch <id>.approved` works), and a denial wins if both exist. Requests are removed once answered, timed out, or cancelled.

**`elicitation`**. The proxy asks through the MCP client, using the protocol's own mechanism for a server to request input from the user. Only an explicit accept with `approve: true` forwards the call; decline, cancel, or anything else blocks it. If the client did not declare elicitation support the call is refused and the message says to use `file`. Both forms the SDK speaks are implemented: an `elicitation/create` request on protocol versions up to 2025-11-25, and an `input_required` result that the client answers with a second `tools/call` on 2026-07-28.

Set `timeout_seconds` below your client's own request timeout. If the client gives up first, the call is cancelled, the pending request is withdrawn, and the audit log records `cancelled`.

## Audit log

JSONL, appended to the file given by `--audit`. A call that needs no approval produces one line. A call held for approval produces two with the same `call_id`: `approval_requested` when the wait starts, then the outcome. These four lines are from one real session: a read, a denied call, and an approved one.

```json
{"timestamp": "2026-11-12T06:57:49.102+00:00", "call_id": "1ccdcfe115fa4cf1b34cfd17eb9ac176", "tool": "get_status", "arguments": {}, "decision": "allow", "rule": "read_only_passthrough", "reason": null, "approver": null, "upstream_status": "ok", "latency_ms": 1.2}
{"timestamp": "2026-11-12T06:57:49.119+00:00", "call_id": "23af4edb6d5040858775b53a2ab8d955", "tool": "delete_record", "arguments": {"record_id": "r-1001"}, "decision": "deny", "rule": "tools.delete_record: deny", "reason": "Blocked by mcp-guardrail-proxy: policy rule 'tools.delete_record: deny' denies calls to 'delete_record'.", "approver": null, "upstream_status": "not_called", "latency_ms": 0.0}
{"timestamp": "2026-11-12T06:57:49.120+00:00", "call_id": "c536458b289847328b792ee5d3671e74", "tool": "send_email", "arguments": {"to": "ops@example.test", "subject": "Disk alert", "smtp": {"host": "mail.example.test", "password": "[REDACTED]"}}, "decision": "approval_requested", "rule": "default: require_approval", "reason": null, "approver": null, "upstream_status": "not_called", "latency_ms": 0.0}
{"timestamp": "2026-11-12T06:57:49.733+00:00", "call_id": "c536458b289847328b792ee5d3671e74", "tool": "send_email", "arguments": {"to": "ops@example.test", "subject": "Disk alert", "smtp": {"host": "mail.example.test", "password": "[REDACTED]"}}, "decision": "approved", "rule": "default: require_approval", "reason": null, "approver": "enrique", "upstream_status": "ok", "latency_ms": 612.4}
```

| Field | Meaning |
|-------|---------|
| `timestamp` | UTC, ISO 8601, when the line was written. |
| `call_id` | Random id for the call. Also the approval request id. |
| `tool` | Tool name as the client sent it. |
| `arguments` | The call's arguments, after redaction. |
| `decision` | `allow`, `deny`, `approval_requested`, `approved`, `denied`, `timeout`, or `cancelled` (the call was withdrawn while approval was pending, by the client or because the proxy was stopping). |
| `rule` | The policy rule that decided: `tools.<name>: <action>`, `read_only_passthrough`, `default: <action>`, or `unknown_tool`. |
| `reason` | Free text: the refusal shown to the client, the approver's reason, or a note on an upstream failure. |
| `approver` | Who answered, if anyone: the name from the decision file, or `elicitation:<client name>`. |
| `upstream_status` | `ok`, `error` (the tool returned `isError`), `protocol_error` (the upstream answered with a JSON-RPC error), `connection_lost`, `invalid_response`, `cancelled`, or `not_called`. |
| `latency_ms` | From receiving the call to writing this line. Includes any time spent waiting for approval. |

Each line is a single `write` to a file opened with `O_APPEND`; the proxy never rewrites or truncates the log, and a restart adds to the existing file. The file is created with mode 0600 and reopened for each line, so it can be rotated while the proxy runs. Tool results are not logged.

## Exit status

| Status | Meaning |
|--------|---------|
| 0 | The client disconnected. |
| 2 | Bad arguments, an invalid policy, or an unusable audit path or approvals directory. Nothing was started. |
| 3 | The upstream could not be started, exited during startup, or did not answer within `--startup-timeout` (default 30s). |
| 4 | The upstream exited or closed its connection mid-session. A call in flight gets an `isError` result saying so. |
| 5 | The audit log could not be written. |

The upstream's stderr is passed through to the proxy's, so its own error output appears just above the proxy's.

## Design notes

- **Trust `readOnlyHint`, deny everything else by default.** The annotation is the one machine-readable statement MCP has about what a tool does, and an author who sets it has thought about the question. Using it means reads flow without a rule or a prompt each, which matters more than it sounds: a guardrail that interrupts every read gets switched off, and one that asks for approval constantly trains people to approve without reading. The trust is deliberately narrow. Only an explicit `true` passes; a tool with no annotations, the common case of an author who never considered it, is treated as a write. And it is revocable: a per-tool rule always wins, and `read_only_passthrough: false` withdraws it altogether.
- **File approval is the baseline because it needs nothing from the client.** The answer is a file appearing in a directory. It never travels over MCP, so it works with clients that do not implement elicitation, and the thing being gated is not on the path the approval takes. Elicitation is more convenient, but it asks the client to relay the human's answer, and the proxy has to take the client's word for it.
- **Redaction happens at log time, not call time.** The proxy's job is to decide whether a call goes through and to record that it did, not to rewrite it. A tool that needs a password to do its work has to receive the password; scrubbing the forwarded call would break tools in a way that looks like an upstream bug. So redaction applies to copies on their way to somewhere they will be read later: the audit log, the pending-approval file, and the elicitation prompt. The tests check this against the upstream's own record of what it received.
- **The tool list is pinned at startup.** Tools are read once and decisions use the annotations captured then. An upstream cannot add a tool mid-session, or relabel one as read-only, and have the proxy go along with it. The cost is that a legitimate change needs a restart, and the refusal says so.
- **A policy that does not parse does not load.** Every way a policy file can mean something other than what was typed is an error: unknown keys, duplicate keys, bad actions. Plain PyYAML keeps the last of two duplicate keys, so a later `send_email: allow` would quietly override an earlier `deny`. Failing closed at startup is cheaper than explaining an incident.
- **No record, no call.** The proxy checks that it can append to the audit log before forwarding a call. If the log goes away, the call is not forwarded, the client is told why, and the proxy exits with status 5 instead of carrying on unaudited.
- **Refusals name the rule.** A denied call returns a normal tool result with `isError: true` and the policy rule that fired. The model can tell the user what happened and why, instead of retrying or guessing.
- **Tools are handed back, not re-declared.** The proxy serves through the SDK's low-level `Server`, whose handlers return protocol objects. The decorator API derives a schema from a Python function signature, which is the wrong tool when the schema already exists and belongs to someone else. Upstream results are passed through unvalidated for the same reason: judging the upstream's output is the client's job.
- **An approval cannot be reused.** On protocol 2026-07-28 the approval answer arrives as arguments to a second `tools/call`, which hands the client everything it would need to try again. The state the proxy sends is only the random id of an entry it keeps in memory; the entry is bound to the tool and arguments that were shown, expires, and is deleted when used.

### Known limits

- **Annotations are self-reported.** The proxy cannot verify that a tool marked read-only really is. A careless or hostile upstream can mark a destructive tool `readOnlyHint: true` and it will pass. Pair the proxy with least-privilege credentials on the upstream, so that what a tool can do is bounded by something other than its own description, and use explicit rules or `read_only_passthrough: false` for a server you have no reason to trust.
- **Policy is by tool name only.** There are no rules on arguments. `run_query` is allowed or it is not; the proxy cannot allow `SELECT` and hold `DELETE`.
- **Tools only.** Resources, prompts, sampling, progress and log notifications, and tool-list change notifications are not proxied. A client asking for `resources/list` gets "Method not found".
- **Whoever can write to the approvals directory can approve.** That includes an agent that also has a filesystem or shell tool. Keep the directory somewhere the agent cannot reach. The proxy creates it with mode 0700, which stops other users, not other tools running as you.
- **Elicitation is only as trustworthy as the client.** A client can answer an approval prompt without showing it to anyone. The `approver` recorded in that mode is the client's name, because that is all the proxy can see.
- **Redaction is by key name.** A secret inside a free-text value (a password in an email body) is logged as is.
- **The audit log is append-only by the proxy's behaviour, not by enforcement.** Anything with write access to the file can alter it. For tamper evidence, ship it elsewhere or use the filesystem's append-only flag.
- **Fields the SDK does not model are dropped.** Tools pass through the SDK's models. Everything the protocol defines survives, and input and output schemas survive whole, vendor keywords included. A non-standard key on the tool object itself, or inside `annotations`, does not. Key order within JSON objects is not preserved.
- **stdio only, one upstream, one client.** The proxy always uses the `initialize` handshake with the upstream.
- **A killed proxy does not signal the upstream.** On a normal disconnect the upstream is shut down properly. If the proxy itself is killed, the upstream sees its stdin close, which a well-behaved stdio server treats as the signal to exit.
- **When the upstream dies mid-call, the proxy cannot say whether the call took effect.** The audit line records `connection_lost`, not an outcome.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

114 tests, all offline. They start real subprocesses, so a run takes about 40 seconds.

- **`test_policy.py`** and **`test_audit.py`** test the decision table, policy parsing, the log writer, and redaction directly.
- **`test_proxy.py`**, **`test_approval.py`**, and **`test_lifecycle.py`** start the proxy as a subprocess in front of `tests/fake_upstream.py` and talk to it over stdio, with an SDK client session or with raw JSON-RPC lines. Nothing in them calls the proxy's functions. `tools/list` and a tool result are compared, as JSON, against what the upstream returns when asked directly. "Blocked" is asserted against the fake upstream's own log of the calls it received, not against the proxy's account of itself.

Covered over the protocol: tool re-exposure including a paged upstream list, each policy outcome, redaction in the log and not in the forwarded call, file approval (approved, denied, timed out, cancelled, and through `mcp-guardrail-approve`), elicitation at both protocol versions including attempts to replay or move an approval, upstream paths with spaces in both command forms, and each exit status. The upstream-crash tests kill the fake upstream while the client is still connected.

The guards were mutation-checked: 51 deliberate breakages of the source (forwarding a denied call, redacting the forwarded arguments, reading only the first page of tools, accepting duplicate policy keys, and so on), each confirmed to fail a specific test before being reverted.

### Verified and pending

Verified, on macOS (Apple Silicon) with `mcp` 2.3.0:

- The test suite on Python 3.13 and 3.15.
- The sysops-mcp demo above, with the proxy on `mcp` 2.3.0 and sysops-mcp on `mcp` 2.0.0.
- Installing from a fresh clone by the quickstart steps and running the tests there.

Pending:

- **Linux and Windows.** Not run. A CI workflow for Linux and macOS across Python 3.10 to 3.13 is in the repo but has not run yet. Nothing has been tried on Windows.
- **Python 3.10 to 3.12.** Declared supported, not yet run.
- **Claude Desktop and other GUI clients.** The config example passes the same arguments the tests and the demo pass, but has not been loaded into Claude Desktop.
- **Elicitation against a third-party client.** Tested only with the Python SDK's own client, at both protocol versions.
- **Upstreams other than sysops-mcp and the test fake**, such as servers written with the TypeScript SDK.

## Roadmap

- Argument-level rules (allow a tool only for certain argument values)
- Streamable HTTP upstreams
- Proxying resources and prompts, and relaying progress notifications
- An approval backend that posts to a chat webhook

## License

MIT
