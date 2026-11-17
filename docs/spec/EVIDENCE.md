# Evidence events

**Status:** Active, schema version 1. Schema: [`evidence-event.schema.json`](./evidence-event.schema.json). Writer: [`catpilot_guard/evidence.py`](../../catpilot_guard/evidence.py).
**Companion to:** [`docs/DEPLOY_ORG.md`](../DEPLOY_ORG.md#the-evidence-log) (turning the log on, and what it is for), [`OVERLAY_V2.md`](./OVERLAY_V2.md) (where `rule_id` and `mode` come from).

---

## 1. What a line is

The three Claude Code hooks and the reference MCP server can record what they
did as one JSON object per line. Each line is UTF-8 and ends with a newline.
Nothing is written unless one of these is set in the writer's environment:

- `CATPILOT_EVIDENCE_LOG`: a file path. Each event appends one line. `~` is
  expanded and missing directories are created.
- `CATPILOT_EVIDENCE_SYSLOG`: `1`, `true` or `yes` for the local syslog
  socket, a `host:port` for UDP, or a socket path. Each event sends the same
  line, prefixed `catpilot-guardrails: `.

One writer, `catpilot_guard/evidence.py`, builds every line for both sources.
The server imports it from the repository root, and the container image
copies it.

## 2. Fields

Every line has the first five fields. The rest appear when the writer has a
value for them, and are left out otherwise.

| Field | Written by | Value |
| --- | --- | --- |
| `schema_version` | all | `1`. A line without it was written before this schema. |
| `event_id` | all | A random UUID, lowercase. Unique per line; it has no other meaning. |
| `ts` | all | The time in UTC, to the second: `2026-11-16T15:04:05+00:00`. |
| `source` | all | `claude-code-hook` or `mcp-server`. |
| `event` | all | One of the list in §3. |
| `host` | hooks | `claude-code` when the hook runs as a Claude Code `PreToolUse` hook. Absent when a harness calls the check, and on server lines: the server does not know which tool called it. Never the machine's hostname. |
| `session_id` | hooks | The session id from the hook event, when it is an opaque id: 1 to 128 letters, digits, `.`, `_`, `:` or `-`. Any other value is left out. |
| `release` | server | The CalVer release of the guidance that answered, from `mcp-server/defaults/guidance.json`. The hooks have no release of their own yet and leave it out. |
| `policy_sha256` | server | SHA-256 of the company rules file's bytes, on every call where the file was read and parsed, error answers included. Absent with no file, a missing file, or one that fails the structure check. The hooks load no rules file yet. |
| `rule_id` | not yet | The id of the company rule that decided ([`OVERLAY_V2.md`](./OVERLAY_V2.md) §2.1). |
| `mode` | not yet | That rule's mode: `monitor`, `ask` or `block` ([`OVERLAY_V2.md`](./OVERLAY_V2.md) §2.3). The built-in checks have no mode. |
| `hook` | hooks | `pretooluse-secrets`, `pretooluse-write-secrets` or `pretooluse-destructive-ops`. |
| `tool` | all | Hooks: the tool checked (`Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`). Server: the MCP tool called. |
| `label` | hooks | The fixed label of what matched: a credential type, `private-key-block`, or a destructive-operation type. |
| `error`, `policy_status`, `unknown_policy` | server | On every server line; `null` when the tool returned an error. |
| `topic`, `category`, `kind` | server | The enumerated argument, or `invalid`. |
| `outcome`, `ask_a_human`, `fields` | server | For `check_plan`: the outcome, whether to ask a human, and the names of the fields supplied. |

## 3. Events

`event` takes one closed list of values.

| Event | Meaning | Written by today |
| --- | --- | --- |
| `deny` | A check denied a tool call. | the three hooks |
| `input_error` | A hook could not read its input and exited 2, which blocks. | the three hooks |
| `lookup` | The server answered a tool call, including with an error. | the server |
| `ask` | A rule in `ask` mode asked the person. The line records that they were asked, not what they chose. | nothing yet |
| `would_deny` | A rule in `monitor` mode matched; nothing was blocked. | nothing yet |
| `policy_error` | A company rules file could not be loaded or did not validate. | nothing yet |
| `rules_delivered` | The company rules were delivered at session start. | nothing yet |
| `rules_expired` | At session start, the company rules file was past its expiry date. | nothing yet |

Lines written before schema version 1 map onto the list without a change:
hook lines already carry `event` (`deny` or `input_error`), and a server line
without `event` is a `lookup`. No key was renamed, so
`tools/evidence_summary.py` reads old lines, new lines, and a mix of the two.
On the server, a broken or missing rules file is reported in a `lookup`
line's `policy_status`, as before, not as `policy_error`.

## 4. Never recorded

No line carries a command, a file path, file content, a prompt, a plan
description, a data class, hosting or service text, a credential reference
name, a matched secret, or any value from the company rules file. A
`session_id` that is not an opaque id is dropped. The writer refuses a line
whose `event`, `mode`, `rule_id`, `session_id` or `policy_sha256` has the
wrong shape, and the schema allows no field beyond those in §2.

## 5. How lines are written

- Each line is one `write` to a file opened for append.
- Where `fcntl` exists, the writer takes an exclusive lock on the file first.
  It waits at most half a second for the lock and then writes without it, so
  a held lock cannot stall a decision. Where `fcntl` does not exist (Windows),
  or the file system has no locks, it writes without one.
- The writer never raises. A path it cannot write, a syslog address that does
  not resolve, or a broken writer module drops the line and changes no
  decision, exit code or answer. The hooks and the server import the writer
  only when they write a line.

## 6. Versions

`schema_version` goes up when a field is removed or renamed, a field changes
meaning or type, or the `event` list changes. Adding an optional field, or a
value to any other list, keeps version 1. Validate a line against the schema
in the release that wrote it.

## 7. Not in version 1

- Tamper evidence. A line can be edited or deleted by anyone who can write
  the file. A hash chain is planned separately.
- Who acted. There is no user or account field; an opt-in one is planned
  separately.
- Mappings to other event formats, such as OCSF or ECS.
