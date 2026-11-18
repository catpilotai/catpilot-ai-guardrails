# Evidence events

**Status:** Active, schema version 1. Schema: [`evidence-event.schema.json`](./evidence-event.schema.json). Writer: [`catpilot_guard/evidence.py`](../../catpilot_guard/evidence.py).
**Companion to:** [`docs/DEPLOY_ORG.md`](../DEPLOY_ORG.md#the-evidence-log) (turning the log on, and what it is for), [`OVERLAY_V2.md`](./OVERLAY_V2.md) (where `rule_id`, `mode` and `exception_id` come from).

---

## 1. What a line is

The three Claude Code hooks, the session-start script
([`hooks/session-start/`](../../hooks/session-start/README.md)) and the
reference MCP server can record what they did as one JSON object per line. Each line is UTF-8 and ends with a newline.
Nothing is written unless one of these is set in the writer's environment:

- `CATPILOT_EVIDENCE_LOG`: a file path. Each event appends one line. `~` is
  expanded and missing directories are created.
- `CATPILOT_EVIDENCE_SYSLOG`: `1`, `true` or `yes` for the local syslog
  socket, a `host:port` for UDP, or a socket path. Each event sends the same
  line, prefixed `catpilot-guardrails: `.

One writer, `catpilot_guard/evidence.py`, builds every line for every source.
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
| `source` | all | `claude-code-hook`, `mcp-server` or `session-start`. `claude-code-hook` names the hooks in `hooks/claude-code/` by the event format they read, on whichever tool runs them; `host` says which tool that was. |
| `event` | all | One of the list in §3. |
| `host` | hooks, session start | For a `PreToolUse` hook, `claude-code`, `codex` or `copilot-cli`, from its `--host` argument, and `claude-code` with no argument, as in every configuration written before the argument existed; absent when the argument was malformed or named another tool. Hook lines written before the argument said `claude-code` on Codex too. For the session-start script, `claude-code` or `codex`, from its `--host` argument; absent when that argument was missing or unknown. Absent when a harness calls the check, and on server lines: the server does not know which tool called it. Never the machine's hostname. |
| `session_id` | hooks, session start | The session id from the hook event, when it is an opaque id: 1 to 128 letters, digits, `.`, `_`, `:` or `-`. Any other value is left out. |
| `session_source` | session start | How the session started, from the `SessionStart` event: `startup`, `resume`, `clear`, `compact` or `fork`. Absent when the event did not say, or said something else. |
| `release` | server, session start | Server: the CalVer release of the guidance that answered, from `mcp-server/defaults/guidance.json`. Session start: the release the company rules bundle was built from, from its `company-checklist.json`, when it has this shape. The hooks have no release of their own yet and leave it out. |
| `policy_sha256` | server, session start, company-rules hook | SHA-256 of the company rules file's bytes. Server: on every call where the file was read and parsed, error answers included; absent with no file, a missing file, or one that fails the structure check. Session start: the hash the private build recorded, on `rules_delivered` and `rules_expired`. Company-rules hook: the hash its compiled policy records, on `deny`, `ask` and `would_deny`. |
| `block_chars`, `block_lines` | session start | On `rules_delivered`: the size of `company-checklist.md` in characters and in lines. Sizes only, so an administrator can see a block that is over a host's budget. |
| `rule_id` | company-rules hook | The id of the company rule that matched ([`OVERLAY_V2.md`](./OVERLAY_V2.md) §2.1), on `deny`, `ask` and `would_deny`. When several rules match one command, each writes its own line. |
| `mode` | company-rules hook | The mode that applied to that rule: `monitor`, `ask` or `block` ([`OVERLAY_V2.md`](./OVERLAY_V2.md) §2.3), and `monitor` for every rule once the rules file has expired. On a `would_deny` line with `exception_id`, the rule's own mode, whether or not that mode would have decided anything. The built-in checks have no mode. |
| `exception_id` | company-rules hook | The id of an expiring exception that covered something the rule `rule_id` names matched ([`OVERLAY_V2.md`](./OVERLAY_V2.md) §3.1), when exceptions covered all of that rule's matches, so the rule decided nothing. Written whether or not the rule would have decided anything (a `monitor` rule would not) and whether or not another rule decided the command. Only on `would_deny`, always with `rule_id`: one line per exception that covered something the rule matched. Absent unless exceptions covered all of the rule's matches. Same shape as `rule_id`. |
| `hook` | hooks | `pretooluse-secrets`, `pretooluse-write-secrets`, `pretooluse-destructive-ops` or `pretooluse-company-rules`. |
| `tool` | all | Hooks: the tool checked (`Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, or Codex's `apply_patch`). Server: the MCP tool called. |
| `label` | hooks, session start | Hooks: the fixed label of what matched: a credential type, `private-key-block`, or a destructive-operation type. Company-rules hook, on `policy_error`: why its compiled policy could not be used, one of `bad-arguments`, `missing`, `unreadable`, `wrong-owner`, `malformed` or `internal-error`. Session start, on `policy_error`: why the rules could not be loaded, one of `bad-arguments`, `missing`, `unreadable`, `malformed`, `hash-mismatch` or `internal-error`. |
| `error`, `policy_status`, `unknown_policy` | server | On every server line; `null` when the tool returned an error. |
| `topic`, `category`, `kind` | server | The enumerated argument, or `invalid`. |
| `outcome`, `ask_a_human`, `fields` | server | For `check_plan`: the outcome, whether to ask a human, and the names of the fields supplied. |

## 3. Events

`event` takes one closed list of values.

| Event | Meaning | Written by today |
| --- | --- | --- |
| `deny` | A check denied a tool call. From the company-rules hook, one line per company rule that matched and denied, or whose `ask` acted as `block` because nobody could be asked. | the four hooks |
| `input_error` | A hook could not read its input and exited 2, which blocks. | the four hooks |
| `lookup` | The server answered a tool call, including with an error. | the server |
| `ask` | A rule in `ask` mode had the host ask the person. The line records that they were asked, not what they chose: a `PreToolUse` hook does not see the answer. | the company-rules hook |
| `would_deny` | A rule in `monitor` mode, or any rule of an expired rules file, matched; nothing was blocked. With `exception_id`: a rule matched and an active expiring exception covered everything it matched, so the rule decided nothing, whatever its `mode`. | the company-rules hook |
| `policy_error` | A company rules file could not be loaded or did not validate. The company-rules hook then applies no company rule; the built-in checks are unaffected. | the session-start script, the company-rules hook |
| `rules_delivered` | The company rules were delivered at session start. On Claude Code, the script delivers a one-line status; the managed `CLAUDE.md` carries the rules. | the session-start script |
| `rules_expired` | At session start, the company rules file was past its expiry date. | the session-start script |

Lines written before schema version 1 map onto the list without a change:
hook lines already carry `event` (`deny` or `input_error`), and a server line
without `event` is a `lookup`. No key was renamed, so
`tools/evidence_summary.py` reads old lines, new lines, and a mix of the two.
On the server, a broken or missing rules file is reported in a `lookup`
line's `policy_status`, as before, not as `policy_error`.

## 4. Never recorded

No line carries a command, a file path, file content, a prompt, a plan
description, a data class, hosting or service text, a credential reference
name, a matched secret, or any value from the company rules file, including
its owner and its dates. A
`session_id` that is not an opaque id is dropped. The writer refuses a line
whose `event`, `mode`, `rule_id`, `exception_id`, `session_id` or `policy_sha256` has the
wrong shape, and the schema allows no field beyond those in §2. The schema
also limits a session-start line's `event` and `label` to the values above,
and, with the writer, refuses `exception_id` anywhere but on a company-rules
hook's `would_deny` line that has `rule_id`.

## 5. How lines are written

- Each line is one `write` to a file opened for append.
- Where `fcntl` exists, the writer takes an exclusive lock on the file first.
  It waits at most half a second for the lock and then writes without it, so
  a held lock cannot stall a decision. Where `fcntl` does not exist (Windows),
  or the file system has no locks, it writes without one.
- The writer never raises. A path it cannot write, a syslog address that does
  not resolve, or a broken writer module drops the line and changes no
  decision, exit code, answer or session-start output. The hooks, the
  session-start script and the server import the writer only when they write
  a line.

## 6. Versions

`schema_version` goes up when a field is removed or renamed, a field changes
meaning or type, or the `event` list changes. Adding an optional field, or a
value to any other list, keeps version 1. The `session-start` source, the
`codex` host, and the `session_source`, `block_chars`, `block_lines` and
`exception_id` fields were added this way, so a session-start line is version
1 too, and so is a hook line with `host` `codex`. That rule is why an
exception that covered all of a rule's matches writes `would_deny` with `exception_id`
rather than an event of its own. Validate a line
against the schema in the release that wrote it.

## 7. Not in version 1

- Tamper evidence. A line can be edited or deleted by anyone who can write
  the file. A hash chain is planned separately.
- Who acted. There is no user or account field; an opt-in one is planned
  separately.
- Mappings to other event formats, such as OCSF or ECS.
