# Company rules at session start

`catpilot-company-rules.py` is a `SessionStart` hook for Claude Code and
Codex. It puts a company's reviewed rules in front of the model when a
session starts, or says plainly that they expired or could not be loaded.
The code is `catpilot_guard/session_start.py`.

This is advice, not enforcement. `SessionStart` cannot block on either host,
so every message it prints is a notice, not a control. It has not been run
on a host. `deploy/org/install.sh --overlay` places it on both tools
([below](#deployed-by-deployorg)).

## What it reads

A private build (`python tools/bundle.py --overlay rules.yaml --private-out DIR`)
writes two files into `DIR/catpilot-safe-building-<org>-hosts/`:

| File | What it holds |
| --- | --- |
| `company-checklist.md` | The short checklist and the company rules: the text benchmark condition F plants. |
| `company-checklist.json` | The owner, `reviewed_on`, `expires_on`, the release, the SHA-256 of the rules file, and the SHA-256 of `company-checklist.md`. No rule text. |

The script reads both from one directory. By default that is `instructions/`
beside the directory that holds the script, so a copy at
`<managed dir>/catpilot-guardrails/hooks/catpilot-company-rules.py` reads
`<managed dir>/catpilot-guardrails/instructions/`. `--dir` names another
directory; it must be an absolute path, because the hook runs in the
session's working directory, which the user controls.

```
python3 catpilot-company-rules.py --host claude-code|codex [--dir /absolute/path]
```

It reads the `SessionStart` event on stdin for the session id and how the
session started (`startup`, `resume`, `clear`, `compact` or `fork`). A
missing or unreadable event is not an error.

## What it prints

On both hosts it prints one JSON object, the shape both vendors document for
`SessionStart`:

```json
{"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "..."}, "systemMessage": "..."}
```

`additionalContext` goes to the model. `systemMessage`, a warning both hosts
show the person, is added only when the rules expired or could not be loaded.

| Rules | Codex | Claude Code | Evidence |
| --- | --- | --- | --- |
| Current: today is on or before `expires_on` | The whole block, as developer context | One line: "Company rules from `<owner>`, reviewed `<date>`, valid until `<date>`, are current." The block itself comes from a managed `CLAUDE.md`. | `rules_delivered` |
| Expired | "The company rules expired on `<date>` and are not in force. Ask `<owner>` for current rules." No rules. | The same, plus: "The company rules in the instruction file are out of date and must not be relied on." | `rules_expired` |
| Anything wrong | "Company rules could not be loaded and are unknown. Ask your IT or security owner." | The same | `policy_error` |

"Anything wrong" means a file is missing, unreadable, too large or
malformed; the JSON file's hashes do not match the block (for example, the
two files came from different builds); or the arguments are wrong. Without
the `catpilot_guard` package beside it or at the repository root, the script
prints the same notice. Every path exits 0, including a stdout the host
closed: a non-zero exit would only add a hook-error notice.

**Dates.** The expiry day itself is current. "Today" is the machine's local
date, as in `tools/validate_overlay.py` and the reference server: the
owner wrote a calendar date, and the person reads it against their own
calendar. With UTC, the rules would end in the afternoon or evening of the
expiry day in the Americas, and on the morning after it in East Asia. With
the local date, machines in different time zones switch at different
moments, about a day apart at the extremes; for a date reviewed every few
months, that is the smaller problem.

**Size.** On Codex, the block counts against the hook's context budget. Codex
gives the model only a preview of `additionalContext` above about 2,500
tokens unless the hook's `additionalContextLimit` is raised. Above that
budget, estimated at four characters per token, the script still delivers
the whole block and writes the size, never the text, to stderr. On Claude
Code, it does the same when the block is over 200 lines, the vendor's
guidance for a `CLAUDE.md` file. Every `rules_delivered` line carries the
block's size in `block_chars` and `block_lines`.

## Deployed by `deploy/org/`

`deploy/org/install.sh --overlay rules.yaml` builds the rules privately and
places them on each tool, root-owned, from its own copy:

| | Claude Code | Codex |
| --- | --- | --- |
| Script and package | `<managed dir>/catpilot-guardrails/hooks/catpilot-company-rules.py` and `hooks/catpilot_guard/` | `/etc/codex/catpilot-guardrails/hooks/`, the same two |
| Block and sidecar | `<managed dir>/catpilot-guardrails/instructions/company-checklist.md` and `.json` | `/etc/codex/catpilot-guardrails/instructions/`, the same two |
| The block reaches the model through | the managed `CLAUDE.md`, `<managed dir>/CLAUDE.md`, between `<!-- catpilot-company-rules:begin -->` and `<!-- catpilot-company-rules:end -->` | this script's `additionalContext` |
| The hook is registered in | `<managed dir>/managed-settings.json`, `hooks.SessionStart` | `/etc/codex/requirements.toml`, `[[hooks.SessionStart]]`, with `[hooks] managed_dir` set to the `hooks/` directory above |

`<managed dir>` is `/Library/Application Support/ClaudeCode` on macOS and
`/etc/claude-code` on Linux. Both registrations use the matcher
`startup|resume|clear|compact|fork`, a 10-second timeout, and the
`CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl"` prefix
the other hooks use. A managed file that already exists is never
overwritten: `install.sh` prints what to merge. The one exception is the
marked section of a managed `CLAUDE.md` that already has the markers: only
that section is replaced. Without `--overlay`, nothing here is placed or
registered.

`deploy/org/verify.sh` checks both copies and their hashes, the marked
section, the expiry date, the script run directly for each tool, and each
registered command run through a shell, writing no evidence line.
`deploy/org/uninstall.sh` removes the copies, the marked section (and the
`CLAUDE.md` when nothing else is in it), and a managed file that is still
byte-for-byte what `install.sh` wrote. Why the managed `CLAUDE.md` rather
than the `claudeMd` settings key, and what each tool does not reach:
[`docs/DEPLOY_ORG.md`](../../docs/DEPLOY_ORG.md#company-rules-at-session-start-on-claude-code).

## Evidence

With `CATPILOT_EVIDENCE_LOG` or `CATPILOT_EVIDENCE_SYSLOG` set, each run
writes one line with `source` `session-start`
([`docs/spec/EVIDENCE.md`](../../docs/spec/EVIDENCE.md)): the event, the host,
the session id when it is an opaque id, how the session started, the rules
file's SHA-256 and the release on `rules_delivered` and `rules_expired`, and
on `policy_error` a fixed `label` saying why (`bad-arguments`, `missing`,
`unreadable`, `malformed`, `hash-mismatch` or `internal-error`). Never rule
text, the owner, the dates, a path, or anything from the hook event besides
the session id. A logging failure changes nothing the script prints.

## What it does not do

- It does not block, approve or check anything the model does.
- It does not prove the model read or followed the rules.
- It does not reach Claude Code cloud sessions, Claude.ai or ChatGPT.
- On Claude Code it does not deliver the rules; the managed `CLAUDE.md` does.
