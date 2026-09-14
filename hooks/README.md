# Hooks

Host hooks are the only part of this repository that can stop an action. Each
one is scoped to a named host and a named tool path, and is labeled as
enforcement for that path only. Everything else in the repository is advice.

| Hook | Host | Path covered | What it does | Verified |
| --- | --- | --- | --- | --- |
| `claude-code/pretooluse-secrets.py` | Claude Code | `Bash` tool, PreToolUse | Denies a shell command that contains a literal credential (the secret-blocking patterns) with a plain-language reason. Never returns allow. Fails closed on malformed input. | See the tested-runtimes table in the README for the host version and date. |
| `claude-code/pretooluse-write-private-key.py` | Claude Code | `Write`/`Edit`/`MultiEdit`/`NotebookEdit` tools, PreToolUse | Denies file content that contains a PEM private-key header (RSA, EC, DSA, OPENSSH, ENCRYPTED, and PGP PRIVATE KEY BLOCK variants) with a plain-language reason that never echoes the content. Never returns allow. Fails closed on malformed or oversized input. | See the tested-runtimes table in the README for the host version and date, and [`evals/reports/2026.09.14-write-hook-verification.md`](../evals/reports/2026.09.14-write-hook-verification.md). |

## Claude Code: literal credentials in shell commands

### Install

1. Copy `claude-code/pretooluse-secrets.py` somewhere stable, or reference it
   from a clone of this repository. Python 3.8 or later is required; the
   script uses only the standard library.
2. Add the hook to your user settings (`~/.claude/settings.json`) or a
   project's `.claude/settings.json`. `claude-code/settings.example.json` is
   the exact shape; replace the absolute path.
3. Start a new Claude Code session. Hooks are read at session start.

### Test it without a real secret

Ask Claude Code to run a command that contains AWS's published example key
(`AKIAIOSFODNN7EXAMPLE` is documentation-only and not a real credential).
The command is denied and the reason names the credential type without
echoing the value. Then ask for the same command with `$AWS_ACCESS_KEY_ID`
instead; it runs.

### Exact coverage

- Covered: commands the agent runs through the `Bash` tool in a session
  where the hook is configured and the host reports it loaded.
- Not covered: file writes and edits, prompts, other tools, MCP servers,
  commands you type yourself, subprocesses spawned by scripts the agent
  already had permission to run, and any host other than Claude Code.
- Failure behavior: if the hook cannot parse its input, it exits 2 and the
  host blocks the command. If the hook is not configured, disabled, or times
  out, the host's own rules apply and nothing here protects the path. A hook
  that is not running is not a control.

### False positives

The patterns are conservative, and the escape hatch is deliberate: reference
the value from an environment variable or a secret store (the hook never
matches `$VAR` or `${VAR}`), or run the command yourself. There is no bypass
flag.

### Patterns

The patterns are the shell-relevant subset of the secret-blocking component's
detection table: Stripe, AWS, GitHub, GitLab, Anthropic, OpenAI, Slack,
Google, Square, SendGrid, npm, JSON Web Tokens, private key blocks, database
URLs with embedded passwords, bearer tokens, and literal `api_key`,
`password`, `secret`, `token`, and `DATABASE_URL` assignments. Read the
script; it is short.

## Claude Code: private-key blocks in file writes

### Install

1. Both hooks come from the same `claude-code/settings.example.json`. Copy
   `claude-code/pretooluse-write-private-key.py` somewhere stable, or
   reference it from a clone of this repository. Python 3.8 or later is
   required; the script uses only the standard library.
2. Add the hook to your user settings (`~/.claude/settings.json`) or a
   project's `.claude/settings.json`, matcher
   `Write|Edit|MultiEdit|NotebookEdit`. `claude-code/settings.example.json`
   has the exact shape for both hooks; replace the absolute path.
3. Start a new Claude Code session. Hooks are read at session start.

### Test it without a real secret

Ask Claude Code to write a file whose content is a PEM private-key header
line (for example `-----BEGIN RSA PRIVATE KEY-----`) plus a synthetic body
such as `SYNTHETIC-NOT-A-KEY`. The write is denied and the reason names the
problem without echoing the content. Then ask for the same file without the
header line; it is written.

### Exact coverage

- Covered: content added through the `Write`, `Edit`, `MultiEdit`, and
  `NotebookEdit` tools (the `content`, `new_string`, each edit's
  `new_string`, and `new_source` fields) in a session where the hook is
  configured and the host reports it loaded, when that content contains a
  PEM private-key header (RSA, EC, DSA, OPENSSH, ENCRYPTED, and PGP PRIVATE
  KEY BLOCK variants).
- Not covered: shell commands (the existing `pretooluse-secrets.py` Bash
  hook separately denies a command containing a private-key header), file
  reads, prompts, other tools, other hosts, and files a person edits
  themselves.
- Failure behavior: if the hook cannot parse its input, or the input is
  over 1 MiB, it exits 2 and the host blocks the write. If the hook is not
  configured, disabled, or times out, the host's own rules apply and
  nothing here protects the path. A hook that is not running is not a
  control.

## Inside your own harness

The same check is available as a function for any Python loop you control:
`hooks/harness/secret_gate.py`, documented in [`harness/README.md`](harness/README.md).
The harness owns its tool boundary, so a gate it enforces is enforcement on
that path; a skill it loads is still advice.

## Other hosts

Cursor has a hooks facility. The same check will be ported only after it is
tested there, and the tested-runtimes table will say so. ChatGPT and
Claude.ai have no hook surface; the honest story on those hosts is coaching
plus the platform's own admin controls.
