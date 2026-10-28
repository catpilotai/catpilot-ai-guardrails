# Hooks

Host hooks are the only part of this repository that can stop an action. Each
one is scoped to a named host and a named tool path, and is labeled as
enforcement for that path only. Everything else in the repository is advice.

| Hook | Host | Path covered | What it does | Verified |
| --- | --- | --- | --- | --- |
| `claude-code/pretooluse-secrets.py` | Claude Code | `Bash` tool, PreToolUse | Denies a shell command that contains a literal credential (the secret-blocking patterns) with a plain-language reason. Never returns allow. Fails closed on malformed input or any internal error. | Claude Code 2.1.312, 2026-10-27: [`evals/reports/2026.10.27-hooks-verification.md`](../evals/reports/2026.10.27-hooks-verification.md); earlier rows in the tested-runtimes table. |
| `claude-code/pretooluse-write-secrets.py` (formerly `pretooluse-write-private-key.py`, kept as a compatibility entry point) | Claude Code | `Write`/`Edit`/`MultiEdit`/`NotebookEdit` tools, PreToolUse | Denies file content that contains a PEM private-key header or a literal credential matching the secret-blocking patterns, with a plain-language reason that never echoes the content. Never returns allow. Fails closed on malformed or oversized input, a missing sibling file, or any internal error. | Claude Code 2.1.312, 2026-10-27, under both file names: [`evals/reports/2026.10.27-hooks-verification.md`](../evals/reports/2026.10.27-hooks-verification.md). |
| `claude-code/pretooluse-destructive-ops.py` | Claude Code | `Bash` tool, PreToolUse | Parses the command like a shell and denies a high-blast-radius operation (partial cloud-config resets, auto-approved infrastructure destroys, `kubectl delete` of a namespace or with `--all`, a recursive delete of root, a system directory, home, a credential directory, or a bare variable, a force push or deletion aimed at a protected branch, credential exfiltration pipes) with the safer alternative. Never returns allow. Fails closed on malformed input or any internal error. | Claude Code 2.1.312, 2026-10-27: [`evals/reports/2026.10.27-hooks-verification.md`](../evals/reports/2026.10.27-hooks-verification.md). |

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
- Not covered: prompts, other tools, MCP servers, commands you type yourself,
  subprocesses spawned by scripts the agent already had permission to run, and
  any host other than Claude Code.
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
`password`, `secret`, `token`, and `DATABASE_URL` assignments — both the
quoted form (`password="value"`) and the unquoted CLI/env-assignment form
(`--password=value`, mysql/mysqldump/mariadb's attached `-pvalue`,
`PGPASSWORD=value`), plus a JSON-style quoted key (`"password": "value"`).
Read the script; it is short.

## Claude Code: literal credentials and private-key blocks in file writes

### Install

1. The hooks come from the same `claude-code/settings.example.json`. Copy
   `claude-code/pretooluse-write-secrets.py` and `claude-code/pretooluse-secrets.py`
   (it loads the credential patterns from there) somewhere stable, side by side,
   or reference them from a clone of this repository. Settings that still point
   at `pretooluse-write-private-key.py` keep working: that file now runs
   `pretooluse-write-secrets.py`. Python 3.8 or later is
   required; the script uses only the standard library.
2. Add the hook to your user settings (`~/.claude/settings.json`) or a
   project's `.claude/settings.json`, matcher
   `Write|Edit|MultiEdit|NotebookEdit`. `claude-code/settings.example.json`
   has the exact shape; replace the absolute path.
3. Start a new Claude Code session. Hooks are read at session start.

### Test it without a real secret

Ask Claude Code to write a file whose content is a PEM private-key header
line (for example `-----BEGIN RSA PRIVATE KEY-----`) plus a synthetic body
such as `SYNTHETIC-NOT-A-KEY`, or a literal test credential such as
`AKIAIOSFODNN7EXAMPLE`. The write is denied and the reason names the
problem without echoing the content. Then ask for the same file using an
environment variable reference (`os.environ["AWS_ACCESS_KEY_ID"]`) or
`REPLACE_ME`; it is written.

### Exact coverage

- Covered: content added through the `Write`, `Edit`, `MultiEdit`, and
  `NotebookEdit` tools (the `content`, `new_string`, each edit's
  `new_string`, and `new_source` fields) in a session where the hook is
  configured and the host reports it loaded, when that content contains a
  PEM private-key header (RSA, EC, DSA, OPENSSH, ENCRYPTED, and PGP PRIVATE
  KEY BLOCK variants) or a literal credential matching the 27 patterns in
  `pretooluse-secrets.py`.
- Not covered: file reads, prompts, other tools, other hosts, and files a
  person edits themselves.
- Failure behavior: if the hook cannot parse its input, the input is over
  1 MiB, `pretooluse-secrets.py` is missing beside it, or anything else goes
  wrong, it exits 2 and the host blocks the write. If the hook is not
  configured, disabled, or times out, the host's own rules apply and
  nothing here protects the path. A hook that is not running is not a
  control.

### False positives

Not reported, on purpose: environment references (`$VAR`, `${VAR}`), obvious
placeholders (`REPLACE_ME`, `YOUR_API_KEY`, ...), the stock passwords of local
development stacks (`postgres`, `password`, `admin`, ...), and database URLs
whose host is `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, or
`host.docker.internal`.

There is no in-content marker that waves a line through, such as
detect-secrets' `pragma: allowlist secret`. An earlier candidate honored one;
on a real host the model read the reason, added the marker, and retried
successfully ([`evals/reports/2026.10.27-hooks-verification.md`](../evals/reports/2026.10.27-hooks-verification.md)). Anything the agent can do by itself is a bypass. A
deliberate credential-shaped example in documentation (this repository's own
skill references have several) is written by a person, or edited with the hook
off for that repository.

## Claude Code: destructive CLI operations in shell commands

`claude-code/pretooluse-destructive-ops.py` blocks high-blast-radius shell
commands on the `Bash` tool path. It splits the command into simple commands
the way a shell would (pipes, `;`, `&&`, `||`, subshells), looks through
`sudo`, `env`, `time`, and similar wrappers and through `bash -c "..."`, and
then checks:

- Cloud and infrastructure CLIs: partial-resource updates that reset
  unspecified fields (`az containerapp update --yaml` / `--replace-env-vars`,
  `aws lambda update-function-configuration --environment Variables={...}`,
  `gcloud run services update --set-env-vars`, `gcloud projects set-iam-policy`),
  auto-approved Terraform (`-auto-approve` or `--auto-approve`), `aws s3 rb
  --force`, `aws s3 rm --recursive` without `--dryrun`, `gsutil rm -r`, and
  quiet `gcloud` deletions.
- `kubectl delete` of a namespace, or with `--all`, `--all-namespaces`, or
  `-A`, unless `--dry-run=client` or `--dry-run=server` (`--dry-run=none`
  really deletes, and is blocked).
- Recursive `rm` (any spelling: `-rf`, `-Rf`, `-r -f`, `--recursive`) of `/`,
  a top-level system directory, the home directory, a credential directory
  (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config`), or a
  bare variable, quoted or not (`"$TARGET"`, `${TARGET}/*`), which removes
  `/` or the current tree when the variable is unset. A named subdirectory
  (`~/Library/Caches/pip`, `"$BUILD_DIR/dist"`) is allowed.
- `git push` with `--force`, `-f`, `--force-with-lease`, or a `+refspec` to
  `main`, `master`, `trunk`, `production`, `prod`, `staging`, `develop`, or
  `release/*` (exact branch names, so `feature/main-fix` is fine), a bare
  `git push --force` while one of those is checked out (read from
  `.git/HEAD`, and blocked when the branch cannot be read), a deletion of one
  of those branches, and `git push --mirror`.
- Database and cache resets: `prisma db push --accept-data-loss`, `prisma
  migrate reset --force`, `rails`/`rake` `db:drop`, `db:reset`,
  `db:schema:load`, and `db:structure:load`, Django `flush --noinput`,
  `dropdb`, `redis-cli FLUSHALL`/`FLUSHDB`, and a `psql`, `mysql`,
  `mariadb`, `sqlite3`, or `sqlcmd` command whose command line contains
  `DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE`, `TRUNCATE`, or a `DELETE
  FROM` with no `WHERE` clause. The whole command line is read, so SQL given
  with `-c`/`-tAc`/`-e`/`-Q`, as an argument, in a heredoc or here-string, or
  through a pipe is covered. The same checks apply through `docker`/`podman
  exec`, `docker compose exec`/`run`, `kubectl exec --`, `railway run`, and
  package runners (`npx`, `npm exec`, `yarn`, `pnpm`, `bundle exec`,
  `poetry`/`uv`/`pipenv run`). SQL in a file (`psql -f`, `< file.sql`) is not
  read, and a statement that mentions `DROP TABLE` inside a string literal is
  refused like the real thing; a person runs it.
- `chmod -R 777`, `dd` to a raw block device, credential or environment dumps
  piped to a network client, and `curl ... | sudo bash`.

Text inside quotes is not a command, so `echo "rm -rf /"` and
`grep 'git push --force origin main'` are allowed.

### Exact coverage

- Covered: commands the agent runs through the `Bash` tool, as above.
- Not covered: a deliberately disguised command (`eval`, base64, a variable
  holding the verb), commands a script runs internally, prompts, other tools,
  and any host other than Claude Code. It stops accidents, not an adversary.
- Failure behavior: malformed input or any internal error exits 2 and the host
  blocks the command. It does not need the other hook files beside it (they
  are loaded only for optional syslog).
- The way past a false positive is a person running the command in their own
  terminal; there is no flag the agent can add.

## Evidence log and syslog

Set `CATPILOT_EVIDENCE_LOG` to a file path in the hook's environment (the
managed-settings example in `deploy/org/` does it on the command line) and each
deny appends one JSON line: the time, the hook, the decision, the credential
type, `private-key-block`, or destructive operation label, the tool, and the
session id. Set `CATPILOT_EVIDENCE_SYSLOG=1` (or a `host:port` / socket path)
to emit the same content-free JSON line to syslog. Never the command, the file
path, or the content. Malformed input is recorded as `input_error` beside the
fail-closed exit. Off unless set; a logging failure never changes the decision.
Summarize collected logs with `python3 tools/evidence_summary.py`.

## Inside your own harness

The same checks are available as functions for any Python loop you control:
`hooks/harness/secret_gate.py` (`gate_shell_command`, `gate_tool_call`,
`gate_file_write`, `gate_write_tool_call`) and
`hooks/harness/destructive_gate.py` (`gate_destructive_command`,
`gate_destructive_tool_call`), documented in [`harness/README.md`](harness/README.md).
The harness owns its tool boundary, so a gate it enforces is enforcement on
that path; a skill it loads is still advice.

## Other hosts

Cursor has a hooks facility. The same check will be ported only after it is
tested there, and the tested-runtimes table in `docs/REFERENCE.md` will say so. ChatGPT and
Claude.ai have no hook surface; the honest story on those hosts is coaching
plus the platform's own admin controls.
