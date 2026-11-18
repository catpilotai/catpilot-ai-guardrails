# Hooks

Host hooks are the only part of this repository that can stop an action. Each
one is scoped to a named host and a named tool path, and is labeled as
enforcement for that path only. Everything else in the repository is advice.

| Hook | Host | Path covered | What it does | Verified |
| --- | --- | --- | --- | --- |
| `claude-code/pretooluse-secrets.py` | Claude Code | `Bash` tool, PreToolUse | Denies a shell command that contains a literal credential (the secret-blocking patterns) with a plain-language reason. Never returns allow. Fails closed on malformed input or any internal error. | Claude Code 2.1.312, 2026-10-27: [`evals/reports/2026.10.27-hooks-verification.md`](../evals/reports/2026.10.27-hooks-verification.md); earlier rows in the tested-runtimes table. |
| `claude-code/pretooluse-write-secrets.py` (formerly `pretooluse-write-private-key.py`, kept as a compatibility entry point) | Claude Code; Codex (`apply_patch`) | `Write`/`Edit`/`MultiEdit`/`NotebookEdit` tools, and Codex's `apply_patch`, PreToolUse | Denies file content that contains a PEM private-key header or a literal credential matching the secret-blocking patterns, with a plain-language reason that never echoes the content. Never returns allow. Fails closed on malformed or oversized input, a missing sibling file, or any internal error. | Claude Code 2.1.312, 2026-10-27, under both file names: [`evals/reports/2026.10.27-hooks-verification.md`](../evals/reports/2026.10.27-hooks-verification.md). |
| `claude-code/pretooluse-company-rules.py` | Claude Code; Codex; Copilot CLI | `Bash` tool, PreToolUse | The company's own enforcement rules, from a compiled policy (`tools/validate_overlay.py compile`): denies, asks the person about, or only logs a force push or deletion aimed at a branch the company protects, or a deploy to a host it has not approved, by each rule's mode (`block`, `ask`, `monitor`). Names the rule and the approved alternative, never a listed value. Never returns allow. A policy it cannot use applies no company rule and is logged; the built-in hooks are unaffected. Fails closed on malformed input. | Claude Code 2.1.326, Codex CLI 0.169.0 and Copilot CLI 1.0.113, 2026-11-17, `block` and `monitor` with a control run (on Copilot, probe and control in separate runs at one commit): [`evals/reports/2026.11.17-host-check-company-rules.md`](../evals/reports/2026.11.17-host-check-company-rules.md). |
| `claude-code/pretooluse-destructive-ops.py` | Claude Code | `Bash` tool, PreToolUse | Parses the command like a shell and denies a high-blast-radius operation (partial cloud-config resets, auto-approved infrastructure destroys, `kubectl delete` of a namespace or with `--all`, a recursive delete of root, a system directory, home, a credential directory, or a bare variable, a force push or deletion aimed at a protected branch, credential exfiltration pipes) with the safer alternative. Never returns allow. Fails closed on malformed input or any internal error. | Claude Code 2.1.312, 2026-10-27: [`evals/reports/2026.10.27-hooks-verification.md`](../evals/reports/2026.10.27-hooks-verification.md). |

Each file in `claude-code/` is a thin shim. The check itself is a module of the
standard-library package [`catpilot_guard/`](../catpilot_guard/) at the repository
root: `secrets.py`, `write_secrets.py`, `destructive.py`, and `company_rules.py`
(with `policy.py`, which reads its compiled policy), with `evidence.py`, the
evidence writer they share. A shim looks for
`catpilot_guard/` next to itself (the layout `deploy/org/install.sh` places), then at
the repository root two levels up (a checkout), and runs the module's `main()`. If
the package is missing or cannot be imported, the shim exits 2, which blocks. The
host verifications in the table ran each hook as a self-contained script; the shim
layout has not been run on a host.

## Claude Code: literal credentials in shell commands

### Install

1. Copy `claude-code/pretooluse-secrets.py` and the `catpilot_guard/` directory
   from the repository root somewhere stable, side by side, or reference the
   hook from a clone of this repository, where it finds the package at the root.
   Python 3.8 or later is required; the code uses only the standard library.
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
- Failure behavior: if the hook cannot parse its input or cannot load the
  `catpilot_guard` package, it exits 2 and the host blocks the command. If the
  hook is not configured, disabled, or times out, the host's own rules apply
  and nothing here protects the path. A hook that is not running is not a
  control.

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
Read `catpilot_guard/secrets.py`; it is short.

## Claude Code: literal credentials and private-key blocks in file writes

### Install

1. The hooks come from the same `claude-code/settings.example.json`. Copy
   `claude-code/pretooluse-write-secrets.py` and the `catpilot_guard/` directory
   (the write check loads the credential patterns from its `secrets` module)
   somewhere stable, side by side, or reference the hook from a clone of this
   repository. Settings that still point at `pretooluse-write-private-key.py`
   keep working: that file runs `pretooluse-write-secrets.py`, so keep both
   files together. Python 3.8 or later is required; the code uses only the
   standard library.
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
  `new_string`, and `new_source` fields), and the lines a Codex `apply_patch`
  patch adds (each line that starts with `+`, in a new file or a hunk;
  removed and context lines are not added text), in a session where the hook is
  configured and the host reports it loaded, when that content contains a
  PEM private-key header (RSA, EC, DSA, OPENSSH, ENCRYPTED, and PGP PRIVATE
  KEY BLOCK variants) or a literal credential matching the 27 patterns in
  `catpilot_guard/secrets.py`.
- Not covered: a credential the edit completes from text already in the
  file (only added text is checked, for `Edit` and `apply_patch` alike: a
  value added under an existing `password =` line, or a key body added
  under an existing PEM header), file reads, prompts, other tools, other
  hosts, and files a
  person edits themselves.
- Failure behavior: if the hook cannot parse its input, the input is over
  1 MiB, the `catpilot_guard` package or its `secrets` module is missing, or
  anything else goes wrong, it exits 2 and the host blocks the write. If the
  hook is not configured, disabled, or times out, the host's own rules apply
  and nothing here protects the path. A hook that is not running is not a
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
the way a shell would (pipes, `;`, `&&`, `||`, subshells, and each line of a
multi-line command, with a backslash at the end of a line joining it to the
next), looks through
`sudo`, `env`, `time`, `timeout`, `stdbuf`, `ionice`, `setsid`, `unbuffer`, and
similar wrappers and through a shell's command string, however its options
are written (`bash -c "..."`, `bash -lc`, `sh -ec`, `bash -o pipefail -c`,
`bash --login -c`), and then checks:

- Cloud and infrastructure CLIs: partial-resource updates that reset
  unspecified fields (`az containerapp update --yaml` / `--replace-env-vars`,
  `aws lambda update-function-configuration --environment Variables={...}`,
  `gcloud run services update --set-env-vars`, `gcloud projects set-iam-policy`),
  auto-approved Terraform or OpenTofu (`-auto-approve` or `--auto-approve`,
  also after global options such as `-chdir=infra`), `aws s3 rb
  --force`, `aws s3 rm --recursive` without `--dryrun`, `gsutil rm -r`, and
  quiet `gcloud` deletions.
- `kubectl delete` of a namespace, or with `--all`, `--all-namespaces`, or
  `-A`, unless `--dry-run=client` or `--dry-run=server` (`--dry-run=none`
  really deletes, and is blocked).
- Recursive `rm` (any spelling: `-rf`, `-Rf`, `-r -f`, `--recursive`) of `/`,
  a top-level system directory, the home directory (`~`, `$HOME`,
  `/Users/<name>`, `/home/<name>`, or the running user's home by its absolute
  path), a credential directory (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`,
  `~/.docker`, `~/.config`, also under those absolute home paths), or a
  bare variable, quoted or not (`"$TARGET"`, `${TARGET}/*`), which removes
  `/` or the current tree when the variable is unset. A named subdirectory
  (`~/Library/Caches/pip`, `/Users/<name>/project/build`, `"$BUILD_DIR/dist"`)
  is allowed.
- `git push` with `--force`, `-f`, `--force-with-lease`, or a `+refspec` to
  `main`, `master`, `trunk`, `production`, `prod`, `staging`, `develop`, or
  `release/*` (exact branch names, so `feature/main-fix` is fine), a bare
  `git push --force` while one of those is checked out (read from
  `.git/HEAD`, and blocked when the branch cannot be read), a deletion of one
  of those branches, and `git push --mirror`, `--all` or `--branches` with a
  force or `--prune`, and a forced or pruned refspec pattern
  (`refs/heads/*:refs/heads/*`). A force push or deletion whose destination
  holds a shell variable or a substitution is read as its literal text up to
  the first expansion followed by anything, and blocked when that could name a
  protected branch (also spelled `heads/X` or `refs/heads/X`, or as `@` or
  `HEAD`): `git push --force origin $BRANCH`, `"${TARGET}"`, `${B:-main}`,
  `release/$V`, `"ma$X"` and `"$P/main"` are blocked, while `feature/$TICKET`,
  `"v$VERSION"` and a tag (`:refs/tags/$TAG`) are not. A variable whose value
  holds a space or a colon, which splits the word or the refspec, is not seen;
  in the pull-request check a `${{ ... }}` in a destination is unknown, since
  GitHub puts its text in before the shell runs. Brace expansion
  (`{main,feature}`) is unknown, and a refspec splits at its last colon, as git
  splits it. An ordinary push to a variable is not read at all. Three
  exceptions:
  - A substitution that asks git for the checked-out branch, as one quoted
    word (`"$(git branch --show-current)"`, `"$(git rev-parse --abbrev-ref
    HEAD)"`, `"$(git symbolic-ref --short HEAD)"`, or the same in backticks),
    is read as that branch. Unquoted, the shell-word reader splits it, so it
    is unknown and blocked.
  - So are `HEAD` and `@`, and `heads/main` as `main`.
  - After a command earlier in the same line that may change the branch or
    the directory, the branch is unknown, and so blocked: `cd`, `chdir`,
    `pushd`, `popd`, `git checkout` (but not `git checkout [x] -- <paths>`,
    which restores files), `git switch`, `git init`, `git rebase
    <upstream> <branch>` or `--root <branch>`, `git stash branch`, `git
    symbolic-ref`, `git branch -m`, `gh pr checkout`, `gh co`, `source`,
    `eval`, `exec` or `alias`. A switch never names the branch, since it may
    fail, run in another repository, or take its name from a variable, so
    `git switch feature-y && git push --force-with-lease` is blocked too.
  - It is unknown for the whole line when the line, or a `bash -c` body in
    it, defines a function (`name()`, `function name`), assigns `GIT_DIR`,
    `GIT_WORK_TREE` or `GIT_COMMON_DIR` (also `export GIT_DIR` and `read
    GIT_DIR`), or gives env or sudo a directory (`env -C`, `--chdir`), at a
    command's start, among a declaration's names (`export FOO GIT_DIR=...`),
    or behind a wrapper and its option values (`sudo -u bob`, `nice -n 5`,
    `timeout 60`); and when a variable comes before a git command's
    subcommand, other than as the value of `-C`, `-c` or `--git-dir`. A line that assigns a `GIT_CONFIG_*` variable, which can set
    `remote.<name>.mirror`, makes any push in it count as a mirror. These are
    read as shell words, with assignments only where they are assignments, so
    a mention inside a quoted message does not count. A script run earlier in
    the line that switches branches is not seen, nor a git alias (`git co`).

  A word that starts with a variable may hold an option. When it is followed
  by a literal word, with two literal words besides (`git push $F origin
  main`, `git push origin $F main`), the push counts as a force push. A
  trailing one (`git push origin main "$TAG"`) does not, so `git push $F
  origin` with `F=--force` is not caught.

  Also blocked:
  - the matching refspec (`:`) with a force or a `+`;
  - a push given `-c remote.<name>.mirror` (it acts as `--mirror`);
  - a bare push given `-c remote.<name>.push=...` or `--config-env` for it;
  - a bare push given `-c push.default=matching` with a force;
  - a bare force push given `-c push.default=upstream` or a `branch.*`
    setting, whose destination is then unknown;
  - a bare push after a command earlier in the line sets
    `remote.<name>.mirror`, `remote.<name>.push`, an include, or
    `push.default` to `matching`, `upstream` or `tracking` (`git config KEY
    VALUE`, `git config set`, `git remote add --mirror`); a read (`git config
    --get`) does not, and a push that names a refspec is never a mirror (git
    refuses a refspec with `remote.<name>.mirror`, and a refspec overrides
    `remote.<name>.push`). The same holds for a `GIT_CONFIG_*` assignment.

  These settings in git's config files are not read. An
  option's value (`-o ci.skip`, `--push-option`, `--repo`) is not read as the
  remote.
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
  holding the verb, ANSI-C quoting such as `bash -c $'ls\nrm -rf ~'`), commands a script runs internally, prompts, other tools,
  and any host other than Claude Code. It stops accidents, not an adversary.
- Failure behavior: malformed input, a missing `catpilot_guard` package, or any
  internal error exits 2 and the host blocks the command. It needs the package
  beside it, but not the other hook files or the package's `secrets` module.
  It imports the package's `evidence` module only to write an evidence line,
  and decides the same way without it.
- The way past a false positive is a person running the command in their own
  terminal; there is no flag the agent can add.

## Company rules: your own enforcement rules (monitor, ask, block)

`claude-code/pretooluse-company-rules.py` enforces the rules in the
`enforcement` section of a version 2 company rules file
([`docs/spec/OVERLAY_V2.md`](../docs/spec/OVERLAY_V2.md) §2.2). The built-in
hooks above stay as they are: a company rule adds to them and never softens
one.

It does not read the YAML file. `python tools/validate_overlay.py compile
rules.yaml --out company-policy.json` validates the file and writes a JSON
policy: each rule's id, kind, mode (its own, or `default_mode`) and values,
the approved alternative's text when the rule names one, the file's
`expires_on`, and the SHA-256 of its bytes. Nothing else from the file is
copied. It also prints what each rule does on each tool, without the values.
`deploy/org/install.sh --overlay` compiles and places the policy and
registers the hook on both tools
([`docs/DEPLOY_ORG.md`](../docs/DEPLOY_ORG.md#company-enforcement-rules)).

The hook takes the policy only from an absolute path on its own command line:

```bash
python3 "/path/to/hooks/pretooluse-company-rules.py" --host claude-code --policy "/path/to/company-policy.json"
```

| Mode | Claude Code | Codex | Evidence |
| --- | --- | --- | --- |
| `block` | Deny | Deny | `deny` |
| `ask` | Deny, unless the hook's command line has `--ask`. With it, ask the person in the `default`, `acceptEdits` and `plan` permission modes, and deny in any other mode, since those approve without a person or have nobody to answer | Deny: Codex does not support `ask` | `ask`, or `deny` where it acted as `block` |
| `monitor` | No decision | No decision | `would_deny` |

`ask` is opt-in because the hook cannot tell a person from a program: a
`claude -p` run with a permission-prompt tool, or an Agent SDK callback that
approves, sends the same event as an interactive session, and `ask` means a
person decides first (decision 2). Add `--ask` to the root-owned command only
after a host check shows a person answers on your machines.

When several rules match one command, the strictest effect wins and each rule
writes its own evidence line. After the file's `expires_on`, every company
rule acts in `monitor` until the file is renewed and recompiled: nothing is
blocked on stale values, and each match still writes `would_deny`.

The same compiled policy drives the pull-request check, `tools/pr_check.py`,
which a company runs in its own CI
([`docs/DEPLOY_ORG.md`](../docs/DEPLOY_ORG.md#pull-request-check)). It applies
these rules, with this hook's matching, to the workflows, composite actions,
`package.json` scripts and deploy configuration files a pull request adds or
changes, so a deploy a CI job would run, which this hook never sees, is
checked before merge. There `monitor` annotates and passes, and `ask` fails the
check as `block` does. Not yet run in a real repository's CI.

### Exact coverage

- Kind `protected_branch`: a `git push` that force-pushes to (`--force`,
  `-f`, `--force-with-lease`, `--force-if-includes`, or a `+refspec`) or
  deletes (`--delete`, `-d`, or `:branch`) a branch a value covers, a bare
  force push while such a branch is checked out, and `git push --mirror`.
  Pushes are read exactly as the destructive-operation check reads them,
  through the same wrappers and `bash -c` bodies, so `--all` or `--branches`
  with a force or `--prune`, and a forced refspec pattern
  (`refs/heads/*:refs/heads/*`), match every rule. A force push or deletion
  whose branch the hook cannot read also matches every rule: a destination in
  a variable or a substitution (`git push --force origin $BRANCH`), a bare
  force push or a push to `HEAD` with no branch checked out (a detached
  `HEAD`, or no repository; the built-in check blocks the bare force push
  there, not the push to `HEAD`), and the checked-out branch after a command
  that may change it, as the destructive-operation check reads it (above). A value
  ending in `/*` covers every branch under the prefix; case is ignored. A
  value is a branch name: the validator refuses a `refs/` prefix and names
  longer than 255 characters. An ordinary push is not a match.
- Kind `deploy_host`, an allow-list: a deploy or publish whose target no value
  of the rule covers fires the rule. `catpilot_guard/deploy_targets.py` reads
  the target, through the same splitting and wrappers, and through package
  runners (`npx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `bunx`):
  - a hosting service's own domain, for `vercel`/`vc` (every run except help,
    version and its non-deploy subcommands, such as `env`, `link`, `pull`,
    `whoami`, `dev`, `build`, `curl`; any other first word is the directory it
    deploys, which may not exist until a build before it runs), `netlify deploy`, `fly`/`flyctl` `deploy`,
    `launch` (unless `--no-deploy`) or `machine run`, `firebase deploy` and
    `hosting:channel:deploy`, `wrangler deploy`/`publish`/`versions deploy`/
    `versions upload` and `wrangler pages deploy`, `surge` (except its account
    commands), `gh-pages`, `railway up`/`redeploy`, `amplify publish`, and
    `git push` to a remote named `heroku` or a `git.heroku.com` URL: the
    service's names end in `vercel.app`, `netlify.app`, `fly.dev`, `web.app`,
    `workers.dev`, `pages.dev`, `surge.sh`, `github.io`, `up.railway.app`,
    `amplifyapp.com` and `herokuapp.com`, so only a value `*.vercel.app` (and so
    on) covers one. A runner's package spec is read with its version and by its
    package name (`npx vercel@latest`, `npx netlify-cli`, `npx firebase-tools`,
    `npx @railway/cli`), as are `yarn`/`pnpm` scripts and tools (`yarn vercel`,
    `pnpm dlx`, `yarn workspace web vercel`) and `npx -c '...'` strings;
  - a named host: the remote destination of an `scp` or `rsync` upload
    (`[user@]host:path`, `scp://`, `sftp://`, `rsync://`): the last path, when
    it is remote, whatever the sources; a copy to a local path is a download.
    Also the domain given to `surge`;
  - a destination it cannot read, which no value covers: a variable (`rsync
    dist/ $HOST:/srv`), an address in brackets (IPv6), or an SSH alias without
    a dot (`scp f prod:/srv`, from `~/.ssh/config`), since every value needs a
    dot.

  Every `scp` or `rsync` upload to another machine counts, a backup to a dev
  box included, so start a `deploy_host` rule in `monitor` and read the
  `would_deny` counts before you block.

  A value `*.D` covers every name under `D`; any other value covers that host
  only. Each `deploy_host` rule is its own allow-list, so list every approved
  host in one rule. Not covered: a deploy a script or CI job runs (the
  pull-request check reads the workflows and scripts a pull request changes), a
  vendor not listed here, a custom domain set in a project file (the service's
  own domain is the target then), `ssh` sessions, `curl` uploads, container
  pushes and cloud object copies.
- The reason names the rule ids and the approved alternative, never a listed
  value, and never repeats the command. Evidence lines carry the rule id, the
  mode that applied and the policy's hash, never a command or a value.
- The policy must be a regular file, not a symlink, owned by the same user as
  the `catpilot_guard` package the hook runs from, and neither the file nor its
  directory may be writable by group or others. `install.sh` places both as
  root. A policy that is missing, unreadable, malformed or placed any other
  way, or a command line the hook cannot read, applies no company rule: the
  hook returns no decision and writes a `policy_error` line with a fixed
  label. A rules file is never less careful than none (§6.1).
- The policy is readable by each person's account, because the hook runs as
  them. The values stay out of every prompt, bundle and server answer, but an
  agent that reads files on the machine can read them.
- Failure behavior: malformed hook input or a missing `catpilot_guard`
  package exits 2, and the host blocks the command.
- Not covered: everything the destructive-operation check does not cover, and
  any host other than Claude Code and Codex.

## When a hook cannot start

Each hook fails closed once Python is running: malformed input, a missing
`catpilot_guard` package, an internal error, or a decision it cannot write
(for example, the host closed the pipe) exits 2, which blocks. Before
that point it cannot. If the `python3` in the hook command is missing, is the
macOS Command Line Tools stub on a machine without the tools, or is older than
3.8, the command exits with another code, which Claude Code treats as a
non-blocking error: the command or write goes ahead unchecked. `deploy/org/verify.sh` checks the interpreter, runs each
installed hook on harmless probes, and runs each hook command in
`managed-settings.json` the same way. Run it as a normal user on each machine
after install and after an OS or Python upgrade. It cannot see Claude Code's
own `PATH`, so the session check in [`docs/DEPLOY_ORG.md`](../docs/DEPLOY_ORG.md)
stays the proof.

## Evidence log and syslog

Set `CATPILOT_EVIDENCE_LOG` to a file path in the hook's environment (the
managed-settings example in `deploy/org/` does it on the command line) and each
deny appends one JSON line: the schema version, a random event id, the time,
the hook, the event (`deny`), the host (`claude-code`, or `codex` with
`--host codex`), the credential type,
`private-key-block`, or destructive operation label, the tool, and the session
id when it is an opaque id. Set `CATPILOT_EVIDENCE_SYSLOG=1` (or a `host:port`
/ socket path) to emit the same content-free JSON line to syslog. Never the
command, the file path, or the content. Malformed input is recorded as
`input_error` beside the fail-closed exit. Off unless set.

All three hooks write through one writer, `catpilot_guard/evidence.py`, which
the reference server uses too. The line format is versioned:
[`docs/spec/EVIDENCE.md`](../docs/spec/EVIDENCE.md), with a JSON Schema beside
it. Each line is one write to the file, under an `fcntl` lock where the
platform has one, so hooks in several sessions can share a file. The writer
waits at most half a second for the lock, never raises, and a logging failure,
or a missing `evidence` module, never changes the decision. A check called
from a harness writes the same line without `host`. Summarize collected logs
with `python3 tools/evidence_summary.py`.

## Inside your own harness

The same checks are available as functions for any Python loop you control:
`hooks/harness/secret_gate.py` (`gate_shell_command`, `gate_tool_call`,
`gate_file_write`, `gate_write_tool_call`) and
`hooks/harness/destructive_gate.py` (`gate_destructive_command`,
`gate_destructive_tool_call`), documented in [`harness/README.md`](harness/README.md).
Both import the checks from `catpilot_guard`, the same code the hooks run.
The harness owns its tool boundary, so a gate it enforces is enforcement on
that path; a skill it loads is still advice.

## Session start: company rules (advice, not enforcement)

`session-start/catpilot-company-rules.py` is a `SessionStart` hook for Claude
Code and Codex. It is not in the table above because it stops nothing:
`SessionStart` cannot block on either host, so what it prints is a notice,
not a control. It reads the company rules block and its sidecar from a
private build. When the rules are current, it gives Codex the whole block as
developer context and gives Claude Code a one-line status (a managed
`CLAUDE.md` carries the block there). When they expired, or cannot be loaded
or checked, it says so and names who to ask, and prints no rules. It always
exits 0 and writes one evidence line. Details, dates and size budgets:
[`session-start/README.md`](session-start/README.md). `deploy/org/install.sh
--overlay` places it on both tools ([`docs/DEPLOY_ORG.md`](../docs/DEPLOY_ORG.md#company-rules-at-session-start-on-claude-code)).
Not run on a host.

## Codex CLI

Codex sends the same `PreToolUse` event for `Bash` (`tool_input.command`) and
reads the same deny decision, so `pretooluse-secrets.py` and
`pretooluse-destructive-ops.py` run there unchanged. Add `--host codex` to
each command so their evidence lines say `codex`; without it they say
`claude-code`. The argument changes the evidence label only, never the
decision. A project-level example for `.codex/config.toml`, which Codex runs
only after the folder and each hook are trusted in `/hooks`:

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'python3 "/path/to/catpilot-ai-guardrails/hooks/claude-code/pretooluse-destructive-ops.py" --host codex'
timeout = 30
```

Add the secret check the same way. Verified on Codex CLI 0.169.0 as
project-level hooks on 2026-11-17, before `--host` existed
([note](../evals/reports/2026.11.17-session-start-rules-verification.md)).

Codex sends file edits as `apply_patch`, with the patch in
`tool_input.command`, whichever of `apply_patch`, `Edit` or `Write` the
matcher names. `pretooluse-write-secrets.py` reads the lines the patch adds,
split on newlines the way Codex's own patch parser splits them. Verified on
Codex CLI 0.169.0 on 2026-11-17 as a managed hook: a synthetic key block
written through Codex's file-edit tool was blocked
([note](../evals/reports/2026.11.17-host-check-codex-managed-hooks.md)):

```toml
[[hooks.PreToolUse]]
matcher = "^apply_patch$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'python3 "/path/to/catpilot-ai-guardrails/hooks/claude-code/pretooluse-write-secrets.py" --host codex'
timeout = 30
```

`deploy/org/install.sh` sets the three up as managed Codex hooks in
`/etc/codex/requirements.toml`, with `--host codex`
([`docs/DEPLOY_ORG.md`](../docs/DEPLOY_ORG.md#blocking-hooks-on-codex)).

## GitHub Copilot CLI

Copilot CLI runs the same checks as policy hooks: JSON files in
`/etc/github-copilot/policy.d/` that root owns and no one else can write.
Copilot loads them before user and project hooks, whatever the folder's trust
state, and people cannot turn them off with `disableAllHooks`
([hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference),
read on 2026-11-17). `deploy/org/install.sh` writes
`policy.d/catpilot-guardrails.json` and copies the hooks to
`/etc/github-copilot/catpilot-guardrails/hooks/`
([`docs/DEPLOY_ORG.md`](../docs/DEPLOY_ORG.md#github-copilot-cli)).

The hooks are registered under the Claude-style event name `PreToolUse`, so
Copilot sends Claude Code's event shape and Claude tool names: `Bash` for its
`bash` and `powershell` tools, `Write` for `create`, and `Edit` for `edit`,
`str_replace_editor` and `apply_patch`. `tool_input` keeps the runtime tool's
own arguments (`file_text`, `new_str`, or a patch). With `--host copilot-cli`,
[`catpilot_guard/copilot.py`](../catpilot_guard/copilot.py) reads them in the
shape every check takes: `write_bash` and `write_powershell` (input sent to a
running shell) as commands, file text and new text as content, and a patch as
`apply_patch`. A file write of any other shape exits 2, which Copilot treats
as a deny. Each decision also carries the top-level `permissionDecision` and
`permissionDecisionReason` that Copilot documents. What a check decides does
not change.

```json
{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "matcher": "Bash|write_bash|write_powershell",
        "bash": "python3 \"/path/to/hooks/pretooluse-destructive-ops.py\" --host copilot-cli",
        "timeoutSec": 30
      }
    ]
  }
}
```

Two differences from the other tools:

- **A timeout lets the call run.** Copilot's documentation says a timed-out
  hook, policy hooks included, fails open. The timeout is Copilot's default of
  30 seconds; a check takes well under one.
- **`ask` is opt-in, and Copilot settles it.** With `--ask` on its command,
  the company-rules hook returns `ask`; Copilot denies an ask in autopilot
  mode and the cloud agent. How it treats one under `copilot -p` or an
  allow-all mode is not verified. Without `--ask`, `ask` acts as `block`.
- **Shell input is read line by line.** `write_bash` sends keystrokes to a
  running shell. `{enter}` is read as a line break. Any other key token
  (`{up}`, `{backspace}`, `{tab}`, ...) can change which command runs, so the
  checks cannot read it and the hook exits 2, which Copilot treats as a deny.
  The same goes for raw control characters, tab included, since tab
  completes (a carriage return is read as a line break). Tokens match in any case and after `$`, so text such as
  `${HOME}` or `{{end}}` sent with `write_bash` is refused too; `$HOME` and the
  `bash` tool are not affected. A command split across several `write_bash`
  calls is not covered.

Not covered: Copilot in the cloud (policy hooks do not run there),
PowerShell-specific forms of the destructive checks, and the session-start
rules. Not run on a host.

## Other hosts

Cursor has a hooks facility. The same check will be ported only after it is
tested there, and the tested-runtimes table in `docs/REFERENCE.md` will say so. ChatGPT and
Claude.ai have no hook surface; the honest story on those hosts is coaching
plus the platform's own admin controls.
