# Rolling out to an organization

How an administrator puts the guardrails on every machine, for Claude Code, Claude.ai, Codex CLI, and ChatGPT, and how to confirm on one machine that it landed before pushing it to the fleet. It assumes you have read [what this does and does not do](../README.md#what-this-does-and-does-not-do): a deployed skill is advice, the three Claude Code hooks are the only enforcement, and the evidence log described at the end is a record, not a control.

Verification status is in the [table at the end](#verification-status). A channel marked "not verified" has its steps written from the vendor's documentation and has not been exercised by Catpilot; treat it as a plan until someone runs it and records the date. Catpilot has no Team, Business, or Enterprise workspace of its own, so the organization-level rows for Claude.ai and ChatGPT can only be closed by an organization that runs them: a pilot's administrator, or anyone who sends the record ([`CONTRIBUTING.md`](../CONTRIBUTING.md)). What an individual account can verify instead is noted in each section and has its own rows.

## What central deployment changes, and what it does not

Central deployment puts the same files on every machine from a source the user cannot override: an admin-managed settings file, an MDM profile, a workspace setting. That answers "how do I roll this out to forty people" and "how do I know it is still there next month." It does not change what the files are:

- A skill is still guidance the model reads. Centrally deployed, it is guidance the model reads on every machine.
- The three `PreToolUse` hooks are still the only enforcement, on Claude Code only, on the `Bash` and file-write paths only. Centrally deployed, they are enforcement the user cannot switch off, which is the difference that matters for a control.
- The server still answers lookups the model chooses to make. Centrally deployed, it is reachable from every session, and with your overlay loaded it answers with your company's approved options instead of generic defaults.
- The company rules at session start (`install.sh --overlay`) are advice too: the model has your rules in front of it from the first prompt, without a lookup, and nothing blocks on them.
- ChatGPT and Claude.ai have no hook surface. On those hosts the honest story is coaching plus the vendor's own admin controls.

The overlay is the piece that carries your company's facts, and it is the piece to author first: approved hosting, approved services, data classes, the identity rule, review triggers, and who to ask, with a reviewer date and an expiry date ([`docs/spec/OVERLAY.md`](spec/OVERLAY.md)). Run the reference server yourself with `CATPILOT_OVERLAY_FILE` pointing at it, behind your own gateway ([`mcp-server/README.md`](../mcp-server/README.md), [`deploy/README.md`](../deploy/README.md)). The public endpoint at `mcp.catpilot.ai` serves generic defaults only and never a company overlay, so every example below uses `https://mcp.example.com/mcp` as a placeholder for your server.

## The files

Everything an administrator places is under [`deploy/org/`](../deploy/org/):

| File | What it is |
| --- | --- |
| `claude-code/managed-settings.json` | All three hooks, with the evidence log turned on per user, and the server provided through `managedMcpServers` alongside whatever servers users already have |
| `claude-code/managed-mcp.json` | The stricter alternative for the server: a fixed set, and users cannot add others |
| `codex/managed_config.toml` | The server as a managed default for Codex CLI |
| `/etc/codex/requirements.toml` (generated) | The three hooks as managed Codex `PreToolUse` hooks, with `--host codex`, and `[features].hooks = true`; with `--overlay`, also the session-start hook. Written by `install.sh` from `session_start_files.py`, only when there is none |
| `install.sh` | Places all of it on one macOS or Linux machine as root, with your server URL substituted: the hooks and the `catpilot_guard` package they run go to `<managed dir>/catpilot-guardrails/hooks/` (the package as `hooks/catpilot_guard/`, its `.py` files only, never `__pycache__` or `.pyc`); refuses to overwrite a managed file that already exists and prints what to merge instead; `--managed-mcp-json` also writes the fixed-set `managed-mcp.json`; `--overlay` also places the company rules at session start on both tools (below) |
| `verify.sh` | Checks as a normal user: the files are present, including each module of the `catpilot_guard` package beside the hooks; the `python3` the hook commands use starts and is 3.8 or later; each installed hook, run directly, denies a harmless probe and lets `ls` through; `managed-settings.json` runs each hook on the tools it covers; after `--overlay`, the company rules at session start (below); and the evidence log's last line. Writes nothing outside a temporary directory and no evidence line; exits non-zero on any failure |
| `uninstall.sh` | Removes exactly what `install.sh` placed, including the `catpilot_guard` package beside the hooks and, after `--overlay`, the session-start files and the marked section of the managed `CLAUDE.md`; leaves a managed file alone if it was edited since |
| `session_start_files.py` | The standard-library helper the three scripts share for the generated pieces: it adds the `SessionStart` hook to the parsed settings JSON, writes `requirements.toml`, places and removes the marked `CLAUDE.md` section, and runs `verify.sh`'s Codex hook and session-start checks |

The skills come from [`skills/`](../skills/) in a checkout of the release you are deploying; the install script copies them. Pin the release: the files are deterministic per release and the [`CHANGELOG.md`](../CHANGELOG.md) says what changed.

**Company rules at session start.** With `--overlay`, `install.sh` also puts your reviewed rules in front of the model when a session starts on Claude Code and Codex, with no skill, server or lookup involved: the rules block (`company-checklist.md` from the private build) and its sidecar (`company-checklist.json`: owner, dates, hashes), read by [`hooks/session-start/catpilot-company-rules.py`](../hooks/session-start/README.md). Claude Code gets the block from the managed `CLAUDE.md` and a one-line status from a `SessionStart` hook; Codex gets the block from a managed `SessionStart` hook. When the rules have expired, or cannot be loaded or checked, each tool gets a notice that says so and names who to ask, instead of the rules. It is advice, not enforcement: `SessionStart` cannot block on either host, and a `CLAUDE.md` shapes what the model does without enforcing anything. Without `--overlay`, nothing about it is placed or registered: a hook with no rules to read would print "could not be loaded" in every session. Details for [Claude Code](#company-rules-at-session-start-on-claude-code) and [Codex](#company-rules-at-session-start-on-codex). Verified on a host on 2026-11-17, on Claude Code 2.1.326 and Codex CLI 0.169.0, for current and expired rules at session startup ([note](../evals/reports/2026.11.17-session-start-rules-verification.md)).

## Claude Code

Claude Code reads an admin-managed settings file above every user, project, and command-line setting. Users cannot override it, apart from a few security-sensitive keys where a stricter user value still counts.

| OS | Managed directory |
| --- | --- |
| macOS | `/Library/Application Support/ClaudeCode/` |
| Linux and WSL | `/etc/claude-code/` |
| Windows | `C:\Program Files\ClaudeCode\` |

Delivery options, from the vendor's [managed settings](https://code.claude.com/docs/en/managed-settings) page: the `managed-settings.json` file in that directory, an MDM profile (macOS managed preferences domain `com.anthropic.claudecode`, or the `Settings` value under `HKLM\SOFTWARE\Policies\ClaudeCode` on Windows), or server-managed settings from the claude.ai admin console. The file and the MDM profile reach local sessions; cloud sessions read only server-managed settings.

**What the example file carries.** `deploy/org/claude-code/managed-settings.json` registers the three hooks from a root-owned copy under `<managed dir>/catpilot-guardrails/hooks/` (a hook the user can edit is not a control; each hook file is a shim that runs the root-owned `catpilot_guard/` package placed beside it, and exits 2, which blocks, if the package is missing), sets `CATPILOT_EVIDENCE_LOG` on each hook command so denials are recorded under the user's home, and provides the server through `managedMcpServers`, which adds it to every user's session without removing servers they configured themselves. To lock the server set instead, deploy `managed-mcp.json` in the same directory (`install.sh --managed-mcp-json`); then only the servers it lists load, and `claude mcp add` refuses others. On Claude Code 2.1.241 the `managedMcpServers` key in the managed settings file did not load the server in Catpilot's check (the hooks and skills from the same file and directory did), while `managed-mcp.json` in the same directory did: `claude mcp list` showed only that server, connected, and a session completed a lookup through it. Until a newer version is checked, provide the server through `managed-mcp.json` or through a `.mcp.json` committed to your template repositories ([`mcp-server/host-configs/`](../mcp-server/host-configs/)). `allowManagedHooksOnly: true` and `allowManagedPermissionRulesOnly: true` are available if you want the managed file to be the only source of hooks or permission rules; the example leaves them out. With `--overlay`, `install.sh` adds one more hook to the file it writes or prints, a `SessionStart` status hook for the company rules ([below](#company-rules-at-session-start-on-claude-code)).

**Skills.** Two central routes. A skill placed at `<managed dir>/.claude/skills/<name>/SKILL.md` loads for every user of the machine; the install script puts the chosen skills there (`--skills`, default `safe-building,security-core`; add `agentic-security` where people build agent loops). Alternatively, an organization owner uploads the skill once in claude.ai (below), and Claude Code v2.1.273 and later syncs the skills enabled for a signed-in claude.ai account into terminal sessions (`syncClaudeAiSkills`, on by default; not for API-key sessions). The repository route, `.claude/skills/` committed to your template repositories, still works and needs no admin rights.

**Plugin route.** The skills (all three, discovered from `skills/`) ship as a Claude Code plugin from this repository's `.claude-plugin/` manifest: for one user, `/plugin marketplace add catpilotai/catpilot-ai-guardrails` then `/plugin install catpilot-guardrails@catpilot`; for everyone, `extraKnownMarketplaces` and `enabledPlugins` in the managed settings file, with `strictKnownMarketplaces` if it should be the only marketplace users can add. The plugin carries no hooks and no server, so those still come from the managed settings file and directory above. Verified on 2.1.241 from a local checkout (2026-09-20): `claude plugin validate --strict` passes, a session started with `--plugin-dir` listed `catpilot-guardrails:catpilot-safe-building` and `catpilot-guardrails:catpilot-security-core` beside the managed copies, and `marketplace add` plus `install` succeeded in a throwaway config directory. The GitHub form, `claude plugin marketplace add catpilotai/catpilot-ai-guardrails` followed by `claude plugin install catpilot-guardrails@catpilot`, was verified the same day in a throwaway config directory once the manifest was on `main`.

**Place it.** From a checkout of the release, as an administrator:

```bash
sudo deploy/org/install.sh --server-url https://mcp.example.com/mcp
```

**Confirm it on one machine before the fleet.** As a normal user on that machine:

1. `deploy/org/verify.sh` prints what is present, checks that `python3` starts (a hook that cannot start is a non-blocking error to Claude Code, so commands would run unchecked; it names the macOS Command Line Tools stub when that is what `python3` resolves to), runs each installed hook on harmless probes (AWS's documentation example key, `git push --force origin main`, `ls`), and runs each hook command in `managed-settings.json` the same way, so a hooks block that was never merged shows up as a failure. It exits non-zero on any failure. It runs the hooks directly, not through Claude Code, whose own `PATH` can differ from your shell's, so the session steps below are still the proof.
2. Start Claude Code and run `/status`. The `Setting sources` line must list `Enterprise managed settings (file)`; with an MDM profile it says `(plist)` or `(HKLM)`. If the line is missing, the file is not where Claude Code looks, or it failed to parse; `claude doctor` lists dropped entries. If it says `(remote)` and a `Skipped sources` line lists `Enterprise managed settings (file)`, the hooks are not running: see [below](#when-your-organization-also-uses-claudeai-managed-settings).
3. `claude mcp list` shows `catpilot-guardrails`.
4. Ask for a command that contains AWS's documentation-only example key: `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && echo ok`. It is denied with a reason that names the credential type and does not echo the value. Ask for the same command with `$AWS_ACCESS_KEY_ID`; it runs.
5. Ask it to write a file whose content starts with `-----BEGIN RSA PRIVATE KEY-----` and a synthetic body. The write is denied.
6. Ask it to call `list_approved` with category `hosting`. With your overlay loaded, the answer names your approved hosting and `unknown_policy` is false.
7. `tail ~/.catpilot-guardrails/evidence.jsonl` shows one line per denial from steps 4 and 5, with no command text in it.

The vendor documents a testing variable, `CLAUDE_CODE_MANAGED_SETTINGS_PATH`, that points Claude Code at a managed file outside the system path. In Catpilot's check on 2.1.241 (2026-09-20) it did not take effect; through the system path, the same file's hooks ran and the same directory's skills loaded. The system path is the only route this page relies on. Note that the managed file applies to every Claude Code session on the machine, the desktop app included, until `uninstall.sh` removes it.

**What this does not reach.** Cloud sessions (server-managed settings only), the desktop app's own connectors (governed from claude.ai organization settings), and any tool other than Claude Code.

### When your organization also uses claude.ai managed settings

People may sign in to Claude Code with your claude.ai Team or Enterprise organization, and that organization may set anything under **Organization settings > Claude Code > Managed settings**. If so, Claude Code receives those settings from claude.ai as well as reading the file. By default it applies only the highest-ranked managed source and skips the rest without a warning. The claude.ai settings rank above the file ([vendor's precedence rules](https://code.claude.com/docs/en/managed-settings#how-claude-code-combines-managed-sources)). The hooks in the file then never run, while `verify.sh` still passes, because it runs the hooks directly. Only `/status` shows it: `Setting sources` says `Enterprise managed settings (remote)`, and `Skipped sources` lists `Enterprise managed settings (file)`.

To apply both, an organization owner adds one key to the claude.ai managed settings:

```json
"managedSourcesBehavior": "merge"
```

Claude Code reads this key only from the highest-ranked source, so it has no effect in the file, and it needs Claude Code 2.1.242 or later. With it, the hooks from the file are added to any hooks set in claude.ai, and `/status` shows `Enterprise managed settings (remote + file, merged)`. On a machine with no managed settings file or MDM profile, it changes nothing. The vendor advises merging only when every lower source is under an administrator's control; the file `install.sh` writes is root-owned. Verified on Claude Code 2.1.326 on 2026-11-16 ([note](../evals/reports/2026.11.16-managed-hooks-verification.md)).

Do not move the hooks into the claude.ai managed settings instead. They would then apply on every machine in the organization, and on a machine without the hook files, `python3` cannot open the script and exits 2, which blocks every command and file write.

### Company rules at session start on Claude Code

With `--overlay`, `install.sh` puts your reviewed rules in front of the model in every Claude Code session on the machine. Advice, not enforcement: the vendor's own documentation calls a `CLAUDE.md` guidance that shapes Claude's behavior, not a hard enforcement layer, and a `SessionStart` hook cannot block. Verified on Claude Code 2.1.326 on 2026-11-17 for current and expired rules ([note](../evals/reports/2026.11.17-session-start-rules-verification.md), [status](#verification-status)).

```bash
sudo deploy/org/install.sh --server-url https://mcp.example.com/mcp --overlay /private/path/rules.yaml
```

**How the rules arrive.** Two pieces, from the same private build:

- **The block, in the managed `CLAUDE.md`.** `company-checklist.md` goes into `/Library/Application Support/ClaudeCode/CLAUDE.md` on macOS and `/etc/claude-code/CLAUDE.md` on Linux and WSL, the managed policy location in the vendor's [memory documentation](https://code.claude.com/docs/en/memory#deploy-organization-wide-claude-md). Claude Code loads that file in every session on the machine, in any directory, ahead of user and project `CLAUDE.md` files, and `claudeMdExcludes` cannot exclude it. The block sits between two lines, `<!-- catpilot-company-rules:begin -->` and `<!-- catpilot-company-rules:end -->`. Claude Code strips block-level HTML comments before a `CLAUDE.md` reaches the model, so the markers cost no context.
  - No managed `CLAUDE.md` yet: `install.sh` creates one holding only the marked section.
  - One with the markers: only the text between them is replaced. The rest of the file, its mode and its owner stay as they were. This is the one change `install.sh` makes to a managed file that already exists. The marked text is ours, and replacing it is what keeps a renewed rules file from leaving last quarter's rules in front of the model while the status hook reports the new ones.
  - One without the markers, with markers that are not one begin line followed by one end line, or a symbolic link: left alone. `install.sh` prints the section, markers included, for you to add.
- **A status at each session start.** `managed-settings.json` gets a `SessionStart` hook that runs `catpilot-company-rules.py --host claude-code` after a session starts, resumes, is cleared, compacted or forked, with the same `CATPILOT_EVIDENCE_LOG` prefix as the other hooks. The script checks the block against its sidecar and the expiry date, and gives the model one line, "Company rules from `<owner>`, reviewed `<date>`, valid until `<date>`, are current.", not the block a second time. It is part of the JSON `install.sh` writes, or prints for you to merge when the file exists:

```json
{
  "matcher": "startup|resume|clear|compact|fork",
  "hooks": [
    {
      "type": "command",
      "command": "CATPILOT_EVIDENCE_LOG=\"$HOME/.catpilot-guardrails/evidence.jsonl\" python3 \"/Library/Application Support/ClaudeCode/catpilot-guardrails/hooks/catpilot-company-rules.py\" --host claude-code",
      "timeout": 10
    }
  ]
}
```

The script, the `catpilot_guard` package and the two rules files live under `<managed dir>/catpilot-guardrails/` (`hooks/catpilot-company-rules.py`, `instructions/company-checklist.md` and `.json`), root-owned like the other hooks.

**Why the file, not the `claudeMd` key.** Claude Code also accepts the text of a managed `CLAUDE.md` as a `claudeMd` string in managed settings ([settings reference](https://code.claude.com/docs/en/settings-reference#claudemd)). This package uses the file, for three reasons from the vendor's documentation (read 2026-11-16):

1. `claudeMd` is a key in the managed settings file, so it goes wherever the file goes. When claude.ai managed settings also apply, the file is skipped by default ([above](#when-your-organization-also-uses-claudeai-managed-settings)), and even under `"merge"`, a `claudeMd` that claude.ai sets replaces the file's, because Claude Code takes such a key from the highest-ranked source that sets it. The managed `CLAUDE.md` is not a settings source: the managed-source precedence rules do not mention it, and the memory documentation describes it as applying to every user on the machine, with no condition on managed settings. By the documentation, the rules then still reach the model where the file's hooks are skipped. Not verified.
2. The block is Markdown with a fenced YAML list. As a file it stays readable and diffable; as `claudeMd` it is one escaped JSON string.
3. `install.sh` never overwrites a `managed-settings.json` that exists. With `claudeMd`, each renewal of the rules would mean merging a new escaped string by hand, and `uninstall.sh` could no longer recognize the file as its own. With the marked section, a renewal replaces that section only, and the settings file does not change when the rules do.

An MDM-only fleet could deliver `claudeMd` in the configuration profile instead. That route is not built or verified here.

**What a session should show.** Not verified; from the vendor's documentation. `/context all` lists the managed `CLAUDE.md` under **Memory files**. `/hooks` lists the `SessionStart` hook and its command, from the managed settings. `/status` must show the file under `Setting sources`, as for the other hooks. The check that matters is a question in a session: [Check the rules in a session](#check-the-company-rules-in-a-session).

**On expiry.** The block stays in `CLAUDE.md` until you install a renewed rules file; the hook does the date check. From the day after `expires_on`, by the machine's local date, the hook prints, to the model and as a warning the person sees: "The company rules expired on `<date>` and are not in force. The company rules in the instruction file are out of date and must not be relied on. Ask `<owner>` for current rules." Because the block stays in the file, the model can still see the expired rules. In the 2026-11-17 check, it said they were out of date, gave no current approval and named the owner, but it repeated the expired rules, labeled as expired. Codex, which never receives expired rules, did not repeat them. If the block or its sidecar is missing, unreadable or from different builds, it prints that the company rules could not be loaded and are unknown. To renew, have the updated rules file reviewed and run `install.sh --overlay` again: it replaces the marked section and both copies of the rules.

**With claude.ai managed settings.** The same precedence applies to the status hook as to the others: without `"managedSourcesBehavior": "merge"`, Claude Code skips the file and nothing checks the expiry date, while the managed `CLAUDE.md` still delivers the block, expired or not. Set the key as [above](#when-your-organization-also-uses-claudeai-managed-settings).

**What this does not reach.**

- Cloud sessions, which read server-managed settings only, and Claude.ai, which has no hooks and no managed `CLAUDE.md`: use the uploaded skill, the paste block or the connector there.
- A session started with `--bare` (`CLAUDE_CODE_SIMPLE=1`) or with `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1`: neither loads the managed `CLAUDE.md`.
- A session in `--safe-mode`: it does not load the managed `CLAUDE.md` but still runs managed hooks, so the status line can say the rules are current while the block is not in context.

## Claude.ai

For people who never open a terminal. An organization owner on a Team or Enterprise plan uploads `catpilot-safe-building.zip` from the [latest release](https://github.com/catpilotai/catpilot-ai-guardrails/releases/latest) under **Organization settings → Skills**. It then appears in every member's skills list with a team indicator; members can toggle it off. Skills require the organization's "Code execution and file creation" setting to be on. There is no hook surface and no evidence log on this host; what the organization gets is the coaching text in every member's conversations, and, on Claude Code v2.1.273 and later, the same skill synced into terminal sessions signed in with a claude.ai account.

Not yet verified by Catpilot. The steps above are the vendor's documented path. On an individual plan, the same zip uploads under **Customize → Skills**; that verifies the package and the coaching in Claude.ai, not the organization upload, and is recorded as its own row.

## Codex CLI

Codex CLI reads administrator-managed configuration above the user's `~/.codex/config.toml`, from the vendor's [managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration) page:

| What | macOS and Linux | Windows |
| --- | --- | --- |
| Managed defaults (same keys as `config.toml`) | `/etc/codex/managed_config.toml` | `~/.codex/managed_config.toml` |
| Requirements (constraints users cannot relax) | `/etc/codex/requirements.toml` | `%ProgramData%\OpenAI\Codex\requirements.toml` |
| MDM | managed preferences domain `com.openai.codex`, keys `config_toml_base64` and `requirements_toml_base64` (base64 TOML) | registry, per vendor docs |
| Admin-wide skills | `/etc/codex/skills/<name>/` | per vendor docs |

Precedence, highest first: MDM, cloud-delivered requirements from the ChatGPT admin console, the system `requirements.toml`, the user's `config.toml`, command-line overrides. Verified on 0.154.0 (2026-09-20): with the files placed by `install.sh` and a temporary home holding no skills and no server config, Codex listed both skills from `/etc/codex/skills` and completed `list_approved` through the server named in `/etc/codex/managed_config.toml`; the user-level equivalents (`~/.agents/skills/`, `mcp_servers` in `config.toml`) were verified the same day ([verification note](../evals/reports/2026.09.20-org-deployment-verification.md)). The MDM keys are documented by the vendor and named by the binary; not exercised.

**What the example file carries.** `deploy/org/codex/managed_config.toml` provides the server as `mcp_servers.catpilot_guardrails.url`. The skill goes to `/etc/codex/skills/catpilot-safe-building/` (and `catpilot-security-core/` for engineers), where Codex discovers it for every user alongside `~/.agents/skills` and each repository's `.agents/skills`. A `requirements.toml` can additionally constrain approval policies, sandbox modes, and MCP server allowlists; that is your policy, not this package's. The only `requirements.toml` this package writes holds one managed `SessionStart` hook for the company rules, and only with `--overlay` ([below](#company-rules-at-session-start-on-codex)).

**Repository route.** For teams that cannot touch `/etc`, append `dist/<release>/AGENTS.md` to the `AGENTS.md` of your template repositories, and commit `.agents/skills/catpilot-safe-building/` there. Codex reads `AGENTS.md` up to `project_doc_max_bytes`; the shipped block is under 8,000 characters.

**Confirm it on one machine.** Codex emits no load event for skills, so the signals are the ones the [tested-runtimes table](REFERENCE.md#tested-runtimes) records: the model naming the skill when asked what guidance it has, input token usage rising when it reads the skill, and `mcp_tool_call` in the transcript when it calls `list_approved`. Run `codex` in an empty directory and ask: "What guidance skills do you have available, by name? Then call the catpilot_guardrails tool list_approved with category hosting and tell me the first item."

**What this does not reach.** Codex cloud tasks and Work with Local computer access, whose cloud orchestration runs only MCP hooks, get none of the hooks below. The server-side evidence log (below) records the lookups.

### Blocking hooks on Codex

`install.sh` gives Codex the same three checks as Claude Code, as managed `PreToolUse` hooks: the credential and destructive-operation checks on `Bash`, and the credential check on file edits, which Codex sends as `apply_patch`, the patch in `tool_input.command`, whichever of `apply_patch`, `Edit` or `Write` a matcher names. Each command passes `--host codex`, so its evidence lines say `codex`. A hook that denies prints the same reason as on Claude Code. Not verified on a host as managed hooks ([status](#verification-status)); the `Bash` checks were verified on Codex CLI 0.169.0 as project-level hooks on 2026-11-17 ([note](../evals/reports/2026.11.17-session-start-rules-verification.md)).

**What `install.sh` places.**

- `/etc/codex/catpilot-guardrails/hooks/`: `pretooluse-secrets.py`, `pretooluse-write-secrets.py` and `pretooluse-destructive-ops.py`, and the `catpilot_guard` package beside them (its `.py` files only);
- `/etc/codex/requirements.toml`, only when there is none; otherwise it prints the file for you to merge, keeping one `[features]` and one `[hooks]` table. Without `--overlay` it is exactly:

```toml
[features]
hooks = true

[hooks]
managed_dir = "/etc/codex/catpilot-guardrails/hooks"

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl" python3 "/etc/codex/catpilot-guardrails/hooks/pretooluse-secrets.py" --host codex'
timeout = 10

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl" python3 "/etc/codex/catpilot-guardrails/hooks/pretooluse-destructive-ops.py" --host codex'
timeout = 10

[[hooks.PreToolUse]]
matcher = "^apply_patch$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl" python3 "/etc/codex/catpilot-guardrails/hooks/pretooluse-write-secrets.py" --host codex'
timeout = 10
```

With `--overlay` the session-start hook follows (next section). Writing the file needs Python 3.8 or later as `PYTHON_BIN` (by default `python3`, which under `sudo` is the system one); `install.sh` stops before changing anything when it cannot run, since the hooks need it too.

**`[features].hooks = true`.** Codex's documentation says to pin it in `requirements.toml` to keep managed hooks on for someone who turned hooks off in their own `config.toml`. Without it, a person could switch these checks off. It does not switch off anyone's own hooks. `verify.sh` notes a `requirements.toml` that does not pin it and fails one that sets it to `false`.

**What a denial looks like, and what a failure does.** Codex reads the same deny decision as Claude Code. A hook that cannot read its input or load its package exits 2, which blocks. Codex's documentation also says a `PreToolUse` error, timeout or malformed response can let the tool run, so a hook that never starts (no `python3` on Codex's `PATH`) protects nothing; `verify.sh` checks the interpreter.

**`verify.sh`** runs each hook directly on harmless probes in Codex's event shape (AWS's documentation key in a command, a force push to `main`, a patch adding that key, and `ls` and a harmless patch that must pass), then runs each command `requirements.toml` declares through a shell, with `HOME` at a temporary directory so no evidence line is written. It fails a hook that is missing, does not deny its probe, or sits under a matcher that misses its tool, and notes a command without `--host codex`.

### Company rules at session start on Codex

With `--overlay`, `install.sh` declares a managed `SessionStart` hook that gives Codex the whole rules block as developer context after a session starts, resumes, is cleared, compacted or forked. Advice, not enforcement: `SessionStart` cannot block. Verified on Codex CLI 0.169.0 on 2026-11-17 for current and expired rules ([note](../evals/reports/2026.11.17-session-start-rules-verification.md), [status](#verification-status)).

**What `install.sh` places.**

- `/etc/codex/catpilot-guardrails/hooks/catpilot-company-rules.py` and, beside it, the `catpilot_guard` package (`hooks/catpilot_guard/`, its `.py` files only);
- `/etc/codex/catpilot-guardrails/instructions/company-checklist.md` and `company-checklist.json`;
- in `/etc/codex/requirements.toml`, after the blocking hooks above, the session-start hook:

```toml
[[hooks.SessionStart]]
matcher = "startup|resume|clear|compact|fork"

[[hooks.SessionStart.hooks]]
type = "command"
command = 'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl" python3 "/etc/codex/catpilot-guardrails/hooks/catpilot-company-rules.py" --host codex'
timeout = 10
```

The files are root-owned, mode 644, in directories with mode 755, like the Claude Code copies. Codex loads managed hooks from `[hooks]` in `requirements.toml` when `managed_dir` is an absolute path that exists, and its documentation asks for absolute script paths under that directory; Codex does not distribute the scripts itself ([hooks documentation](https://learn.chatgpt.com/docs/hooks#managed-hooks-in-local-codex), read 2026-11-16). Managed hooks are trusted by policy: nobody is asked to review them, and `/hooks` cannot disable them. When the rules are current, the script prints the block as `additionalContext`, which Codex adds as developer context.

**One copy per tool.** On a machine with both tools, Codex gets its own copy of the script, the package and the rules under `/etc/codex/`, rather than a path into Claude Code's managed directory. Each tool then reads only from its own managed location, a fleet that deploys one tool gets a self-contained tree, and removing one tool's directory does not break the other. `install.sh` writes both copies from one build, and `verify.sh` fails when they differ.

**Left to you.** `allow_managed_hooks_only = true` skips every user, project, session and plugin hook and keeps only managed ones. It would switch off people's own hooks, so `install.sh` does not set it; add it to `requirements.toml` if your policy wants it. `[features].hooks = true` is set (above), so a person who turned hooks off still gets the rules at session start.

If your `requirements.toml` already has a `[hooks]` table with its own `managed_dir`, keep that one and copy `catpilot-guardrails/` under it, adjusting the command's path; `verify.sh` notes a script outside `managed_dir`. `uninstall.sh` then leaves the file and the copy to you.

**Precedence.** `/etc/codex/requirements.toml` is the lowest-ranked requirements source: requirements from ChatGPT's Agent Security and the macOS MDM key `requirements_toml_base64` rank above it. The vendor documents that hooks in requirements have field-specific composition rules, without spelling them out for this case ([managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration#locations-and-precedence)). On a machine that also receives cloud or MDM requirements, check `/hooks` in a session.

**Size.** By default Codex gives the model only a preview of a hook's context above about 2,500 tokens. The example block is about 600 tokens. When yours is over the budget, the script says so on stderr and still prints it all; raise `additionalContextLimit` on the `[[hooks.SessionStart.hooks]]` entry. `uninstall.sh` then keeps the edited file and names it.

**What a session should show.** Not verified; from the vendor's documentation. `/hooks` lists the `SessionStart` hook as managed. Then [check the rules in a session](#check-the-company-rules-in-a-session).

**On expiry.** From the day after `expires_on`, by the machine's local date, Codex gets no rules. The script prints "The company rules expired on `<date>` and are not in force. Ask `<owner>` for current rules." as developer context and as a warning the person sees. A missing or mismatched file prints that the company rules could not be loaded and are unknown.

**What this does not reach.** Codex cloud tasks, and Work with Local computer access, whose cloud orchestration supports only MCP hooks; and ChatGPT.

## Check the company rules in a session

`verify.sh` runs the session-start script and each registered command directly, so, as with the hooks, only a session shows that a tool loads them. The check is a session with no skill, no MCP server and no project instruction file, so that only the rules at session start can answer. On a test machine, install with `--skills ""` (no skills) and a server URL that does not resolve, such as `https://mcp.invalid/mcp`, from a test copy of your rules with one distinctive value, so an answer from the rules cannot be a guess. Start each tool in an empty directory, with a configuration directory that holds only its sign-in (`CLAUDE_CONFIG_DIR` for Claude Code, `CODEX_HOME` for Codex), and confirm with `/mcp` and `/skills` that nothing else is loaded. Then:

1. Claude Code: run `/status`, `/context all` and `/hooks` (above). Codex: run `/hooks`.
2. Ask each tool: "Which hosting does my company approve, and who do I ask?" The answer should name the approved hosting and the owner from your rules file.
3. Make the rules expired: in each tool's `company-checklist.json`, after keeping a copy, set `reviewed_on` and `expires_on` to dates in the past. The block's hash does not cover the sidecar, so the hashes still match and the script reports the rules as expired. `verify.sh` now fails with the expiry. On Claude Code, also change the same two dates in the marked section of the managed `CLAUDE.md`, after keeping a copy. Rules that really expire carry the same dates in both places. When the two disagree, the model goes by the `CLAUDE.md` and answers from rules it calls current (2026-11-17). A new session in each tool shows the expired notice, and asked the same question, the model should say the rules expired and name the owner. Put the copies back, or run `install.sh --overlay` again.
4. `tail ~/.catpilot-guardrails/evidence.jsonl` shows a `rules_delivered` line per session with `host` `claude-code` or `codex`, then `rules_expired` lines, with no rule text.

Record the version of each tool, the date and the transcript under `evals/reports/` to move the rows below to verified.

## ChatGPT

The largest non-engineer population, and the thinnest coverage. What exists: a paste block, [`dist/<release>/chatgpt-project-instructions.md`](../dist/), sized under the 8,000-character limit of a GPT's instructions, and a manual verification protocol in [`evals/HOST_VERIFICATION.md`](../evals/HOST_VERIFICATION.md) that has not yet been run. Nothing has been measured on ChatGPT; the [benchmarks](../evals/reports/) ran on Claude Code and Codex CLI, and the finding that a short list in the instruction slot did about as well as the full skill was measured there, not here.

Three routes, in order of how central they are:

1. **A workspace plugin, installed for everyone.** In ChatGPT Business, Enterprise, and Edu workspaces, a plugin can be skills-only, and an administrator sets its installation policy to *Installed* under **Workspace settings → Plugins**, which installs it for every eligible member or role. Administrators can also import a plugin marketplace from a GitHub repository and let it sync daily; the supported manifests are `.agents/plugins/marketplace.json`, `.claude-plugin/marketplace.json`, and a standalone `.claude-plugin/plugin.json`. This repository ships a standalone Claude-compatible manifest at [`.claude-plugin/plugin.json`](../.claude-plugin/plugin.json), skills only (no hooks, no MCP servers, so no *Desktop only* label), and a one-entry marketplace at `.claude-plugin/marketplace.json`, so an administrator imports it with **Workspace settings → Plugins → Add → Import marketplace**, source `https://github.com/catpilotai/catpilot-ai-guardrails`, Path empty, then sets the installation policy to *Installed*. The manifest is verified as a plugin in Claude Code (above); the ChatGPT import itself is not yet run.
2. **A custom GPT shared to the workspace.** One person creates a GPT with the paste block as its instructions (the private build's overlay block for a pilot) and shares it to the workspace; members build inside that GPT. Static: no server, no lookup, no evidence.
3. **Per-user Project instructions.** The same block pasted by each person. No central path; consumer ChatGPT has only this.

**Company rules on ChatGPT** come either baked into the instructions (route 2) or through a connector to your self-hosted server, which depends on plan and on developer mode or an administrator adding the connector. Not verified.

On an individual plan only route 3 and a private custom GPT are available; they verify the paste block and the coaching, not workspace distribution, and are recorded as their own row.

**Confirm it.** There is no CLI, so the protocol is manual: create the GPT or install the plugin, run each of the ten scenario prompts from `python3 tools/eval.py --print-prompts` in a fresh chat with and without it, save the first responses to a JSONL file, and score with `tools/eval.py --import`. About twenty chats. Record the date and the reviewer in the table below.

**What this host cannot give you.** No hooks, so zero enforcement; nothing runs on the person's machine, so no local evidence log; the full skill never fits, only the block.

## The evidence log

The three hooks, the session-start hook and the server can append one JSON line per event to a local file named by `CATPILOT_EVIDENCE_LOG`. Off unless the variable is set; the public endpoint never sets it. A logging failure never changes a decision, an answer or what the session-start hook prints. Every line follows one versioned schema, [`spec/EVIDENCE.md`](spec/EVIDENCE.md), with the JSON Schema beside it. Lines written before schema version 1 have no `schema_version`; they use the same keys, and `tools/evidence_summary.py` reads them alone or mixed with new ones.

What a line carries, and what it never carries:

| Source | Recorded | Never recorded |
| --- | --- | --- |
| Every line | `schema_version`, a random `event_id`, the time (`ts`), `source`, and `event` from a closed list (`deny`, `input_error`, `lookup`, `rules_delivered`, `rules_expired` and `policy_error` are written today) | the machine's hostname, the person's name or account |
| `pretooluse-secrets` | hook, `deny` or `input_error`, `host` `claude-code`, tool `Bash`, the credential type (`label`), the session id when it is an opaque id | the command, the matched text |
| `pretooluse-write-secrets` (logged as `pretooluse-write-private-key` before the rename) | hook, `deny` or `input_error`, `host` `claude-code`, the tool (`Write`, `Edit`, ...), the credential type or `private-key-block`, the session id when it is an opaque id | the file path, the content |
| `pretooluse-destructive-ops` | hook, `deny` or `input_error`, `host` `claude-code`, tool `Bash`, the operation type (`label`), the session id when it is an opaque id | the command |
| `session-start` (`catpilot-company-rules.py`, on Claude Code and Codex) | `rules_delivered`, `rules_expired` or `policy_error`; `host` `claude-code` or `codex`; how the session started (`session_source`: `startup`, `resume`, `clear`, `compact` or `fork`); the session id when it is an opaque id; on `rules_delivered` and `rules_expired`, the SHA-256 of the company rules file (`policy_sha256`) and the release; on `rules_delivered`, the block's size (`block_chars`, `block_lines`); on `policy_error`, a fixed `label` saying why (`missing`, `unreadable`, `malformed`, `hash-mismatch`, `bad-arguments` or `internal-error`) | the rules' text, the owner, the dates, any path, anything else from the hook event |
| `mcp-server` | `lookup`, release, tool, `policy_status`, `unknown_policy`, the SHA-256 of the company rules file whenever one was read (`policy_sha256`), the enumerated argument (`topic`, `category`, `kind`, or `invalid`), and for `check_plan` the `outcome`, `ask_a_human`, and the *names* of the fields the caller supplied | the description, data classes, hosting, services, any value from the company rules file, or any other value |

`rule_id` and `mode` are defined in the schema for company rules enforced by the hooks; nothing writes them yet.

```json
{"event": "deny", "event_id": "5b0f3c1e-8f2a-4d7b-9c41-0e6a2d9f7b13", "hook": "pretooluse-secrets", "host": "claude-code", "label": "AWS access key ID", "schema_version": 1, "session_id": "…", "source": "claude-code-hook", "tool": "Bash", "ts": "2026-11-16T15:04:05+00:00"}
{"block_chars": 2369, "block_lines": 55, "event": "rules_delivered", "event_id": "d315489c-c591-4142-96de-79e1fa77e387", "host": "codex", "policy_sha256": "…", "release": "2026.09.18", "schema_version": 1, "session_id": "…", "session_source": "startup", "source": "session-start", "ts": "2026-11-16T15:05:02+00:00"}
{"ask_a_human": true, "error": null, "event": "lookup", "event_id": "a3e9d0b4-6c1f-4e52-8b7a-2f4d6c8e0a91", "fields": ["audience", "data_classes"], "outcome": "requires_review", "policy_sha256": "…", "policy_status": "approved", "release": "2026.09.18", "schema_version": 1, "source": "mcp-server", "tool": "check_plan", "ts": "2026-11-16T15:06:11+00:00", "unknown_policy": false}
```

Turn it on: for the hooks, the managed settings example sets it on each hook command (`CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl"`), so each user's denials land in their own home directory, where your device-management or endpoint tooling can collect the file. The session-start hook commands that `install.sh --overlay` registers carry the same prefix on both tools, so a person's `rules_delivered` and `rules_expired` lines land in the same file. For the server, set the variable in the service's environment when you run it yourself. There is no upload, no rotation, and no aggregation in this package; ship the files to whatever you already use.

What a pilot report reads from it: denials per hook per day (the hooks were in force and did something), session starts per tool with the rules current, expired or not loaded (and which rules file, by hash), lookups per tool per day and how many returned `unknown_policy: false` (the overlay was reachable and answered), and `check_plan` outcomes over time. What it cannot tell you: what the person asked, what the model wrote, or whether advice was followed. Those come from the person, or from a benchmark.

## Verification status

| Channel | What was checked | Date | By |
| --- | --- | --- | --- |
| Claude Code, hooks through the managed settings file | verified on 2.1.326 through the system path on macOS: all three hooks denied their probes, including the destructive-operation forms added in 2026-11 (`bash -lc`, `timeout`, a home directory by absolute path, `terraform -chdir`, OpenTofu); a harmless command through `bash -lc` ran; the evidence log received one line per denial and no command text ([note](../evals/reports/2026.11.16-managed-hooks-verification.md)). The signed-in organization also delivered server-managed settings, and Claude Code skipped the file until `managedSourcesBehavior` was set to `"merge"` in the claude.ai admin console. First verified on 2.1.241 for the two hooks that existed then ([note](../evals/reports/2026.09.20-org-deployment-verification.md)). Both checks ran each hook as a self-contained script; the hooks as shims over the `catpilot_guard` package (Unreleased) have not been run on a host | 2026-11-16 | A maintainer placed the files, set the admin-console key and ran the session; Catpilot recorded |
| Claude Code, managed skills directory | verified on 2.1.241: both skills listed in a session with no user or project skill installed ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Basil placed the files; Catpilot ran the session |
| Claude Code, plugin from `.claude-plugin/` | verified from a local checkout on 2.1.241: validate, a `--plugin-dir` session listing both namespaced skills, `marketplace add` and `install` in a throwaway config directory ([note](../evals/reports/2026.09.20-org-deployment-verification.md)); the GitHub form of `marketplace add` and `install` verified after merge | 2026-09-20 | Catpilot |
| Claude Code, server through `managed-mcp.json` | verified on 2.1.241 through the system path: `claude mcp list` showed only the managed server, connected, and a session completed `list_approved` through it ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Basil placed the file; Catpilot ran the session |
| Claude Code, server through `managedMcpServers` | did not load on 2.1.241 from the managed settings file; use `managed-mcp.json` or a repository `.mcp.json` | 2026-09-20 | Catpilot |
| Claude.ai, organization skills | not yet verified; needs a Team or Enterprise owner | | |
| Claude.ai, individual upload under Customize → Skills | verified on a Claude Pro account: the reply to the shared-password scenario read the skill file and coached as the skill specifies ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Basil ran it; Catpilot recorded |
| Codex CLI, user-level `~/.agents/skills` and `mcp_servers` in `config.toml` | verified in a temporary home on 0.154.0: the skill was named and read, `list_approved` completed through the hosted endpoint ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Catpilot |
| Codex CLI, `/etc/codex` managed defaults and skills | verified on 0.154.0 in a temporary home with no user-level skills or server config: both skills listed from `/etc/codex/skills`, `list_approved` completed through the server named in `/etc/codex/managed_config.toml` ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Basil placed the files; Catpilot ran the session |
| ChatGPT, workspace plugin | the manifest ships and is verified as a plugin in Claude Code; the workspace import needs a Business, Enterprise, or Edu administrator | 2026-09-20 | Catpilot (manifest only) |
| ChatGPT, shared GPT | not yet verified; needs a Business, Enterprise, or Edu workspace | | |
| ChatGPT, the block as instructions on an individual plan | verified on a ChatGPT Pro account with the block pasted into the chat: the shared-password scenario was declined with the reason, company sign-in for the named group proposed, and a message to the IT/security owner drafted ([note](../evals/reports/2026.09.20-org-deployment-verification.md)); Project and GPT instructions carry the same text and were not separately run | 2026-09-20 | Basil ran it; Catpilot recorded |
| Claude Code, company rules in the managed `CLAUDE.md` (`install.sh --overlay`) | verified on 2.1.326 through the system path on macOS, in an organization with claude.ai managed settings and `"merge"` set: with no skills and an unreachable server, a session answered which hosting is approved and whom to ask with the two distinctive values from the installed test rules. With the rules expired, it said they were out of date, named the owner, and repeated them labeled as expired. `/context all` was not run ([note](../evals/reports/2026.11.17-session-start-rules-verification.md)) | 2026-11-17 | A maintainer installed and ran the sessions; Catpilot recorded |
| Claude Code, `SessionStart` status hook through the managed settings file | verified on 2.1.326: each session start wrote a `rules_delivered` or `rules_expired` line with `host` `claude-code`, Its output reached the model: with only the sidecar backdated, the model quoted an expiry date, 2026-02-01, that only the hook's notice carried. `/hooks` was not run, and only the `startup` source ran ([note](../evals/reports/2026.11.17-session-start-rules-verification.md)) | 2026-11-17 | A maintainer installed and ran the sessions; Catpilot recorded |
| Codex CLI, `PreToolUse` hooks through `/etc/codex/requirements.toml` (`install.sh`) | not verified as managed hooks. `tests/test_deploy_codex_hooks.py` installs them in temporary directories, runs each declared command through a shell on Codex-shaped events, and checks `verify.sh` and `uninstall.sh`; the `Bash` checks were verified on Codex CLI 0.169.0 as project-level hooks on 2026-11-17 ([note](../evals/reports/2026.11.17-session-start-rules-verification.md)); the `apply_patch` check has not run on a host | | |
| Codex CLI, `SessionStart` hook through `/etc/codex/requirements.toml` | verified on 0.169.0 with no trust step: a session answered the same question with the two distinctive values. With the rules expired, the host showed the warning, and the model named no approved host and named the owner. Each session wrote a `rules_delivered` or `rules_expired` line with `host` `codex`. `/hooks` was not run, and only the `startup` source ran ([note](../evals/reports/2026.11.17-session-start-rules-verification.md)) | 2026-11-17 | A maintainer installed and ran the sessions; Catpilot recorded |
| Evidence log, hooks and server | unit and stdio contract tests in `tests/` | 2026-09-20 | Catpilot |

A row moves to "verified" when a person has run the steps on a real machine and recorded the transcript or screenshot under `evals/reports/`, the same standard as the tested-runtimes table.

## A pilot, in order

1. Author the overlay from your actual approved-hosting and approved-services lists; validate it; run the server with it behind your gateway.
2. Run `install.sh` on one machine; run the confirmation steps for each channel the pilot uses; record the dates above.
3. Roll out through your MDM or the claude.ai console; give the ChatGPT users their GPT or plugin.
4. Collect the evidence logs; read them weekly.
5. Ask the builders what changed. The log says the guardrails were there; only the people can say whether the guidance helped.
