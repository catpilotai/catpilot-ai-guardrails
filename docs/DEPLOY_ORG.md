# Rolling out to an organization

How an administrator puts the guardrails on every machine, for Claude Code, Claude.ai, Codex CLI, and ChatGPT, and how to confirm on one machine that it landed before pushing it to the fleet. It assumes you have read [what this does and does not do](../README.md#what-this-does-and-does-not-do): a deployed skill is advice, the two Claude Code hooks are the only enforcement, and the evidence log described at the end is a record, not a control.

Verification status is in the [table at the end](#verification-status). A channel marked "not verified" has its steps written from the vendor's documentation and has not been exercised by Catpilot; treat it as a plan until someone runs it and records the date. Catpilot has no Team, Business, or Enterprise workspace of its own, so the organization-level rows for Claude.ai and ChatGPT can only be closed by an organization that runs them: a pilot's administrator, or anyone who sends the record ([`CONTRIBUTING.md`](../CONTRIBUTING.md)). What an individual account can verify instead is noted in each section and has its own rows.

## What central deployment changes, and what it does not

Central deployment puts the same files on every machine from a source the user cannot override: an admin-managed settings file, an MDM profile, a workspace setting. That answers "how do I roll this out to forty people" and "how do I know it is still there next month." It does not change what the files are:

- A skill is still guidance the model reads. Centrally deployed, it is guidance the model reads on every machine.
- The two `PreToolUse` hooks are still the only enforcement, on Claude Code only, on the `Bash` and file-write paths only. Centrally deployed, they are enforcement the user cannot switch off, which is the difference that matters for a control.
- The server still answers lookups the model chooses to make. Centrally deployed, it is reachable from every session, and with your overlay loaded it answers with your company's approved options instead of generic defaults.
- ChatGPT and Claude.ai have no hook surface. On those hosts the honest story is coaching plus the vendor's own admin controls.

The overlay is the piece that carries your company's facts, and it is the piece to author first: approved hosting, approved services, data classes, the identity rule, review triggers, and who to ask, with a reviewer date and an expiry date ([`docs/spec/OVERLAY.md`](spec/OVERLAY.md)). Run the reference server yourself with `CATPILOT_OVERLAY_FILE` pointing at it, behind your own gateway ([`mcp-server/README.md`](../mcp-server/README.md), [`deploy/README.md`](../deploy/README.md)). The public endpoint at `mcp.catpilot.ai` serves generic defaults only and never a company overlay, so every example below uses `https://mcp.example.com/mcp` as a placeholder for your server.

## The files

Everything an administrator places is under [`deploy/org/`](../deploy/org/):

| File | What it is |
| --- | --- |
| `claude-code/managed-settings.json` | Both hooks, with the evidence log turned on per user, and the server provided through `managedMcpServers` alongside whatever servers users already have |
| `claude-code/managed-mcp.json` | The stricter alternative for the server: a fixed set, and users cannot add others |
| `codex/managed_config.toml` | The server as a managed default for Codex CLI |
| `install.sh` | Places all of it on one macOS or Linux machine as root, with your server URL substituted; refuses to overwrite a managed file that already exists and prints what to merge instead; `--managed-mcp-json` also writes the fixed-set `managed-mcp.json` |
| `verify.sh` | Read-only presence checks as a normal user, and the evidence log's last line |
| `uninstall.sh` | Removes exactly what `install.sh` placed; leaves a managed file alone if it was edited since |

The skills come from [`skills/`](../skills/) in a checkout of the release you are deploying; the install script copies them. Pin the release: the files are deterministic per release and the [`CHANGELOG.md`](../CHANGELOG.md) says what changed.

## Claude Code

Claude Code reads an admin-managed settings file above every user, project, and command-line setting. Users cannot override it, apart from a few security-sensitive keys where a stricter user value still counts.

| OS | Managed directory |
| --- | --- |
| macOS | `/Library/Application Support/ClaudeCode/` |
| Linux and WSL | `/etc/claude-code/` |
| Windows | `C:\Program Files\ClaudeCode\` |

Delivery options, from the vendor's [managed settings](https://code.claude.com/docs/en/managed-settings) page: the `managed-settings.json` file in that directory, an MDM profile (macOS managed preferences domain `com.anthropic.claudecode`, or the `Settings` value under `HKLM\SOFTWARE\Policies\ClaudeCode` on Windows), or server-managed settings from the claude.ai admin console. The file and the MDM profile reach local sessions; cloud sessions read only server-managed settings.

**What the example file carries.** `deploy/org/claude-code/managed-settings.json` registers the two hooks from a root-owned copy under `<managed dir>/catpilot-guardrails/hooks/` (a hook the user can edit is not a control), sets `CATPILOT_EVIDENCE_LOG` on each hook command so denials are recorded under the user's home, and provides the server through `managedMcpServers`, which adds it to every user's session without removing servers they configured themselves. To lock the server set instead, deploy `managed-mcp.json` in the same directory (`install.sh --managed-mcp-json`); then only the servers it lists load, and `claude mcp add` refuses others. On Claude Code 2.1.241 the `managedMcpServers` key in the managed settings file did not load the server in Catpilot's check (the hooks and skills from the same file and directory did); until a newer version is checked, provide the server through `managed-mcp.json` or through a `.mcp.json` committed to your template repositories ([`mcp-server/host-configs/`](../mcp-server/host-configs/)). `allowManagedHooksOnly: true` and `allowManagedPermissionRulesOnly: true` are available if you want the managed file to be the only source of hooks or permission rules; the example leaves them out.

**Skills.** Two central routes. A skill placed at `<managed dir>/.claude/skills/<name>/SKILL.md` loads for every user of the machine; the install script puts the chosen skills there. Alternatively, an organization owner uploads the skill once in claude.ai (below), and Claude Code v2.1.273 and later syncs the skills enabled for a signed-in claude.ai account into terminal sessions (`syncClaudeAiSkills`, on by default; not for API-key sessions). The repository route, `.claude/skills/` committed to your template repositories, still works and needs no admin rights.

**Place it.** From a checkout of the release, as an administrator:

```bash
sudo deploy/org/install.sh --server-url https://mcp.example.com/mcp
```

**Confirm it on one machine before the fleet.** As a normal user on that machine:

1. `deploy/org/verify.sh` prints what is present.
2. Start Claude Code and run `/status`. The `Setting sources` line must list `Enterprise managed settings (file)`; with an MDM profile it says `(plist)` or `(HKLM)`. If the line is missing, the file is not where Claude Code looks, or it failed to parse; `claude doctor` lists dropped entries.
3. `claude mcp list` shows `catpilot-guardrails`.
4. Ask for a command that contains AWS's documentation-only example key: `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && echo ok`. It is denied with a reason that names the credential type and does not echo the value. Ask for the same command with `$AWS_ACCESS_KEY_ID`; it runs.
5. Ask it to write a file whose content starts with `-----BEGIN RSA PRIVATE KEY-----` and a synthetic body. The write is denied.
6. Ask it to call `list_approved` with category `hosting`. With your overlay loaded, the answer names your approved hosting and `unknown_policy` is false.
7. `tail ~/.catpilot-guardrails/evidence.jsonl` shows one line per denial from steps 4 and 5, with no command text in it.

The vendor documents a testing variable, `CLAUDE_CODE_MANAGED_SETTINGS_PATH`, that points Claude Code at a managed file outside the system path. In Catpilot's check on 2.1.241 (2026-09-20) it did not take effect; through the system path, the same file's hooks ran and the same directory's skills loaded. The system path is the only route this page relies on. Note that the managed file applies to every Claude Code session on the machine, the desktop app included, until `uninstall.sh` removes it.

**What this does not reach.** Cloud sessions (server-managed settings only), the desktop app's own connectors (governed from claude.ai organization settings), and any tool other than Claude Code.

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

**What the example file carries.** `deploy/org/codex/managed_config.toml` provides the server as `mcp_servers.catpilot_guardrails.url`. The skill goes to `/etc/codex/skills/catpilot-safe-building/` (and `catpilot-security-core/` for engineers), where Codex discovers it for every user alongside `~/.agents/skills` and each repository's `.agents/skills`. A `requirements.toml` can additionally constrain approval policies, sandbox modes, and MCP server allowlists; that is your policy, not this package's, and no example is shipped.

**Repository route.** For teams that cannot touch `/etc`, append `dist/<release>/AGENTS.md` to the `AGENTS.md` of your template repositories, and commit `.agents/skills/catpilot-safe-building/` there. Codex reads `AGENTS.md` up to `project_doc_max_bytes`; the shipped block is under 8,000 characters.

**Confirm it on one machine.** Codex emits no load event for skills, so the signals are the ones the [tested-runtimes table](REFERENCE.md#tested-runtimes) records: the model naming the skill when asked what guidance it has, input token usage rising when it reads the skill, and `mcp_tool_call` in the transcript when it calls `list_approved`. Run `codex` in an empty directory and ask: "What guidance skills do you have available, by name? Then call the catpilot_guardrails tool list_approved with category hosting and tell me the first item."

**What this does not reach.** Codex has no hook that this package ships, so there is no enforcement and no local evidence on this host; the server-side evidence log (below) records the lookups.

## ChatGPT

The largest non-engineer population, and the thinnest coverage. What exists: a paste block, [`dist/<release>/chatgpt-project-instructions.md`](../dist/), sized under the 8,000-character limit of a GPT's instructions, and a manual verification protocol in [`evals/HOST_VERIFICATION.md`](../evals/HOST_VERIFICATION.md) that has not yet been run. Nothing has been measured on ChatGPT; the [benchmarks](../evals/reports/) ran on Claude Code and Codex CLI, and the finding that a short list in the instruction slot did about as well as the full skill was measured there, not here.

Three routes, in order of how central they are:

1. **A workspace plugin, installed for everyone.** In ChatGPT Business, Enterprise, and Edu workspaces, a plugin can be skills-only, and an administrator sets its installation policy to *Installed* under **Workspace settings → Plugins**, which installs it for every eligible member or role. Administrators can also import a plugin marketplace from a GitHub repository and let it sync daily; the supported manifests are `.agents/plugins/marketplace.json`, `.claude-plugin/marketplace.json`, and a standalone `.claude-plugin/plugin.json`. This repository does not yet ship a plugin manifest; adding one so that a workspace can import it directly is the next step, and until then an administrator packages the skill folder as a plugin following OpenAI's plugin-management documentation. A plugin that declares MCP servers is marked *Desktop only* and does not run in ChatGPT on the web.
2. **A custom GPT shared to the workspace.** One person creates a GPT with the paste block as its instructions (the private build's overlay block for a pilot) and shares it to the workspace; members build inside that GPT. Static: no server, no lookup, no evidence.
3. **Per-user Project instructions.** The same block pasted by each person. No central path; consumer ChatGPT has only this.

**Company rules on ChatGPT** come either baked into the instructions (route 2) or through a connector to your self-hosted server, which depends on plan and on developer mode or an administrator adding the connector. Not verified.

On an individual plan only route 3 and a private custom GPT are available; they verify the paste block and the coaching, not workspace distribution, and are recorded as their own row.

**Confirm it.** There is no CLI, so the protocol is manual: create the GPT or install the plugin, run each of the ten scenario prompts from `python3 tools/eval.py --print-prompts` in a fresh chat with and without it, save the first responses to a JSONL file, and score with `tools/eval.py --import`. About twenty chats. Record the date and the reviewer in the table below.

**What this host cannot give you.** No hooks, so zero enforcement; nothing runs on the person's machine, so no local evidence log; the full skill never fits, only the block.

## The evidence log

Both hooks and the server can append one JSON line per event to a local file named by `CATPILOT_EVIDENCE_LOG`. Off unless the variable is set; the public endpoint never sets it. A logging failure never changes a decision or an answer.

What a line carries, and what it never carries:

| Source | Recorded | Never recorded |
| --- | --- | --- |
| `pretooluse-secrets` | time, hook, `deny` or `input_error`, tool `Bash`, the credential type (`label`), the session id | the command, the matched text |
| `pretooluse-write-private-key` | time, hook, `deny` or `input_error`, the tool (`Write`, `Edit`, ...), `private-key-block`, the session id | the file path, the content |
| `mcp-server` | time, release, tool, `policy_status`, `unknown_policy`, the enumerated argument (`topic`, `category`, `kind`, or `invalid`), and for `check_plan` the `outcome`, `ask_a_human`, and the *names* of the fields the caller supplied | the description, data classes, hosting, services, or any other value |

```json
{"event": "deny", "hook": "pretooluse-secrets", "label": "aws access key", "session_id": "…", "source": "claude-code-hook", "tool": "Bash", "ts": "2026-09-20T15:04:05+00:00"}
{"ask_a_human": true, "error": null, "fields": ["audience", "data_classes"], "outcome": "requires_review", "policy_status": "current", "release": "2026.09.18", "source": "mcp-server", "tool": "check_plan", "ts": "2026-09-20T15:06:11+00:00", "unknown_policy": false}
```

Turn it on: for the hooks, the managed settings example sets it on each hook command (`CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl"`), so each user's denials land in their own home directory, where your device-management or endpoint tooling can collect the file. For the server, set the variable in the service's environment when you run it yourself. There is no upload, no rotation, and no aggregation in this package; ship the files to whatever you already use.

What a pilot report reads from it: denials per hook per day (the hooks were in force and did something), lookups per tool per day and how many returned `unknown_policy: false` (the overlay was reachable and answered), and `check_plan` outcomes over time. What it cannot tell you: what the person asked, what the model wrote, or whether advice was followed. Those come from the person, or from a benchmark.

## Verification status

| Channel | What was checked | Date | By |
| --- | --- | --- | --- |
| Claude Code, hooks through the managed settings file | verified on 2.1.241 through the system path: both hooks denied, the evidence log received one line per denial with the session id, no user or project hook was configured ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Basil placed the file; Catpilot ran the session |
| Claude Code, managed skills directory | verified on 2.1.241: both skills listed in a session with no user or project skill installed ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Basil placed the files; Catpilot ran the session |
| Claude Code, server through `managedMcpServers` | did not load on 2.1.241 from the managed settings file; `managed-mcp.json` not yet exercised; the repository `.mcp.json` route is verified in the tested-runtimes table | 2026-09-20 | Catpilot |
| Claude.ai, organization skills | not yet verified; needs a Team or Enterprise owner | | |
| Claude.ai, individual upload under Customize → Skills | not yet verified | | |
| Codex CLI, user-level `~/.agents/skills` and `mcp_servers` in `config.toml` | verified in a temporary home on 0.154.0: the skill was named and read, `list_approved` completed through the hosted endpoint ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Catpilot |
| Codex CLI, `/etc/codex` managed defaults and skills | verified on 0.154.0 in a temporary home with no user-level skills or server config: both skills listed from `/etc/codex/skills`, `list_approved` completed through the server named in `/etc/codex/managed_config.toml` ([note](../evals/reports/2026.09.20-org-deployment-verification.md)) | 2026-09-20 | Basil placed the files; Catpilot ran the session |
| ChatGPT, workspace plugin | not yet verified; no manifest shipped | | |
| ChatGPT, shared GPT | not yet verified; needs a Business, Enterprise, or Edu workspace | | |
| ChatGPT, GPT or Project instructions on an individual plan | not yet verified; protocol written | | |
| Evidence log, hooks and server | unit and stdio contract tests in `tests/` | 2026-09-20 | Catpilot |

A row moves to "verified" when a person has run the steps on a real machine and recorded the transcript or screenshot under `evals/reports/`, the same standard as the tested-runtimes table.

## A pilot, in order

1. Author the overlay from your actual approved-hosting and approved-services lists; validate it; run the server with it behind your gateway.
2. Run `install.sh` on one machine; run the confirmation steps for each channel the pilot uses; record the dates above.
3. Roll out through your MDM or the claude.ai console; give the ChatGPT users their GPT or plugin.
4. Collect the evidence logs; read them weekly.
5. Ask the builders what changed. The log says the guardrails were there; only the people can say whether the guidance helped.
