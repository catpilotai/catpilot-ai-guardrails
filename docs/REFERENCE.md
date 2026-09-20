# Technical reference

Sections moved here from the README on 2026-09-20 so the README stays short. Nothing in them changed; runtime observations keep their recorded dates and versions. The [protection contract](PROTECTION_CONTRACT.md) says what is advice, what is a tested hook, and what is outside both.

## For agent harnesses

Domain-specific harnesses are being built everywhere: a loop that plans, calls a tool, checks the result, and repeats, wrapped around a model for one job, on the Claude Agent SDK, the OpenAI Agents SDK, LangGraph, CrewAI, or plain code. Hermes Agent and OpenClaw are harnesses with native skill support; most in-house loops have none. The loop owns the tool boundary, and that is the one place enforcement is possible.

- **Standing guidance for the loop.** Load `catpilot-security-core` for engineering work, or `catpilot-safe-building` for a loop that serves non-engineers, as system-level instructions or through the SDK's skills support. This is advice: it shapes what the model proposes on every iteration.
- **A gate on the shell tool.** [`hooks/harness/secret_gate.py`](../hooks/harness/secret_gate.py) is the Claude Code hook's credential check as a plain function. Call it before a command runs; the model gets the reason as the tool result and nothing executes. This is enforcement on the path you route through it, and only that path. How to wire it and what you may claim afterwards: [`hooks/harness/README.md`](../hooks/harness/README.md).
- **Rules for the loop itself.** [`frameworks/agentic/FULL_AGENTIC.md`](../frameworks/agentic/FULL_AGENTIC.md) covers what a one-line gate cannot: tool-execution sandboxing, human-in-the-loop for destructive operations, memory and context isolation, prompt-injection defense, multi-agent coordination and authentication, rate limiting and runaway prevention, scheduled-task idempotency, agent identity integrity, and tool-loop discipline with retry caps, state invalidation after every state-changing call, verifier-backed progress, and delegation-depth caps. Reference text today, not a packaged bundle.

A harness that loads the text has advice. A harness that gates a tool has enforcement on that tool. Write down which tool calls pass through the gate; the rest are uncovered until they do.

## Tested runtimes

Installable via skills.sh into 50+ runtimes; verified only on the runtimes and dates listed here.

| Runtime | Skill loads | Coaching (MCP) | Enforcement (hook) | Last verified | Release |
| --- | --- | --- | --- | --- | --- |
| Claude Code 2.1.241 | yes: a project `.claude/skills/` install is listed in the session init, and so is the admin-managed skills directory (2026-09-20); with the split core skill, Sonnet invoked it and read `references/cloud-cli-safety.md` before answering (2026-09-15), Haiku did not invoke it on the same prompt | yes: `list_approved` returned over stdio and through the hosted `http` endpoint; also through an admin-managed `managed-mcp.json` (2026-09-20) | yes: the `Bash` credential hook and the `Write`/`Edit` private-key hook each denied the action; each control run without the hook performed it ; both hooks also denied when configured only through the admin-managed settings file, with the evidence log written (2026-09-20) | 2026-09-15 | 2026.09.13 |
| Cursor | not verified | not verified | not tested | | |
| Codex CLI 0.154.0 | yes, with a caveat: a project `.agents/skills/` install; the host reads the skill on demand and emits no load event, so the signal is the model naming the skill and input usage rising from about 17k to over 90k tokens; with the split core skill it read the baseline and `references/cloud-cli-safety.md` (2026-09-15); a user-level `~/.agents/skills/` install was named and read the same way (2026-09-20) | yes: `mcp_tool_call` completed over stdio and through the hosted endpoint | none | 2026-09-14 | 2026.09.13 |
| Claude.ai (individual upload or organization provisioning) | yes, individual upload on a Pro account: the reply read the skill file and coached the shared-password scenario as specified (2026-09-20); organization provisioning not verified | custom connector to the hosted endpoint not yet verified | none, advisory only | 2026-09-20 | 2026.09.18 |
| ChatGPT (project or GPT instructions) | n/a, pasted text; with the block pasted into a chat on a Pro account it coached the shared-password scenario (refusal with reason, company sign-in, the human to ask, a drafted message) (2026-09-20); the manual protocol in [`evals/HOST_VERIFICATION.md`](../evals/HOST_VERIFICATION.md) is not yet run | custom connector to the hosted endpoint not yet verified | none | | |
| Microsoft Copilot Studio | n/a, pasted text | not verified | none | | |
| Lovable, Bolt, Replit, v0 | n/a, pasted text | not applicable | none | | |
| Everything else reachable through skills.sh | not verified | not verified | none | | |
| Your own harness | depends on how the loop loads it; not verified by Catpilot | call the server from the loop; not verified by Catpilot | the credential gate on the shell path you route through it; you test it in your loop | | |

"Skill loads" means a host signal showed the skill available in a recorded session, not the model saying it read it. "Enforcement" means a recorded tool-result trace showed the host applying the hook's deny decision, with a control run that executed the same command without the hook. Every dated cell has a note in [`evals/reports/`](../evals/reports/) with the exact commands and observations. A row without a date is a row without evidence. "Coaching (MCP)" means a recorded tool call from that host to the reference server, not that the host uses it in daily work.

## The hooks

Two Claude Code `PreToolUse` hooks, each on one tool path. Neither ever returns allow, so every other host rule still applies; malformed input fails closed. Install steps, exact coverage, and how to test each without a real secret: [`hooks/README.md`](../hooks/README.md).

- [`hooks/claude-code/pretooluse-secrets.py`](../hooks/claude-code/pretooluse-secrets.py), on the `Bash` tool: denies a shell command that contains a literal credential (the secret-blocking patterns), with a plain-language reason that never echoes the value. The escape hatch for a false positive is to reference the value from an environment variable, or to run the command yourself; there is no bypass flag.
- [`hooks/claude-code/pretooluse-write-private-key.py`](../hooks/claude-code/pretooluse-write-private-key.py), on `Write`, `Edit`, `MultiEdit`, and `NotebookEdit`: denies content that adds a PEM private-key block. It does not scan shell commands, reads, prompts, or other tools.

Both hooks can record each denial as one content-free JSON line when `CATPILOT_EVIDENCE_LOG` is set ([`hooks/README.md`](../hooks/README.md)); an organization deploys them through managed settings ([`DEPLOY_ORG.md`](DEPLOY_ORG.md)). For your own agent loop, [`hooks/harness/secret_gate.py`](../hooks/harness/secret_gate.py) is the credential check as a plain function; see [For agent harnesses](#for-agent-harnesses).

## The reference MCP server

A skill is text the model reads; the server in [`mcp-server/`](../mcp-server/) is a tool the model calls at the moment it matters. Four read-only tools: guidance for one checkpoint, a deterministic check of a building plan, a safe starting point for a common kind of app, and what the company has approved. With no overlay configured it answers from generic defaults and says `unknown_policy: true` on every answer; with a validated, unexpired [overlay](../docs/spec/OVERLAY.md) it answers with the company's values and cites their review and expiry dates. Stdio for Claude Code, Codex, and Cursor; streamable HTTP bound to localhost for anything that needs a remote server, behind your own gateway.

```bash
python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.txt
CATPILOT_OVERLAY_FILE=/private/path/overlay.yaml python mcp-server/server.py
```

It is a reference implementation you run yourself: no authentication, no tenant isolation, no logging, no outbound calls. The tenant-scoped, authenticated version is the Catpilot platform. A lookup the model never made protects nothing; the tested-runtimes table records where a real lookup was observed. Details: [`mcp-server/README.md`](../mcp-server/README.md).

### Hosted endpoint

A hosted instance of this same reference server is live at `https://mcp.catpilot.ai/mcp` (MCP streamable HTTP, stateless, JSON responses, no authentication). Health check: `https://mcp.catpilot.ai/health`. The root path `https://mcp.catpilot.ai/` returns a JSON data statement.

It serves generic defaults only. No company overlay is loaded, and none ever will be on this public endpoint: every answer carries `policy_status: "none"` and `unknown_policy: true`. It is advisory. Nothing it returns blocks an action.

Data handling: it receives only the topic, plan text, template kind, or category a client sends, stores nothing, and logs no request content. Responses carry `Cache-Control: no-store`.

In front of it: a per-client rate limit (60 requests per 10 seconds, then HTTP 429), a path allowlist, TLS end to end, and an origin that accepts connections only from the edge. What each protection does and how it was verified: [`deploy/README.md`](../deploy/README.md).

Claude Code:

```bash
claude mcp add --transport http catpilot-guardrails https://mcp.catpilot.ai/mcp
```

or as a one-off:

```bash
claude --mcp-config '{"mcpServers":{"catpilot-guardrails":{"type":"http","url":"https://mcp.catpilot.ai/mcp"}}}' --strict-mcp-config
```

Codex CLI, in `~/.codex/config.toml`:

```toml
[mcp_servers.catpilot_guardrails]
url = "https://mcp.catpilot.ai/mcp"
```

Example configs for both: [`mcp-server/host-configs/`](../mcp-server/host-configs/). Deployment steps and what the protections do: [`deploy/README.md`](../deploy/README.md). ChatGPT and Claude.ai custom connectors: not yet verified.

## Format

Skills use the [Agent Skills](https://agentskills.io/specification) format exactly. A skill is a directory containing a `SKILL.md` file with YAML frontmatter and a markdown body. Catpilot extensions (severity, control mappings, applies-to, mode, training-module links, evidence patterns) live in `catpilot.json` next to the shipped `SKILL.md`, and as string-valued `catpilot-*` keys in `metadata`, because the specification defines `metadata` as a map from string keys to string values; other runtimes ignore both. Details: [`docs/spec/SKILL_FORMAT.md`](../docs/spec/SKILL_FORMAT.md).

A recognized file layout helps distribution; it does not guarantee that a host loads every instruction or reference. Follow the host's current installation guidance and record the activation and behavioral checks you actually perform.

## Versioning

- **Repository releases** are CalVer (`YYYY.MM.DD`), listed on the Releases page and in the README's release badge, with the details in [`CHANGELOG.md`](../CHANGELOG.md).
- **Source skill components** inside a release are semver. `cloud-cli-safety` and `secret-blocking` are at `1.0.3`; `local-cli-safety` and `supply-chain` are at `1.0.2`; `database-safety`, `docker-safety`, `language-baseline`, `pii-and-test-data`, and `secrets-management` are at `1.0.1`. Each bumped after gaining the `## Baseline` section the baseline-references layout requires. The bundle frontmatter records which versions of which components shipped.
- The core bundle is `2026.09.16`; the safe-building bundle is `2026.09.18`. A bundle's version changes only when its content does.

CalVer matches the cadence of a content repo: each release is a dated snapshot, and the date is the meaningful signal for users and auditors. Semver on individual components carries the breaking-change semantics that matter for downstream consumers.

## How it's built

`tools/bundle.py` turns the source components under `src/skills/` into the shipped bundles under `skills/` and the per-host artifacts under `dist/<release>/`, deterministically; CI fails on drift. The core tier renders a baseline plus per-component references; the safe-building tier renders one file plus its per-host targets. The directory tree and the aggregation rules: [`docs/REPOSITORY_LAYOUT.md`](../docs/REPOSITORY_LAYOUT.md) and [`docs/spec/PACKAGING.md`](../docs/spec/PACKAGING.md).
