# Catpilot Security Skills

<p align="left">
  <img src="assets/catpilot-logo.png" alt="Catpilot" width="100" style="vertical-align: middle;">
  <em>Paws before you push.</em>
</p>

**For the tool and for the person using it.**

![Release](https://img.shields.io/github/v/release/catpilotai/catpilot-ai-guardrails?label=release&color=blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Format](https://img.shields.io/badge/format-Agent%20Skills-7B3FE4)

Security skills for AI coding agents, for people building apps with AI assistants, and for the domain-specific agent harnesses teams build around both, in the [Agent Skills](https://agentskills.io/specification) format. Two skills, one repository, no telemetry.

| Skill | Who it is for | What it covers |
| --- | --- | --- |
| **`catpilot-safe-building`** | A person, often not a developer, building an app, automation, dashboard, or data tool with an AI assistant, and the assistant helping them | Eight plain-language checkpoints that mirror Catpilot's Safe AI-assisted building course: data in prompts, access and identity, hosting, sharing, keys and credentials, third-party services, untrusted input, when to ask a human. |
| **`catpilot-security-core`** | Coding agents working in real codebases | Nine engineering components: cloud CLI, databases, local shell, Docker, hardcoded secrets, secrets lifecycle, supply chain, PII and test data, secure-coding patterns. |
| **Either skill, plus `hooks/` and `frameworks/agentic/`** | A harness: the loop a team builds around a model for one job | Standing guidance for every iteration of the loop, a credential gate the loop enforces on its shell tool, and reference rules for retries, scheduled runs, delegation, and self-modification. See [For agent harnesses](#for-agent-harnesses). |

Born from a real incident where an agent wiped production environment variables with a partial YAML update. The rules draw on incidents like that one and are used at [Catpilot.ai](https://catpilot.ai). They are MIT-licensed guidance, not a guarantee that an agent will follow them.

This repository is the portable baseline, not the Catpilot hosted platform. Read [what this does and does not do](#what-this-does-and-does-not-do) before treating anything here as a security control.

## Install for coding agents

```bash
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-safe-building
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core
```

Installation makes the instructions available to a compatible host. It does **not** prove they were loaded, followed, or enforced. Confirm the installed version, then test representative safe and unsafe tasks in an isolated environment. The [skills.sh CLI](https://skills.sh) (`vercel-labs/skills`) handles placement for the hosts it supports; installer compatibility is separate from anything Catpilot has verified. See [Tested runtimes](#tested-runtimes). Global installs, a specific agent, manual copies, and Hermes Agent: [`docs/INSTALL.md`](docs/INSTALL.md).

## For non-engineers

Nobody has to open a terminal.

- **Read the eight checkpoints** in five minutes: [`skills/catpilot-safe-building/SKILL.md`](skills/catpilot-safe-building/SKILL.md), the same text the tool follows. The web page source is [`dist/2026.09.16/web/safe-ai-building.html`](dist/2026.09.16/web/safe-ai-building.html); the formatted page ships with the website pass.
- **Claude.ai:** download `catpilot-safe-building.zip` from the [latest release](https://github.com/catpilotai/catpilot-ai-guardrails/releases/latest) (also at [`dist/2026.09.16/`](dist/2026.09.16/)) and upload it under Customize → Skills. An organization owner uploads it once under Organization settings → Skills and every member gets it.
- **ChatGPT, Microsoft Copilot Studio, Lovable, Bolt, Replit, v0:** paste the block for your tool from [`dist/2026.09.16/`](dist/2026.09.16/). Each file says where it goes, and each is under 8,000 characters.
- **Repository-based agents:** append the `AGENTS.md` or `copilot-instructions.md` block from the same directory.

What it does and does not do: guidance the tool can reference while you build. It is not monitoring, not enforcement, and not a substitute for your company's own controls.

## For agent harnesses

Domain-specific harnesses are being built everywhere: a loop that plans, calls a tool, checks the result, and repeats, wrapped around a model for one job, on the Claude Agent SDK, the OpenAI Agents SDK, LangGraph, CrewAI, or plain code. Hermes Agent and OpenClaw are harnesses with native skill support; most in-house loops have none. The loop owns the tool boundary, and that is the one place enforcement is possible.

- **Standing guidance for the loop.** Load `catpilot-security-core` for engineering work, or `catpilot-safe-building` for a loop that serves non-engineers, as system-level instructions or through the SDK's skills support. This is advice: it shapes what the model proposes on every iteration.
- **A gate on the shell tool.** [`hooks/harness/secret_gate.py`](hooks/harness/secret_gate.py) is the Claude Code hook's credential check as a plain function. Call it before a command runs; the model gets the reason as the tool result and nothing executes. This is enforcement on the path you route through it, and only that path. How to wire it and what you may claim afterwards: [`hooks/harness/README.md`](hooks/harness/README.md).
- **Rules for the loop itself.** [`frameworks/agentic/FULL_AGENTIC.md`](frameworks/agentic/FULL_AGENTIC.md) covers what a one-line gate cannot: tool-execution sandboxing, human-in-the-loop for destructive operations, memory and context isolation, prompt-injection defense, multi-agent coordination and authentication, rate limiting and runaway prevention, scheduled-task idempotency, agent identity integrity, and tool-loop discipline with retry caps, state invalidation after every state-changing call, verifier-backed progress, and delegation-depth caps. Reference text today, not a packaged bundle.

A harness that loads the text has advice. A harness that gates a tool has enforcement on that tool. Write down which tool calls pass through the gate; the rest are uncovered until they do.

## What this does and does not do

Three different things get called "protection". This repository uses the narrow words.

- **Advice.** A skill is guidance the model reads. It shapes what the model says and suggests. It is loaded only when the host chooses to load it. Both skills here are advice.
- **Contextual coaching.** A supported event in a work surface produces one explanation and one next step, at the moment it matters. That is a Catpilot platform capability, not something a skill file does. The safe-building skill tells an assistant how to coach; it cannot create the event.
- **Enforcement.** A specific action cannot proceed without a tested check in a trusted host. This repository ships exactly two, both Claude Code `PreToolUse` hooks: one denies a shell command that contains a literal credential, the other denies a file write or edit that adds a private-key block. Each covers that one path, on the host version in the table below, and nothing else.

It does not monitor anyone's work, send telemetry, block anything except through the documented hooks, scan repositories, certify compliance, or record training completion. An installed skill that is not loaded is not a control. A hook that is not configured is not a control.

The full statement is the [protection contract](docs/PROTECTION_CONTRACT.md).

## Tested runtimes

Installable via skills.sh into 50+ runtimes; verified only on the runtimes and dates listed here.

| Runtime | Skill loads | Coaching (MCP) | Enforcement (hook) | Last verified | Release |
| --- | --- | --- | --- | --- | --- |
| Claude Code 2.1.241 | yes: a project `.claude/skills/` install is listed in the session init; with the split core skill, Sonnet invoked it and read `references/cloud-cli-safety.md` before answering (2026-09-15), Haiku did not invoke it on the same prompt | yes: `list_approved` returned over stdio and through the hosted `http` endpoint | yes: the `Bash` credential hook and the `Write`/`Edit` private-key hook each denied the action; each control run without the hook performed it | 2026-09-15 | 2026.09.13 |
| Cursor | not verified | not verified | not tested | | |
| Codex CLI 0.154.0 | yes, with a caveat: a project `.agents/skills/` install; the host reads the skill on demand and emits no load event, so the signal is the model naming the skill and input usage rising from about 17k to over 90k tokens; with the split core skill it read the baseline and `references/cloud-cli-safety.md` (2026-09-15) | yes: `mcp_tool_call` completed over stdio and through the hosted endpoint | none | 2026-09-14 | 2026.09.13 |
| Claude.ai (individual upload or organization provisioning) | not verified | custom connector to the hosted endpoint not yet verified | none, advisory only | | |
| ChatGPT (project or GPT instructions) | n/a, pasted text; manual protocol in [`evals/HOST_VERIFICATION.md`](evals/HOST_VERIFICATION.md), not yet run | custom connector to the hosted endpoint not yet verified | none | | |
| Microsoft Copilot Studio | n/a, pasted text | not verified | none | | |
| Lovable, Bolt, Replit, v0 | n/a, pasted text | not applicable | none | | |
| Everything else reachable through skills.sh | not verified | not verified | none | | |
| Your own harness | depends on how the loop loads it; not verified by Catpilot | call the server from the loop; not verified by Catpilot | the credential gate on the shell path you route through it; you test it in your loop | | |

"Skill loads" means a host signal showed the skill available in a recorded session, not the model saying it read it. "Enforcement" means a recorded tool-result trace showed the host applying the hook's deny decision, with a control run that executed the same command without the hook. Every dated cell has a note in [`evals/reports/`](evals/reports/) with the exact commands and observations. A row without a date is a row without evidence. "Coaching (MCP)" means a recorded tool call from that host to the reference server, not that the host uses it in daily work.

## The hooks

Two Claude Code `PreToolUse` hooks, each on one tool path. Neither ever returns allow, so every other host rule still applies; malformed input fails closed. Install steps, exact coverage, and how to test each without a real secret: [`hooks/README.md`](hooks/README.md).

- [`hooks/claude-code/pretooluse-secrets.py`](hooks/claude-code/pretooluse-secrets.py), on the `Bash` tool: denies a shell command that contains a literal credential (the secret-blocking patterns), with a plain-language reason that never echoes the value. The escape hatch for a false positive is to reference the value from an environment variable, or to run the command yourself; there is no bypass flag.
- [`hooks/claude-code/pretooluse-write-private-key.py`](hooks/claude-code/pretooluse-write-private-key.py), on `Write`, `Edit`, `MultiEdit`, and `NotebookEdit`: denies content that adds a PEM private-key block. It does not scan shell commands, reads, prompts, or other tools.

For your own agent loop, [`hooks/harness/secret_gate.py`](hooks/harness/secret_gate.py) is the credential check as a plain function; see [For agent harnesses](#for-agent-harnesses).

## The reference MCP server

A skill is text the model reads; the server in [`mcp-server/`](mcp-server/) is a tool the model calls at the moment it matters. Four read-only tools: guidance for one checkpoint, a deterministic check of a building plan, a safe starting point for a common kind of app, and what the company has approved. With no overlay configured it answers from generic defaults and says `unknown_policy: true` on every answer; with a validated, unexpired [overlay](docs/spec/OVERLAY.md) it answers with the company's values and cites their review and expiry dates. Stdio for Claude Code, Codex, and Cursor; streamable HTTP bound to localhost for anything that needs a remote server, behind your own gateway.

```bash
python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.txt
CATPILOT_OVERLAY_FILE=/private/path/overlay.yaml python mcp-server/server.py
```

It is a reference implementation you run yourself: no authentication, no tenant isolation, no logging, no outbound calls. The tenant-scoped, authenticated version is the Catpilot platform. A lookup the model never made protects nothing; the tested-runtimes table records where a real lookup was observed. Details: [`mcp-server/README.md`](mcp-server/README.md).

### Hosted endpoint

A hosted instance of this same reference server is live at `https://mcp.catpilot.ai/mcp` (MCP streamable HTTP, stateless, JSON responses, no authentication). Health check: `https://mcp.catpilot.ai/health`. The root path `https://mcp.catpilot.ai/` returns a JSON data statement.

It serves generic defaults only. No company overlay is loaded, and none ever will be on this public endpoint: every answer carries `policy_status: "none"` and `unknown_policy: true`. It is advisory. Nothing it returns blocks an action.

Data handling: it receives only the topic, plan text, template kind, or category a client sends, stores nothing, and logs no request content. Responses carry `Cache-Control: no-store`.

In front of it: a per-client rate limit (60 requests per 10 seconds, then HTTP 429), a path allowlist, TLS end to end, and an origin that accepts connections only from the edge. What each protection does and how it was verified: [`deploy/README.md`](deploy/README.md).

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

Example configs for both: [`mcp-server/host-configs/`](mcp-server/host-configs/). Deployment steps and what the protections do: [`deploy/README.md`](deploy/README.md). ChatGPT and Claude.ai custom connectors: not yet verified.

## What's in the box

### `catpilot-security-core` (bundle `2026.09.15`; `cloud-cli-safety` at `1.0.3`, `local-cli-safety`, `secret-blocking`, and `supply-chain` at `1.0.2`, the other five at `1.0.1`)

Guidance for code generation, file edits, and shell commands. "Always-on" in older content described intended use; the bundle now says what it is: advice the agent reads, applied whenever the host has loaded it.

The bundle uses a baseline-references layout. `SKILL.md` is the baseline: the host reads it on every activation, and it holds a short entry per component with a link to that component's reference. Each reference file, under `references/<component>.md`, carries that component's full text: examples, remediation, and detection patterns. The host opens a reference only when it is acting in that component's area. The baseline is 396 lines, about 22 KB. Before this change the single file was 3,663 lines, about 134 KB, and a host read it in full on every activation. The `catpilot-safe-building` skill below stays one file.

| Component | Severity | Guidance covers |
|---|---|---|
| **secret-blocking** | critical | Hardcoded API keys, tokens, passwords, private keys, OAuth secrets, JWT signing keys, database URLs with embedded credentials. |
| **cloud-cli-safety** | critical | Partial-YAML resets (Azure, AWS, GCP), `terraform apply -auto-approve` against prod state, `kubectl delete namespace`, `helm upgrade` without diff, recursive S3 deletes — with a six-step review protocol for cloud changes. |
| **database-safety** | critical | Destructive database operations, unscoped row changes, prod migrations without dry-run, raw SQL string interpolation, schema changes without transactional safety, locking DDL on hot tables. |
| **local-cli-safety** | critical | `rm -rf` near `/` or `$HOME`, `find -delete` on broad scopes, `dd` to block devices, `chmod -R 777`, force-push to shared branches, mass-rewrite over agent/SSH/cloud-credential paths. |
| **docker-safety** | critical | `--privileged`, host network, `-v /:/host`, root user in container, secrets baked into image layers, `:latest` tags, untrusted base images, build-args used for sensitive values. |
| **secrets-management** | critical | `.env` committed, secrets in CI logs / URL query strings / error messages, long-lived static keys where short-lived/OIDC works, secret reuse across environments, missing rotation cadence. |
| **supply-chain** | high | `curl \| bash` installers, unpinned dependencies, GitHub Actions on `@main` or floating tags instead of SHAs, typosquats, post-install scripts, unvetted agent skills / MCP servers / IDE extensions. |
| **pii-and-test-data** | high | Real customer data in tests/fixtures/comments/docs, prod DB dumps to dev, full request-body logging, real-PII in LLM prompts and fine-tuning sets, demos against real customer accounts. |
| **language-baseline** | high | SQL injection (concatenation, f-strings), command injection (`shell=True`), XSS (`innerHTML`, `document.write`), path traversal, insecure deserialization (`pickle`, `yaml.load`, `Marshal`, `ObjectInputStream`), `eval`/`Function`/`setTimeout(string)`, TypeScript `as any` escape hatches, SSRF (unvalidated outbound URLs, cloud metadata at `169.254.169.254`). |

Components carry control references for **SOC 2, PCI-DSS, ISO 27001, NIST CSF, and OWASP Top 10**, with severity, suggested evidence patterns, and worked negative examples. These references do not establish compliance, current control applicability, or that a check ran. Review mappings against the relevant standard version and customer scope.

### `catpilot-safe-building` (bundle `2026.09.16`; `data-in-prompts`, `hosting-and-where-it-runs`, `sharing-and-publishing`, and `third-party-services` at `1.0.1`, the other four at `1.0.0`)

Plain language for a person with a deadline: one question at a time, the risk in one sentence, the safe alternative, and when to stop and ask a human. Each component mirrors checkpoints in Catpilot's Safe AI-assisted building course (Module 399), so the human course and the tool guidance are one artifact in two forms.

| Component | Severity | Course checkpoints | The assistant |
|---|---|---|---|
| **data-in-prompts** | high | 3.1, 3.2 | Asks what a file contains before real data goes into a prompt, upload, or test; steers to a made-up sample of the same shape, which stands in for the real file rather than sitting beside it; refuses card numbers, government IDs, health data, and credentials. |
| **access-and-identity** | high | 2.2, 3.3 | Defaults to the company's sign-in and the smallest named group; flags public links, shared passwords, and everyone-can-see settings. |
| **hosting-and-where-it-runs** | medium | 3.3, 5.1 | Asks where the finished thing will live; steers to approved hosting; flags personal accounts, free tiers, and unmanaged servers, including one already written into a deployment file, and does not deploy with it. |
| **sharing-and-publishing** | medium | 5.1, 5.2, 5.3 | Checks contents and audience before publishing, sharing, embedding, or sending; names an anyone-with-the-link setting already in a settings file before the link goes anywhere; starts with a private preview; keeps a way back. |
| **keys-and-credentials** | high | 3.2 | Never takes a password, key, or token into a prompt or generated code; uses the approved connection; treats anything pasted as exposed. |
| **third-party-services** | medium | 3.3 | Treats any new service, plugin, extension, or model endpoint as an approval question, says what it would receive, and keeps an unapproved service as a marked stub that sends nothing. |
| **untrusted-input** | medium | 2.2, 4.2 | Treats documents, emails, and user text as data, never instructions; explains prompt injection in plain words; tests blank, wrong, and hostile entries. |
| **when-to-ask-a-human** | medium | 1.4, 3.4 | Names the triggers for a security review and drafts the two-sentence message to send. |

The bundle also carries generic values for the things a company would specify: approved hosting, approved services, data classes, the default identity rule, review triggers, and who to ask. An [organization overlay](docs/spec/OVERLAY.md) replaces them in a private build. Control references on this skill are marked `mapping_review: pending` until a mapping review confirms them; describe SOC 2 references as "where applicable".

## Public baseline vs company overlay

The open-source skills are static and inspectable. They do not call Catpilot services or send telemetry. Review any skill before installing it; your AI host's own data handling and permissions still apply.

Everything company-specific lives in an **overlay**: a short, reviewed list of approved hosting, approved services, data classes, the identity rule, review triggers, and who to ask, with a reviewer date and an expiry date. The schema and validator are public; the values are private.

| Open source (this repository) | Catpilot Plus |
| --- | --- |
| Overlay schema and validator, local merge into a private bundle, generic defaults, the same eight checkpoints as a course for people | Authoring the overlay from the company's actual policies, named-reviewer approval, versioning, tenant-scoped serving to tools, per-person coaching in Slack and Teams, and the evidence trail that links a coached moment to a policy version |

Do not put private incidents, customer data, secrets, employee identifiers, or internal policy excerpts into this public baseline or a public fork. The bundler refuses to build if an overlay-shaped file is inside the tree, and a private build must be written outside it. A fork of a public repository is not private storage. Never turn an unreviewed event or document into an authoritative company rule automatically.

## Format

Skills use the [Agent Skills](https://agentskills.io/specification) format exactly. A skill is a directory containing a `SKILL.md` file with YAML frontmatter and a markdown body. Catpilot extensions (severity, control mappings, applies-to, mode, training-module links, evidence patterns) live in `catpilot.json` next to the shipped `SKILL.md`, and as string-valued `catpilot-*` keys in `metadata`, because the specification defines `metadata` as a map from string keys to string values; other runtimes ignore both. Details: [`docs/spec/SKILL_FORMAT.md`](docs/spec/SKILL_FORMAT.md).

A recognized file layout helps distribution; it does not guarantee that a host loads every instruction or reference. Follow the host's current installation guidance and record the activation and behavioral checks you actually perform.

## Versioning

- **Repository releases** are CalVer (`YYYY.MM.DD`), listed on the Releases page and in the badge above, with the details in [`CHANGELOG.md`](CHANGELOG.md).
- **Source skill components** inside a release are semver. `cloud-cli-safety` is at `1.0.3`; `local-cli-safety`, `secret-blocking`, and `supply-chain` are at `1.0.2`; `database-safety`, `docker-safety`, `language-baseline`, `pii-and-test-data`, and `secrets-management` are at `1.0.1`. Each bumped after gaining the `## Baseline` section the baseline-references layout requires. The bundle frontmatter records which versions of which components shipped.
- The core bundle is `2026.09.15`; the safe-building bundle is `2026.09.16`. A bundle's version changes only when its content does.

CalVer matches the cadence of a content repo: each release is a dated snapshot, and the date is the meaningful signal for users and auditors. Semver on individual components carries the breaking-change semantics that matter for downstream consumers.

## How it's built

`tools/bundle.py` turns the source components under `src/skills/` into the shipped bundles under `skills/` and the per-host artifacts under `dist/<release>/`, deterministically; CI fails on drift. The core tier renders a baseline plus per-component references; the safe-building tier renders one file plus its per-host targets. The directory tree and the aggregation rules: [`docs/REPOSITORY_LAYOUT.md`](docs/REPOSITORY_LAYOUT.md) and [`docs/spec/PACKAGING.md`](docs/spec/PACKAGING.md).

## Evaluation

Two fixture sets and one small smoke report. The commands below validate the **test inputs**, not agent behavior.

```bash
python3 tools/validate_evals.py                 # cases.json: core and companion development corpus
python3 tools/eval.py                           # evals/scenarios/: safe-building with/without fixtures
python3 -m unittest discover -s tests -v
```

`tools/eval.py --execute` runs each safe-building scenario twice against a named host CLI, without and with the skill, scores responses with readable keyword heuristics, and writes a report a human reviews before it is committed under `evals/reports/`. Hosts with no CLI, such as ChatGPT, are driven by hand: `--print-prompts` gives the exact prompts, `--import` scores the collected responses. `--overlay` turns on the checks that a company's approved values were cited. A two-scenario Codex smoke report is published under [`evals/reports/`](evals/reports/); a full with/without report is not yet. The [evaluation guide](evals/README.md) has the protocol and the honesty rules, and [`evals/HOST_VERIFICATION.md`](evals/HOST_VERIFICATION.md) has the per-host steps.

## Contributing

PRs welcome: propose a rule, fix a false positive, review a control mapping, add a scenario, or record a host you verified.

- Read [`docs/spec/SKILL_FORMAT.md`](./docs/spec/SKILL_FORMAT.md) for the frontmatter shape.
- Read [`docs/spec/PACKAGING.md`](./docs/spec/PACKAGING.md) for tier conventions, targets, and bundler aggregation rules.
- Run `python tools/bundle.py --target all` before pushing; the CI gate is strict.
- See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the rest; the issue forms and the pull request template carry the evidence checklist.

## Roadmap

What is shipped, what is deferred, and what this quarter is for: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

MIT. See [LICENSE](./LICENSE).

## Security

Found something dangerous? See [SECURITY.md](./SECURITY.md). For specific vulnerabilities, email **hi@catpilot.ai**.
