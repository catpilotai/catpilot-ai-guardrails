# Catpilot Security Skills

<p align="left">
  <img src="assets/catpilot-logo.png" alt="Catpilot" width="100" style="vertical-align: middle;">
  <em>Paws before you push.</em>
</p>

**For the tool and for the person using it.**

![Release](https://img.shields.io/badge/release-2026.09.13-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Format](https://img.shields.io/badge/format-Agent%20Skills-7B3FE4)

Security skills for AI coding agents, for people building apps with AI assistants, and for the domain-specific agent harnesses teams build around both, in the [Agent Skills](https://agentskills.io/specification) format. Two skills, one repository, no telemetry.

| Skill | Who it is for | What it covers |
| --- | --- | --- |
| **`catpilot-security-core`** | Coding agents working in real codebases | Nine engineering components: cloud CLI, databases, local shell, Docker, hardcoded secrets, secrets lifecycle, supply chain, PII and test data, secure-coding patterns. |
| **`catpilot-safe-building`** | A person, often not a developer, building an app, automation, dashboard, or data tool with an AI assistant, and the assistant helping them | Eight plain-language checkpoints that mirror Catpilot's Safe AI-assisted building course: data in prompts, access and identity, hosting, sharing, keys and credentials, third-party services, untrusted input, when to ask a human. |
| **Either skill, plus `hooks/` and `frameworks/agentic/`** | A harness: the loop a team builds around a model for one job | Standing guidance for every iteration of the loop, a credential gate the loop enforces on its shell tool, and reference rules for retries, scheduled runs, delegation, and self-modification. See [For agent harnesses](#for-agent-harnesses). |

Born from a real incident where an agent wiped production environment variables with a partial YAML update. The rules draw on incidents like that one and are used at [Catpilot.ai](https://catpilot.ai). They are MIT-licensed guidance, not a guarantee that an agent will follow them.

This repository is the portable baseline, not the Catpilot hosted platform. Read [what this does and does not do](#what-this-does-and-does-not-do) before treating anything here as a security control.

## Install for coding agents

```bash
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-safe-building
```

Installation makes the instructions available to a compatible host. It does **not** prove they were loaded, followed, or enforced. Confirm the installed version, then test representative safe and unsafe tasks in an isolated environment. The [skills.sh CLI](https://skills.sh) (`vercel-labs/skills`) handles placement for the hosts it supports; installer compatibility is separate from anything Catpilot has verified. See [Tested runtimes](#tested-runtimes).

## For non-engineers

Nobody has to open a terminal.

- **Read the eight checkpoints** in five minutes: [`dist/2026.09.13/web/safe-ai-building.html`](dist/2026.09.13/web/safe-ai-building.html), the source for `catpilot.ai/safe-ai-building`.
- **Claude.ai:** upload [`dist/2026.09.13/catpilot-safe-building.zip`](dist/2026.09.13/catpilot-safe-building.zip) under Customize → Skills. An organization owner uploads it once under Organization settings → Skills and every member gets it.
- **ChatGPT, Microsoft Copilot Studio, Lovable, Bolt, Replit, v0:** paste the block for your tool from [`dist/2026.09.13/`](dist/2026.09.13/). Each file says where it goes, and each is under 8,000 characters.
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
- **Enforcement.** A specific action cannot proceed without a tested check in a trusted host. This repository ships exactly one: a Claude Code hook on the Bash tool that denies a shell command containing a literal credential. It covers that path, on the host version in the table below, and nothing else.

It does not monitor anyone's work, send telemetry, block anything except through the documented hook, scan repositories, certify compliance, or record training completion. An installed skill that is not loaded is not a control. A hook that is not configured is not a control.

The full statement is the [protection contract](docs/PROTECTION_CONTRACT.md).

## Tested runtimes

Installable via skills.sh into 50+ runtimes; verified only on the runtimes and dates listed here.

| Runtime | Skill loads | Coaching (MCP) | Enforcement (hook) | Last verified | Release |
| --- | --- | --- | --- | --- | --- |
| Claude Code 2.1.241 | yes: a project `.claude/skills/` install is listed in the session init | yes: a `list_approved` lookup over stdio, with the server connected in the session init, recorded 2026-09-14; the hosted endpoint (`mcp.catpilot.ai`) verified the same day over the `http` transport, server connected, all four tools listed, `list_approved` returned through the edge | yes, two `PreToolUse` hooks: `Bash` (a command with AWS's example key was denied, the control run without the hook executed it) and `Write`/`Edit`/`MultiEdit`/`NotebookEdit` (a `Write` adding a synthetic private-key block was denied on 2026-09-14, the control run without the hook wrote the file) | 2026-09-14 | 2026.09.13 |
| Cursor | not verified | not verified | not tested | | |
| Codex CLI 0.154.0 | yes, with a caveat: a project `.agents/skills/` install; on a data scenario the model named the skill and input usage rose from about 17k to over 90k tokens; the host emits no explicit load event and reads the skill on demand, not on every task | yes: a completed `mcp_tool_call` to `list_approved` over stdio, recorded 2026-09-14; the hosted endpoint (`mcp.catpilot.ai`) verified the same day via the `url` MCP server config, `mcp_tool_call` completed | none | 2026-09-14 | 2026.09.13 |
| Claude.ai (individual upload or organization provisioning) | not verified | hosted endpoint at `mcp.catpilot.ai` exists; custom connector not yet verified | none, advisory only | | |
| ChatGPT (project or GPT instructions) | n/a, pasted text; manual protocol in [`evals/HOST_VERIFICATION.md`](evals/HOST_VERIFICATION.md), not yet run | hosted endpoint at `mcp.catpilot.ai` exists; custom connector not yet verified | none | | |
| Microsoft Copilot Studio | n/a, pasted text | not verified | none | | |
| Lovable, Bolt, Replit, v0 | n/a, pasted text | not applicable | none | | |
| Everything else reachable through skills.sh | not verified | not verified | none | | |
| Your own harness | depends on how the loop loads it; not verified by Catpilot | call the server from the loop; not verified by Catpilot | the credential gate on the shell path you route through it; you test it in your loop | | |

"Skill loads" means a host signal showed the skill available in a recorded session, not the model saying it read it. "Enforcement" means a recorded tool-result trace showed the host applying the hook's deny decision, with a control run that executed the same command without the hook. The exact commands and observations are in [`evals/reports/`](evals/reports/). A row without a date is a row without evidence. "Coaching (MCP)" means a recorded tool call from that host to the reference server, not that the host uses it in daily work.

## The one hook

[`hooks/claude-code/pretooluse-secrets.py`](hooks/claude-code/pretooluse-secrets.py) is a Claude Code `PreToolUse` hook on the `Bash` tool. It scans the proposed command for the credential patterns documented in the secret-blocking component and returns a deny decision with a plain-language reason, without echoing the value. It never returns allow, and malformed input fails closed. It does not cover file writes, prompts, other tools, other hosts, or commands a person types themselves. The escape hatch for a false positive is to reference the value from an environment variable instead, or to run the command yourself; there is no bypass flag. A second hook, [`hooks/claude-code/pretooluse-write-private-key.py`](hooks/claude-code/pretooluse-write-private-key.py), covers the `Write`, `Edit`, `MultiEdit`, and `NotebookEdit` tools instead: it denies file content containing a PEM private-key header with the same never-allow, fail-closed behavior, and it does not cover shell commands, file reads, or other hosts. Install steps and exact coverage for both: [`hooks/README.md`](hooks/README.md).

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

Protections in front of it (Cloudflare, scoped to this one hostname): a rate limit of 60 requests per 10 seconds per client IP per Cloudflare location, then HTTP 429 for 10 seconds; only `/mcp`, `/health`, and `/` are allowed, everything else gets HTTP 403 at the edge; TLS is enforced end to end. The origin only accepts connections from Cloudflare's published IP ranges; a direct request to it returns HTTP 403.

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

### `catpilot-security-core` (bundle `2026.09.14`; `cloud-cli-safety` at `1.0.1`, the other eight at `1.0.0`)

Guidance for code generation, file edits, and shell commands. "Always-on" in older content described intended use; the bundle now says what it is: advice the agent reads, applied whenever the host has loaded it.

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

### `catpilot-safe-building` (bundle `2026.09.13`, eight components at `1.0.0`)

Plain language for a person with a deadline: one question at a time, the risk in one sentence, the safe alternative, and when to stop and ask a human. Each component mirrors checkpoints in Catpilot's Safe AI-assisted building course (Module 399), so the human course and the tool guidance are one artifact in two forms.

| Component | Severity | Course checkpoints | The assistant |
|---|---|---|---|
| **data-in-prompts** | high | 3.1, 3.2 | Asks what a file contains before real data goes into a prompt, upload, or test; steers to a made-up sample of the same shape; refuses card numbers, government IDs, health data, and credentials. |
| **access-and-identity** | high | 2.2, 3.3 | Defaults to the company's sign-in and the smallest named group; flags public links, shared passwords, and everyone-can-see settings. |
| **hosting-and-where-it-runs** | medium | 3.3, 5.1 | Asks where the finished thing will live; steers to approved hosting; flags personal accounts, free tiers, and unmanaged servers. |
| **sharing-and-publishing** | medium | 5.1, 5.2, 5.3 | Checks contents and audience before publishing, sharing, embedding, or sending; starts with a private preview; keeps a way back. |
| **keys-and-credentials** | high | 3.2 | Never takes a password, key, or token into a prompt or generated code; uses the approved connection; treats anything pasted as exposed. |
| **third-party-services** | medium | 3.3 | Treats any new service, plugin, extension, or model endpoint as an approval question and says what it would receive. |
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

Skills use the [Agent Skills](https://agentskills.io/specification) format exactly. A skill is a directory containing a `SKILL.md` file with YAML frontmatter and a markdown body. Catpilot extensions (severity, control mappings, applies-to, mode, training-module links, evidence patterns) live under `metadata.catpilot.*`, which other runtimes ignore. Details: [`docs/spec/SKILL_FORMAT.md`](docs/spec/SKILL_FORMAT.md).

A recognized file layout helps distribution; it does not guarantee that a host loads every instruction or reference. Follow the host's current installation guidance and record the activation and behavioral checks you actually perform.

## Other ways to install

```bash
# Install globally so every project picks it up
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core --global

# Pick a specific agent (skills.sh defaults to detecting installed agents)
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-safe-building --agent cursor

# List what's available without installing
npx skills add catpilotai/catpilot-ai-guardrails --list

# Or skip the CLI entirely: copy the skill in by hand
git clone https://github.com/catpilotai/catpilot-ai-guardrails.git
cp -r catpilot-ai-guardrails/skills/catpilot-security-core ~/.claude/skills/
cp -r catpilot-ai-guardrails/skills/catpilot-safe-building ~/.claude/skills/
```

### Hermes Agent

[Hermes Agent](https://hermes-agent.nousresearch.com) (Nous Research) has its own native skills system that reads from skills.sh. From inside Hermes:

```
/skills install catpilotai/catpilot-ai-guardrails/catpilot-security-core
```

## Versioning

- **Repository releases** are CalVer (`YYYY.MM.DD`). Current release: **`2026.09.13`**.
- **Source skill components** inside a release are semver. `cloud-cli-safety` is at `1.0.1` after the Azure environment-variable correction; every other component is at `1.0.0`. The bundle frontmatter records which versions of which components shipped.
- The core bundle is `2026.09.14`; the safe-building bundle is `2026.09.13`. The core bundle's earlier `2026.09.13` step changed only its description, preamble, and a new `mode: advisory` field.
- The `2026.09.11` release added the evaluation foundation and protection contract. The `2026.06.25` release added framework-level agentic/OpenClaw guardrails under `frameworks/`.

CalVer matches the cadence of a content repo: each release is a dated snapshot, and the date is the meaningful signal for users and auditors. Semver on individual components carries the breaking-change semantics that matter for downstream consumers.

## How it's built

```
src/skills/                 # source components (semver, edited by hand)
  core/
    bundle.toml             # tier config: name, version, description, mode
    secret-blocking/SKILL.md
    ...                     # nine components
  safe-building/
    bundle.toml             # plus [bundle.slots] defaults and [bundle.targets]
    data-in-prompts/SKILL.md
    ...                     # eight components, plain language, {{slot}} markers
skills/                     # shipped bundles (CalVer, generated)
  catpilot-security-core/SKILL.md
  catpilot-safe-building/SKILL.md
dist/2026.09.13/            # per-host artifacts (generated): zip, paste blocks, web page
hooks/claude-code/          # the one hook, its example settings, and its README
hooks/harness/              # the same check as a function for your own agent loop
mcp-server/                 # reference MCP server: four read-only tools over the checkpoints and an overlay
tools/
  bundle.py                 # deterministic bundler: --target all, --overlay, --check
  targets.py                # per-host renderers
  validate_skill.py         # skill directory validator
  validate_overlay.py       # organization overlay validator
  validate_evals.py         # cases.json validator
  eval.py                   # safe-building with/without runner
docs/spec/                  # format, packaging, overlay specs; V2 postmortem
evals/                      # cases.json, scenarios/, reports/
```

`tools/bundle.py` reads source components, aggregates frontmatter (severity = max, control mappings = sorted union, `applies_to` = union with `any` collapse), fills `{{slot}}` markers from the tier's defaults, concatenates bodies in lexicographic order, and writes the shipped bundle. `--target all` renders the per-host artifacts into `dist/<release>/`. CI runs `python tools/bundle.py --check` on PRs affecting bundle inputs or outputs; if `skills/` or `dist/` drifts from `src/skills/`, the build fails with a unified diff.

## Evaluation

Two fixture sets, no published behavioral result yet. Commands validate the **test inputs**, not agent behavior.

```bash
python3 tools/validate_evals.py                 # cases.json: core and companion development corpus
python3 tools/eval.py                           # evals/scenarios/: safe-building with/without fixtures
python3 -m unittest discover -s tests -v
```

`tools/eval.py --execute` runs each safe-building scenario twice against a named host CLI, without and with the skill, scores responses with readable keyword heuristics, and writes a report a human reviews before it is committed under `evals/reports/`. Hosts with no CLI, such as ChatGPT, are driven by hand: `--print-prompts` gives the exact prompts, `--import` scores the collected responses. `--overlay` turns on the checks that a company's approved values were cited. The first report is scheduled with the MCP release. The [evaluation guide](evals/README.md) has the protocol and the honesty rules, and [`evals/HOST_VERIFICATION.md`](evals/HOST_VERIFICATION.md) has the per-host steps.

## Contributing

PRs welcome: propose a rule, fix a false positive, review a control mapping, add a scenario, or record a host you verified.

- Read [`docs/spec/SKILL_FORMAT.md`](./docs/spec/SKILL_FORMAT.md) for the frontmatter shape.
- Read [`docs/spec/PACKAGING.md`](./docs/spec/PACKAGING.md) for tier conventions, targets, and bundler aggregation rules.
- Run `python tools/bundle.py --target all` before pushing; the CI gate is strict.
- See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the rest.

## Roadmap

The core content baseline is shipped and maintained. This quarter's work is the safe-building wedge and honest verification, not more frameworks.

| Item | Status |
|---|---|
| `catpilot-security-core` | shipped, nine components; maintained; no new components this quarter |
| `catpilot-safe-building` | shipped in `2026.09.13` |
| Per-host targets and the safe-building web page source | shipped in `2026.09.13`; the live `catpilot.ai/safe-ai-building` page ships with the site pass |
| README contract, tested-runtimes table, one Claude Code hook | shipped in `2026.09.13` |
| Organization-overlay schema, validator, private builds | shipped in `2026.09.13` |
| Safe-building evaluation fixtures and with/without runner | shipped; first report with the MCP release |
| Reference MCP server (`get_guidance`, `check_plan`, `get_template`, `list_approved`) | shipped as a self-hosted reference in `mcp-server/`; lookups verified from Claude Code and Codex on 2026-09-14; tenant-scoped, authenticated serving is the platform's work, sequenced with the design partnership |
| Framework extensions (`catpilot-<framework>-security`) | content kept in `frameworks/`; no bundle promised this quarter |
| Agentic loop guidance for harnesses | reference text in `frameworks/agentic/` and the harness gate in `hooks/harness/`; packaging as a bundle deferred |
| `catpilot-security-advanced` | deferred |
| `tools/recommend.py` | deferred |
| HIPAA and GDPR mappings | deferred |

## License

MIT. See [LICENSE](./LICENSE).

## Security

Found something dangerous? See [SECURITY.md](./SECURITY.md). For specific vulnerabilities, email **hi@catpilot.ai**.
