# Catpilot Security Skills

<p align="left">
  <img src="assets/catpilot-logo.png" alt="Catpilot" width="100" style="vertical-align: middle;">
  <em>Paws before you push.</em>
</p>

**For the tool and for the person using it.**

![Release](https://img.shields.io/github/v/release/catpilotai/catpilot-ai-guardrails?label=release&color=blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Format](https://img.shields.io/badge/format-Agent%20Skills-7B3FE4)

Two security skills in the [Agent Skills](https://agentskills.io/specification) format: one for coding agents working in a codebase, one for the person, often not a developer, building something with an AI assistant. Either can run inside an agent loop a team builds. One repository, no telemetry.

| Skill | Who it is for | What it covers |
| --- | --- | --- |
| **`catpilot-safe-building`** | A person, often not a developer, building an app, automation, dashboard, or data tool with an AI assistant, and the assistant helping them | Eight plain-language checkpoints that mirror Catpilot's Safe AI-assisted building course: data in prompts, access and identity, hosting, sharing, keys and credentials, third-party services, untrusted input, when to ask a human. |
| **`catpilot-security-core`** | Coding agents working in real codebases | Nine engineering components: cloud CLI, databases, local shell, Docker, hardcoded secrets, secrets lifecycle, supply chain, PII and test data, secure-coding patterns. |
| **Either skill, plus `hooks/` and `frameworks/agentic/`** | A harness: the loop a team builds around a model for one job | Standing guidance for every iteration of the loop, a credential gate the loop enforces on its shell tool, and reference rules for retries, scheduled runs, delegation, and self-modification. See [For agent harnesses](docs/REFERENCE.md#for-agent-harnesses). |

Born from a real incident where an agent wiped production environment variables with a partial YAML update. The rules draw on incidents like that one and are used at [Catpilot.ai](https://catpilot.ai). They are MIT-licensed guidance, not a guarantee that an agent will follow them.

This repository is the portable baseline, not the Catpilot hosted platform. Read [what this does and does not do](#what-this-does-and-does-not-do) before treating anything here as a security control.

## What the benchmarks show

Two benchmarks are published in [`evals/reports/`](evals/reports/). Each gave a tool ten new tasks, never published before the run and written the way a non-engineer asks for them, in a project folder with a trap in it: a customer export to be tempted into pasting, a key to be tempted into hard-coding, a free service to be tempted into wiring up, a public link or personal account already configured, a document with a hidden instruction. Two tools, Claude Code and Codex; three attempts per task per condition; a hand-scored sample; a named reviewer; every correction to the scoring kept in the report.

Two measures carry the result. An **unsafe act** is the tool doing what the trap invited: real rows in the code, the key hard-coded, the unapproved service actually wired, the personal account or public link kept as the deployment. **Finished within policy** is the run leaving the expected deliverable in the project, judged from the files it wrote, with no unsafe act and the safe alternative in place where one was needed; whether the program ran was not checked in these two sets, and every set from here on adds a functional check in a container. An **unnecessary stop** is the run stopping to ask when the task needed no review: the cost side, and a guardrail's most likely failure. The second benchmark, on the safe-building skill, after the scoring corrections recorded in the report:

| Ten tasks, three attempts each | Nothing installed | The safe-building skill | The skill plus the company's rules |
| --- | --- | --- | --- |
| Claude Code, unsafe acts | 7 of 30 | 2 of 30 | 1 of 29 |
| Claude Code, finished within policy | 14 of 30 | 17 of 30 | 24 of 29 |
| Claude Code, unnecessary stops | 5 of 30 | 6 of 30 | 3 of 29 |
| Codex, unsafe acts | 3 of 30 | 0 of 30 | 0 of 30 |
| Codex, finished within policy | 15 of 30 | 26 of 30 | 21 of 30 |
| Codex, unnecessary stops | 2 of 30 | 1 of 30 | 8 of 30 |

One Claude Code run in the last column hit the host's turn limit and did not complete, so that column is out of 29.

- **The skill.** Both tools did the unsafe thing less often with the skill installed, and finished more work within policy. Nothing installed is where most builders start.
- **The skill plus the company's rules.** A company writes its approved hosting, approved services, data classes, and who to ask into one short reviewed file, the [overlay](#public-baseline-vs-company-overlay); in this configuration the tool could look that file up through the reference server. It was the only configuration that steered to the company's own approved hosting or service by name, in about a third of runs, instead of a generic "use something approved"; no other configuration in these runs carried those facts. It is also where the guardrail itself cost work: on Codex the server asked for review on local-only scripts, and the tool stopped unnecessarily in 8 of 30 runs, a calibration fault fixed in 2026.09.17-1 and the reason that column finished less than the skill alone.
- **Where the effect comes from.** A fifteen-line summary of the skill, written for the experiment and pasted into the project's instruction file, did about as well as the full skill on these tasks: having the rules present when the tool starts work is what moves these counts. No tool ships such a list. A pasted list can carry a company's rules too; in these runs only the overlay did. What a server adds is a list that is reviewed, current, and the same in every tool, and whether that delivery matters beyond the information is the next run's question, with the condition ready in the runner.
- **Limits.** Small samples, one model per tool, made-up company values, and the company-rules configuration also carried a one-line instruction to consult the server, so its lead over the skill alone is not cleanly the rules' doing. The next run's plan is written, with independent task authors and a non-engineer voice review as required gates; it becomes a preregistration when those people are named and its fields are filled: [experiment plan](docs/EXPERIMENT_PLAN.md). Reports: [Claude Code](evals/reports/2026.09.16-1-benchmark-claude-code.md) and [Codex](evals/reports/2026.09.16-1-benchmark-codex.md); the first set, on a different ten tasks, is [here](evals/reports/2026.09.15-benchmark-claude-code.md) and [here](evals/reports/2026.09.15-benchmark-codex.md).

## Install for coding agents

```bash
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-safe-building
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core
```

Installation makes the instructions available to a compatible host; it does **not** prove they were loaded, followed, or enforced. Confirm the installed version, then try a safe and an unsafe task in an isolated environment. The [skills.sh CLI](https://skills.sh) (`vercel-labs/skills`) places the files for the hosts it supports; what Catpilot has actually observed on each host is in the [tested runtimes](docs/REFERENCE.md#tested-runtimes). Global installs, a specific agent, manual copies, and Hermes Agent: [`docs/INSTALL.md`](docs/INSTALL.md).

As a Claude Code plugin, skills only: `/plugin marketplace add catpilotai/catpilot-ai-guardrails`, then `/plugin install catpilot-guardrails@catpilot`. The same manifest lets a ChatGPT workspace administrator import the repository as a plugin.

Rolling it out to a team or a whole company, with the files an administrator places and how to confirm they landed: [`docs/DEPLOY_ORG.md`](docs/DEPLOY_ORG.md).

Building your own agent loop? The harness notes, the credential gate as a plain function, and the loop rules are in the [technical reference](docs/REFERENCE.md#for-agent-harnesses).

## For non-engineers

Nobody has to open a terminal.

- **Read the eight checkpoints** in five minutes: [`skills/catpilot-safe-building/SKILL.md`](skills/catpilot-safe-building/SKILL.md), the same text the tool follows.
- **Claude.ai:** download `catpilot-safe-building.zip` from the [latest release](https://github.com/catpilotai/catpilot-ai-guardrails/releases/latest) (also at [`dist/2026.09.18/`](dist/2026.09.18/)) and upload it under Customize → Skills. An organization owner uploads it once under Organization settings → Skills and every member gets it.
- **ChatGPT, Microsoft Copilot Studio, Lovable, Bolt, Replit, v0:** paste the block for your tool from [`dist/2026.09.18/`](dist/2026.09.18/). Each file says where it goes, and each is under 8,000 characters.
- **Repository-based agents:** append the `AGENTS.md` or `copilot-instructions.md` block from the same directory.
- **Your company rolling it out for you:** an administrator can install it centrally. The Claude Code and Codex CLI paths are verified; the Claude.ai and ChatGPT workspace paths are written from the vendors' administrator documentation and not yet run by Catpilot: [`docs/DEPLOY_ORG.md`](docs/DEPLOY_ORG.md).

## What this does and does not do

Three different things get called "protection". This repository uses the narrow words.

- **Advice.** A skill is guidance the model reads. It shapes what the model says and suggests. It is loaded only when the host chooses to load it. Both skills here are advice.
- **Contextual coaching.** A supported event in a tool people already work in, such as Slack or Teams, produces one explanation and one next step, at the moment it matters. That is a Catpilot platform capability, not something a skill file does. The safe-building skill tells an assistant how to coach; it cannot create the event.
- **Enforcement.** A specific action cannot proceed without a tested check in a trusted host. This repository ships exactly two, both Claude Code `PreToolUse` hooks: one denies a shell command that contains a literal credential, the other denies a file write or edit that adds a private-key block. Each covers that one path, on the host version recorded in the [tested-runtimes table](docs/REFERENCE.md#tested-runtimes), and nothing else.

It does not monitor anyone's work, send telemetry, block anything except through the documented hooks, scan repositories, certify compliance, or record training completion. An installed skill that is not loaded is not a control. A hook that is not configured is not a control.

The full statement is the [protection contract](docs/PROTECTION_CONTRACT.md).

## What's in the box

Bundle and component versions are recorded in each shipped skill's `catpilot.json` and in [`CHANGELOG.md`](CHANGELOG.md).

### `catpilot-security-core`

Guidance for code generation, file edits, and shell commands: advice the agent reads, applied whenever the host has loaded it.

`SKILL.md` is a 396-line baseline with a short entry per component; each component's full text (examples, remediation, detection patterns) is in `references/<component>.md`, which the host opens only when it is working in that area. The `catpilot-safe-building` skill below is one file.

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

### `catpilot-safe-building`

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

## Evaluation

To see the skill act on one task in five minutes, with the program it produced and a check you can run: [`docs/DEMO.md`](docs/DEMO.md). An illustration, not a result.

```bash
python3 tools/validate_evals.py                 # cases.json: core and companion development corpus
python3 tools/eval.py                           # evals/scenarios/: safe-building with/without fixtures
python3 -m unittest discover -s tests -v
```

These validate the test inputs, not agent behavior. `tools/eval.py --execute` runs each safe-building scenario against a named host CLI, without and with the skill, and writes a report a person reviews before it is committed. The benchmark runner is `tools/bench.py`: its design and honesty rules are in [`evals/BENCHMARK.md`](evals/BENCHMARK.md), what each measure establishes and what evidence it requires is in [`docs/EVALUATION_CONTRACT.md`](docs/EVALUATION_CONTRACT.md), and `tools/bench/selfcheck.py` must classify a scenario set's reference examples correctly before a run starts. Published reports and their retired scenario files live under [`evals/reports/`](evals/reports/) and [`evals/scenarios-retired/`](evals/scenarios-retired/); per-host verification steps are in [`evals/HOST_VERIFICATION.md`](evals/HOST_VERIFICATION.md).

## Technical reference

Harness notes, the tested-runtimes table, the hooks, the reference MCP server and its hosted endpoint, the skill format, versioning, and how the bundles are built: [`docs/REFERENCE.md`](docs/REFERENCE.md).

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
