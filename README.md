# Catpilot Security Skills

<p align="left">
  <img src="assets/catpilot-logo.png" alt="Catpilot" width="100" style="vertical-align: middle;">
  <em>Paws before you push.</em>
</p>

![Release](https://img.shields.io/badge/release-2026.05.17-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Format](https://img.shields.io/badge/format-Anthropic%20Agent%20Skills-7B3FE4)

Security skills for AI coding agents — installable into Claude Code, Cursor, Codex, OpenClaw, Cline, Aider, GitHub Copilot, OpenCode, and 40+ other agents with one command. Also natively consumable by [Hermes Agent](https://hermes-agent.nousresearch.com) via its built-in skills system.

Born from a real incident where an agent wiped production environment variables with a partial YAML update. The rules in this repo come from incidents like that one — battle-tested, dogfooded daily at [Catpilot.ai](https://catpilot.ai), MIT-licensed.

This repository is the portable baseline. The Catpilot enterprise platform is separate: it collects security events from your tools, coaches the person closest to the issue, and can generate private team-specific guardrail or skill updates with approvals and audit evidence.

## Install

```bash
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core
```

That's it. Your coding agent now follows the security rules.

This uses the [skills.sh CLI](https://skills.sh) (`vercel-labs/skills`), which copies `catpilot-security-core/SKILL.md` into the right place for your agent (e.g. `~/.claude/skills/`, `.cursor/rules/`, `~/.codex/skills/`, …). 51+ runtimes supported.

## Public Baseline vs Team Memory

The open-source skill is intentionally static, inspectable, and safe to install in any repo. It does not call Catpilot services and it does not send telemetry.

Catpilot's enterprise platform adds the private memory loop:

1. Collect security events from tools such as TruffleHog, Semgrep, Snyk, Wiz, Okta, Defender, GitHub, and phishing platforms.
2. Coach the developer or employee in Slack while context is fresh.
3. Generate a scoped guardrail or team skill update from the approved lesson.
4. Ship the update through a fork, pull request, or managed deployment path.
5. Record evidence linking the event, coaching, approval, diff, and deployed skill version.

Do not put private incidents, customer data, secrets, employee identifiers, or internal policy excerpts into this public baseline. Keep those in private team skills generated and reviewed inside your organization.


## What's in the box

`catpilot-security-core` — the always-on baseline, **9 components** as of `2026.05.17`. Apply on every code generation, file write, and shell command:

| Component | Severity | Catches |
|---|---|---|
| **secret-blocking** | critical | Hardcoded API keys, tokens, passwords, private keys, OAuth secrets, JWT signing keys, database URLs with embedded credentials. |
| **cloud-cli-safety** | critical | Partial-YAML resets (Azure, AWS, GCP), `terraform apply -auto-approve` against prod state, `kubectl delete namespace`, `helm upgrade` without diff, recursive S3 deletes — every cloud command goes through the universal six-step protocol. |
| **database-safety** | critical | `DROP`/`TRUNCATE` without `WHERE`, prod migrations without dry-run, raw SQL string interpolation, schema changes without transactional safety, locking DDL on hot tables. |
| **local-cli-safety** | critical | `rm -rf` near `/` or `$HOME`, `find -delete` on broad scopes, `dd` to block devices, `chmod -R 777`, force-push to shared branches, mass-rewrite over agent/SSH/cloud-credential paths. |
| **docker-safety** | critical | `--privileged`, host network, `-v /:/host`, root user in container, secrets baked into image layers, `:latest` tags, untrusted base images, build-args used for sensitive values. |
| **secrets-management** | critical | `.env` committed, secrets in CI logs / URL query strings / error messages, long-lived static keys where short-lived/OIDC works, secret reuse across environments, missing rotation cadence. |
| **supply-chain** | high | `curl \| bash` installers, unpinned dependencies, GitHub Actions on `@main` or floating tags instead of SHAs, typosquats, post-install scripts, unvetted agent skills / MCP servers / IDE extensions. |
| **pii-and-test-data** | high | Real customer data in tests/fixtures/comments/docs, prod DB dumps to dev, full request-body logging, real-PII in LLM prompts and fine-tuning sets, demos against real customer accounts. |
| **language-baseline** | high | SQL injection (concatenation, f-strings), command injection (`shell=True`), XSS (`innerHTML`, `document.write`), path traversal, insecure deserialization (`pickle`, `yaml.load`, `Marshal`, `ObjectInputStream`), `eval`/`Function`/`setTimeout(string)`, TypeScript `as any` escape hatches, SSRF (unvalidated outbound URLs, cloud metadata at `169.254.169.254`). |

Each component carries control mappings for **SOC 2, PCI-DSS, ISO 27001, NIST CSF, and OWASP Top 10**, with severity, evidence patterns, and worked negative examples (real incidents, masked).

## Format

Skills use the [Anthropic Agent Skills](https://agentskills.io/specification) format exactly. A skill is a directory containing a `SKILL.md` file with YAML frontmatter and a markdown body. Catpilot extensions (severity, control mappings, applies-to, evidence patterns) live under `metadata.catpilot.*`, which other runtimes ignore.

This means: anywhere `npx skills add` works, Catpilot skills work. Anywhere it doesn't, you can copy the directory in by hand and your agent will read it.

## Other ways to install

```bash
# Install globally so every project picks it up
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core --global

# Pick a specific agent (skills.sh defaults to detecting installed agents)
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core --agent cursor

# List what's available without installing
npx skills add catpilotai/catpilot-ai-guardrails --list

# Or skip the CLI entirely — just copy the skill in by hand
git clone https://github.com/catpilotai/catpilot-ai-guardrails.git
cp -r catpilot-ai-guardrails/skills/catpilot-security-core ~/.claude/skills/
```

### Hermes Agent

[Hermes Agent](https://hermes-agent.nousresearch.com) (Nous Research) has its own native skills system that reads from skills.sh. From inside Hermes:

```
/skills install catpilotai/catpilot-ai-guardrails/catpilot-security-core
```

## Versioning

- **Releases** are CalVer (`YYYY.MM.DD`). Current release: **`2026.05.17`**.
- **Source skill components** inside a release are semver — each component currently at `1.0.0`. The release frontmatter records which versions of which components shipped.

CalVer matches the cadence of a content repo: each release is a dated snapshot, and the date is the meaningful signal for users and auditors. Semver on individual components carries the breaking-change semantics that matter for downstream consumers.

## How it's built

```
src/skills/             # source components (semver, edited by hand)
  core/
    bundle.toml         # tier config: name, version, description
    secret-blocking/
      SKILL.md          # one component
    cloud-cli-safety/
      SKILL.md
skills/                 # shipped bundles (CalVer, generated)
  catpilot-security-core/
    SKILL.md            # what `npx skills add` installs
tools/
  bundle.py             # deterministic bundler
docs/spec/              # format spec, packaging spec, V2 postmortem
```

`tools/bundle.py` reads source components, aggregates frontmatter (severity = max, control mappings = sorted union, `applies_to` = union with `any` collapse), concatenates bodies in lexicographic order, and writes the shipped bundle. CI runs `python tools/bundle.py --check` on every PR — if `skills/` drifts from `src/skills/`, the build fails with a unified diff.

## Contributing

PRs welcome — propose a new rule, fix a false positive, add a control mapping, port a v2.x rule into a source skill.

- Read [`docs/spec/SKILL_FORMAT.md`](./docs/spec/SKILL_FORMAT.md) for the frontmatter shape.
- Read [`docs/spec/PACKAGING.md`](./docs/spec/PACKAGING.md) for tier conventions and bundler aggregation rules.
- Run `python tools/bundle.py` before pushing; the CI gate is strict.
- See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the rest.

## Roadmap

With `2026.05.17`, the core bundle is **feature-complete** (9 components covering the v2.x rule surface). Next workstreams:

| Tier | Bundle | Status |
|---|---|---|
| Core (always-on) | `catpilot-security-core` | **shipped — 9 components (`2026.05.17`)** |
| Framework extensions | `catpilot-django-security`, `catpilot-fastapi-security`, `catpilot-rails-security`, `catpilot-express-security`, `catpilot-nextjs-security`, `catpilot-springboot-security`, `catpilot-docker-security` | planned (content exists in `frameworks/`, migrating into source skills) |
| Advanced (multi-agent / opt-in) | `catpilot-security-advanced` | planned |

Validator (`tools/validate-skill.py`) and framework-detection helper (`tools/recommend.py`) follow. HIPAA and GDPR control mappings land in a later release.

## License

MIT. See [LICENSE](./LICENSE).

## Security

Found something dangerous? See [SECURITY.md](./SECURITY.md). For specific vulnerabilities, email **hi@catpilot.ai**.
