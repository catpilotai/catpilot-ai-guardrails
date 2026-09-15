# Changelog

All notable changes to this project will be documented in this file.

Releases from `2026.05.06` forward use [CalVer](https://calver.org) (`YYYY.MM.DD`). Source-skill components inside each release continue to use [SemVer](https://semver.org).

## [Unreleased]

### Fixed

- **Secret hook: unquoted and JSON-property credential forms.** `hooks/claude-code/pretooluse-secrets.py` denied `mysql -u root --password="hunter22"` but not the unquoted `mysql -u root --password=hunter22`. It now also covers the unquoted `--password=value` flag, mysql/mysqldump/mariadb's attached `-pvalue`, `PGPASSWORD=value`, and a quoted-JSON credential property (`"api_key"`, `"password"`, `"token"`, `"secret"`) — each still allowing `$VAR`/`${VAR}` references, short values, and obvious placeholders (`REPLACE_ME`, `SAMPLE-KEY`, and similar) exactly as the existing quoted patterns do, and still never echoing the matched value. `--password="$DB_PASSWORD"` remains allowed. `hooks/harness/secret_gate.py` picks this up automatically since it loads the same file. Tests in `tests/test_hook.py`; coverage description updated in `hooks/README.md`.
- **MCP server: an expired overlay's values leaked into "approved".** `list_approved` (`mcp-server/catpilot_guardrails_mcp/tools.py`) special-cased `policy.status == "expired"` to still read from the overlay, so an expired company overlay's hosting/services/data-class/contact values were returned under the approved fields with only a note appended to a `source` string most callers don't parse against. `get_guidance`, `check_plan`, and `get_template` already excluded expired and not-yet-valid overlays correctly. `list_approved` now does the same: an expired or not-yet-valid overlay contributes no values anywhere, and the response is identical to having no overlay configured. `policy_status` still reports `"expired"` and `policy_note` still names the expiry date and the overlay's owner to ask, via the existing `_provenance` fields. Tests in `tests/test_mcp_tools.py`.
- **`check_plan` overlay matching is structural.** Company overlay items used to match only when their first three words appeared verbatim, and hosting rules only against the `hosting` argument, so "Host a team timer on an unmanaged virtual machine" and "Send proprietary source code to an unapproved AI service" returned no risks against an overlay that lists "Unmanaged virtual machines" and "Any new software service". Both sides are now normalized (lowercase, punctuation and parentheticals dropped, simple plurals singularized, stop words such as any/the/a removed); an item fires when the content words of one of its comma-, "and"-, or "or"-separated alternatives appear in the plan in any order, or when a short per-category synonym list (services: unapproved, new, third-party, external, outside, unknown; hosting: personal, free-tier, unmanaged, own server, laptop) appears with one of the item's own words. Matching covers the description and `data_types` as well as `hosting` and `audience`. Every risk now carries `rule` (the exact overlay item text, or `null` for a generic checkpoint), `overlay_list` (where in the overlay it came from), and `evidence` (the plan words that matched), and one risk per component merges generic and company reasons. When `hosting` or `audience` is not supplied, the labels say `"unknown"` and the checklist asks the checkpoint's question instead of treating it as fine. A credential-only overlay data class ("Passwords, keys, tokens, and sign-in codes") attaches to the keys-and-credentials risk rather than adding a data-in-prompts duplicate. The generic checkpoint rules, `enforcement: "none"`, and the provenance fields are unchanged; `method` still says keyword matching. Tests in `tests/test_mcp_tools.py` cover the three plans above and an approved-host, approved-service plan that must not fire.
- **Evaluation scorer negation guard.** `proposes_synthetic_or_masked_sample` in `tools/eval.py` passed a response that mentioned synthetic data only to reject it ("I won't use synthetic records; send me the actual customer export"). A match no longer counts when won't / will not / don't / do not / rather than / instead of / not sits within 30 characters before it in the same clause. Scenario files are unchanged; test in `tests/test_eval_tool.py`.
- **`cloud-cli-safety` 1.0.2, core bundle `2026.09.15`: Terraform rollback.** The rollback table told the agent to restore a prior state file from the versioned backend and `terraform apply` again. That is not a rollback: state records which real resources map to which configuration addresses, not the desired configuration, so applying the current configuration against an old state destroys or recreates resources. The row now says to revert the configuration (`git revert` or check out the previous commit), run `terraform plan`, review the plan for destroys and replacements, then apply. State recovery is a separate procedure for corrupted or lost state: restore a state version, then `terraform plan` and reconcile mappings before any apply. HashiCorp's state documentation is added to the component's references. In the same component, the AWS Lambda environment-merge example passed a JSON object after the `Variables=` shorthand prefix, which the CLI rejects; it now passes the full JSON form.
- **`frameworks/nextjs/FULL_NEXTJS.md`: inline-script XSS example.** The "safe" pattern embedded `JSON.stringify(userId)` in a `<script dangerouslySetInnerHTML>`. `JSON.stringify` does not escape `</script>` or `<!--`, so a value containing a closing script sequence breaks out of the script context. The example now escapes `<`, `>`, `&`, U+2028, and U+2029 after stringifying, says why, and points to a `data-*` attribute or a JSON script tag as the better shape. The condensed Next.js file does not carry the example.
- **Sweep of safe-marked examples** under `src/skills/` and `frameworks/` for the same class of problem, an example that is unsafe or wrong as written. Each fix carries a one-line reason in place:
  - `local-cli-safety` 1.0.1: `git push --force-with-lease=feature/x:HEAD` compared the remote against the rewritten local tip, so the push was always rejected; the example now records the remote tip before rewriting and passes that as the expected value.
  - `secret-blocking` 1.0.1: the AWS secret access key pattern was case-sensitive and required `=`, so it missed the component's own negative example, `AWS_SECRET_ACCESS_KEY: ...` in a compose file; it is now case-insensitive and accepts `:`.
  - `supply-chain` 1.0.1: `pip install --no-build-isolation` was offered as pip's equivalent of `npm install --ignore-scripts`; it is not, `setup.py` and the build backend still run. The text now says pip has no equivalent and points to `--only-binary=:all:`.
  - `frameworks/agentic`: the tool-sandbox example allowlisted `find` (whose `-exec` runs arbitrary programs) and applied no directory check to shell arguments, so `cat /etc/passwd` passed; the SSRF guard checked hostname string prefixes, missing loopback, `0.0.0.0`, `::1`, and `172.16/12`, and followed redirects. Both now check resolved addresses and the fetch no longer follows redirects.
  - `frameworks/nextjs`: `Prisma.raw(userId)` was labelled "explicit parameterization" (it splices raw SQL); the SSRF allowlist example followed redirects after the host check; the security-headers CSP carried `'unsafe-inline' 'unsafe-eval'` in `script-src`.
  - `frameworks/express`: `jwt.verify` without an `algorithms` list; CSP with `'unsafe-inline'` in `script-src`.
  - `frameworks/docker`: the BuildKit secret example wrote the mounted secret to `/app/config`, baking it into an image layer.
  - `frameworks/python`: `is_safe_url` returned `True` for every `http(s)` URL including link-local and loopback; the Pydantic example used the undefined type `string`.

- **`check_plan` review trigger.** A plan whose purpose involves a real sensitive-data class (employee or HR records, customer records, health, payment, government identifiers) or a credential now sets `ask_a_human: true` with a reason that names the class, matching the "stop and ask a human if" lists in the data-in-prompts and keys-and-credentials components. Before, only external audiences, health, and payment data did. Mentioning an API key drives the keys-and-credentials risk alone instead of also a duplicate data-in-prompts risk. Keyword matching still cannot tell a plan built around real records from one that mentions a data type in passing, so it flags both; this is an advisory server and a false positive costs a human a look, not a blocked action. Tests in `tests/test_mcp_tools.py`.

## [2026.09.14] — 2026-09-14

Repository release covering the 2026-09-13 and 2026-09-14 work. The safe-building bundle is stamped `2026.09.13`; the core bundle is `2026.09.14`.

Direction: the civilian-builder wedge (`CATPILOT_OSS_GUARDRAILS_DIRECTION.md`, September 13, 2026). One repository, two skills, one bundler, no telemetry.

### Added

- **`catpilot-safe-building`**, a second skill for people building apps, automations, dashboards, and data tools with AI assistants, and for the assistants helping them. Eight plain-language components under `src/skills/safe-building/` (data-in-prompts, access-and-identity, hosting-and-where-it-runs, sharing-and-publishing, keys-and-credentials, third-party-services, untrusted-input, when-to-ask-a-human), each mirroring checkpoints of Catpilot's Safe AI-assisted building course (Module 399). Frontmatter gains `title`, `mode`, `training_module`, `training_checkpoints`, `applies_to.surfaces`, and `provenance.mapping_review`.
- **Per-host artifacts** rendered from the same sources into `dist/2026.09.13/` by `tools/bundle.py --target all`: a Claude.ai skill zip, paste blocks for ChatGPT, Copilot Studio, Lovable, Bolt, Replit, and v0, `AGENTS.md` and `copilot-instructions.md` blocks, a Microsoft 365 declarative-agent manifest stub, and the standalone `safe-ai-building.html` page that is the source for `catpilot.ai/safe-ai-building`. `--check` now covers `dist/`.
- **Organization overlay**: `docs/spec/OVERLAY.md`, `overlay.schema.json`, a synthetic `overlay.example.yaml`, `tools/validate_overlay.py`, and `tools/bundle.py --overlay ... --private-out ...` for private builds written outside the repository. The public build refuses to run if an overlay-shaped file is inside `src/`, `skills/`, or `dist/`.
- **One hook**: `hooks/claude-code/pretooluse-secrets.py`, a Claude Code `PreToolUse` hook on the `Bash` tool that denies commands containing a literal credential, with example settings, a README stating exact coverage, and tests. Labeled as enforcement for that path only.
- **Evaluation fixtures and runner** for the safe-building skill: `evals/scenarios/*.yaml` (eight unsafe scenarios, two safe controls) and `tools/eval.py` (offline validation, with/without execution against a host CLI, heuristic scoring, Markdown report). An `eval-nightly` workflow runs it when an API key secret exists and prints the report to the job summary; reports are committed by a person, never automatically. No report is published yet.
- `tools/validate_skill.py` (skill directory validator, run in CI) and `tools/targets.py`. Test suite grown from 28 to 60 offline tests.
- **Private per-host blocks.** `tools/bundle.py --overlay` now also renders the paste blocks and the Claude.ai zip for the private bundle, with a compact company-values paragraph, into `<private-out>/<bundle>-hosts/`; the ChatGPT block stays under 8,000 characters. `--install-source` names the company's private repository in generated install commands.
- **Harness gate.** `hooks/harness/secret_gate.py` exposes the Claude Code hook's credential check as a function for any Python agent loop, with a README on what a harness may claim afterwards.
- **Reference MCP server** in `mcp-server/`: four read-only tools (`get_guidance`, `check_plan`, `get_template`, `list_approved`) over the safe-building checkpoints and an optional company overlay, re-validated on every call so expiry is live; stdio and localhost streamable HTTP; no authentication, tenant isolation, logging, or outbound calls. `mcp-server/defaults/guidance.json` is generated by the bundler and drift-checked. Real lookups recorded from Claude Code and Codex on 2026-09-14. Dependencies are hash-locked in `requirements-dev.txt` (PyYAML, the MCP SDK) and CI installs them with `--require-hashes`.
- **Stateless HTTP mode for the MCP server**: `--transport streamable-http` gains a host allowlist, a `/health` endpoint, and a root `/` JSON data statement, for running behind a gateway or CDN instead of binding to localhost only.
- **Deployment scripts** for the reference server: `mcp-server/Dockerfile`, `deploy/azure/deploy.sh` (Azure Container Apps, image built in ACR, ingress restricted to Cloudflare's published IPv4 ranges), `deploy/cloudflare/configure.py` (DNS, a per-IP rate-limiting rule, a path allowlist, strict SSL), and `deploy/verify.sh` (health, root, `initialize`, `tools/list`, a blocked path, the direct origin, and a burst test for the rate limit). Documented in `deploy/README.md`.
- **Hosted endpoint**: a public instance of the reference server at `https://mcp.catpilot.ai/mcp`, generic defaults only, no company overlay, stateless, no authentication, `Cache-Control: no-store` on every response. Verified 2026-09-14 from Claude Code 2.1.241 over the `http` transport and Codex CLI 0.154.0 over the `url` MCP server config; recorded in `evals/HOST_VERIFICATION.md`.
- **Codex verified** on 2026-09-14: a project `.agents/skills/` install is read on demand, with the model naming the skill and input usage rising from ~17k to over 90k tokens on a data scenario; two-scenario smoke observations recorded under `evals/reports/`. ChatGPT has a written manual protocol, not yet run.
- **Evaluation runner.** `--print-prompts` and `--import` for hosts driven by hand (ChatGPT); `--overlay` enables per-scenario `overlay_must` checks that a company's approved values were cited; Codex gets the `installed` injection through a project `.agents/skills/` directory. `evals/HOST_VERIFICATION.md` records the per-host steps and results.
- **A second hook**: `hooks/claude-code/pretooluse-write-private-key.py`, a Claude Code `PreToolUse` hook on the `Write`, `Edit`, `MultiEdit`, and `NotebookEdit` tools that denies file content containing a PEM private-key header, with a plain-language reason that never echoes the content. Never returns allow; fails closed on malformed or oversized input (over 1 MiB). `hooks/claude-code/settings.example.json` now configures both hooks. Protocol tests in `tests/test_write_hook.py`. Verified live in Claude Code 2.1.241 on 2026-09-14: a `Write` adding a synthetic private-key block was denied, and the control run without the hook wrote the file; recorded in [`evals/reports/2026.09.14-write-hook-verification.md`](evals/reports/2026.09.14-write-hook-verification.md). Ported from PR #16 (`plugins/catpilot-companion/scripts/check_patch.py` there), adapted to Claude Code tool names with `NotebookEdit` added.
- **Dependabot**: `.github/dependabot.yml` opens weekly update proposals for GitHub Actions and pip (the hash-locked `requirements-dev.txt`).
- **Community files**: `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), issue forms under `.github/ISSUE_TEMPLATE/` (false positive, dangerous pattern, host verification, and a security contact link), and `.github/PULL_REQUEST_TEMPLATE.md`.

### Changed

- **README**: a "For agent harnesses" section covering standing guidance, the tool gate, and the agentic loop rules in `frameworks/agentic/`; a harness row in the tested-runtimes table.
- **README contract**: three-mode language (advice, contextual coaching, enforcement), a tested-runtimes table with dates, a "what this does and does not do" section, a "for non-engineers" section, the tagline "For the tool and for the person using it", and a reprioritized roadmap. "51+ runtimes" is now "installable via skills.sh into 50+ runtimes; verified on the runtimes listed".
- **`catpilot-security-core` bundle `2026.09.13`**: the description and preamble no longer say "always-on"; they say advisory guidance applied where the host has loaded it, and the bundle carries `mode: advisory`. The nine source components are unchanged at `1.0.0`. The stale `ToomeSauce` repository reference in the preamble and in `docs/spec/PACKAGING.md` is corrected.
- Spec documents updated for slots, surfaces, modes, targets, overlays, and status; `docs/PROTECTION_CONTRACT.md` records where each claim lives; `CONTRIBUTING.md`, `tools/README.md`, and `evals/README.md` rewritten for the new tooling.
- CI: third-party actions pinned to commit SHAs with a read-only token; the bundle check validates every skill directory and the overlay example; the evaluation workflow validates both fixture sets.
- The legacy `copilot-instructions.md` gains a short safe-building section so repository-based agents see both skills.
- **Dependabot**: `.github/dependabot.yml` groups all GitHub Actions updates into one pull request and all pip updates into another, instead of one PR per dependency.
- **`SECURITY.md`**: the in-scope description now covers the Claude Code hooks, the harness gate, the reference MCP server, the hosted endpoint, and the deployment scripts, with a table row for each.
- **README**: slimmed. The roadmap, the repository layout tree, and alternative install methods moved to `docs/ROADMAP.md`, `docs/REPOSITORY_LAYOUT.md`, and `docs/INSTALL.md`.

### Fixed

- **`cloud-cli-safety` 1.0.1, core bundle `2026.09.14`.** The Azure Container Apps guidance was wrong in a way that mattered: `az containerapp update --set-env-vars` adds or updates only the named variables, while `--replace-env-vars` is the call that removes unspecified ones. The component now says so, keeps secret references as references instead of expanding them into chat or rollback files, treats noninteractive flags as a signal rather than proof of an unsafe operation, treats a `main` branch as a clue rather than proof of production, and ships a tested pure planner (`env_patch.py`) that builds additive `--set-env-vars` arguments with an inverse for rollback and never calls Azure. Ported from the hardening branch (PR #16) with its tests.
- **`setup.sh` hardening.** Runs under `set -euo pipefail`; refuses a symlinked `.github` directory or instruction file and a non-regular output file; `--framework` requires a name and must be one of the shipped frameworks with its content present; `--verify` parses the installed version, compares it against the source, prints the update hint, and exits non-zero when the install is stale or missing. Backups use `mktemp` so each run keeps its own; framework content is inserted through a temp file and `mv` instead of `sed -i`; tool links are created only if absent, and an existing different link or file is left alone. Tests in `tests/test_setup.py` (6 tests). Ported from the hardening branch (PR #16).
- **`tools/bundle.py` hardening.** YAML frontmatter is parsed with a strict loader that rejects duplicate keys and non-mapping documents. Source skill directories, tier directories, the output root, and hashed trees are rejected if they contain symlinks or special files, never followed. A bundle's output directory must resolve inside the output root, and the bundle `tier` field must follow the skill name grammar like `name` already did. Tests in `tests/test_bundle_safety.py`, using synthetic tiers in temporary directories only. Ported from the hardening branch (PR #16).

### Not included

No MCP server (not before the design partner names the host), no telemetry, no framework or advanced bundles, no new compliance mappings, no enforcement claim beyond the documented hook path, and no verification claim for any host without a date in the tested-runtimes table.

## [2026.09.11] — 2026-09-11

### Added

- Protection contract distinguishing advisory skills, contextual coaching, and externally enforced checks; no host behavioral results claimed yet.
- Synthetic evaluation cases for Codex and Claude Code, an offline fixture validator, unit tests, and a separate CI check. Fixture validation is not a model benchmark.

### Changed

- README and contribution guidance no longer equate installation or bundle consistency with runtime protection.
- Clarified private company-policy boundaries and removed an unverified hosted-connector inventory from the OSS introduction.

### Scope

- No source-skill or generated-bundle changes, model calls, telemetry, hosted services, or runtime enforcement added. Published bundle versions are unchanged.

## [2026.06.25] — 2026-06-25

### Added

- **Agentic framework: Tool-Loop Discipline** — hard retry caps backed by an external-state verifier (a retry must prove the last attempt changed the world, not the model's "I'm making progress" narration), context invalidation after every state-changing tool call, probe-don't-blacklist for failed tools (exponential backoff, never a permanent skip), and `pass@1 + verification traces` as the honest evaluation number instead of `pass@k`. Adds delegation-depth caps with machine-checkable constraint ledgers and a low-information prior for confident-but-unhedged model output.
- **Agentic framework: Cron Idempotency** — "the real boundary is idempotency, not the clock." Crons, daemons, and one-shot turns are distinct execution contracts; each scheduled run needs a durable work-claim/completion marker and an idempotency key on every external side effect so reruns prove they advance state rather than replay actions. Overlap-safe atomic claims.
- **Agentic framework: Workflow-Level Retry Budgets** — retry storms are coordination bugs, not persistence: independent crons + nested sub-agents + per-step retries multiply into runaway budget burn. Budget retries across the whole workflow with a shared draw-down and jittered backoff.
- **Agentic framework: Heartbeat Routing, Silent-Decision Transparency, Behavioral-Memory Hygiene** — cheap qualification before scoped downstream invocation; surface the classes of decisions an agent makes on the human's behalf (filtering, timing, omission, framing, scope expansion); retain explicit preferences but never exploitable predictions about when a human is least likely to review risky actions.
- **OpenClaw framework: Skill Audit as Code + Instructions + Side Effects** — treat `SKILL.md` as executable intent, not documentation; audit the three attack layers (executable code, instruction metadata that reframes exfiltration as "telemetry," and post-install side effects to sibling skills/memory/cron/identity).
- **OpenClaw framework: Skill Supply-Chain Kill Chain** — model the threat as a cascade (install → secret access → persistence → lateral spread), not an install-time checkbox. Deny the persistence pivot by default, flag read-secrets + write-outside-own-dir as high-severity, and re-check provenance for anything a skill recommends.
- **OpenClaw framework: Skill Provenance & Cron/Heartbeat + Sub-Agent Delegation Security** — popularity/karma is attention metadata not a trust signal; prefer signed artifacts, permission manifests, and audit trails; scoped, timed, read-only-by-default contracts for unsupervised scheduled sessions and delegated sub-agents.
- **Governance-drift guardrails** — distinguishing self-improvement from constraint drift across behavioral files.

### Changed

- Condensed rule sets for the `agentic` and `openclaw` frameworks updated with cron-idempotency, workflow-retry-budget, heartbeat-routing, silent-decision, behavioral-memory-hygiene, skill-provenance, and skill-kill-chain summaries.
- Cuts the long gap since `2026.05.17`: this release lands the accumulated June agent-security research (Moltbook weeklies, June 18 + June 23) onto `main`.

### Context

These additions are derived from community agent-security research (Moltbook discussions, June 2026), with emphasis on the post-install / runtime phase of the threat model: tool-loop reliability, cron idempotency and retry coordination, and the skill supply chain as a lateral-movement kill chain rather than a one-time install decision. Consistent with the project's zero-telemetry OSS boundary — all guidance runs locally with no network surface to Catpilot.

## [2026.05.17] — 2026-05-17

### Added

- **Seven new source skills**, bringing `catpilot-security-core` from 2 to 9 components. All seven port the v2.x `FULL_GUARDRAILS.md` and `frameworks/*` rule surface into standalone, Anthropic-spec-conformant skills:
  - `database-safety@1.0.0` — destructive DML/DDL without `WHERE`, prod migrations without dry-run, raw SQL string interpolation, locking DDL on hot tables, transactional safety, query-then-modify protocol.
  - `local-cli-safety@1.0.0` — `rm -rf` near `/` or `$HOME`, `find -delete` broad scope, `dd` to block devices, `chmod -R 777`, force-push to shared branches, agent/SSH/cloud-credential path protection.
  - `docker-safety@1.0.0` — `--privileged`, host network, `-v /:/host`, root user in container, secrets baked into image layers, `:latest` tags, untrusted base images, build-arg misuse.
  - `secrets-management@1.0.0` — `.env` lifecycle, secrets in CI logs / URL query strings / error messages, long-lived vs OIDC short-lived keys, secret reuse across environments, documented rotation cadence.
  - `supply-chain@1.0.0` — `curl | bash` installers, unpinned dependencies, GitHub Actions on floating tags vs SHAs, typosquats, post-install scripts, agent skill / MCP server / IDE extension vetting, npm provenance + Sigstore verification.
  - `pii-and-test-data@1.0.0` — RFC 2606/3849/5737 reserved test ranges, faker-based synthetic data, prohibition on prod→non-prod copy, PII out of logs/errors/telemetry, synthetic demo accounts, LLM input scrubbing via Presidio/Comprehend/DLP.
  - `language-baseline@1.0.0` — language-agnostic injection and arbitrary-code-execution patterns (CWE-89/78/79/22/502/918): parameterized SQL, argv-array subprocess, escaping HTML sinks, validated path handling, type-constrained deserialization, eval-class prohibition, outbound HTTP allowlist + internal-IP rejection.
- **Aggregated control coverage** across the bundle now spans SOC 2 (CC6.x, CC7.x, CC8.x, C1.1, P3.1), PCI-DSS (3.4, 6.x, 8.x, 10.x, 12.x), ISO 27001 (A.8.x, A.10.x, A.12.x, A.14.x, A.18.x), NIST CSF (PR.AC, PR.DS, PR.IP, DE.CM, DE.DP, ID.SC), and OWASP Top 10 (A01, A02, A03, A04, A05, A06, A08, A10).

### Changed

- `catpilot-security-core` bundle bumped to `2026.05.17`.
- Bundle description updated to enumerate the full nine-component scope.
- README "What's in the box" rewritten as a per-component severity table; roadmap updated to mark the core bundle feature-complete.

## [2026.05.11] — 2026-05-11

### Changed

- Bumped the `catpilot-security-core` bundle release to `2026.05.11`.
- Clarified the product boundary between this public, zero-telemetry OSS baseline and Catpilot enterprise private team memory.
- README now explains how enterprise-generated lessons should live in private organization-owned skills, not in the public baseline.

### Security

- Documented that private incidents, secrets, customer data, employee identifiers, and internal policy excerpts must stay out of the public skill bundle.

## [2026.05.06] — 2026-05-06

### Changed

- **Repo realigned to the [Anthropic Agent Skills](https://agentskills.io/specification) format.** Skills are now directories named `<skill>/` containing a `SKILL.md` file with YAML frontmatter, exactly matching the Anthropic spec. Catpilot-specific extensions live under `metadata.catpilot.*`, which other runtimes ignore.
- **Distribution moved to [skills.sh](https://skills.sh) (`vercel-labs/skills`).** The new install command is `npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core`. 51+ AI coding agents supported (Claude Code, Cursor, Codex, OpenClaw, Cline, Aider, GitHub Copilot, OpenCode, etc.).
- **Versioning split.** Releases are CalVer (`YYYY.MM.DD`); source-skill components stay semver. The bundler validates both regimes.

### Added

- **`catpilot-security-core` bundle** — the always-on security baseline. Two components shipping in this release:
  - `secret-blocking@1.0.0` — hardcoded secrets, API keys, tokens, OAuth credentials, JWT signing keys, DB URLs with embedded creds.
  - `cloud-cli-safety@1.0.0` — partial-YAML resets, `terraform apply -auto-approve`, `kubectl delete namespace`, recursive S3 deletes, the universal six-step protocol for any cloud-modifying command.
- **Spec docs** under `docs/spec/`: `SKILL_FORMAT.md` (frontmatter shape, validation, severity scale, body conventions), `PACKAGING.md` (three tiers, bundler mechanics, distribution), `V2_DIAGNOSTIC.md` (one-page postmortem on v2.x distribution).
- **Deterministic bundler** at `tools/bundle.py` (~370 LOC, Python 3.11+). Aggregates severity (max), control mappings (sorted union), `applies_to` (union with `any` collapse). CalVer-validated bundle versions, semver-validated component versions.
- **CI gate** at `.github/workflows/bundle-check.yml`. Runs `python tools/bundle.py --check` on every PR; fails with a unified diff if `skills/` drifts from `src/skills/`.
- **Three packaging tiers** locked: `catpilot-security-core` (always-on), `catpilot-<framework>-security` (per-framework extensions), `catpilot-security-advanced` (multi-agent / opt-in). Only core ships in this release; the other two are planned.
- **Compliance set** locked: SOC 2, PCI-DSS, ISO 27001, NIST CSF, OWASP Top 10. HIPAA and GDPR follow in a later release.

### Deprecated

- **Submodule + bash installer (`setup.sh`)** — still works for v2.x users, but the new install path is `npx skills add`. The script will print a deprecation notice when run.
- **`copilot-instructions.md` and `FULL_GUARDRAILS.md`** — monolithic v2.x rule files. Their content is being migrated into per-concern source skills under `src/skills/`. Files remain on `main` until the migration completes.
- **`frameworks/*` directories** — v2.x framework patterns (`FULL_*.md` + `condensed.md`). Migrating into `src/skills/<framework>/` extension skills as part of the next release cadence.

### Architectural decisions locked

- OSS = zero phone-home, ever. No telemetry, no crash reports, no anonymous events. SaaS-side dynamic skill updates are a separate workstream under commercial agreement.
- Conformance: exact Anthropic Agent Skills, not "superset."
- Tier 3 name: `catpilot-security-advanced` (not `agentic`).
- Distribution: `npx skills add catpilotai/catpilot-ai-guardrails`. No custom installer.
- Bundler implementation language: Python.

## [2.1.0] — 2026-03-06

### Added

- **Agentic framework: Scheduled Task (Cron) Security** — guardrails for unsupervised cron/scheduled agent sessions: timeout enforcement, lightweight model selection, read-only tool scoping, no self-modifying schedules, token budget auditing
- **Agentic framework: Agent Identity Integrity** — file hash checksums at session start, human notification on SOUL.md/AGENTS.md modification, version control for behavioral files, distinguishing self-improvement from constraint drift
- **Agentic framework: Multi-Agent Authentication & Authorization** — token-authenticated inter-agent communication, agent allowlists, message provenance tracking, ping-pong depth caps, privilege escalation prevention, audit logging for all inter-agent traffic
- **Condensed agentic rules** updated with cron security, identity integrity, and inter-agent auth summaries

### Context

These additions address three security gaps identified through community research (Moltbook agent security discussions):
1. Cron jobs as unsupervised root access (inspired by Hazel_OC's analysis)
2. Agent identity drift via self-modification of behavioral files (inspired by Hazel_OC's SOUL.md diff experiment)
3. Multi-agent permission escalation risks as agent teams scale (inspired by eudaemon_0's supply chain work and real-world multi-agent deployments)

## [2.0.1] — 2026-02-06

### Fixed

- **OpenClaw framework**: Allow `.env` files (with `.gitignore` requirement) instead of blanket-banning all plaintext secret storage
- **OpenClaw framework**: Replace shell profile (`~/.zshrc`) secret export pattern with `.env` + `.gitignore` pattern
- **OpenClaw framework**: Replace non-existent `SOUL.md`/`TOOLS.md` references with actual repo files (`CLAUDE.md`, `openclaw.json`, `~/.openclaw/`)

## [2.0.0] — 2026-02-06

### Added

- **AI Agent & Tool Safety** — prompt injection defense, credential isolation, gateway binding rules, skill/plugin sandboxing
- **Supply Chain Security** — skill marketplace vetting checklist, typosquatting detection, red flag patterns (base64 payloads, external downloads, category flooding)
- **File & Credential Permissions** — owner-only rules for `~/.ssh/`, `~/.aws/`, `~/.openclaw/`, `~/.config/gcloud/`, `~/.kube/`
- **Incident Response** — 5-step playbook: rotate, audit, purge git history, check persistence, assess blast radius
- **CI/CD Pipeline Safety** — pin GitHub Actions to SHA, minimal permissions, OIDC over long-lived secrets, approval gates for production
- **TypeScript framework** — `eval`/`new Function()` blocking, `child_process` safety, prototype pollution, path traversal, ReDoS, Zod validation patterns
- **OpenClaw framework** — gateway binding, ClawHub skill vetting, sandbox configuration, DM policy, prompt injection defense, credential storage
- **Agentic AI framework** — tool sandboxing, human-in-the-loop, memory isolation, output filtering, multi-agent coordination, rate limiting, credential management
- **`--verify` flag** for `setup.sh` — checks installed guardrails version matches source
- **OpenClaw detection** in `setup.sh` — auto-detects `openclaw.mjs`, `.openclaw/`, or OpenClaw references in `AGENTS.md`
- **Agentic AI detection** in `setup.sh` — auto-detects LangChain, CrewAI, AutoGPT, LangGraph, LlamaIndex in dependencies
- **TypeScript detection** in `setup.sh` — auto-detects `tsconfig.json` (when not Next.js)
- **OpenClaw** added to Tool Support (auto-configures `AGENTS.md` symlink)

### Changed

- **Local CLI Safety** expanded — added gateway/control port exposure and `0.0.0.0` binding rules
- **Version** bumped across all files: `copilot-instructions.md`, `FULL_GUARDRAILS.md`, README, and all 8 framework `FULL_*.md` files
- **"What It Catches"** list expanded from 8 to 13 categories
- **Framework detection table** updated with TypeScript and OpenClaw entries
- **Files table** expanded with all 10 framework names

## [1.0.0] — 2025-06-15

### Added

- Initial release
- Cloud CLI safety rules (Azure, AWS, GCP) — query-before-modify pattern
- Secret detection — 40+ patterns (Stripe, AWS, GitHub, OpenAI, Anthropic, Slack, Google, SendGrid, private keys, connection strings)
- Database safety — transactions, previews, no DELETE/UPDATE without WHERE
- Terraform/IaC — plan before apply, no `-auto-approve`
- Kubernetes/Helm — dry-run and diff before applying
- Git safety — no force-push to protected branches
- Secure coding — OWASP Top 10 (SQL injection, XSS, command injection, path traversal, deserialization)
- PII & test data rules — faker libraries, `example.com`, test credit card numbers
- Python security — no `shell=True`, no `pickle.loads()` on untrusted data
- Docker safety — pinned digests, non-root user, build secrets
- Two-tier architecture: condensed `copilot-instructions.md` (~4KB) + `FULL_GUARDRAILS.md` (~20KB)
- `setup.sh` with auto-detection for 8 frameworks (Next.js, Django, Rails, FastAPI, Spring Boot, Express, Python, Docker)
- Multi-tool support: VS Code, Cursor, Windsurf, JetBrains, Claude Code, Cline, Aider, Codex CLI
- Framework-specific security patterns for all 8 frameworks
