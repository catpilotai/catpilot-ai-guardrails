---
name: catpilot-security-core
description: 'Catpilot''s universal AI-coding-agent security baseline: advisory guardrails across nine components: cloud CLI mutations, database state changes, local CLI destruction, Docker container builds, hardcoded secrets, secrets management, supply-chain integrity, PII / test-data hygiene, and language-agnostic secure-coding patterns (SQL injection, command injection, XSS, path traversal, insecure deserialization, eval-class APIs, SSRF). Intended to apply on every code generation, file write, and shell command in a host that has loaded it. Born from real production incidents. Guidance the agent reads, not a runtime control.'
license: MIT
metadata:
  catpilot-bundle: catpilot-security-core
  catpilot-version: 2026.09.15
  catpilot-tier: core
  catpilot-layout: baseline-references
  catpilot-severity: critical
  catpilot-category: security
  catpilot-mode: advisory
  catpilot-components: cloud-cli-safety@1.0.3, database-safety@1.0.1, docker-safety@1.0.1, language-baseline@1.0.1, local-cli-safety@1.0.2, pii-and-test-data@1.0.1, secret-blocking@1.0.2, secrets-management@1.0.1, supply-chain@1.0.2
  catpilot-manifest: catpilot.json
---

# Catpilot Security Core

Catpilot's universal security baseline for AI coding agents, intended to
apply on every file write, diff review, and shell command the agent is about
to run, regardless of language or framework, whenever the host has loaded
this skill. It is advice the agent reads: installing this bundle is not
activation, and an instruction the agent has read is not an enforced
control. The repository's protection contract explains the difference
between advice, coaching, and enforcement.

This file is deliberately short. Each component below names its reference
file, states when it applies, and lists the rules that always hold. Do not
answer from this file alone: before acting in a component's area (a cloud
command that changes infrastructure, a database migration or data change, a
Dockerfile, a dependency change, anything that handles a secret or real
personal data, or code in the language-baseline patterns), read the named
reference file with your file-reading tool and follow it. The examples, the
remediation steps, and the detection patterns live there, and so do the
facts that decide whether a command is safe. Component IDs match the entries in
`metadata.catpilot.bundle.components` in the frontmatter so a finding can
be mapped back to a specific source skill (and to its severity, version, and
control mappings).

This bundle is generated deterministically from
`src/skills/core/<id>/SKILL.md` by `tools/bundle.py` in the
catpilotai/catpilot-ai-guardrails repository. Edits to this file or to the
reference files are overwritten on the next bundle. To change behavior, edit
the corresponding source skill and rebuild.

---

## cloud-cli-safety

Before acting in this area, read [references/cloud-cli-safety.md](references/cloud-cli-safety.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Before invoking a mutating `az`, `aws`, `gcloud`/`gsutil`, `kubectl`, `helm`, or `terraform` command, or a custom deploy wrapper (`./deploy.sh`, `make deploy`), especially against production-heuristic targets.

**Always:**
- Query current state (read-only) and show the relevant fields before any mutating command.
- Show the full command and affected targets; preserve env/secret references and never expand credentials into chat, logs, or history.
- Enumerate fields that will change (env vars, IAM bindings, replica counts, CPU/memory, probes).
- Get explicit confirmation (a literal "yes") before executing; do not infer consent.
- Prepare a rollback command before executing the forward command.
- Know which flags merge and which replace: `az containerapp update --set-env-vars` adds or updates only the named variables and keeps the rest; `--replace-env-vars` and `--yaml` replace the whole set; `aws lambda update-function-configuration --environment` replaces the whole map.
- Verify after execution by re-running the read-only query and diffing against the pre-change snapshot.

**Never:**
- `az containerapp update --yaml <partial>` — overwrites all unspecified fields; `--replace-env-vars` removes unspecified variables too.
- `aws lambda update-function-configuration --environment "Variables={ONLY_ONE=value}"` — replaces, does not merge.
- `aws s3 rm s3://bucket --recursive` without prior `aws s3 ls` and explicit confirmation.
- `gcloud projects set-iam-policy PROJECT policy.json` — wipes existing bindings; use `add-iam-policy-binding` instead.
- `terraform apply -auto-approve` / `terraform destroy -auto-approve` anywhere production is plausible.
- `kubectl delete namespace production` or `kubectl delete pods --all -n <ns>` against a non-dev namespace.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## database-safety

Before acting in this area, read [references/database-safety.md](references/database-safety.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Any SQL execution, ORM write, schema operation, migration command, or query-string construction against a real database, especially `prod`/`production`/`live`/`customer` environments.

**Always:**
- Require a `WHERE` clause on every `DELETE`, `UPDATE`, or `MERGE` (and ORM equivalents) unless the user has explicitly confirmed "all rows."
- Run the matching `SELECT COUNT(*)` with the same predicate and show the count before any mutating statement; the count is what the user approves.
- Wrap every mutating statement in an explicit transaction (`BEGIN`/`COMMIT`) opened by the agent; never autocommit against a production-class database.
- Clear all three migration gates in order: dry-run on a staging clone, backup taken in the same maintenance window, and a tested reversible migration (or approved restore procedure).
- Parameterize every query through driver-level binding; never build SQL by concatenation, f-strings, or ORM raw-query helpers that bypass binding.
- Identify rows by primary key and redact sensitive columns when debugging; never log full rows or copy production data downstream.

**Never:**
- `DELETE`/`UPDATE`/`MERGE` without a `WHERE` clause, or ORM equivalents like `Model.objects.all().delete()` or `prisma.model.deleteMany({})` with an empty `where`.
- A mutating statement run in autocommit mode against a production-class database.
- A migration run straight against production with no dry-run, no backup, no rollback.
- SQL built by string concatenation, f-strings, template literals, or raw-query ORM helpers.
- Copying production rows into development, staging, or any lower-controlled environment, "just for testing."

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## docker-safety

Before acting in this area, read [references/docker-safety.md](references/docker-safety.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Writing or running a `Dockerfile`/`Containerfile`, `docker-compose.yml`, `docker build`/`run`/`exec` (or podman/nerdctl/buildah equivalents), or a Kubernetes manifest setting `securityContext`, `hostNetwork`, `hostPID`, `hostIPC`, `privileged`, or `hostPath` volumes.

**Always:**
- Pin base images to an immutable digest (`FROM <image>@sha256:...`); floating tags (`latest`, major/minor only) are for non-deployed internal tooling only.
- Declare and switch to a non-root `USER` before `CMD`/`ENTRYPOINT`; `COPY --chown=app:app` files the runtime needs to read.
- Pass build-time secrets with BuildKit `--mount=type=secret`; pass runtime secrets via `--env-file` or a secret store, never baked into the image.
- Run production containers with `read_only`/`--read-only`, `no-new-privileges`, and `cap_drop: [ALL]` with only required capabilities re-added.
- Pin package versions, use the minimal-install flag, and clean the package cache in the same layer; verify checksums for downloaded binaries.

**Never:**
- `--privileged` / `privileged: true` — disables seccomp, AppArmor, and capability dropping.
- `--net=host` / `network_mode: host` or `--pid=host` / `pid: host` — shares the host's network or process namespace.
- `-v /:/host` or mounting `/var/run/docker.sock` into the container — full host filesystem or Docker daemon control.
- `ENV`/`ARG` for secrets, or `COPY .env .` — persists secrets in image history.
- `chmod -R 777` inside a container image.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## language-baseline

Before acting in this area, read [references/language-baseline.md](references/language-baseline.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Writing or committing code that builds SQL from non-literal values, runs a subprocess/shell with non-literal arguments, writes input into the DOM/HTML, resolves a filesystem path from input, deserializes untrusted data, executes a string as code, bypasses type-system checks, or issues an outbound HTTP request to an input-derived URL.

**Always:**
- Route SQL values through driver parameter binding; never string concatenation, f-strings, template literals, or ORM raw-query helpers.
- Run subprocesses with an argv array and no shell (`shell=False`); the command name is a literal or from an allowlist, never derived from input.
- Write user-controlled values to the DOM/HTML only through escaping sinks (`textContent`, not `innerHTML`/`document.write`); sanitize with a vetted library when raw HTML is required.
- Normalize input-derived filesystem paths: strip to basename, join against a known-safe directory, resolve symlinks, and reject anything outside that directory.
- Deserialize untrusted data only with type-constrained formats (`json.loads`, `yaml.safe_load`); never `pickle.loads`, unsafe `yaml.load`, `Marshal.load`, `ObjectInputStream`, or `unserialize`.
- Never execute a string as code (`eval`, `new Function`, `setTimeout(stringArg)`) or bypass type-system checks (`as any`, `@ts-ignore`) on external input.
- Before an outbound HTTP request to an input-derived URL, check the host against an allowlist and reject internal/link-local IP ranges.

**Never:**
- SQL built by string concatenation, f-strings, or template literals with non-literal values.
- `subprocess`/`exec`/`system` invoked with a single shell-interpreted string containing non-literal elements.
- `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, or `{{ x | safe }}` fed with unsanitized user input.
- `pickle.loads`, `yaml.load`/`yaml.unsafe_load`, `Marshal.load`, or `unserialize` on external data.
- `eval`, `new Function`, or TypeScript `as any`/`@ts-ignore` used to bypass validation of external input.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## local-cli-safety

Before acting in this area, read [references/local-cli-safety.md](references/local-cli-safety.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Running `rm`/`find ... -delete`/`shred`/`dd` on paths outside the project or from a variable, `chmod`/`chown` with `-R` near credential directories, history-rewriting `git` commands, commands that start a network service, or anything piping credentials or `env` into a network request.

**Always:**
- Verify a destructive-command path is non-empty and not `/` or `$HOME` before running; never interpolate a bare, unguarded variable.
- Keep `chmod`/`chown` scoped, never recursive (`-R`) on `$HOME` or a credential directory (`~/.ssh`, `~/.aws`, etc.); tighten permissions, never loosen them.
- Treat `main`, `master`, `release/*`, `production`, `staging`, `develop`, `prod*` as protected: no history-rewriting `git` command against them; use `--force-with-lease` elsewhere.
- Bind development network services to `127.0.0.1`, never `0.0.0.0`, unless the user explicitly names external exposure.
- Keep credential paths and `env`/`printenv` output out of any network call, even to what looks like an internal URL.
- Scope `sudo` to the specific named command; run the minimum privileged step and return to the unprivileged shell.

**Never:**
- `rm -rf`/`find ... -delete` against an unset or unguarded variable, or any path outside the project directory.
- Recursive `chmod`/`chown` on `$HOME` or a credential directory, or world-readable/writable modes on credential files.
- `git push --force`/`push -f`, `reset --hard`, `clean -fd`, `filter-branch`, or `filter-repo` against `main`, `master`, `release/*`, `production`, `staging`, or `develop`.
- Binding a dev service to `0.0.0.0`.
- Piping `~/.ssh`, `~/.aws`, or an `env` dump into a network request, or untrusted content into `sudo bash`/`sudo sh`.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## pii-and-test-data

Before acting in this area, read [references/pii-and-test-data.md](references/pii-and-test-data.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Writing test fixtures, seed data, illustrative doc/comment records, error messages, logs, telemetry, screenshots or recordings shared outside the org, migrations/ETL between environments, or LLM prompts, fine-tuning sets, and RAG corpora.

**Always:**
- Use reserved test ranges for identifiers that have one (`*@example.com`, the `555-01xx` phone block, RFC 5737 IPs, provider test card numbers, SSA-reserved SSN ranges) instead of a real-looking value.
- Generate names, addresses, and other free-form identifiers with a seeded synthetic generator (`faker`, `@faker-js/faker`, etc.), not free-form invention.
- Refuse to copy production rows into development, staging, demo, or test environments, including "just one row" or hash-based "anonymization."
- Keep emails, phone numbers, full names, addresses, government IDs, DOB, and payment/bank numbers out of logs, errors, and telemetry; identify by internal ID instead.
- Use synthetic test accounts for anything leaving the organization (demos, screenshots, recordings, shared transcripts).
- Screen data going into an LLM prompt, fine-tuning set, or RAG corpus with a PII/PHI/PCI scrubber before ingestion.

**Never:**
- A real, or real-looking, email, phone number, SSN, or card number in a fixture, comment, or doc example.
- Copying production rows into a lower environment, including a single row "to reproduce a bug."
- Hashing names or emails and calling it anonymization.
- Logging or erroring with a user's email, phone, full name, address, government ID, or payment/bank number.
- Recording or screenshotting the production app against a real customer account.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## secret-blocking

Before acting in this area, read [references/secret-blocking.md](references/secret-blocking.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Every code generation, file write, file edit, and diff review, and any shell command with inline credentials, environment-variable assignments, or `curl -H` headers.

**Always:**
- Scan every file write, edit, and diff for secret patterns before it lands, including shell commands with inline credentials or env assignments.
- Stop and do not write the file when a detection pattern matches; name the provider to the user and propose an environment-variable or secret-manager remediation.
- Treat a match for Stripe (`sk_live_`/`sk_test_`/`pk_live_`), AWS (`AKIA`/`ASIA`/`aws_secret_access_key`), GitHub (`ghp_`/`gho_`/`ghs_`), GitLab (`glpat-`), Anthropic (`sk-ant-`), OpenAI (`sk-`), Slack (`xox[abprs]-`), Google (`AIza`/`ya29.`), a private-key block (`-----BEGIN ... PRIVATE KEY-----`), or a credentialed DB URI as a stop condition.
- Use environment variables or a secret manager instead of a literal value.
- Generate `.env.example` with placeholder values and confirm `.env` is in `.gitignore`.
- Use clearly fake placeholders (`your-api-key-here`, `REPLACE_ME`) in example code, never realistic-looking strings.

**Never:**
- Write a literal secret into source code, config files, comments, test fixtures, or documentation.
- Echo a secret in a shell command the agent intends to run (e.g. `curl -H "Authorization: Bearer sk-ant-..."`).
- Paste a secret into a commit message, PR description, or issue body.
- Write `.env` files containing real secrets.
- Include a secret in a log statement, even at DEBUG level.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## secrets-management

Before acting in this area, read [references/secrets-management.md](references/secrets-management.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Writing or committing `.env`/secret files, `.gitignore` or CI workflow configuration, container/Kubernetes/Terraform manifests defining runtime config, application code that reads credentials or logs errors, or incident-response steps after a secret is exposed.

**Always:**
- Add `.env*` patterns to `.gitignore` before the first `.env` file exists; commit only `.env.example` with key names, no values.
- Reference CI secrets from the provider's secret store (`${{ secrets.X }}` or masked variables), never as plain variables; never `echo`, `printenv`, `env`, or `set -x` a secret.
- Read secrets from the process environment or a vault-fetch SDK at runtime; never from a URL query/path segment or a file baked into the image.
- Use different secret values per environment; never copy a production secret into a lower environment or share one across environments.
- Keep Authorization headers, cookies, connection strings, and full environment dumps out of exception messages, logs, and observability payloads.
- On exposure, rotate the secret at the source and verify the new value is in use before any cleanup; revoke the old value before rewriting history or deleting logs.

**Never:**
- Commit a `.env` file, or consider it cleaned up once a later commit deletes it.
- Echo a secret, run `printenv`/`env`, or enable `set -x` in a CI workflow step.
- Log or return a connection string with embedded credentials, in an error message or a debug endpoint.
- Share the same secret value across development, staging, and production.
- "Remediate" an exposed secret by deleting the file or rewriting git history before revoking the credential at its source.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

---

## supply-chain

Before acting in this area, read [references/supply-chain.md](references/supply-chain.md) in this skill's directory; the rules below are the minimum, not the whole component.

**Applies when:** Adding a dependency to a manifest or running an install command, referencing a third-party CI action, building a `Dockerfile`/compose that pulls images or binaries, piping `curl`/`wget` output into a shell, or installing an agent skill, MCP server, or IDE extension.

**Always:**
- Install from a lockfile (`npm ci`, `pip install --require-hashes`, `poetry install --no-update`, `bundle install --frozen`, `cargo build --locked`), never a bare install that re-resolves.
- Pin third-party CI references (actions, orbs, plugins, reusable workflows) to a full commit SHA, not a mutable tag.
- Before adding a dependency, verify its spelling against the canonical upstream name, its publisher/namespace, its provenance/attestation, and its download/maintenance history.
- Replace `curl | bash`-style pipe-to-shell installs with download, hash-verify, inspect, then run; prefer the project's package-manager distribution.
- Review a package's install/build-hook scripts before installing; refuse ones that download external artifacts or touch `~/.ssh`, `~/.aws`, or similar credential paths.
- Vet any third-party agent skill, MCP server, or IDE extension as code: read the source, check the permission scope, and reject obfuscated or "ClickFix" install instructions.

**Never:**
- `npm install`/`yarn add`/`pip install <pkg>` (unpinned, no lockfile) in CI.
- A GitHub Actions third-party reference pinned to a tag or branch (`@main`, `@v1`) instead of a commit SHA.
- Silently substituting a similar-looking package when a typosquat or namespace check fails.
- `curl ... | bash`, `wget -qO- ... | sh`, or `iwr ... | iex` piped installs.
- Installing an agent skill or extension with a "ClickFix" instruction, an obfuscated/base64 payload, or a typosquatted publisher name.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.
