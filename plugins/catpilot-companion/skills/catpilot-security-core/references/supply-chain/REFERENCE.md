
## Why

Modern applications execute orders of magnitude more code from
external publishers than from the developer who wrote the project.
A typical Node service pulls in 1,000+ transitive npm packages on
first install; a typical Python service depends on a wheel built
by a maintainer the developer has never met; a typical CI pipeline
executes third-party GitHub Actions that have access to repository
secrets and `GITHUB_TOKEN`.

The failures this skill blocks share a common shape: **the agent
adds, recommends, or trusts code from a publisher that hasn't been
verified, pinned, or scoped.**

- A typosquatted package (`requets` instead of `requests`, `1odash`
  instead of `lodash`) ships a working API surface and a payload
  that runs at install time.
- A floating GitHub Action tag (`uses: some-org/action@main`)
  silently changes its source code overnight; the next CI run
  executes whatever the maintainer pushed last, with access to
  every secret the workflow can read.
- A `curl ... | bash` install pipes a script the developer never
  read into the shell. The script can do anything the shell can.
- An unverified agent skill, MCP server, or VS Code extension runs
  with the IDE's full permissions — access to the file tree, the
  shell, paired credentials, the developer's chat history with the
  agent itself. In February 2026, 341 malicious skills were found
  on ClawHub alone.
- A `postinstall` script from a recently-published package executes
  during `npm install` — before any code review, before any
  test, before the developer has even read what the package does.

This skill applies the same query-then-modify discipline used
elsewhere in the bundle: **inspect first, pin always, prefer the
verifiable source.**

## When to apply

Apply this skill **before** the agent runs, recommends, or commits
any of the following:

- A new entry in `package.json`, `requirements.txt`,
  `pyproject.toml`, `Pipfile`, `Gemfile`, `go.mod`, `Cargo.toml`,
  `pom.xml`, `build.gradle`, `composer.json`, or any other
  dependency manifest.
- An install command — `npm install`, `pnpm add`, `yarn add`,
  `pip install`, `poetry add`, `bundle add`, `gem install`,
  `go install`, `cargo install`, `brew install`, `apt-get install`,
  `apk add`.
- A GitHub Actions workflow that consumes a third-party action
  (`uses: <owner>/<action>@<ref>`), or any CI provider equivalent
  (GitLab `include:`, CircleCI orbs, Buildkite plugins, Azure
  Pipelines tasks).
- A `Dockerfile` or `docker-compose.yml` that pulls a base image,
  installs OS packages, or downloads binaries inside the build
  (cross-references `docker-safety`).
- A `curl`, `wget`, or `Invoke-WebRequest` command that pipes its
  output into a shell, language runtime, or installer.
- Any agent skill, MCP server, IDE extension, OpenClaw skill,
  ClawHub install, or similar published-by-someone-else artifact
  the agent is about to install or run.
- Any post-install script (`postinstall`, `prepare`, `prepublish`,
  pip `setup.py install`-time code, `pyproject.toml` `[tool.*]`
  build hooks).

This skill is the publisher-trust counterpart to `docker-safety`
(image build), `secrets-management` (CI logs), and
`local-cli-safety` (curl-pipe-bash). All four apply together.

## Rules

### Rule 1 — Dependencies are pinned and locked

Every dependency manifest must be accompanied by a lockfile, and
installs must consult the lockfile rather than re-resolving from
the manifest:

| Manifest | Lockfile | Install command |
|---|---|---|
| `package.json` | `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` | `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` |
| `requirements.txt` | `requirements.txt` with pinned versions and `--hash=` entries | `pip install --require-hashes -r requirements.txt` |
| `pyproject.toml` | `poetry.lock` / `uv.lock` / `pdm.lock` | `poetry install --no-update` / `uv sync --frozen` |
| `Gemfile` | `Gemfile.lock` | `bundle install --frozen` |
| `go.mod` | `go.sum` | `go mod download` |
| `Cargo.toml` | `Cargo.lock` | `cargo build --locked` |

`npm install`, `pip install <package>` without a lockfile, and `yarn
add` in CI are prohibited because they re-resolve and may pull a
newer version than the developer tested with.

### Rule 2 — GitHub Actions and other CI references are SHA-pinned

Third-party CI references must pin to a full commit SHA, not a tag.
Tags are mutable; SHAs are immutable.

```yaml
# ✅ SHA-pinned with the tag in a comment for human readability
- uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab  # v4.1.0
```

The same applies to:

- CircleCI orbs (use the SHA-pinned form, not `orb: foo@1.0`).
- Buildkite plugins (`plugins: foo#sha`).
- Reusable workflows (`uses: org/repo/.github/workflows/x.yml@<sha>`).
- Docker base images (cross-references `docker-safety`).

GitHub-owned actions (`actions/*`, `github/*`) and other
organization-trusted publishers may use tag pinning in
non-production repositories; production workflows pin everything to
SHAs.

### Rule 3 — Package identity is verified before install

Before adding a dependency, the agent verifies:

- **Spelling.** Compare character-by-character against the
  upstream canonical name. `requests` vs `requets`, `lodash` vs
  `1odash`, `colors` vs `coIors` (capital `i`).
- **Publisher / namespace.** `@types/*`, `@stripe/*`, etc. are
  scoped to known publishers; their unscoped lookalikes
  (`stripe-helper`, `types-react`) are suspect.
- **Provenance.** Prefer packages with npm provenance attestations,
  Sigstore signatures, or other verifiable build origin. `npm view
  <pkg> --json` exposes the publish source; GitHub attestations are
  surfaced via `gh attestation verify`.
- **History.** Reject packages with `< 100` weekly downloads when
  there is a high-volume alternative; reject packages with no
  releases in `> 2` years when an actively maintained alternative
  exists.
- **Maintainer reputation.** A single author publishing 50+
  packages across unrelated categories (crypto, finance, social
  tools, scraping) is a red flag pattern for mass-malware
  distribution.

If any check fails, the agent does not silently substitute a
similar-looking package. It surfaces the concern and waits for the
user to confirm or redirect.

### Rule 4 — `curl | bash` and equivalent pipe-to-shell installs are prohibited

The following patterns are prohibited and must be flagged whenever
the agent encounters them in a script, Dockerfile, README
copy-paste, or AI-generated install instruction:

```bash
# ❌ Any of these
curl -fsSL https://example.com/install.sh | bash
curl ... | sh
wget -qO- https://example.com/setup | bash
iwr -useb https://example.com/install.ps1 | iex   # PowerShell
```

The agent replaces them with: download, inspect, hash-verify, then
run. Where the project publishes an installer, prefer the project's
package-manager distribution (`brew`, `apt`, `dnf`, the
language-native package manager) over the upstream install script.

The same rule applies to language-runtime installs that pipe to
shell (`nvm install` from a piped script, `rustup` if invoked via
pipe, `oh-my-zsh` if invoked via pipe). Pre-download, read, verify,
then execute.

### Rule 5 — Post-install scripts and build hooks are reviewed

Packages that run code at install time (`postinstall` in
`package.json`, `setup.py` `cmdclass`, `pyproject.toml`
`[build-system]` with custom hooks, `gem install` native extension
builds) are reviewed before the install runs.

The agent:

- Surfaces the package's install scripts when adding a new
  dependency. `npm view <pkg> scripts` shows the script block;
  inspect Python package metadata/source in an isolated environment.
  `pip install --dry-run` may invoke a build backend to prepare metadata;
  it is not a no-code-execution inspection sandbox.
- Refuses to add a package with an install script that downloads
  external artifacts, modifies files outside the package's own
  directory, or executes against `~/.ssh`, `~/.aws`,
  `~/.openclaw`, or any path matched by
  `local-cli-safety` Rule 5.
- For npm, `npm install --ignore-scripts` can disable lifecycle scripts
  when the package remains usable without them. Python's
  `--no-build-isolation` does **not** disable build hooks; it removes
  build-environment isolation. Do not use it as a security control.
- For reviewed Python dependencies, prefer pinned, hash-verified wheels
  (`--only-binary=:all:` and `--require-hashes` with a complete lockfile).
  Fail when a required wheel is unavailable. Review/build source packages
  in a separate isolated builder with no credentials and restricted network
  access. Wheels remain untrusted code when imported or executed.

### Rule 6 — Agent skills, MCP servers, and IDE extensions are vetted as code

Anything the agent installs or runs that is published by a third
party — agent skills (ClawHub, OpenClaw, MCP registries), IDE
extensions (VS Code Marketplace, JetBrains Marketplace), CLI tools
distributed via brew taps, language-runtime plugins (Vim, Emacs,
shell prompts) — is reviewed as code, not as a feature.

The vetting checklist:

- **Read the source.** The README is marketing. The code is the
  contract.
- **Look at the manifest** for permission scope. Skills that
  request access beyond their stated purpose are rejected.
- **Reject "ClickFix" install patterns.** Any skill whose
  prerequisites say "run this command to fix installation,"
  "download this ZIP and extract before installing," or "execute
  this base64 string" is rejected without further review.
- **Reject obfuscated payloads.** Base64-encoded scripts, minified
  install code, packed binaries — all are reasons to refuse.
- **Compare the package name character-by-character** against the
  publisher the user named. `clawhubb`, `cllawhub`, `clawhub-cli`,
  `clawhub-tools` are typosquats.
- **Prefer registry-managed installs.** `npx skills add
  <verified-publisher>/<skill>` (which validates source against the
  publisher's GitHub) is preferred over manual file drops.

For production-critical or organization-wide skills, the install
goes through the team's documented review process even when the
above checks pass.

## Negative examples

```yaml
# ❌ GitHub Actions: floating tag from a non-canonical publisher
- uses: some-org/build-action@main
- uses: random-user/upload-artifact@v1
```

```yaml
# ❌ Production workflow with write-all permissions
permissions: write-all
```

```bash
# ❌ npm install in CI — re-resolves from manifest, ignores lockfile drift
npm install
yarn add some-package          # adds without freezing
pip install requests           # unpinned, no lockfile
```

```json
// ❌ Unpinned versions in package.json — `^` allows minor bumps on install
{
  "dependencies": {
    "express": "^4.17.0",
    "lodash": "*"
  }
}
```

```bash
# ❌ Pipe-to-shell installer
curl -fsSL https://get.example.com | bash
wget -qO- https://install.example.com/setup.sh | sh
iwr https://get.example.com/install.ps1 | iex
```

```bash
# ❌ Typosquat suggestions
npm install requets            # should be `requests` (and that's pypi anyway)
pip install python-discord     # should be `discord.py` from the correct publisher
npm install coIors             # capital "i", should be `colors`
```

```bash
# ❌ Installing a skill without source review
npx skills add random-user/some-new-skill
code --install-extension untrusted-publisher.fake-claude
```

```dockerfile
# ❌ Random registry pull during image build (cross-ref docker-safety)
FROM random-registry.com/some-image:latest
RUN curl -fsSL https://install.example.com | bash
```

```toml
# ❌ pyproject.toml with no hash pinning
[project]
dependencies = [
    "requests",
    "django>=4.0"
]
```

## Remediation

### npm with full lockfile install

```bash
# ✅ Lockfile-respecting install (also faster in CI)
npm ci

# ✅ Adding a new dep: check provenance first
npm view express --json | jq '{name, version, maintainers, repository, dist}'

# Then add
npm install express@4.18.2 --save-exact
git add package.json package-lock.json
```

### Python with pip-tools or uv (hash-locked)

```bash
# ✅ pip-tools workflow
pip-compile --generate-hashes requirements.in -o requirements.txt
pip install --require-hashes -r requirements.txt

# ✅ uv workflow
uv add requests
uv sync --frozen
```

### GitHub Actions — SHA-pinned third-party

```yaml
# ✅ Action pinned to SHA, tag in comment, minimal perms
jobs:
  build:
    permissions:
      contents: read
      id-token: write     # for OIDC
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: actions/setup-node@8f152de45cc393bb48ce5d89d36b731f54556e65  # v4.0.0
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123:role/github-actions
          aws-region: us-east-1
```

### Pre-download + verify replacement for `curl | bash`

```bash
# ✅ Download, inspect, hash-verify, then execute
curl -fsSL -o /tmp/install.sh https://example.com/install.sh
EXPECTED="abc123...sha256-from-vendor-docs"
ACTUAL=$(sha256sum /tmp/install.sh | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "hash mismatch" >&2; exit 1; }
less /tmp/install.sh                # human review
bash /tmp/install.sh
```

### Verifying an npm package's provenance attestation

```bash
# ✅ Check that the package was built by the claimed publisher's CI
npm view <pkg> --json | jq '.dist.attestations'

# ✅ Or via sigstore
cosign verify-attestation \
  --certificate-identity-regexp 'https://github.com/<owner>/<repo>/.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <pkg-tarball>
```

### Reviewing an agent skill before install

```bash
# ✅ Inspect the skill before installing
npx skills add <publisher>/<skill> --list   # preview
git clone https://github.com/<publisher>/<repo> /tmp/skill-review
cd /tmp/skill-review
# Read SKILL.md, scripts/, manifest. Look for:
#   - ClickFix install instructions
#   - Base64 / minified / obfuscated content
#   - External-download steps
#   - Permission scope beyond stated purpose
grep -rE "(eval|exec|base64|curl.*\|.*sh|wget.*\|.*sh)" .

# If clean, install with the official CLI
npx skills add <publisher>/<skill> --agent claude-code -g -y --copy
```

### Dockerfile install — minimal, verified, locked

```dockerfile
# ✅ Cross-references docker-safety + supply-chain
# syntax=docker/dockerfile:1.7
FROM node:20.11.1-alpine3.19@sha256:f1fe1d...
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY package.json package-lock.json ./
# Lockfile install, no scripts, deterministic
RUN npm ci --omit=dev --ignore-scripts
COPY --chown=app:app . .
USER app
CMD ["node", "index.js"]
```

## Production detection heuristics

Treat the supply-chain context as production-class (escalating the
protocol) when **any** of these match:

- The change is in a workflow or branch that publishes a release,
  pushes to a registry, or deploys to a production environment.
- The repository is the source of an image, library, or skill
  other organizations consume.
- The dependency manifest belongs to a service that handles
  cardholder data, PHI, or regulated material.
- A separate `dev`/`staging` workflow exists with looser rules —
  this is the prod workflow.

If any signal matches, all six rules apply without exception. In
particular, Rule 2 (SHA pinning) and Rule 1 (lockfile-respecting
installs) become hard requirements with no tag-pinning exception
for the GitHub-owned actions.

## References

- SLSA framework — https://slsa.dev/spec/v1.0/levels
- GitHub Actions security hardening — https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- npm provenance — https://docs.npmjs.com/generating-provenance-statements
- Sigstore — https://www.sigstore.dev/
- OWASP Top 10 CI/CD Security Risks — https://owasp.org/www-project-top-10-ci-cd-security-risks/
- OpenSSF Scorecard — https://github.com/ossf/scorecard
- Socket.dev (npm supply-chain analysis) — https://socket.dev/
- pip-audit — https://github.com/pypa/pip-audit
- govulncheck — https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
