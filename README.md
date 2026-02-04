
# Guardrails for Coding Agents
<p align="left">
  <img src="assets/catpilot-logo.png" alt="Catpilot" width="100" style="vertical-align: middle;">
  <em>Paws before you push.</em>
</p>

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![License](https://img.shields.io/badge/license-MIT-green)

Most coding agents read a local file for project-specific guidance—but most teams leave it empty. Drop in these guardrails to catch dangerous patterns that cause **outages, security vulnerabilities, and secret leaks.**

Built by [Catpilot.ai](https://catpilot.ai)—born from a real incident where an agent wiped production environment variables with a partial YAML update. MIT licensed. Dogfooded daily. PRs welcome.

## Quick Start

```bash
git submodule add https://github.com/catpilotai/catpilot-ai-guardrails.git .github/ai-safety
./.github/ai-safety/setup.sh
git add .gitmodules .github/
git commit -m "Add AI guardrails"
```

That's it. Your coding agent now follows the safety rules.

<details>
<summary><strong>🧩 Framework Detection (Automatic)</strong></summary>

The setup script auto-detects your framework and adds relevant security patterns:

| Detected File | Framework |
|---------------|-----------|
| `package.json` with `"next"` | Next.js |
| `manage.py` or `requirements.txt` with `django` | Django (+Core Python) |
| `Gemfile` with `rails` | Rails |
| `requirements.txt` with `fastapi` | FastAPI (+Core Python) |
| `pom.xml`/`build.gradle` with `spring` | Spring Boot |
| `package.json` with `"express"` | Express |
| `*.py` or `requirements.txt` | Python (Core/Scripts) |
| `Dockerfile` | Docker |

```bash
# Auto-detect (recommended)
./.github/ai-safety/setup.sh

# Override detection
./.github/ai-safety/setup.sh --framework django

# Skip framework patterns
./.github/ai-safety/setup.sh --no-framework
```

Each framework adds ~600-800 bytes of security patterns specific to that stack.

</details>

<details>
<summary><strong>📁 For Organizations (Fork-based workflow)</strong></summary>

For teams that want to customize rules or control updates:

### Step 1: Fork This Repo

Fork `catpilotai/catpilot-ai-guardrails` to your organization (e.g., `YOUR_ORG/ai-guardrails`).

### Step 2: Add Submodule to Your Repos

```bash
git submodule add git@github.com:YOUR_ORG/ai-guardrails.git .github/ai-safety
```

### Step 3: Run Setup & Commit

```bash
./.github/ai-safety/setup.sh
git add .gitmodules .github/
git commit -m "Add AI guardrails"
```

### Customizing Rules

Add company-specific rules by editing the "🎯 Project-Specific Rules" section at the bottom of `copilot-instructions.md` in your fork.

### Staying Up to Date

```bash
cd your-fork-of-ai-guardrails
git fetch upstream    # git remote add upstream https://github.com/catpilotai/catpilot-ai-guardrails.git
git merge upstream/main
git push
```

Then in each repo:
```bash
git submodule update --remote .github/ai-safety
./.github/ai-safety/setup.sh --force
git commit -m "Update AI guardrails"
```

</details>

## Tool Support

| Tool | Instruction File | Auto-configured |
|------|------------------|------------------|
| VS Code + GitHub Copilot | `.github/copilot-instructions.md` | ✅ |
| Cursor | `.cursorrules` | ✅ (symlink) |
| Windsurf | `.windsurf/rules/` | ✅ (symlink) |
| JetBrains + AI Assistant | `.github/copilot-instructions.md` | ✅ |
| Claude Code | `CLAUDE.md` | ✅ (symlink) |
| Cline | `.clinerules` | ✅ (symlink) |
| Aider | `.aider.conf.yml` | ✅ (config entry) |
| Codex CLI | Manual | ⚠️ See below |

<details>
<summary><strong>Codex CLI usage</strong></summary>

Codex CLI doesn't auto-read project files. Pass guardrails via the `--instructions` flag:

```bash
# One-off command
codex --instructions "$(cat .github/copilot-instructions.md)" "fix the auth bug"

# Or create a shell alias in ~/.zshrc or ~/.bashrc
alias codex-safe='codex --instructions "$(cat .github/copilot-instructions.md)"'

# Then use normally
codex-safe "fix the auth bug"
```

</details>

## What It Catches

- ☁️ **Cloud CLI safety** (Azure, AWS, GCP) — query before modify, confirm before execute
- 🔑 **Secret detection** — 40+ patterns (Stripe, AWS, GitHub tokens, etc.)
- 🗄️ **Database safety** — transactions, previews, no DELETE without WHERE
- 🏗️ **Terraform/IaC** — plan before apply, no `-auto-approve`
- ☸️ **Kubernetes/Helm** — dry-run and diff before applying
- 📦 **Git safety** — no force-push to protected branches
- 🛡️ **Secure coding** — OWASP Top 10, input validation, output encoding
- 🧩 **Framework patterns** — Next.js, Django, Rails, FastAPI, Spring Boot, Express, Python (General), Docker

**Example: Cloud CLI protection**

Without guardrails:
```bash
# AI runs this — looks fine, right?
az containerapp update --yaml partial-config.yaml
# 💥 Result: CPU reset to 0.5, memory to 1GB, all env vars deleted
```

With guardrails:
```bash
# AI queries current state first
az containerapp show --name myapp --query "properties.template"
# Shows you the full command and asks for confirmation before executing
# Prepares rollback command in case something goes wrong
```

<details>
<summary><strong>More examples</strong></summary>

**Command Injection prevention**

Without guardrails:
```python
# AI generates this — user controls filename
os.system(f"convert {filename} output.png")
# 💥 Attacker passes: "image.png; rm -rf /"
```

With guardrails:
```python
# AI uses subprocess with list (no shell interpretation)
subprocess.run(["convert", filename, "output.png"], check=True)
```

**SQL Injection prevention**

Without guardrails:
```python
# AI generates this
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

With guardrails:
```python
# AI uses parameterized queries
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

**Secret detection**

Without guardrails:
```python
# AI hardcodes credentials
API_KEY = "sk_live_abc123..."
stripe.api_key = API_KEY
```

With guardrails:
```python
# AI uses environment variables
import os
stripe.api_key = os.environ["STRIPE_API_KEY"]
```

</details>

## Files

| File | Purpose |
|------|---------|
| `copilot-instructions.md` | Condensed rules (~4KB) — **auto-loaded by IDE** |
| `FULL_GUARDRAILS.md` | Complete reference (~20KB) — detailed examples, loaded on-demand |
| `frameworks/` | Framework-specific patterns (auto-detected) |

<details>
<summary><strong>How the two files work together</strong></summary>

The condensed `copilot-instructions.md` is automatically injected into every AI request by your IDE. The complete `FULL_GUARDRAILS.md` is NOT auto-loaded (too large), but the AI can read it when encountering edge cases or when you ask explicitly.

This approach optimizes for minimal context window usage while keeping complete documentation available.

</details>

## Cloning Repos With This Submodule

```bash
git clone --recurse-submodules <repo-url>

# Or if already cloned:
git submodule update --init --recursive
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding patterns and submitting PRs.

## License

MIT — See [LICENSE](LICENSE) for details.
