# Changelog

All notable changes to this project will be documented in this file.

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
