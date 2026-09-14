# Security Policy

If you believe you've found a security issue, please report it privately. 🙏

## Reporting

**Email:** hi@catpilot.ai

**What to include:**
- Reproduction steps
- Impact assessment
- Suggested fix (if you have one)

**Response time:** We'll acknowledge within 48 hours and provide a detailed response within 7 days.

## What's In Scope

This project ships skill markdown files in [Anthropic Agent Skills](https://agentskills.io/specification) format under `skills/` and `src/skills/`, the bundler and validators in `tools/`, the Claude Code hooks and the harness gate in `hooks/`, a reference MCP server in `mcp-server/`, the deployment scripts for the hosted reference server in `deploy/`, and the legacy v2.x bash installer (`setup.sh`). Security concerns include:

| Risk | Example |
|------|---------|
| **Bundler vulnerabilities** | Path traversal, YAML injection, frontmatter sanitization issues in `tools/bundle.py` |
| **Skill content bypasses** | Rule patterns that miss real-world dangerous code; evidence regexes that don't match actual incidents |
| **Harmful advice** | Rules that, if followed by an agent, would cause damage (false-positive denials of legitimate operations, or false-negative passes on dangerous ones) |
| **Skill packaging vulnerabilities** | A maliciously-crafted `bundle.toml` or `SKILL.md` that breaks the deterministic bundler in unsafe ways |
| **Legacy `setup.sh` vulnerabilities** | Command injection, path traversal in the v2.x installer (still kept on `main` for backward compatibility) |
| **Supply chain on the install path** | Anything that could compromise users running `npx skills add catpilotai/catpilot-ai-guardrails` |
| **Hooks** | A way to get a literal credential or a private-key block past a configured hook, or a denial of a legitimate action that the documented escape hatch cannot resolve |
| **Reference MCP server** | Input handling in `mcp-server/`, an overlay validation bypass, or anything that would make it store or log request content contrary to its data statement |
| **Hosted endpoint `mcp.catpilot.ai`** | A bypass of the edge rules, a way to reach the origin directly, or a way to make it serve anything other than the generic defaults; please do not load-test it |
| **Deployment scripts** | Anything in `deploy/` that would expose the origin or a token |

## What's NOT in Scope

- Vulnerabilities in AI assistants themselves → report to GitHub, Cursor, Windsurf, etc.
- Issues with referenced tools → report to Azure, AWS, Terraform, etc.

## Recognition

We credit researchers who report valid vulnerabilities. Let us know if you'd like to be acknowledged in the fix commit.

---

We take security seriously—that's literally why this project exists. 🐾
