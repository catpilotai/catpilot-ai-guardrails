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

This project is markdown files + a bash script. Security concerns include:

| Risk | Example |
|------|---------|
| **setup.sh vulnerabilities** | Command injection, path traversal |
| **Guardrail bypasses** | Dangerous patterns that slip through |
| **Harmful advice** | Rules that could cause damage if followed |

## What's NOT in Scope

- Vulnerabilities in AI assistants themselves → report to GitHub, Cursor, Windsurf, etc.
- Issues with referenced tools → report to Azure, AWS, Terraform, etc.

## Recognition

We credit researchers who report valid vulnerabilities. Let us know if you'd like to be acknowledged in the fix commit.

---

We take security seriously—that's literally why this project exists. 🐾
