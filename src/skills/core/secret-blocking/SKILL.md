---
name: secret-blocking
description: Detects and blocks hardcoded secrets — API keys, tokens, private keys, and database connection strings — before they are written to disk, committed to git, or echoed to logs. Covers 40+ patterns across Stripe, AWS, GitHub, GitLab, OpenAI, Anthropic, Slack, Google, SendGrid, Mailgun, Square, Twilio, and generic credential formats. Apply on every file write, every diff review, and every shell command that emits configuration.
license: MIT
metadata:
  catpilot:
    id: secret-blocking
    version: 1.0.1
    severity: critical
    category: secrets
    applies_to:
      languages:
      - any
      frameworks:
      - any
      runtimes:
      - claude-code
      - cursor
      - openclaw
      - cline
      - aider
      - copilot
      - codex-cli
    control_mappings:
      soc2:
      - CC6.1
      - CC6.6
      - CC7.2
      pci_dss:
      - '3.4'
      - '3.5'
      - '3.6'
      - 8.2.1
      iso_27001:
      - A.9.4.3
      - A.10.1.1
      - A.10.1.2
      nist_csf:
      - PR.AC-1
      - PR.DS-1
      - PR.DS-5
      owasp_top_10:
      - A02:2021
      - A07:2021
    provenance:
      origin: catpilot
      incident_derived: false
    maintainers:
    - team: catpilot-security
    references:
    - https://owasp.org/www-project-top-ten/A02_2021-Cryptographic_Failures/
    - https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning
    - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
---
## When to apply

Apply on **every** code generation, file write, file edit, and diff review.
Apply also on shell commands the agent is about to execute that include
inline credentials, environment variable assignments, or `curl -H` headers.

This skill is one of the always-on critical skills. It is cheap to evaluate
(regex over the diff or the proposed write), and the cost of a false negative
is a leaked credential that ends up in git history forever.

## Why

A hardcoded secret in a public repository has, on average, been scraped within
minutes of the push. Rotation is required even if the commit is deleted —
git history is forever, and bots monitor force-pushes too. Detection at the
agent layer, before the file write, is the cheapest place to catch this.

## Rules

- **[critical]** Never write a literal secret into source code, config files,
  comments, test fixtures, or documentation.
- **[critical]** Never echo a secret in a shell command the agent intends to
  run (e.g. `curl -H "Authorization: Bearer sk-ant-..."`). Use environment
  variables.
- **[critical]** Never paste a secret into a commit message, PR description,
  or issue body.
- **[high]** Never write `.env` files containing real secrets. Generate
  `.env.example` with placeholder values instead, and ensure `.env` is in
  `.gitignore`.
- **[high]** Never include a secret in a log statement, even at DEBUG level.
- **[medium]** Prefer secret managers (AWS Secrets Manager, Azure Key Vault,
  Google Secret Manager, HashiCorp Vault, Doppler, 1Password Secrets
  Automation) over `.env` for production deployments.
- **[medium]** When generating example code, use clearly fake placeholders
  (`your-api-key-here`, `REPLACE_ME`) rather than realistic-looking strings.

> [!agent] When you detect a match for any pattern in the "Detection
> patterns" table below, **stop**. Do not write the file. Surface the match
> to the user, name the provider, and propose the environment-variable or
> secret-manager remediation. Do not proceed without explicit confirmation
> that the value is a known-fake test fixture.

## Detection patterns

| Pattern (regex, case-sensitive) | Provider / Type | Example |
|---|---|---|
| `\bsk_live_[A-Za-z0-9]{20,}\b` | Stripe live secret key | `sk_live_51H...` |
| `\bsk_test_[A-Za-z0-9]{20,}\b` | Stripe test secret key | `sk_test_4eC39...` |
| `\bpk_live_[A-Za-z0-9]{20,}\b` | Stripe live publishable | `pk_live_51H...` |
| `\bpk_test_[A-Za-z0-9]{20,}\b` | Stripe test publishable | `pk_test_TYoo...` |
| `\brk_live_[A-Za-z0-9]{20,}\b` | Stripe restricted key | `rk_live_...` |
| `\bAKIA[0-9A-Z]{16}\b` | AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| `\bASIA[0-9A-Z]{16}\b` | AWS temp Access Key ID | `ASIAIOSFODNN7EXAMPLE` |
| `(?i)aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?` | AWS secret access key (`=` or `:`; `AWS_SECRET_ACCESS_KEY: ...` in YAML/compose/CI is the common shape) | 40-char base64 |
| `\bghp_[A-Za-z0-9]{36}\b` | GitHub personal token | `ghp_xxxxxxxx...` |
| `\bgho_[A-Za-z0-9]{36}\b` | GitHub OAuth token | `gho_xxxxxxxx...` |
| `\bghu_[A-Za-z0-9]{36}\b` | GitHub user-to-server | `ghu_xxxxxxxx...` |
| `\bghs_[A-Za-z0-9]{36}\b` | GitHub server-to-server | `ghs_xxxxxxxx...` |
| `\bghr_[A-Za-z0-9]{36}\b` | GitHub refresh token | `ghr_xxxxxxxx...` |
| `\bglpat-[A-Za-z0-9_\-]{20,}\b` | GitLab personal token | `glpat-xxxx...` |
| `\bsk-ant-(?:api\|admin)\d+-[A-Za-z0-9_\-]{80,}\b` | Anthropic API key | `sk-ant-api03-...` |
| `\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}\b` | OpenAI API key | `sk-proj-...` (56+ chars) |
| `\bxox[abprs]-[A-Za-z0-9-]{10,}\b` | Slack token | `xoxb-123-456-abc` |
| `\bAIza[0-9A-Za-z_\-]{35}\b` | Google API key | `AIzaSyD...` |
| `\bya29\.[A-Za-z0-9_\-]+\b` | Google OAuth access token | `ya29.a0AfH...` |
| `\bsq0[a-z]{3}-[A-Za-z0-9_\-]{20,}\b` | Square token | `sq0atp-...`, `sq0csp-...` |
| `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` | SendGrid API key | `SG.xxx.yyy` |
| `\bkey-[a-f0-9]{32}\b` | Mailgun API key | `key-xxxx...` |
| `\bSK[a-f0-9]{32}\b` | Twilio API SID | `SKxxxx...` |
| `\bAC[a-f0-9]{32}\b` | Twilio Account SID | `ACxxxx...` |
| `\bDOCKER_AUTH_CONFIG\s*=\s*` | Docker registry creds | env-style |
| `npm_[A-Za-z0-9]{36}` | npm access token | `npm_xxxx...` |
| `\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b` | JWT with payload | three-part `eyJ...` |
| `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----` | Private key (any) | RSA / EC / OpenSSH / PGP |
| `-----BEGIN CERTIFICATE-----` | TLS / x509 cert | Cert in source |
| `mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@` | MongoDB URI w/ password | `mongodb+srv://u:p@host` |
| `postgres(?:ql)?://[^:\s]+:[^@\s]+@` | Postgres URI w/ password | `postgres://u:p@host` |
| `mysql://[^:\s]+:[^@\s]+@` | MySQL URI w/ password | `mysql://u:p@host` |
| `redis://[^:\s]*:[^@\s]+@` | Redis URI w/ password | `redis://:pw@host` |
| `amqp(?:s)?://[^:\s]+:[^@\s]+@` | RabbitMQ URI w/ password | `amqps://u:p@host` |
| `(?i)\b(?:api[_-]?key\|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']` | Generic API key literal | `api_key="..."` |
| `(?i)\b(?:password\|passwd\|pwd)\s*[:=]\s*["'][^"']{6,}["']` | Hardcoded password | `password="..."` |
| `(?i)\b(?:secret\|client_secret)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']` | OAuth client secret | `client_secret="..."` |
| `(?i)\b(?:token\|auth_token\|access_token)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{16,}["']` | Auth tokens | `token="..."` |
| `(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{16,}\b` | Bearer in headers | `Authorization: Bearer ...` |
| `(?i)\baz(?:ure)?[_-]?(?:client[_-]?secret\|tenant[_-]?id)\s*[:=]\s*` | Azure credentials | inline assignments |
| `(?i)\bDATABASE_URL\s*=\s*[^$\s][^"'\s]+` | DB URL set to literal (not `${...}`) | `DATABASE_URL=postgres://...` |

> Patterns are intentionally conservative on length/charset to minimize
> false positives in test fixtures. When in doubt, ask the user.

## Negative examples

```python
# ❌ Stripe live key in source — leaks the moment this is pushed
import stripe
stripe.api_key = "sk_live_<REDACTED_FAKE_EXAMPLE_DO_NOT_SCAN>"
```

```typescript
// ❌ OpenAI key in a Next.js client component — also ships to the browser
const client = new OpenAI({
  apiKey: "sk-proj-AbCdEf123456789..."
});
```

```yaml
# ❌ AWS keys in a docker-compose.yml committed to the repo
services:
  api:
    environment:
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
      AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

```python
# ❌ Connection string with embedded password
DATABASE_URL = "postgres://app:hunter2@db.internal:5432/prod"
```

```bash
# ❌ Bearer token inlined into a curl invocation in a script
curl -H "Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  https://api.github.com/user
```

```dockerfile
# ❌ Secret baked into an image layer — visible to anyone with `docker history`
ENV STRIPE_API_KEY=sk_live_<REDACTED_FAKE_EXAMPLE_DO_NOT_SCAN>
```

```python
# ❌ Private key committed alongside test fixtures
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1...
-----END RSA PRIVATE KEY-----"""
```

## Remediation

### Pattern 1: read from environment

```python
# ✅ Python
import os
import stripe
stripe.api_key = os.environ["STRIPE_API_KEY"]
```

```typescript
// ✅ Node / TypeScript
const apiKey = process.env.STRIPE_API_KEY;
if (!apiKey) {
  throw new Error("STRIPE_API_KEY is not set");
}
```

```go
// ✅ Go
apiKey := os.Getenv("STRIPE_API_KEY")
if apiKey == "" {
    log.Fatal("STRIPE_API_KEY is not set")
}
```

### Pattern 2: `.env` for local dev, never committed

```bash
# .env  (must be in .gitignore — always check)
STRIPE_API_KEY=sk_live_...
DATABASE_URL=postgres://app:...@localhost:5432/dev
```

```gitignore
# .gitignore
.env
.env.*
!.env.example
```

```bash
# .env.example  (committed; placeholders only)
STRIPE_API_KEY=sk_live_REPLACE_ME
DATABASE_URL=postgres://app:REPLACE_ME@localhost:5432/dev
```

### Pattern 3: secret manager in production

```python
# ✅ AWS Secrets Manager
import boto3, json
sm = boto3.client("secretsmanager")
secret = json.loads(sm.get_secret_value(SecretId="prod/stripe")["SecretString"])
stripe.api_key = secret["api_key"]
```

```typescript
// ✅ Azure Key Vault
import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

const credential = new DefaultAzureCredential();
const client = new SecretClient(process.env.KEY_VAULT_URL!, credential);
const secret = await client.getSecret("stripe-api-key");
stripe.apiKey = secret.value!;
```

### Pattern 4: Docker build secrets (BuildKit)

```dockerfile
# syntax=docker/dockerfile:1.4
FROM node:20@sha256:abc123...
# ✅ Mounted at build time, never persisted in any layer
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm install
```

```bash
docker build --secret id=npmrc,src=$HOME/.npmrc -t myapp .
```

### Pattern 5: CI/CD — never echo, always mask

```yaml
# ✅ GitHub Actions
- name: Deploy
  env:
    STRIPE_API_KEY: ${{ secrets.STRIPE_API_KEY }}
  run: ./deploy.sh   # script reads from env, does not echo

# ❌ Never:
# run: echo "Deploying with key ${{ secrets.STRIPE_API_KEY }}"
```

### If a secret has already been committed

This is an incident. Run, in order:

1. **Rotate the credential immediately** at the provider. Assume it is already compromised.
2. **Audit usage logs** at the provider for unauthorized calls.
3. **Purge git history** with `git filter-repo` or BFG Repo-Cleaner. A new commit deleting the file does **not** remove the value from history.
4. **Force-push the rewritten history** (coordinate with the team — this rewrites everyone's clones).
5. **Invalidate cached copies**: GitHub forks, mirrors, CI caches, container registries that pulled the affected commit.

The full incident-response playbook is in the `incident-response` skill.

## References

- OWASP A02:2021 — Cryptographic Failures: <https://owasp.org/www-project-top-ten/A02_2021-Cryptographic_Failures/>
- OWASP A07:2021 — Identification and Authentication Failures: <https://owasp.org/www-project-top-ten/A07_2021-Identification_and_Authentication_Failures/>
- OWASP Secrets Management Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- GitHub Secret Scanning patterns: <https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns>
- AWS Secrets Manager: <https://docs.aws.amazon.com/secretsmanager/>
- Azure Key Vault: <https://learn.microsoft.com/en-us/azure/key-vault/>
- Google Secret Manager: <https://cloud.google.com/secret-manager/docs>
- HashiCorp Vault: <https://developer.hashicorp.com/vault/docs>
