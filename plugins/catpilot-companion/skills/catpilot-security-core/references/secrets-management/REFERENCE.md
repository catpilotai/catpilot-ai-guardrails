
## Why

Secrets fail in predictable ways. `secret-blocking` catches the
hardcoded patterns themselves — `sk-live-...`, `AKIA...`, private-key
blocks — and prevents them from being written into source files. But
secrets that are *correctly handled at the point of generation* still
fail in five other places:

1. **`.env` files committed by accident.** A developer adds `.env` to
   the repo for "just one quick test" and the secret is in git
   history forever, even after a follow-up commit removes it.
2. **CI logs echo the secret.** A workflow step does `echo $API_KEY`
   for "debugging," or a tool the workflow runs decides to print the
   environment, and the secret lands in a log that the CI provider
   retains for 30+ days and that anyone with read access to the repo
   can view.
3. **Secrets travel in URLs.** A database connection string with the
   password embedded ends up in error messages, in `SELECT pg_stat_*`
   output, in HTTP request logs from a reverse proxy, in browser
   history, in the agent's own tool-call transcripts.
4. **One secret for every environment.** The same `STRIPE_API_KEY`
   value is configured in dev, staging, and prod because there is no
   separation. A developer-laptop compromise becomes a production
   compromise.
5. **No rotation, no inventory.** When a secret leaks, nobody knows
   where it is used, what it grants access to, or how to revoke it.
   The leak persists because rotation requires hand-tracing every
   service that has the value pinned.

This skill governs the lifecycle around the secret value once it
exists: **stored in a secret manager, scoped per environment,
distributed via tooling that redacts, never logged, rotated on a
schedule, and revoked on exposure.**

## When to apply

Apply this skill **before** the agent recommends, writes, or commits
any of the following:

- `.env`, `.env.*`, `.envrc`, `secrets.yml`, `secrets.json`, or
  similar developer-environment secret files.
- `.gitignore`, repository setup scripts, or PR/CI configuration that
  determines what gets committed.
- CI workflow files (GitHub Actions, GitLab CI, CircleCI, Azure
  Pipelines, Buildkite, Jenkinsfile, Drone) — particularly any step
  that uses `echo`, `printenv`, `env`, `set`, or shell tracing
  (`set -x`).
- Container manifests, Helm charts, Kubernetes `Secret`/`ConfigMap`,
  Terraform/Pulumi/Bicep that defines runtime configuration.
- Application code that connects to a database, calls an external
  API, or reads configuration from the environment.
- Error-handling code paths that format exception messages, log
  request/response payloads, or post to external observability
  systems.
- Incident-response steps after a secret has been exposed.

This skill is the lifecycle counterpart to `secret-blocking`. Both
apply: `secret-blocking` stops the hardcoded value from being written
in the first place; `secrets-management` makes sure the *correctly
referenced* secret stays secret across its full lifecycle.

## Rules

### Rule 1 — `.env*` and credential files are gitignored before they exist

Every repository that uses environment-variable configuration must
include `.env*` patterns in `.gitignore` **before** the first `.env`
file is created. The canonical entry:

```gitignore
# Environment files — never commit
.env
.env.*
!.env.example
!.env.*.example

# Credential caches
.aws/
.azure/
.config/gcloud/
*.pem
*.key
*.p12
*.pfx
id_rsa
id_ed25519
```

`.env.example` (no values, only key names) is the documentation
artifact that gets committed. The real `.env` is never tracked.

When the agent creates a new project or adds environment-variable
configuration to an existing project, it verifies `.gitignore` has
these entries first and adds them if missing.

### Rule 2 — Secrets never appear in CI logs

CI workflows must satisfy all of the following:

- Secrets are referenced via the provider's secret store
  (`${{ secrets.STRIPE_API_KEY }}` on GitHub Actions, masked variables
  on GitLab/CircleCI/Azure Pipelines), never as plain variables.
- No step echoes a secret to stdout. `echo $SECRET`, `printenv`,
  `env`, `set`, and `set -x`/`bash -x` are prohibited in workflow
  scripts. If shell tracing is needed for debugging, it is scoped to
  the smallest possible block and the secret variable is `unset`
  before tracing enters scope.
- Third-party actions that consume secrets are pinned to a SHA
  (cross-references `supply-chain`) and read from the provider's
  secret store, not from plain inputs.
- Workflow logs are reviewed before being shared externally. Even
  with masking enabled, secrets can leak through transformations
  (base64 encoding, JSON serialization, error messages that include
  the value as a substring).

### Rule 3 — Secrets travel through process environment or a secret-fetch SDK, never through URLs or files

The runtime contract is:

- **Read** secrets from the process environment (`process.env.FOO`,
  `os.environ["FOO"]`, `ENV["FOO"]`) at startup, or from a
  vault-fetch SDK (AWS Secrets Manager, Azure Key Vault, GCP Secret
  Manager, HashiCorp Vault, Doppler, 1Password Connect).
- **Never** read secrets from filesystem paths the application user
  doesn't own, from configuration files that ship inside the
  container image, or from URLs that include the secret as a query
  parameter or path segment.

Database connection strings with embedded credentials
(`postgres://user:pass@host/db`) are constructed at runtime from
separate `DB_USER`/`DB_PASSWORD`/`DB_HOST` variables, not stored as
single concatenated strings. The connection string is built, used,
and goes out of scope; it is never logged, never returned in an
error, never serialized into a config dump.

### Rule 4 — Secrets are scoped per environment, not shared across them

`development`, `staging`, and `production` use **different secret
values** for every external service that issues per-environment
credentials. Stripe test keys (`sk_test_*`) for dev, separate Stripe
restricted keys for staging, full Stripe live keys (`sk_live_*`) for
prod and for prod only.

The agent must not:

- Copy a production secret into a developer-laptop `.env`.
- Reference a production secret from a staging or dev workflow.
- Generate code that reads from a single `API_KEY` variable when the
  service issues separate keys per environment.

When the agent encounters a single shared secret across environments
in an existing codebase, it surfaces the finding ("`STRIPE_API_KEY`
appears to be used in both staging and production configuration —
this should be split into environment-specific values") rather than
silently propagating the shape.

### Rule 5 — Errors and logs do not contain secret material

Exception messages, log lines, and observability payloads must not
include:

- Authorization headers (`Authorization: Bearer ...`).
- Cookies that carry session tokens.
- Connection strings that include credentials.
- Request/response bodies for endpoints that exchange credentials
  (login, OAuth callback, password reset, token refresh).
- The output of `process.env`, `os.environ`, `ENV.to_h`, or any
  full-environment dump.

When debugging an authentication failure, log the **decision** ("auth
failed: invalid signature") and a non-sensitive identifier (the user
ID, the request ID), not the credential that was rejected. When an
HTTP client logs a request, the agent ensures the logger has a
redaction policy for `Authorization`, `Cookie`, `Set-Cookie`,
`X-Api-Key`, and any custom auth header the service uses.

### Rule 6 — Exposure triggers rotation, not deletion

When a secret is exposed (committed to a public repo, posted in a
shared transcript, logged in CI, sent in a screenshot, leaked
through any channel), the response is **rotate the secret first,
clean up the leak second**.

The rotation flow:

1. Issue a new secret value at the source (Stripe dashboard, AWS IAM,
   GitHub PAT settings).
2. Update every system that holds the secret — secret manager,
   CI provider, runtime environment, paired developer laptops.
3. Verify the new value is in use (deploy or restart consumers, check
   logs for successful authentication with the new credential).
4. **Revoke the old value at the source.**
5. Only after revocation, clean up the leaked artifact (rewrite git
   history, delete logs, redact transcripts) — and only if cleanup
   adds value beyond revocation. A revoked secret in a public log is
   no longer a credential; the priority was revocation.

The agent must not "remediate" an exposed secret by deleting the file
or rewriting git history without first revoking the value. A deleted
file is a public-record secret; a revoked credential is a string.

## Negative examples

```bash
# ❌ Adding .env to the repo after the fact — already in history
git add .env && git commit -m "add config"
git rm .env && git commit -m "oops"   # secret is still in the history
```

```yaml
# ❌ GitHub Actions: secret echoed for "debugging"
- name: debug
  run: |
    echo "API_KEY=$STRIPE_API_KEY"
    env
    set -x
```

```yaml
# ❌ GitHub Actions: secret passed via plain input, not from secret store
- uses: some-org/deploy-action@v1
  with:
    api_key: sk_live_abc123xyz789
```

```python
# ❌ Connection string with embedded credentials, logged on error
DSN = "postgres://app_user:hunter2@db.prod.internal/app"
try:
    connect(DSN)
except Exception as e:
    log.error(f"db connect failed: dsn={DSN} err={e}")  # secret in logs
```

```javascript
// ❌ Logging the full request including Authorization
fetch(url, opts).then(res => {
  console.log("request", { url, opts, headers: opts.headers });
  // opts.headers.Authorization = "Bearer sk-ant-..."
});
```

```python
# ❌ Single shared secret across environments
STRIPE_KEY = os.environ["STRIPE_API_KEY"]
# dev and prod both read the same key — the test/live distinction is lost
```

```bash
# ❌ Production secret pulled into dev laptop
ssh prod-host 'cat /etc/app/secrets.env' > ~/Projects/myapp/.env
```

```bash
# ❌ Rotation done wrong: delete-then-rotate
git filter-branch --tree-filter 'rm -f .env' HEAD  # leak is now "removed"
# ... but the secret is still valid and the file is still in old clones
```

```python
# ❌ Returning an environment dump from a debug endpoint
@app.route("/debug/env")
def debug_env():
    return dict(os.environ)
```

```yaml
# ❌ Kubernetes Secret base64'd into the manifest, committed to git
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
data:
  STRIPE_API_KEY: c2tfbGl2ZV9hYmMxMjN4eXo3ODk=  # base64 is not encryption
```

## Remediation

### Project bootstrap: `.gitignore` and `.env.example`

```bash
# ✅ Before creating any .env file
cat >> .gitignore <<'EOF'
# Environment files
.env
.env.*
!.env.example
!.env.*.example

# Credential caches and key material
.aws/
.azure/
.config/gcloud/
*.pem
*.key
*.p12
*.pfx
id_rsa
id_ed25519
EOF

# ✅ Commit a key-only example file
cat > .env.example <<'EOF'
STRIPE_API_KEY=
DATABASE_URL=
REDIS_URL=
EOF
git add .gitignore .env.example
```

### GitHub Actions: secrets from the secret store, no echo

```yaml
# ✅ Reference from secrets.*, never echo
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: deploy
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          STRIPE_API_KEY: ${{ secrets.STRIPE_API_KEY }}
        run: |
          # No `set -x`, no `env`, no `echo $SECRET`.
          terraform apply -auto-approve
```

### Vault-backed runtime fetch

```python
# ✅ Fetch at startup from a vault SDK, hold in memory only
import boto3, json
client = boto3.client("secretsmanager", region_name="us-east-1")
def _load_secret(name: str) -> dict:
    resp = client.get_secret_value(SecretId=name)
    return json.loads(resp["SecretString"])

_SECRETS = _load_secret("prod/app/v1")
STRIPE_KEY = _SECRETS["stripe_api_key"]
DB_PASSWORD = _SECRETS["db_password"]
# Build the DSN at use-time, never log it
def get_dsn() -> str:
    return f"postgres://{_SECRETS['db_user']}:{_SECRETS['db_password']}@{_SECRETS['db_host']}/{_SECRETS['db_name']}"
```

### Connection string built from parts, logged without credentials

```python
# ✅ Compose the DSN, redact for logging
import urllib.parse as up
def build_dsn(user, password, host, db):
    return f"postgres://{user}:{up.quote(password)}@{host}/{db}"

def redacted_dsn(dsn: str) -> str:
    parsed = up.urlparse(dsn)
    return parsed._replace(netloc=f"{parsed.username}:***@{parsed.hostname}").geturl()

dsn = build_dsn(USER, PASSWORD, HOST, DB)
log.info("connecting to db", extra={"dsn": redacted_dsn(dsn)})
```

### Per-environment secret separation

```yaml
# ✅ Stripe test keys in dev/staging, live keys only in prod
# .env.development.example
STRIPE_API_KEY=sk_test_<set-in-dev-vault>

# .env.production.example
STRIPE_API_KEY=sk_live_<set-in-prod-vault>
```

### Logger with redaction policy

```python
# ✅ structlog redaction example
import structlog
SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie",
                  "x-api-key", "password", "token", "secret"}

def redact_processor(_, __, event_dict):
    for k in list(event_dict.keys()):
        if k.lower() in SENSITIVE_KEYS:
            event_dict[k] = "[REDACTED]"
    return event_dict

structlog.configure(processors=[redact_processor, structlog.processors.JSONRenderer()])
```

### Incident response: rotate-then-clean

```text
1. New value issued:
   - Stripe dashboard → Developers → API keys → "+ Create restricted key"
   - Copy new value into the production secret manager
2. Consumers updated:
   - Trigger redeploy of every service that reads STRIPE_API_KEY
   - Confirm logs show successful Stripe calls with the new key
3. Old value revoked:
   - Stripe dashboard → revoke the leaked key
4. Cleanup (optional, after revocation):
   - Rewrite git history if the leak is in a private repo and the
     history rewrite is operationally feasible
   - File a request with the CI provider to purge logs containing
     the value
   - Redact the value from any shared transcript or ticket
```

## Production detection heuristics

Treat the secret-handling context as production-class (escalating the
protocol) when **any** of these match:

- Variable names contain `LIVE`, `PROD`, `PRODUCTION`, or known
  prod-only patterns (`sk_live_`, AWS IAM role names containing
  `prod`).
- The repository, branch, or workflow is named `main`, `master`,
  `release/*`, `production`, or `prod*`.
- The runtime target is a production hostname pattern (cross-
  references `cloud-cli-safety`, `database-safety`, `docker-safety`).
- The secret has documented compliance scope (PCI cardholder data,
  HIPAA PHI, SOC2 control owner).

If any signal matches, all six rules apply without exception, and
Rule 6 (exposure response) requires the user to confirm rotation has
completed before cleanup begins.

## References

- OWASP Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP Insecure Storage of Sensitive Information — https://owasp.org/www-community/vulnerabilities/Insecure_Storage_of_Sensitive_Information
- GitHub Actions security: using secrets — https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
- Azure Key Vault best practices — https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices
- AWS Secrets Manager rotation — https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
- HashiCorp Vault patterns — https://developer.hashicorp.com/vault/tutorials/recommended-patterns
- 12-factor app: config — https://12factor.net/config
