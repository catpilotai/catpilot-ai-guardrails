# AI Safety Guidelines — Full Reference

> **Version:** 2.1.0  
> **Last Updated:** January 23, 2026  
> **Condensed Version:** [copilot-instructions.md](./copilot-instructions.md)

---

## 🔒 CRITICAL: Azure CLI Safety Protocol

**BEFORE executing ANY Azure CLI command that modifies resources, you MUST:**

1. **Query current state** and show it to the user
2. **Show the COMPLETE command** (no truncation)
3. **List ALL fields that will change** (CPU, memory, env vars, probes)
4. **Prepare a rollback command** with specific revision name
5. **Get explicit "yes"** from user before proceeding
6. **Verify changes after execution** (compare before/after)

### ❌ NEVER Do This (Azure)

```bash
# DANGEROUS: Partial YAML resets unspecified fields to defaults
az containerapp update --yaml <partial-config.yaml>

# DANGEROUS: This DELETES all other env vars
az containerapp update --set-env-vars ONLY_ONE_VAR=value

# DANGEROUS: Missing resource specs resets CPU/memory to defaults
az containerapp update --name myapp --image newimage:latest
```

### ✅ Always Do This (Azure)

```bash
# SAFE: Query current state first
az containerapp show \
  --name <name> \
  --resource-group <rg> \
  --query "properties.template.containers[0]"

# SAFE: Include ALL resource specifications
az containerapp update \
  --name <name> \
  --resource-group <rg> \
  --cpu 2.0 \
  --memory 4Gi \
  --set-env-vars VAR1=val1 VAR2=val2 [ALL existing vars]
```

### Rollback Template (Azure)

Always prepare this before making changes:

```bash
az containerapp revision activate \
  --name <name> \
  --resource-group <rg> \
  --revision <previous-revision-name>
```

---

## 🔒 CRITICAL: AWS CLI Safety Protocol

**BEFORE executing ANY AWS CLI command that modifies resources, you MUST:**

1. **Query current state** and show it to the user
2. **Show the COMPLETE command** (no truncation)
3. **List ALL fields that will change**
4. **Prepare a rollback plan** (previous task definition, snapshot ID, etc.)
5. **Get explicit "yes"** from user before proceeding
6. **Verify changes after execution** (compare before/after)

### ❌ NEVER Do This (AWS)

```bash
# DANGEROUS: Deletes without confirmation in scripts
aws s3 rm s3://bucket-name --recursive

# DANGEROUS: Force delete non-empty bucket
aws s3 rb s3://bucket-name --force

# DANGEROUS: Overwrites entire task definition, losing existing config
aws ecs register-task-definition --cli-input-json <partial-config.json>

# DANGEROUS: Updates function config without preserving existing env vars
aws lambda update-function-configuration --function-name myFunc --environment "Variables={ONLY_ONE=value}"

# DANGEROUS: Deletes all versions/aliases
aws lambda delete-function --function-name myFunc

# DANGEROUS: Terminates instances without confirmation
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0

# DANGEROUS: Modifies security group without showing current rules
aws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr 0.0.0.0/0
```

### ✅ Always Do This (AWS)

```bash
# SAFE: Query current state first (ECS)
aws ecs describe-task-definition --task-definition myapp --query 'taskDefinition'
aws ecs describe-services --cluster mycluster --services myservice

# SAFE: Query current state first (Lambda)
aws lambda get-function-configuration --function-name myFunc

# SAFE: Query current state first (EC2)
aws ec2 describe-instances --instance-ids i-xxx
aws ec2 describe-security-groups --group-ids sg-xxx

# SAFE: Query current state first (S3)
aws s3 ls s3://bucket-name --recursive | head -20

# SAFE: Use --dry-run where available
aws ec2 run-instances --dry-run ...

# SAFE: For Lambda env vars, MERGE with existing
EXISTING=$(aws lambda get-function-configuration --function-name myFunc --query 'Environment.Variables')
# Then merge and update with ALL vars
```

### Rollback Templates (AWS)

**ECS - Rollback to previous task definition:**
```bash
# List recent task definitions
aws ecs list-task-definitions --family-prefix myapp --sort DESC --max-items 5

# Update service to previous revision
aws ecs update-service --cluster mycluster --service myservice --task-definition myapp:PREVIOUS_VERSION
```

**Lambda - Rollback using alias:**
```bash
# If using aliases, point to previous version
aws lambda update-alias --function-name myFunc --name prod --function-version PREVIOUS

# Or republish previous version
aws lambda publish-version --function-name myFunc --description "Rollback"
```

**EC2 - Restore from snapshot:**
```bash
# Create volume from snapshot
aws ec2 create-volume --snapshot-id snap-xxx --availability-zone us-east-1a
```

---

## 🔑 Secret Handling

- **NEVER** hardcode secrets, API keys, tokens, or passwords
- **ALWAYS** use environment variables or secret managers
- **STOP and alert the user** if you see patterns like:
  - `sk-live-`, `sk-test-` (Stripe)
  - `api_key=`, `apikey=`
  - `password=`, `secret=`, `token=`
  - `-----BEGIN PRIVATE KEY-----`
  - `AKIA` (AWS access keys)
  - `AZURE_` prefixed secrets
  - Connection strings with embedded credentials

**Instead of:**
```typescript
const API_KEY = "sk-live-abc123xyz789";
```

**Suggest:**
```typescript
const API_KEY = process.env.STRIPE_API_KEY;
```

---

## 📦 Dependency Rules

- Check `npm audit` or `pip-audit` before adding new dependencies
- Flag any package with known critical vulnerabilities
- Prefer well-maintained packages with recent updates

---

## 🚨 Why These Rules Exist

Imagine an AI assistant helping update a production container's health probes. It generates a YAML file with just the probe configuration and runs:

```bash
az containerapp update --yaml probes-only.yaml
```

The result? The CLI interprets missing fields as "reset to defaults":
- Production CPU drops from 2.0 to 0.5 cores (75% reduction)
- Memory drops from 4GB to 1GB (75% reduction)
- **All environment variables are deleted** (including secrets)
- Service goes down until manually restored

This isn't hypothetical—it's a common failure pattern when cloud CLIs receive partial configurations. These guardrails prevent such disasters on **any cloud platform**.

---

## 🔒 CRITICAL: GCP CLI Safety Protocol

**BEFORE executing ANY `gcloud` command that modifies resources, you MUST:**

1. **Query current state** and show it to the user
2. **Show the COMPLETE command** (no truncation)
3. **List ALL fields that will change**
4. **Prepare a rollback plan**
5. **Get explicit "yes"** from user before proceeding
6. **Verify changes after execution**

### ❌ NEVER Do This (GCP)

```bash
# DANGEROUS: Deletes all versions without confirmation
gcloud app versions delete --all --quiet

# DANGEROUS: Overwrites ALL IAM bindings (removes existing)
gcloud projects set-iam-policy PROJECT_ID policy.json

# DANGEROUS: Deletes Cloud Run service immediately
gcloud run services delete SERVICE_NAME --quiet

# DANGEROUS: Deletes all objects in bucket
gsutil rm -r gs://bucket-name/**

# DANGEROUS: Updates with partial config
gcloud run services update SERVICE --set-env-vars ONLY_ONE=value
```

### ✅ Always Do This (GCP)

```bash
# SAFE: Query before modifying
gcloud run services describe SERVICE_NAME --format=json

# SAFE: List before delete
gsutil ls gs://bucket-name/ | head -20

# SAFE: Use additive IAM (doesn't remove existing bindings)
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:email@example.com" \
  --role="roles/viewer"

# SAFE: For env vars, get existing first then include ALL
gcloud run services describe SERVICE --format='value(spec.template.spec.containers[0].env)'
```

### Rollback Templates (GCP)

**Cloud Run - Rollback to previous revision:**
```bash
# List revisions
gcloud run revisions list --service=SERVICE_NAME

# Route traffic to previous revision
gcloud run services update-traffic SERVICE_NAME --to-revisions=REVISION_NAME=100
```

**App Engine - Rollback:**
```bash
# List versions
gcloud app versions list --service=default

# Route traffic to previous version
gcloud app services set-traffic default --splits=PREVIOUS_VERSION=1
```

---

## 🏗️ Infrastructure as Code Safety

### Terraform

**ALWAYS run `terraform plan` before `terraform apply`:**

```bash
# SAFE: Review changes first
terraform plan -out=tfplan
# Show plan to user, get approval
terraform apply tfplan
```

### ❌ NEVER Do This (Terraform)

```bash
# DANGEROUS: Skips confirmation, can destroy resources
terraform apply -auto-approve

# DANGEROUS: Destroys everything without review
terraform destroy -auto-approve

# DANGEROUS: Removes state without destroying resources (orphans them)
terraform state rm <resource>
```

### ✅ Always Do This (Terraform)

```bash
# SAFE: Always plan first
terraform plan -out=tfplan

# SAFE: Target specific resources when needed
terraform plan -target=aws_instance.example

# SAFE: Use workspaces for environment isolation
terraform workspace select staging
```

### Pulumi / CloudFormation / Bicep

Same principle applies:
- Always preview/plan changes before applying
- Never use `--yes` or `-auto-approve` flags without user consent
- Show the full diff to the user before proceeding

---

## 🗄️ Database Safety Protocol

### SQL Execution Rules

**BEFORE running ANY SQL that modifies data:**

1. Run as SELECT first to preview affected rows
2. Show count of affected rows to user
3. Get explicit approval
4. Wrap in transaction with rollback option

### ❌ NEVER Do This (SQL)

```sql
-- DANGEROUS: No WHERE clause affects ALL rows
DELETE FROM users;
UPDATE orders SET status = 'cancelled';

-- DANGEROUS: DROP without confirmation
DROP TABLE customers;
DROP DATABASE production;

-- DANGEROUS: TRUNCATE is not transactional in most DBs
TRUNCATE TABLE audit_logs;
```

### ✅ Always Do This (SQL)

```sql
-- SAFE: Always preview first
SELECT COUNT(*) FROM users WHERE last_login < '2023-01-01';
-- Show count, get approval

-- SAFE: Use transactions
BEGIN TRANSACTION;
UPDATE orders SET status = 'cancelled' WHERE created_at < '2024-01-01';
-- Show affected rows: "Updated 150 rows"
-- Wait for approval
COMMIT;  -- or ROLLBACK;

-- SAFE: Backup before destructive operations
CREATE TABLE users_backup_20260123 AS SELECT * FROM users;
```

### Migration Safety

- **NEVER** run migrations directly on production without testing on staging
- **ALWAYS** backup database before migrations
- **ALWAYS** have a rollback migration ready
- Use migration tools with dry-run options when available

---

## ☸️ Kubernetes Safety Protocol

### ❌ NEVER Do This (kubectl)

```bash
# DANGEROUS: Deletes all pods in namespace
kubectl delete pods --all -n production

# DANGEROUS: Force applies without review
kubectl apply -f manifest.yaml --force

# DANGEROUS: Scales to zero without confirmation
kubectl scale deployment myapp --replicas=0

# DANGEROUS: Deletes namespace (and everything in it)
kubectl delete namespace production

# DANGEROUS: Edits live resources directly
kubectl edit deployment myapp -n production
```

### ✅ Always Do This (kubectl)

```bash
# SAFE: Dry-run first
kubectl apply -f manifest.yaml --dry-run=client -o yaml

# SAFE: Diff before applying
kubectl diff -f manifest.yaml

# SAFE: Query before modifying
kubectl get deployment myapp -n production -o yaml > before.yaml

# SAFE: Use --dry-run for destructive commands
kubectl delete pod mypod --dry-run=client
```

### Helm Safety

```bash
# SAFE: Always diff before upgrade
helm diff upgrade myrelease mychart/

# SAFE: Use --dry-run
helm upgrade myrelease mychart/ --dry-run

# SAFE: Keep history for rollbacks
helm upgrade myrelease mychart/ --history-max=10

# Rollback if needed
helm rollback myrelease 1
```

---

## 📦 Git Safety Protocol

### ❌ NEVER Do This (Git)

```bash
# DANGEROUS: Rewrites history on shared branches
git push --force origin main

# DANGEROUS: Discards all local changes permanently
git reset --hard HEAD
git clean -fd

# DANGEROUS: Deletes remote branch without confirmation
git push origin --delete feature-branch

# DANGEROUS: Amends commits already pushed
git commit --amend && git push --force
```

### ✅ Always Do This (Git)

```bash
# SAFE: Force-with-lease prevents overwriting others' work
git push --force-with-lease origin feature-branch

# SAFE: Stash before destructive operations
git stash
git reset --hard HEAD

# SAFE: Verify branch exists before deletion
git branch -r | grep feature-branch
# Get confirmation, then delete

# SAFE: Create backup branch before rebasing
git branch backup-branch
git rebase main
```

### Protected Branches

- **NEVER** force push to `main`, `master`, `production`, or `release/*`
- **ALWAYS** create PR/MR for changes to protected branches
- **ALWAYS** verify you're on the correct branch before pushing

---

## 🔑 Expanded Secret Detection

**If you see ANY of these patterns, STOP and alert the user:**

| Pattern | Type | Example |
|---------|------|---------|
| `sk-live-*`, `sk-test-*` | Stripe API Key | `sk-live-abc123...` |
| `pk-live-*`, `pk-test-*` | Stripe Publishable Key | `pk-live-abc123...` |
| `AKIA*` | AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| `ghp_*`, `gho_*`, `ghu_*`, `ghs_*` | GitHub Token | `ghp_xxxxxxxxxxxx` |
| `gitlab-*-token` | GitLab Token | `glpat-xxxxxxxxxx` |
| `xoxb-*`, `xoxp-*`, `xoxa-*` | Slack Token | `xoxb-123-456-abc` |
| `sq0atp-*`, `sq0csp-*` | Square API Key | `sq0atp-xxxxx` |
| `SG.*` | SendGrid API Key | `SG.xxxxxx.yyyyyy` |
| `key-*` | Mailgun API Key | `key-xxxxxxxxxx` |
| `sk-ant-*` | Anthropic API Key | `sk-ant-api03-...` |
| `sk-*` (56+ chars) | OpenAI API Key | `sk-proj-xxxxxx...` |
| `AIza*` | Google API Key | `AIzaSyDxxxxx...` |
| `-----BEGIN.*PRIVATE KEY-----` | Private Key | RSA/EC/PGP keys |
| `-----BEGIN CERTIFICATE-----` | Certificate | SSL/TLS certs |
| `mongodb+srv://*:*@` | MongoDB URI | Connection string with password |
| `postgres://*:*@` | PostgreSQL URI | Connection string with password |
| `mysql://*:*@` | MySQL URI | Connection string with password |
| `redis://:*@` | Redis URI | Connection string with password |
| `amqp://*:*@` | RabbitMQ URI | Connection string with password |
| `api_key=`, `apikey=`, `api-key=` | Generic API Key | Various services |
| `password=`, `passwd=`, `pwd=` | Passwords | Hardcoded passwords |
| `secret=`, `client_secret=` | Secrets | OAuth client secrets |
| `token=`, `auth_token=`, `access_token=` | Tokens | Various auth tokens |
| `bearer *` | Bearer Token | Authorization headers |

### Remediation

**Instead of hardcoding:**
```typescript
const API_KEY = "sk-live-abc123xyz789";  // ❌ NEVER
```

**Use environment variables:**
```typescript
const API_KEY = process.env.STRIPE_API_KEY;  // ✅ SAFE
```

**Or use secret managers:**
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager
- HashiCorp Vault
- Doppler, 1Password Secrets Automation

---

## 📦 Dependency Security

### Before Adding Dependencies

1. **Check for known vulnerabilities:**
   ```bash
   # Node.js
   npm audit
   
   # Python
   pip-audit
   
   # Ruby
   bundle audit
   
   # Go
   govulncheck ./...
   ```

2. **Verify package legitimacy:**
   - Check download counts (npm, PyPI)
   - Verify maintainer reputation
   - Look for typosquatting (e.g., `lodash` vs `1odash`, `requests` vs `request`)
   - Check last publish date (abandoned packages are risky)

### High-Risk Dependency Patterns

| Pattern | Risk |
|---------|------|
| Package with < 100 weekly downloads | May be typosquat |
| No updates in > 2 years | Likely unmaintained |
| Single maintainer, no org backing | Bus factor risk |
| Excessive permissions requested | Potential malware |
| Name similar to popular package | Typosquatting attempt |

### When AI Suggests a Dependency

- Check if newer version exists
- Verify it's the official package (correct author/org)
- Prefer packages with TypeScript types, active maintenance
- Consider native/stdlib alternatives when possible

---

## 🔄 CI/CD Pipeline Safety

### GitHub Actions

**NEVER do this in workflows:**
```yaml
# DANGEROUS: Exposes secrets in logs
run: echo ${{ secrets.API_KEY }}

# DANGEROUS: Uses potentially compromised action at floating tag
uses: random-user/untrusted-action@main

# DANGEROUS: Pulls from untrusted registries
run: docker pull untrusted-registry.com/image
```

**Safe patterns:**
```yaml
# SAFE: Pin actions to full SHA
uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab  # v4.1.0

# SAFE: Use GITHUB_TOKEN with minimal permissions
permissions:
  contents: read
  pull-requests: write

# SAFE: Mask sensitive outputs
run: echo "::add-mask::$SECRET_VALUE"
```

### Deployment Safety

- **NEVER** deploy directly to production without staging test
- **ALWAYS** require approval gates for production deployments
- **ALWAYS** use feature flags for risky changes
- **ALWAYS** have automated rollback triggers (health checks)

---

## 🛡️ Secure Coding — Detailed Examples {#secure-coding}

### SQL Injection (CWE-89)

```javascript
// ❌ NEVER — String concatenation/interpolation
const query = `SELECT * FROM users WHERE id = ${userId}`
const query = "SELECT * FROM users WHERE id = '" + userId + "'"

// ✅ ALWAYS — Parameterized queries
// Node.js (mysql2)
db.query('SELECT * FROM users WHERE id = ?', [userId])

// Python (psycopg2)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// Java (PreparedStatement)
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
```

### Cross-Site Scripting / XSS (CWE-79)

```javascript
// ❌ NEVER — Raw user input in HTML
element.innerHTML = userInput
document.write(userInput)
$('#div').html(userInput)  // jQuery

// ✅ ALWAYS — Auto-escaped methods
element.textContent = userInput
$('#div').text(userInput)  // jQuery

// When HTML is needed, sanitize first
import DOMPurify from 'dompurify'
element.innerHTML = DOMPurify.sanitize(userInput)
```

### Command Injection (CWE-78)

```javascript
// ❌ NEVER — User input in shell commands
exec(`ls ${userInput}`)
os.system(f"grep {pattern} file.txt")
subprocess.call(f"echo {user_input}", shell=True)

// ✅ ALWAYS — Avoid shell, use arrays
execFile('ls', ['-la', directory])  // No shell interpretation
subprocess.run(['grep', pattern, 'file.txt'])  // Python, no shell=True
```

### Path Traversal (CWE-22)

```javascript
// ❌ NEVER — Direct user input as path
fs.readFile(req.query.filename)
open(user_provided_path)

// ✅ ALWAYS — Validate and constrain to allowed directory
const safeName = path.basename(userInput)  // Strip directory components
const safePath = path.join(ALLOWED_DIR, safeName)

// Verify it's still within allowed directory
if (!safePath.startsWith(ALLOWED_DIR)) {
  throw new Error('Invalid path')
}
```

### Insecure Deserialization (CWE-502)

```python
# ❌ NEVER — Untrusted data in unsafe deserializers
pickle.loads(user_data)          # Python
yaml.load(user_data)             # Python (unsafe loader)
unserialize($user_data)          # PHP
ObjectInputStream.readObject()    # Java with untrusted input

# ✅ ALWAYS — Safe formats with validation
import json
data = json.loads(user_input)    # Safe, limited types

# If YAML needed, use safe loader
import yaml
data = yaml.safe_load(user_input)
```

### Server-Side Request Forgery / SSRF (CWE-918)

```javascript
// ❌ NEVER — Fetch arbitrary user-controlled URLs
const response = await fetch(req.query.url)
requests.get(user_provided_url)

// ✅ ALWAYS — Allowlist permitted hosts
const ALLOWED_HOSTS = ['api.stripe.com', 'api.github.com']

function safeFetch(url) {
  const parsed = new URL(url)
  if (!ALLOWED_HOSTS.includes(parsed.host)) {
    throw new Error('URL not allowed')
  }
  // Also block internal IPs: 127.0.0.1, 10.x, 172.16-31.x, 192.168.x
  return fetch(url)
}
```

---

## 🛡️ OWASP Top 10 Quick Checks

When generating code, verify against these common vulnerabilities:

| # | Vulnerability | AI Assistant Check |
|---|---------------|-------------------|
| A01 | **Broken Access Control** | Verify authorization on every endpoint, not just authentication |
| A02 | **Cryptographic Failures** | Use strong encryption (AES-256, RSA-2048+), no hardcoded keys |
| A03 | **Injection** | Parameterize ALL queries, sanitize ALL input |
| A04 | **Insecure Design** | Follow least privilege, defense in depth |
| A05 | **Security Misconfiguration** | No default credentials, disable debug in prod |
| A06 | **Vulnerable Components** | Check dependencies for CVEs before adding |
| A07 | **Auth Failures** | Enforce MFA, strong passwords, secure sessions |
| A08 | **Data Integrity Failures** | Verify signatures, use integrity checks |
| A09 | **Logging Failures** | Log security events, NEVER log secrets |
| A10 | **SSRF** | Validate and allowlist all external URLs |

**If generating code that handles user input, authentication, or external requests, explicitly verify these checks.**

---

## 🌍 Environment-Aware Safety

### Production Environment Indicators

If you detect ANY of these, apply **MAXIMUM SAFETY** mode:

**Hostnames/URLs containing:**
- `prod`, `production`, `live`, `prd`

**Environment variables:**
- `NODE_ENV=production`
- `ENVIRONMENT=prod` / `ENV=prod`
- `RAILS_ENV=production`
- `DJANGO_SETTINGS_MODULE=*.production`

**Branch names:**
- `main`, `master`, `production`, `release/*`

**Resource names containing:**
- `prod`, `prd`, `live`, `production`

### Maximum Safety Mode Rules

1. ⛔ **NEVER** execute destructive commands without explicit approval
2. 📋 **ALWAYS** show full impact analysis before changes
3. 🔄 **ALWAYS** prepare and show rollback plan
4. ✅ **REQUIRE** explicit "yes" or "approved" confirmation
5. 📸 **ALWAYS** capture before/after state for verification

### Development/Local Environment

If clearly in development (`localhost`, `dev` branch, `NODE_ENV=development`):
- Still warn about dangerous patterns
- Can execute read-only/query commands without approval
- Still require approval for destructive operations
- Remind user to test changes before applying to production

---

## 🎯 Project-Specific Rules

<!-- 
This section is intentionally minimal in the generic repo.
Fork this repo and add project-specific rules below if needed.
Example sections:
- Teams Bot rules
- Frontend/React rules  
- Backend/FastAPI rules
-->

---

*This file is automatically loaded by GitHub Copilot, Cursor, and other AI assistants when working in this repository.*
