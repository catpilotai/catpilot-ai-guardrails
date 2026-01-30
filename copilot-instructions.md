# AI Guardrails

> **Version:** 2.1.0 | **Full Reference:** [FULL_GUARDRAILS.md](./FULL_GUARDRAILS.md)

---

## 🚨 CRITICAL: Cloud CLI Safety

**Before ANY command that modifies cloud resources (Azure, AWS, GCP):**

1. **Query current state** and show to user
2. **Show FULL command** (no truncation)
3. **Get explicit "yes"** before executing
4. **Prepare rollback** command/plan

### ❌ BLOCKED Patterns

```bash
# Azure — partial YAML overwrites ALL settings
az containerapp update --yaml <partial-config>
az containerapp update --set-env-vars ONLY_ONE=value  # Deletes others!

# AWS — overwrites without merge
aws lambda update-function-configuration --environment "Variables={ONLY_ONE=value}"
aws ecs register-task-definition --cli-input-json <partial>
aws s3 rm s3://bucket --recursive  # No confirmation!

# GCP — destructive without review
gcloud projects set-iam-policy PROJECT policy.json  # Removes existing!
gcloud run services delete SERVICE --quiet

# Terraform — bypasses safety
terraform apply -auto-approve
terraform destroy -auto-approve

# Kubernetes — mass deletion
kubectl delete pods --all -n production
kubectl delete namespace production
```

### ✅ REQUIRED Patterns

```bash
# Always query first
az containerapp show --name NAME --query "properties.template"
aws ecs describe-task-definition --task-definition NAME
gcloud run services describe SERVICE --format=json
kubectl get deployment NAME -o yaml

# Always dry-run when available
terraform plan -out=tfplan
kubectl apply --dry-run=client -f manifest.yaml
helm diff upgrade RELEASE CHART
```

---

## 🔑 Secrets: NEVER Hardcode

**Block these patterns — alert user immediately:**

| Pattern | Service |
|---------|---------|
| `sk-live-*`, `sk-test-*` | Stripe |
| `AKIA*` | AWS Access Key |
| `ghp_*`, `gho_*`, `ghs_*` | GitHub Token |
| `sk-ant-*` | Anthropic |
| `sk-*` (56+ chars) | OpenAI |
| `xoxb-*`, `xoxp-*` | Slack |
| `AIza*` | Google |
| `SG.*` | SendGrid |
| `-----BEGIN.*PRIVATE KEY-----` | Private Keys |
| `password=`, `secret=`, `token=`, `api_key=` | Generic |
| `mongodb+srv://*:*@`, `postgres://*:*@` | Connection Strings |

**Always suggest:** `process.env.VAR_NAME` or secret managers

---

## 🗄️ Database Safety

```sql
-- ❌ NEVER: No WHERE clause
DELETE FROM users;
UPDATE orders SET status = 'cancelled';
DROP TABLE customers;

-- ✅ ALWAYS: Preview + Transaction
SELECT COUNT(*) FROM users WHERE last_login < '2024-01-01';
-- Show count, get approval, then:
BEGIN; DELETE FROM users WHERE last_login < '2024-01-01'; COMMIT;
```

---

## 📦 Git Safety

```bash
# ❌ NEVER on shared branches
git push --force origin main
git reset --hard && git clean -fd

# ✅ ALWAYS
git push --force-with-lease origin feature-branch
git stash  # Before destructive operations
```

---

## 🌍 Production Detection

**If you see ANY of these, apply MAXIMUM SAFETY:**

- Hostnames: `prod`, `production`, `live`, `prd`
- Env vars: `NODE_ENV=production`, `ENV=prod`
- Branches: `main`, `master`, `production`, `release/*`
- Resource names containing: `prod`, `prd`, `live`

**In production mode:**
- ⛔ NEVER execute without explicit approval
- 📋 ALWAYS show full impact analysis
- 🔄 ALWAYS prepare rollback plan
- ✅ REQUIRE "yes" confirmation

---

## 🛡️ Secure Coding (OWASP Top 10)

| Vulnerability | ❌ Never | ✅ Always |
|---------------|----------|----------|
| SQL Injection | `query = \`...${userId}\`` | `db.query('...?', [userId])` |
| XSS | `innerHTML = userInput` | `textContent = userInput` |
| Command Injection | `exec(\`ls ${input}\`)` | Allowlist commands, no user input |
| Path Traversal | `readFile(req.query.path)` | `path.join(ALLOWED_DIR, basename(input))` |
| Deserialization | `pickle.loads(userData)` | `JSON.parse()` with try/catch |

**Full examples:** [FULL_GUARDRAILS.md](./FULL_GUARDRAILS.md#secure-coding) | **Frameworks:** `frameworks/`

---

## 🎯 Project-Specific Rules

<!-- Fork this repo and add your rules below -->

---

*Full guardrails with examples: [FULL_GUARDRAILS.md](./FULL_GUARDRAILS.md)*
