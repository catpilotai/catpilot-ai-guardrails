---
name: pii-and-test-data
description: Block real customer data from appearing in test fixtures, code comments, documentation, debug output, or shared transcripts. Require synthetic generators (`faker`, `@faker-js/faker`, provider test cards), reserved test ranges (555 phone numbers, `@example.com` emails, RFC 5737 IPs), and redaction of PII/PHI/PCI from logs and error messages. Refuse to copy production rows into development environments under any framing.
license: MIT
metadata:
  catpilot:
    id: pii-and-test-data
    version: 1.0.1
    severity: high
    category: data-protection
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
      - CC6.7
      - C1.1
      - P3.1
      pci_dss:
      - '3.4'
      - 3.4.1
      - '6.4'
      - 6.4.3
      iso_27001:
      - A.8.2.3
      - A.14.3.1
      - A.18.1.4
      - A.18.1.5
      nist_csf:
      - PR.DS-5
      - PR.DS-1
      - PR.IP-6
      - DE.DP-2
      owasp_top_10:
      - A01:2021
      - A02:2021
      - A04:2021
    provenance:
      origin: catpilot
      incident_derived: false
    maintainers:
    - team: catpilot-security
    references:
    - https://docs.stripe.com/testing
    - https://www.faker.cloud/
    - https://www.rfc-editor.org/rfc/rfc2606
    - https://www.rfc-editor.org/rfc/rfc5737
    - https://gdpr.eu/data-protection-impact-assessment-template/
---

## Why

Production data carries legal, contractual, and operational
obligations that test environments are not designed to honor.
Every time a real customer record appears in a fixture file, a
comment, a screenshot, a chat transcript, or a debug log, the
organization picks up the same obligations for that copy as for
the original — without the controls that protect the original.

The failures this skill blocks share a common shape: **a real
customer's data ends up somewhere the customer's data was never
authorized to be**.

- A test fixture committed to git uses a real customer's email,
  phone, or address. The repository becomes a partial copy of the
  customer database, retained for the life of the project.
- A debug log includes a real request body — full names, SSN-like
  identifiers, payment-card-shaped numbers — and the log is
  shipped to a third-party observability vendor.
- A demo recording shows the production app with a real customer
  account loaded. The recording is shared on a public marketing
  page.
- "Just for testing," a developer pulls a row from the production
  `users` table into a local SQLite database. The local database
  is now production data without production controls.
- An error message embeds the user's email or phone for debugging.
  The error is logged, indexed, and surfaced in an analytics
  dashboard a customer-success team can search.

This is a tractable problem: every domain that uses real
identifiers has a reserved test range or synthetic-data tool. The
agent's job is to default to the synthetic option and refuse the
real one.

## When to apply

Apply this skill **before** the agent writes, recommends, or
commits any of the following:

- Test fixtures, factories, seed files, demo data, `db/seeds.rb`,
  `fixtures/`, `tests/fixtures/`, `__tests__/data/`, or any other
  data file consumed by an automated test or local dev environment.
- Code comments, docstrings, README examples, or documentation
  that includes an illustrative user record.
- Error messages, log lines, telemetry payloads, or anything
  shipped to an observability vendor.
- Screenshots, screen recordings, marketing assets, or anything
  shared outside the organization.
- Migration scripts, ETL pipelines, or anything moving rows
  between environments — particularly `prod` → anything-else.
- LLM prompts, fine-tuning datasets, evaluation suites, or RAG
  ingestion corpora.
- Bug-report templates and incident-response artifacts where
  reproducers might include real data.

This skill is the data-content counterpart to `database-safety`
(operations on rows), `secrets-management` (credential lifecycle),
and `secret-blocking` (credential patterns). All four apply
together — a fixture that contains both a real email and a real
API key fails this skill *and* `secret-blocking`.

## Rules

### Rule 1 — Test identifiers use reserved test ranges, never real values

For every field that has a reserved test range, the agent uses
that range by default:

| Field | Reserved range | Why |
|---|---|---|
| Email | `*@example.com`, `*@example.org`, `*@example.net` | RFC 2606 — reserved for documentation |
| Phone (US) | `555-01xx` block (e.g., `+1-415-555-0100`) | Reserved for fiction; never assigned |
| Domain | `example.com`, `example.org`, `example.net`, `*.test`, `*.invalid` | RFC 2606 — reserved |
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 — reserved for documentation |
| IPv6 | `2001:db8::/32` | RFC 3849 — reserved for documentation |
| Credit card | Provider test PANs (Stripe `4242 4242 4242 4242`, etc.) | Issuer test ranges — never authorize |
| SSN (US) | `000-00-0000` through `000-99-9999`, `666-*`, `9xx-*` | SSA-reserved ranges (never issued) |

Real values for any of these fields are prohibited even if the
agent believes the value is fictional. If the agent generates an
email address that "looks made up," it goes to `example.com`. If a
phone number is needed and the agent doesn't know whether the
number is real, the agent uses the `555-01xx` block.

### Rule 2 — Synthetic data comes from a generator, not from imagination

For names, addresses, dates of birth, and other identifiers
without a single reserved range, the agent uses a deterministic
synthetic-data generator rather than free-form invention:

| Language | Generator |
|---|---|
| Python | `faker` |
| Node.js | `@faker-js/faker` |
| Ruby | `faker` |
| Go | `gofakeit` / `go-faker/faker` |
| Java | `java-faker` / `datafaker` |
| .NET | `Bogus` |

Generators are preferred because they:

- Produce values flagged as obviously synthetic by tooling
  (downstream consumers can detect "this is faker output").
- Avoid the small but non-zero chance of "inventing" a real
  person's name + DOB combination.
- Make fixtures reproducible across runs when seeded.

### Rule 3 — No production data is copied into non-production environments

Direct copying of production rows into development, staging, demo,
test, or any environment with lower controls is prohibited. This
includes:

- `pg_dump prod | psql staging`
- `SELECT * FROM users INTO OUTFILE` followed by import elsewhere.
- A custom script that "anonymizes" production data by hashing
  names and emails (hashing is not anonymization — it preserves
  joinability and is reversible for low-entropy fields).
- Pulling a single row from the production database "just to
  reproduce a bug locally."

When realistic test data is needed, the agent uses the team's
documented subset/synthetic pipeline. If the team doesn't have
one, the agent surfaces that as a gap rather than silently
copying.

The only exception is a tightly-scoped, audited refresh from
production into a separate environment **specifically designed
to inherit production controls** (a "prod-mirror" staging
environment with the same SOC2/HIPAA/PCI scope). That refresh is
not run ad-hoc by the agent.

### Rule 4 — Errors and logs do not contain user-identifying data

Application logs, error messages, and telemetry payloads must not
contain:

- Email addresses (use the user ID instead).
- Phone numbers.
- Full names (first + last together).
- Postal addresses.
- Government identifiers (SSN, national ID, passport number,
  driver's license).
- Date of birth.
- Payment card numbers (full PAN), bank account numbers, routing
  numbers.
- Health information (diagnoses, medications, procedure codes).
- Precise geolocation (street-level lat/long).
- Authentication artifacts (cross-references `secrets-management`).

Where debugging requires correlating a log entry to a user, the
agent uses a stable internal identifier (`user_id`, `account_id`,
`request_id`, `trace_id`) and the consumer of the log resolves
the identifier to a user through an authenticated lookup if and
when needed.

For inspectability without exposure, the agent emits the **shape**
of the data ("email length 27, domain `corp.example.com`") rather
than the data itself.

### Rule 5 — Demos, recordings, and shared transcripts use synthetic accounts

Anything that leaves the organization's controlled environment —
demo videos, screenshots in blog posts, screen-shares with
prospects, training materials, conference talks, support
transcripts shared with vendors — uses synthetic test accounts
populated with synthetic data.

The agent does not record, screenshot, or share an interaction
with the production app loaded against a real customer account.
If asked to capture a flow that requires a logged-in user, the
agent first switches to a documented test account.

### Rule 6 — LLM prompts, fine-tuning sets, and RAG corpora are screened

Data ingested into a model — used as few-shot examples in a
prompt, included in a fine-tuning dataset, or chunked into a
vector store for RAG — is screened for PII/PHI/PCI before it goes
in. Once data is inside a model's training set or a vector index,
it cannot be reliably removed.

The screening pass:

- Strips email addresses, phone numbers, government identifiers,
  payment card numbers using a deterministic scrubber (Microsoft
  Presidio, AWS Comprehend Detect PII, Google DLP, or an internal
  equivalent).
- Replaces names with role tokens (`<USER>`, `<AGENT>`) where the
  identity is not load-bearing.
- Logs the scrubbing pass (what was redacted, how many tokens,
  which file) so a future audit can verify the input went through
  the scrubber.

The agent does not include raw customer transcripts, raw support
tickets, or raw email threads in a prompt or training set without
this pass running first.

## Negative examples

```python
# ❌ Real-looking PII in a fixture
USERS = [
    {"name": "John Smith", "email": "jsmith@gmail.com", "phone": "415-555-1234"},
    {"name": "Jane Doe", "email": "jane@acme.com", "ssn": "123-45-6789"},
]
```

```python
# ❌ Real credit card number, even "for testing"
CARD = "4532 7654 3210 9876"
```

```javascript
// ❌ Real-feeling email in a code comment / docstring
// Example: send a notification to john.smith@gmail.com
```

```python
# ❌ Logging the full user object on error
log.error(f"signup failed for user={user.__dict__}")
# user contains email, phone, dob, address
```

```python
# ❌ Error message embeds the email
raise ValueError(f"email {email} is already registered")
```

```bash
# ❌ Copying production rows into local dev
pg_dump $PROD_URL -t users --data-only | psql $DEV_URL

# ❌ "Just one row" copy
psql $PROD_URL -c "COPY (SELECT * FROM orders WHERE id = 12345) TO STDOUT" \
  | psql $DEV_URL -c "COPY orders FROM STDIN"
```

```python
# ❌ Hash-as-anonymization (still reversible/joinable)
df["email"] = df["email"].apply(lambda e: hashlib.sha256(e.encode()).hexdigest())
df.to_csv("dev_users.csv")
```

```python
# ❌ Real support transcript embedded in a fine-tuning JSONL
{"messages": [
    {"role": "user", "content": "hi this is jane.doe@realco.com, my order #4521 ..."},
    {"role": "assistant", "content": "Hi Jane, I see your order ..."}
]}
```

```bash
# ❌ Screen recording of the production app with a real customer loaded
# (no code snippet — surfaces as a policy violation in review)
```

## Remediation

### Test fixture with synthetic data (Python)

```python
# ✅ Synthetic and obviously so
from faker import Faker
fake = Faker()
Faker.seed(42)  # reproducible

USERS = [
    {
        "id": i,
        "name": fake.name(),
        "email": fake.safe_email(),           # reserved example domains, explicit
        "phone": f"+1-415-555-{100+i:04d}",   # 0100–0199 for range(100)
        "address": fake.address(),
        "dob": fake.date_of_birth().isoformat(),
    }
    for i in range(100)
]
```

### Provider test data for payments

```python
# ✅ Stripe test card numbers — never authorize real charges
STRIPE_TEST_CARDS = {
    "visa_success": "4242424242424242",
    "visa_declined": "4000000000000002",
    "visa_3ds":     "4000002500003155",
    # See https://docs.stripe.com/testing for the full set
}
```

### Logging with user_id, not email

```python
# ✅ Stable internal identifier, no PII
log.info("signup completed", extra={"user_id": user.id, "tenant_id": user.tenant_id})

# ✅ Shape of the input on validation failure, not the input itself
log.warn("email validation failed",
         extra={"length": len(email), "has_at": "@" in email})
```

### Error messages without PII

```python
# ✅ User-friendly message, no PII in the exception
raise BusinessError(
    code="email_already_registered",
    message="This email address is already registered.",
    # No email in the payload — the API client already has it
)
```

### Synthetic-data pipeline (subset + scrubbed)

```text
1. Subset:
   - SELECT ~1% of rows from each table, scoped to a small set of
     synthetic tenant IDs created in production specifically for
     this purpose (or to a documented internal-test tenant).
2. Scrub:
   - Run the subset through Presidio / Comprehend / DLP.
   - Replace emails with `<id>@example.com`, phones with
     `+1-415-555-NNNN`, names with faker output, postal addresses
     with faker output, payment card numbers with Stripe test
     PANs.
3. Verify:
   - Sample 1% of the scrubbed output. Confirm no real customer
     identifier survives.
4. Ship:
   - Materialize as a versioned dataset (S3 + manifest).
   - Refresh on a documented cadence.
```

### LLM input scrubbing

```python
# ✅ Presidio scrub before any prompt that includes user content
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def scrub_for_llm(text: str) -> tuple[str, list[dict]]:
    results = analyzer.analyze(text=text, language="en")
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text, [
        {"entity": r.entity_type, "start": r.start, "end": r.end}
        for r in results
    ]

scrubbed, log = scrub_for_llm(user_message)
# log_to_audit_trail(scrubbed=scrubbed, redactions=log)
prompt_llm(scrubbed)
```

### Bug reproducer using synthetic data

```python
# ✅ Reproduce the bug with faker-generated data rather than the
# real row, then attach the reproducer (not the row) to the ticket
def reproduce_bug_12345():
    user = User(
        email=fake.safe_email(),
        name=fake.name(),
        signup_at=datetime(2026, 5, 17, 14, 32),
    )
    # exercise the failing code path
    process_signup(user)
```

## Production detection heuristics

Treat the data context as production-class (escalating the
protocol) when **any** of these match:

- The source table, file, or dataset name contains `users`,
  `accounts`, `customers`, `members`, `patients`, `subscribers`,
  `payments`, `invoices`, `transactions`, `pii_*`, `phi_*`,
  `pci_*`.
- The source database, S3 bucket, or storage path contains
  `prod`, `production`, `live`, `customer`, `tenant`, or a
  customer/tenant identifier.
- The fields involved include email, phone, name, address, DOB,
  SSN/national ID, card number, bank account, diagnosis code,
  medication, prescription number, geolocation, or government
  identifier.
- The destination is anything outside the production environment
  (dev, staging, demo, test, marketing, vendor, support, AI/ML
  training).

If any signal matches, all six rules apply without exception, and
Rule 3 (no production-to-non-production copy) becomes a hard
refusal — the agent does not propose, generate, or run a copy
operation even if the user frames it as a one-off.

## References

- Stripe testing reference — https://docs.stripe.com/testing
- Faker (Python) — https://faker.readthedocs.io/
- @faker-js/faker (Node) — https://fakerjs.dev/
- RFC 2606 — Reserved Top Level DNS Names — https://www.rfc-editor.org/rfc/rfc2606
- RFC 5737 — IPv4 Address Blocks Reserved for Documentation — https://www.rfc-editor.org/rfc/rfc5737
- RFC 3849 — IPv6 Address Prefix Reserved for Documentation — https://www.rfc-editor.org/rfc/rfc3849
- Microsoft Presidio — https://microsoft.github.io/presidio/
- AWS Comprehend Detect PII — https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html
- Google Cloud DLP — https://cloud.google.com/dlp
- GDPR Data Protection Impact Assessment — https://gdpr.eu/data-protection-impact-assessment-template/
- HIPAA Safe Harbor de-identification — https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/
