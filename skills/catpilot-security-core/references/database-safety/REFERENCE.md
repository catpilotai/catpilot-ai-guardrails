
## Why

Database state is the asset that survives every deploy. Compute can be
rebuilt from images in minutes; rows cannot be rebuilt from anywhere except
the last backup. Most catastrophic AI-assisted incidents at the database
layer follow the same three shapes:

1. **A `DELETE` or `UPDATE` runs without a `WHERE` clause** because the
   model treated "delete the old test rows" as a sentence rather than a
   query. Every row in the table is touched in one statement and the
   transaction commits before anyone notices.
2. **A migration runs straight against production** with no dry-run, no
   staging dress rehearsal, no rollback file. The schema change succeeds
   on the structure but breaks an index, a foreign key, or an application
   assumption, and the only way back is point-in-time recovery.
3. **A query is built by string-concatenating user input** into SQL,
   producing a working feature that also produces an injection vector
   the first time an attacker sends a quote character.

These are not language-specific or framework-specific failures. They occur
in raw `psql`, in ORMs, in serverless functions calling RDS, in
`prisma db push --accept-data-loss`, and in `manage.py shell` one-liners.
This skill applies the same six-step protocol the cloud-cli-safety skill
applies to infrastructure: **never modify state you have not first
queried, counted, and shown to the user.**

## When to apply

Apply this skill **before** the agent runs, recommends, or commits any of
the following:

- Direct SQL execution against a real database (`psql`, `mysql`, `sqlcmd`,
  `sqlite3`, `mongo`, cloud SQL consoles, JDBC clients, `\copy`).
- ORM operations that translate to SQL writes — `INSERT`, `UPDATE`,
  `DELETE`, `MERGE`, `UPSERT`, `BULK INSERT`, `COPY FROM`.
- Schema operations — `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `RENAME`,
  `GRANT`, `REVOKE`.
- Migration commands — `alembic upgrade`, `prisma migrate`, `django
  migrate`, `rake db:migrate`, `knex migrate:latest`, `flyway migrate`,
  `liquibase update`, `goose up`, `dbmate up`, `sqlx migrate run`.
- Anywhere a query string is being built — raw SQL files, `cursor.execute`,
  `db.query`, `Sequelize.query`, `EntityManager.createNativeQuery`,
  template literals tagged as `sql\``.
- Bulk data operations against any environment named `prod`, `production`,
  `live`, `customer`, or sharing a connection string with one.

This skill does **not** replace your normal review for query correctness,
index choice, or transaction isolation level. It enforces the procedural
floor: query first, count first, transaction always, dry-run for
migrations, parameterize always.

## Rules

### Rule 1 — Verify the affected scope using the database's actual syntax

Standalone `DELETE` and `UPDATE` statements must have a restrictive predicate
unless the agent has explicitly confirmed with the user that the intent is
"all rows in this table." A missing `WHERE` is the single most common
cause of total-table loss in AI-assisted database work.

A `WHERE` token is not proof of a bounded change (`WHERE TRUE` still
affects all rows). For PostgreSQL `MERGE`, review the `ON` join and each
`WHEN ... AND` action condition, including `NOT MATCHED BY SOURCE`;
there is no top-level `WHERE` requirement. `TRUNCATE`/`DROP` require an
explicitly approved object scope, not a nonexistent `WHERE` clause.

The same rule applies through ORMs:

- Django: `Model.objects.all().delete()`, `Model.objects.update(...)`
  without a `.filter()` chain.
- SQLAlchemy: `session.query(Model).delete()` without `.filter()`,
  `session.execute(update(Model).values(...))` without `.where()`.
- Prisma: `prisma.model.deleteMany({})`, `prisma.model.updateMany({ data:
  {...} })` with an empty `where`.
- ActiveRecord: `Model.delete_all`, `Model.update_all(...)` without a
  scope.

Treat each of these as equivalent to `DELETE FROM model;` and apply the
same six-step protocol below.

### Rule 2 — Query before modify, show the count

Before any data-mutating statement, run the corresponding `SELECT
COUNT(*) ... WHERE ...` with the **same predicate** and show the count to
the user. The count is what the user is approving — not the SQL phrasing,
not the model's interpretation of the request.

If the count is materially larger than the user expects (for example, the
user said "delete the test orders" and the count is 184,000), stop and
re-confirm. The count is the contract.

### Rule 3 — Wrap in an explicit transaction with rollback ready

Every mutating statement runs inside a transaction the agent opened
itself: `BEGIN;` (or the driver/ORM equivalent), the statement, then a
`COMMIT;` only after the user has approved the row count and the visible
effect. Never run a mutating statement in autocommit mode against a
production-class database.

For drivers that default to autocommit (MySQL `mysql` CLI in interactive
mode, MS SQL Server `sqlcmd` without `BEGIN TRAN`, some ORMs configured
with autocommit=true), the agent must explicitly disable autocommit or
open the transaction before running the statement.

### Rule 4 — Migrations: dry-run, backup, rollback

Production migrations must clear three gates **in this order**:

1. **Dry-run on a staging clone of the production schema.** Most
   migration tools support `--sql`, `--plan`, `--dry-run`, or `--check`.
   Run the migration there first, read the generated SQL, and confirm
   it matches the intent of the change.
2. **Backup taken inside the same maintenance window** — point-in-time
   recovery is not a substitute for a logical or physical backup taken
   immediately before the migration runs.
3. **Reversible migration written and tested.** Either a down-migration
   that has been exercised against the up-migration in staging, or, for
   irreversible changes, a documented restore procedure approved by the
   owner of the data.

For "destructive" migrations (any `DROP COLUMN`, `DROP TABLE`,
`ALTER TYPE` that loses information, `TRUNCATE`, or any operation that
removes constraints protecting referential integrity), require explicit
user approval that names the destructive operation by type. "Yes, run
the migration" is not consent to drop a column.

### Rule 5 — Parameterize every query, always

User-controlled values reach SQL only through driver-level parameter
binding. The agent must not produce code that builds SQL by string
concatenation, f-strings, `printf`-style format, template literals, or
ORM raw-query helpers that bypass binding.

This applies even when the value "looks safe" (an integer ID from a URL,
a known enum, a session attribute the agent is sure is internal).
Parameterization is not an optimization to apply when convenient — it is
the only correct shape for queries that touch outside input.

### Rule 6 — Never log full rows; never copy production data downstream

When asked to debug a failing query, the agent must not log entire row
contents, full request bodies, or any column likely to contain PII, PHI,
PCI, or credential material to application logs, ticket systems, chat
transcripts, or shared workspaces. Identify rows by primary key, redact
sensitive columns, and reference data by reference rather than by value.

When asked to copy production data into a development or staging
environment, refuse. Direct the user to the team's data-subset or
synthetic-data pipeline. There is no "small subset" of production rows
that is safe to copy by hand into a less-protected database.

## Negative examples

```sql
-- ❌ DELETE without WHERE — every row goes
DELETE FROM users;
```

```sql
-- ❌ UPDATE without WHERE — every order is cancelled
UPDATE orders SET status = 'cancelled';
```

```sql
-- ❌ TRUNCATE without confirmation — not transactional in MySQL,
--    not rolled back on commit failure
TRUNCATE TABLE audit_logs;
```

```sql
-- ❌ DROP without confirmation, on a production-named database
DROP DATABASE production;
DROP TABLE customers CASCADE;
```

```python
# ❌ Raw f-string into cursor.execute — SQL injection vector
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
```

```python
# ❌ Django ORM bypassed with extra() and string interpolation
User.objects.extra(where=[f"created_at > '{cutoff}'"])
```

```javascript
// ❌ Template literal SQL in a Node driver — injection vector
await client.query(`SELECT * FROM accounts WHERE id = ${accountId}`);
```

```bash
# ❌ Prisma "accept data loss" against a real database
prisma db push --accept-data-loss
```

```bash
# ❌ Migration run straight against production, no dry-run, no backup
DATABASE_URL=$PROD_DATABASE_URL alembic upgrade head
```

```ruby
# ❌ Scoped ActiveRecord delete without a preview or approved affected set
User.where("created_at < ?", 1.year.ago).delete_all
# (still dangerous if the scope is wrong — Rule 2 applies: COUNT first)
```

```sql
-- ❌ "Cleanup" script with no preview and no transaction
DELETE FROM events WHERE event_type = 'test';  -- count? rollback?
```

## Remediation

### PostgreSQL — destructive UPDATE, the right shape

```sql
-- ✅ Step 1 — query the same predicate the UPDATE will use
SELECT COUNT(*) FROM orders WHERE created_at < '2024-01-01';
-- → 1,482 rows. Show this to the user.

-- ✅ Step 2 — open an explicit transaction
BEGIN;

-- ✅ Step 3 — run the mutating statement
UPDATE orders SET status = 'cancelled'
WHERE created_at < '2024-01-01';
-- → "UPDATE 1482"  -- matches the count above

-- ✅ Step 4 — sanity-check the visible effect before committing
SELECT status, COUNT(*) FROM orders
WHERE created_at < '2024-01-01'
GROUP BY status;

-- ✅ Step 5 — COMMIT only within the previously approved scope/count limit
COMMIT;
-- (or ROLLBACK; to abandon the change)
```

Preview counts can change before a write. Obtain approval before opening
the transaction; use a reviewed isolation/locking strategy and check actual
affected rows against the approved scope before commit. Roll back on a
mismatch; do not hold production locks while waiting for a chat reply.

### PostgreSQL — protected backup for irreversible cleanup

```sql
-- Illustrative only: not a consistent backup+delete workflow on a live table.
-- Take a protected, restorable backup with the approved retention policy.
CREATE TABLE users_backup_20260516 AS
SELECT * FROM users WHERE last_login < '2024-01-01';

-- ✅ Confirm row count in backup before deleting from live table
SELECT COUNT(*) FROM users_backup_20260516;

BEGIN;
DELETE FROM users WHERE last_login < '2024-01-01';
-- show "DELETE 412" — matches backup count
ROLLBACK; -- do not commit this illustrative sequence as-is
```

A copied table inherits neither all access controls nor a retention plan.
For a real cleanup, select/lock an approved batch inside a suitable transaction,
back up that exact batch to protected storage, and delete only those IDs.

### Alembic — dry-run a migration against the production schema

```bash
# ✅ Generate the SQL the migration will execute, without running it
alembic upgrade head --sql > pending_migration.sql

# ✅ Review the generated SQL with the user, then run against staging
DATABASE_URL=$STAGING_URL alembic upgrade head

# ✅ Only after staging passes, with a backup taken, run on prod
pg_dump $PROD_URL > backup_pre_migration_$(date +%Y%m%d_%H%M).sql
DATABASE_URL=$PROD_URL alembic upgrade head
```

### Django — destructive ORM call, the right shape

```python
# ✅ Preview root objects AND cascading deletions; approve both scopes first
queryset = User.objects.filter(last_login__lt=cutoff)
count = queryset.count()
# → show "Will delete 412 users" to the user, get approval

with transaction.atomic():
    # Application supplies an approved model-label -> count plan and appropriate
    # isolation/locking for related writers; a stale preview is not authorization.
    deleted, by_model = queryset.delete()
    if by_model != approved_deletion_counts:
        raise RuntimeError("Deletion scope changed; transaction rolled back")
```

Django's total includes cascading related objects. Comparing that total to
the root queryset count is incorrect. This is a pattern, not a runnable
production script: define the approved cascade plan and concurrency controls
for the application's relationships before executing it.

### Parameterized query — Python `psycopg`

```python
# ✅ Driver parameter binding, not string interpolation
cursor.execute(
    "SELECT * FROM users WHERE email = %s AND tenant_id = %s",
    (email, tenant_id),
)
```

### Parameterized query — Node `pg`

```javascript
// ✅ Numbered placeholders, not template literals
await client.query(
  'SELECT * FROM accounts WHERE id = $1 AND tenant_id = $2',
  [accountId, tenantId],
);
```

### Prisma — safe migration command

```bash
# ✅ migrate dev — generates a migration file you can review
prisma migrate dev --name add_user_email_index --create-only

# Review the generated SQL in prisma/migrations/<timestamp>_*/migration.sql

# ✅ Apply with the deploy command (idempotent, transactional, logged)
prisma migrate deploy
```

### kubectl-style "describe before destroy" applied to DB

For any database object the agent is about to drop or alter destructively,
show the user the current definition first:

```sql
-- ✅ Show the table the agent is about to ALTER or DROP
\d+ orders        -- psql
SHOW CREATE TABLE orders;  -- MySQL
sp_help 'dbo.orders';      -- SQL Server
```

Then proceed only after the user confirms the object shown is the one
they meant.

## Production detection heuristics

Treat a connection as production when **any** of these match:

- The hostname or connection string contains `prod`, `production`,
  `live`, `customer`, `tenant`, or a customer/tenant identifier.
- The connection targets a managed-database hostname pattern (`*.rds.
  amazonaws.com`, `*.postgres.database.azure.com`,
  `*.aiven.io`, `*.supabase.co`, `*.neon.tech`, `*.planetscale.com`,
  `*.cockroachlabs.cloud`, `*.cosmos.azure.com`).
- The schema contains tables named `users`, `accounts`, `subscriptions`,
  `payments`, `invoices`, `audit_log`, `events`, or `pii_*`.
- The environment variable, secret name, or vault path used to source
  the connection string contains `prod`, `live`, or `primary`.
- A separate `staging`, `dev`, `test`, `qa`, or `sandbox` environment is
  defined alongside this one in the same configuration.

If **any** signal matches, escalate the protocol: require the count step
to be a separate user turn from the mutating step, and require explicit
user confirmation of the database name and host before running the
mutating statement.

## References

- PostgreSQL `BEGIN` / transactional DDL — https://www.postgresql.org/docs/current/sql-begin.html
- MySQL InnoDB autocommit semantics — https://dev.mysql.com/doc/refman/8.0/en/innodb-autocommit-commit-rollback.html
- SQL Server transactions — https://learn.microsoft.com/en-us/sql/t-sql/language-elements/transactions-transact-sql
- OWASP SQL Injection prevention cheat sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Alembic offline-mode SQL generation — https://alembic.sqlalchemy.org/en/latest/offline.html
- Prisma migrate workflow — https://www.prisma.io/docs/orm/prisma-migrate/workflows/development-and-production
