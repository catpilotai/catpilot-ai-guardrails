# Spec — Index

**Status:** Active.
**Scope:** Catpilot skill format and packaging, aligned to the [Anthropic Agent Skills](https://agentskills.io/specification) format and the [skills.sh](https://skills.sh) distribution channel.

---

## What lives here

| File | Purpose |
|---|---|
| [`SKILL_FORMAT.md`](./SKILL_FORMAT.md) | Catpilot skills are valid Anthropic Agent Skills. Catpilot extensions live under `metadata.catpilot.*`. Frontmatter shape, validation rules, severity scale, body conventions. |
| [`PACKAGING.md`](./PACKAGING.md) | Three tiers, bundler mechanics, deterministic output, distribution via `npx skills add`. |
| [`V2_DIAGNOSTIC.md`](./V2_DIAGNOSTIC.md) | One-page postmortem on why v2.x of this repo got zero external traction, and what the rewrite changes. |
| [`OVERLAY.md`](./OVERLAY.md) | Organization overlay: the open schema for company-specific values, the validator, private builds, and the seam with Catpilot Plus. JSON Schema at [`overlay.schema.json`](./overlay.schema.json); synthetic example at [`overlay.example.yaml`](./overlay.example.yaml). |
| [`README.md`](./README.md) | This file. |

## How the format and packaging fit together

- **Authoring units** are per-concern. `secret-blocking` and `database-safety` are different rules with different evidence trails, severities, and release cadences. They each get their own source skill at `src/skills/<tier>/<name>/SKILL.md`.
- **Install units** are per-tier. End users don't want to run `npx skills add` 11 times — they want one install for "the security baseline," one for "the framework I'm using," and optionally one for "advanced agent stuff." The bundler at `tools/bundle.py` materializes those bundles deterministically from the source skills.
- **Versioning splits**: bundles are CalVer (`YYYY.MM.DD`), source skills are semver. See `tools/README.md` for the rationale.

## Decisions

| Decision | Status | Notes |
|---|---|---|
| OSS is zero-phone-home, ever. No telemetry, no crash reports, no anonymous events. SaaS-side dynamic skill updates are a separate workstream under commercial agreement. | LOCKED | Load-bearing. |
| Conformance: exact Anthropic Agent Skills, not "superset." Catpilot extensions live entirely under `metadata.catpilot.*`. Other runtimes ignore unknown metadata. | LOCKED | |
| Severity scale: `info < low < medium < high < critical`. | LOCKED | |
| Control mappings: SOC2, PCI-DSS, ISO 27001, NIST CSF, OWASP Top 10. | LOCKED | HIPAA / GDPR follow in a later release. |
| Tiers: `catpilot-security-core` (engineering baseline), `catpilot-safe-building` (non-engineers), then `catpilot-<framework>-security` and `catpilot-security-advanced` as plans. | LOCKED | Framework and advanced tiers are deferred this quarter; content stays in `frameworks/`. |
| Source layout: `src/skills/<tier>/<name>/SKILL.md`. Bundle layout: `skills/<bundle-name>/SKILL.md`. | LOCKED | Source is outside `skills/` so the skills.sh CLI surfaces only bundles. |
| Bundle frontmatter records per-component versions for traceability. | LOCKED | Lives at `metadata.catpilot.bundle.components[]`. |
| Bundler aggregates severity (max), control mappings (sorted union), `applies_to` (union with `any` collapse). | LOCKED | |
| Distribution: `npx skills add catpilotai/catpilot-ai-guardrails`. No custom installer. | LOCKED | The vercel-labs/skills CLI handles per-runtime placement for 51+ AI coding agents. |
| Bundle versioning: CalVer (`YYYY.MM.DD` or `YYYY.MM`). Source-skill versioning: semver. | LOCKED | Bundles are content on a rolling release cadence; source skills have a real "breaking change" notion. |
| Tier 3 naming: `advanced` (not `agentic`). | LOCKED | |
| Bundler implementation: Python (matches Catpilot stack). | LOCKED | |
| Validator: `tools/validate_skill.py` runs in CI. | DONE | Structure and links only. |
| Framework-detection helper (`tools/recommend.py`). | DEFERRED | With the framework tiers. |
| Core migration from v2.x: nine components. Framework extensions and advanced tier. | CORE DONE; REST DEFERRED | `frameworks/` content kept, promise removed. |
| Three modes, advice / contextual coaching / enforcement, in every description of what the repository does. Enforcement claims only for a tested hook on a named host and path. | LOCKED | `docs/PROTECTION_CONTRACT.md`, `hooks/README.md`. |
| Organization overlay: schema and validator public; values private; the bundler refuses to build a public bundle if an overlay is in the tree; private output goes outside the repository. | LOCKED | `OVERLAY.md`. |
| Per-host targets rendered from the same sources into `dist/<release>/`; `--check` covers them. | LOCKED | `PACKAGING.md` §9. |
| Reference MCP server. | DEFERRED | Not before the design partner names the host. Contract sketched in the direction document, not in code. |

## Reading order

1. This file — context.
2. `PACKAGING.md` — three tiers, bundler aggregation rules, distribution.
3. `SKILL_FORMAT.md` — frontmatter, validation, body conventions.
4. `V2_DIAGNOSTIC.md` — why this rewrite exists at all.
5. A real source skill: `src/skills/core/secret-blocking/SKILL.md`.
6. A real shipped bundle: `skills/catpilot-security-core/SKILL.md`.
