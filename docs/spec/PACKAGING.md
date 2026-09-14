# Packaging

**Status:** Active.
**Companion to:** [`SKILL_FORMAT.md`](./SKILL_FORMAT.md).
**Distribution channel:** [`npx skills add catpilotai/catpilot-ai-guardrails`](https://github.com/vercel-labs/skills) → indexed at [skills.sh](https://skills.sh).

---

## 1. The problem

Authoring granularity and install granularity are not the same thing.

**Authoring wants per-concern.** `secret-blocking` and `database-safety` are different rules with different evidence trails, different severities, and different release cadences. Reviewing them together would be a mess. They want their own `SKILL.md` files, their own version numbers, their own change history.

**Installing wants per-tier.** A user adopting Catpilot does not want to run `npx skills add` 11 times. They want one install for "the security baseline," one install for "the framework I'm using," and optionally one for "the agent-specific advanced stuff." Three installs, total. Most users will only do the first.

This layout decouples them. Authors edit small files; users install small numbers of bundles.

## 2. The three tiers

| Bundle | Source path | Audience | Default install? |
|---|---|---|---|
| `catpilot-security-core` | `src/skills/core/` | Every project, every language, every framework. The non-negotiable security baseline. | Yes |
| `catpilot-safe-building` | `src/skills/safe-building/` | Anyone building an app, automation, dashboard, or data tool with an AI assistant, whether or not they can read code. Also rendered into per-host artifacts under `dist/` (§9). | Yes, for non-engineers |
| `catpilot-<framework>-security` | `src/skills/frameworks/<fw>/` | Projects using the named framework. Auto-detected from `package.json`, `pyproject.toml`, `Gemfile`, etc. | Yes when framework is detected |
| `catpilot-security-advanced` | `src/skills/advanced/` | Multi-agent systems, agent identity boundaries, cron-driven autonomous workflows. | No (opt-in) |

Total bundles a typical user installs: **1–3.** Framework and advanced tiers are plans; their content lives in `frameworks/` and is not promised for this quarter.

### 2.1 `catpilot-security-core`

The skills that apply to any code-generating AI agent regardless of language or framework. ~9 source skills:

- `secret-blocking`
- `cloud-cli-safety`
- `local-cli-safety`
- `database-safety`
- `docker-safety`
- `secrets-management`
- `pii-and-test-data`
- `supply-chain`
- `language-baseline`

### 2.2 Framework extensions

Framework-specific patterns that build on (and assume) the core tier. Initial set: `django`, `fastapi`, `rails`, `express`, `nextjs`, `springboot`, `docker`. Each ships ~3–6 source skills.

The bundler emits one bundle per framework, named `catpilot-<framework>-security`. Users install only the bundles for the frameworks their project uses; the skills.sh CLI plus our framework-detection script handles auto-selection.

### 2.3 `catpilot-security-advanced`

Patterns for autonomous agent systems: identity integrity, multi-agent auth, cron security, agent-led code review. Smaller audience, higher complexity. Opt-in.

## 3. Bundling mechanics

The bundler is `tools/bundle.py` (Python, deterministic). Input: a tier directory under `src/skills/`. Output: a single skill directory under `skills/` containing one `SKILL.md` plus copied `references/`, `scripts/`, and `assets/` from each component.

### 3.1 Output frontmatter

A bundle's `SKILL.md` has its own frontmatter, generated mechanically from its components:

```yaml
---
name: catpilot-security-core
description: |
  Catpilot's universal AI-coding-agent security baseline. Bundles 9 always-on
  guardrails covering secrets, cloud CLI safety, local shell safety, database
  ops, docker, secrets management, PII handling, supply-chain integrity, and
  per-language baselines. Apply on every code generation, file write, and
  shell command. Born from real production incidents.
license: MIT
metadata:
  catpilot:
    bundle:
      name: catpilot-security-core
      version: 2026.05.06               # CalVer; bumped per release
      tier: core
      components:
        - id: secret-blocking
          version: 1.0.0
        - id: cloud-cli-safety
          version: 1.0.0
        # ... one row per source skill
    severity: critical                    # max(component severities)
    mode: advisory                        # from bundle.toml; every bundle here is advisory
    control_mappings:                     # union of all components
      soc2: [CC6.1, CC6.6, CC7.2, CC8.1, A1.2]
      pci_dss: ["3.4", "3.5", "3.6", "6.4.5", "6.4.5.2", "8.2.1", "10.2"]
      iso_27001: [A.9.4.3, A.10.1.1, A.10.1.2, A.12.1.2, A.12.5.1, A.14.2.2, A.14.2.3]
      nist_csf: [PR.AC-1, PR.DS-1, PR.DS-5, PR.IP-1, PR.IP-3, DE.CM-7, RS.MI-2]
      owasp_top_10: ["A02:2021", "A05:2021", "A07:2021", "A08:2021"]
    applies_to:
      languages: [any]
      frameworks: [any]
      runtimes: [claude-code, cursor, openclaw, cline, aider, github-copilot, codex]
---
```

### 3.2 Aggregation rules

| Bundle field | Source |
|---|---|
| `name` | Constant per tier (`catpilot-security-core`, `catpilot-django-security`, `catpilot-security-advanced`). |
| `description` | Hand-curated per tier. The bundler enforces ≤1024 chars but does not generate the prose. |
| `license` | Inherited from `LICENSE` at repo root (MIT). |
| `metadata.catpilot.bundle.version` | Hand-set in `bundle.toml` at the tier root. **CalVer** (`YYYY.MM.DD` or `YYYY.MM`) — bumped per release. The bundler refuses non-CalVer values. |
| `metadata.catpilot.bundle.components[]` | Auto-listed from source skills, with their individual versions. |
| `metadata.catpilot.severity` | `max(component severities)` using the ordering `info < low < medium < high < critical`. |
| `metadata.catpilot.control_mappings.<fw>` | `union(component[*].control_mappings.<fw>)`, sorted, deduplicated. |
| `metadata.catpilot.applies_to.languages` | `union(...)`, with `any` collapsing the set. |
| `metadata.catpilot.applies_to.frameworks` | `union(...)`, with `any` collapsing the set. |
| `metadata.catpilot.applies_to.runtimes` | `intersection(...)` if all components specify; else `union`. |

### 3.3 Body composition

The bundler concatenates component bodies under stable subheadings, in lexicographic-by-id order:

```markdown
# Catpilot Security Core

[hand-curated bundle preamble: ~50 words explaining the bundle, when to apply, link to source]

---

## secret-blocking

<verbatim body of src/skills/core/secret-blocking/SKILL.md>

---

## cloud-cli-safety

<verbatim body of src/skills/core/cloud-cli-safety/SKILL.md>

---

[...]
```

Component headings use the source skill's `metadata.catpilot.id` so that an agent reading the bundle can map specific findings back to a source skill (and to its version, control mappings, and provenance). A component with a `title` gets that title as its heading and a `Component: \`id\`` line underneath, so a skill written for non-engineers reads as prose while staying traceable.

### 3.4 Companion files

`references/`, `scripts/`, and `assets/` from each component are copied into the bundle directory under namespaced subpaths:

```
skills/catpilot-security-core/
├── SKILL.md
├── references/
│   ├── secret-blocking/
│   │   └── REFERENCE.md
│   └── cloud-cli-safety/
│       └── INCIDENT.md
├── scripts/
│   └── secret-blocking/
│       └── scan.py
└── assets/
```

Cross-component file references inside `SKILL.md` bodies are rewritten by the bundler to use the namespaced paths.

## 4. Per-component versioning inside a bundle

Bundles ship a single user-visible version (`bundle.version`, CalVer), but the components inside have their own versions (semver). This matters for SaaS-side dynamic updates (out of scope for OSS) and for change tracking:

- `secret-blocking@1.4.0` can ship inside `catpilot-security-core@2026.07.15` without forcing every other component to bump.
- The bundle's `components[]` list lets a runtime (or a curious user) see exactly which source-skill versions are baked in.
- Bumping or adding a component is just the next dated bundle. Removing a component is also just the next dated bundle — CalVer doesn't try to communicate "breaking," because at the bundle level the install command is stable forever.
- Source skills carry their own breaking-change semantics via semver, for the SaaS-side pipeline that consumes them.

## 5. Determinism

The bundler is required to be deterministic: same input tree → byte-identical output. This is enforced in CI (`tools/bundle.py --check` re-bundles and diffs against the committed `skills/` tree).

Determinism rules:

1. Component ordering: lexicographic by `metadata.catpilot.id`.
2. List-valued aggregations (`control_mappings`, `applies_to`, etc.): sorted alphabetically, deduplicated.
3. Frontmatter key ordering: stable schema (defined in `tools/bundle.py`).
4. Newlines: LF only. Bundler enforces.
5. No timestamps in output.

## 6. Distribution

Catpilot does not ship a custom installer. Users install bundles via the [skills.sh](https://skills.sh) CLI:

```bash
# install the core bundle
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core

# install core + the framework you're using
npx skills add catpilotai/catpilot-ai-guardrails \
  --skill catpilot-security-core \
  --skill catpilot-django-security

# install everything
npx skills add catpilotai/catpilot-ai-guardrails --all
```

The CLI handles per-runtime installation (Claude Code, Cursor, OpenClaw, …) — 51 supported agents at time of writing.

The framework-detection helper (`tools/recommend.py`) is deferred with the framework tiers.

Non-engineers do not run `npx`. For them, §9 renders the safe-building bundle into a Claude.ai zip, paste-ready instruction blocks, and a web page.

## 7. Why not ship the source skills directly?

We could put each source skill at `skills/<name>/SKILL.md` and let users install them individually. We do not, for three reasons:

1. **Install friction.** ~13 individual installs vs. 1 bundle install for the same coverage. Bundle wins.
2. **Coherent prompts.** A single SKILL.md per bundle gives the agent one coherent context to reason from. Many small skills mean many separate activations.
3. **Versioning surface.** Bumping 13 skills independently in a public CLI ecosystem creates more update toil than value.

The source-vs-bundle split is the right tradeoff: authors get fine-grained control, users get coarse-grained installs.

## 8. Status

- Bundler, validator (`tools/validate_skill.py`), nine core components, and the safe-building tier: shipped.
- Per-host targets (§9) and private overlay builds (§10): shipped.
- Framework extension tiers, the advanced tier, and `tools/recommend.py`: deferred. Content stays in `frameworks/`.

## 9. Per-host targets and `dist/`

`python tools/bundle.py --target all` renders every target a tier enables in
its `bundle.toml` (`[bundle.targets] enabled = [...]`) into
`dist/<bundle version>/`. `--check` compares `dist/` as well as `skills/`, so
rendered artifacts cannot drift from source. Only the safe-building tier
enables targets today.

| Target | File | Host |
|---|---|---|
| `claude-zip` | `catpilot-safe-building.zip` | Claude.ai: individual upload, or organization-wide provisioning by an owner. One folder with `SKILL.md` inside. |
| `chatgpt` | `chatgpt-project-instructions.md` | ChatGPT Project or Custom GPT instructions (≤8,000 characters). |
| `copilot` | `copilot-agent-instructions.md`, `copilot-declarative-agent.stub.json` | Copilot Studio instructions; Microsoft 365 declarative-agent manifest stub. |
| `agents-md` | `AGENTS.md` | Block to append to a project's `AGENTS.md`. |
| `copilot-instructions` | `copilot-instructions.md` | Block to append to `.github/copilot-instructions.md`. |
| `lovable` | `lovable-knowledge.md` | Lovable project Knowledge. |
| `bolt` | `bolt-prompt.txt` | `.bolt/prompt`. |
| `replit` | `replit-instructions.md` | Replit Agent instructions or `replit.md`. |
| `v0` | `v0-instructions.md` | v0 project instructions. |
| `web` | `web/safe-ai-building.html` | Source for `catpilot.ai/safe-ai-building`; ported into the site, not served as-is. |

The paste targets are a condensed rendering (`tools/targets.py`): the coaching
preamble plus, per component, the first question, the safe alternatives, and
the stop triggers. The bundler fails if the condensed text exceeds 8,000
characters. Every artifact's first line carries the bundle version. The zip
uses fixed timestamps derived from the CalVer date, so rebuilding produces
identical bytes. A `README.md` in the release directory says where each file
goes.

## 10. Private bundles

`python tools/bundle.py --overlay overlay.yaml --private-out ../private-skills`
renders a tier's slots from an organization overlay instead of the generic
defaults and writes `catpilot-safe-building-<organization slug>/SKILL.md`
outside the repository. The public build refuses to run if an overlay-shaped
file is present under `src/`, `skills/`, or `dist/`. Details and the seam
between the open tooling and the Catpilot Plus product are in
[`OVERLAY.md`](./OVERLAY.md).
