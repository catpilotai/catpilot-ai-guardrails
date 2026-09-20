# Contributing to Catpilot Security Skills

You found the community scratching post.

## Quick Links

- **GitHub:** [catpilotai/catpilot-ai-guardrails](https://github.com/catpilotai/catpilot-ai-guardrails)
- **Website:** [catpilot.ai](https://catpilot.ai)
- **Skill format spec:** [`docs/spec/SKILL_FORMAT.md`](./docs/spec/SKILL_FORMAT.md)
- **Packaging spec:** [`docs/spec/PACKAGING.md`](./docs/spec/PACKAGING.md)
- **Overlay spec:** [`docs/spec/OVERLAY.md`](./docs/spec/OVERLAY.md)
- **Protection contract:** [`docs/PROTECTION_CONTRACT.md`](./docs/PROTECTION_CONTRACT.md)

## How to Contribute

| What | How |
|------|-----|
| Found a dangerous pattern for coding agents | Open an issue, or PR a new component under `src/skills/core/<id>/SKILL.md` |
| A checkpoint the safe-building skill gets wrong for non-engineers | PR the component under `src/skills/safe-building/<id>/SKILL.md`; keep the plain-language shape in the format spec §4 |
| False positive in an existing rule, or in a hook | PR a fix and bump `metadata.catpilot.version`; for a hook, add the case to `tests/test_hook.py` or `tests/test_write_hook.py`, whichever one it is |
| Add a control mapping (SOC 2, PCI-DSS, ISO 27001, NIST CSF, OWASP) | PR the component's frontmatter. Safe-building mappings are marked `mapping_review: pending`; a PR that reviews them should say what edition it checked against |
| A host you verified (skill loads, hook blocks) | PR the tested-runtimes table in `docs/REFERENCE.md` with the host version, date, and what you observed; a verification note under `evals/reports/` is welcome |
| A new evaluation scenario | PR `evals/scenarios/<id>.yaml`; every `must`/`must_not` id has to exist in `tools/eval.py` |
| Bundler / target / validator / CI bug | PR `tools/` or `.github/workflows/` |
| Bug in the reference MCP server or the deployment scripts | PR `mcp-server/` or `deploy/`; anything security-related about the hosted endpoint goes to SECURITY.md, not an issue |
| Typo / docs fix | Just PR it |
| Questions | Open an issue |

## Before You PR

- [ ] Read [`docs/spec/SKILL_FORMAT.md`](./docs/spec/SKILL_FORMAT.md): frontmatter shape, severity scale, body conventions, slots.
- [ ] Edit `src/skills/<tier>/<id>/SKILL.md`, **not** the shipped bundle in `skills/` or the artifacts in `dist/`. The bundler regenerates both.
- [ ] Install the hash-locked dependencies in an isolated environment: `python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.txt`.
- [ ] Run `python tools/bundle.py --target all` to rebuild `skills/` and `dist/`.
- [ ] Run `python tools/bundle.py --check` to confirm determinism. CI runs the same check and fails on drift in either tree.
- [ ] Run `python tools/validate_skill.py` and `python -m unittest discover -s tests -v`. These validate structure and tooling, not model behavior.
- [ ] Bump `metadata.catpilot.version` on any source skill you change. Source skills use semver; rename or severity changes are major bumps.
- [ ] When changing a bundle's contents, bump its version in `src/skills/<tier>/bundle.toml` to the current date in CalVer (`YYYY.MM.DD`). The bundler refuses non-CalVer values. Documentation-only repository releases leave unchanged bundle versions intact.
- [ ] Never add company names, internal URLs, policy excerpts, incident details, credentials, or a real overlay. The bundler refuses overlay-shaped files in the tree; the validator refuses secrets, internal identifiers, and narratives in overlays.
- [ ] Keep PRs focused (one rule, one fix, one mapping per PR — easier review).

## Anatomy of a source skill

```
src/skills/core/secret-blocking/
├── SKILL.md              # name, description, severity, control mappings, applies_to, body
└── (optional) references/, scripts/, assets/ — bundler namespaces these into the bundle
```

Core component bodies must start with a `## Baseline` section, at most 35 lines: a bold `Applies when:` line, an `Always:` bullet list, an optional `Never:` bullet list, and a closing line telling the model to open the full component before acting. The bundler refuses to build a core component that lacks this section.

Core bodies should:
- Lead with **why** the rule exists (concrete incident or class of incident)
- State **when to apply** (file types, command shapes, language patterns)
- List **rules** (concrete, actionable — "block X", "require Y", not "be careful")
- Show **negative examples** (real bad code in fenced code blocks)

Safe-building bodies follow a fixed shape (`When this applies`, `What to ask`, `What to say`, `Safe alternative`, optional `Company-specific values` with `{{slot}}` markers, `Stop and ask a human if`) because the same file is rendered into paste-size blocks for hosts with an instruction field. Second person, short sentences, no jargon without a one-line meaning, no shell commands, and nothing company-specific.

## AI-assisted PRs welcome

Built with Copilot, Claude, Cursor, or other AI tools? Perfect — this is literally a project about AI coding.

Just note in your PR:
- [ ] Mark as AI-assisted
- [ ] Report which actual agent/version and safe/unsafe cases you tested, with observed results. If no live agent test was run, say **not run**; fixture validation is not a substitute.
- [ ] Distinguish model advice from a tool action being blocked by a verified enforcement mechanism. See the [protection contract](docs/PROTECTION_CONTRACT.md).
- [ ] Confirm you understand the rule end-to-end

No judgment. We just want reviewers to know what to look for.

## What makes a good rule

```
✅ Specific    → "Block hardcoded values matching ^(sk-|pk-|ghp_|xoxb-|AKIA)…"
❌ Vague       → "Be careful with secrets"

✅ Actionable  → Bad code → Good code examples
❌ Abstract    → "Follow best practices"

✅ Impactful   → Prevents outages, data loss, security holes, audit failures
❌ Pedantic    → Style preferences
```

For the safe-building skill the test is different: would a marketing analyst with a deadline understand it in one read, and does it tell them what to do next?

## File / size conventions

| Where | Convention |
|---|---|
| `src/skills/<tier>/<id>/SKILL.md` | One concern per file. Core: 100–300 lines of body. Safe-building: under 100 lines, plain language. |
| `src/skills/<tier>/bundle.toml` | Tier name, CalVer version, description, preamble; slots and targets where the tier uses them. |
| `skills/<bundle-name>/SKILL.md` | Auto-generated. Do not hand-edit. |
| `dist/<release>/` | Auto-generated per-host artifacts. Do not hand-edit. |
| Components per bundle | No hard cap, but keep a bundle scannable. Core is at nine; safe-building at eight, matching the course. |

## Current focus

- Recording ChatGPT and Claude.ai custom-connector verification against the hosted endpoint.
- Publishing the first full with/without evaluation report.
- The organization-overlay path end to end: a reviewed overlay, a private build, an installed private bundle, a tenant-scoped MCP lookup.
- Populating the tested-runtimes table with real dates for Cursor, Claude.ai, and the design partner's host.

Deferred this quarter: framework extension bundles, the advanced tier, `tools/recommend.py`, HIPAA and GDPR mappings. The `frameworks/` content stays; PRs that port it into source skills are still welcome, they just will not ship as bundles yet.

Check [Issues](https://github.com/catpilotai/catpilot-ai-guardrails/issues) for "good first issue" labels.

---

By contributing, you agree your work is licensed under MIT. Now go catch some bugs. 🐾
