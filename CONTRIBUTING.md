# Contributing to Catpilot Security Skills

You found the community scratching post.

## Quick Links

- **GitHub:** [catpilotai/catpilot-ai-guardrails](https://github.com/catpilotai/catpilot-ai-guardrails)
- **Website:** [catpilot.ai](https://catpilot.ai)
- **Skill format spec:** [`docs/spec/SKILL_FORMAT.md`](./docs/spec/SKILL_FORMAT.md)
- **Packaging spec:** [`docs/spec/PACKAGING.md`](./docs/spec/PACKAGING.md)

## How to Contribute

| What | How |
|------|-----|
| Found a dangerous pattern | Open an issue, or PR a new component under `src/skills/<tier>/<id>/SKILL.md` |
| False positive in an existing rule | PR a fix to the relevant `src/skills/<tier>/<id>/SKILL.md` and bump its `metadata.catpilot.version` |
| Add a control mapping (SOC 2, PCI-DSS, ISO 27001, NIST CSF, OWASP) | PR the existing component's frontmatter |
| Port a v2.x rule from `frameworks/` or `FULL_GUARDRAILS.md` into a source skill | PR welcome — see the migration notes below |
| Bundler / CI bug | PR `tools/bundle.py` or `.github/workflows/bundle-check.yml` |
| Typo / docs fix | Just PR it |
| Questions | Open a discussion |

## Before You PR

- [ ] Read [`docs/spec/SKILL_FORMAT.md`](./docs/spec/SKILL_FORMAT.md) — frontmatter shape, severity scale, body conventions.
- [ ] Edit `src/skills/<tier>/<id>/SKILL.md`, **not** the shipped bundle in `skills/`. The bundler regenerates `skills/`.
- [ ] Run `python tools/bundle.py` locally to rebuild bundles.
- [ ] Run `python tools/bundle.py --check` to confirm determinism. CI runs the same check on PRs affecting bundle inputs, outputs, or its workflow and fails on drift.
- [ ] Run `python3 tools/validate_evals.py` and `python3 -m unittest discover -s tests -v` when changing the evaluation foundation. These validate fixtures/tooling, not model behavior.
- [ ] Bump `metadata.catpilot.version` on any source skill you change. Source skills use semver; rename or severity changes are major bumps.
- [ ] When changing a bundle's contents, bump its version in `src/skills/<tier>/bundle.toml` to the current date in CalVer (`YYYY.MM.DD`). The bundler refuses non-CalVer values. Documentation/evaluation-only repository releases leave unchanged bundle versions intact.
- [ ] Keep PRs focused (one rule, one fix, one mapping per PR — easier review).

## Anatomy of a source skill

```
src/skills/core/secret-blocking/
├── SKILL.md              # name, description, severity, control mappings, applies_to, body
└── (optional) references/, scripts/, assets/ — bundler namespaces these into the bundle
```

Bodies should:
- Lead with **why** the rule exists (concrete incident or class of incident)
- State **when to apply** (file types, command shapes, language patterns)
- List **rules** (concrete, actionable — "block X", "require Y", not "be careful")
- Show **negative examples** (real bad code in fenced code blocks)

The `metadata.catpilot.evidence` array carries regex patterns or matchers an automated reviewer can use; the body is the natural-language version your agent reads.

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

## File / size conventions

| Where | Convention |
|---|---|
| `src/skills/<tier>/<id>/SKILL.md` | One concern per file. Aim for 100–300 lines of body. |
| `src/skills/<tier>/bundle.toml` | Tier name, CalVer version, description. |
| `skills/<bundle-name>/SKILL.md` | Auto-generated. Do not hand-edit. |
| Components per bundle | No hard cap, but keep a bundle scannable. If `core` outgrows ~10 components, split into a fresh tier. |

## Migration from v2.x

If you were a v2.x contributor: rules in `frameworks/<fw>/FULL_*.md` and `FULL_GUARDRAILS.md` are being ported, one rule at a time, into source skills. PRs that port a v2.x rule into a new `src/skills/<tier>/<id>/SKILL.md` are very welcome — open an issue first if you want to claim a section so we don't duplicate work.

## Current focus

- A reproducible behavioral baseline in Codex and Claude Code, using [synthetic scenarios](evals/README.md).
- Safe-building guidance and private organization-overlay boundaries informed by those results.
- A tested host integration with a clearly scoped check and explicit failure behavior.

All nine core components have shipped. Framework extension bundles, the standalone skill validator, and the framework-detection helper remain future work, not prerequisites for the first evaluation.

Check [Issues](https://github.com/catpilotai/catpilot-ai-guardrails/issues) for "good first issue" labels.

---

By contributing, you agree your work is licensed under MIT. Now go catch some bugs. 🐾
