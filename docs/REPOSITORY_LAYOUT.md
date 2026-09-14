# Repository layout

```
src/skills/                 # source components (semver, edited by hand)
  core/
    bundle.toml             # tier config: name, version, description, mode
    secret-blocking/SKILL.md
    ...                     # nine components
  safe-building/
    bundle.toml             # plus [bundle.slots] defaults and [bundle.targets]
    data-in-prompts/SKILL.md
    ...                     # eight components, plain language, {{slot}} markers
skills/                     # shipped bundles (CalVer, generated)
  catpilot-security-core/SKILL.md
  catpilot-safe-building/SKILL.md
dist/2026.09.13/            # per-host artifacts (generated): zip, paste blocks, web page
hooks/claude-code/          # the two hooks, their example settings, and their README
hooks/harness/              # the same credential check as a function for your own agent loop
mcp-server/                 # reference MCP server: four read-only tools over the checkpoints and an overlay
deploy/                     # Azure and Cloudflare scripts for the hosted reference server, and verify.sh
tools/
  bundle.py                 # deterministic bundler: --target all, --overlay, --check
  targets.py                # per-host renderers
  validate_skill.py         # skill directory validator
  validate_overlay.py       # organization overlay validator
  validate_evals.py         # cases.json validator
  eval.py                   # safe-building with/without runner
docs/spec/                  # format, packaging, overlay specs; V2 postmortem
evals/                      # cases.json, scenarios/, reports/
```

`tools/bundle.py` reads source components, aggregates frontmatter (severity = max, control mappings = sorted union, `applies_to` = union with `any` collapse), fills `{{slot}}` markers from the tier's defaults, concatenates bodies in lexicographic order, and writes the shipped bundle. `--target all` renders the per-host artifacts into `dist/<release>/`. CI runs `python tools/bundle.py --check` on PRs affecting bundle inputs or outputs; if `skills/` or `dist/` drifts from `src/skills/`, the build fails with a unified diff.
