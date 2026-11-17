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
  agentic/
    bundle.toml
    tool-sandboxing/SKILL.md
    ...                     # five components for teams building an agent loop
skills/                     # shipped bundles (CalVer, generated)
  catpilot-security-core/
    SKILL.md                # baseline: per component, applies-when/always/never plus a reference link
    references/<component>.md  # each component's full text: examples, remediation, detection patterns
  catpilot-safe-building/SKILL.md
  catpilot-agentic-security/
    SKILL.md
    references/<component>.md
dist/2026.09.18/            # per-host artifacts (generated): zip, paste blocks, web page
hooks/README.md             # install steps and exact coverage for every hook and gate
hooks/claude-code/          # the three PreToolUse hooks (credentials in Bash, credentials in file writes,
                            # destructive commands), the former write hook's name kept as an entry point,
                            # and example settings
hooks/harness/              # the same checks as functions for your own agent loop, plus outbound-URL and file-path gates
mcp-server/                 # reference MCP server: four read-only tools over the checkpoints and an overlay
deploy/                     # Azure and Cloudflare scripts for hosting the reference server, notes on Catpilot's instance, and verify.sh
  org/                      # install.sh, verify.sh, uninstall.sh and templates for the Claude Code and Codex managed locations
.claude-plugin/             # skills-only plugin manifest and one-entry marketplace
tools/
  bundle.py                 # deterministic bundler: --target all, --overlay, --check
  targets.py                # per-host renderers
  company_checklist.py      # company checklist block: benchmark condition F and the private company-checklist.md target
  validate_skill.py         # skill directory validator
  validate_overlay.py       # organization overlay validator
  validate_evals.py         # cases.json validator
  eval.py                   # safe-building with/without runner
  bench.py, bench/          # benchmark runner: conditions, scanners, functional checks, reports
  evidence_summary.py       # pilot readout from the content-free evidence log
  sbom.py                   # SPDX SBOM of the pinned dependencies, for signed releases
docs/spec/                  # format, packaging, overlay specs; V2 postmortem
frameworks/                 # long-form framework guides, kept as reference and not packaged as skills
evals/                      # cases.json, scenarios/, retired scenarios, reference examples, reports/
tests/                      # unit tests for the bundler, validators, hooks, gates, server, deployment scripts, and runner
```

`tools/bundle.py` reads source components, aggregates frontmatter (severity = max, control mappings = sorted union, `applies_to` = union with `any` collapse), fills `{{slot}}` markers from the tier's defaults, concatenates bodies in lexicographic order, and writes the shipped bundle. `--target all` renders the per-host artifacts into `dist/<release>/`. CI runs `python tools/bundle.py --check` on PRs affecting bundle inputs or outputs; if `skills/` or `dist/` drifts from `src/skills/`, the build fails with a unified diff.
