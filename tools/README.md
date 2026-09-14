# tools/

Build and validation scripts for the Catpilot skill format. Python 3.11+ and
PyYAML; nothing else. None of these scripts calls a model or the network
except `eval.py --execute`, which calls the host CLI you name.

## bundle.py

Deterministic bundler. Reads source skills under
`src/skills/<tier>/<name>/SKILL.md` and produces shipped bundles at
`skills/<bundle-name>/SKILL.md` in the [Agent Skills](https://agentskills.io/specification)
format that [`npx skills add`](https://github.com/vercel-labs/skills) installs.

```bash
python tools/bundle.py                 # build all tiers into skills/
python tools/bundle.py --target all    # also render per-host artifacts into dist/<release>/
python tools/bundle.py --tier core     # one tier
python tools/bundle.py --check         # CI mode: skills/ and dist/ match src/skills/

# private bundle from an organization overlay; output must be outside the repository
python tools/bundle.py --overlay /private/overlay.yaml --private-out /private/private-skills --allow-host intranet.example.org
```

Aggregation rules (severity = max, control mappings = sorted union,
`applies_to` = union with `any` collapse, components in lexicographic order
by id) are in [`docs/spec/PACKAGING.md`](../docs/spec/PACKAGING.md) §3.
Slots and overlays are in [`docs/spec/OVERLAY.md`](../docs/spec/OVERLAY.md).
Targets are in `PACKAGING.md` §9. The bundler refuses to run the public build
when an overlay-shaped file is inside `src/`, `skills/`, or `dist/`.

## targets.py

Renderers used by `bundle.py --target`: the Claude.ai zip, paste-ready
instruction blocks for ChatGPT, Copilot Studio, Lovable, Bolt, Replit, and v0,
`AGENTS.md` and `copilot-instructions.md` blocks, the Microsoft 365 declarative
agent manifest stub, and the standalone web page. Deterministic; fixed zip
timestamps; fails the build if a paste block exceeds 8,000 characters.

## validate_skill.py

Offline validation of skill directories: every source component and shipped
bundle by default, or the paths you pass. Frontmatter shape, name grammar,
semver/CalVer, enums, no unresolved `{{slot}}` in a bundle, relative links
resolve. Not activation, not a security scanner.

```bash
python tools/validate_skill.py
python tools/validate_skill.py skills/catpilot-safe-building
```

## validate_overlay.py

Offline validation of an organization overlay: the schema in
`docs/spec/overlay.schema.json`, the expiry window, and a scan for anything
that looks like a secret, a URL outside the allowlist, an email other than
`owner`, an IP address, or an incident narrative. Whether the listed items are
actually approved is the reviewer's call, not the validator's.

```bash
python tools/validate_overlay.py docs/spec/overlay.example.yaml --allow-host intranet.example.org
```

## validate_evals.py

Standard-library-only validation of `evals/cases.json` (the core/companion
development corpus): required fields and types, stable/unique IDs, known
source-component references, consistent policy states, and safe/unsafe
examples for the three initial risk categories.

```bash
python tools/validate_evals.py
```

## eval.py

With/without evaluation runner for the safe-building scenarios in
`evals/scenarios/`. With no flags it validates the fixtures offline. `--plan`
prints what a run would do. `--execute` runs each scenario twice (without the
skill, with the skill) against one host CLI, scores responses with readable
keyword heuristics, and writes a Markdown report under `evals/reports/`.

```bash
python tools/eval.py                                   # validate fixtures; no model calls
python tools/eval.py --plan --host claude --binary /abs/path/claude --model claude-haiku-4-5-20251001
python tools/eval.py --execute --host claude --binary /abs/path/claude --model claude-haiku-4-5-20251001 --runs 1 --max-calls 20
```

Hosts without a CLI are driven by hand: `--print-prompts` prints each
scenario's exact prompt, `--import responses.jsonl --host chatgpt` scores the
responses you collected. `--overlay overlay.yaml` adds the scenarios'
`overlay_must` checks, which look for the company's approved values in the
"with" condition. Private per-host blocks come from
`bundle.py --overlay ... --install-source <org/repo>`.

A heuristic pass is not a reviewer's pass. The report says so, and every
report records host, model, injection method, run count, and hashes. See
[`evals/README.md`](../evals/README.md).

## Versioning

- **Bundles use CalVer** (`YYYY.MM.DD` or `YYYY.MM`). Set in each tier's `bundle.toml`. The bundler refuses to build a bundle whose version isn't CalVer or isn't a real date.
- **Source skills use semver.** Each `src/skills/<tier>/<name>/SKILL.md` has its own `metadata.catpilot.version` that bumps semver-style on changes to that skill.

CalVer is right for the shipped artifact because this is a content repo on a rolling release cadence — the date of release is the meaningful signal for users and auditors. Semver is right for source skills because rename/severity changes are breaking events that downstream consumers need expressed.

## Dependencies

- Python 3.11+ (uses `tomllib` from the stdlib).
- `pyyaml` for frontmatter and overlay parsing (`python -m pip install "pyyaml==6.0.3"`).
