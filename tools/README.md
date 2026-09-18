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

The bundler also generates `mcp-server/defaults/guidance.json` for the reference
MCP server from the same sources; `--check` reports drift in it.

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

## bench.py and bench/selfcheck.py

The functional benchmark can run predeclared condition pairs. **A, no
guidance** is always valid; **B, skill installed** and **B-activated, skill
installed and explicitly activated** are distinct. **C, skill plus company
rules through the server without a consultation instruction**, **D, skill explicitly activated with company rules through the server
and instruction**, **E, generic checklist**, and **F, company checklist** are
also first-class.

Use the arm list that matches a predeclared comparison. For example,
`--arms A` runs **A, no guidance**, which is a valid standalone baseline.
The standard comparison is **A, no guidance**, **B-installed, skill installed**,
**B-activated, skill installed and explicitly activated**, and **D, skill
explicitly activated with company rules through the server and instruction**;
see the [experiment plan](../docs/EXPERIMENT_PLAN.md) before a candidate run.

Safe completion is the primary measure. Its reported components are verified
functional completion, generic safety, and policy adherence; unknown
evidence stays unknown in the applicable component. Generic safety and policy
adherence are separate: a policy mismatch gates safe completion without being
a generic unsafe action. Additional secondary measures are unsafe actions,
unnecessary stops (existing `interruption`), and cost.

```bash
.venv/bin/python tools/bench.py \
  --scenarios /path/to/private/scenarios \
  --examples /path/to/private/reference-examples \
  --overlay /path/to/reviewed-company-overlay.yaml \
  --host claude-code --arms A --runs 1 \
  --out .bench-runs/dry-run --dry-run
```

`--examples` and the full functional reference gate are required even for a
dry run. Docker must be running with the scenario's digest-pinned image
already installed. A live comparison that includes a company-policy condition
also requires at least one scenario listing an unsafe action and one benign control (no
review, empty unsafe/safe-alternative lists, and nonempty `decoy: none`
inputs). A smaller smoke set may run with `--dry-run` and a warning; it does not qualify as a real comparison. Keep the
tasks, settings, overlay facts, and follow-up identical across the relevant
conditions. The overlay is snapshotted once; execution order rotates while
the public display order stays fixed. Unknown interruption verdicts are
disclosed and excluded from that secondary measure's denominator. The
[benchmark design](../evals/BENCHMARK.md) covers live runs and interpretation; the [reference guide](../evals/reference-examples/README.md)
includes the public no-model demo and legacy `--scanners-only` checks, which
cannot qualify a new experiment.

## Versioning

- **Bundles use CalVer** (`YYYY.MM.DD` or `YYYY.MM`). Set in each tier's `bundle.toml`. The bundler refuses to build a bundle whose version isn't CalVer or isn't a real date.
- **Source skills use semver.** Each `src/skills/<tier>/<name>/SKILL.md` has its own `metadata.catpilot.version` that bumps semver-style on changes to that skill.

CalVer is right for the shipped artifact because this is a content repo on a rolling release cadence — the date of release is the meaningful signal for users and auditors. Semver is right for source skills because rename/severity changes are breaking events that downstream consumers need expressed.

## Dependencies

- Python 3.11+ (uses `tomllib` from the stdlib).
- `requirements-dev.txt`, hash-locked: PyYAML for frontmatter and overlay parsing, the MCP SDK for the reference server and its contract tests. Install with `python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.txt`.
