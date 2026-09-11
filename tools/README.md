# tools/

Build and validation scripts for the Catpilot skill format.

## bundle.py

Deterministic bundler that reads source skills under `src/skills/<tier>/<name>/SKILL.md` and produces shipped bundles at `skills/<bundle-name>/SKILL.md` in the [Anthropic Agent Skills](https://agentskills.io/specification) format that [`npx skills add`](https://github.com/vercel-labs/skills) installs.

```bash
# build all tiers
python tools/bundle.py

# build a single tier (matches src/skills/<tier> directory name)
python tools/bundle.py --tier core

# CI mode: fail if skills/ isn't the deterministic output of src/skills/
python tools/bundle.py --check
```

Determinism contract is in [`docs/spec/PACKAGING.md` §5](../docs/spec/PACKAGING.md). Aggregation rules (severity = max, control_mappings = sorted union, applies_to = union with `any` collapse, components in lexicographic order by id) are in §3.2.

The bundler runs on every PR via `.github/workflows/bundle-check.yml`. If you edit a source skill and forget to rebuild, the check fails with a unified diff pointing at the drift.

## validate_evals.py

Standard-library-only validation of `evals/cases.json`: required fields and types, stable/unique IDs, known source-component references, consistent policy states, and safe/unsafe examples for the three initial risk categories.

```bash
python3 tools/validate_evals.py
python3 tools/validate_evals.py --cases evals/cases.json
python3 -m unittest discover -s tests -v  # after installing requirements-dev.txt
```

The validator only reads local files. It never executes prompts, contacts a model, uploads data, or grades a response. A successful exit establishes fixture validity—not security effectiveness. See [the evaluation protocol](../evals/README.md).

## Versioning

- **Bundles use CalVer** (`YYYY.MM.DD` or `YYYY.MM`). Set in each tier's `bundle.toml`. The bundler refuses to build a bundle whose version isn't CalVer.
- **Source skills use semver.** Each `src/skills/<tier>/<name>/SKILL.md` has its own `metadata.catpilot.version` that bumps semver-style on changes to that skill.

CalVer is right for the shipped artifact because this is a content repo on a rolling release cadence — the date of release is the meaningful signal for users and auditors. Semver is right for source skills because rename/severity changes are breaking events that downstream consumers (eventually, the SaaS-side dynamic-update pipeline) need expressed.

## Dependencies

- Python 3.11+ (uses `tomllib` from the stdlib).
- Install `requirements-dev.txt` with `--only-binary=:all: --require-hashes` in
  an isolated environment. It pins PyYAML, the official MCP SDK, and transitives.

## New hardening tools

- `validate_skill.py <skill-directory>`: portable frontmatter, local Markdown
  links, and entrypoint size checks; not agent activation.
- `package_plugin.py [--check]`: generate/verify the companion's core from the
  same sources. Run alongside `bundle.py` after every source change.
- `recommend.py <project-directory>`: local framework hints without installing
  anything. Legacy framework references are not migrated skill bundles.
- `run_live_evals.py`: no-cost plan by default; `--execute` runs bounded,
  synthetic CLI calls. Requires explicit host binary and model. See
  [the live evaluation guide](../evals/LIVE_EVALUATION.md).

The deprecated `setup.sh` now preserves existing links and Aider YAML, retains
unique backups, rejects unsafe output paths, and returns nonzero when missing
or stale. New installs should use the portable package. It still edits legacy
project files and is not a transaction across all tool configurations.
