"""Catpilot skill bundler.

Reads source skills under src/skills/<tier>/<name>/SKILL.md and produces
shipped bundles at skills/<bundle-name>/SKILL.md, in the Anthropic Agent
Skills format expected by `npx skills add`.

Determinism rules (PACKAGING.md §5):
  1. Components are emitted in lexicographic order by metadata.catpilot.id.
  2. List-valued aggregations are sorted alphabetically and deduplicated.
  3. Frontmatter key order is fixed by KEY_ORDER below.
  4. Output uses LF line endings exclusively.
  5. No timestamps appear in output.

Versioning:
  - Bundles are CalVer (YYYY.MM.DD or YYYY.MM), matching the
    "content-on-a-rolling-cadence" nature of this repo. The release date is
    the meaningful signal for users and auditors.
  - Individual source skills are semver; rename or severity changes are
    breaking and need to be expressible to downstream consumers (eventually,
    the SaaS-side dynamic-update pipeline).

Run with --check to re-bundle and diff against the committed skills/ tree
(used in CI to enforce that skills/ is the deterministic output of src/).

Usage:
  python tools/bundle.py                # build all tiers
  python tools/bundle.py --tier core    # build a single tier
  python tools/bundle.py --check        # CI mode: verify skills/ is up to date
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "skills"
DIST_ROOT = REPO_ROOT / "skills"

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Anthropic spec name regex: 1-64 chars, lowercase a-z + digits + hyphens,
# no leading/trailing/consecutive hyphens.
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$|^[a-z0-9]$")
# Source skills use semver; bundles use CalVer (YYYY.MM.DD or YYYY.MM).
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
CALVER_RE = re.compile(r"^20\d{2}\.(0[1-9]|1[0-2])(?:\.(0[1-9]|[12]\d|3[01]))?(?:[-+][0-9A-Za-z.-]+)?$")

# Stable frontmatter key order. Anything not listed appears after, sorted.
TOP_KEY_ORDER = ["name", "description", "license", "compatibility", "metadata"]
CATPILOT_KEY_ORDER = [
    "bundle",
    "severity",
    "category",
    "applies_to",
    "control_mappings",
    "provenance",
    "maintainers",
    "references",
]
BUNDLE_KEY_ORDER = ["name", "version", "tier", "components"]


@dataclass
class SourceSkill:
    path: Path
    frontmatter: dict
    body: str

    @property
    def cp(self) -> dict:
        return self.frontmatter.get("metadata", {}).get("catpilot", {})

    @property
    def id(self) -> str:
        return self.cp.get("id") or self.frontmatter.get("name", "")

    @property
    def version(self) -> str:
        return self.cp.get("version", "0.0.0")

    @property
    def severity(self) -> str:
        return self.cp.get("severity", "medium")


# --------------------------------------------------------------------------
# Parsing


class StrictLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate keys, including YAML merge overrides."""


def _strict_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError("YAML keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping)


def valid_name(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 64 and NAME_RE.fullmatch(value) is not None


def require_text(value: object, label: str, maximum: int = 1024) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label}: expected nonempty text of at most {maximum} characters")


def reject_unsafe_tree(root: Path) -> None:
    """Never follow source/output symlinks or copy special files."""
    if root.is_symlink():
        raise ValueError(f"symlinks are not allowed: {root}")
    if not root.exists():
        return
    for item in [root, *sorted(root.rglob('*'))]:
        mode = item.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError(f"only regular files/directories are allowed: {item}")


def split_frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        raise ValueError("missing YAML frontmatter")
    fm = yaml.load(m.group(1), Loader=StrictLoader)
    if not isinstance(fm, dict):
        raise ValueError("frontmatter must be an object")
    return fm, m.group(2)


def load_source_skill(skill_dir: Path) -> SourceSkill:
    reject_unsafe_tree(skill_dir)
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        raise FileNotFoundError(f"no SKILL.md at {skill_md}")
    fm, body = split_frontmatter(skill_md.read_text(encoding="utf-8"))
    skill = SourceSkill(path=skill_dir, frontmatter=fm, body=body)
    validate_source_skill(skill)
    return skill


def validate_source_skill(skill: SourceSkill) -> None:
    fm = skill.frontmatter
    name = fm.get("name")
    if not valid_name(name):
        raise ValueError(f"{skill.path}: 'name' {name!r} fails Anthropic spec regex")
    if name != skill.path.name:
        raise ValueError(
            f"{skill.path}: directory name {skill.path.name!r} != frontmatter name {name!r}"
        )
    desc = fm.get("description")
    require_text(desc, f"{skill.path}: description")
    require_text(fm.get("license"), f"{skill.path}: license")
    if "compatibility" in fm:
        require_text(fm["compatibility"], f"{skill.path}: compatibility", 500)
    if not isinstance(fm.get("metadata"), dict) or not isinstance(fm["metadata"].get("catpilot"), dict):
        raise ValueError(f"{skill.path}: metadata.catpilot must be an object")
    cp = skill.cp
    if not cp:
        raise ValueError(f"{skill.path}: missing metadata.catpilot block")
    if cp.get("id") != name:
        raise ValueError(
            f"{skill.path}: metadata.catpilot.id {cp.get('id')!r} != name {name!r}"
        )
    if 'version' not in cp or 'severity' not in cp:
        raise ValueError(f'{skill.path}: explicit component version and severity required')
    if not isinstance(skill.version, str) or not SEMVER_RE.fullmatch(skill.version):
        raise ValueError(f"{skill.path}: invalid semver {skill.version!r}")
    if skill.severity not in SEVERITY_ORDER:
        raise ValueError(f"{skill.path}: bad severity {skill.severity!r}")
    require_text(cp.get("category"), f"{skill.path}: category")
    require_text(skill.body, f"{skill.path}: body", 250_000)
    for field in ("applies_to", "control_mappings"):
        mapping = cp.get(field, {})
        if not isinstance(mapping, dict):
            raise ValueError(f"{skill.path}: {field} must be an object")
        for key, values in mapping.items():
            if not isinstance(values, list) or not all(isinstance(v, str) and v.strip() for v in values):
                raise ValueError(f"{skill.path}: {field}.{key} must be a string list")
    if not isinstance(cp.get("provenance", {}), dict):
        raise ValueError(f"{skill.path}: provenance must be an object")


# --------------------------------------------------------------------------
# Aggregation


def max_severity(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.index(s))


def union_sorted(items: list[list[str]]) -> list[str]:
    seen: set[str] = set()
    for sub in items:
        for x in sub or []:
            seen.add(str(x))
    return sorted(seen)


def collapse_any(values: list[str]) -> list[str]:
    """If 'any' appears anywhere, the result is just ['any']."""
    if "any" in values:
        return ["any"]
    return values


def aggregate_applies_to(skills: list[SourceSkill]) -> dict:
    langs = union_sorted([s.cp.get("applies_to", {}).get("languages", []) for s in skills])
    fws = union_sorted([s.cp.get("applies_to", {}).get("frameworks", []) for s in skills])
    runtimes = union_sorted([s.cp.get("applies_to", {}).get("runtimes", []) for s in skills])
    return {
        "languages": collapse_any(langs),
        "frameworks": collapse_any(fws),
        "runtimes": runtimes,
    }


def aggregate_control_mappings(skills: list[SourceSkill]) -> dict:
    frameworks = ["soc2", "pci_dss", "iso_27001", "nist_csf", "owasp_top_10"]
    out = {}
    for fw in frameworks:
        merged = union_sorted(
            [s.cp.get("control_mappings", {}).get(fw, []) for s in skills]
        )
        if merged:
            out[fw] = merged
    return out


# --------------------------------------------------------------------------
# Emission


def order_dict(d: dict, order: list[str]) -> dict:
    """Return a new dict with keys in the given order, then any extras sorted."""
    out: dict = {}
    for k in order:
        if k in d:
            out[k] = d[k]
    for k in sorted(d.keys()):
        if k not in out:
            out[k] = d[k]
    return out


class FlowList(list):
    """List that yaml.dump emits in flow style ([a, b, c])."""


def _flow_list_representer(dumper, data):
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=True)


yaml.add_representer(FlowList, _flow_list_representer)


def dump_yaml(d: dict) -> str:
    # Ensure deterministic ordering at every level we care about.
    return yaml.dump(d, sort_keys=False, allow_unicode=True, width=10_000, default_flow_style=False)


def build_bundle_manifest(
    bundle_name: str,
    bundle_cfg: dict,
    skills: list[SourceSkill],
) -> dict:
    components = [
        {"id": s.id, "version": s.version} for s in sorted(skills, key=lambda s: s.id)
    ]
    cp = {
        "bundle": order_dict(
            {
                "name": bundle_name,
                "version": bundle_cfg["version"],
                "tier": bundle_cfg["tier"],
                "components": components,
            },
            BUNDLE_KEY_ORDER,
        ),
        "severity": max_severity([s.severity for s in skills]),
        "category": bundle_cfg.get("category", "security"),
        "applies_to": aggregate_applies_to(skills),
        "control_mappings": aggregate_control_mappings(skills),
        "provenance": {
            "origin": "catpilot",
            "incident_derived": any(
                s.cp.get("provenance", {}).get("incident_derived") for s in skills
            ),
        },
        "maintainers": [{"team": "catpilot-security"}],
    }
    cp = order_dict(cp, CATPILOT_KEY_ORDER)

    return cp


def build_bundle_frontmatter(bundle_name: str, bundle_cfg: dict, skills: list[SourceSkill]) -> dict:
    # Rich metadata is a sidecar, not nonportable nested values in SKILL.md.
    fm = {
        "name": bundle_name,
        "description": bundle_cfg["description"].strip().replace("\n", " "),
        "license": "MIT",
        "metadata": {
            "author": "catpilot",
            "version": bundle_cfg["version"],
            "catpilot-manifest": "catpilot.json",
        },
    }
    return order_dict(fm, TOP_KEY_ORDER)


def build_bundle_body(bundle_cfg: dict, skills: list[SourceSkill]) -> str:
    parts = [bundle_cfg["preamble"].strip(), ""]
    for s in sorted(skills, key=lambda s: s.id):
        summary = s.cp.get("summary", s.frontmatter["description"].split(". ")[0])
        require_text(summary, f"{s.id}: summary", 1024)
        parts.append(f"- [{s.id}](references/{s.id}/REFERENCE.md): {summary}")
    return "\n".join(parts).rstrip() + "\n"


_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_HEADING_RE = re.compile(r"^(#{1,5}) \S")


def _demote_headings(md: str) -> str:
    """Add one '#' to every ATX heading so component H2 -> H3 inside bundle.

    Skips lines inside fenced code blocks so '# bash comments' aren't mangled.
    """
    out = []
    fence = None
    for line in md.split("\n"):
        m = _FENCE_RE.match(line)
        if m and fence is None:
            fence = m.group(1)
            out.append(line)
            continue
        if m and fence and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not m.group(2).strip():
            fence = None
            out.append(line)
            continue
        if fence is None and _HEADING_RE.match(line):
            out.append("#" + line)
        else:
            out.append(line)
    return "\n".join(out)


def render_skill_md(frontmatter: dict, body: str) -> str:
    return "---\n" + dump_yaml(frontmatter) + "---\n\n" + body.lstrip("\n")


# --------------------------------------------------------------------------
# Companion files


COMPANION_DIRS = ("references", "scripts", "assets")


def is_companion_file(path: Path) -> bool:
    return path.is_file() and '__pycache__' not in path.parts and path.name != '.DS_Store' and path.suffix not in ('.pyc', '.pyo')


def copy_companions(src_skill: Path, dst_bundle: Path, namespace: str) -> None:
    if not valid_name(namespace):
        raise ValueError("invalid companion namespace")
    reject_unsafe_tree(src_skill)
    for d in COMPANION_DIRS:
        src = src_skill / d
        if not src.is_dir():
            continue
        dst = dst_bundle / d / namespace
        dst.mkdir(parents=True, exist_ok=True)
        for item in sorted(src.rglob("*")):
            if is_companion_file(item):
                rel = item.relative_to(src)
                target = dst / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise ValueError(f"companion output collision: {target}")
                if item.suffix.lower() == '.md':
                    skill = SourceSkill(src_skill, {'metadata': {'catpilot': {'id': namespace}}}, '')
                    target.write_text(rewrite_companion_paths(item.read_text(encoding='utf-8'), skill, item.relative_to(src_skill)), encoding='utf-8', newline='\n')
                else:
                    target.write_bytes(item.read_bytes())
                target.chmod(0o644 | (item.stat().st_mode & 0o111))


def rewrite_companion_paths(body: str, skill: SourceSkill, source_file: Path = Path('SKILL.md')) -> str:
    """Relocate documented source-root paths into the component reference."""
    mappings = {'SKILL.md': f'references/{skill.id}/REFERENCE.md'}
    for directory in COMPANION_DIRS:
        for item in sorted((skill.path / directory).rglob('*')):
            if is_companion_file(item):
                source = item.relative_to(skill.path).as_posix()
                destination = Path(directory) / skill.id / item.relative_to(skill.path / directory)
                mappings[source] = destination.as_posix()
    output_parent = Path(mappings[source_file.as_posix()]).parent
    pattern = re.compile(r"(?<![\w./-])(?:\.\.?/)*(?:references|scripts|assets)/[^\s`\)\]\"'<>]+")
    def replace(match):
        value, separator, anchor = match.group(0).partition('#')
        source = posixpath.normpath((source_file.parent / value).as_posix())
        destination = mappings.get(source) or mappings.get(value.removeprefix('./'))
        if destination is None:
            return match.group(0)
        return os.path.relpath(destination, output_parent).replace(os.sep, '/') + (separator + anchor)
    rewritten = pattern.sub(replace, body)
    # Also handle sibling/parent Markdown links (including back to SKILL.md).
    return re.sub(r'(?<=\]\()[^\s)]+(?=\))', replace, rewritten)


# --------------------------------------------------------------------------
# Tier orchestration


def discover_tiers() -> list[Path]:
    """Return tier directories under src/skills/ that contain a bundle.toml."""
    reject_unsafe_tree(SRC_ROOT)
    out = []
    for child in sorted(SRC_ROOT.iterdir()):
        if not child.is_dir():
            continue
        if (child / "bundle.toml").is_file():
            out.append(child)
        # frameworks/ has nested bundle.tomls.
        if child.name == "frameworks":
            for fw in sorted(child.iterdir()):
                if fw.is_dir() and (fw / "bundle.toml").is_file():
                    out.append(fw)
    names = [load_bundle_cfg(tier)['name'] for tier in out]
    if len(names) != len(set(names)):
        raise ValueError('duplicate bundle output names across tiers')
    return out


def load_bundle_cfg(tier_dir: Path) -> dict:
    reject_unsafe_tree(tier_dir)
    document = tomllib.loads((tier_dir / "bundle.toml").read_text(encoding="utf-8"))
    cfg = document.get("bundle")
    if not isinstance(cfg, dict):
        raise ValueError(f"{tier_dir}: missing bundle object")
    if cfg.keys() - {'name', 'tier', 'version', 'description', 'preamble', 'category'}:
        raise ValueError(f'{tier_dir}: unknown bundle configuration field')
    if 'category' in cfg:
        require_text(cfg['category'], f'{tier_dir}: category')
    if not valid_name(cfg.get("name")) or not valid_name(cfg.get("tier")):
        raise ValueError(f"{tier_dir}: invalid bundle name or tier")
    for field in ('description', 'preamble'):
        require_text(cfg.get(field), f"{tier_dir}: {field}", 1024 if field == 'description' else 20_000)
    version = cfg.get("version", "")
    if not isinstance(version, str) or not CALVER_RE.fullmatch(version):
        raise ValueError(
            f"{tier_dir}/bundle.toml: bundle version {version!r} is not CalVer "
            f"(expected YYYY.MM.DD or YYYY.MM, e.g. 2026.05.06)"
        )
    core = re.split(r'[-+]', version)[0].split('.')
    date(int(core[0]), int(core[1]), int(core[2]) if len(core) > 2 else 1)
    return cfg


def build_tier(tier_dir: Path, dist_root: Path) -> Path:
    cfg = load_bundle_cfg(tier_dir)
    bundle_name = cfg["name"]
    skill_dirs = sorted(d for d in tier_dir.iterdir() if d.is_dir())
    skills = [load_source_skill(d) for d in skill_dirs]
    if not skills:
        raise ValueError(f"{tier_dir}: no source skills found")

    fm = build_bundle_frontmatter(bundle_name, cfg, skills)
    body = build_bundle_body(cfg, skills)
    rendered = render_skill_md(fm, body)

    # Validate all input before touching a previously built package. Never
    # derive a deletion target from a configuration value.
    reject_unsafe_tree(dist_root)
    dist_root.mkdir(parents=True, exist_ok=True)
    root = dist_root.resolve()
    bundle_dir = root / bundle_name
    if bundle_dir.resolve().parent != root:
        raise ValueError("bundle output escapes its root")
    with tempfile.TemporaryDirectory(prefix='.bundle-', dir=root) as temporary:
        stage = Path(temporary) / bundle_name
        stage.mkdir()
        (stage / 'SKILL.md').write_text(rendered, encoding='utf-8', newline='\n')
        (stage / 'catpilot.json').write_text(json.dumps(build_bundle_manifest(bundle_name, cfg, skills), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        for skill in skills:
            reference = stage / 'references' / skill.id / 'REFERENCE.md'
            reference.parent.mkdir(parents=True)
            reference.write_text(rewrite_companion_paths(skill.body, skill), encoding='utf-8', newline='\n')
            copy_companions(skill.path, stage, namespace=skill.id)
        backup = None
        previous = None
        if bundle_dir.exists():
            backup = Path(tempfile.mkdtemp(prefix='.previous-', dir=root))
            previous = backup / 'package'
            try:
                bundle_dir.rename(previous)
            except OSError:
                backup.rmdir()  # empty directory created by this invocation
                raise
        try:
            stage.rename(bundle_dir)
        except OSError:
            if previous is not None:
                try:
                    previous.rename(bundle_dir)
                except OSError as exc:
                    # Outside the stage context: never delete the only old copy
                    # if the filesystem prevents restoring it.
                    raise OSError(f'restore failed; previous package retained at {previous}') from exc
                backup.rmdir()
            raise
        if backup is not None:
            # Exact private temporary path, never the configured bundle target.
            shutil.rmtree(backup)
    return bundle_dir


# --------------------------------------------------------------------------
# CLI


def cmd_build(tier_filter: str | None) -> int:
    tiers = discover_tiers()
    if tier_filter:
        tiers = [t for t in tiers if t.name == tier_filter]
        if not tiers:
            print(f"no tier matched {tier_filter!r}", file=sys.stderr)
            return 2
    for tier in tiers:
        out = build_tier(tier, DIST_ROOT)
        print(f"built {out.relative_to(REPO_ROOT)}")
    return 0


def _hash_tree(root: Path) -> dict[str, str]:
    reject_unsafe_tree(root)
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root))
            out[rel] = hashlib.sha256((p.stat().st_mode & 0o111).to_bytes(2, 'big') + p.read_bytes()).hexdigest()
    return out


def cmd_check() -> int:
    snapshot_before = _hash_tree(DIST_ROOT)
    # Build into a scratch dir so we don't mutate skills/ on a check run.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "skills"
        scratch.mkdir()
        for tier in discover_tiers():
            build_tier(tier, scratch)
        snapshot_after = _hash_tree(scratch)

    drift = []
    all_keys = sorted(set(snapshot_before) | set(snapshot_after))
    for k in all_keys:
        a = snapshot_before.get(k)
        b = snapshot_after.get(k)
        if a != b:
            drift.append((k, a, b))

    if not drift:
        print("OK: skills/ matches src/skills/ deterministic output")
        return 0

    print("DRIFT: skills/ does not match src/skills/ deterministic output", file=sys.stderr)
    for k, a, b in drift:
        if a is None:
            print(f"  + {k}  (missing in skills/)", file=sys.stderr)
        elif b is None:
            print(f"  - {k}  (extra in skills/)", file=sys.stderr)
        else:
            print(f"  ~ {k}  (content differs)", file=sys.stderr)
            # Print a small diff for SKILL.md drift.
            if k.endswith("SKILL.md"):
                committed = (DIST_ROOT / k).read_text().splitlines()
                with tempfile.TemporaryDirectory() as tmp:
                    scratch = Path(tmp) / "skills"
                    scratch.mkdir()
                    for tier in discover_tiers():
                        build_tier(tier, scratch)
                    fresh = (scratch / k).read_text().splitlines()
                diff = difflib.unified_diff(
                    committed, fresh, fromfile=f"a/{k}", tofile=f"b/{k}", lineterm=""
                )
                for line in list(diff)[:60]:
                    print("    " + line, file=sys.stderr)
    print("\nRebuild locally with:  python tools/bundle.py", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="bundle.py", description="Catpilot skill bundler")
    p.add_argument("--tier", help="build only this tier (matches src/skills/<tier> dir name)")
    p.add_argument("--check", action="store_true", help="verify skills/ is up to date with src/")
    args = p.parse_args(argv)
    try:
        if args.check:
            return cmd_check()
        return cmd_build(args.tier)
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
