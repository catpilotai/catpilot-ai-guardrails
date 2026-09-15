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
  - Bundles are CalVer (YYYY.MM.DD or YYYY.MM). The release date is the
    meaningful signal for users and auditors.
  - Individual source skills are semver; rename or severity changes are
    breaking and need to be expressible to downstream consumers.

Slots and overlays (docs/spec/OVERLAY.md):
  - Component bodies may contain {{slot}} markers. The public build renders
    every slot from the generic defaults in the tier's bundle.toml. A private
    build (--overlay) renders them from a validated organization overlay and
    writes outside this repository (--private-out).
  - The public build refuses to run if an overlay-shaped YAML file exists
    under src/, skills/, or dist/.

Per-host targets (docs/spec/PACKAGING.md §9):
  - `--target all` also renders the tier's enabled per-host artifacts into
    dist/<release>/ (zip, paste blocks, web page). `--check` covers dist/.

Usage:
  python tools/bundle.py                        # build all tiers into skills/
  python tools/bundle.py --target all           # also render dist/<release>/
  python tools/bundle.py --tier core            # build a single tier
  python tools/bundle.py --check                # CI mode: skills/ and dist/ are current
  python tools/bundle.py --overlay overlay.yaml --private-out ../private-skills
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import re
import shutil
import stat
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

import yaml

try:
    from tools import targets as targets_module
    from tools import validate_overlay
except ModuleNotFoundError:  # invoked as `python tools/bundle.py`
    import targets as targets_module
    import validate_overlay

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "skills"
DIST_ROOT = REPO_ROOT / "skills"
TARGETS_ROOT = REPO_ROOT / "dist"
DEFAULT_PRIVATE_OUT = REPO_ROOT.parent / "private-skills"

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
MODES = ("advisory", "coaching", "enforcement")
SURFACES = ("app-builder", "chat", "coding-agent")
CONTROL_FRAMEWORKS = ["soc2", "pci_dss", "iso_27001", "nist_csf", "owasp_top_10"]
BUNDLE_CFG_KEYS = {
    "name", "tier", "version", "category", "description", "preamble",
    "mode", "training_module", "slots", "targets", "mcp", "layout",
}
LAYOUT_KINDS = ("single", "baseline-references")

# Anthropic spec name regex: 1-64 chars, lowercase a-z + digits + hyphens,
# no leading/trailing/consecutive hyphens.
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$|^[a-z0-9]$")
# Source skills use semver; bundles use CalVer (YYYY.MM.DD or YYYY.MM).
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
CALVER_RE = re.compile(r"^20\d{2}\.(0[1-9]|1[0-2])(?:\.(0[1-9]|[12]\d|3[01]))?(?:[-+][0-9A-Za-z.-]+)?$")
SLOT_RE = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)\s*\}\}")
_FENCE_RE = re.compile(r"^(```|~~~)")

# Stable frontmatter key order. Anything not listed appears after, sorted.
TOP_KEY_ORDER = ["name", "description", "license", "compatibility", "metadata"]
CATPILOT_KEY_ORDER = [
    "bundle",
    "overlay",
    "severity",
    "category",
    "mode",
    "training_module",
    "applies_to",
    "control_mappings",
    "provenance",
    "maintainers",
    "references",
]
BUNDLE_KEY_ORDER = ["name", "version", "tier", "layout", "components"]


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

    @property
    def title(self) -> str | None:
        return self.cp.get("title")

    @property
    def training_checkpoints(self) -> list[str]:
        return [str(c) for c in self.cp.get("training_checkpoints", [])]


# --------------------------------------------------------------------------
# Parsing


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""


def _strict_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ValueError(f"YAML mapping keys must be strings, got {key!r}")
        if key in result:
            raise ValueError(f"duplicate YAML key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping)


def reject_unsafe_tree(root: Path) -> None:
    """Refuse a tree that contains symlinks or special files. Never follows a link."""
    if root.is_symlink():
        raise ValueError(f"symlinks are not allowed: {root}")
    if not root.exists():
        return
    for item in [root, *sorted(root.rglob("*"))]:
        mode = item.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError(f"only regular files and directories are allowed: {item}")


def split_frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        raise ValueError("missing YAML frontmatter")
    fm = yaml.load(m.group(1), Loader=StrictLoader)
    if fm is None:
        fm = {}
    if not isinstance(fm, dict):
        raise ValueError("frontmatter must be a mapping")
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


def _string_list(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ValueError(f"{where}: expected a list of nonempty strings")
    return value


def validate_source_skill(skill: SourceSkill) -> None:
    fm = skill.frontmatter
    name = fm.get("name")
    if not name or not isinstance(name, str):
        raise ValueError(f"{skill.path}: frontmatter missing 'name'")
    if len(name) > 64 or not NAME_RE.match(name):
        raise ValueError(f"{skill.path}: 'name' {name!r} fails Anthropic spec regex")
    if name != skill.path.name:
        raise ValueError(
            f"{skill.path}: directory name {skill.path.name!r} != frontmatter name {name!r}"
        )
    desc = fm.get("description")
    if not desc or not isinstance(desc, str) or len(desc) > 1024:
        raise ValueError(f"{skill.path}: 'description' missing or >1024 chars")
    if not fm.get("license"):
        raise ValueError(f"{skill.path}: Catpilot requires 'license'")
    if "compatibility" in fm and (not isinstance(fm["compatibility"], str) or len(fm["compatibility"]) > 500):
        raise ValueError(f"{skill.path}: 'compatibility' must be a string of at most 500 chars")
    cp = skill.cp
    if not cp or not isinstance(cp, dict):
        raise ValueError(f"{skill.path}: missing metadata.catpilot block")
    if cp.get("id") != name:
        raise ValueError(
            f"{skill.path}: metadata.catpilot.id {cp.get('id')!r} != name {name!r}"
        )
    if not isinstance(skill.version, str) or not SEMVER_RE.match(skill.version):
        raise ValueError(f"{skill.path}: invalid semver {skill.version!r}")
    if skill.severity not in SEVERITY_ORDER:
        raise ValueError(f"{skill.path}: bad severity {skill.severity!r}")
    if not cp.get("category") or not isinstance(cp["category"], str):
        raise ValueError(f"{skill.path}: metadata.catpilot.category required")
    if "title" in cp and (not isinstance(cp["title"], str) or not cp["title"].strip() or len(cp["title"]) > 80):
        raise ValueError(f"{skill.path}: title must be a string of at most 80 chars")
    if "mode" in cp and cp["mode"] not in MODES:
        raise ValueError(f"{skill.path}: mode must be one of {MODES}")
    if "training_module" in cp and (not isinstance(cp["training_module"], str) or not cp["training_module"].strip()):
        raise ValueError(f"{skill.path}: training_module must be a nonempty string (quote it)")
    if "training_checkpoints" in cp:
        _string_list(cp["training_checkpoints"], f"{skill.path}: training_checkpoints")
    applies = cp.get("applies_to", {})
    if not isinstance(applies, dict):
        raise ValueError(f"{skill.path}: applies_to must be a mapping")
    for key, values in applies.items():
        if key not in ("languages", "frameworks", "runtimes", "surfaces"):
            raise ValueError(f"{skill.path}: applies_to.{key} is not a known key")
        _string_list(values, f"{skill.path}: applies_to.{key}")
    for surface in applies.get("surfaces", []):
        if surface not in SURFACES:
            raise ValueError(f"{skill.path}: applies_to.surfaces {surface!r} not in {SURFACES}")
    mappings = cp.get("control_mappings", {})
    if not isinstance(mappings, dict):
        raise ValueError(f"{skill.path}: control_mappings must be a mapping")
    for key, values in mappings.items():
        if key not in CONTROL_FRAMEWORKS:
            raise ValueError(f"{skill.path}: control_mappings.{key} is not a known framework")
        _string_list(values, f"{skill.path}: control_mappings.{key}")
    if not isinstance(cp.get("provenance", {}), dict):
        raise ValueError(f"{skill.path}: provenance must be a mapping")
    if not skill.body.strip():
        raise ValueError(f"{skill.path}: body is empty")


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
    out = {
        "languages": collapse_any(langs),
        "frameworks": collapse_any(fws),
        "runtimes": runtimes,
    }
    surfaces = union_sorted([s.cp.get("applies_to", {}).get("surfaces", []) for s in skills])
    if surfaces:
        out["surfaces"] = surfaces
    return out


def aggregate_control_mappings(skills: list[SourceSkill]) -> dict:
    out = {}
    for fw in CONTROL_FRAMEWORKS:
        merged = union_sorted(
            [s.cp.get("control_mappings", {}).get(fw, []) for s in skills]
        )
        if merged:
            out[fw] = merged
    return out


def aggregate_training_module(cfg: dict, skills: list[SourceSkill]) -> str | list[str] | None:
    if cfg.get("training_module"):
        return cfg["training_module"]
    modules = union_sorted([[s.cp["training_module"]] for s in skills if s.cp.get("training_module")])
    if not modules:
        return None
    return modules[0] if len(modules) == 1 else modules


# --------------------------------------------------------------------------
# Slots


def strip_fences(text: str) -> str:
    """Return text with fenced code blocks removed, so examples never count as slots."""
    out, in_fence = [], False
    for line in text.split("\n"):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)


def used_slots(text: str) -> set[str]:
    return set(SLOT_RE.findall(strip_fences(text)))


def format_slot_value(value: object, key: str) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return "\n".join(f"- {v.strip()}" for v in value)
    raise ValueError(f"slot {key!r}: value must be a string or a list of strings")


def render_slots(text: str, values: dict | None, where: str) -> str:
    """Fill {{slot}} markers outside fenced code. A tier without slots is returned unchanged."""
    if values is None:
        return text

    def replace(match: re.Match) -> str:
        key = match.group(1)
        if key not in values:
            raise ValueError(f"{where}: slot {{{{{key}}}}} has no value; add a default under [bundle.slots]")
        return format_slot_value(values[key], key)

    out, in_fence = [], False
    for line in text.split("\n"):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            out.append(line)
        elif in_fence:
            out.append(line)
        else:
            out.append(SLOT_RE.sub(replace, line))
    return "\n".join(out)


def overlay_slot_values(overlay: dict, defaults: dict) -> dict:
    """Merge validated overlay values over the tier defaults. Additive only."""
    values = dict(defaults)
    values["owner"] = overlay["owner"]
    values["organization"] = overlay["organization"]
    classes = overlay["data_classes"]
    values["data_never_in_prompts"] = classes["never_in_prompts"]
    values["data_ok_with_approval"] = classes["ok_with_approval"]
    values["data_ok"] = classes["ok"]
    values["approved_hosting"] = overlay["hosting"]["approved"]
    values["not_approved_hosting"] = overlay["hosting"]["not_approved"]
    values["approved_services"] = overlay["services"]["approved"]
    values["services_needs_review"] = overlay["services"]["needs_review"]
    values["identity_default"] = overlay["identity"]["default"]
    values["identity_never"] = overlay["identity"]["never"]
    values["review_triggers"] = overlay["review_triggers"]
    if overlay.get("templates"):
        values["templates"] = [
            f"{t['kind']}: {t['location']}" if t.get("location") else t["kind"]
            for t in overlay["templates"]
        ]
    values["overlay_notice"] = (
        f"Company-specific values in this copy were reviewed for {overlay['organization']} on "
        f"{overlay['reviewed_on'].isoformat()} and expire on {overlay['expires_on'].isoformat()}. "
        f"After that date, treat them as unknown and ask {overlay['owner']}."
    )
    return values


def overlay_values_block(overlay: dict) -> str:
    """Compact company-values paragraph for paste-size targets built from an overlay."""
    def join(items: list[str]) -> str:
        return "; ".join(i.rstrip(".") for i in items)
    return (
        f"Company values for {overlay['organization']}, reviewed {overlay['reviewed_on'].isoformat()}, "
        f"expire {overlay['expires_on'].isoformat()}; after that date treat them as unknown. Who to ask: {overlay['owner']}. "
        f"Never in prompts, uploads, or tests: {join(overlay['data_classes']['never_in_prompts'])}. "
        f"Needs the data owner's approval: {join(overlay['data_classes']['ok_with_approval'])}. "
        f"Fine to use: {join(overlay['data_classes']['ok'])}. "
        f"Approved hosting: {join(overlay['hosting']['approved'])}. Not approved: {join(overlay['hosting']['not_approved'])}. "
        f"Approved services: {join(overlay['services']['approved'])}. Needs review first: {join(overlay['services']['needs_review'])}. "
        f"Sign-in default: {overlay['identity']['default'].rstrip('.')}. Never: {join(overlay['identity']['never'])}. "
        f"Always ask before continuing when: {join(overlay['review_triggers'])}."
    )


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not slug:
        raise ValueError(f"cannot derive a skill-name slug from {text!r}")
    return slug


# --------------------------------------------------------------------------
# Overlay guard


OVERLAY_NAME_RE = re.compile(r"^overlay.*\.ya?ml$|.*\.overlay\.ya?ml$", re.IGNORECASE)


def looks_like_overlay(path: Path) -> bool:
    if OVERLAY_NAME_RE.match(path.name):
        return True
    if path.suffix.lower() not in (".yaml", ".yml"):
        return False
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return False
    return isinstance(data, dict) and {"schema_version", "organization", "owner"} <= set(data)


def find_overlay_files(roots: list[Path]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and looks_like_overlay(path):
                found.append(path)
    return found


def guard_no_overlay_in_public_tree(roots: list[Path] | None = None) -> None:
    roots = roots if roots is not None else [SRC_ROOT, DIST_ROOT, TARGETS_ROOT]
    found = find_overlay_files(roots)
    if found:
        listing = ", ".join(str(p) for p in found)
        raise ValueError(
            "refusing to build a public bundle: overlay-shaped file(s) found in the public tree: "
            f"{listing}. Company overlays must live outside this repository (docs/spec/OVERLAY.md)."
        )


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


def dump_yaml(d: dict) -> str:
    return yaml.dump(d, sort_keys=False, allow_unicode=True, width=10_000, default_flow_style=False)


def build_bundle_frontmatter(
    bundle_name: str,
    bundle_cfg: dict,
    skills: list[SourceSkill],
    overlay_meta: dict | None = None,
) -> dict:
    components = [
        {"id": s.id, "version": s.version} for s in sorted(skills, key=lambda s: s.id)
    ]
    cp: dict = {
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
    if overlay_meta:
        cp["overlay"] = overlay_meta
    if layout_kind(bundle_cfg) != "single":
        cp["bundle"]["layout"] = layout_kind(bundle_cfg)
        cp["bundle"] = order_dict(cp["bundle"], BUNDLE_KEY_ORDER)
    if bundle_cfg.get("mode"):
        cp["mode"] = bundle_cfg["mode"]
    training_module = aggregate_training_module(bundle_cfg, skills)
    if training_module:
        cp["training_module"] = training_module
    cp = order_dict(cp, CATPILOT_KEY_ORDER)

    fm = {
        "name": bundle_name,
        "description": bundle_cfg["description"].strip().replace("\n", " "),
        "license": "MIT",
        "metadata": {"catpilot": cp},
    }
    return order_dict(fm, TOP_KEY_ORDER)


def layout_kind(bundle_cfg: dict) -> str:
    return (bundle_cfg.get("layout") or {}).get("kind", "single")


def extract_section(body: str, heading: str) -> str:
    """The text under `## <heading>` up to the next H2, fence-aware, without the heading line."""
    lines = body.splitlines()
    in_fence = False
    start = end = None
    for i, line in enumerate(lines):
        if _FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if start is None:
            if re.fullmatch(rf"##\s+{re.escape(heading)}\s*", line.strip()):
                start = i + 1
        elif line.startswith("## "):
            end = i
            break
    if start is None:
        raise ValueError(f"missing '## {heading}' section")
    return "\n".join(lines[start:end if end is not None else len(lines)]).strip("\n")


def reference_path(skill: SourceSkill) -> str:
    return f"references/{skill.id}.md"


def build_reference(bundle_name: str, skill: SourceSkill, body: str) -> str:
    """One reference file per component: the complete component text, opened on demand."""
    title = skill.title or skill.id
    head = [
        f"# {title}",
        "",
        f"Component `{skill.id}` · version {skill.version} · severity {skill.severity} · category {skill.cp.get('category', '')}.",
        f"Full text of one component of the `{bundle_name}` bundle. The baseline rules are in `../SKILL.md`; this file has the rest: examples, remediation, and detection patterns.",
        "",
    ]
    return "\n".join(head) + body.lstrip("\n").rstrip() + "\n"


def build_bundle_body(bundle_cfg: dict, skills: list[SourceSkill], values: dict) -> str:
    kind = layout_kind(bundle_cfg)
    section = (bundle_cfg.get("layout") or {}).get("baseline_section", "Baseline")
    parts = [render_slots(bundle_cfg["preamble"].strip(), values, "preamble"), ""]
    for s in sorted(skills, key=lambda s: s.id):
        parts.append("---")
        parts.append("")
        if s.title:
            parts.append(f"## {s.title}")
            parts.append("")
            meta = f"Component: `{s.id}`"
            if s.training_checkpoints:
                meta += f" · Course checkpoints: {', '.join(s.training_checkpoints)}"
            parts.append(meta)
        else:
            parts.append(f"## {s.id}")
        parts.append("")
        body = render_slots(s.body.lstrip("\n"), values, s.id)
        if kind == "baseline-references":
            try:
                body = extract_section(body, section)
            except ValueError as e:
                raise ValueError(f"{s.path}: {e}; every component in a baseline-references bundle needs one") from e
            body = _demote_headings(body)
            parts.append(f"Before acting in this area, read [{reference_path(s)}]({reference_path(s)}) in this skill's directory; the rules below are the minimum, not the whole component.")
            parts.append("")
            parts.append(body.rstrip())
        else:
            # Demote any H1/H2 inside component bodies by one level so the
            # bundle's H2 component heading stays the highest within the section.
            body = _demote_headings(body)
            parts.append(body.rstrip())
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


_HEADING_RE = re.compile(r"^(#{1,5}) \S")


def _demote_headings(md: str) -> str:
    """Add one '#' to every ATX heading so component H2 -> H3 inside bundle.

    Skips lines inside fenced code blocks so '# bash comments' aren't mangled.
    """
    out = []
    in_fence = False
    for line in md.split("\n"):
        m = _FENCE_RE.match(line)
        if m:
            in_fence = not in_fence
            out.append(line)
            continue
        if not in_fence and _HEADING_RE.match(line):
            out.append("#" + line)
        else:
            out.append(line)
    return "\n".join(out)


def render_skill_md(frontmatter: dict, body: str) -> str:
    return "---\n" + dump_yaml(frontmatter) + "---\n\n" + body.lstrip("\n")


# --------------------------------------------------------------------------
# Companion files


COMPANION_DIRS = ("references", "scripts", "assets")


def copy_companions(src_skill: Path, dst_bundle: Path, namespace: str) -> None:
    for d in COMPANION_DIRS:
        src = src_skill / d
        if not src.is_dir():
            continue
        dst = dst_bundle / d / namespace
        if dst.exists():
            shutil.rmtree(dst)
        dst.mkdir(parents=True)
        for item in sorted(src.rglob("*")):
            if item.is_file() and "__pycache__" not in item.parts and item.suffix not in (".pyc", ".pyo"):
                rel = item.relative_to(src)
                target = dst / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(item.read_bytes())


# --------------------------------------------------------------------------
# Tier orchestration


def discover_tiers(src_root: Path | None = None) -> list[Path]:
    """Return tier directories under src/skills/ that contain a bundle.toml."""
    src_root = src_root or SRC_ROOT
    reject_unsafe_tree(src_root)
    out = []
    for child in sorted(src_root.iterdir()):
        if not child.is_dir():
            continue
        if (child / "bundle.toml").is_file():
            out.append(child)
        # frameworks/ has nested bundle.tomls.
        if child.name == "frameworks":
            for fw in sorted(child.iterdir()):
                if fw.is_dir() and (fw / "bundle.toml").is_file():
                    out.append(fw)
    return out


def calver_date(version: str) -> dt.date:
    core = re.split(r"[-+]", version)[0].split(".")
    return dt.date(int(core[0]), int(core[1]), int(core[2]) if len(core) > 2 else 1)


def load_bundle_cfg(tier_dir: Path) -> dict:
    reject_unsafe_tree(tier_dir)
    document = tomllib.loads((tier_dir / "bundle.toml").read_text(encoding="utf-8"))
    cfg = document.get("bundle")
    if not isinstance(cfg, dict):
        raise ValueError(f"{tier_dir}/bundle.toml: missing [bundle] table")
    unknown = set(cfg) - BUNDLE_CFG_KEYS
    if unknown:
        raise ValueError(f"{tier_dir}/bundle.toml: unknown keys {sorted(unknown)}")
    for key in ("name", "tier", "version", "description", "preamble"):
        if not isinstance(cfg.get(key), str) or not cfg[key].strip():
            raise ValueError(f"{tier_dir}/bundle.toml: {key} is required")
    if len(cfg["name"]) > 64 or not NAME_RE.match(cfg["name"]):
        raise ValueError(f"{tier_dir}/bundle.toml: bundle name {cfg['name']!r} fails the skill name grammar")
    if len(cfg["tier"]) > 64 or not NAME_RE.match(cfg["tier"]):
        raise ValueError(f"{tier_dir}/bundle.toml: tier {cfg['tier']!r} fails the skill name grammar")
    if len(cfg["description"].strip()) > 1024:
        raise ValueError(f"{tier_dir}/bundle.toml: description exceeds 1024 characters")
    version = cfg["version"]
    if not CALVER_RE.match(version):
        raise ValueError(
            f"{tier_dir}/bundle.toml: bundle version {version!r} is not CalVer "
            f"(expected YYYY.MM.DD or YYYY.MM, e.g. 2026.05.06)"
        )
    calver_date(version)  # raises on impossible dates such as 2026.02.30
    if "mode" in cfg and cfg["mode"] not in MODES:
        raise ValueError(f"{tier_dir}/bundle.toml: mode must be one of {MODES}")
    if "training_module" in cfg and (not isinstance(cfg["training_module"], str) or not cfg["training_module"].strip()):
        raise ValueError(f"{tier_dir}/bundle.toml: training_module must be a nonempty string")
    slots = cfg.get("slots", {})
    if not isinstance(slots, dict):
        raise ValueError(f"{tier_dir}/bundle.toml: [bundle.slots] must be a table")
    for key, value in slots.items():
        if not SLOT_RE.fullmatch("{{" + key + "}}"):
            raise ValueError(f"{tier_dir}/bundle.toml: slot name {key!r} must be lowercase snake_case")
        format_slot_value(value, key)
    mcp_cfg = cfg.get("mcp", {})
    if mcp_cfg:
        if not isinstance(mcp_cfg, dict) or not isinstance(mcp_cfg.get("defaults"), str) or ".." in mcp_cfg["defaults"] or mcp_cfg["defaults"].startswith("/"):
            raise ValueError(f"{tier_dir}/bundle.toml: [bundle.mcp] needs a relative 'defaults' path")
    layout = cfg.get("layout", {})
    if layout:
        if not isinstance(layout, dict) or layout.get("kind") not in LAYOUT_KINDS:
            raise ValueError(f"{tier_dir}/bundle.toml: [bundle.layout] kind must be one of {LAYOUT_KINDS}")
        unknown_layout = set(layout) - {"kind", "baseline_section", "max_lines"}
        if unknown_layout:
            raise ValueError(f"{tier_dir}/bundle.toml: unknown [bundle.layout] keys {sorted(unknown_layout)}")
        section = layout.get("baseline_section", "Baseline")
        if not isinstance(section, str) or not section.strip():
            raise ValueError(f"{tier_dir}/bundle.toml: [bundle.layout] baseline_section must be a nonempty string")
        max_lines = layout.get("max_lines", 500)
        if not isinstance(max_lines, int) or isinstance(max_lines, bool) or max_lines < 50:
            raise ValueError(f"{tier_dir}/bundle.toml: [bundle.layout] max_lines must be an integer of at least 50")
    targets = cfg.get("targets", {})
    if targets:
        if not isinstance(targets, dict) or not isinstance(targets.get("enabled"), list):
            raise ValueError(f"{tier_dir}/bundle.toml: [bundle.targets] needs an 'enabled' list")
        unknown_targets = set(targets["enabled"]) - set(targets_module.TARGET_NAMES)
        if unknown_targets:
            raise ValueError(f"{tier_dir}/bundle.toml: unknown targets {sorted(unknown_targets)}")
    return cfg


def load_tier_skills(tier_dir: Path) -> list[SourceSkill]:
    skill_dirs = sorted(d for d in tier_dir.iterdir() if d.is_dir() and not d.name.startswith("."))
    skills = [load_source_skill(d) for d in skill_dirs]
    if not skills:
        raise ValueError(f"{tier_dir}: no source skills found")
    return skills


def _check_slots(cfg: dict, skills: list[SourceSkill], values: dict, tier_dir: Path) -> None:
    needed = used_slots(cfg["preamble"])
    for s in skills:
        needed |= used_slots(s.body)
    missing = sorted(needed - set(values))
    if missing:
        raise ValueError(f"{tier_dir}: slots without defaults in [bundle.slots]: {missing}")


def render_mcp_defaults_for(tier_dir: Path) -> tuple[Path, str] | None:
    """Return (path, content) for the tier's generated MCP defaults, or None if the tier has none."""
    cfg = load_bundle_cfg(tier_dir)
    if not cfg.get("mcp"):
        return None
    skills = load_tier_skills(tier_dir)
    values = dict(cfg["slots"]) if cfg.get("slots") else None
    if values is not None:
        _check_slots(cfg, skills, values, tier_dir)
    rendered_bodies = {s.id: render_slots(s.body, values, s.id) for s in skills}
    ordered = sorted(skills, key=lambda s: s.id)
    digests = [targets_module.digest(s, rendered_bodies[s.id]) for s in ordered]
    preamble = render_slots(cfg["preamble"].strip(), values, "preamble")
    return REPO_ROOT / cfg["mcp"]["defaults"], targets_module.mcp_defaults(cfg, digests, preamble, values or {})


def build_tier(
    tier_dir: Path,
    dist_root: Path,
    *,
    overlay: dict | None = None,
    overlay_bytes: bytes | None = None,
    with_targets: bool = False,
    targets_root: Path | None = None,
    target_filter: str = "all",
    install_source: str | None = None,
) -> Path:
    cfg = load_bundle_cfg(tier_dir)
    skills = load_tier_skills(tier_dir)
    values = dict(cfg["slots"]) if cfg.get("slots") else None
    overlay_meta = None
    bundle_name = cfg["name"]
    if overlay is not None:
        if values is None:
            raise ValueError(f"{tier_dir}: this tier has no slots, so an overlay cannot be applied")
        values = overlay_slot_values(overlay, values)
        bundle_name = f"{cfg['name']}-{slugify(overlay['organization'])}"
        if len(bundle_name) > 64 or not NAME_RE.match(bundle_name):
            raise ValueError(f"private bundle name {bundle_name!r} fails the skill name grammar; shorten the organization name")
    if values is not None:
        _check_slots(cfg, skills, values, tier_dir)

    body = build_bundle_body(cfg, skills, values)
    if overlay is not None:
        overlay_meta = {
            "organization": overlay["organization"],
            "reviewed_on": overlay["reviewed_on"].isoformat(),
            "expires_on": overlay["expires_on"].isoformat(),
            "overlay_sha256": hashlib.sha256(overlay_bytes or b"").hexdigest(),
            "content_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        }
    fm = build_bundle_frontmatter(bundle_name, cfg, skills, overlay_meta)
    if overlay is not None:
        fm["description"] = (fm["description"] + f" Includes reviewed company values for {overlay['organization']}.")[:1024]
    rendered = render_skill_md(fm, body)
    if layout_kind(cfg) == "baseline-references":
        max_lines = (cfg.get("layout") or {}).get("max_lines", 500)
        n_lines = len(rendered.splitlines())
        if n_lines > max_lines:
            raise ValueError(f"{tier_dir}: the baseline SKILL.md is {n_lines} lines; [bundle.layout] max_lines is {max_lines}. Shorten the components' baseline sections.")

    # Every input is validated above; only now touch the output tree, and never
    # follow a link or delete anything outside the output root.
    reject_unsafe_tree(dist_root)
    dist_root.mkdir(parents=True, exist_ok=True)
    bundle_dir = dist_root / bundle_name
    if bundle_dir.resolve().parent != dist_root.resolve():
        raise ValueError(f"bundle output {bundle_dir} escapes {dist_root}")
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True)
    (bundle_dir / "SKILL.md").write_text(rendered, encoding="utf-8", newline="\n")

    for s in skills:
        copy_companions(s.path, bundle_dir, namespace=s.id)
    if layout_kind(cfg) == "baseline-references":
        (bundle_dir / "references").mkdir(exist_ok=True)
        for s in skills:
            ref = bundle_dir / reference_path(s)
            ref.write_text(build_reference(bundle_name, s, render_slots(s.body, values, s.id)), encoding="utf-8", newline="\n")

    enabled = list(cfg.get("targets", {}).get("enabled", []))
    if with_targets and enabled:
        if target_filter != "all":
            enabled = [t for t in enabled if t == target_filter]
        rendered_bodies = {s.id: render_slots(s.body, values, s.id) for s in skills}
        if overlay is None:
            release_dir = (targets_root or TARGETS_ROOT) / cfg["version"]
            targets_module.render_all(cfg, skills, rendered_bodies, rendered, release_dir, enabled)
        else:
            hosts_dir = dist_root / f"{bundle_name}-hosts"
            if hosts_dir.exists():
                shutil.rmtree(hosts_dir)
            targets_module.render_all(
                cfg, skills, rendered_bodies, rendered, hosts_dir, [t for t in enabled if t != "web"],
                bundle_name=bundle_name, values_block=overlay_values_block(overlay), install_source=install_source or "<your private repository>",
            )
    return bundle_dir


# --------------------------------------------------------------------------
# CLI


def cmd_build(tier_filter: str | None, target: str | None) -> int:
    guard_no_overlay_in_public_tree()
    tiers = discover_tiers()
    if tier_filter:
        tiers = [t for t in tiers if t.name == tier_filter]
        if not tiers:
            print(f"no tier matched {tier_filter!r}", file=sys.stderr)
            return 2
    if target:
        if tier_filter is None and TARGETS_ROOT.exists():
            shutil.rmtree(TARGETS_ROOT)
        else:
            for tier in tiers:
                release_dir = TARGETS_ROOT / load_bundle_cfg(tier)["version"]
                if release_dir.exists():
                    shutil.rmtree(release_dir)
    for tier in tiers:
        out = build_tier(tier, DIST_ROOT, with_targets=bool(target), target_filter=target or "all")
        print(f"built {out.relative_to(REPO_ROOT)}")
        rendered = render_mcp_defaults_for(tier)
        if rendered:
            path, text = rendered
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"rendered {path.relative_to(REPO_ROOT)}")
    if target and TARGETS_ROOT.exists():
        for p in sorted(TARGETS_ROOT.rglob("*")):
            if p.is_file():
                print(f"rendered {p.relative_to(REPO_ROOT)}")
    return 0


def _hash_tree(root: Path) -> dict[str, str]:
    reject_unsafe_tree(root)
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root))
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _report_drift(label: str, committed_root: Path, fresh_root: Path) -> int:
    before = _hash_tree(committed_root)
    after = _hash_tree(fresh_root)
    drift = [(k, before.get(k), after.get(k)) for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)]
    if not drift:
        return 0
    print(f"DRIFT: {label} does not match the deterministic output of src/skills/", file=sys.stderr)
    for k, a, b in drift:
        if a is None:
            print(f"  + {k}  (missing in {label})", file=sys.stderr)
        elif b is None:
            print(f"  - {k}  (extra in {label})", file=sys.stderr)
        else:
            print(f"  ~ {k}  (content differs)", file=sys.stderr)
            if k.endswith((".md", ".txt", ".json", ".html")):
                committed = (committed_root / k).read_text(encoding="utf-8", errors="replace").splitlines()
                fresh = (fresh_root / k).read_text(encoding="utf-8", errors="replace").splitlines()
                diff = difflib.unified_diff(committed, fresh, fromfile=f"a/{k}", tofile=f"b/{k}", lineterm="")
                for line in list(diff)[:60]:
                    print("    " + line, file=sys.stderr)
    return len(drift)


def cmd_check() -> int:
    guard_no_overlay_in_public_tree()
    with tempfile.TemporaryDirectory() as tmp:
        scratch_skills = Path(tmp) / "skills"
        scratch_dist = Path(tmp) / "dist"
        scratch_skills.mkdir()
        for tier in discover_tiers():
            build_tier(tier, scratch_skills, with_targets=True, targets_root=scratch_dist)
        drift = _report_drift("skills/", DIST_ROOT, scratch_skills)
        drift += _report_drift("dist/", TARGETS_ROOT, scratch_dist)
        for tier in discover_tiers():
            rendered = render_mcp_defaults_for(tier)
            if rendered:
                path, text = rendered
                committed = path.read_text(encoding="utf-8") if path.exists() else None
                if committed != text:
                    drift += 1
                    print(f"DRIFT: {path.relative_to(REPO_ROOT)} does not match src/skills/ (rebuild with python tools/bundle.py)", file=sys.stderr)
    if drift:
        print("\nRebuild locally with:  python tools/bundle.py --target all", file=sys.stderr)
        return 1
    print("OK: skills/ and dist/ match the deterministic output of src/skills/")
    return 0


def cmd_private(overlay_path: Path, private_out: Path | None, allow_hosts: list[str], tier_filter: str | None, install_source: str | None = None) -> int:
    private_out = (private_out or DEFAULT_PRIVATE_OUT).expanduser().resolve()
    repo = REPO_ROOT.resolve()
    if private_out == repo or repo in private_out.parents:
        print(
            f"INVALID: --private-out {private_out} is inside this repository. Private bundles must be written "
            "outside the public tree (docs/spec/OVERLAY.md).",
            file=sys.stderr,
        )
        return 2
    data, raw = validate_overlay.load_overlay_file(overlay_path)
    overlay, errors = validate_overlay.validate_overlay(data, set(allow_hosts))
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    tiers = [t for t in discover_tiers() if load_bundle_cfg(t).get("slots")]
    if tier_filter:
        tiers = [t for t in tiers if t.name == tier_filter]
    if not tiers:
        print("no tier with slots matched; nothing to render", file=sys.stderr)
        return 2
    private_out.mkdir(parents=True, exist_ok=True)
    for tier in tiers:
        out = build_tier(tier, private_out, overlay=overlay, overlay_bytes=raw, with_targets=True, install_source=install_source)
        print(f"built private bundle {out} (reviewed {overlay['reviewed_on']}, expires {overlay['expires_on']})")
        hosts = out.parent / f"{out.name}-hosts"
        if hosts.exists():
            print(f"rendered private per-host blocks in {hosts}")
    print("Keep this output in private storage. Do not commit it to a public repository.")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="bundle.py", description="Catpilot skill bundler")
    p.add_argument("--tier", help="build only this tier (matches src/skills/<tier> dir name)")
    p.add_argument("--check", action="store_true", help="verify skills/ and dist/ are up to date with src/")
    p.add_argument("--target", nargs="?", const="all", help="also render per-host artifacts into dist/<release>/ ('all' or one target name)")
    p.add_argument("--overlay", type=Path, help="organization overlay YAML; renders a private bundle instead of the public one")
    p.add_argument("--private-out", type=Path, help="directory for private bundles; must be outside the repository (default ../private-skills)")
    p.add_argument("--allow-host", action="append", default=[], help="hostname allowed in overlay templates[].location (repeatable)")
    p.add_argument("--install-source", help="with --overlay: the private repository a builder installs from, e.g. acme/ai-guidance (used in generated install commands)")
    args = p.parse_args(argv)
    try:
        if args.check:
            return cmd_check()
        if args.overlay:
            return cmd_private(args.overlay, args.private_out, args.allow_host, args.tier, args.install_source)
        if args.private_out:
            print("INVALID: --private-out requires --overlay", file=sys.stderr)
            return 2
        return cmd_build(args.tier, args.target)
    except (ValueError, OSError, yaml.YAMLError, validate_overlay.OverlayError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
