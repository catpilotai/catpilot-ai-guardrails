"""Offline validation of skill directories: source components and shipped bundles.

Checks the frontmatter shape in docs/spec/SKILL_FORMAT.md, the version regime
(semver for sources, CalVer for bundles), the known enums, that no {{slot}}
marker survives into a shipped bundle, and that relative Markdown links
resolve inside the skill directory.

It does not prove a host loads the skill, and it is not a security scanner.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

try:
    from tools import bundle
except ModuleNotFoundError:  # invoked as `python tools/validate_skill.py`
    import bundle

LINK_RE = re.compile(r"\]\(([^\s)]+)\)")
FENCE_RE = re.compile(r"(?ms)^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1\s*$")
BODY_LINE_BUDGET = 500


def _local_link_errors(path: Path) -> list[str]:
    errors = []
    root = path.resolve()
    for document in sorted(path.rglob("*.md")):
        text = FENCE_RE.sub("", document.read_text(encoding="utf-8"))
        for target in LINK_RE.findall(text):
            link = urlsplit(target.strip("<>"))
            if link.scheme or link.netloc or not link.path:
                continue
            resolved = (document.parent / unquote(link.path)).resolve()
            if root not in resolved.parents and resolved != root:
                errors.append(f"{document.relative_to(path)}: link escapes the skill directory: {target}")
            elif not resolved.is_file():
                errors.append(f"{document.relative_to(path)}: broken local link: {target}")
    return errors


def validate_skill_dir(path: Path) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for one skill directory."""
    errors: list[str] = []
    warnings: list[str] = []
    skill_md = path / "SKILL.md"
    if not skill_md.is_file():
        return [f"{path}: no SKILL.md"], warnings
    try:
        fm, body = bundle.split_frontmatter(skill_md.read_text(encoding="utf-8"))
    except (ValueError, yaml.YAMLError) as exc:
        return [f"{path}: {exc}"], warnings
    cp = fm.get("metadata", {}).get("catpilot", {}) if isinstance(fm.get("metadata"), dict) else {}
    is_bundle = isinstance(cp, dict) and isinstance(cp.get("bundle"), dict)
    if is_bundle:
        name = fm.get("name")
        if not isinstance(name, str) or len(name) > 64 or not bundle.NAME_RE.match(name):
            errors.append(f"{path}: bundle name {name!r} fails the skill name grammar")
        elif name != path.name:
            errors.append(f"{path}: directory {path.name!r} != bundle name {name!r}")
        desc = fm.get("description")
        if not isinstance(desc, str) or not desc.strip() or len(desc) > 1024:
            errors.append(f"{path}: description missing or >1024 chars")
        if not fm.get("license"):
            errors.append(f"{path}: license required")
        meta = cp["bundle"]
        if meta.get("name") != name:
            errors.append(f"{path}: metadata.catpilot.bundle.name != name")
        version = meta.get("version")
        if not isinstance(version, str) or not bundle.CALVER_RE.match(version):
            errors.append(f"{path}: bundle version {version!r} is not CalVer")
        components = meta.get("components")
        if not isinstance(components, list) or not components:
            errors.append(f"{path}: bundle.components must be a nonempty list")
        else:
            for c in components:
                if not isinstance(c, dict) or not bundle.NAME_RE.match(str(c.get("id", ""))) or not bundle.SEMVER_RE.match(str(c.get("version", ""))):
                    errors.append(f"{path}: bad component entry {c!r}")
        if cp.get("severity") not in bundle.SEVERITY_ORDER:
            errors.append(f"{path}: bad bundle severity {cp.get('severity')!r}")
        if "mode" in cp and cp["mode"] not in bundle.MODES:
            errors.append(f"{path}: mode must be one of {bundle.MODES}")
        for surface in cp.get("applies_to", {}).get("surfaces", []) if isinstance(cp.get("applies_to"), dict) else []:
            if surface not in bundle.SURFACES:
                errors.append(f"{path}: unknown surface {surface!r}")
        for fw in cp.get("control_mappings", {}) if isinstance(cp.get("control_mappings"), dict) else []:
            if fw not in bundle.CONTROL_FRAMEWORKS:
                errors.append(f"{path}: unknown control framework {fw!r}")
        if bundle.SLOT_RE.search(re.sub(r"`[^`\n]*`", "", bundle.strip_fences(body))):
            errors.append(f"{path}: unresolved {{{{slot}}}} marker in a shipped bundle")
        if not body.strip():
            errors.append(f"{path}: body is empty")
    else:
        try:
            bundle.validate_source_skill(bundle.SourceSkill(path=path, frontmatter=fm, body=body))
        except ValueError as exc:
            errors.append(str(exc))
        if len(body.splitlines()) > BODY_LINE_BUDGET:
            warnings.append(f"{path}: body has {len(body.splitlines())} lines; the spec recommends at most {BODY_LINE_BUDGET}")
    errors.extend(_local_link_errors(path))
    return errors, warnings


def default_paths() -> list[Path]:
    paths: list[Path] = []
    for tier in bundle.discover_tiers():
        paths.extend(sorted(d for d in tier.iterdir() if d.is_dir() and (d / "SKILL.md").is_file()))
    if bundle.DIST_ROOT.exists():
        paths.extend(sorted(d for d in bundle.DIST_ROOT.iterdir() if d.is_dir() and (d / "SKILL.md").is_file()))
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="*", help="skill directories (default: every source component and shipped bundle)")
    args = parser.parse_args(argv)
    paths = args.paths or default_paths()
    total_errors = 0
    for path in paths:
        errors, warnings = validate_skill_dir(path)
        for w in warnings:
            print(f"WARN: {w}")
        for e in errors:
            print(f"INVALID: {e}", file=sys.stderr)
        total_errors += len(errors)
    if total_errors:
        return 1
    print(f"OK: {len(paths)} skill directories validated (structure and links only; not activation or security)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
