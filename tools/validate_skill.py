"""Offline validation of portable packages, not agent activation or security."""
from pathlib import Path
import argparse
import re
import sys
import yaml
from urllib.parse import unquote, urlsplit

try:
    from tools.bundle import reject_unsafe_tree, require_text, split_frontmatter, valid_name
except ModuleNotFoundError:
    from bundle import reject_unsafe_tree, require_text, split_frontmatter, valid_name


def validate_package(path: Path) -> list[str]:
    errors = []
    try:
        reject_unsafe_tree(path)
        entry = (path / 'SKILL.md').read_text(encoding='utf-8')
        fm, body = split_frontmatter(entry)
        if not valid_name(fm.get('name')) or fm['name'] != path.name:
            errors.append('skill name must match the directory and portable name limits')
        require_text(fm.get('description'), 'description')
        require_text(body, 'body', 50_000)
        if 'compatibility' in fm:
            require_text(fm['compatibility'], 'compatibility', 500)
        allowed = {'name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools'}
        if fm.keys() - allowed:
            errors.append('unknown portable frontmatter keys')
        metadata = fm.get('metadata', {})
        if not isinstance(metadata, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()):
            errors.append('metadata must map strings to strings; put rich data in a sidecar')
        if len(entry.splitlines()) > 500:
            errors.append('entrypoint exceeds the 500-line routing budget')
        # Local inline Markdown links only. Fenced examples are not link targets.
        for document in sorted(path.rglob('*.md')):
            text = re.sub(r'(?ms)^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1\s*$', '', document.read_text(encoding='utf-8'))
            for target in re.findall(r'\]\(([^\s)]+)\)', text):
                link = urlsplit(target.strip('<>'))
                if link.scheme or link.netloc or not link.path:
                    continue
                resolved = (document.parent / unquote(link.path)).resolve()
                if not resolved.is_relative_to(path.resolve()) or not resolved.is_file():
                    errors.append(f'{document.relative_to(path)}: missing or escaping link {target}')
        if isinstance(metadata, dict) and 'catpilot-manifest' in metadata:
            manifest = metadata['catpilot-manifest']
            if not isinstance(manifest, str) or manifest != 'catpilot.json' or not (path / manifest).is_file():
                errors.append('missing or invalid catpilot sidecar')
    except (ValueError, OSError, yaml.YAMLError) as exc:
        errors.append(str(exc))
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', type=Path, nargs='+')
    args = parser.parse_args(argv)
    errors = [f'{path}: {error}' for path in args.paths for error in validate_package(path)]
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print('OK: portable package structure and local Markdown links')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
