"""Read-only framework hints; does not install skills or prove protection."""
import argparse
import json
from pathlib import Path
import sys


def recommend(project):
    def read(name):
        file = project / name
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 131072:
            return ''
        return file.read_text(encoding='utf-8', errors='replace')
    matches = set()
    try:
        package = json.loads(read('package.json') or '{}')
        for group in ('dependencies', 'devDependencies'):
            dependencies = package.get(group, {}) if isinstance(package, dict) else {}
            if isinstance(dependencies, dict):
                for name, framework in {'next': 'nextjs', 'express': 'express', 'typescript': 'typescript'}.items():
                    if name in dependencies:
                        matches.add(framework)
    except ValueError:
        pass
    requirements = (read('requirements.txt') + '\n' + read('pyproject.toml')).lower()
    for name in ('django', 'fastapi'):
        if name in requirements:
            matches.add(name)
    if read('Dockerfile'):
        matches.add('docker')
    if 'rails' in read('Gemfile').lower():
        matches.add('rails')
    if 'spring-boot' in read('pom.xml') or 'org.springframework.boot' in read('build.gradle'):
        matches.add('springboot')
    return {'installable_baseline': 'catpilot-security-core', 'framework_hints': sorted(matches), 'framework_references': [f'frameworks/{name}/' for name in sorted(matches)], 'framework_bundles': 'not-yet-packaged; references are legacy guidance', 'activation': 'not-tested', 'mutations': 'none'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    args = parser.parse_args(argv)
    if args.project.is_symlink() or not args.project.is_dir():
        parser.error('provide a real project directory, not a symlink')
    print(json.dumps(recommend(args.project), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
