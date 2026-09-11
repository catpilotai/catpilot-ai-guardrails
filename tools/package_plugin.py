"""Generate the plugin's core skill from the same sources; reject drift in CI."""
from pathlib import Path
import argparse
import sys
import tempfile

try:
    from tools.bundle import build_tier, _hash_tree
    from tools.validate_skill import validate_package
except ModuleNotFoundError:
    from bundle import build_tier, _hash_tree
    from validate_skill import validate_package

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / 'plugins/catpilot-companion/skills'
NAME = 'catpilot-security-core'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    if args.check:
        with tempfile.TemporaryDirectory() as temp:
            expected = build_tier(ROOT / 'src/skills/core', Path(temp))
            if _hash_tree(expected) != _hash_tree(DESTINATION / NAME):
                print('DRIFT: rebuild with python tools/package_plugin.py', file=sys.stderr)
                return 1
    else:
        build_tier(ROOT / 'src/skills/core', DESTINATION)
    errors = [error for path in sorted(DESTINATION.iterdir()) if path.is_dir() for error in validate_package(path)]
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('OK: plugin core matches source and portable skills validate')
    return 0


if __name__ == '__main__':
    sys.exit(main())
