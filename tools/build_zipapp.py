#!/usr/bin/env python3
"""Build the hooks as one deterministic zipapp, catpilot-guard.pyz (issue #97, option 2, first step).

    python tools/build_zipapp.py --out /tmp/catpilot-guard.pyz
    python /tmp/catpilot-guard.pyz secrets --evidence-default    # the same check as pretooluse-secrets.py

The archive is the format `python -m zipapp` writes: a `#!/usr/bin/env python3` line, then a zip whose
__main__.py runs. It is written with zipfile instead, because zipapp takes the order, timestamps and permissions of
its entries from the file system: here the entries are sorted, every timestamp is 1980-01-01 00:00:00, every mode
is 0644, and nothing is compressed (stored), so the same sources give the same bytes on any machine, Python or zlib.
CI builds it twice and compares SHA-256 (.github/workflows/baseline.yml).

It holds catpilot_guard/*.py and a __main__.py that runs one check by name: secrets, write-secrets, destructive,
company-rules or session-start. An unknown name, or a check that cannot load, exits 2, which the hosts treat as a
block. install.sh and install.ps1 do not place it yet: wiring it in, and attesting it, is the next step.
Standard library only, Python 3.8+.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
SHEBANG = b"#!/usr/bin/env python3\n"
MAIN = '''"""Run one Catpilot check by name: python catpilot-guard.pyz CHECK [options]. Built by tools/build_zipapp.py."""
import importlib
import sys

CHECKS = {
    "secrets": "catpilot_guard.secrets",
    "write-secrets": "catpilot_guard.write_secrets",
    "destructive": "catpilot_guard.destructive",
    "company-rules": "catpilot_guard.company_rules",
    "session-start": "catpilot_guard.session_start",
}


def run():
    sys.dont_write_bytecode = True
    if len(sys.argv) < 2 or sys.argv[1] not in CHECKS:
        sys.stderr.write("usage: catpilot-guard.pyz {%s} [options]; nothing was allowed\\n" % ",".join(sorted(CHECKS)))
        return 2
    name = sys.argv.pop(1)
    try:
        module = importlib.import_module(CHECKS[name])
    except Exception as exc:  # fail closed: a check that cannot load blocks
        sys.stderr.write("Catpilot %s check unavailable (%s), so nothing was allowed.\\n" % (name, exc.__class__.__name__))
        return 2
    return module.main()


if __name__ == "__main__":
    sys.exit(run())
'''


def entries() -> list:
    """(archive name, bytes), sorted by name."""
    files = [("__main__.py", MAIN.encode("utf-8"))]
    for path in sorted((ROOT / "catpilot_guard").glob("*.py")):
        files.append(("catpilot_guard/" + path.name, path.read_bytes()))
    return sorted(files)


def build(out: Path) -> str:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as handle:
        handle.write(SHEBANG)
        with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in entries():
                info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
                info.external_attr = (0o100644 & 0xFFFF) << 16
                info.create_system = 3  # Unix, whatever builds it, so the mode bits read the same everywhere
                archive.writestr(info, data, compress_type=zipfile.ZIP_STORED)
    out.chmod(0o755)
    return hashlib.sha256(out.read_bytes()).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True, help="where to write the archive (outside dist/, which holds releases)")
    args = parser.parse_args(argv)
    digest = build(args.out)
    print("%s  %s" % (digest, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
