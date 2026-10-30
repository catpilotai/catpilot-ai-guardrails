#!/usr/bin/env python3
"""Write an SPDX 2.3 software bill of materials for a release, from the hash-pinned requirements-dev.txt.

The hooks and harness gates are standard library only, and the skills are Markdown, so the release's third-party
code is exactly the pinned Python dependencies that the reference MCP server and the tools install. Each package is
listed with its version, a PyPI package URL, and the number of sha256 hashes pip will accept for it. Output is
deterministic for a given tag, commit time, and lock file, so the release workflow can attest it.

Standard library only.

Usage:
    python3 tools/sbom.py --tag 2026.10.29 --created 2026-10-29T00:00:00Z > catpilot-ai-guardrails.spdx.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/catpilotai/catpilot-ai-guardrails"
REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def pinned_packages(lock_text: str) -> list[dict]:
    """(name, version, hash count) for every `name==version` entry in a pip-compile style lock, in file order."""
    packages: list[dict] = []
    for line in lock_text.splitlines():
        match = REQUIREMENT.match(line)
        if match:
            packages.append({"name": match.group(1).lower(), "version": match.group(2), "hashes": 0})
        elif packages and line.strip().startswith("--hash=sha256:"):
            packages[-1]["hashes"] += 1
    names = [p["name"] for p in packages]
    if len(names) != len(set(names)):
        raise ValueError("a package is pinned more than once")
    if not packages or any(p["hashes"] == 0 for p in packages):
        raise ValueError("every pinned package must carry at least one sha256 hash")
    return packages


def spdx_id(name: str) -> str:
    return "SPDXRef-Package-pypi-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def build_sbom(tag: str, created: str, lock_text: str) -> dict:
    packages = pinned_packages(lock_text)
    root = {
        "SPDXID": "SPDXRef-Package-catpilot-ai-guardrails",
        "name": "catpilot-ai-guardrails",
        "versionInfo": tag,
        "downloadLocation": f"git+{REPOSITORY}@{tag}",
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": "NOASSERTION",
        "supplier": "Organization: Catpilot",
        "filesAnalyzed": False,
    }
    deps = [
        {
            "SPDXID": spdx_id(p["name"]),
            "name": p["name"],
            "versionInfo": p["version"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": f"pkg:pypi/{p['name']}@{p['version']}"}],
            "comment": f"Pinned in requirements-dev.txt with {p['hashes']} accepted sha256 hash(es).",
        }
        for p in packages
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"catpilot-ai-guardrails-{tag}",
        "documentNamespace": f"{REPOSITORY}/releases/tag/{tag}#sbom",
        "creationInfo": {"created": created, "creators": ["Tool: catpilot-ai-guardrails tools/sbom.py"]},
        "documentDescribes": [root["SPDXID"]],
        "packages": [root, *deps],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root["SPDXID"]},
            *({"spdxElementId": root["SPDXID"], "relationshipType": "DEPENDS_ON", "relatedSpdxElement": d["SPDXID"]} for d in deps),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True, help="release tag, for example 2026.10.29")
    parser.add_argument("--created", required=True, help="ISO 8601 UTC time, normally the tagged commit's time")
    parser.add_argument("--lock", default=str(ROOT / "requirements-dev.txt"))
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}(?:-\d+)?", args.tag):
        parser.error("--tag must be a CalVer release tag such as 2026.10.29 or 2026.09.28-1")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", args.created):
        parser.error("--created must look like 2026-10-29T00:00:00Z")
    sbom = build_sbom(args.tag, args.created, Path(args.lock).read_text(encoding="utf-8"))
    json.dump(sbom, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
