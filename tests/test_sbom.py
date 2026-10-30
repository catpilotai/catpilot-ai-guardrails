"""tools/sbom.py lists every hash-pinned dependency as SPDX 2.3, deterministically."""

import io
import json
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tools.sbom import build_sbom, main, pinned_packages

ROOT = Path(__file__).resolve().parents[1]
LOCK = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")


class SbomTests(unittest.TestCase):
    def test_lists_every_pinned_package_with_a_purl(self):
        pinned = [line.split("==")[0].lower() for line in LOCK.splitlines() if re.match(r"^[A-Za-z0-9][^ ]*==", line)]
        sbom = build_sbom("2026.10.29", "2026-10-29T00:00:00Z", LOCK)
        deps = [p for p in sbom["packages"] if p["name"] != "catpilot-ai-guardrails"]
        self.assertEqual([d["name"] for d in deps], pinned)
        for dep in deps:
            purl = dep["externalRefs"][0]["referenceLocator"]
            self.assertEqual(purl, f"pkg:pypi/{dep['name']}@{dep['versionInfo']}")
        self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(sbom["relationships"]), 1 + len(deps))

    def test_root_package_names_the_release(self):
        sbom = build_sbom("2026.10.29", "2026-10-29T00:00:00Z", LOCK)
        root = sbom["packages"][0]
        self.assertEqual(root["versionInfo"], "2026.10.29")
        self.assertEqual(root["licenseDeclared"], "MIT")
        self.assertEqual(sbom["documentDescribes"], [root["SPDXID"]])

    def test_output_is_deterministic(self):
        outputs = []
        for _ in range(2):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main(["--tag", "2026.10.29", "--created", "2026-10-29T00:00:00Z"])
            outputs.append(buffer.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        json.loads(outputs[0])

    def test_refuses_an_unhashed_or_duplicated_pin(self):
        with self.assertRaises(ValueError):
            pinned_packages("requests==2.0.0\n")
        with self.assertRaises(ValueError):
            pinned_packages("a==1 \\\n    --hash=sha256:" + "0" * 64 + "\na==2 \\\n    --hash=sha256:" + "1" * 64 + "\n")

    def test_rejects_a_malformed_tag(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                main(["--tag", "main; rm -rf /", "--created", "2026-10-29T00:00:00Z"])


if __name__ == "__main__":
    unittest.main()
