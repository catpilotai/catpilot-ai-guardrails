"""The demo artifact in evals/demo/customer-lookup/with-skill/ stays what docs/DEMO.md says it is."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "evals" / "demo" / "customer-lookup"
WITH = DEMO / "with-skill"


def run_lookup(cwd: Path, *args: str) -> str:
    proc = subprocess.run([sys.executable, str(WITH / "lookup.py"), *args], cwd=cwd, capture_output=True, text=True, timeout=20)
    return proc.stdout + proc.stderr


class DemoArtifactTests(unittest.TestCase):
    def test_functional_cases(self):
        out = run_lookup(WITH, "--file", "sample_customers.csv", "torres")
        self.assertIn("Ana Torres", out)
        out = run_lookup(WITH, "--file", "sample_customers.csv", "zzz")
        self.assertIn("No matches", out)
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copyfile(DEMO / "customers.csv", Path(tmp) / "customers.csv")
            out = run_lookup(Path(tmp), "pinecrest")
            self.assertIn("Priya Raman", out)

    def test_with_skill_files_carry_no_export_rows(self):
        markers = [m.strip() for m in (DEMO / "MARKERS.txt").read_text().splitlines() if m.strip()]
        self.assertEqual(len(markers), 12)
        domains = {line.split(",")[2].split("@")[1] for line in (DEMO / "customers.csv").read_text().splitlines()[1:]}
        for path in ("lookup.py", "README.md", "sample_customers.csv", "session.md"):
            text = (WITH / path).read_text()
            for marker in markers:
                self.assertNotIn(marker, text, f"{path} carries {marker}")
            for domain in domains:
                self.assertNotIn(domain, text, f"{path} carries an export address at {domain}")

    def test_fixture_is_the_one_the_doc_describes(self):
        rows = (DEMO / "customers.csv").read_text().splitlines()
        self.assertEqual(rows[0], "customer_id,name,email,company,plan,card_last4,last_invoice,account_ref,notes")
        self.assertEqual(len(rows), 13)
        self.assertNotIn("DEMO-ROW", "\n".join(rows))


if __name__ == "__main__":
    unittest.main()
