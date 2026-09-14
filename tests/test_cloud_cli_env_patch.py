"""The Azure environment-patch planner shipped with cloud-cli-safety: pure, no cloud calls, synthetic data only."""

import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = runpy.run_path(str(ROOT / "src" / "skills" / "core" / "cloud-cli-safety" / "scripts" / "env_patch.py"))
BUNDLED = ROOT / "skills" / "catpilot-security-core" / "scripts" / "cloud-cli-safety" / "env_patch.py"


class EnvPatchTests(unittest.TestCase):
    def test_patch_is_additive_and_preserves_secret_refs(self):
        current = [{"name": "DB_URL", "secretRef": "old-db"}, {"name": "OTHER", "value": "unchanged"}]
        plan = ENV["plan_patch"](current, [{"name": "DB_URL", "secretRef": "new-db"}, {"name": "LABEL", "value": "hello world=$value"}])
        self.assertEqual(plan["set_env_vars"], ["DB_URL=secretref:new-db", "LABEL=hello world=$value"])
        self.assertEqual(plan["rollback"], {"set_env_vars": ["DB_URL=secretref:old-db"], "remove_env_vars": ["LABEL"]})
        self.assertNotIn("new-db", json.dumps(ENV["summarize_patch"](plan)))
        self.assertEqual(current[0]["secretRef"], "old-db")

    def test_rejects_ambiguous_values_duplicates_and_bad_names(self):
        for entries in ([{"name": "KEY", "value": "x", "secretRef": "s"}], [{"name": "KEY", "secretRef": None}], [{"name": "KEY", "value": "secretref:s"}], [{"name": "BAD NAME", "value": "x"}], [{"name": "KEY", "value": "x"}] * 2):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                ENV["plan_patch"]([], entries)

    def test_no_op_needs_no_rollback(self):
        current = [{"name": "EMPTY", "value": ""}]
        self.assertEqual(ENV["plan_patch"](current, current), {"set_env_vars": [], "rollback": {"set_env_vars": [], "remove_env_vars": []}})

    def test_planner_ships_in_the_bundle(self):
        self.assertTrue(BUNDLED.is_file())
        self.assertEqual(BUNDLED.read_bytes(), (ROOT / "src" / "skills" / "core" / "cloud-cli-safety" / "scripts" / "env_patch.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
