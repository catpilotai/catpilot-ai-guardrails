"""The experimental allow/deny list export (`validate_overlay.py export`, issue #100). Offline, synthetic only."""

from __future__ import annotations

import copy
import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import validate_overlay as vo  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

SPEC = ROOT / "docs" / "spec"
SALT = "5f0c9a1e7d3b4c2a8e6f1d0b9a7c5e3f"
TODAY = dt.date(2026, 11, 17)


def example() -> dict:
    data, _ = vo.load_overlay_file(SPEC / "overlay.v2.example.yaml")
    data["salt"] = SALT
    overlay, errors = vo.validate_overlay(data, today=TODAY)
    assert not errors, errors
    return overlay


def exception(**fields) -> dict:
    entry = {"id": "exception-hotfix", "rule": "protected-branches", "allows": ["hotfix/urgent"],
             "approver_role": "Release manager", "expires_on": dt.date(2027, 1, 1)}
    entry.update(fields)
    return entry


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.overlay = example()

    def export(self, today=TODAY, overlay=None):
        return vo.export_policy(overlay or self.overlay, today)

    def test_shape_and_modes(self):
        doc = self.export()
        self.assertEqual((doc["format"], doc["format_version"], doc["experimental"]), ("catpilot-allowlist-export", 1, True))
        self.assertEqual(doc["expires_on"], "2027-05-17")
        self.assertEqual(set(doc["allow"]), {"deploy_hosts", "package_registries", "cloud_accounts"})
        self.assertEqual(list(doc["deny"]), ["protected_branches"])
        branches = {e["value"]: e for e in doc["deny"]["protected_branches"]}
        self.assertEqual(branches["main"], {"value": "main", "rule_id": "protected-branches", "mode": "block"})
        self.assertEqual({e["mode"] for e in doc["allow"]["cloud_accounts"]}, {"ask"})
        self.assertEqual({e["mode"] for e in doc["allow"]["deploy_hosts"]} - {"monitor"}, set())

    def test_active_exception_has_its_expiry_and_expired_one_is_dropped(self):
        hosts = [e for e in self.export()["allow"]["deploy_hosts"] if "exception_id" in e]
        self.assertEqual(hosts, [{"value": "preview.analytics.example.org", "rule_id": "deploy-hosts", "mode": "monitor",
                                  "exception_id": "exception-analytics-preview", "expires_on": "2027-02-01"}])
        later = self.export(today=dt.date(2027, 2, 2))
        self.assertFalse([e for e in later["allow"]["deploy_hosts"] if "exception_id" in e])

    def test_protected_branch_exception_becomes_except(self):
        overlay = copy.deepcopy(self.overlay)
        overlay["enforcement"]["exceptions"].append(exception())
        entries = self.export(overlay=overlay)["deny"]["protected_branches"]
        self.assertTrue(all(e["except"] == [{"value": "hotfix/urgent", "exception_id": "exception-hotfix", "expires_on": "2027-01-01"}] for e in entries))

    def test_where_scoped_exception_is_left_out(self):
        overlay = copy.deepcopy(self.overlay)
        overlay["enforcement"]["exceptions"] = [exception(where={"repositories": ["example-org/web"]})]
        text = vo.policy_text(self.export(overlay=overlay))
        self.assertNotIn("hotfix/urgent", text)
        self.assertNotIn("example-org/web", text)

    def test_nothing_machine_only_leaves(self):
        text = vo.policy_text(self.export())
        for secret in (SALT, "salt", "source_sha256", "approver_role", "Platform security lead", "security-review@example.org", "use_instead"):
            self.assertNotIn(secret, text)

    def test_deterministic_and_sorted(self):
        first = vo.policy_text(self.export())
        reordered = copy.deepcopy(self.overlay)
        reordered["enforcement"]["rules"].reverse()
        for rule in reordered["enforcement"]["rules"]:
            rule["values"].reverse()
        self.assertEqual(first, vo.policy_text(self.export(overlay=reordered)))
        values = [e["value"] for e in self.export()["allow"]["deploy_hosts"]]
        self.assertEqual(values, sorted(values))

    def test_no_enforcement_exports_nothing(self):
        overlay = copy.deepcopy(self.overlay)
        del overlay["enforcement"]
        self.assertIsNone(self.export(overlay=overlay))

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_schema_accepts_the_export_and_refuses_extras(self):
        schema = json.loads((SPEC / "policy-export.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        overlay = copy.deepcopy(self.overlay)
        overlay["enforcement"]["exceptions"].append(exception())
        doc = json.loads(vo.policy_text(self.export(overlay=overlay)))
        self.assertEqual(list(validator.iter_errors(doc)), [])
        doc["salt"] = SALT
        self.assertTrue(list(validator.iter_errors(doc)))

    def test_cli_writes_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "rules.yaml"
            text = (SPEC / "overlay.v2.example.yaml").read_text(encoding="utf-8").replace("0123456789abcdef0123456789abcdef", SALT)
            src.write_text(text, encoding="utf-8")
            out = Path(tmp) / "export.json"
            self.assertEqual(vo.main(["export", str(src), "--out", str(out), "--today", "2026-11-18"]), 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(doc["experimental"])
            self.assertEqual(vo.main(["export", str(src), "--out", str(out), "--today", "nonsense"]), 1)


if __name__ == "__main__":
    unittest.main()
