"""The experimental allow/deny list export (`validate_overlay.py export`, issue #100). Offline, synthetic only."""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import stat
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

    def rules(self, doc=None):
        return {r["rule_id"]: r for r in (doc or self.export())["rules"]}

    def test_one_object_per_rule_with_modes(self):
        doc = self.export()
        self.assertEqual((doc["format"], doc["format_version"], doc["experimental"]), ("catpilot-allowlist-export", 2, True))
        self.assertEqual(doc["expires_on"], "2027-05-17")
        rules = self.rules(doc)
        self.assertEqual(set(rules), {"protected-branches", "deploy-hosts", "package-registries", "cloud-accounts"})
        self.assertEqual(rules["protected-branches"]["list"], "deny")
        self.assertEqual(rules["protected-branches"]["mode"], "block")
        self.assertEqual(rules["cloud-accounts"]["mode"], "ask")
        self.assertEqual(rules["deploy-hosts"]["list"], "allow")
        self.assertEqual(rules["deploy-hosts"]["mode"], "monitor")

    def test_rules_of_one_kind_are_not_merged(self):
        overlay = copy.deepcopy(self.overlay)
        overlay["enforcement"]["rules"].append(
            {"id": "deploy-hosts-eu", "kind": "deploy_host", "values": ["eu.example.org"]})
        rules = self.rules(self.export(overlay=overlay))
        self.assertEqual(rules["deploy-hosts-eu"]["values"], ["eu.example.org"])
        self.assertNotIn("eu.example.org", rules["deploy-hosts"]["values"])
        self.assertNotIn("apps.example.org", rules["deploy-hosts-eu"]["values"])

    def test_exception_attaches_only_to_its_own_rule(self):
        overlay = copy.deepcopy(self.overlay)
        overlay["enforcement"]["rules"].append(
            {"id": "release-branches", "kind": "protected_branch", "values": ["release/*"]})
        overlay["enforcement"]["exceptions"].append(exception())
        rules = self.rules(self.export(overlay=overlay))
        self.assertEqual(rules["protected-branches"]["exceptions"],
                         [{"exception_id": "exception-hotfix", "allows": ["hotfix/urgent"], "expires_on": "2027-01-01"}])
        self.assertNotIn("exceptions", rules["release-branches"])
        self.assertNotIn("exceptions", rules["cloud-accounts"])
        self.assertEqual(rules["deploy-hosts"]["exceptions"][0]["exception_id"], "exception-analytics-preview")

    def test_expired_exception_is_dropped(self):
        later = self.export(today=dt.date(2027, 2, 2))
        self.assertNotIn("exceptions", self.rules(later)["deploy-hosts"])
        on_the_day = self.export(today=dt.date(2027, 2, 1))
        self.assertIn("exceptions", self.rules(on_the_day)["deploy-hosts"])

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
        ids = [r["rule_id"] for r in self.export()["rules"]]
        self.assertEqual(ids, sorted(ids))

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
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(vo.main(["export", str(src), "--out", str(out), "--today", "nonsense"]), 1)


if __name__ == "__main__":
    unittest.main()
