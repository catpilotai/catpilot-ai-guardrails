"""End-to-end tests for deploy/org/{install,verify,uninstall}.sh in isolated directories."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "deploy" / "org" / "install.sh"
VERIFY_SH = ROOT / "deploy" / "org" / "verify.sh"
UNINSTALL_SH = ROOT / "deploy" / "org" / "uninstall.sh"
EXAMPLE_OVERLAY = ROOT / "docs" / "spec" / "overlay.example.yaml"


class DeployOrgScriptTests(unittest.TestCase):
    def _env(self, cc_dir: Path, codex_dir: Path) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "CATPILOT_ALLOW_NONROOT": "1",
                "CATPILOT_CC_DIR": str(cc_dir),
                "CATPILOT_CODEX_DIR": str(codex_dir),
                "PYTHON_BIN": sys.executable,
            }
        )
        return env

    def test_standard_install_verify_and_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            codex_dir = Path(tmp) / "codex"
            env = self._env(cc_dir, codex_dir)
            url = "https://mcp.internal.example.org/mcp"

            proc = subprocess.run(
                ["bash", str(INSTALL_SH), "--server-url", url, "--managed-mcp-json"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

            settings = json.loads((cc_dir / "managed-settings.json").read_text(encoding="utf-8"))
            self.assertEqual(settings["managedMcpServers"]["catpilot-guardrails"]["url"], url)
            for hook_name in (
                "pretooluse-secrets.py",
                "pretooluse-write-secrets.py",
                "pretooluse-write-private-key.py",
                "pretooluse-destructive-ops.py",
            ):
                self.assertTrue((cc_dir / "catpilot-guardrails" / "hooks" / hook_name).is_file())

            verify = subprocess.run(
                ["bash", str(VERIFY_SH)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            self.assertIn("0 missing", verify.stdout)

            uninstall = subprocess.run(
                ["bash", str(UNINSTALL_SH), "--server-url", url],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
            self.assertFalse((cc_dir / "managed-settings.json").exists())
            self.assertFalse((cc_dir / "managed-mcp.json").exists())
            self.assertFalse((cc_dir / "catpilot-guardrails").exists())
            self.assertFalse((codex_dir / "managed_config.toml").exists())

    def test_overlay_install_and_edited_config_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            codex_dir = Path(tmp) / "codex"
            env = self._env(cc_dir, codex_dir)
            url = "https://mcp.internal.example.org/mcp"

            proc = subprocess.run(
                [
                    "bash",
                    str(INSTALL_SH),
                    "--server-url",
                    url,
                    "--overlay",
                    str(EXAMPLE_OVERLAY),
                    "--allow-host",
                    "intranet.example.org",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

            # Private overlay bundle and host blocks are installed
            priv_skills = list((cc_dir / ".claude" / "skills").glob("catpilot-safe-building-*"))
            self.assertEqual(len(priv_skills), 1)
            self.assertTrue((cc_dir / "catpilot-guardrails" / "instructions" / "CLAUDE.md").is_file())
            self.assertTrue((cc_dir / "catpilot-guardrails" / "instructions" / "AGENTS.md").is_file())

            # Simulate admin merging an extra key into managed-settings.json after install
            settings_path = cc_dir / "managed-settings.json"
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            data["adminCustomKey"] = True
            settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

            uninstall = subprocess.run(
                ["bash", str(UNINSTALL_SH), "--server-url", url],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
            # Edited file is preserved; private skill and instructions are removed
            self.assertTrue(settings_path.exists())
            self.assertIn("kept", uninstall.stdout)
            self.assertEqual(list((cc_dir / ".claude" / "skills").glob("catpilot-safe-building-*")), [])
            self.assertFalse((cc_dir / "catpilot-guardrails").exists())


if __name__ == "__main__":
    unittest.main()
