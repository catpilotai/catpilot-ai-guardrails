"""The catpilot_guard package and the Claude Code hook shims that run it.

The hook tests (test_hook.py, test_write_hook.py, test_destructive_hook.py) run the shims in
hooks/claude-code/ by path. These tests check that each shim prints exactly what the package
module prints, with the same exit code, for every case in those tests' tables; that a shim
blocks when the package is missing or broken; that the package imports only the standard
library; and that the package and the shims parse as Python 3.8.

Credential-shaped values are built at run time so none sits in this file.
"""

import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "catpilot_guard"
HOOK_DIR = ROOT / "hooks" / "claude-code"
# Each shim and the package module it runs. The legacy name runs the write-secrets shim.
SHIMS = {
    "pretooluse-secrets.py": "catpilot_guard.secrets",
    "pretooluse-write-secrets.py": "catpilot_guard.write_secrets",
    "pretooluse-write-private-key.py": "catpilot_guard.write_secrets",
    "pretooluse-destructive-ops.py": "catpilot_guard.destructive",
}
EVIDENCE_VARS = ("CATPILOT_EVIDENCE_LOG", "CATPILOT_EVIDENCE_SYSLOG")
# The evidence fields that legitimately differ between two runs of the same event.
TIMESTAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$"
EVENT_ID = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"


def _test_module(name: str):
    """A hook test module, loaded by path under another name, for its case tables."""
    spec = importlib.util.spec_from_file_location(f"catpilot_guard_cases_{name}", ROOT / "tests" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SECRET_CASES = _test_module("test_hook")
WRITE_CASES = _test_module("test_write_hook")
DESTRUCTIVE_CASES = _test_module("test_destructive_hook")

AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documentation-only example
MALFORMED = (
    "not json",
    "[]",
    json.dumps({"tool_name": "Bash", "tool_input": "x"}),
    json.dumps({"tool_name": "Bash", "tool_input": {"command": 5}}),
    json.dumps({"tool_name": "Write", "tool_input": "x"}),
    json.dumps({"tool_name": "Write", "tool_input": {"content": None}}),
    json.dumps({"tool_name": "MultiEdit", "tool_input": {"edits": "bad"}}),
    json.dumps({"tool_name": "Write", "tool_input": {"file_path": "f", "content": "a" * 1_100_000}}),
)


def bash_event(command: str, **extra) -> str:
    return json.dumps({"session_id": "sess-parity", "tool_name": "Bash", "tool_input": {"command": command}, **extra})


def tool_event(tool: str, tool_input: dict) -> str:
    return json.dumps({"session_id": "sess-parity", "tool_name": tool, "tool_input": tool_input})


def secret_payloads() -> dict:
    """Every command in test_hook.py's tables, plus the forms it checks inline."""
    payloads = {label: bash_event(command) for label, command in {**SECRET_CASES.DENIED, **SECRET_CASES.ALLOWED}.items()}
    for command in (
        "mysql -u root -p" + 'hunter22secret -e "select 1"',
        '{"api' + '_key": "abcdef1234567890"}',
        '{"pass' + 'word": "hunter22ABC"}',
        '{"tok' + 'en": "abcdef123456"}',
        '{"sec' + 'ret": "abcdef123456"}',
        "psql postgres://app:" + "hunter2@db.internal:5432/prod  # pragma: allowlist secret",
    ):
        payloads["inline: " + command] = bash_event(command)
    payloads["other tool"] = tool_event("Write", {"content": AWS_EXAMPLE_KEY})
    return payloads


def write_payloads() -> dict:
    """The events test_write_hook.py sends, rebuilt from its module-level values."""
    key, token = WRITE_CASES.KEY_BLOCK, WRITE_CASES.SYNTHETIC_GITHUB_TOKEN
    db_url = "postgres://app:" + "s3cr3t-prod-pw" + "@db.internal:5432/prod"
    cases = {
        "Write key block": ("Write", {"file_path": "key.pem", "content": key}),
        "Edit key block": ("Edit", {"file_path": "config.py", "old_string": "KEY = None", "new_string": 'KEY = """' + key + '"""'}),
        "MultiEdit key block": ("MultiEdit", {"file_path": "a.txt", "edits": [{"old_string": "x", "new_string": "y"}, {"old_string": "z", "new_string": key}]}),
        "NotebookEdit key block": ("NotebookEdit", {"notebook_path": "n.ipynb", "new_source": key}),
        "aws key in Write": ("Write", {"file_path": ".env", "content": "AWS_ACCESS_KEY_ID=" + AWS_EXAMPLE_KEY + "\n"}),
        "stripe key in Edit": ("Edit", {"file_path": "config.ts", "old_string": "const k = ''", "new_string": 'const k = "sk_' + "test_" + "x" * 24 + '"'}),
        "github token in MultiEdit": ("MultiEdit", {"file_path": "ci.yml", "edits": [{"old_string": "a", "new_string": "GH_TOKEN=ghp_" + "a" * 36}]}),
        "db url in NotebookEdit": ("NotebookEdit", {"notebook_path": "etl.ipynb", "new_source": 'conn = "' + db_url + '"'}),
        "json api_key in Write": ("Write", {"file_path": "settings.json", "content": '{"api' + '_key": "abcdef1234567890"}'}),
        "github token": ("Write", {"file_path": "f", "content": 'TOKEN = "' + token + '"\n'}),
        "github token with marker": ("Write", {"file_path": "f", "content": 'TOKEN = "' + token + '"  # pragma: allowlist secret\n'}),
        "db url": ("Write", {"file_path": "f", "content": "DATABASE_URL=" + db_url + "\n"}),
        "Bash is out of scope": ("Bash", {"command": "printf -- '-----BEGIN RSA " + "PRIVATE KEY-----' > k"}),
        "Read is out of scope": ("Read", {"file_path": "key.pem"}),
    }
    for variant in ("", "EC ", "OPENSSH ", "ENCRYPTED "):
        cases["header " + (variant or "plain")] = ("Write", {"file_path": "k", "content": "-----BEGIN " + variant + "PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n"})
    cases["header PGP"] = ("Write", {"file_path": "k", "content": "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\nSYNTHETIC-NOT-A-KEY\n"})
    for content in (
        "print('hello')\n",
        "PRIVATE_KEY_PATH = os.environ['PRIVATE_KEY_PATH']\n",
        "-----BEGIN CERTIFICATE-----\nnot a private key\n",
        'STRIPE_API_KEY="REPLACE_ME"\n',
        '{"api_key": "YOUR_API_KEY"}\n',
        'DATABASE_URL="postgres://user:${DB_PASSWORD}@localhost:5432/app"\n',
        "DATABASE_URL=postgres://user:s3cr3t-local-pw@localhost:5432/app\n",
        "DATABASE_URL=postgres://postgres:postgres@db:5432/app\n",
        'password: "password"\n',
    ):
        cases["allowed: " + content.strip()] = ("Write", {"file_path": "f", "content": content})
    return {label: tool_event(tool, tool_input) for label, (tool, tool_input) in cases.items()}


def destructive_payloads(repo: Path) -> dict:
    """Every command in test_destructive_hook.py's tables, and a bare force push read from .git/HEAD."""
    payloads = {label: bash_event(command) for label, command in {**DESTRUCTIVE_CASES.DENIED, **DESTRUCTIVE_CASES.ALLOWED}.items()}
    for command in ("git push -f", "git push --force-with-lease origin", "git push --force origin HEAD"):
        payloads["bare force push: " + command] = bash_event(command, cwd=str(repo))
    payloads["other tool"] = tool_event("Write", {"content": "rm -rf /"})
    return payloads


def hook_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in EVIDENCE_VARS}
    env.update(extra)
    return env


def run_shim(shim: Path, payload: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(shim)], input=payload, capture_output=True, text=True, timeout=30, env=env, cwd=ROOT)


def run_module(module: str, payload: str, env: dict) -> subprocess.CompletedProcess:
    # -m from the repository root: the package module itself, run as a program.
    return subprocess.run([sys.executable, "-B", "-m", module], input=payload, capture_output=True, text=True, timeout=30, env=env, cwd=ROOT)


class ShimParityTests(unittest.TestCase):
    def test_each_shim_prints_what_its_package_module_prints(self):
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / ".git").mkdir()
            (Path(repo) / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            cases = []
            for label, payload in secret_payloads().items():
                cases.append(("pretooluse-secrets.py", label, payload))
            for label, payload in destructive_payloads(Path(repo)).items():
                cases.append(("pretooluse-destructive-ops.py", label, payload))
            for shim in ("pretooluse-write-secrets.py", "pretooluse-write-private-key.py"):
                for label, payload in write_payloads().items():
                    cases.append((shim, label, payload))
            for shim in SHIMS:
                for number, payload in enumerate(MALFORMED):
                    cases.append((shim, f"malformed {number}", payload))
            env = hook_env()

            def both(case):
                shim, label, payload = case
                return shim, label, run_shim(HOOK_DIR / shim, payload, env), run_module(SHIMS[shim], payload, env)

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(both, cases))

        decisions = set()
        for shim, label, from_shim, from_module in results:
            with self.subTest(shim=shim, case=label):
                self.assertEqual(
                    (from_shim.returncode, from_shim.stdout, from_shim.stderr),
                    (from_module.returncode, from_module.stdout, from_module.stderr),
                )
                decisions.add((shim, from_shim.returncode, "deny" in from_shim.stdout))
        # Not a vacuous comparison: each shim denied, let through, and failed closed somewhere above.
        for shim in SHIMS:
            for outcome in ((0, True), (0, False), (2, False)):
                self.assertIn((shim,) + outcome, decisions)

    def test_each_shim_writes_the_evidence_line_its_package_module_writes(self):
        deny = {
            "pretooluse-secrets.py": bash_event("export AWS_ACCESS_KEY_ID=" + AWS_EXAMPLE_KEY),
            "pretooluse-destructive-ops.py": bash_event("git push --force origin main"),
            "pretooluse-write-secrets.py": tool_event("Write", {"file_path": "key.pem", "content": WRITE_CASES.KEY_BLOCK}),
            "pretooluse-write-private-key.py": tool_event("Edit", {"file_path": "a.py", "old_string": "x", "new_string": AWS_EXAMPLE_KEY}),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for shim, payload in deny.items():
                for event_payload in (payload, "not json"):
                    with self.subTest(shim=shim, payload=event_payload[:20]):
                        shim_log, module_log = Path(tmp) / "shim.jsonl", Path(tmp) / "module.jsonl"
                        run_shim(HOOK_DIR / shim, event_payload, hook_env(CATPILOT_EVIDENCE_LOG=str(shim_log)))
                        run_module(SHIMS[shim], event_payload, hook_env(CATPILOT_EVIDENCE_LOG=str(module_log)))
                        lines, event_ids = [], []
                        for log in (shim_log, module_log):
                            entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
                            for entry in entries:
                                # The two fields that differ between runs: each must still be there and well formed.
                                self.assertRegex(entry.pop("ts"), TIMESTAMP)
                                event_id = entry.pop("event_id")
                                self.assertRegex(event_id, EVENT_ID)
                                event_ids.append(event_id)
                            lines.append(entries)
                            log.unlink()
                        self.assertEqual(len(lines[0]), 1)
                        self.assertEqual(lines[0], lines[1])
                        self.assertEqual(len(set(event_ids)), len(event_ids))

    def test_a_shim_loaded_as_a_module_exposes_the_checks_functions(self):
        import catpilot_guard.destructive
        import catpilot_guard.secrets
        import catpilot_guard.write_secrets

        for shim, module, name in (
            ("pretooluse-secrets.py", catpilot_guard.secrets, "find_credential"),
            ("pretooluse-write-secrets.py", catpilot_guard.write_secrets, "inspect_event"),
            ("pretooluse-destructive-ops.py", catpilot_guard.destructive, "find_destructive_op"),
        ):
            with self.subTest(shim=shim):
                spec = importlib.util.spec_from_file_location("catpilot_shim_" + module.__name__.rsplit(".", 1)[1], HOOK_DIR / shim)
                loaded = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(loaded)
                self.assertIs(getattr(loaded, name), getattr(module, name))
                self.assertIs(loaded.main, module.main)


class ShimFailsClosedTests(unittest.TestCase):
    MARKER = "catpilot-probe-7f3a"
    EVENTS = {
        "pretooluse-secrets.py": bash_event("echo catpilot-probe-7f3a"),
        "pretooluse-destructive-ops.py": bash_event("echo catpilot-probe-7f3a"),
        "pretooluse-write-secrets.py": tool_event("Write", {"file_path": "catpilot-probe-7f3a.txt", "content": "catpilot-probe-7f3a"}),
        "pretooluse-write-private-key.py": tool_event("Write", {"file_path": "catpilot-probe-7f3a.txt", "content": "catpilot-probe-7f3a"}),
    }

    def _place_shims(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for shim in SHIMS:
            shutil.copy2(HOOK_DIR / shim, directory / shim)

    def assert_blocked_without_echo(self, proc: subprocess.CompletedProcess) -> None:
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertIn("not allowed", proc.stderr)
        self.assertNotIn(self.MARKER, proc.stderr)

    def test_a_shim_exits_2_when_the_package_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Neither place a shim looks has the package: not beside it, and not two levels up.
            for directory in (Path(tmp) / "hooks" / "claude-code", Path(tmp) / "managed" / "hooks"):
                self._place_shims(directory)
                for shim, payload in self.EVENTS.items():
                    with self.subTest(layout=directory.relative_to(tmp).as_posix(), shim=shim):
                        proc = run_shim(directory / shim, payload, hook_env())
                        self.assert_blocked_without_echo(proc)
                        self.assertIn("catpilot_guard", proc.stderr)

    def test_a_shim_exits_2_when_the_package_cannot_be_imported(self):
        broken_forms = {
            "empty package": {"__init__.py": ""},
            "syntax error": {"__init__.py": "", "secrets.py": "def broken(:\n", "write_secrets.py": "def broken(:\n", "destructive.py": "def broken(:\n"},
            "error at import": {"__init__.py": "raise RuntimeError('broken install')\n"},
        }
        for form, files in broken_forms.items():
            with tempfile.TemporaryDirectory() as tmp:
                hooks = Path(tmp) / "hooks"
                self._place_shims(hooks)
                (hooks / "catpilot_guard").mkdir()
                for name, text in files.items():
                    (hooks / "catpilot_guard" / name).write_text(text, encoding="utf-8")
                for shim, payload in self.EVENTS.items():
                    with self.subTest(form=form, shim=shim):
                        proc = run_shim(hooks / shim, payload, hook_env())
                        self.assert_blocked_without_echo(proc)
                        self.assertNotIn("broken install", proc.stderr)

    def test_write_check_fails_closed_without_the_secrets_module(self):
        # The package keeps the old sibling rule: the write check needs secrets.py, the destructive check does not.
        with tempfile.TemporaryDirectory() as tmp:
            hooks = Path(tmp) / "hooks"
            self._place_shims(hooks)
            shutil.copytree(PACKAGE, hooks / "catpilot_guard", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "secrets.py"))
            for shim in ("pretooluse-write-secrets.py", "pretooluse-write-private-key.py"):
                with self.subTest(shim=shim):
                    proc = run_shim(hooks / shim, self.EVENTS[shim], hook_env())
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, "")
                    self.assertIn("Catpilot write check unavailable", proc.stderr)
                    self.assertNotIn(self.MARKER, proc.stderr)
            proc = run_shim(hooks / "pretooluse-destructive-ops.py", bash_event("rm -rf ~"), hook_env())
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('"deny"', proc.stdout)

    def test_a_shim_prefers_the_package_beside_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A checkout-shaped tree whose root package is broken, and a working package beside the shims.
            hooks = Path(tmp) / "hooks" / "claude-code"
            self._place_shims(hooks)
            (Path(tmp) / "catpilot_guard").mkdir()
            (Path(tmp) / "catpilot_guard" / "__init__.py").write_text("raise RuntimeError('wrong package')\n", encoding="utf-8")
            shutil.copytree(PACKAGE, hooks / "catpilot_guard", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            proc = run_shim(hooks / "pretooluse-secrets.py", bash_event("ls -la"), hook_env())
            self.assertEqual((proc.returncode, proc.stdout), (0, "{}\n"), proc.stderr)
            # Without the package beside it, the shim uses the one two levels up (here, the broken one).
            shutil.rmtree(hooks / "catpilot_guard")
            proc = run_shim(hooks / "pretooluse-secrets.py", bash_event("ls -la"), hook_env())
            self.assertEqual(proc.returncode, 2)

    def test_a_hook_run_writes_no_bytecode_beside_the_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            hooks = Path(tmp) / "hooks"
            self._place_shims(hooks)
            shutil.copytree(PACKAGE, hooks / "catpilot_guard", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            env = hook_env()
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            for shim, payload in self.EVENTS.items():
                self.assertEqual(run_shim(hooks / shim, payload, env).returncode, 0)
            self.assertEqual([p for p in hooks.rglob("*") if p.name == "__pycache__" or p.suffix == ".pyc"], [])


class PackageSourceTests(unittest.TestCase):
    def _sources(self):
        return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)

    def test_package_imports_only_the_standard_library(self):
        stdlib = getattr(sys, "stdlib_module_names", None)
        if stdlib is None:
            self.skipTest("sys.stdlib_module_names needs Python 3.10 or later")
        for path in self._sources():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module]
                else:
                    continue  # not an import, or a relative import inside the package
                for name in names:
                    top = name.split(".")[0]
                    with self.subTest(file=path.name, module=name):
                        self.assertTrue(top in stdlib or top in ("__future__", "catpilot_guard"), f"{path.name} imports {name}")

    def test_package_loads_without_site_packages(self):
        modules = [p.stem for p in self._sources() if p.stem != "__init__"]
        code = (
            "import importlib, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "for name in sys.argv[2:]:\n"
            "    importlib.import_module('catpilot_guard.' + name)\n"
            "importlib.import_module('catpilot_guard.write_secrets').secrets_module()\n"
        )
        # -I: no environment variables, user site, or current directory; -S: no site-packages at all.
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code, str(ROOT), *modules], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(sorted(modules), ["company_rules", "copilot", "destructive", "evidence", "policy", "secrets", "session_start", "write_secrets"])

    def test_package_and_shims_parse_as_python_3_8(self):
        for path in self._sources() + [HOOK_DIR / shim for shim in SHIMS]:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 8))
                annotated = any(
                    isinstance(node, ast.AnnAssign)
                    or (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and (node.returns is not None or any(a.annotation is not None for a in node.args.args + node.args.kwonlyargs)))
                    for node in ast.walk(tree)
                )
                future = any(
                    isinstance(node, ast.ImportFrom) and node.module == "__future__" and any(a.name == "annotations" for a in node.names)
                    for node in tree.body
                )
                # Annotations such as `str | None` are evaluated on 3.8 unless they are postponed.
                self.assertTrue(future or not annotated, "annotated file without `from __future__ import annotations`")


if __name__ == "__main__":
    unittest.main()
