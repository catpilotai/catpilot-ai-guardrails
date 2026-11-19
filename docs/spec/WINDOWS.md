# Windows: design note

**Status:** Proposed on 2026-11-17; the maintainer's decisions are in §5.
Increments 1 and 2 are built (§6). Increments 3 and 4 are not. Nothing in this
note has run on a Windows host: the unit tests run on a `windows-latest` CI
runner, which checks the Python and runs no tool. Each vendor
fact below cites the vendor page it comes from. Facts marked **to check** are
not documented and need a Windows host.

**Companion to:** [`docs/DEPLOY_ORG.md`](../DEPLOY_ORG.md) (the macOS and
Linux deployment), [`hooks/README.md`](../../hooks/README.md) (what each hook
covers) and [`OVERLAY_V2.md`](./OVERLAY_V2.md) (the company rules the hooks
enforce).

The hooks, the company rules and the install scripts assume macOS or Linux.
This note covers what breaks on a Windows machine where people run Claude
Code, Codex CLI or GitHub Copilot CLI natively, not in WSL. It proposes four
increments to fix it and says how each would be verified.

---

## 1. What breaks today

Each item is read from the current code.

1. **The hook commands are POSIX shell.**
   - Every registered command has the form
     `CATPILOT_EVIDENCE_LOG="$HOME/..." python3 "/Library/..."`.
   - The `NAME=value command` prefix is POSIX syntax. PowerShell runs no such
     prefix, and `$HOME` is not a Windows variable.
   - Claude Code runs a shell-form hook with Git Bash, or with PowerShell
     when Git Bash isn't installed ([hooks reference](https://code.claude.com/docs/en/hooks),
     "Exec form and shell form").
   - Without Git Bash, every hook command fails. On Claude Code 2.1.295 and
     later, `"onFailure": "block"` then blocks every command and write
     (#132), which fails safe but makes the tool unusable.
2. **`python3` is usually not a real interpreter.**
   - A Windows machine often has no `python3` at all.
   - Where one is found, it may be the Microsoft Store alias, which opens the
     Store instead of running Python. That is the Windows equivalent of the
     macOS Command Line Tools stub that `verify.sh` already names.
3. **Claude Code's PowerShell tool is not matched.**
   - "On Windows, wherever the PowerShell tool is enabled, Claude treats
     PowerShell as the primary shell and routes shell commands through it."
   - "On Windows without Git Bash, the tool is enabled automatically and
     Claude Code doesn't register the Bash tool at all. A hook that matches
     only `Bash` never fires there." ([hooks reference](https://code.claude.com/docs/en/hooks),
     "PowerShell").
   - Every shell-command matcher in `deploy/org/claude-code/managed-settings.json`
     is `Bash`.
4. **The command readers parse POSIX shell, not PowerShell.**
   - The destructive check, the company rules and the deploy, registry and
     cloud readers all split commands with POSIX shell rules (`shlex`).
   - A PowerShell deletion matches none of their patterns. Examples:
     `Remove-Item -Recurse -Force $env:USERPROFILE`, `rm -r -fo ~`,
     `ri C:\ -r`, or `cmd /c rd /s /q C:\`.
   - So the destructive check lets every PowerShell deletion through.
   - The secret checks are unaffected, because they match text, not shell
     syntax.
   - `git push --force origin main` reads the same in PowerShell, so the
     protected-branch checks still work on it. PowerShell's backtick is its
     escape character, not a substitution. The readers treat a backtick as
     unknown, which fires a rule, so this errs strict.
5. **The policy file check refuses every policy on Windows.**
   - `catpilot_guard/policy.py` `read_checked` compares `st_uid` and refuses
     group- or other-writable mode bits.
   - On Windows, `st_uid` is always 0, and `st_mode` reflects only the
     read-only attribute: a file that is not read-only reports `0o666`.
   - So every policy file reads as `wrong-owner`. Every company rule then
     fails closed as `policy_error`, and no company rule applies.
   - `O_NOFOLLOW` does not exist on Windows (the code falls back to `0`), so
     a symbolic link or junction is not refused either.
6. **Managed paths differ, and the install scripts are bash.**
   - `install.sh`, `uninstall.sh` and `verify.sh` use bash, `sudo`, `chmod`
     and `/etc/...` paths.
   - `evidence.py` already runs without `fcntl`: each line is one write,
     without a lock.

## 2. Where each tool reads managed configuration on Windows

| Tool | Hooks and settings | Machine-wide instructions and skills | Source |
| --- | --- | --- | --- |
| Claude Code | `C:\Program Files\ClaudeCode\managed-settings.json`, or the `Settings` value under `HKLM\SOFTWARE\Policies\ClaudeCode` | `C:\Program Files\ClaudeCode\CLAUDE.md`; skills under `C:\Program Files\ClaudeCode\.claude\skills\` | [managed settings](https://code.claude.com/docs/en/managed-settings), [memory](https://code.claude.com/docs/en/memory) |
| Codex CLI | `%ProgramData%\OpenAI\Codex\requirements.toml`, with hook scripts under `[hooks] windows_managed_dir` (absolute, and it must exist) and each command's `command_windows` | Managed defaults: `~/.codex/managed_config.toml`, which is per user on Windows, so the user can edit it | [managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration), [hooks](https://learn.chatgpt.com/docs/hooks) |
| Copilot CLI | Policy hooks: `C:\ProgramData\GitHub\Copilot\policy.d\*.json`, or values under `HKLM\Software\Policies\GitHub\Copilot`. Managed settings: `%ProgramFiles%\GitHubCopilot\managed-settings.json` or `HKLM\SOFTWARE\Policies\GitHubCopilot` | Not placed by this package today | [hooks reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference), [config directory reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference) |

Hook command forms each tool offers on Windows:

- **Claude Code: exec form.** When `args` is set, Claude Code spawns
  `command` directly, with no shell: "each `args` element is one argument
  exactly as written". On Windows, `command` must resolve to a real
  executable, such as a `.exe`.
- **Codex CLI: `command_windows`.** It overrides `command` on Windows, as in
  the vendor's example, `py -3 C:\enterprise\hooks\pre_tool_use_policy.py`.
- **Copilot CLI: `powershell` or `exec`.** A command hook takes a
  `powershell` field. An `exec` field with `args` runs the executable "without
  shell interpretation", and an `env` field sets environment variables. In
  Claude-shaped `PreToolUse` payloads, the runtime `powershell` tool reports as
  `Bash`, so the existing `Bash` matcher already fires on PowerShell commands.

## 3. Proposal

### 3.1 Increment 1: the hooks run, and the policy check works

The goal: the existing checks run on Windows, with the same results as today
for POSIX-shaped commands. The PowerShell gap from §1 item 4 remains, and
the docs say so.

- **A Python interpreter the hooks control.**
  - `install.ps1` places Python's official embeddable distribution, at a
    pinned version and SHA-256, under
    `<managed dir>\catpilot-guardrails\python\`.
  - Every hook command names that `python.exe` by absolute path.
  - The interpreter then has the same ACL as the hooks, and doesn't depend on
    `PATH`, the Store alias or a version manager.
  - Alternative: `-PythonPath`, for an interpreter IT already deploys.
    `verify.ps1` would check it starts and is 3.8 or later, as `verify.sh`
    does.
- **No shell in hook commands.**
  - A new hook option, `--evidence-default`, means: when
    `CATPILOT_EVIDENCE_LOG` is unset, write to
    `~/.catpilot-guardrails/evidence.jsonl`, through `os.path.expanduser`,
    which resolves to `%USERPROFILE%` on Windows.
  - Each command then needs no environment prefix, and runs:
    - in exec form on Claude Code (`command` set to the `python.exe` path;
      `args` set to the hook path, `--evidence-default` and the hook's other
      options);
    - as `command_windows` on Codex, quoted for its command parsing;
    - as `exec` on Copilot CLI.
  - Every Claude Code entry keeps `"onFailure": "block"`.
  - The option is harmless on macOS and Linux, which keep their current form.
- **Claude Code matchers include PowerShell.** Every shell-command matcher
  becomes `Bash|PowerShell`, on every OS. The PowerShell tool's input has the
  same `command` field as Bash
  ([hooks reference](https://code.claude.com/docs/en/hooks), "PowerShell").
- **The policy check on Windows: owner and ACL, read with `ctypes`.**
  - The check stays stdlib-only. It uses `GetNamedSecurityInfoW` through
    `ctypes` to read the owner SID and the DACL of the policy file and of its
    directory.
  - It passes only when both conditions hold:
    - the owner is `BUILTIN\Administrators` (S-1-5-32-544), `SYSTEM`
      (S-1-5-18) or TrustedInstaller;
    - every allow ACE that grants write, append, delete, `WRITE_DAC` or
      `WRITE_OWNER` names one of those three SIDs.
  - Deny ACEs are ignored, which can only make the check stricter.
  - This is the POSIX rule (owner, then nobody else can write) in Windows
    terms. It does not depend on who runs the hook.
  - A file or directory with the reparse-point attribute is refused, in
    place of `O_NOFOLLOW`. The file is opened first. Then `os.fstat` on the
    open handle is compared with `os.lstat` of the path (volume serial and
    file index), so the file cannot be swapped between the check and the
    read.
  - `install.ps1` sets that ACL explicitly, with `icacls /inheritance:r`,
    granting full control to Administrators and SYSTEM and read and execute
    to Users. The check then doesn't rely on what `Program Files` inherits.
- **Copilot CLI's PowerShell tool.**
  - `catpilot_guard/copilot.py` reads `write_bash` input for its key tokens.
  - **To check:** whether the PowerShell tool has a matching interactive-input
    tool, and what its input looks like. Until that is known, any input tool
    the converter doesn't recognize fails closed, as it does today.
- **Codex on Windows.** **To check:** the `tool_name` Codex sends for a shell
  command on Windows. The vendor's examples match `^Bash$` and don't say.
- **CI.** The unit tests also run on a `windows-latest` runner:
  - the policy ACL check, against files the test creates with `icacls`;
  - the exec-form commands;
  - the evidence writer without `fcntl`.

  That verifies the Python on Windows. It does not verify any tool.

### 3.2 Increment 2: a PowerShell reader for the destructive and company checks

The goal: a command sent through the PowerShell tool is read as PowerShell.

- **When it is used.** `catpilot_guard/powershell.py`, stdlib only, splits a
  command into simple commands with PowerShell's rules, for these inputs:
  - Claude Code's `PowerShell` tool;
  - Copilot CLI's `powershell` runtime tool, if its payload says which tool
    ran (**to check**);
  - `pwsh -Command`, `powershell -c` and `powershell.exe` with a script
    string, inside any command.
- **What it splits on:**
  - single quotes (no escapes) and double quotes (backtick escapes, `$`
    expansion);
  - backtick line continuation;
  - `;`, `|`, `&&` and `||`;
  - the call operator `&`;
  - script blocks `{ }`.
- **What it unwraps:**
  - `Invoke-Expression` and `iex` with a literal string;
  - `pwsh` and `powershell` with `-Command`, `-c` or `-EncodedCommand`. An
    encoded command is base64 of UTF-16LE text, so the reader decodes it and
    reads the text.
  - `cmd /c` and `cmd /k`, read with cmd's simpler rules;
  - `Start-Process` with `-ArgumentList`.
  - An expression the reader cannot resolve, such as a string built at run
    time, is unknown.
- **Parameter names are matched by unambiguous prefix and in any letter
  case,** as PowerShell matches them: `-r`, `-Rec` and `-Recurse` are the
  same option.
- **What the destructive check adds:**
  - `Remove-Item` and its aliases (`rm`, `del`, `erase`, `rd`, `rmdir`, `ri`)
    with `-Recurse` on a dangerous target, and `rd /s` and `del /s` under
    `cmd`;
  - dangerous targets: a drive root (`C:\`, `C:/`, `\`), `$env:SystemRoot`
    and `C:\Windows`, `C:\Program Files`, the home directory (`~`, `$HOME`,
    `$env:USERPROFILE`, `C:\Users\<name>`), and its credential directories
    (`.ssh`, `.aws`, `.azure`, `.kube`, `.docker`, `.gnupg`, and
    `$env:APPDATA\gcloud`);
  - the Windows equivalents of the disk-wiping commands already listed:
    `Format-Volume`, `Clear-Disk`, `Remove-Partition`, `format <drive>:`,
    `diskpart` with a script, `cipher /w`, and `vssadmin delete shadows`.
- **What the company rules, deploy, registry and cloud readers get:** the
  same argv lists, so `git push`, `scp`, `npm --registry` and
  `aws ... --role-arn` read as they do in bash.
  - PowerShell variables (`$x`, `$env:X`, `${x}`) and subexpressions
    (`$( )`) are unknown, as shell variables are today.
  - The current-branch substitutions that #133 reads in bash get no PowerShell
    equivalent until someone asks for one.
- **Tests:** command tables, as in `tests/test_destructive_hook.py`, plus a
  rule that every POSIX case with a PowerShell spelling gets one. CI runs the
  tables on every OS, since the reader is plain Python.

### 3.3 Increment 3: `install.ps1`, `uninstall.ps1` and `verify.ps1`

- **Thin PowerShell over the existing Python.**
  - `session_start_files.py` already writes the generated JSON and TOML and
    runs the verify probes. The PowerShell scripts handle what is
    Windows-specific: elevation, paths, ACLs, the embedded Python and the
    registry.
  - The behavior is the same as the bash scripts, which already handle
    existing files: write a managed file only when it is absent, otherwise
    print it for a merge, and remove only what was placed, unchanged.
- **Paths:**
  - Claude Code: `C:\Program Files\ClaudeCode\catpilot-guardrails\`.
  - Codex: `%ProgramData%\OpenAI\Codex\catpilot-guardrails\hooks\`, the
    `windows_managed_dir`.
  - Copilot: `C:\ProgramData\GitHub\Copilot\catpilot-guardrails\`, with the
    policy file in `policy.d\`.
- **Codex's managed defaults on Windows are per user**
  (`~/.codex/managed_config.toml`). The MCP server cannot be set
  machine-wide there. `install.ps1` says so, and points to MDM or to the
  repository route.
- **`verify.ps1`** runs as a normal user, like `verify.sh`, with the same
  probes, plus two more:
  - a PowerShell deletion probe, once increment 2 is in;
  - an ACL readback that shows the user cannot write the policy or the
    hooks.
- **MDM.** The registry routes (`HKLM\SOFTWARE\Policies\ClaudeCode`
  `Settings`, and Copilot's policy key) are documented for Intune and Group
  Policy. `install.ps1 -PrintRegistry` prints the values instead of writing
  files.

### 3.4 Increment 4: a host check on Windows

- **The host check kit becomes cross-platform Python.** `run.sh` becomes
  `run.py`, so one kit runs on macOS, Linux and Windows.
- **The owner runs it on Windows 11**, in a VM or on a spare machine, with
  the three tools, twice:
  - **with Git Bash:** Claude Code has both tools, and Bash and PowerShell
    commands both reach the hooks;
  - **without Git Bash:** Claude Code has only the PowerShell tool.
- **The probes:** the current nine, plus PowerShell spellings of the deletion
  and the force push, plus a control run after the uninstall.
- **The result** is a verification note under `evals/reports/`, and rows in
  DEPLOY_ORG's status table. Until then, every Windows row says "not verified
  on a host".

## 4. What this does not cover

- **WSL.** Inside WSL, the Linux paths and `install.sh` apply already
  (Claude Code reads `/etc/claude-code/` there). A native Windows session does
  not read WSL's files, and a WSL session does not read the Windows files: a
  machine using both needs both installs.
- **IDE extensions, desktop apps and cloud agents.** That is the same scope
  as on macOS and Linux.
- **Scripts a command runs.** A `.ps1` or `.bat` file the agent wrote and
  then ran is not read, as with `./deploy.sh` today.
- **PowerShell constructs the reader leaves unknown.** Splatting (`@args`),
  dynamic parameter names and `.NET` calls such as
  `[IO.Directory]::Delete($p, $true)` are not read. The destructive check
  lets them through. The company rules fire on them only when an argument is
  a variable they would read.

## 5. Decisions for the maintainer

**Decided on 2026-11-18 by the maintainer:** 1, the embedded pinned interpreter by default with `-PythonPath`;
2, increments 1 and 2 ship together, increment 1's CI job first; 3, `--evidence-default` on every OS, the current
prefix kept on macOS and Linux for one release; 4, the full list in §3.2.

1. **Python on Windows:** the embedded, pinned interpreter by default, with
   `-PythonPath` as the alternative (recommended), or require IT to deploy
   Python.
2. **Order:** increments 1 and 2 together. Shipping hooks that let every
   PowerShell deletion through (increment 1 alone) would put Windows users
   behind macOS on the check people notice most. Recommended: ship them
   together, with increment 1's CI job first.
3. **`--evidence-default` on every OS,** so the hook commands match across
   platforms, or only on Windows. Recommended: every OS, with the current
   prefix kept on macOS and Linux for one release.
4. **Scope of increment 2's destructive list:** the targets and commands in
   §3.2, or a shorter list for a first version.

## 6. What was built (increments 1 and 2)

Built together, increment 1's CI job first (decision 2). Not verified on a host.

- **§3.1.** `--evidence-default` in every hook (`catpilot_guard/__init__.py`
  `take_evidence_default`); `install.sh` writes it after the hook's path on
  every OS, with the prefix kept beside it on macOS and Linux for this release,
  and `verify.sh` accepts a company-rules command with or without it (decision
  3). Every Claude Code shell matcher is `Bash|PowerShell`, and the secret,
  destructive and company-rules checks take the `PowerShell` tool (evidence
  `tool` `PowerShell`). `policy.read_checked` reads the owner and DACL on
  Windows as above; the access list of the file is read from its open handle
  (`GetSecurityInfo`), its directory's by name, and inherit-only entries are
  skipped because they do not apply to the object itself. The `windows-latest`
  job runs `tests/windows_suite.py` on Python 3.8 and 3.12, including files
  whose owner and access list `icacls` sets, and the hooks in exec form.
- **§3.2.** `catpilot_guard/powershell.py`, with the full list (decision 4).
  Additions beyond the text above: a `Get-ChildItem`, `Get-Item` or literal
  path piped into a `Remove-Item` with no path of its own is read with that
  path; `-WhatIf` is allowed; `C:\ProgramData` and `C:\Users` count as system
  directories; any `diskpart` run is denied (its script comes from `/s` or from
  piped input); `wmic shadowcopy delete` joins `vssadmin delete shadows`; the
  whole-command signatures (cloud, `terraform`, `dd`, ...) also run on each
  unwrapped command, so an encoded one is read. A bare variable is dangerous, as
  in bash, except the pipeline's `$_` and `$PSItem`.
- **Copilot CLI and Codex** (the two **to check** items in §3.1): the payloads
  do not say which shell ran, so on Windows the destructive check reads a `Bash`
  event from either host both as bash and as PowerShell, and denies if either
  reading matches. The company rules read it as bash there.
- **Deferred:** the exec-form, `command_windows` and `exec` entries themselves
  and the embedded interpreter belong to `install.ps1` (increment 3); the hooks
  run in that form today (tested), with any Python 3.8 or later. The host check
  is increment 4.

## 7. What was built (increment 3)

Not verified on a host. `deploy/org/install.ps1`, `verify.ps1` and `uninstall.ps1`
(with `windows-common.ps1`) are thin PowerShell over `deploy/org/windows_files.py`,
as §3.3 proposes. Built as described there, with these specifics:

- **The interpreter** (decision 1): python.org's embeddable 3.12.10, AMD64 or ARM64,
  checked against a pinned SHA-256 before it is unpacked; `-PythonPath` otherwise.
  Either must run Python 3.8 or later before anything else is written, as on macOS
  and Linux (issue #97, option 1). `-PythonPath` refuses the Store alias,
  anything under `C:\Users`, and any interpreter whose directory tree, parents or
  `sys.path` entries an account other than Administrators, SYSTEM or
  TrustedInstaller can change (checked with `Get-Acl` before the interpreter runs).
- **Pre-existing directories:** each `catpilot-guardrails` tree is created and
  locked first, a link in its place is refused, and `hooks\` is emptied of
  anything install.ps1 does not place. The pinned archive is staged inside the
  locked tree before it is hashed.
- **Codex `command_windows`:** read from openai/codex on 2026-11-19: Codex runs it
  through the session's shell, PowerShell on Windows
  (`powershell -NoProfile -Command <line>`; `cmd.exe /C` only when no PowerShell is
  found), so the line is `& "<python.exe>" "<hook>" ...`. Under the `cmd.exe`
  fallback it does not run. Not verified with Codex on a host; `verify.ps1` runs it
  through PowerShell the same way.
- **Access lists:** `icacls /inheritance:r` with Administrators and SYSTEM full
  control and Users read and execute, every other explicit entry removed, children
  reset to inherit only, owner Administrators; `verify.ps1` reads them back with
  the same rule as `policy.read_checked`.
- **CI:** `tests/test_windows_install.py` runs the three scripts on the
  `windows-latest` runner, with `-PythonPath` and with the pinned interpreter.
- **Not yet:** `-Overlay` (company rules and enforcement), `-PrintRegistry`, Codex
  skills and managed defaults (per user on Windows), and the PowerShell deletion
  probe through Codex and Copilot CLI, whose Windows tool names are still unknown
  (§3.1).
