<#
.SYNOPSIS
Check what deploy\org\install.ps1 placed, as a normal user: powershell -ExecutionPolicy Bypass -File deploy\org\verify.ps1

.DESCRIPTION
It reads the interpreter the Claude Code hook commands name and checks it runs Python 3.8 or later, then
(deploy\org\windows_files.py verify) runs each hook command in managed-settings.json, requirements.toml and the
Copilot CLI policy file on harmless probes, as the tool would run it (exec form, no shell): AWS's documentation
example key, a force push to main, a PowerShell Remove-Item of C:\Windows, each of which must be denied, and an
ordinary command, which must pass. It reads back the access list of each catpilot-guardrails directory. The
probes' evidence lines go to a temporary directory it removes. It runs the hooks directly, not through a tool, so
it proves nothing about what a session does; the session checks are in docs/DEPLOY_ORG.md.
#>
[CmdletBinding()]
param([string]$PythonPath = '')
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')

$Recorded = Get-RecordedInterpreter
if (-not $Recorded) {
  Write-Output "FAIL     no hook command in $SettingsFile names an interpreter: run install.ps1 (or merge the JSON it printed)"
  exit 1
}
$Python = if ($PythonPath) { $PythonPath } else { $Recorded }
$version = Test-Interpreter $Python
if (-not $version) {
  Write-Output "FAIL     $script:InterpreterError. Claude Code (onFailure block) then blocks every command and write the hooks cover."
  exit 1
}
Write-Output "recorded $Recorded (the interpreter the hook commands name)"
& $Python $WindowsFiles verify --cc-dir $CcDir --codex-dir $CodexDir --copilot-dir $CopilotDir
exit $LASTEXITCODE
