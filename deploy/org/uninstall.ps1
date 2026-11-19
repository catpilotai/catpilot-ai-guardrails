<#
.SYNOPSIS
Remove what deploy\org\install.ps1 placed, and nothing else. Run from an elevated PowerShell.

.DESCRIPTION
  powershell -ExecutionPolicy Bypass -File deploy\org\uninstall.ps1 -ServerUrl https://mcp.example.com/mcp

A managed file is removed only when it is byte for byte what install.ps1 writes for this server URL and the
interpreter its hook commands name; an edited or merged one is kept and named. A tool's catpilot-guardrails\hooks\
stays while a kept managed file still mentions catpilot-guardrails, and the interpreter install.ps1 placed stays
while any kept file may run it: a hook that cannot start blocks every command on Claude Code. The skills it
installed are removed. Per-user evidence logs under ~\.catpilot-guardrails\ are left in place.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ServerUrl,
  [string]$PythonPath = ''
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-Administrator

$Python = if ($PythonPath) { $PythonPath } else { Get-RecordedInterpreter }
if ($Python -and (Test-Interpreter $Python)) {
  & $Python $WindowsFiles remove --python $Python --server-url $ServerUrl --cc-dir $CcDir --codex-dir $CodexDir --copilot-dir $CopilotDir
  if ($LASTEXITCODE -ne 0) { Stop-WithError "windows_files.py remove exited $LASTEXITCODE." }
} else {
  foreach ($file in @($SettingsFile, $RequirementsFile, $CopilotPolicyFile)) {
    if (Test-MentionsGuardrails $file) { Write-Output "kept    $file (no interpreter could run to compare it with what install.ps1 writes; remove the catpilot entries by hand)" }
  }
}

$keepCc = Test-MentionsGuardrails $SettingsFile
$keepCodex = Test-MentionsGuardrails $RequirementsFile
$keepCopilot = $false
if (Test-Path -LiteralPath (Join-Path $CopilotDir 'policy.d')) {
  foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $CopilotDir 'policy.d') -Filter '*.json' -File)) {
    if (Test-MentionsGuardrails $file.FullName) { $keepCopilot = $true }
  }
}

# Remove-Tree ROOT KEEP...: ROOT\catpilot-guardrails, except the named children a kept managed file still needs.
function Remove-Tree([string]$Root, [string[]]$Keep) {
  $tree = Join-Path $Root 'catpilot-guardrails'
  if (-not (Test-Path -LiteralPath $tree)) { return }
  if (@($Keep).Count -eq 0) {
    Remove-Item -LiteralPath $tree -Recurse -Force
    Write-Output "removed $tree"
    return
  }
  Get-ChildItem -LiteralPath $tree -Force | Where-Object { $Keep -notcontains $_.Name } | Remove-Item -Recurse -Force
  Write-Output "kept    $tree\$($Keep -join ', ') (a managed file still runs hooks from it; remove those entries, then run uninstall.ps1 again)"
}

$ccKeep = @()
if ($keepCc) { $ccKeep += 'hooks' }
if ($keepCc -or $keepCodex -or $keepCopilot) { $ccKeep += 'python' }
Remove-Tree $CcDir $ccKeep
Remove-Tree $CodexDir @($(if ($keepCodex) { 'hooks' }))
Remove-Tree $CopilotDir @($(if ($keepCopilot) { 'hooks' }))

foreach ($dir in @(Get-ChildItem -LiteralPath (Join-Path $CcDir '.claude\skills') -Directory -Filter 'catpilot-*' -ErrorAction SilentlyContinue)) {
  Remove-Item -LiteralPath $dir.FullName -Recurse -Force
  Write-Output "removed $($dir.FullName)"
}
Write-Output 'Done. Per-user evidence logs under ~\.catpilot-guardrails\ are left in place.'
