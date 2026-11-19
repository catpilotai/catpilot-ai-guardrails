# Dot-sourced by install.ps1, verify.ps1 and uninstall.ps1 (docs/spec/WINDOWS.md section 3.3): the managed paths, the
# administrator check and the interpreter check. Windows PowerShell 5.1 or PowerShell 7.

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$WindowsFiles = Join-Path $PSScriptRoot 'windows_files.py'
# The managed locations each tool reads (WINDOWS.md section 2). The CATPILOT_* variables point them elsewhere for tests.
$CcDir = if ($env:CATPILOT_CC_DIR) { $env:CATPILOT_CC_DIR } else { Join-Path $env:ProgramFiles 'ClaudeCode' }
$CodexDir = if ($env:CATPILOT_CODEX_DIR) { $env:CATPILOT_CODEX_DIR } else { Join-Path $env:ProgramData 'OpenAI\Codex' }
$CopilotDir = if ($env:CATPILOT_COPILOT_DIR) { $env:CATPILOT_COPILOT_DIR } else { Join-Path $env:ProgramData 'GitHub\Copilot' }
$SettingsFile = Join-Path $CcDir 'managed-settings.json'
$RequirementsFile = Join-Path $CodexDir 'requirements.toml'
$CopilotPolicyFile = Join-Path $CopilotDir 'policy.d\catpilot-guardrails.json'
$EmbeddedPython = Join-Path $CcDir 'catpilot-guardrails\python\python.exe'

function Stop-WithError([string]$Message) {
  [Console]::Error.WriteLine($Message)
  exit 2
}

function Assert-Administrator {
  if ($env:CATPILOT_ALLOW_NONADMIN -eq '1') { return }
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-WithError 'Run from an elevated PowerShell (Run as administrator): the managed locations are writable by administrators only, on purpose.'
  }
}

# Test-Interpreter PATH: the Python version PATH runs when it is an interpreter every account can use and runs
# Python 3.8 or later; otherwise $null, with the reason in $script:InterpreterError.
function Test-Interpreter([string]$Path) {
  $script:InterpreterError = $null
  if ($Path -notmatch '^[A-Za-z]:\\') { $script:InterpreterError = "$Path is not an absolute path (C:\...)"; return $null }
  if ($Path -match '["''$`%<>|*?]') { $script:InterpreterError = "$Path holds a character a hook command cannot carry"; return $null }
  if ($Path -match '\\WindowsApps\\') {
    $script:InterpreterError = "$Path is the Microsoft Store alias, which is per user and can open the Store instead of running Python"; return $null
  }
  if ($Path -match '^[A-Za-z]:\\Users\\') {
    $script:InterpreterError = "$Path is under C:\Users, one person's interpreter; the hooks run as every person"; return $null
  }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $script:InterpreterError = "$Path does not exist"; return $null }
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = $Path
  $info.Arguments = '-c "import sys; print(''%d.%d.%d'' % sys.version_info[:3]); sys.exit(0 if sys.version_info >= (3, 8) else 3)"'
  $info.UseShellExecute = $false
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.CreateNoWindow = $true
  try { $process = [System.Diagnostics.Process]::Start($info) } catch {
    $script:InterpreterError = "$Path could not start ($($_.Exception.Message))"; return $null
  }
  $stdout = $process.StandardOutput.ReadToEndAsync()
  [void]$process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit(10000)) {
    try { $process.Kill() } catch { }
    $script:InterpreterError = "$Path did not start within 10s"; return $null
  }
  $version = $stdout.Result.Trim()
  if ($process.ExitCode -eq 0) { return $version }
  if ($process.ExitCode -eq 3) { $script:InterpreterError = "$Path is Python $version; the hooks need 3.8 or later" }
  else { $script:InterpreterError = "$Path exited $($process.ExitCode) instead of running Python" }
  return $null
}

# Get-RecordedInterpreter: the python.exe the Claude Code hook commands name in managed-settings.json, else the
# interpreter install.ps1 places, else $null.
function Get-RecordedInterpreter {
  if (Test-Path -LiteralPath $SettingsFile) {
    try {
      $settings = Get-Content -Raw -LiteralPath $SettingsFile | ConvertFrom-Json
      foreach ($group in @($settings.hooks.PreToolUse)) {
        foreach ($entry in @($group.hooks)) {
          if ($entry.PSObject.Properties['args'] -and @($entry.args).Count -gt 0 -and "$(@($entry.args)[0])" -like '*catpilot-guardrails*') {
            return [string]$entry.command
          }
        }
      }
    } catch { }
  }
  if (Test-Path -LiteralPath $EmbeddedPython) { return $EmbeddedPython }
  return $null
}

function Test-MentionsGuardrails([string]$File) {
  if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { return $false }
  return [bool]((Get-Content -Raw -LiteralPath $File) -match 'catpilot-guardrails')
}
