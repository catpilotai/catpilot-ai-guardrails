# Dot-sourced by install.ps1, verify.ps1 and uninstall.ps1 (docs/spec/WINDOWS.md section 3.3): the managed paths, the
# administrator check and the interpreter check. Windows PowerShell 5.1 or PowerShell 7.

# Windows PowerShell started from PowerShell 7 inherits a PSModulePath that names PowerShell 7's modules first, and
# then cannot load its own (Get-Acl, Get-FileHash, ...). Start from the machine's value, with this edition's modules.
if ($PSVersionTable.PSEdition -ne 'Core') {
  $env:PSModulePath = (@((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'),
      [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')) | Where-Object { $_ }) -join ';'
}

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
$AdminsSid = 'S-1-5-32-544'
$SystemSid = 'S-1-5-18'
$UsersSid = 'S-1-5-32-545'
$TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$TrustedSids = @($AdminsSid, $SystemSid, $TrustedInstallerSid)
# Rights that change a file or directory: write or append data (create files or subdirectories), write attributes,
# delete, delete a child, change the access list, take ownership, and GENERIC_ALL / GENERIC_WRITE.
$WriteRights = [long]0x500D0156
# In a parent directory, only what can remove or replace the child: delete a child, change the access list, take
# ownership, GENERIC_ALL. (C:\ lets Authenticated Users create folders; that cannot touch an existing one.)
$ParentRights = [long]0x100C0040

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
  # The version, then the directories and archives the interpreter loads from (-I: the installation's own, without
  # this account's PYTHONPATH or user site).
  $info.Arguments = '-I -c "import os, sys; print(''%d.%d.%d'' % sys.version_info[:3]); [print(p) for p in sys.path if p and os.path.exists(p)]; sys.exit(0 if sys.version_info >= (3, 8) else 3)"'
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
  $lines = @($stdout.Result -split "`r?`n" | Where-Object { $_ })
  $version = if ($lines.Count -gt 0) { $lines[0].Trim() } else { '' }
  $script:InterpreterPaths = @($lines | Select-Object -Skip 1)
  if ($process.ExitCode -eq 0) { return $version }
  if ($process.ExitCode -eq 3) { $script:InterpreterError = "$Path is Python $version; the hooks need 3.8 or later" }
  else { $script:InterpreterError = "$Path exited $($process.ExitCode) instead of running Python" }
  return $null
}

# Get-UntrustedReason PATH MASK CHECKOWNER: why PATH can be changed by an account other than Administrators, SYSTEM or
# TrustedInstaller (an owner outside them, or an allow entry with a right in MASK for anyone else), or $null.
function Get-UntrustedReason([string]$Path, [long]$Mask, [bool]$CheckOwner) {
  try { $acl = Get-Acl -LiteralPath $Path } catch { return "$Path (its access list cannot be read)" }
  if ($CheckOwner) {
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -notcontains $owner) { return "$Path (owner $owner)" }
  }
  foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
    if ($rule.AccessControlType -ne 'Allow') { continue }
    if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    if (([long]$rule.FileSystemRights -band $Mask) -eq 0) { continue }
    $sid = $rule.IdentityReference.Value
    if ($TrustedSids -notcontains $sid) { return "$Path ($sid may change it)" }
  }
  return $null
}

# Test-TrustedTree ROOT: whether ROOT and everything under it can be changed only by Administrators, SYSTEM or
# TrustedInstaller, and none of its parents lets anyone else remove or replace it. Sets $script:InterpreterError.
function Test-TrustedTree([string]$Root) {
  $bad = @()
  $items = @(Get-Item -LiteralPath $Root -Force)
  if ($items[0].PSIsContainer) { $items += @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue) }
  foreach ($item in $items) {
    $reason = Get-UntrustedReason $item.FullName $WriteRights $true
    if ($reason) { $bad += $reason; if ($bad.Count -ge 3) { break } }
  }
  $parent = Split-Path -Parent $items[0].FullName
  while ($parent -and $bad.Count -lt 3) {
    $reason = Get-UntrustedReason $parent $ParentRights $false
    if ($reason) { $bad += $reason }
    $next = Split-Path -Parent $parent
    if ($next -eq $parent) { break }
    $parent = $next
  }
  if ($bad.Count -eq 0) { return $true }
  $script:InterpreterError = "an account other than Administrators, SYSTEM or TrustedInstaller can change what the interpreter runs: $($bad -join '; ')"
  return $false
}

# Test-TrustedInterpreter PATH: Test-Interpreter, after its directory tree (checked before it is run) and every
# directory or archive it loads from outside that tree pass Test-TrustedTree. A hook run by an interpreter some user
# can change, or that loads a .pth or module some user can write, is that user's code, run on every account.
# Sets $script:InterpreterVersion, or $script:InterpreterError.
function Test-TrustedInterpreter([string]$Path) {
  $script:InterpreterVersion = $null
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $script:InterpreterError = "$Path does not exist"; return $false }
  $installDir = Split-Path -Parent ((Resolve-Path -LiteralPath $Path).Path)
  if (-not (Test-TrustedTree $installDir)) { return $false }
  $version = Test-Interpreter $Path
  if (-not $version) { return $false }
  foreach ($entry in @($script:InterpreterPaths)) {
    $full = [IO.Path]::GetFullPath($entry)
    if ($full.StartsWith($installDir + '\', [StringComparison]::OrdinalIgnoreCase) -or $full -ieq $installDir) { continue }
    if (-not (Test-TrustedTree $full)) { return $false }
  }
  $script:InterpreterVersion = $version
  return $true
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
