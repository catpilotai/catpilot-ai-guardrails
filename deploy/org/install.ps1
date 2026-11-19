<#
.SYNOPSIS
Place the Catpilot guardrails on one Windows machine the way an organization would (docs/spec/WINDOWS.md section 3.3).

.DESCRIPTION
Run from an elevated PowerShell, from a checkout of this repository:

  powershell -ExecutionPolicy Bypass -File deploy\org\install.ps1 -ServerUrl https://mcp.example.com/mcp

What it does, and nothing else:
  Interpreter  By default, Python's official embeddable distribution at a pinned version, checked against its
               pinned SHA-256, unpacked to <Claude Code dir>\catpilot-guardrails\python\. With -PythonPath, an
               interpreter IT already deploys. Either way it must run Python 3.8 or later before anything else is
               written, and every hook command names it by absolute path.
  Claude Code  hooks and their catpilot_guard package in C:\Program Files\ClaudeCode\catpilot-guardrails\hooks\,
               managed-settings.json with each hook in exec form ("command" python.exe, "args" the hook) and
               "onFailure": "block", and the skills in C:\Program Files\ClaudeCode\.claude\skills\.
  Codex CLI    hooks in %ProgramData%\OpenAI\Codex\catpilot-guardrails\hooks\ (the windows_managed_dir) and
               requirements.toml with each command as command_windows. Codex's managed defaults are per user on
               Windows, so the MCP server is not set machine-wide for Codex.
  Copilot CLI  hooks in %ProgramData%\GitHub\Copilot\catpilot-guardrails\hooks\ and policy.d\catpilot-guardrails.json
               with each hook as exec and args.
Each catpilot-guardrails directory, and each managed file it writes, gets an explicit access list: owner
Administrators; full control to Administrators and SYSTEM; read and execute to Users.

A managed file is written only when absent. An identical one is reported current, so running this again changes
nothing but the hook copies; any other is left alone and the content printed for a merge. Company rules
(-Overlay on macOS and Linux) are not placed on Windows yet. It does not touch user settings and restarts nothing.
Verify as a normal user with deploy\org\verify.ps1; remove with deploy\org\uninstall.ps1.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ServerUrl,
  [string]$PythonPath = '',
  [string]$Skills = 'safe-building,security-core'
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')

# The pinned interpreter (WINDOWS.md section 5, decision 1): python.org's embeddable distribution, by architecture.
$PinnedVersion = '3.12.10'
$PinnedSha256 = @{
  'AMD64' = '4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3'
  'ARM64' = '3065efc3d382d1cda66757ac71ade11904fa6e350f5a97eb74811acd71ba5532'
}

if ($ServerUrl -notmatch '^https?://[^"\\\s]+$') { Stop-WithError "-ServerUrl must be an http(s) URL (your own server)." }
Assert-Administrator


# .NET rather than Get-FileHash, Invoke-WebRequest and Expand-Archive: their modules may not load in Windows
# PowerShell started from PowerShell 7 (see windows-common.ps1), and these calls need no module.
function Get-Sha256([string]$Path) {
  $stream = [IO.File]::OpenRead($Path)
  try { $bytes = [Security.Cryptography.SHA256]::Create().ComputeHash($stream) } finally { $stream.Dispose() }
  return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

# Set-ManagedAcl PATH: owner Administrators; full control to Administrators and SYSTEM, read and execute to Users;
# no inherited entries and no other explicit ones. Children of a directory inherit only that.
function Set-ManagedAcl([string]$Path) {
  $isDir = Test-Path -LiteralPath $Path -PathType Container
  $inherit = if ($isDir) { '(OI)(CI)' } else { '' }
  & icacls $Path /setowner "*$AdminsSid" /T /C /Q | Out-Null
  & icacls $Path /inheritance:r /grant:r "*${AdminsSid}:${inherit}F" "*${SystemSid}:${inherit}F" "*${UsersSid}:${inherit}RX" /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { Stop-WithError "icacls could not set the access list of $Path." }
  # Explicit entries for anyone else (the creating account, or whoever made the directory first) survive
  # /inheritance:r: remove them.
  foreach ($rule in @((Get-Acl -LiteralPath $Path).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
    $sid = $rule.IdentityReference.Value
    if (@($AdminsSid, $SystemSid, $UsersSid) -notcontains $sid) { & icacls $Path /remove "*$sid" /C /Q | Out-Null }
  }
  if ($isDir -and @(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
    & icacls (Join-Path $Path '*') /reset /T /C /Q | Out-Null
  }
}

# New-LockedTree ROOT: ROOT\catpilot-guardrails and its hooks\, created and locked before anything is written into
# them, so nothing another account placed there first (in %ProgramData%, Users may create directories) stays
# writable by it or runs: hooks\ is then emptied of everything install.ps1 does not place.
function New-LockedTree([string]$Root, [string[]]$Names) {
  $tree = Join-Path $Root 'catpilot-guardrails'
  $hooks = Join-Path $tree 'hooks'
  foreach ($dir in @($tree, $hooks)) {
    if (Test-Path -LiteralPath $dir) {
      $item = Get-Item -LiteralPath $dir -Force
      if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Stop-WithError "Not installed: $dir is a link or a file, not a directory install.ps1 made. Remove it and run install.ps1 again."
      }
    }
  }
  if (-not (Test-Path -LiteralPath $tree)) { New-Item -ItemType Directory -Path $tree | Out-Null }
  Set-ManagedAcl $tree
  if (-not (Test-Path -LiteralPath $hooks)) { New-Item -ItemType Directory -Path $hooks | Out-Null }
  foreach ($entry in @(Get-ChildItem -LiteralPath $hooks -Force)) {
    if ($Names -contains $entry.Name -and -not ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      # A link: remove the link itself, never what it points to.
      if ($entry.PSIsContainer) { [IO.Directory]::Delete($entry.FullName, $false) } else { [IO.File]::Delete($entry.FullName) }
    } else {
      Remove-Item -LiteralPath $entry.FullName -Recurse -Force
    }
    Write-Output "removed $($entry.FullName) (not placed by install.ps1)"
  }
}

function Install-EmbeddedPython {
  $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  if (-not $PinnedSha256.ContainsKey($arch)) { Stop-WithError "Not installed: no pinned interpreter for $arch. Pass -PythonPath with Python 3.8 or later." }
  $sha = $PinnedSha256[$arch]
  $dir = Split-Path -Parent $EmbeddedPython
  $marker = Join-Path $dir 'catpilot-python.sha256'
  if ((Test-Path -LiteralPath $marker) -and (Test-Path -LiteralPath $EmbeddedPython) -and ((Get-Content -Raw -LiteralPath $marker).Trim() -eq $sha)) {
    return
  }
  # Staged inside the locked tree, so no other account can change the archive between the hash check and the unpack.
  $stage = Join-Path $CcDir ('catpilot-guardrails\staging-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $stage | Out-Null
  try {
    $zip = Join-Path $stage 'python.zip'
    if ($env:CATPILOT_PYTHON_ZIP) {
      # A copy fetched beforehand, for a machine without internet: copied in first, then checked and unpacked.
      Copy-Item -LiteralPath $env:CATPILOT_PYTHON_ZIP -Destination $zip
    } else {
      $url = "https://www.python.org/ftp/python/$PinnedVersion/python-$PinnedVersion-embed-$($arch.ToLower()).zip"
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      (New-Object Net.WebClient).DownloadFile($url, $zip)
    }
    $got = Get-Sha256 $zip
    if ($got -ne $sha) { Stop-WithError "Not installed: the interpreter archive has SHA-256 $got, not the pinned $sha for Python $PinnedVersion ($arch)." }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, (Join-Path $stage 'python'))
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    Move-Item -LiteralPath (Join-Path $stage 'python') -Destination $dir
    Set-Content -LiteralPath $marker -Value $sha -Encoding Ascii
    Write-Output "python  $dir (Python $PinnedVersion embeddable, SHA-256 checked)"
  } finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
  }
}

$common = @('pretooluse-secrets.py', 'pretooluse-write-secrets.py', 'pretooluse-destructive-ops.py', 'pretooluse-company-rules.py')
$ccNames = $common + 'pretooluse-write-private-key.py'

# 1. The interpreter, proved before anything else is written (issue #97, option 1). One IT deploys must be one only
# administrators can change, all of it, and nothing it loads outside it either (Test-TrustedInterpreter).
if ($PythonPath) {
  $Python = $PythonPath
  if (-not (Test-TrustedInterpreter $Python)) {
    Stop-WithError "Not installed: $script:InterpreterError. Pass -PythonPath with an interpreter only administrators can change, or omit it for the pinned interpreter."
  }
} else {
  New-LockedTree $CcDir ($ccNames + 'catpilot_guard')
  Install-EmbeddedPython
  $Python = $EmbeddedPython
  if (-not (Test-TrustedInterpreter $Python)) { Stop-WithError "Not installed: $script:InterpreterError." }
}
Write-Output "python  $Python (Python $script:InterpreterVersion), recorded in every hook command"

# Install-Hooks ROOT NAMES: the hook scripts and the catpilot_guard package (its .py files only) under
# ROOT\catpilot-guardrails\hooks\, created and locked first, replacing any earlier package so a module a newer
# release dropped does not linger.
function Install-Hooks([string]$Root, [string[]]$Names) {
  New-LockedTree $Root ($Names + 'catpilot_guard')
  $hooks = Join-Path $Root 'catpilot-guardrails\hooks'
  foreach ($name in $Names) { Copy-Item -LiteralPath (Join-Path $Repo "hooks\claude-code\$name") -Destination $hooks -Force }
  $package = Join-Path $hooks 'catpilot_guard'
  if (Test-Path -LiteralPath $package) { Remove-Item -LiteralPath $package -Recurse -Force }
  New-Item -ItemType Directory -Path $package | Out-Null
  Copy-Item -Path (Join-Path $Repo 'catpilot_guard\*.py') -Destination $package
  Write-Output "hooks   $hooks"
}

Install-Hooks $CcDir $ccNames
Install-Hooks $CodexDir $common
Install-Hooks $CopilotDir $common

foreach ($name in ($Skills -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
  $source = Join-Path $Repo "skills\catpilot-$name"
  if (-not (Test-Path -LiteralPath $source -PathType Container)) { Stop-WithError "no such skill: $source" }
  $target = Join-Path $CcDir ".claude\skills\catpilot-$name"
  if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
  Copy-Item -LiteralPath $source -Destination $target -Recurse
  Write-Output "skill   $target"
}

# 2. The managed files, written by windows_files.py with the proved interpreter: only when absent, or when they are
# what an earlier install wrote naming another interpreter.
$previous = Get-RecordedInterpreter
if (-not $previous) { $previous = '' }
$placed = & $Python $WindowsFiles place --python $Python --previous-python $previous --server-url $ServerUrl --cc-dir $CcDir --codex-dir $CodexDir --copilot-dir $CopilotDir
if ($LASTEXITCODE -ne 0) { Stop-WithError "windows_files.py place exited $LASTEXITCODE." }
$placed | Write-Output

# 3. The access lists again (the copies inherit them; this also covers the interpreter), and each managed file
# written now.
foreach ($root in @($CcDir, $CodexDir, $CopilotDir)) { Set-ManagedAcl (Join-Path $root 'catpilot-guardrails') }
foreach ($line in @($placed)) {
  if ("$line" -match '^(policy|updated) +(.+?)( \(now names .*\))?$') { Set-ManagedAcl $Matches[2] }
}
Write-Output 'locked  catpilot-guardrails\ under each managed directory: Administrators and SYSTEM change it, Users read it'

Write-Output ''
Write-Output "Codex's managed defaults are per user on Windows (~\.codex\managed_config.toml): set the MCP server through MDM or the repository route (docs/DEPLOY_ORG.md)."
Write-Output 'Done. Verify as a normal user: powershell -ExecutionPolicy Bypass -File deploy\org\verify.ps1, then the checks in docs/DEPLOY_ORG.md.'
