# fix_environment.ps1 - relocate a Bluebook install out of the user profile and
# leave a directory junction at the original path.
#
# WHY
# ---
# Bluebook 0.9.725 is a 32-bit Electron app. When its files live physically
# inside the current user's profile (C:\Users\<user>\...), its sandboxed GPU
# process dies at startup with IMMEDIATE_CRASH (0x80000003). After six
# retries the browser process calls LOG(FATAL) and exits, so the app never
# shows a window. The same binary works when its files live outside the
# profile. This is reproducible with a stock 32-bit Electron binary, so it is
# a 32-bit-Electron/profile interaction, not a Bluebook bug.
#
# WHAT IT DOES
# ------------
#   1. copies the install to a location outside the profile
#   2. renames the original directory
#   3. creates a directory junction at the original path -> new location
#
# After this, the app's files are physically outside the profile (so the GPU
# process survives) while its expected install path still resolves (so
# shortcuts, the Squirrel updater and the Uninstall registry entry keep
# working). The binary is not modified, so the College Board signature and the
# app's own integrity checks stay valid.
#
# USAGE
# -----
#   powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -DryRun
#   powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Apply
#   powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Revert
#
# -DryRun is the default and changes nothing.
#
# CAVEATS
# -------
# * A directory junction is used rather than a symlink so no elevation or
#   developer mode is required.
# * If Bluebook's auto-updater reinstalls the app, it may recreate the folder
#   inside the profile; re-run this script afterwards.
# * Moving the files changes what the app's file-integrity worker hashes as
#   paths. If the app reports an integrity failure, revert and use a plain
#   copy of the install in an external folder instead.
# * Do not use any of this to defeat exam integrity, proctoring or anti-cheat
#   controls.

[CmdletBinding()]
param(
    [string]$InstallPath = (Join-Path $env:LOCALAPPDATA 'Programs\bluebook'),
    [string]$TargetPath  = 'C:\BluebookApp',
    [switch]$Apply,
    [switch]$Revert,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "== $m" }
function Write-Info($m) { Write-Host "   $m" }

$profileRoot = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
$installFull = [System.IO.Path]::GetFullPath($InstallPath).TrimEnd('\')
$targetFull  = [System.IO.Path]::GetFullPath($TargetPath).TrimEnd('\')

Write-Step "Configuration"
Write-Info "profile      : $profileRoot"
Write-Info "install path : $installFull"
Write-Info "target path  : $targetFull"
Write-Info "mode         : $(if ($Revert) { 'REVERT' } elseif ($Apply) { 'APPLY' } else { 'DRY RUN' })"

# ---------------------------------------------------------------- revert -----
if ($Revert) {
    $backup = "$installFull.orig"
    Write-Step "Revert: restoring the original directory layout"
    if (-not (Test-Path $installFull)) { throw "install path not found: $installFull" }
    $item = Get-Item $installFull -Force
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Write-Info "install path is not a junction; nothing to revert"
        return
    }
    if (-not (Test-Path $backup)) { throw "backup not found: $backup" }
    Write-Info "removing junction $installFull"
    [System.IO.Directory]::Delete($installFull)
    Write-Info "restoring $backup -> $installFull"
    Move-Item $backup $installFull
    Write-Info "reverted. Files are back inside the profile (the crash will return)."
    return
}

# ------------------------------------------------------------------ apply ----
if (-not (Test-Path $installFull)) { throw "install path not found: $installFull" }
$exe = Join-Path $installFull 'Bluebook.exe'
if (-not (Test-Path $exe)) { throw "Bluebook.exe not found under $installFull" }

$insideProfile = $installFull.StartsWith($profileRoot + '\', [StringComparison]::OrdinalIgnoreCase)
Write-Step "Preconditions"
Write-Info "install is inside the user profile : $insideProfile"
if (-not $insideProfile) {
    Write-Info "This install is already outside the profile, so it is not affected"
    Write-Info "by this bug. Nothing to do."
    return
}

if (Test-Path $targetFull) { throw "target already exists: $targetFull (choose another -TargetPath)" }

$running = Get-Process Bluebook -ErrorAction SilentlyContinue
if ($running) { throw "Bluebook is running (pid $($running.Id -join ',')); close it first" }

$free = (Get-PSDrive -Name ([IO.Path]::GetPathRoot($targetFull).TrimEnd(':\'))).Free
$need = (Get-ChildItem $installFull -Recurse -File -ErrorAction SilentlyContinue |
         Measure-Object -Property Length -Sum).Sum
Write-Info ("space needed on target volume : {0:N0} MB" -f ($need / 1MB))
Write-Info ("space free on target volume   : {0:N0} MB" -f ($free / 1MB))
if ($free -lt $need) { throw "not enough free space on the target volume" }

Write-Step "Planned actions"
Write-Info "1. copy $installFull -> $targetFull"
Write-Info "2. rename $installFull -> $installFull.orig"
Write-Info "3. create junction $installFull -> $targetFull"
Write-Info "4. launch test from $installFull\Bluebook.exe"

if (-not $Apply) {
    Write-Host ""
    Write-Host "DRY RUN - nothing was changed. Re-run with -Apply to perform it."
    return
}

Write-Step "1/4 copying files"
Copy-Item $installFull $targetFull -Recurse -Force
Write-Info "copied"

Write-Step "2/4 renaming original"
Rename-Item $installFull "$([IO.Path]::GetFileName($installFull)).orig"
Write-Info "renamed to $installFull.orig"

Write-Step "3/4 creating junction"
$out = cmd /c mklink /J "$installFull" "$targetFull" 2>&1
Write-Info ($out -join ' ')
if (-not (Test-Path (Join-Path $installFull 'Bluebook.exe'))) {
    throw "junction did not resolve to Bluebook.exe; restore manually from $installFull.orig"
}
Write-Info "junction in place"

Write-Step "4/4 launch test (20 s)"
$p = Start-Process -FilePath (Join-Path $installFull 'Bluebook.exe') `
                   -WorkingDirectory $installFull -PassThru
$ok = $false
for ($i = 0; $i -lt 200; $i++) {
    Start-Sleep -Milliseconds 100
    $w = Get-Process Bluebook -ErrorAction SilentlyContinue |
         Where-Object { $_.MainWindowHandle -ne 0 }
    if ($w) { $ok = $true; break }
    if (-not (Get-Process Bluebook -ErrorAction SilentlyContinue)) { break }
}
Get-Process Bluebook -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($ok) {
    Write-Host ""
    Write-Host "SUCCESS - Bluebook opened a window."
    Write-Host "Its files now live at $targetFull."
    Write-Host "To undo:  -Revert"
} else {
    Write-Host ""
    Write-Host "FAILED - no window appeared. Reverting automatically."
    & $PSCommandPath -InstallPath $installFull -Revert
}
