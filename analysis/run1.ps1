# Minimal launcher: start an exe, poll for a window, report outcome. No extra flags.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File run1.ps1 -Exe <path> -Tag <name> [-Secs 30]
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Tag,
  [int]$Secs = 30
)
$ErrorActionPreference = 'SilentlyContinue'
$outDir = 'D:\Temp\bluebook-investigation\analysis\runs'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$report = Join-Path $outDir "$Tag.report.txt"

Get-Process Bluebook,etest32 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$exeDir = Split-Path $Exe -Parent
$base   = [System.IO.Path]::GetFileNameWithoutExtension($Exe)
$t0 = Get-Date
$proc = Start-Process -FilePath $Exe -WorkingDirectory $exeDir -PassThru

$maxProcs=0; $everSeen=0; $diedAt=$null; $win=$false; $title=''; $types=@{}
for ($i=0; $i -lt ($Secs*4); $i++) {
  Start-Sleep -Milliseconds 250
  $all = @(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
  if ($all.Count -gt 0) { $everSeen++ }
  if ($all.Count -gt $maxProcs) { $maxProcs = $all.Count }
  foreach ($p in $all) {
    $t='browser'; if ($p.CommandLine -match '--type=([A-Za-z0-9_-]+)') { $t=$matches[1] }
    $types[$t]=$true
  }
  $w = Get-Process $base -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
  if ($w) { $win=$true; $title=($w|Select-Object -First 1).MainWindowTitle; break }
  if ($all.Count -eq 0 -and $everSeen -gt 0) { $diedAt=((Get-Date)-$t0).TotalSeconds; break }
}
$verdict = if ($win) { "WINDOW OK ('$title')" } elseif ($diedAt) { "DIED $([math]::Round($diedAt,1))s" } elseif ($everSeen -gt 0) { "ALIVE-no-window" } else { "NEVER-STARTED" }
$line = "$Tag | $verdict | maxProcs=$maxProcs | types=$(($types.Keys|Sort-Object) -join ',') | exe=$Exe"
$line | Tee-Object -FilePath $report -Append | Write-Output
Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
