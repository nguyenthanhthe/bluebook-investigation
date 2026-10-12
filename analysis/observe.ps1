# Detailed observer: capture child command lines, timing, and Chromium log.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File observe.ps1 -Exe <path> -Tag <name> [-Secs 30] [-NoLog]
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Tag,
  [int]$Secs = 30,
  [switch]$NoLog
)
$ErrorActionPreference = 'SilentlyContinue'
$outDir = 'D:\Temp\bluebook-investigation\analysis\runs'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$logFile = Join-Path $outDir "$Tag.chromium.log"
$report  = Join-Path $outDir "$Tag.detail.txt"
Remove-Item $logFile,$report -Force -ErrorAction SilentlyContinue

Get-Process Bluebook,etest32 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$exeDir = Split-Path $Exe -Parent
$base   = [System.IO.Path]::GetFileNameWithoutExtension($Exe)
$args = @()
if (-not $NoLog) { $args = @('--enable-logging', "--log-file=$logFile", '--v=1') }

$L = New-Object System.Collections.Generic.List[string]
$L.Add("TAG=$Tag EXE=$Exe CWD=$exeDir ARGS=$($args -join ' ')")
$t0 = Get-Date
$proc = Start-Process -FilePath $Exe -WorkingDirectory $exeDir -ArgumentList $args -PassThru
$L.Add("launcher_pid=$($proc.Id)")

$firstSeen = @{}   # type -> ms of first observation
$lastSeen  = @{}
$win=$false; $title=''; $everSeen=0
for ($i=0; $i -lt ($Secs*10); $i++) {   # 100ms poll
  Start-Sleep -Milliseconds 100
  $ms = [int]((Get-Date)-$t0).TotalMilliseconds
  $all = @(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
  if ($all.Count -gt 0) { $everSeen++ }
  foreach ($p in $all) {
    $t='browser'; if ($p.CommandLine -match '--type=([A-Za-z0-9_-]+)') { $t=$matches[1] }
    if (-not $firstSeen.ContainsKey($t)) {
      $firstSeen[$t]=$ms
      $cl=$p.CommandLine; if ($cl.Length -gt 500){$cl=$cl.Substring(0,500)}
      $L.Add("FIRST $t @${ms}ms pid=$($p.ProcessId)")
      $L.Add("   cmd: $cl")
    }
    $lastSeen[$t]=$ms
  }
  $w = Get-Process $base -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
  if ($w) { $win=$true; $title=($w|Select-Object -First 1).MainWindowTitle; $L.Add("WINDOW @${ms}ms title='$title'"); break }
  if ($all.Count -eq 0 -and $everSeen -gt 0) { $L.Add("ALL_GONE @${ms}ms"); break }
}
$L.Add("--- lifetimes (first/last ms) ---")
foreach ($k in ($firstSeen.Keys | Sort-Object)) { $L.Add("  $k : $($firstSeen[$k]) .. $($lastSeen[$k])") }
$L.Add("RESULT: window=$win title='$title'")
if (Test-Path $logFile) { $L.Add("chromium log bytes=$((Get-Item $logFile).Length)") }
$L | Set-Content $report -Encoding UTF8
Get-Content $report | Write-Output
Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
