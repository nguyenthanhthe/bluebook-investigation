# Capture a Process Monitor trace while launching Bluebook from a given path.
# Requires admin for full fidelity. Uses Procmon's /Quiet /Minimized /BackingFile.
# Usage: powershell -File procmon_cap.ps1 -Exe <path> -Tag <name> [-Secs 20]
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Tag,
  [int]$Secs = 20
)
$ErrorActionPreference='SilentlyContinue'
$pm = 'D:\Temp\tools\Procmon\Procmon64.exe'
$outDir = 'D:\Temp\bluebook-investigation\analysis\runs'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$pml = Join-Path $outDir "$Tag.pml"
$csv = Join-Path $outDir "$Tag.csv"
Remove-Item $pml,$csv -Force -ErrorAction SilentlyContinue

Get-Process Bluebook -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process Procmon64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

# /NoFilter: we filter in analysis. /Quiet /Minimized: no UI. /AcceptEula required.
Start-Process -FilePath $pm -ArgumentList '/AcceptEula','/Quiet','/Minimized','/NoConnect' -Wait -WindowStyle Minimized | Out-Null
Start-Sleep -Seconds 2

# Start capture to backing file.
Start-Process -FilePath $pm -ArgumentList '/AcceptEula','/Quiet','/Minimized',"/BackingFile:$pml" -WindowStyle Minimized | Out-Null
Start-Sleep -Seconds 4

$exeDir = Split-Path $Exe -Parent
$base   = [System.IO.Path]::GetFileNameWithoutExtension($Exe)
$t0 = Get-Date
$p = Start-Process -FilePath $Exe -WorkingDirectory $exeDir -PassThru
Write-Output "launched pid=$($p.Id) at $($t0.ToString('o'))"

Start-Sleep -Seconds $Secs
Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Stop capture.
Start-Process -FilePath $pm -ArgumentList '/AcceptEula','/Quiet','/Terminate' -Wait -WindowStyle Minimized | Out-Null
Start-Sleep -Seconds 3

if (Test-Path $pml) { Write-Output "PML: $pml  bytes=$((Get-Item $pml).Length)" } else { Write-Output "PML MISSING" }

# Convert to CSV (all events).
Start-Process -FilePath $pm -ArgumentList '/AcceptEula','/Quiet','/OpenLog',"$pml",'/SaveAs',"$csv" -Wait -WindowStyle Minimized | Out-Null
Start-Sleep -Seconds 3
if (Test-Path $csv) { Write-Output "CSV: $csv  bytes=$((Get-Item $csv).Length)" } else { Write-Output "CSV MISSING" }
Get-Process Procmon64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
