# Launch with Electron/Chromium logging enabled via ENV VARS (no CLI args,
# which the app rejects) and capture stderr to a file.
# Usage: powershell -File envlog.ps1 -Exe <path> -Tag <name> [-Secs 20]
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Tag,
  [int]$Secs = 20
)
$ErrorActionPreference='SilentlyContinue'
$outDir='D:\Temp\bluebook-investigation\analysis\runs'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$err=Join-Path $outDir "$Tag.stderr.txt"
$out=Join-Path $outDir "$Tag.stdout.txt"
Remove-Item $err,$out -Force -ErrorAction SilentlyContinue

$base=[System.IO.Path]::GetFileNameWithoutExtension($Exe)
Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 700

$dir=Split-Path $Exe -Parent
$env:ELECTRON_ENABLE_LOGGING='1'
$env:ELECTRON_ENABLE_STACK_DUMPING='1'
$env:ELECTRON_LOG_FILE=$err
$env:CHROME_LOG_FILE=$err
$env:CHROME_HEADLESS=''
# Chromium reads --v via env? no. But ELECTRON_ENABLE_LOGGING maps to --enable-logging.

Write-Output "launching $Exe  cwd=$dir"
$p = Start-Process -FilePath $Exe -WorkingDirectory $dir -RedirectStandardError $err -RedirectStandardOutput $out -PassThru -NoNewWindow
$t0=Get-Date
for($i=0;$i -lt ($Secs*4);$i++){
  Start-Sleep -Milliseconds 250
  $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
  $w=Get-Process $base -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
  if($w){ Write-Output "WINDOW_OK after $([math]::Round(((Get-Date)-$t0).TotalSeconds,1))s"; break }
  if($all.Count -eq 0){ Write-Output "ALL_GONE after $([math]::Round(((Get-Date)-$t0).TotalSeconds,1))s"; break }
}
Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800
Remove-Item Env:\ELECTRON_ENABLE_LOGGING,Env:\ELECTRON_LOG_FILE,Env:\CHROME_LOG_FILE -ErrorAction SilentlyContinue
foreach($f in @($err,$out)){
  if(Test-Path $f){ Write-Output "--- $f  ($((Get-Item $f).Length) bytes) ---"; Get-Content $f -TotalCount 80 | Write-Output }
}
