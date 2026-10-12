# Dump the FULL command line of every process in the tree, for a crashing run
# and a working run, so any differing Chromium switch is visible.
param([Parameter(Mandatory=$true)][string]$Exe,[Parameter(Mandatory=$true)][string]$Tag,[int]$Secs=14)
$ErrorActionPreference='SilentlyContinue'
$base=[System.IO.Path]::GetFileNameWithoutExtension($Exe)
Get-Process $base -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Milliseconds 700
$dir=Split-Path $Exe -Parent
Start-Process -FilePath $Exe -WorkingDirectory $dir | Out-Null
$seen=@{}
for($i=0;$i -lt ($Secs*20);$i++){
  Start-Sleep -Milliseconds 50
  foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -EA SilentlyContinue)){
    $t='browser'; if($p.CommandLine -match '--type=([A-Za-z0-9_-]+)'){$t=$matches[1]}
    if(-not $seen.ContainsKey($t)){
      $seen[$t]=$p.CommandLine
      Write-Output "=== $Tag :: $t (pid $($p.ProcessId))"
      Write-Output $p.CommandLine
      Write-Output ""
    }
  }
  $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -EA SilentlyContinue)
  if($all.Count -eq 0 -and $i -gt 20){ break }
}
Get-Process $base -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Milliseconds 400
