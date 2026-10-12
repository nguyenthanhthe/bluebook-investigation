# Discriminator: is the profile-path crash Bluebook-specific, or does ANY
# 32-bit Electron app fail there?
#   Uses the stock Electron tree already staged at D:\Temp\etest32 (renamed exe
#   + minimal app), copied to (a) inside the profile and (b) outside it.
$ErrorActionPreference='SilentlyContinue'
$src='D:\Temp\bluebook-investigation\exe\etest32'
if(-not (Test-Path "$src\etest32.exe")){
  # Fall back to the etest32 tree used earlier in the investigation.
  $src='D:\Temp\etest32'
}
Write-Output "source tree: $src  exists=$(Test-Path $src)"

function RunOnce([string]$exe,[string]$tag){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$died=$null;$ever=0;$types=@{}
  for($i=0;$i -lt 180;$i++){
    Start-Sleep -Milliseconds 100
    $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
    if($all.Count -gt 0){$ever++}
    foreach($p in $all){ $t='browser'; if($p.CommandLine -match '--type=([A-Za-z0-9_-]+)'){$t=$matches[1]}; $types[$t]=$true }
    $w=Get-Process $base -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
    if($w){$win=$true;break}
    if($all.Count -eq 0 -and $ever -gt 0){$died=((Get-Date)-$t0).TotalSeconds;break}
  }
  $v= if($win){'WINDOW_OK'} elseif($died){("DIED_{0:N1}s" -f $died)} elseif($ever -gt 0){'ALIVE'} else {'NEVER'}
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
  Write-Output ("{0,-40} {1,-13} types={2}" -f $tag,$v,(($types.Keys|Sort-Object) -join ','))
}

if(-not (Test-Path $src)){ Write-Output "no etest32 tree available; abort"; exit }

$A='C:\Users\Admin\etest_profile'
$B='C:\TempBB\etest_outside'
foreach($d in @($A,$B)){
  if(Test-Path $d){ Remove-Item $d -Recurse -Force }
  Copy-Item $src $d -Recurse -Force
}
RunOnce "$A\etest32.exe" 'etest32 INSIDE profile (C:\Users\Admin)'
RunOnce "$B\etest32.exe" 'etest32 OUTSIDE profile (C:\TempBB)'
