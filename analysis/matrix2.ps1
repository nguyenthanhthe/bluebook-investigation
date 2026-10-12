# Refine: is the trigger "Programs", all of LOCALAPPDATA, or all of AppData?
$ErrorActionPreference='SilentlyContinue'
$real = 'C:\Users\Admin\AppData\Local\Programs\bluebook'
$L = [System.Environment]::GetFolderPath('LocalApplicationData')
$A = [System.Environment]::GetFolderPath('ApplicationData')
$U = [System.Environment]::GetFolderPath('UserProfile')

$locs = [ordered]@{
  'P1_Programs'          = "$L\Programs\bbt"
  'P2_Local_root'        = "$L\bbt"
  'P3_Local_Temp'        = "$L\Temp\bbt"
  'P4_Roaming'           = "$A\bbt"
  'P5_UserProfile'       = "$U\bbt"
  'P6_C_Temp'            = 'C:\TempBB\bbt'
}

function RunOnce([string]$exe,[string]$tag){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$sawGpu=$false;$died=$null;$ever=0
  for ($i=0;$i -lt 150;$i++){
    Start-Sleep -Milliseconds 100
    $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
    if($all.Count -gt 0){$ever++}
    foreach($p in $all){ if($p.CommandLine -match '--type=gpu-process'){$sawGpu=$true} }
    $w=Get-Process $base -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
    if($w){$win=$true;break}
    if($all.Count -eq 0 -and $ever -gt 0){$died=((Get-Date)-$t0).TotalSeconds;break}
  }
  $v= if($win){'WINDOW_OK'} elseif($died){("DIED_{0:N1}s" -f $died)} elseif($ever -gt 0){'ALIVE_NO_WINDOW'} else {'NEVER_STARTED'}
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  return "$tag`t$v`tgpu=$sawGpu"
}

foreach ($k in $locs.Keys) {
  $dst=$locs[$k]
  if (Test-Path $dst) { Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue }
  New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
  Copy-Item $real $dst -Recurse -Force
  RunOnce (Join-Path $dst 'Bluebook.exe') $k | Write-Output
}
