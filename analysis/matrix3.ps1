# Localize the crash boundary: test many install locations to find exactly
# which path property triggers the GPU-process crash.
$ErrorActionPreference='SilentlyContinue'
$real='C:\Users\Admin\AppData\Local\Programs\bluebook'

$locs = [ordered]@{
  'U1_Users_Admin_root'    = 'C:\Users\Admin\bbt2'
  'U2_Users_Admin_Desktop' = 'C:\Users\Admin\Desktop\bbt2'
  'U3_Users_Admin_Docs'    = 'C:\Users\Admin\Documents\bbt2'
  'U4_Users_Admin_AppData' = 'C:\Users\Admin\AppData\bbt2'
  'U5_Users_Public'        = 'C:\Users\Public\bbt2'
  'U6_Users_Other'         = 'C:\Users\bbt2'
  'U7_ProgramData'         = 'C:\ProgramData\bbt2'
  'U8_C_root'              = 'C:\bbt2'
  'U9_C_ProgramFiles'      = 'C:\Program Files\bbt2'
}

function RunOnce([string]$exe){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 600
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$died=$null;$ever=0
  for($i=0;$i -lt 140;$i++){
    Start-Sleep -Milliseconds 100
    $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
    if($all.Count -gt 0){$ever++}
    $w=Get-Process $base -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
    if($w){$win=$true;break}
    if($all.Count -eq 0 -and $ever -gt 0){$died=((Get-Date)-$t0).TotalSeconds;break}
  }
  $v= if($win){'WINDOW_OK'} elseif($died){("DIED_{0:N1}s" -f $died)} elseif($ever -gt 0){'ALIVE'} else {'NEVER'}
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
  return $v
}

foreach($k in $locs.Keys){
  $dst=$locs[$k]
  if(Test-Path $dst){ Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue }
  New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
  $ok=$false
  try { Copy-Item $real $dst -Recurse -Force -ErrorAction Stop; $ok=$true } catch { }
  if(-not $ok){ Write-Output ("{0,-24} COPY_FAILED" -f $k); continue }
  $v = RunOnce (Join-Path $dst 'Bluebook.exe')
  Write-Output ("{0,-24} {1}" -f $k,$v)
}
