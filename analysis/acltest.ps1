# Decisive ACL test:
#   T1: copy into Programs (crashing parent), then GRANT BUILTIN\Users read+exec
#   T2: copy to C:\TempBB (working parent), then STRIP Users/AuthUsers + add pkg SID
# If T1 works and/or T2 breaks, the trigger is the directory ACL, not the path.
$ErrorActionPreference='SilentlyContinue'
$real='C:\Users\Admin\AppData\Local\Programs\bluebook'
$pkg='S-1-15-2-4242747332-3023982413-4100939420-2084055787-1724500538-1861032378-3897255926'

function RunOnce([string]$exe,[string]$tag){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$died=$null;$ever=0;$gpu=$false
  for($i=0;$i -lt 150;$i++){
    Start-Sleep -Milliseconds 100
    $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
    if($all.Count -gt 0){$ever++}
    foreach($p in $all){ if($p.CommandLine -match '--type=gpu-process'){$gpu=$true} }
    $w=Get-Process $base -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
    if($w){$win=$true;break}
    if($all.Count -eq 0 -and $ever -gt 0){$died=((Get-Date)-$t0).TotalSeconds;break}
  }
  $v= if($win){'WINDOW_OK'} elseif($died){("DIED_{0:N1}s" -f $died)} elseif($ever -gt 0){'ALIVE_NO_WINDOW'} else {'NEVER_STARTED'}
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  Write-Output ("{0,-26} {1,-14} gpu={2}" -f $tag,$v,$gpu)
}

# ---------- T1: Programs + grant Users read ----------
$t1='C:\Users\Admin\AppData\Local\Programs\bb_acl_fixed'
if(Test-Path $t1){ Remove-Item $t1 -Recurse -Force }
Copy-Item $real $t1 -Recurse -Force
Write-Output "--- T1 before icacls ---"
icacls $t1 | Select-Object -First 6 | Write-Output
icacls $t1 /grant '*S-1-5-32-545:(OI)(CI)RX' /T /C /Q 2>&1 | Select-Object -Last 2 | Write-Output
Write-Output "--- T1 after icacls ---"
icacls $t1 | Select-Object -First 8 | Write-Output
RunOnce (Join-Path $t1 'Bluebook.exe') 'T1_Programs_grantUsers'

# ---------- T2: TempBB + strip Users ----------
$t2='C:\TempBB\bb_acl_stripped'
if(Test-Path $t2){ Remove-Item $t2 -Recurse -Force }
Copy-Item $real $t2 -Recurse -Force
Write-Output "--- T2 before icacls ---"
icacls $t2 | Select-Object -First 6 | Write-Output
icacls $t2 /inheritance:r 2>&1 | Select-Object -Last 1 | Write-Output
icacls $t2 /remove:g '*S-1-5-32-545' '*S-1-5-11' /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
icacls $t2 /grant "*${pkg}:(OI)(CI)RX" /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
Write-Output "--- T2 after icacls ---"
icacls $t2 | Select-Object -First 8 | Write-Output
RunOnce (Join-Path $t2 'Bluebook.exe') 'T2_TempBB_stripUsers'
