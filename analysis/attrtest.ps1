# Test whether inheriting the profile's directory ATTRIBUTES (Hidden/System)
# is what breaks the GPU process. Clear Hidden/System on a crashing copy and
# see if it starts working.
$ErrorActionPreference='SilentlyContinue'
$real='C:\Users\Admin\AppData\Local\Programs\bluebook'

function RunOnce([string]$exe){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$died=$null;$ever=0
  for($i=0;$i -lt 150;$i++){
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

# --- E1: copy into the profile, then clear Hidden/System recursively ---
$e1='C:\Users\Admin\bbt_attrs'
if(Test-Path $e1){ Remove-Item $e1 -Recurse -Force }
Copy-Item $real $e1 -Recurse -Force
Write-Output ("E1 dir attrs BEFORE: {0}" -f (Get-Item $e1 -Force).Attributes)
attrib -H -S "$e1\*.*" /S /D 2>&1 | Out-Null
attrib -H -S $e1 2>&1 | Out-Null
Write-Output ("E1 dir attrs AFTER : {0}" -f (Get-Item $e1 -Force).Attributes)
Write-Output ("E1 verdict: {0}" -f (RunOnce "$e1\Bluebook.exe"))

# --- E2: control - copy into the profile untouched ---
$e2='C:\Users\Admin\bbt_attrs_ctrl'
if(Test-Path $e2){ Remove-Item $e2 -Recurse -Force }
Copy-Item $real $e2 -Recurse -Force
Write-Output ("E2 dir attrs       : {0}" -f (Get-Item $e2 -Force).Attributes)
Write-Output ("E2 verdict: {0}" -f (RunOnce "$e2\Bluebook.exe"))

# --- E3: working location, but SET Hidden/System on it ---
$e3='C:\TempBB\bbt_hidden'
if(Test-Path $e3){ Remove-Item $e3 -Recurse -Force }
Copy-Item $real $e3 -Recurse -Force
attrib +H +S "$e3\*.*" /S /D 2>&1 | Out-Null
attrib +H +S $e3 2>&1 | Out-Null
Write-Output ("E3 dir attrs       : {0}" -f (Get-Item $e3 -Force).Attributes)
Write-Output ("E3 verdict: {0}" -f (RunOnce "$e3\Bluebook.exe"))
