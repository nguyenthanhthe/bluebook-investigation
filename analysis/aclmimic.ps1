# Replicate the profile root's ACL *shape* at a working location:
#   F1: mimic C:\Users\Admin (owner BUILTIN\Administrators, inheritance blocked,
#       no BUILTIN\Users ACE, package-SID ACE) on a copy at C:\TempBB
#   F2: control - same copy untouched
# If F1 breaks, the trigger is an ACL/owner property inherited from the profile.
$ErrorActionPreference='SilentlyContinue'
$real='C:\Users\Admin\AppData\Local\Programs\bluebook'
$pkg='S-1-15-2-4242747332-3023982413-4100939420-2084055787-1724500538-1861032378-3897255926'
$appc='S-1-15-3-65536-599108337-2355189375-1353122160-3480128286-3345335107-485756383-4087318168-230526575'

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

$f1='C:\TempBB\bb_mimic_admin'
if(Test-Path $f1){ Remove-Item $f1 -Recurse -Force }
Copy-Item $real $f1 -Recurse -Force
Write-Output "--- F1 BEFORE ---"; (icacls $f1) | Select-Object -First 5 | Write-Output
# Block inheritance, drop Users/AuthUsers, set owner to Administrators, add pkg ACE.
icacls $f1 /inheritance:r /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
icacls $f1 /remove:g '*S-1-5-32-545' '*S-1-5-11' /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
icacls $f1 /setowner 'BUILTIN\Administrators' /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
icacls $f1 /grant "*${pkg}:(OI)(CI)RX" "*${appc}:(OI)(CI)X" /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
Write-Output "--- F1 AFTER ---"; (icacls $f1) | Select-Object -First 8 | Write-Output
Write-Output ("F1 verdict: {0}" -f (RunOnce "$f1\Bluebook.exe"))

$f2='C:\TempBB\bb_mimic_ctrl'
if(Test-Path $f2){ Remove-Item $f2 -Recurse -Force }
Copy-Item $real $f2 -Recurse -Force
Write-Output ("F2 verdict: {0}" -f (RunOnce "$f2\Bluebook.exe"))
