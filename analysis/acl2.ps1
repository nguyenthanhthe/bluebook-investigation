# Mimic the profile root's ACL shape at a WORKING location, carefully.
# Profile root C:\Users\Admin has:
#   inheritance blocked, no BUILTIN\Users, owner BUILTIN\Administrators,
#   plus package-SID and appcontainer-SID ACEs.
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

# F3: at a working location, deny the GPU-sandbox package SID read on the exe dir.
$f3='C:\TempBB\bb_denypkg'
if(Test-Path $f3){ Remove-Item $f3 -Recurse -Force }
Copy-Item $real $f3 -Recurse -Force
# Ensure Admin still has full control before/after.
icacls $f3 /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 'DESKTOP-GJJ8AO3\Admin:(OI)(CI)F' /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
# Explicitly DENY the package SID read/execute.
icacls $f3 /deny "*${pkg}:(OI)(CI)RX" /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
Write-Output "--- F3 ACL ---"; (icacls $f3) | Select-Object -First 8 | Write-Output
Write-Output ("F3 (deny pkg SID at working loc) verdict: {0}" -f (RunOnce "$f3\Bluebook.exe"))

# F4: control - same copy, no deny.
$f4='C:\TempBB\bb_denypkg_ctrl'
if(Test-Path $f4){ Remove-Item $f4 -Recurse -Force }
Copy-Item $real $f4 -Recurse -Force
Write-Output ("F4 (control) verdict: {0}" -f (RunOnce "$f4\Bluebook.exe"))
