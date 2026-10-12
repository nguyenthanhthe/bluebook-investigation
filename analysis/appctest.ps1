# Hypothesis: the user profile grants the AppContainer/sandbox SID only
# ExecuteFile (not Read), so a sandboxed GPU process whose executable lives in
# the profile cannot READ its own DLLs and dies.
#   H1: grant the sandbox SIDs READ on the crashing install dir -> fixes?
#   H2: mimic the profile's ExecuteFile-only ACE at a working dir -> breaks?
$ErrorActionPreference='SilentlyContinue'
$real='C:\Users\Admin\AppData\Local\Programs\bluebook'
$pkg='S-1-15-2-4242747332-3023982413-4100939420-2084055787-1724500538-1861032378-3897255926'
$appc='S-1-15-3-65536-599108337-2355189375-1353122160-3480128286-3345335107-485756383-4087318168-230526575'
$everyone='*S-1-1-0'

function RunOnce([string]$exe){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$died=$null;$ever=0
  for($i=0;$i -lt 160;$i++){
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

Write-Output "=== H1: grant sandbox SIDs READ on the CRASHING install dir (in place) ==="
icacls $real /grant "*${appc}:(OI)(CI)RX" "*${pkg}:(OI)(CI)RX" "${everyone}:(OI)(CI)RX" /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
Write-Output "H1 verdict: $(RunOnce "$real\Bluebook.exe")"

Write-Output "`n=== H2: mimic ExecuteFile-only sandbox ACE at a WORKING dir ==="
$h2='C:\TempBB\bb_execonly'
if(Test-Path $h2){ Remove-Item $h2 -Recurse -Force }
Copy-Item $real $h2 -Recurse -Force
icacls $h2 /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 'DESKTOP-GJJ8AO3\Admin:(OI)(CI)F' /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
icacls $h2 /deny "*${appc}:(OI)(CI)R" /T /C /Q 2>&1 | Select-Object -Last 1 | Write-Output
Write-Output "H2 verdict: $(RunOnce "$h2\Bluebook.exe")"
