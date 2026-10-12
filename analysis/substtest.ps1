# Decisive test: is the trigger the literal path STRING or the real directory?
#   subst X: -> C:\Users\Admin\AppData\Local\Programs   then run X:\bluebook\Bluebook.exe
#   - If it WORKS via subst: the trigger is the path string the process sees.
#   - If it DIES via subst:  the trigger is the real directory (ACL/marker/reparse).
# Also test a mimicked string elsewhere: C:\TempBB\Users\Admin\bbt2
$ErrorActionPreference='SilentlyContinue'
$real='C:\Users\Admin\AppData\Local\Programs\bluebook'

function RunOnce([string]$exe){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$died=$null;$ever=0;$gpu=$false
  for($i=0;$i -lt 160;$i++){
    Start-Sleep -Milliseconds 100
    $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
    if($all.Count -gt 0){$ever++}
    foreach($p in $all){ if($p.CommandLine -match '--type=gpu-process'){$gpu=$true} }
    $w=Get-Process $base -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
    if($w){$win=$true;break}
    if($all.Count -eq 0 -and $ever -gt 0){$died=((Get-Date)-$t0).TotalSeconds;break}
  }
  $v= if($win){'WINDOW_OK'} elseif($died){("DIED_{0:N1}s" -f $died)} elseif($ever -gt 0){'ALIVE'} else {'NEVER'}
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  Write-Output ("  -> {0,-12} gpu={1}" -f $v,$gpu)
}

Write-Output "=== A) baseline real install (expect DIED) ==="
Write-Output "  exe: $real\Bluebook.exe"; RunOnce "$real\Bluebook.exe"

Write-Output "`n=== B) same install reached through a subst drive ==="
subst X: /D 2>&1 | Out-Null
subst X: 'C:\Users\Admin\AppData\Local\Programs' 2>&1 | Out-Null
Start-Sleep -Milliseconds 500
if(Test-Path 'X:\bluebook\Bluebook.exe'){
  Write-Output "  exe: X:\bluebook\Bluebook.exe  (X: -> C:\Users\Admin\AppData\Local\Programs)"
  RunOnce 'X:\bluebook\Bluebook.exe'
} else { Write-Output "  subst failed / not visible" }
subst X: /D 2>&1 | Out-Null

Write-Output "`n=== C) mimicked path string outside the profile ==="
$mimic='C:\TempBB\Users\Admin\bbt2'
if(Test-Path $mimic){ Remove-Item $mimic -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Split-Path $mimic -Parent) | Out-Null
Copy-Item $real $mimic -Recurse -Force
Write-Output "  exe: $mimic\Bluebook.exe"; RunOnce "$mimic\Bluebook.exe"

Write-Output "`n=== D) real dir but reached via 8.3 short name ==="
$short = cmd /c 'for %I in ("C:\Users\Admin\AppData\Local\Programs\bluebook") do @echo %~sI' 2>$null
if($short -and (Test-Path "$short\Bluebook.exe")){
  Write-Output "  short: $short"
  RunOnce "$short\Bluebook.exe"
} else { Write-Output "  8.3 name unavailable" }
