# Determine the fix shape:
#   J1: junction INSIDE the profile -> real files OUTSIDE the profile.
#       If this works, relocating the real install + leaving a junction at the
#       original path is a valid fix.
#   J2: junction OUTSIDE the profile -> real files INSIDE the profile.
#       If this dies, it confirms the trigger is the real file location.
$ErrorActionPreference='SilentlyContinue'

function RunOnce([string]$exe,[string]$tag){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false;$died=$null;$ever=0
  for($i=0;$i -lt 170;$i++){
    Start-Sleep -Milliseconds 100
    $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -EA SilentlyContinue)
    if($all.Count -gt 0){$ever++}
    $w=Get-Process $base -EA SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
    if($w){$win=$true;break}
    if($all.Count -eq 0 -and $ever -gt 0){$died=((Get-Date)-$t0).TotalSeconds;break}
  }
  $v= if($win){'WINDOW_OK'} elseif($died){("DIED_{0:N1}s" -f $died)} elseif($ever -gt 0){'ALIVE'} else {'NEVER'}
  Get-Process $base -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep -Milliseconds 400
  Write-Output ("{0,-52} -> {1}" -f $tag,$v)
}

# Real files OUTSIDE the profile.
$outside='C:\BluebookReal'
if(Test-Path $outside){ Remove-Item $outside -Recurse -Force }
Copy-Item 'C:\Users\Admin\AppData\Local\Programs\bluebook' $outside -Recurse -Force

# J1: junction inside the profile -> outside real files
$j1='C:\Users\Admin\AppData\Local\Programs\bb_junc_in'
if(Test-Path $j1){ (Get-Item $j1 -Force).Delete() }
cmd /c mklink /J "$j1" "$outside" 2>&1 | Out-Null
Write-Output "J1 junction target: $((Get-Item $j1 -Force).Target)"
RunOnce "$j1\Bluebook.exe" 'J1 profile-junction -> outside real files'

# J2: junction outside the profile -> inside real files
$j2='C:\TempBB\bb_junc_out'
if(Test-Path $j2){ (Get-Item $j2 -Force).Delete() }
cmd /c mklink /J "$j2" 'C:\Users\Admin\AppData\Local\Programs\bluebook' 2>&1 | Out-Null
Write-Output "J2 junction target: $((Get-Item $j2 -Force).Target)"
RunOnce "$j2\Bluebook.exe" 'J2 outside-junction -> profile real files'

# Control: direct run from outside real files
RunOnce "$outside\Bluebook.exe" 'CONTROL outside real files (no junction)'
