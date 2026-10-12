# Test whether %TEMP% location decides the outcome.
#   G1: working copy + TEMP forced under the user profile (crash if TEMP is the factor)
#   G2: crashing real install + TEMP forced to C:\TempBB (fix if TEMP is the factor)
$ErrorActionPreference='SilentlyContinue'

function RunOnce([string]$exe,[string]$tempdir,[string]$tag){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  New-Item -ItemType Directory -Force -Path $tempdir | Out-Null
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  # Launch via a child cmd so TEMP/TMP apply only to the app.
  $env:TEMP=$tempdir; $env:TMP=$tempdir
  $p = Start-Process -FilePath $exe -WorkingDirectory $dir -PassThru
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
  Remove-Item Env:\TEMP,Env:\TMP -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
  Write-Output ("{0,-34} TEMP={1,-42} -> {2}" -f $tag,$tempdir,$v)
}

Write-Output "### baseline (current TEMP=D:\Temp) ###"
RunOnce 'D:\Temp\bbcopy\Bluebook.exe' 'D:\Temp' 'G0_copy_DTemp'
RunOnce 'C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe' 'D:\Temp' 'G0_real_DTemp'

Write-Output "`n### G1: working copy with TEMP under the profile ###"
RunOnce 'D:\Temp\bbcopy\Bluebook.exe' 'C:\Users\Admin\AppData\Local\Temp' 'G1_copy_profileTEMP'

Write-Output "`n### G2: crashing install with TEMP outside the profile ###"
RunOnce 'C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe' 'C:\TempBB\tmp' 'G2_real_CTempBB'
RunOnce 'C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe' 'D:\Temp' 'G2_real_DTemp'
