# Test whether GPU-sandbox / ANGLE flags change the outcome, on both the
# crashing real install and the working copy. Args ARE passed here (unlike the
# earlier probe) so we can see if the app honours them.
$ErrorActionPreference='SilentlyContinue'
$real='C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe'
$copy='D:\Temp\bbcopy\Bluebook.exe'

function RunOnce([string]$exe,[string]$tag,[string[]]$extra){
  $base=[System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir=Split-Path $exe -Parent
  $t0=Get-Date
  if($extra.Count -gt 0){ Start-Process -FilePath $exe -WorkingDirectory $dir -ArgumentList $extra | Out-Null }
  else { Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null }
  $win=$false;$died=$null;$ever=0;$gpu=$false;$max=0
  for($i=0;$i -lt 200;$i++){
    Start-Sleep -Milliseconds 100
    $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
    if($all.Count -gt 0){$ever++}
    if($all.Count -gt $max){$max=$all.Count}
    foreach($p in $all){ if($p.CommandLine -match '--type=gpu-process'){$gpu=$true} }
    $w=Get-Process $base -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0}
    if($w){$win=$true;break}
    if($all.Count -eq 0 -and $ever -gt 0){$died=((Get-Date)-$t0).TotalSeconds;break}
  }
  $v= if($win){'WINDOW_OK'} elseif($died){("DIED_{0:N1}s" -f $died)} elseif($ever -gt 0){'ALIVE'} else {'NEVER'}
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  Write-Output ("{0,-30} {1,-13} gpu={2,-6} max={3}" -f $tag,$v,$gpu,$max)
}

Write-Output "### COPY (known-good location) ###"
RunOnce $copy 'copy_noflags'        @()
RunOnce $copy 'copy_no-sandbox'     @('--no-sandbox')
RunOnce $copy 'copy_no-gpu-sandbox' @('--disable-gpu-sandbox')
RunOnce $copy 'copy_swiftshader'    @('--use-angle=swiftshader')

Write-Output "`n### REAL (crashing location) ###"
RunOnce $real 'real_noflags'        @()
RunOnce $real 'real_no-sandbox'     @('--no-sandbox')
RunOnce $real 'real_no-gpu-sandbox' @('--disable-gpu-sandbox')
RunOnce $real 'real_disable-gpu'    @('--disable-gpu')
RunOnce $real 'real_swiftshader'    @('--use-angle=swiftshader')
RunOnce $real 'real_in-process-gpu' @('--in-process-gpu')
