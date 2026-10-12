# Path-dependency matrix: does the crash follow the folder NAME, the PARENT dir,
# or the DRIVE? Runs each location 2x and reports window/gpu-process outcome.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File matrix.ps1
$ErrorActionPreference='SilentlyContinue'
$real = 'C:\Users\Admin\AppData\Local\Programs\bluebook'

# Candidate locations, isolating one variable at a time.
$locs = [ordered]@{
  '1_real_baseline'      = 'C:\Users\Admin\AppData\Local\Programs\bluebook'
  '2_sameparent_newname' = 'C:\Users\Admin\AppData\Local\Programs\bluebook_test'
  '3_C_drive_other'      = 'C:\TempBB\bluebook'
  '4_D_drive_root'       = 'D:\bluebook_test'
  '5_D_Temp_sibling'     = 'D:\Temp\bluebook_test'
}

function RunOnce([string]$exe,[string]$tag){
  $base = [System.IO.Path]::GetFileNameWithoutExtension($exe)
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $dir = Split-Path $exe -Parent
  $t0 = Get-Date
  Start-Process -FilePath $exe -WorkingDirectory $dir | Out-Null
  $win=$false; $sawGpu=$false; $died=$null; $ever=0; $types=@{}
  for ($i=0; $i -lt 160; $i++) {   # 16 s @100ms
    Start-Sleep -Milliseconds 100
    $all = @(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -ErrorAction SilentlyContinue)
    if ($all.Count -gt 0) { $ever++ }
    foreach ($p in $all) {
      $t='browser'; if ($p.CommandLine -match '--type=([A-Za-z0-9_-]+)') { $t=$matches[1] }
      $types[$t]=$true
      if ($t -eq 'gpu-process') { $sawGpu=$true }
    }
    $w = Get-Process $base -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
    if ($w) { $win=$true; break }
    if ($all.Count -eq 0 -and $ever -gt 0) { $died=((Get-Date)-$t0).TotalSeconds; break }
  }
  $v = if ($win) {'WINDOW_OK'} elseif ($died) {("DIED_{0:N1}s" -f $died)} elseif ($ever -gt 0) {'ALIVE_NO_WINDOW'} else {'NEVER_STARTED'}
  Get-Process $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 600
  return [pscustomobject]@{ Tag=$tag; Verdict=$v; GPU=$sawGpu; Types=(($types.Keys|Sort-Object) -join ',') }
}

$results = @()
foreach ($k in $locs.Keys) {
  $src = $real
  $dst = $locs[$k]
  if ($dst -ne $real) {
    if (Test-Path $dst) { Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
    Copy-Item $src $dst -Recurse -Force
  }
  for ($n=1; $n -le 2; $n++) {
    $r = RunOnce (Join-Path $dst 'Bluebook.exe') "$k#$n"
    $results += $r
    Write-Output ("{0,-22} {1,-16} gpu={2,-6} types={3}" -f $r.Tag,$r.Verdict,$r.GPU,$r.Types)
  }
}
Write-Output "`n=== SUMMARY ==="
$results | Format-Table -AutoSize | Out-String | Write-Output
$results | Export-Csv 'D:\Temp\bluebook-investigation\analysis\runs\matrix.csv' -NoTypeInformation
