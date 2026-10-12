# Aggressively harvest EVERY Crashpad artifact during a crash, polling fast and
# copying with a distinct name, to catch the short-lived GPU-process dump.
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Tag,
  [int]$Secs = 20
)
$ErrorActionPreference='SilentlyContinue'
$cp = 'C:\Users\Admin\AppData\Roaming\bluebook\Crashpad'
$cap = "D:\Temp\bluebook-investigation\analysis\dumps\$Tag"
New-Item -ItemType Directory -Force -Path $cap | Out-Null

# Snapshot everything already present anywhere under Crashpad.
$before = @{}
foreach($d in @('reports','pending','completed','attachments')){
  Get-ChildItem (Join-Path $cp $d) -File -Recurse -EA SilentlyContinue | ForEach-Object { $before[$_.FullName]=$true }
}
Write-Output "pre-existing artifacts: $($before.Count)"

$base=[System.IO.Path]::GetFileNameWithoutExtension($Exe)
Get-Process $base -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Milliseconds 700
$dir=Split-Path $Exe -Parent
$t0=Get-Date
Start-Process -FilePath $Exe -WorkingDirectory $dir | Out-Null

$n=0
for($i=0;$i -lt ($Secs*100);$i++){
  Start-Sleep -Milliseconds 10
  $files = @()
  foreach($d in @('reports','pending','completed')){
    $files += @(Get-ChildItem (Join-Path $cp $d) -File -Recurse -EA SilentlyContinue)
  }
  foreach($f in $files){
    if(-not $before.ContainsKey($f.FullName)){
      $before[$f.FullName]=$true
      $n++
      $dst = Join-Path $cap ("{0:000}_{1}ms_{2}" -f $n, [int]((Get-Date)-$t0).TotalMilliseconds, $f.Name)
      # Copy with retry: the file may still be being written.
      for($try=0;$try -lt 20;$try++){
        try { Copy-Item $f.FullName $dst -Force -EA Stop; break } catch { Start-Sleep -Milliseconds 5 }
      }
      if(Test-Path $dst){
        Write-Output ("HARVEST {0}ms  {1}  {2} bytes  (src dir: {3})" -f [int]((Get-Date)-$t0).TotalMilliseconds, $f.Name, (Get-Item $dst).Length, (Split-Path $f.DirectoryName -Leaf))
      }
    }
  }
  $all=@(Get-CimInstance Win32_Process -Filter "Name='$base.exe'" -EA SilentlyContinue)
  if($all.Count -eq 0 -and $i -gt 30){ break }
}
Get-Process $base -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Write-Output "total harvested: $n"
Get-ChildItem $cap -File | Sort-Object Length -Descending | Select-Object -First 12 Name,Length | Format-Table -AutoSize | Out-String | Write-Output
