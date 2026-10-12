# Probe per-profile / per-path security policy that could explain
# "crash only when the app lives under the current user's profile".
# Reads Defender Exploit Guard, ASR, CFA, IFEO and process-mitigation keys.
$ErrorActionPreference='SilentlyContinue'

function Show([string]$label,[string]$path){
  Write-Output "--- $label"
  Write-Output "    $path"
  if(-not (Test-Path $path)){ Write-Output "    (key absent)"; return }
  $p = Get-ItemProperty $path
  $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
    Write-Output ("      {0} = {1}" -f $_.Name, $_.Value)
  }
}

Write-Output "########## Windows Defender Exploit Guard ##########"
Show 'CFA (Controlled Folder Access)' 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
Show 'CFA protected folders'          'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\ProtectedFolders'
Show 'CFA allowed apps'               'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications'
Show 'ASR rules'                      'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
Show 'Exploit Protection (system)'    'HKLM:\SOFTWARE\Microsoft\Windows Defender Exploit Guard\Exploit Protection\MitigationOptions'
Show 'ExploitProtection settings'     'HKLM:\SOFTWARE\Microsoft\Windows Defender Exploit Guard\Exploit Protection\MitigationAuditOptions'

Write-Output ""
Write-Output "########## Defender core ##########"
Show 'Defender policy'                'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
Show 'Defender realtime'              'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
Show 'Spynet'                         'HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet'

Write-Output ""
Write-Output "########## IFEO (per-exe) ##########"
foreach($k in @(
  'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluebook.exe',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluebook.exe',
  'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluebook.exe')){
  Show 'IFEO' $k
}

Write-Output ""
Write-Output "########## AppCompat / mitigation ##########"
Show 'AppCompatFlags Layers (HKCU)'   'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
Show 'AppCompatFlags Layers (HKLM)'   'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'

Write-Output ""
Write-Output "########## Smart App Control / SmartScreen ##########"
Show 'CI policy (WDAC)'               'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
Show 'SmartScreen'                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'

Write-Output ""
Write-Output "########## Per-user GPU prefs (HKCU) ##########"
Show 'UserGpuPreferences'             'HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences'
