# Compare directory properties that could be inherited from the profile root:
# integrity/mandatory labels, attributes, reparse points, owner, and ACL
# inheritance, for a crashing location vs a working one.
$ErrorActionPreference='SilentlyContinue'

$paths = @(
  'C:\Users\Admin',
  'C:\Users\Admin\bbt2',
  'C:\Users\Admin\AppData\Local\Programs\bluebook',
  'C:\Users\Public',
  'C:\Users\Public\bbt2',
  'C:\TempBB\bluebook'
)

foreach($p in $paths){
  if(-not (Test-Path $p)){ Write-Output "MISSING: $p"; continue }
  Write-Output "==================== $p"
  $i = Get-Item $p -Force
  Write-Output ("  Attributes : {0}" -f $i.Attributes)
  Write-Output ("  Owner      : {0}" -f $i.GetAccessControl().Owner)
  $acl = Get-Acl $p
  Write-Output ("  AreAccessRulesProtected (inheritance blocked): {0}" -f $acl.AreAccessRulesProtected)
  foreach($a in $acl.Access){
    Write-Output ("    {0,-52} {1,-6} {2,-34} inh={3}" -f $a.IdentityReference, $a.AccessControlType, $a.FileSystemRights, $a.IsInherited)
  }
  # Integrity / mandatory label
  $ml = $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference -like 'S-1-16-*' }
  Write-Output ("  MandatoryLabel ACEs: {0}" -f (($ml | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" }) -join '; '))
  Write-Output ""
}

Write-Output "==================== whoami /groups (integrity level)"
whoami /groups 2>&1 | Select-String -Pattern 'Mandatory|Integrity|Label' | ForEach-Object { Write-Output "  $_" }

Write-Output ""
Write-Output "==================== reparse points on profile chain"
foreach($p in @('C:\Users','C:\Users\Admin','C:\Users\Admin\AppData','C:\Users\Admin\AppData\Local','C:\Users\Admin\AppData\Local\Programs')){
  $i = Get-Item $p -Force
  Write-Output ("  {0,-46} attrs={1}" -f $p, $i.Attributes)
}
