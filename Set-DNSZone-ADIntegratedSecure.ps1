<#
.SYNOPSIS
  Converts a standard primary zone to AD-integrated (if needed) and sets DynamicUpdates to Secure.
.NOTES
  Run on a DC with DNS role. For public/DMZ zones, do NOT convert.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ZoneName,
  [ValidateSet('Forest','Domain')] [string]$ReplicationScope = 'Domain'
)
Import-Module DnsServer
$ErrorActionPreference='Stop'

$z = Get-DnsServerZone -Name $ZoneName -ErrorAction Stop
if(-not $z.IsDsIntegrated){
  Write-Host "Converting $ZoneName to AD-integrated..."
  $scope = if($ReplicationScope -eq 'Forest'){'Forest'} else {'Domain'}
  Set-DnsServerPrimaryZone -Name $ZoneName -ReplicationScope $scope -PassThru | Out-Null
}else{
  Write-Host "$ZoneName already AD-integrated."
}
Write-Host "Setting Dynamic updates = Secure only..."
Set-DnsServerPrimaryZone -Name $ZoneName -DynamicUpdate Secure
Write-Host "Done."
