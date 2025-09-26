<#
.SYNOPSIS
  Converts a standard primary zone to AD-integrated (if needed) and sets DynamicUpdates to Secure.
.DESCRIPTION
  Validates that the specified zone exists, converts it to an Active Directory-integrated zone when required, and forces
  secure-only dynamic updates. Should be executed on a domain controller hosting DNS.
.PARAMETER ZoneName
  Specifies the DNS zone to convert and secure.
.PARAMETER ReplicationScope
  Indicates the desired replication scope for the zone. Accepts Forest or Domain, defaulting to Domain.
.NOTES
  Run on a DC with DNS role. For public/DMZ zones, do NOT convert.
.EXAMPLE
  PS C:\> .\Set-DNSZone-ADIntegratedSecure.ps1 -ZoneName "contoso.com" -ReplicationScope Forest

  Converts contoso.com to a forest-wide AD-integrated zone and sets dynamic updates to Secure Only.
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
