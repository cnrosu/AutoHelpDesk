<#
.SYNOPSIS
  Creates DHCP failover between two DHCP servers for all or selected scopes.
.EXAMPLE
  .\New-DHCPFailoverPair.ps1 -Primary DHCPA -Partner DHCPB -Mode LoadBalance -BalancePercent 50 -SharedSecret 'S3cret!'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Primary,
  [Parameter(Mandatory)] [string]$Partner,
  [ValidateSet('LoadBalance','HotStandby')] [string]$Mode = 'LoadBalance',
  [ValidateRange(1,99)] [int]$BalancePercent = 50,
  [int]$MaxClientLeadTimeMinutes = 60,
  [string]$SharedSecret = (Read-Host -AsSecureString | %{ throw "Use -SharedSecret to avoid prompt in scripts." }),
  [string[]]$ScopeIds # e.g. '192.168.60.0','192.168.70.0'
)
Import-Module DhcpServer
$ErrorActionPreference='Stop'

# Authorize if needed
foreach($s in @($Primary,$Partner)){
  if(-not (Get-DhcpServerInDC | Where-Object {$_.DnsName -ieq "$s"})){
    Write-Host "Authorizing $s in AD..."
    $ip = (Resolve-DnsName $s -Type A -ErrorAction Stop).IPAddress[0]
    Add-DhcpServerInDC -DnsName $s -IpAddress $ip
  }
}

# Scopes
if (-not $ScopeIds){
  $ScopeIds = (Get-DhcpServerv4Scope -ComputerName $Primary | Select-Object -ExpandProperty ScopeId | ForEach-Object {$_.IPAddressToString})
  Write-Host "Using all scopes from $Primary: $($ScopeIds -join ', ')"
}

# Create failover
$mlt = New-TimeSpan -Minutes $MaxClientLeadTimeMinutes
if($Mode -eq 'LoadBalance'){
  Add-DhcpServerv4Failover -ComputerName $Primary -Name "${Primary}_$Partner" -PartnerServer $Partner -ScopeId $ScopeIds -LoadBalancePercent $BalancePercent -MaxClientLeadTime $mlt -SharedSecret $SharedSecret
}else{
  Add-DhcpServerv4Failover -ComputerName $Primary -Name "${Primary}_$Partner" -PartnerServer $Partner -ScopeId $ScopeIds -HotStandby -MaxClientLeadTime $mlt -SharedSecret $SharedSecret
}
Write-Host "Failover created."
