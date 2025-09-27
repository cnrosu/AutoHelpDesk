<#
.SYNOPSIS
  Creates a DHCP failover partnership between two DHCP servers for all or selected scopes.
.DESCRIPTION
  Authorizes both servers in Active Directory (when necessary) and configures DHCP failover using either load-balanced or
  hot-standby modes. All scopes from the primary are included unless specific scope IDs are supplied.
.PARAMETER Primary
  Specifies the hostname of the primary DHCP server.
.PARAMETER Partner
  Specifies the hostname of the partner DHCP server.
.PARAMETER Mode
  Sets the failover mode. Valid values are LoadBalance and HotStandby.
.PARAMETER BalancePercent
  When using load balancing, determines the percentage of the address pool serviced by the primary server.
.PARAMETER MaxClientLeadTimeMinutes
  Controls the maximum client lead time communicated between partners in minutes.
.PARAMETER SharedSecret
  Provides the shared secret used to secure the replication partnership.
.PARAMETER ScopeIds
  Limits the configuration to the provided IPv4 scope IDs. When omitted, all scopes on the primary server are included.
.EXAMPLE
  .\New-DHCPFailoverPair.ps1 -Primary DHCPA -Partner DHCPB -Mode LoadBalance -BalancePercent 50 -SharedSecret 'S3cret!'

  Creates a load-balanced failover partnership using a 50/50 split between DHCPA and DHCPB.
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
