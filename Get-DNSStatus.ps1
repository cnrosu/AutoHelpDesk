<#
.SYNOPSIS
  DNS server configuration snapshot (zones, dynamic updates, forwarders, scavenging).
.REQUIRES
  DnsServer module.
#>
[CmdletBinding()]
param(
  [string]$ComputerName = $env:COMPUTERNAME,
  [switch]$SaveReport
)
$ErrorActionPreference = 'Stop'
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$reportDir = Join-Path -Path $PSScriptRoot -ChildPath "Reports"
if ($SaveReport -and -not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }
$sb = New-Object System.Text.StringBuilder
function Add-Line($t){[void]$sb.AppendLine($t); $t}

Add-Line "=== DNS STATUS on $ComputerName $(Get-Date) ==="

try{
  Add-Line "`n--- Forwarders ---"
  $fwd = Get-DnsServerForwarder -ComputerName $ComputerName -ErrorAction Stop
  if ($fwd){ $fwd | ForEach-Object { Add-Line ("  {0}" -f $_.IPAddress.IPAddressToString) } }
  else { Add-Line "  (none)" }
}catch{ Add-Line "Get-DnsServerForwarder error: $_" }

try{
  Add-Line "`n--- Scavenging ---"
  $scv = Get-DnsServerScavenging -ComputerName $ComputerName -ErrorAction Stop
  Add-Line ("  ScavengingEnabled: {0}  NoRefreshInterval: {1}  RefreshInterval: {2}" -f $scv.ScavengingState,$scv.NoRefreshInterval,$scv.RefreshInterval)
}catch{ Add-Line "Scavenging query error: $_" }

try{
  Add-Line "`n--- Zones ---"
  $zones = Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop
  foreach($z in $zones){
    $dyn = if ($z.IsDsIntegrated){ (Get-DnsServerZone -Name $z.ZoneName -ComputerName $ComputerName | Select-Object -ExpandProperty DynamicUpdate) } else { $z.DynamicUpdate }
    Add-Line ("  {0}  Type:{1}  AD-Integrated:{2}  Dynamic:{3}  ReplicationScope:{4}" -f $z.ZoneName,$z.ZoneType,$z.IsDsIntegrated,$dyn,$z.ReplicationScope)
  }
}catch{ Add-Line "Zone list error: $_" }

$txt = $sb.ToString()
Write-Host $txt
if ($SaveReport){
  $out = Join-Path $reportDir "DNSStatus_$stamp.txt"
  $txt | Out-File -Encoding UTF8 $out
  Write-Host "`nSaved: $out"
}
