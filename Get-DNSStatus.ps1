<#
.SYNOPSIS
  Captures an at-a-glance snapshot of DNS server configuration and health.
.DESCRIPTION
  Reviews forwarders, scavenging posture, and zone metadata (including replication and dynamic update mode). Requires the
  DnsServer module on the executing host.
.PARAMETER ComputerName
  Specifies the DNS server to query. Defaults to the local computer.
.PARAMETER SaveReport
  Saves the collected output to a timestamped text report beneath the local Reports directory when specified.
.OUTPUTS
  System.String. Writes results to the console and optionally saves a timestamped TXT under .\Reports\.
.EXAMPLE
  PS C:\> .\Get-DNSStatus.ps1 -ComputerName DNS01 -SaveReport

  Collects configuration details from DNS01 and saves them to the Reports folder alongside the script.
#>
[CmdletBinding()]
param(
  [string]$ComputerName = $env:COMPUTERNAME,
  [switch]$SaveReport
)
$ErrorActionPreference = 'Stop'
$now = Get-Date
$stamp = $now.ToString('yyyyMMdd_HHmmss')
$reportDir = Join-Path -Path $PSScriptRoot -ChildPath "Reports"
if ($SaveReport -and -not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }
$sb = New-Object System.Text.StringBuilder
<#
.SYNOPSIS
  Adds a formatted line to the in-memory report buffer and returns the same text for display.
.PARAMETER t
  The text to append to the report buffer.
.OUTPUTS
  System.String. Returns the same string that was added to the buffer.
#>
function Add-Line($t){[void]$sb.AppendLine($t); $t}

Add-Line "=== DNS STATUS on $ComputerName $now ==="

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
