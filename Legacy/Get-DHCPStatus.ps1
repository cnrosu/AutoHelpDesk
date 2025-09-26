<#
.SYNOPSIS
  Captures an at-a-glance snapshot of DHCP server configuration and health.
.DESCRIPTION
  Reviews the current DHCP authorization state, IPv4 scopes, failover partnerships, and dynamic DNS update configuration.
  Requires the DhcpServer PowerShell module on the executing host.
.PARAMETER ComputerName
  Specifies the DHCP server to query. Defaults to the local computer.
.PARAMETER SaveReport
  Saves the collected output to a timestamped text report beneath the local Reports directory when specified.
.OUTPUTS
  System.String. Writes results to the console and optionally saves a timestamped TXT under .\Reports\.
.EXAMPLE
  PS C:\> .\Get-DHCPStatus.ps1 -ComputerName DHCP01 -SaveReport

  Collects configuration details from DHCP01 and saves them to the Reports folder alongside the script.
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
<#
.SYNOPSIS
  Adds a formatted line to the in-memory report buffer and returns the same text for display.
.PARAMETER t
  The text to append to the report buffer.
.OUTPUTS
  System.String. Returns the same string that was added to the buffer.
#>
function Add-Line($t){[void]$sb.AppendLine($t); $t}

Add-Line "=== DHCP STATUS on $ComputerName $(Get-Date) ==="

try{
  Add-Line "`n--- Authorized DHCP servers in AD ---"
  $auth = Get-DhcpServerInDC
  if ($auth){ $auth | ForEach-Object { Add-Line ("  {0,-30} {1}" -f $_.DnsName, $_.IpAddress) } } else { Add-Line "  (none)" }
}catch{ Add-Line "Get-DhcpServerInDC error: $_" }

try{
  Add-Line "`n--- Scopes ---"
  $scopes = Get-DhcpServerv4Scope -ComputerName $ComputerName
  foreach($s in $scopes){
    Add-Line ("  {0,-18} {1,-15} Lease:{2}h  Free:{3}" -f $s.ScopeId, $s.Name, $s.LeaseDuration.TotalHours, (Get-DhcpServerv4ScopeStatistics -ComputerName $ComputerName -ScopeId $s.ScopeId).Free)
  }
}catch{ Add-Line "Scope list error: $_" }

try{
  Add-Line "`n--- Failover Partnerships ---"
  $fos = Get-DhcpServerv4Failover -ComputerName $ComputerName -ErrorAction SilentlyContinue
  if ($fos){
    foreach($fo in $fos){
      Add-Line ("  Name:{0} Mode:{1} Partner:{2} State:{3}" -f $fo.Name,$fo.Mode,$fo.PartnerServer,$fo.State)
    }
  }else{ Add-Line "  (none)" }
}catch{ Add-Line "Failover query error: $_" }

try{
  Add-Line "`n--- DNS Update Settings (server-level) ---"
  $props = Get-DhcpServerv4DnsSetting -ComputerName $ComputerName
  $props | Format-List | Out-String | ForEach-Object { Add-Line $_ }
}catch{ Add-Line "DNS setting query error: $_" }

$txt = $sb.ToString()
Write-Host $txt
if ($SaveReport){
  $out = Join-Path $reportDir "DHCPStatus_$stamp.txt"
  $txt | Out-File -Encoding UTF8 $out
  Write-Host "`nSaved: $out"
}
