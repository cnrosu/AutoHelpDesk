<#
.SYNOPSIS
  DHCP snapshot: authorization, scopes, failover partnerships, DNS update settings.
.REQUIRES
  DhcpServer module.
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
