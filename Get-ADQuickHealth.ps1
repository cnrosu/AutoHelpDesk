<#
.SYNOPSIS
  Quick AD/DC health snapshot for helpdesk/MSP.
.DESCRIPTION
  - Lists FSMO roles, DCs, GC status, replication summary, time source, and basic DFSR SYSVOL health.
  - Requires: RSAT AD PowerShell, repadmin, dcdiag present on the machine running it.
.PARAMETER SaveReport
  Saves the collected output to a timestamped text report beneath the local Reports directory when specified.
.OUTPUTS
  System.String. Writes results to the console and optionally saves a timestamped TXT under .\Reports\.
.EXAMPLE
  PS C:\> .\Get-ADQuickHealth.ps1 -SaveReport

  Runs the health snapshot and saves the output to the Reports folder alongside the script.
#>
[CmdletBinding()]
param(
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
.DESCRIPTION
  Appends the supplied text to the script-scoped StringBuilder so it can be emitted to the console and, if requested,
  written to a report file without duplicating logic.
.PARAMETER txt
  The text to append to the report buffer.
.OUTPUTS
  System.String. Returns the same string that was added to the buffer.
#>
function Add-Line($txt){[void]$sb.AppendLine($txt); $txt}

Add-Line "=== AD QUICK HEALTH $now ==="

# Domain/Forest basics
try{
  $dom = Get-ADDomain
  $forest = Get-ADForest
  Add-Line "Domain            : $($dom.DNSRoot)    NetBIOS: $($dom.NetBIOSName)"
  Add-Line "Forest            : $($forest.Name)"
  Add-Line "Forest Functional : $($forest.ForestMode)  Domain Functional: $($dom.DomainMode)"
}catch{ Add-Line "Get-ADDomain/Forest error: $_" }

# FSMO
try{
  $fsmo = (netdom query fsmo) 2>&1
  Add-Line "`n--- FSMO Roles ---"
  $fsmo | ForEach-Object { Add-Line $_ }
}catch{ Add-Line "netdom error: $_" }

# DCs & GC
try{
  Add-Line "`n--- Domain Controllers & GC ---"
  $dcs = Get-ADDomainController -Filter *
  $dcs | Sort-Object HostName | ForEach-Object {
    Add-Line ("{0,-30}  Site:{1,-20}  GC:{2}  IPv4:{3}" -f $_.HostName,$_.Site,$_.IsGlobalCatalog,$_.IPv4Address)
  }
}catch{ Add-Line "Get-ADDomainController error: $_" }

# Replication summary
try{
  Add-Line "`n--- Replication Summary (repadmin /replsummary) ---"
  $rep = (repadmin /replsummary) 2>&1
  $rep | ForEach-Object { Add-Line $_ }
}catch{ Add-Line "repadmin error: $_" }

# DCDIAG quick
try{
  Add-Line "`n--- DCDIAG /q (errors only) ---"
  $dcdiag = (dcdiag /q) 2>&1
  if ($dcdiag){ $dcdiag | ForEach-Object { Add-Line $_ } } else { Add-Line "No errors reported." }
}catch{ Add-Line "dcdiag error: $_" }

# Time source (PDC is authoritative)
try{
  Add-Line "`n--- Time Service (w32time) on this server ---"
  $w32 = (w32tm /query /configuration) 2>&1
  $w32 | ForEach-Object { Add-Line $_ }
  Add-Line "`n--- NTP Peers ---"
  $peers = (w32tm /query /peers) 2>&1
  $peers | ForEach-Object { Add-Line $_ }
}catch{ Add-Line "w32tm error: $_" }

# DFSR SYSVOL state
try{
  Add-Line "`n--- DFSR SYSVOL Backlog (this server) ---"
  $comp = $env:COMPUTERNAME
  $partners = dfsrdiag ReplicationState 2>$null
  if ($LASTEXITCODE -eq 0){
     $partners | Out-String | ForEach-Object { Add-Line $_ }
  } else {
     Add-Line "dfsrdiag not available or not DFSR (older FRS?)."
  }
}catch{ Add-Line "DFSR check error: $_" }

$txt = $sb.ToString()
Write-Host $txt
if ($SaveReport){
  $out = Join-Path $reportDir "ADQuickHealth_$stamp.txt"
  $txt | Out-File -Encoding UTF8 $out
  Write-Host "`nSaved: $out"
}
