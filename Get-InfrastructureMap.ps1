<#
.SYNOPSIS
  Generates a Markdown summary and Graphviz .dot of AD/DNS/DHCP/Sites with optional Hyper-V inventory.
.DESCRIPTION
  Collects directory services, DNS, DHCP, and AD Sites metadata to produce a Markdown report and a Graphviz DOT map inside
  the Reports folder. When requested, Hyper-V host and VM information is also appended.
.PARAMETER IncludeHyperV
  Adds Hyper-V inventory details to the Markdown report when the Hyper-V module is available.
.OUTPUTS
  System.String. Writes the generated report and DOT file paths to the console.
.EXAMPLE
  PS C:\> .\Get-InfrastructureMap.ps1 -IncludeHyperV

  Creates infrastructure report and map files including Hyper-V host and VM inventory.
#>
[CmdletBinding()]
param(
  [switch]$IncludeHyperV
)
$ErrorActionPreference='Stop'
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$reportDir = Join-Path -Path $PSScriptRoot -ChildPath "Reports"
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }

# Collect
$dom = Get-ADDomain
$forest = Get-ADForest
$dcs = Get-ADDomainController -Filter *
$zones = @()
try { $zones = Get-DnsServerZone } catch {}
$scopes = @()
try { $scopes = Get-DhcpServerv4Scope -ComputerName $env:COMPUTERNAME } catch {}

$sites = Get-ADReplicationSite -Filter *
$subnets = Get-ADReplicationSubnet -Filter *
$sitelinks = Get-ADReplicationSiteLink -Filter *

$md = @()
$md += "# Infrastructure Report ($stamp)`n"
$md += "## Domain / Forest"
$md += "- Domain: **$($dom.DNSRoot)** (NetBIOS: $($dom.NetBIOSName))"
$md += "- Forest: **$($forest.Name)**"
$md += "- Forest Mode: $($forest.ForestMode)  |  Domain Mode: $($dom.DomainMode)`n"

$md += "## Domain Controllers"
foreach($dc in $dcs | Sort-Object HostName){
  $md += "- $($dc.HostName)  Site:$($dc.Site)  IPv4:$($dc.IPv4Address)  GC:$($dc.IsGlobalCatalog)"
}
$md += ""

$md += "## DNS Zones"
foreach($z in $zones){
  $md += "- $($z.ZoneName)  Type:$($z.ZoneType)  AD-Integrated:$($z.IsDsIntegrated)  Replication:$($z.ReplicationScope)"
}
$md += ""

$md += "## DHCP (local server overview)"
foreach($s in $scopes){
  $md += "- Scope $($s.ScopeId)  $($s.Name)  Lease:$([int]$s.LeaseDuration.TotalHours)h"
}
$md += ""

$md += "## AD Sites/Subnets"
$md += "Sites:"
foreach($s in $sites){ $md += "- $($s.Name)" }
$md += "Subnets:"
foreach($sn in $subnets){ $md += "- $($sn.Name)  Site:$($sn.Site) " }
$md += "Site Links:"
foreach($sl in $sitelinks){ $md += "- $($sl.Name)  Sites: $((($sl.SitesIncluded | ForEach-Object {$_.Name}) -join ', '))" }

# Optional Hyper-V
if ($IncludeHyperV){
  try{
    Import-Module Hyper-V -ErrorAction Stop
    $hosts = @(Get-VMHost)
    $md += "## Hyper-V Hosts/VMs"
    foreach($h in $hosts){
      $md += "- Host $($h.ComputerName) CPUs:$($h.LogicalProcessorCount) MemGB:$([math]::Round($h.MemoryCapacity/1GB,1))"
      Get-VM -ComputerName $h.ComputerName | ForEach-Object {
        $md += "  - VM $($_.Name) State:$($_.State) CPU:$($_.ProcessorCount) RAMMB:$($_.MemoryAssigned/1MB)"
      }
    }
  }catch{
    $md += "_Hyper-V module not available on this machine._"
  }
}

$mdPath = Join-Path $reportDir "Infrastructure_Report_$stamp.md"
$md -join "`n" | Out-File -Encoding UTF8 $mdPath

# Graphviz DOT (very simple)
$dot = @()
$dot += 'digraph Infra {'
$dot += '  rankdir=LR; node [shape=box, fontsize=10];'
$dot += "  subgraph cluster_domain { label=\"Domain: $($dom.DNSRoot)\"; style=dashed;"
foreach($dc in $dcs){ $dot += "    \"DC:$($dc.HostName)\";" }
$dot += "  }"
foreach($z in $zones){ $dot += "  \"Zone:$($z.ZoneName)\";" }
foreach($s in $sites){ $dot += "  \"Site:$($s.Name)\";"; }
foreach($dc in $dcs){
  $dot += "  \"Site:$($dc.Site)\" -> \"DC:$($dc.HostName)\";"
}
foreach($z in $zones){
  foreach($dc in $dcs){ $dot += "  \"DC:$($dc.HostName)\" -> \"Zone:$($z.ZoneName)\" [style=dotted];" }
}
$dot += '}'
$dotPath = Join-Path $reportDir "Infrastructure_Map_$stamp.dot"
$dot -join "`n" | Out-File -Encoding UTF8 $dotPath

Write-Host "Report: $mdPath"
Write-Host "Graphviz DOT: $dotPath (render with 'dot -Tpng file.dot -o file.png')"
