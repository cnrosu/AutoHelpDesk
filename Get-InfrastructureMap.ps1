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

$mdBuilder = [System.Text.StringBuilder]::new()
$null = $mdBuilder.AppendLine("# Infrastructure Report ($stamp)")
$null = $mdBuilder.AppendLine('')
$null = $mdBuilder.AppendLine('## Domain / Forest')
$null = $mdBuilder.AppendLine("- Domain: **$($dom.DNSRoot)** (NetBIOS: $($dom.NetBIOSName))")
$null = $mdBuilder.AppendLine("- Forest: **$($forest.Name)**")
$null = $mdBuilder.AppendLine("- Forest Mode: $($forest.ForestMode)  |  Domain Mode: $($dom.DomainMode)")
$null = $mdBuilder.AppendLine('')

$null = $mdBuilder.AppendLine('## Domain Controllers')
foreach($dc in $dcs | Sort-Object HostName){
  $null = $mdBuilder.AppendLine("- $($dc.HostName)  Site:$($dc.Site)  IPv4:$($dc.IPv4Address)  GC:$($dc.IsGlobalCatalog)")
}
$null = $mdBuilder.AppendLine('')

$null = $mdBuilder.AppendLine('## DNS Zones')
foreach($z in $zones){
  $null = $mdBuilder.AppendLine("- $($z.ZoneName)  Type:$($z.ZoneType)  AD-Integrated:$($z.IsDsIntegrated)  Replication:$($z.ReplicationScope)")
}
$null = $mdBuilder.AppendLine('')

$null = $mdBuilder.AppendLine('## DHCP (local server overview)')
foreach($s in $scopes){
  $null = $mdBuilder.AppendLine("- Scope $($s.ScopeId)  $($s.Name)  Lease:$([int]$s.LeaseDuration.TotalHours)h")
}
$null = $mdBuilder.AppendLine('')

$null = $mdBuilder.AppendLine('## AD Sites/Subnets')
$null = $mdBuilder.AppendLine('Sites:')
foreach($s in $sites){ $null = $mdBuilder.AppendLine("- $($s.Name)") }
$null = $mdBuilder.AppendLine('Subnets:')
foreach($sn in $subnets){ $null = $mdBuilder.AppendLine("- $($sn.Name)  Site:$($sn.Site) ") }
$null = $mdBuilder.AppendLine('Site Links:')
foreach($sl in $sitelinks){ $null = $mdBuilder.AppendLine("- $($sl.Name)  Sites: $((($sl.SitesIncluded | ForEach-Object {$_.Name}) -join ', '))") }

# Optional Hyper-V
if ($IncludeHyperV){
  try{
    Import-Module Hyper-V -ErrorAction Stop
    $hosts = @(Get-VMHost)
    $null = $mdBuilder.AppendLine('## Hyper-V Hosts/VMs')
    foreach($h in $hosts){
      $null = $mdBuilder.AppendLine("- Host $($h.ComputerName) CPUs:$($h.LogicalProcessorCount) MemGB:$([math]::Round($h.MemoryCapacity/1GB,1))")
      Get-VM -ComputerName $h.ComputerName | ForEach-Object {
        $null = $mdBuilder.AppendLine("  - VM $($_.Name) State:$($_.State) CPU:$($_.ProcessorCount) RAMMB:$($_.MemoryAssigned/1MB)")
      }
    }
  }catch{
    $null = $mdBuilder.AppendLine('_Hyper-V module not available on this machine._')
  }
}

$mdPath = Join-Path $reportDir "Infrastructure_Report_$stamp.md"
$mdBuilder.ToString().TrimEnd([Environment]::NewLine.ToCharArray()) | Out-File -Encoding UTF8 $mdPath

# Graphviz DOT (very simple)
$dotBuilder = [System.Text.StringBuilder]::new()
$null = $dotBuilder.AppendLine('digraph Infra {')
$null = $dotBuilder.AppendLine('  rankdir=LR; node [shape=box, fontsize=10];')
$null = $dotBuilder.AppendLine("  subgraph cluster_domain { label=\"Domain: $($dom.DNSRoot)\"; style=dashed;")
foreach($dc in $dcs){ $null = $dotBuilder.AppendLine("    \"DC:$($dc.HostName)\";") }
$null = $dotBuilder.AppendLine('  }')
foreach($z in $zones){ $null = $dotBuilder.AppendLine("  \"Zone:$($z.ZoneName)\";") }
foreach($s in $sites){ $null = $dotBuilder.AppendLine("  \"Site:$($s.Name)\";") }
foreach($dc in $dcs){
  $null = $dotBuilder.AppendLine("  \"Site:$($dc.Site)\" -> \"DC:$($dc.HostName)\";")
}
foreach($z in $zones){
  foreach($dc in $dcs){ $null = $dotBuilder.AppendLine("  \"DC:$($dc.HostName)\" -> \"Zone:$($z.ZoneName)\" [style=dotted];") }
}
$null = $dotBuilder.AppendLine('}')
$dotPath = Join-Path $reportDir "Infrastructure_Map_$stamp.dot"
$dotBuilder.ToString().TrimEnd([Environment]::NewLine.ToCharArray()) | Out-File -Encoding UTF8 $dotPath

Write-Host "Report: $mdPath"
Write-Host "Graphviz DOT: $dotPath (render with 'dot -Tpng file.dot -o file.png')"
