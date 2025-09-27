<#!
.SYNOPSIS
    Aggregates evidence of DHCP scope exhaustion from events and APIPA fallbacks.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder
)

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Import-Module (Join-Path -Path $repoRoot -ChildPath 'Modules/Common.psm1') -Force
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerCommon.ps1')

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-scope-exhaustion.json'
if ($null -eq $payload) { return @() }
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'DHCP scope exhaustion' -Severity 'warning' -Message "Unable to parse DHCP scope exhaustion collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

$events = Ensure-Array $payload.Events | Where-Object { $_ -and $_.Id }
$exhaustionEvents = $events | Where-Object { [string]$_.Id -eq '1046' }
$eventEvidence = $null
if ($exhaustionEvents) {
    $sorted = $exhaustionEvents | Sort-Object { ConvertFrom-Iso8601 $_.TimeCreated } -Descending
    $latest = $sorted | Select-Object -First 1
    $oldest = $sorted | Select-Object -Last 1
    $eventEvidence = [ordered]@{
        Count         = $exhaustionEvents.Count
        LatestTime    = if ($latest.TimeCreated) { (ConvertFrom-Iso8601 $latest.TimeCreated).ToString('o') } else { $latest.TimeCreated }
        FirstSeenTime = if ($oldest.TimeCreated) { (ConvertFrom-Iso8601 $oldest.TimeCreated).ToString('o') } else { $oldest.TimeCreated }
        SampleMessage = if ($latest.Message) { Get-TopLines -Text $latest.Message -Count 20 } else { $null }
    }
}

$apipaAdapters = @()
foreach ($adapter in (Ensure-Array $payload.AdapterConfigurations)) {
    if (-not $adapter) { continue }
    $addresses = Get-AdapterIpv4Addresses $adapter
    $apipa = $addresses | Where-Object { Test-IsApipaIPv4 $_ }
    if (-not $apipa) { continue }
    $gateway = ''
    $gws = Ensure-Array $adapter.DefaultIPGateway | Where-Object { $_ -and $_.Trim() }
    if ($gws) { $gateway = $gws[0].Trim() } else { $gateway = '<none>' }
    $apipaAdapters += [pscustomobject]@{
        Adapter = Get-AdapterIdentity $adapter
        Gateway = $gateway
        Address = $apipa[0]
    }
}

$apipaGroups = @()
if ($apipaAdapters) {
    $apipaGroups = $apipaAdapters | Group-Object -Property Gateway | Where-Object { $_.Count -ge 2 }
}

if (-not $eventEvidence -and -not $apipaGroups) {
    return @()
}

$messageParts = @()
if ($eventEvidence) { $messageParts += "detected $($eventEvidence.Count) DHCP scope exhaustion warnings (event ID 1046)" }
if ($apipaGroups) {
    $affected = ($apipaGroups | ForEach-Object { $_.Count }) -join ', '
    $messageParts += "found multiple adapters reverting to APIPA under gateway groupings ($affected)"
}

$message = "Indicators of DHCP scope depletion: " + ($messageParts -join '; ') + '.'

$evidence = [ordered]@{}
if ($eventEvidence) { $evidence['Events'] = $eventEvidence }
if ($apipaGroups) {
    $adapterEvidence = @()
    foreach ($group in $apipaGroups) {
        $adapterEvidence += [pscustomobject]@{
            Gateway  = $group.Name
            Adapters = ($group.Group | ForEach-Object { $_.Adapter })
            Addresses = ($group.Group | ForEach-Object { $_.Address })
        }
    }
    $evidence['ApipaAdapters'] = $adapterEvidence
}

return @(New-DhcpFinding -Check 'DHCP scope exhaustion' -Severity 'critical' -Message $message -Evidence $evidence)
