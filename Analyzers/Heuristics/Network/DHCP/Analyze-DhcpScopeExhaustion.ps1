<#!
.SYNOPSIS
    Aggregates evidence of DHCP scope exhaustion from events and APIPA fallbacks.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Parameter(Mandatory)]
    [pscustomobject]$CategoryResult,

    [Parameter(Mandatory)]
    [pscustomobject]$Context
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerHelper.ps1')

Write-DhcpDebug -Message 'Analyzing DHCP scope utilization' -Data ([ordered]@{ InputFolder = $InputFolder })

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileNames @('dhcp-scope-exhaustion.json')
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

$messageBuilder = [System.Text.StringBuilder]::new()
if ($eventEvidence) {
    $null = $messageBuilder.Append("detected $($eventEvidence.Count) DHCP scope exhaustion warnings (event ID 1046)")
}
if ($apipaGroups) {
    $affectedCounts = [System.Collections.Generic.List[int]]::new()
    foreach ($group in $apipaGroups) {
        $null = $affectedCounts.Add([int]$group.Count)
    }

    $affected = ($affectedCounts -join ', ')
    if ($messageBuilder.Length -gt 0) { $null = $messageBuilder.Append('; ') }
    $null = $messageBuilder.Append("found multiple adapters reverting to APIPA under gateway groupings ($affected)")
}

$message = "Indicators of DHCP scope depletion: " + $messageBuilder.ToString() + '.'

$evidence = [ordered]@{}
if ($eventEvidence) { $evidence['Events'] = $eventEvidence }
if ($apipaGroups) {
    $adapterEvidence = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($group in $apipaGroups) {
        $groupAdapters = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $group.Group) {
            $null = $groupAdapters.Add($item.Adapter)
        }

        $groupAddresses = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $group.Group) {
            $null = $groupAddresses.Add($item.Address)
        }

        $null = $adapterEvidence.Add([pscustomobject]@{
            Gateway   = $group.Name
            Adapters  = $groupAdapters
            Addresses = $groupAddresses
        })
    }
    $evidence['ApipaAdapters'] = $adapterEvidence
}

return @(New-DhcpFinding -Check 'DHCP scope exhaustion' -Severity 'critical' -Message $message -Evidence $evidence)
