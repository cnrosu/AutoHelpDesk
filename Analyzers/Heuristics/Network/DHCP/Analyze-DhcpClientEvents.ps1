<#!
.SYNOPSIS
    Summarizes DHCP client event log failures and conflicts.
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

Write-DhcpDebug -Message 'Analyzing DHCP client events' -Data ([ordered]@{ InputFolder = $InputFolder })

. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerCommon.ps1')

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-client-events.json'
if ($null -eq $payload) { return @() }
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'DHCP client event failures' -Severity 'warning' -Message "Unable to parse DHCP client event collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

$severityMap = @{
    '1001' = 'high'
    '1003' = 'high'
    '1005' = 'high'
    '1006' = 'high'
    '50013' = 'medium'
    '1046' = 'critical'
}

$descriptionMap = @{
    '1001' = 'address conflicts detected by clients'
    '1003' = 'no DHCP server responses during discovery'
    '1005' = 'no DHCP server responses during renewals'
    '1006' = 'lease renewal failures'
    '50013' = 'DHCP NACK responses from server'
    '1046' = 'scope exhaustion warnings'
}

$events = Ensure-Array $payload.Events | Where-Object { $_ -and $_.PSObject.Properties['Id'] }
if (-not $events) { return @() }

$findings = @()
$grouped = $events | Group-Object -Property Id
foreach ($group in $grouped) {
    $idText = [string]$group.Name
    if (-not $severityMap.ContainsKey($idText)) { continue }

    $entries = $group.Group | Sort-Object { ConvertFrom-Iso8601 $_.TimeCreated } -Descending
    $latest = $entries | Select-Object -First 1
    $first = $entries | Select-Object -Last 1

    $evidence = [ordered]@{
        EventId       = [int]$group.Name
        Count         = $group.Count
        LatestTime    = if ($latest.TimeCreated) { (ConvertFrom-Iso8601 $latest.TimeCreated).ToString('o') } else { $latest.TimeCreated }
        FirstSeenTime = if ($first.TimeCreated) { (ConvertFrom-Iso8601 $first.TimeCreated).ToString('o') } else { $first.TimeCreated }
        SampleMessage = if ($latest.Message) { Get-TopLines -Text $latest.Message -Count 20 } else { $null }
    }

    $description = if ($descriptionMap.ContainsKey($idText)) { $descriptionMap[$idText] } else { "DHCP client issue ($idText)" }
    $message = "Observed $($group.Count) DHCP client events (ID $idText) indicating $description."

    $findings += New-DhcpFinding -Check 'DHCP client event failures' -Severity $severityMap[$idText] -Message $message -Evidence $evidence
}

return $findings
