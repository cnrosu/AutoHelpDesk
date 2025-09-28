function Invoke-SystemUptimeChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Uptime' -Message 'Starting uptime checks'

    $uptimeArtifact = Get-AnalyzerArtifact -Context $Context -Name 'uptime'
    Write-HeuristicDebug -Source 'System/Uptime' -Message 'Resolved uptime artifact' -Data ([ordered]@{
        Found = [bool]$uptimeArtifact
    })
    if (-not $uptimeArtifact) { return }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $uptimeArtifact)
    Write-HeuristicDebug -Source 'System/Uptime' -Message 'Evaluating uptime payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if ($payload -and $payload.Uptime -and -not $payload.Uptime.Error) {
        $uptimeRecord = $payload.Uptime
        $uptimeText = $uptimeRecord.Uptime
        $span = $null
        if ($uptimeText) {
            try { $span = [TimeSpan]::Parse($uptimeText) } catch { $span = $null }
        }

        if ($span) {
            $days = [math]::Floor($span.TotalDays)
            Add-CategoryCheck -CategoryResult $Result -Name 'Current uptime (days)' -Status ([string][math]::Round($span.TotalDays,2))
            if ($span.TotalDays -gt 30) {
                Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Device has not rebooted in over 30 days' -Evidence ("Reported uptime: {0}" -f $uptimeText) -Subcategory 'Uptime'
            } elseif ($span.TotalDays -lt 1) {
                Add-CategoryNormal -CategoryResult $Result -Title 'Recent reboot detected'
            }
        }
    }
}
