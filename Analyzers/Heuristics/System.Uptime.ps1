function Add-SystemUptimeInsights {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult
    )

    $uptimeArtifact = Get-AnalyzerArtifact -Context $Context -Name 'uptime'
    if ($uptimeArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $uptimeArtifact)
        if ($payload -and $payload.Uptime -and -not $payload.Uptime.Error) {
            $uptimeRecord = $payload.Uptime
            $uptimeText = $uptimeRecord.Uptime
            $span = $null
            if ($uptimeText) {
                try { $span = [TimeSpan]::Parse($uptimeText) } catch { $span = $null }
            }

            if ($span) {
                $days = [math]::Floor($span.TotalDays)
                Add-CategoryCheck -CategoryResult $CategoryResult -Name 'Current uptime (days)' -Status ([string][math]::Round($span.TotalDays,2))
                if ($span.TotalDays -gt 30) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Device has not rebooted in over 30 days' -Evidence ("Reported uptime: {0}" -f $uptimeText) -Subcategory 'Uptime'
                } elseif ($span.TotalDays -lt 1) {
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Recent reboot detected'
                }
            }
        }
    }
}
