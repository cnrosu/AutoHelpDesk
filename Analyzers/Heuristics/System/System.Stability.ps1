function Update-SystemStabilityInsights {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $criticalEventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system-critical-events'
    if (-not $criticalEventsArtifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Targeted system event artifact missing' -Subcategory 'System stability'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $criticalEventsArtifact)
    if (-not $payload) { return }

    if ($payload.PSObject.Properties['Events']) {
        $rawEvents = $payload.Events
        if ($null -eq $rawEvents) {
            $rawEvents = @()
        } elseif ($rawEvents -isnot [System.Collections.IEnumerable] -or $rawEvents -is [string]) {
            $rawEvents = @($rawEvents)
        } else {
            $rawEvents = @($rawEvents)
        }

        if ($rawEvents.Count -eq 1 -and $rawEvents[0].PSObject.Properties['Error']) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to query targeted system events' -Evidence $rawEvents[0].Error -Subcategory 'System stability'
            return
        }

        $normalizedEvents = New-Object System.Collections.Generic.List[object]
        foreach ($event in $rawEvents) {
            if (-not $event) { continue }
            if (-not $event.PSObject.Properties['Id']) { continue }

            $parsedTime = $null
            if ($event.PSObject.Properties['TimeCreated']) {
                $parsedTime = ConvertFrom-EventIsoString -Timestamp ([string]$event.TimeCreated)
            }

            $normalizedEvents.Add([pscustomobject]@{
                    Id          = [int]$event.Id
                    TimeCreated = $parsedTime
                    RawTime     = $event.TimeCreated
                    Properties  = if ($event.PSObject.Properties['Properties']) { $event.Properties } else { $null }
                    Message     = if ($event.PSObject.Properties['Message']) { $event.Message } else { $null }
                }) | Out-Null
        }

        $windowStart = (Get-Date).AddDays(-7)

        $bugcheckEvents = @($normalizedEvents | Where-Object { $_.Id -eq 1001 -and $_.TimeCreated -and $_.TimeCreated -ge $windowStart })
        $kernelPowerEvents = @($normalizedEvents | Where-Object { $_.Id -eq 41 -and $_.TimeCreated -and $_.TimeCreated -ge $windowStart })
        $unexpectedShutdownEvents = @($normalizedEvents | Where-Object { $_.Id -eq 6008 -and $_.TimeCreated -and $_.TimeCreated -ge $windowStart })
        $tdrEvents = @($normalizedEvents | Where-Object { $_.Id -eq 4101 -and $_.TimeCreated -and $_.TimeCreated -ge $windowStart })

        $bugcheckCount = $bugcheckEvents.Count
        Add-CategoryCheck -CategoryResult $Result -Name 'BugCheck 1001 events (7 days)' -Status ([string]$bugcheckCount) -CheckId 'System/BugChecks'

        if ($bugcheckCount -gt 0) {
            $latestBugcheck = $bugcheckEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $bugcheckEvidence = New-Object System.Collections.Generic.List[string]
            [void]$bugcheckEvidence.Add("Count (7 days): {0}" -f $bugcheckCount)
            if ($latestBugcheck.TimeCreated) { [void]$bugcheckEvidence.Add("Most recent: {0}" -f $latestBugcheck.TimeCreated.ToString('u')) }
            $paramEvidence = Format-EventParameterEvidence -Parameters $latestBugcheck.Properties
            [void]$bugcheckEvidence.Add("Last parameters: {0}" -f $paramEvidence)

            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Recent bugcheck detected' -Evidence ($bugcheckEvidence -join '; ') -Subcategory 'System stability' -CheckId 'System/BugChecks'
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'No recent bugchecks detected' -Evidence 'Count (7 days): 0' -Subcategory 'System stability' -CheckId 'System/BugChecks'
        }

        $kernelPowerCount = $kernelPowerEvents.Count
        $unexpectedCount = $unexpectedShutdownEvents.Count
        $totalPowerResets = $kernelPowerCount + $unexpectedCount

        Add-CategoryCheck -CategoryResult $Result -Name 'Kernel-Power 41 events (7 days)' -Status ([string]$kernelPowerCount) -CheckId 'System/PowerResets'
        Add-CategoryCheck -CategoryResult $Result -Name 'Unexpected shutdown 6008 events (7 days)' -Status ([string]$unexpectedCount) -CheckId 'System/PowerResets'

        if ($totalPowerResets -gt 0) {
            $latestPowerEvent = @($kernelPowerEvents + $unexpectedShutdownEvents) | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $powerEvidence = New-Object System.Collections.Generic.List[string]
            [void]$powerEvidence.Add("Kernel-Power 41 count (7 days): {0}" -f $kernelPowerCount)
            [void]$powerEvidence.Add("Unexpected shutdown 6008 count (7 days): {0}" -f $unexpectedCount)
            if ($latestPowerEvent -and $latestPowerEvent.TimeCreated) { [void]$powerEvidence.Add("Most recent: {0}" -f $latestPowerEvent.TimeCreated.ToString('u')) }
            if ($latestPowerEvent) {
                $powerParams = Format-EventParameterEvidence -Parameters $latestPowerEvent.Properties
                [void]$powerEvidence.Add("Last parameters: {0}" -f $powerParams)
            }

            if ($kernelPowerCount -ge 5 -or $totalPowerResets -ge 6) {
                Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Frequent power reset events detected' -Evidence ($powerEvidence -join '; ') -Subcategory 'Power' -CheckId 'System/PowerResets'
            } elseif ($kernelPowerCount -ge 2 -or $unexpectedCount -ge 2 -or $totalPowerResets -ge 3) {
                Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Repeated power reset events detected' -Evidence ($powerEvidence -join '; ') -Subcategory 'Power' -CheckId 'System/PowerResets'
            } else {
                Add-CategoryNormal -CategoryResult $Result -Title 'Power reset events observed' -Evidence ($powerEvidence -join '; ') -Subcategory 'Power' -CheckId 'System/PowerResets'
            }
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'No recent power reset events detected' -Evidence 'Count (7 days): 0' -Subcategory 'Power' -CheckId 'System/PowerResets'
        }

        $tdrCount = $tdrEvents.Count
        Add-CategoryCheck -CategoryResult $Result -Name 'Display driver TDR 4101 events (7 days)' -Status ([string]$tdrCount) -CheckId 'System/GpuTdr'

        if ($tdrCount -ge 2) {
            $latestTdr = $tdrEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $tdrEvidence = New-Object System.Collections.Generic.List[string]
            [void]$tdrEvidence.Add("Count (7 days): {0}" -f $tdrCount)
            if ($latestTdr -and $latestTdr.TimeCreated) { [void]$tdrEvidence.Add("Most recent: {0}" -f $latestTdr.TimeCreated.ToString('u')) }
            if ($latestTdr) {
                $tdrParams = Format-EventParameterEvidence -Parameters $latestTdr.Properties
                [void]$tdrEvidence.Add("Last parameters: {0}" -f $tdrParams)
            }

            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Display driver timeouts detected' -Evidence ($tdrEvidence -join '; ') -Subcategory 'Graphics' -CheckId 'System/GpuTdr'
        } elseif ($tdrCount -eq 1) {
            $latestTdr = $tdrEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $tdrEvidence = New-Object System.Collections.Generic.List[string]
            [void]$tdrEvidence.Add('Count (7 days): 1')
            if ($latestTdr -and $latestTdr.TimeCreated) { [void]$tdrEvidence.Add("Most recent: {0}" -f $latestTdr.TimeCreated.ToString('u')) }
            if ($latestTdr) {
                $tdrParams = Format-EventParameterEvidence -Parameters $latestTdr.Properties
                [void]$tdrEvidence.Add("Last parameters: {0}" -f $tdrParams)
            }

            Add-CategoryNormal -CategoryResult $Result -Title 'Single recent GPU timeout event observed' -Evidence ($tdrEvidence -join '; ') -Subcategory 'Graphics' -CheckId 'System/GpuTdr'
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'No recent GPU timeout events detected' -Evidence 'Count (7 days): 0' -Subcategory 'Graphics' -CheckId 'System/GpuTdr'
        }

        return
    }

    if ($payload.PSObject.Properties['Error']) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Targeted system event collection failed' -Evidence $payload.Error -Subcategory 'System stability'
    } elseif ($payload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Targeted system event data unavailable' -Subcategory 'System stability'
    }
}
