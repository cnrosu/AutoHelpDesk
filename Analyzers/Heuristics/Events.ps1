<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-EventsHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Events'

    $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    if ($eventsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
        if ($payload) {
            foreach ($logName in @('System','Application','GroupPolicy')) {
                if (-not $payload.PSObject.Properties[$logName]) { continue }
                $entries = $payload.$logName
                if ($entries -and -not $entries.Error) {
                    $errorCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
                    $warnCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log errors" -f $logName) -Status ([string]$errorCount)
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log warnings" -f $logName) -Status ([string]$warnCount)
                    if ($logName -eq 'GroupPolicy') {
                        if ($errorCount -gt 0) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Group Policy Operational log errors detected' -Evidence ("Errors: {0}" -f $errorCount)
                        }
                    } else {
                        if ($errorCount -gt 20) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("High error volume in {0} log" -f $logName) -Evidence ("Recent errors: {0}" -f $errorCount)
                        }
                        if ($warnCount -gt 40) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("Many warnings in {0} log" -f $logName)
                        }
                    }
                } elseif ($entries.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title ("Unable to read {0} event log" -f $logName) -Evidence $entries.Error
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Event log artifact missing'
    }

    return $result
}
