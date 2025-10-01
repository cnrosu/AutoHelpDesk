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

    Write-HeuristicDebug -Source 'Events' -Message 'Starting event log heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Events'

    $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    Write-HeuristicDebug -Source 'Events' -Message 'Resolved events artifact' -Data ([ordered]@{
        Found = [bool]$eventsArtifact
    })
    if ($eventsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
        Write-HeuristicDebug -Source 'Events' -Message 'Resolved events payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        if ($payload) {
            foreach ($logName in @('System','Application','GroupPolicy')) {
                Write-HeuristicDebug -Source 'Events' -Message ('Inspecting {0} log entries' -f $logName)
                if (-not $payload.PSObject.Properties[$logName]) { continue }
                $entries = $payload.$logName
                if ($entries -and -not $entries.Error) {
                    $logSubcategory = ("{0} Event Log" -f $logName)
                    $errorCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
                    $warnCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log errors" -f $logName) -Status ([string]$errorCount)
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log warnings" -f $logName) -Status ([string]$warnCount)
                    if ($logName -eq 'GroupPolicy') {
                        if ($errorCount -gt 0) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Group Policy Operational log errors detected, indicating noisy or unhealthy logs.' -Evidence ("Errors: {0}" -f $errorCount) -Subcategory $logSubcategory
                        }
                    } else {
                        if ($errorCount -gt 20) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("{0} log shows many errors ({1} in recent sample), indicating noisy or unhealthy logs." -f $logName, $errorCount) -Evidence ("Errors recorded: {0}" -f $errorCount) -Subcategory $logSubcategory
                        }
                        if ($warnCount -gt 40) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("Many warnings in {0} log, indicating noisy or unhealthy logs." -f $logName) -Subcategory $logSubcategory
                        }
                    }
                } elseif ($entries.Error) {
                    $logSubcategory = ("{0} Event Log" -f $logName)
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Unable to read {0} event log, so noisy or unhealthy logs may be hidden." -f $logName) -Evidence $entries.Error -Subcategory $logSubcategory
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    $pendingArtifacts = Get-AnalyzerArtifact -Context $Context -Name 'pendingreboot'
    Write-HeuristicDebug -Source 'Events' -Message 'Evaluating pending rename persistence window' -Data ([ordered]@{
        ArtifactsPresent = [bool]$pendingArtifacts
    })

    if ($pendingArtifacts) {
        $artifactItems = @()
        if ($pendingArtifacts -is [System.Collections.IEnumerable] -and -not ($pendingArtifacts -is [string])) {
            $artifactItems = @($pendingArtifacts)
        } else {
            $artifactItems = @($pendingArtifacts)
        }

        $renameSnapshots = New-Object System.Collections.Generic.List[pscustomobject]
        $sha256 = $null

        try {
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            foreach ($artifact in $artifactItems) {
                if (-not $artifact -or -not $artifact.Data) { continue }

                $data = $artifact.Data
                if (-not $data.PSObject.Properties['Payload']) { continue }

                $payload = $data.Payload
                if (-not $payload) { continue }

                $collectedAtUtc = $null
                if ($data.PSObject.Properties['CollectedAt'] -and $data.CollectedAt) {
                    $timestamp = [string]$data.CollectedAt
                    if ($timestamp) {
                        try {
                            $parsed = [datetime]::Parse($timestamp, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
                        } catch {
                            try { $parsed = [datetime]::Parse($timestamp) } catch { $parsed = $null }
                        }

                        if ($parsed) { $collectedAtUtc = $parsed.ToUniversalTime() }
                    }
                }

                $indicatorList = @()
                if ($payload.PSObject.Properties['Indicators'] -and $payload.Indicators) {
                    $indicatorList = Ensure-Array $payload.Indicators
                }

                $rebootKeyPresent = $false
                foreach ($indicator in $indicatorList) {
                    if (-not $indicator) { continue }
                    $name = if ($indicator.PSObject.Properties['Name']) { [string]$indicator.Name } else { $null }
                    if (-not $name) { continue }
                    if ($name -in @('WindowsUpdateRebootRequired','ComponentBasedServicingRebootPending')) {
                        $present = $false
                        if ($indicator.PSObject.Properties['Present']) { $present = [bool]$indicator.Present }
                        if ($present) { $rebootKeyPresent = $true; break }
                    }
                }

                if ($rebootKeyPresent) { continue }

                $renameEntries = @()
                if ($payload.PSObject.Properties['PendingFileRenames']) {
                    $renamePayload = $payload.PendingFileRenames
                    if ($renamePayload -and $renamePayload.PSObject.Properties['PendingFileRenameOperations']) {
                        $rawEntries = $renamePayload.PendingFileRenameOperations
                        if ($rawEntries) {
                            if ($rawEntries -is [System.Collections.IEnumerable] -and -not ($rawEntries -is [string])) {
                                foreach ($value in $rawEntries) {
                                    if ($null -eq $value) { continue }
                                    if ($value -is [string]) {
                                        $trimmed = $value.Trim()
                                        if ($trimmed) { $renameEntries += $trimmed }
                                    }
                                }
                            } elseif ($rawEntries -is [string]) {
                                $trimmed = $rawEntries.Trim()
                                if ($trimmed) { $renameEntries += $trimmed }
                            }
                        }
                    }
                }

                $entryCount = $renameEntries.Count
                if ($entryCount -le 0) { continue }

                $hash = $null
                if ($sha256) {
                    try {
                        $joined = [string]::Join("`n", $renameEntries)
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
                        $hashBytes = $sha256.ComputeHash($bytes)
                        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
                    } catch {
                        $hash = $null
                    }
                }

                if (-not $hash) { continue }

                $snapshot = [pscustomobject]@{
                    Hash        = $hash
                    EntryCount  = $entryCount
                    CollectedAt = $collectedAtUtc
                }
                $renameSnapshots.Add($snapshot) | Out-Null
            }
        } finally {
            if ($sha256) { $sha256.Dispose() }
        }

        Write-HeuristicDebug -Source 'Events' -Message 'Pending rename persistence snapshots gathered' -Data ([ordered]@{
            SnapshotCount = $renameSnapshots.Count
        })

        if ($renameSnapshots.Count -gt 0) {
            $groups = $renameSnapshots | Group-Object -Property Hash
            foreach ($group in $groups) {
                $items = $group.Group | Where-Object { $_.CollectedAt }
                if ($items.Count -lt 2) { continue }

                $sorted = $items | Sort-Object -Property CollectedAt
                $first = $sorted[0]
                $last = $sorted[-1]

                $window = $last.CollectedAt - $first.CollectedAt
                if ($window.TotalHours -lt 24) { continue }

                $evidenceObject = [ordered]@{
                    entryCount   = $first.EntryCount
                    firstSeenUtc = $first.CollectedAt.ToString('o')
                    lastSeenUtc  = $last.CollectedAt.ToString('o')
                }

                $evidenceText = $null
                try {
                    $evidenceText = $evidenceObject | ConvertTo-Json -Compress
                } catch {
                    $evidenceText = "entryCount={0}; firstSeenUtc={1}; lastSeenUtc={2}" -f $evidenceObject.entryCount, $evidenceObject.firstSeenUtc, $evidenceObject.lastSeenUtc
                }

                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Pending reboot appears stuck (rename operations persist)' -Evidence $evidenceText -Subcategory 'Servicing / Reboot Coordination'
                break
            }
        }
    }

    return $result
}
