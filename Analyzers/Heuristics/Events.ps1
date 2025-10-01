<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>


. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Get-UsbDeviceIdTail {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $pattern = 'VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}(?:&[A-Za-z0-9_]+)*'
    $match = [regex]::Match($Value, $pattern)
    if ($match.Success) {
        return $match.Value.ToUpperInvariant()
    }

    return $null
}

function ConvertTo-UtcDateTime {
    param(
        [object]$Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime()
    }

    $text = $Value.ToString()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    try {
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        $dt = [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
        return $dt
    } catch {
        try {
            $dt = [datetime]::Parse($text)
            return $dt.ToUniversalTime()
        } catch {
            return $null
        }
    }
}

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

    $deviceInstallArtifact = Get-AnalyzerArtifact -Context $Context -Name 'deviceinstall-events'
    Write-HeuristicDebug -Source 'Events' -Message 'Resolved device install artifact' -Data ([ordered]@{
        Found = [bool]$deviceInstallArtifact
    })

    if ($deviceInstallArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $deviceInstallArtifact)
        Write-HeuristicDebug -Source 'Events' -Message 'Resolved device install payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })

        if ($payload) {
            $windowDays = if ($payload.PSObject.Properties['WindowDays']) { [int]$payload.WindowDays } else { 7 }
            $candidateEvents = [System.Collections.Generic.List[pscustomobject]]::new()
            $errors = [System.Collections.Generic.List[string]]::new()

            $sources = @(
                [pscustomobject]@{ Property = 'UserPnpEvents'; Label = 'Microsoft-Windows-UserPnp/DeviceInstall' },
                [pscustomobject]@{ Property = 'KernelPnPEvents'; Label = 'Microsoft-Windows-Kernel-PnP' }
            )

            foreach ($source in $sources) {
                if (-not $payload.PSObject.Properties[$source.Property]) { continue }
                $items = $payload.($source.Property)

                $isEnumerable = $items -is [System.Collections.IEnumerable] -and -not ($items -is [string]) -and -not ($items -is [hashtable])
                if ($isEnumerable) {
                    foreach ($item in $items) {
                        if (-not $item) { continue }

                        if ($item.PSObject.Properties['Error'] -and $item.Error) {
                            $errors.Add(("{0}: {1}" -f $source.Label, $item.Error)) | Out-Null
                            continue
                        }

                        $tail = $null
                        if ($item.PSObject.Properties['Message']) {
                            $tail = Get-UsbDeviceIdTail -Value $item.Message
                        }

                        if (-not $tail -and $item.PSObject.Properties['Properties'] -and $item.Properties) {
                            foreach ($value in $item.Properties) {
                                $tail = Get-UsbDeviceIdTail -Value $value
                                if ($tail) { break }
                            }
                        }

                        if (-not $tail) { continue }

                        $timestamp = $null
                        if ($item.PSObject.Properties['TimeCreated']) {
                            $timestamp = ConvertTo-UtcDateTime -Value $item.TimeCreated
                        }

                        $candidateEvents.Add([pscustomobject]@{
                            Tail    = $tail
                            Source  = $source.Label
                            EventId = $item.Id
                            TimeUtc = $timestamp
                        }) | Out-Null
                    }
                } elseif ($items -and $items.PSObject.Properties['Error'] -and $items.Error) {
                    $errors.Add(("{0}: {1}" -f $source.Label, $items.Error)) | Out-Null
                }
            }

            $groupSummaries = [System.Collections.Generic.List[pscustomobject]]::new()
            if ($candidateEvents.Count -gt 0) {
                $grouped = $candidateEvents | Group-Object -Property Tail
                foreach ($group in $grouped) {
                    if (-not $group) { continue }
                    $count = $group.Count
                    if ($count -lt 3) { continue }

                    $lastSeen = $null
                    $timestamps = $group.Group | ForEach-Object { $_.TimeUtc } | Where-Object { $_ }
                    if ($timestamps) {
                        $lastSeen = ($timestamps | Sort-Object -Descending | Select-Object -First 1)
                    }

                    if (-not $lastSeen) { $lastSeen = [datetime]::UtcNow }

                    $groupSummaries.Add([pscustomobject]@{
                        deviceIdTail = $group.Name
                        count        = $count
                        lastUtc      = $lastSeen.ToString('o')
                    }) | Out-Null
                }
            }

            $severity = $null
            if ($groupSummaries.Count -gt 0) {
                $maxCount = ($groupSummaries | Measure-Object -Property count -Maximum).Maximum
                $severity = if ($maxCount -ge 5) { 'medium' } else { 'low' }
                $evidence = [ordered]@{
                    windowDays = $windowDays
                    devices    = $groupSummaries
                }

                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Repeated device install failures detected' -Evidence $evidence -Subcategory 'USB / Device Install'
            }

            Write-HeuristicDebug -Source 'Events' -Message 'Device install event evaluation summary' -Data ([ordered]@{
                CandidateCount = $candidateEvents.Count
                IssueCount     = $groupSummaries.Count
                Severity       = if ($severity) { $severity } else { 'none' }
                Errors         = if ($errors.Count -gt 0) { $errors.Count } else { 0 }
            })

            if ($errors.Count -gt 0) {
                Write-HeuristicDebug -Source 'Events' -Message 'Device install event errors encountered' -Data ([ordered]@{
                    Details = ($errors -join ' | ')
                })
            }
        }
    }

    return $result
}
