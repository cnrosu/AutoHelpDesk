<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Normalize-WindowsUpdateHResult {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $trimmed = $text.Trim()
    if ($trimmed -match '^0x[0-9a-fA-F]+$') {
        $hex = $trimmed.Substring(2).ToUpperInvariant()
        $padded = $hex.PadLeft(8, '0')
        return '0x{0}' -f $padded
    }

    $number = 0L
    if ([long]::TryParse($trimmed, [ref]$number)) {
        $unsigned = [uint32]$number
        return ('0x{0:X8}' -f $unsigned)
    }

    $match = [regex]::Match($trimmed, '0x[0-9a-fA-F]+')
    if ($match.Success) {
        $hex = $match.Value.Substring(2).ToUpperInvariant()
        $padded = $hex.PadLeft(8, '0')
        return '0x{0}' -f $padded
    }

    return $null
}

function Get-WindowsUpdateEventHResult {
    param(
        [AllowNull()]
        [object]$Event
    )

    if (-not $Event) { return $null }
    if (-not $Event.PSObject.Properties['EventData']) { return $null }

    $eventData = $Event.EventData
    if ($null -eq $eventData) { return $null }

    $propertyHandler = {
        param($Name, $Value)

        if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
        $normalizedName = $Name.ToLowerInvariant()
        if ($normalizedName -ne 'hr' -and $normalizedName -notmatch 'hresult' -and $normalizedName -notmatch 'errorcode' -and $normalizedName -notmatch 'resultcode') {
            return $null
        }

        return Normalize-WindowsUpdateHResult -Value $Value
    }

    if ($eventData -is [System.Collections.IDictionary]) {
        foreach ($key in $eventData.Keys) {
            $candidate = & $propertyHandler $key $eventData[$key]
            if ($candidate) { return $candidate }
        }
    } else {
        foreach ($prop in $eventData.PSObject.Properties) {
            if (-not $prop) { continue }
            $candidate = & $propertyHandler $prop.Name $prop.Value
            if ($candidate) { return $candidate }
        }
    }

    return $null
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

    $wuArtifact = Get-AnalyzerArtifact -Context $Context -Name 'windows-update-events'
    Write-HeuristicDebug -Source 'Events/WindowsUpdate' -Message 'Resolved Windows Update events artifact' -Data ([ordered]@{
        Found = [bool]$wuArtifact
    })
    if ($wuArtifact) {
        $wuPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wuArtifact)
        Write-HeuristicDebug -Source 'Events/WindowsUpdate' -Message 'Resolved Windows Update payload' -Data ([ordered]@{
            HasPayload = [bool]$wuPayload
        })
        if ($wuPayload) {
            if ($wuPayload.PSObject.Properties['Error'] -and $wuPayload.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Windows Update event log unavailable' -Evidence ([ordered]@{
                    Error  = $wuPayload.Error
                    Source = if ($wuPayload.PSObject.Properties['ErrorSource']) { $wuPayload.ErrorSource } else { 'Microsoft-Windows-WindowsUpdateClient/Operational' }
                }) -Subcategory 'Windows Update'
            } else {
                $events = Ensure-Array $wuPayload.Events
                Write-HeuristicDebug -Source 'Events/WindowsUpdate' -Message 'Windows Update event count' -Data ([ordered]@{
                    Count = $events.Count
                })
                if ($events.Count -gt 0) {
                    $windowEnd = $null
                    if ($wuPayload.PSObject.Properties['WindowEnd'] -and $wuPayload.WindowEnd) {
                        $windowEnd = ConvertFrom-Iso8601 $wuPayload.WindowEnd
                    }
                    if (-not $windowEnd) { $windowEnd = Get-Date }
                    $recentBoundary = $windowEnd.AddDays(-7)
                    $failureIds = @(20, 25, 31, 34)
                    $candidates = @()

                    foreach ($event in $events) {
                        if (-not $event) { continue }
                        $idValue = $null
                        if ($event.PSObject.Properties['Id'] -and $null -ne $event.Id) {
                            try { $idValue = [int]$event.Id } catch { continue }
                        }
                        if (-not $idValue -or ($failureIds -notcontains $idValue)) { continue }

                        $eventTime = $null
                        if ($event.PSObject.Properties['TimeCreated'] -and $event.TimeCreated) {
                            $eventTime = ConvertFrom-Iso8601 $event.TimeCreated
                            if (-not $eventTime -and ($event.TimeCreated -is [datetime])) {
                                $eventTime = [datetime]$event.TimeCreated
                            }
                        }
                        if (-not $eventTime) { continue }
                        if ($eventTime -lt $recentBoundary) { continue }

                        $hresult = Get-WindowsUpdateEventHResult -Event $event
                        if (-not $hresult) { continue }

                        $candidates += [pscustomobject]@{
                            Id      = $idValue
                            Time    = $eventTime
                            HResult = $hresult
                        }
                    }

                    Write-HeuristicDebug -Source 'Events/WindowsUpdate' -Message 'Windows Update failure candidates' -Data ([ordered]@{
                        Count = $candidates.Count
                    })

                    if ($candidates.Count -gt 0) {
                        $grouped = $candidates | Group-Object -Property HResult
                        foreach ($group in $grouped) {
                            if (-not $group -or [string]::IsNullOrWhiteSpace($group.Name)) { continue }
                            if ($group.Count -lt 3) { continue }

                            $sorted = $group.Group | Sort-Object -Property Time -Descending
                            $latest = $sorted | Select-Object -First 1
                            $evidence = [ordered]@{
                                hresult      = $group.Name
                                occurrences  = $group.Count
                                lastUtc      = if ($latest.Time) { $latest.Time.ToUniversalTime().ToString('o') } else { $null }
                                remediation  = 'Run DISM /Online /Cleanup-Image /RestoreHealth and SFC /SCANNOW before retrying Windows Update.'
                            }

                            Write-HeuristicDebug -Source 'Events/WindowsUpdate' -Message 'Detected repeated Windows Update failure' -Data ([ordered]@{
                                HResult     = $group.Name
                                Occurrences = $group.Count
                                LastUtc     = $evidence.lastUtc
                            })

                            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Update repeatedly failing' -Evidence $evidence -Subcategory 'Windows Update'
                        }
                    }
                }
            }
        }
    }

    return $result
}
