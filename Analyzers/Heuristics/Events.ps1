<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Get-AppLockerSampleIdentifier {
    param(
        [string]$Message
    )

    if (-not $Message) { return $null }

    $lines = $Message -split "`r?`n"
    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        $publisherMatch = [regex]::Match($trimmed, '^Publisher\s*:\s*(.+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($publisherMatch.Success) {
            $publisher = $publisherMatch.Groups[1].Value.Trim()
            if ($publisher -and $publisher -notmatch 'Not Available') {
                return ('Publisher: {0}' -f $publisher)
            }
        }
    }

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        $pathMatch = [regex]::Match($trimmed, '^(?:File\s+(?:Path|Name)|Path)\s*:\s*(.+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($pathMatch.Success) {
            $pathValue = $pathMatch.Groups[1].Value.Trim()
            if (-not $pathValue) { continue }

            $leaf = $pathValue
            try {
                $fileName = [System.IO.Path]::GetFileName($pathValue)
                if ($fileName) { $leaf = $fileName }
            } catch {
                $leaf = $pathValue
            }

            return ('File: {0}' -f $leaf)
        }
    }

    $nonEmpty = $lines | Where-Object { $_ -and $_.Trim() }
    if ($nonEmpty) {
        return ($nonEmpty | Select-Object -First 1).Trim()
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

            if ($payload.PSObject.Properties['AppLocker']) {
                $appLocker = $payload.AppLocker
                Write-HeuristicDebug -Source 'Events' -Message 'Evaluating AppLocker channels'

                $channelDefinitions = @(
                    [pscustomobject]@{ Key = 'ExeAndDll'; Label = 'EXE and DLL' },
                    [pscustomobject]@{ Key = 'MsiAndScript'; Label = 'MSI and Script' }
                )

                $availableChannels = New-Object System.Collections.Generic.List[pscustomobject]
                $missingLabels = New-Object System.Collections.Generic.List[string]

                foreach ($definition in $channelDefinitions) {
                    $key = $definition.Key
                    $label = $definition.Label
                    $channelData = $null
                    if ($appLocker -and $appLocker.PSObject.Properties[$key]) {
                        $channelData = $appLocker.$key
                    }

                    if ($channelData -and $channelData.Status -eq 'Success') {
                        $availableChannels.Add([pscustomobject]@{ Key = $key; Label = $label; Data = $channelData }) | Out-Null
                    } else {
                        $missingLabels.Add($label) | Out-Null
                    }
                }

                if ($availableChannels.Count -eq 0) {
                    Add-CategoryCheck -CategoryResult $result -Name 'AppLocker log visibility' -Status 'None' -Details 'AppLocker event channels unavailable.'
                } elseif ($missingLabels.Count -gt 0) {
                    Add-CategoryCheck -CategoryResult $result -Name 'AppLocker log visibility' -Status 'Partial' -Details ('Missing: {0}' -f (($missingLabels.ToArray()) -join ', '))
                } else {
                    Add-CategoryCheck -CategoryResult $result -Name 'AppLocker log visibility' -Status 'Complete'
                }

                $exeChannel = $availableChannels | Where-Object { $_.Key -eq 'ExeAndDll' } | Select-Object -First 1
                if ($exeChannel -and $exeChannel.Data) {
                    $relevantIds = @('8003','8004')
                    $events = Ensure-Array $exeChannel.Data.Events | Where-Object {
                        if (-not $_) { return $false }
                        $idValue = $null
                        if ($_.PSObject.Properties['Id']) { $idValue = $_.Id }
                        if ($null -eq $idValue) { return $false }
                        $idText = [string]$idValue
                        return $relevantIds -contains $idText
                    }

                    $eventCount = $events.Count
                    Add-CategoryCheck -CategoryResult $result -Name 'AppLocker audit/deny events (EXE/DLL, 7d)' -Status ([string]$eventCount)

                    if ($eventCount -ge 3) {
                        $sorted = $events | Sort-Object {
                            $timeValue = $null
                            if ($_.PSObject.Properties['TimeCreated']) {
                                $timeValue = ConvertFrom-Iso8601 ([string]$_.TimeCreated)
                            }
                            if ($timeValue) { return $timeValue }
                            return [datetime]::MinValue
                        } -Descending

                        $latest = $sorted | Select-Object -First 1
                        $lastUtc = $null
                        if ($latest -and $latest.PSObject.Properties['TimeCreated']) {
                            $parsed = ConvertFrom-Iso8601 ([string]$latest.TimeCreated)
                            if ($parsed) {
                                $lastUtc = $parsed.ToUniversalTime().ToString('o')
                            } else {
                                $lastUtc = [string]$latest.TimeCreated
                            }
                        }

                        $sample = $null
                        if ($latest -and $latest.PSObject.Properties['Message']) {
                            $sample = Get-AppLockerSampleIdentifier -Message ([string]$latest.Message)
                        }

                        $evidence = [ordered]@{
                            count                       = $eventCount
                            samplePublisherOrPathMasked = $sample
                            lastUtc                     = $lastUtc
                        }

                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Application blocked or audited by policy' -Evidence $evidence -Subcategory 'Application Control' -CheckId 'Events/AppLocker/AuditDenyVolume'
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
