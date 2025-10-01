<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-EventDateTime {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) { return $Value }

    if ($Value -is [string]) {
        $text = $Value.Trim()
        if (-not $text) { return $null }

        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse($text, [ref]$parsed)) { return $parsed }
        try { return [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
    }

    return $null
}

function Get-MaskedNetBiosName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    $trimmed = [regex]::Replace($Name.Trim(), "^[\"']+|[\"']+$", '')
    if (-not $trimmed) { return $null }

    if ($trimmed.Length -le 1) { return '***' }
    if ($trimmed.Length -eq 2) { return ('{0}**' -f $trimmed.Substring(0, 1)) }

    $first = $trimmed.Substring(0, 1)
    $last = $trimmed.Substring($trimmed.Length - 1, 1)
    return ('{0}***{1}' -f $first, $last)
}

function Get-DuplicateNameFromMessage {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $patterns = @(
        '(?i)name\s+"([^"\r\n]+)"',
        "(?i)name\s+'([^'\r\n]+)'",
        '(?i)duplicate\s+name\s+([A-Za-z0-9._$-]+)'
    )

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Message, $pattern)
        if ($match.Success -and $match.Groups.Count -gt 1) {
            $candidate = $match.Groups[1].Value.Trim()
            if ($candidate) { return $candidate }
        }
    }

    return $null
}

function Get-EventMessageSnippet {
    param(
        [string]$Message,
        [string]$OriginalName,
        [string]$MaskedName,
        [int]$MaxLength = 160
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $text = [System.Text.RegularExpressions.Regex]::Replace($Message.Trim(), '\s+', ' ')

    if ($OriginalName -and $MaskedName) {
        $escaped = [regex]::Escape($OriginalName)
        $text = [regex]::Replace(
            $text,
            $escaped,
            [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $MaskedName },
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    if ($text.Length -le $MaxLength) { return $text }

    return ($text.Substring(0, $MaxLength).TrimEnd() + '…')
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
            $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
            $systemPayload = if ($systemArtifact) { Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact) } else { $null }
            $localComputerName = $null
            $localComputerNameMasked = $null
            if ($systemPayload -and $systemPayload.ComputerSystem -and -not $systemPayload.ComputerSystem.Error) {
                if ($systemPayload.ComputerSystem.PSObject.Properties['Name']) {
                    $localComputerName = [string]$systemPayload.ComputerSystem.Name
                    $localComputerNameMasked = Get-MaskedNetBiosName -Name $localComputerName
                }
            }

            $systemEntries = $null
            foreach ($logName in @('System','Application','GroupPolicy')) {
                Write-HeuristicDebug -Source 'Events' -Message ('Inspecting {0} log entries' -f $logName)
                if (-not $payload.PSObject.Properties[$logName]) { continue }
                $entries = $payload.$logName
                if ($entries -and -not $entries.Error) {
                    if ($logName -eq 'System') { $systemEntries = $entries }
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

            if ($systemEntries) {
                $cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-7)
                $matchingEvents = @()

                foreach ($entry in $systemEntries) {
                    if (-not $entry) { continue }

                    $message = if ($entry.PSObject.Properties['Message']) { [string]$entry.Message } else { $null }
                    $id = if ($entry.PSObject.Properties['Id']) { [int]$entry.Id } else { $null }
                    $matchesDuplicate = $false

                    if ($id -eq 4319) {
                        $matchesDuplicate = $true
                    } elseif ($message -and ($message -match '(?i)duplicate\s+name')) {
                        $matchesDuplicate = $true
                    }

                    if (-not $matchesDuplicate) { continue }

                    $eventTime = $null
                    if ($entry.PSObject.Properties['TimeCreated'] -and $entry.TimeCreated) {
                        $eventTime = ConvertTo-EventDateTime -Value $entry.TimeCreated
                    }

                    if (-not $eventTime) { continue }

                    $eventUtc = $eventTime.ToUniversalTime()
                    if ($eventUtc -lt $cutoffUtc) { continue }

                    $matchingEvents += [pscustomobject]@{ Entry = $entry; Time = $eventTime }
                }

                if ($matchingEvents.Count -gt 0) {
                    $selected = $matchingEvents | Sort-Object -Property @{ Expression = { $_.Time }; Descending = $true } | Select-Object -First 1
                    $selectedEntry = $selected.Entry
                    $selectedMessage = if ($selectedEntry.PSObject.Properties['Message']) { [string]$selectedEntry.Message } else { $null }
                    $nameFromMessage = Get-DuplicateNameFromMessage -Message $selectedMessage

                    $maskedName = $localComputerNameMasked
                    if (-not $maskedName -and $nameFromMessage) {
                        $maskedName = Get-MaskedNetBiosName -Name $nameFromMessage
                    }
                    if (-not $maskedName) { $maskedName = 'Unknown' }

                    $originalNameForSnippet = if ($nameFromMessage) { $nameFromMessage } elseif ($localComputerName) { $localComputerName } else { $null }
                    $snippet = Get-EventMessageSnippet -Message $selectedMessage -OriginalName $originalNameForSnippet -MaskedName $maskedName
                    if (-not $snippet) { $snippet = 'Event message unavailable.' }

                    $evidence = [ordered]@{
                        localNameMasked = $maskedName
                        lastUtc         = $selected.Time.ToUniversalTime().ToString('o')
                        messageSnippet  = $snippet
                    }

                    Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Duplicate machine name detected on network (NetBT 4319)' -Evidence $evidence -Subcategory 'Networking / NetBIOS'
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
