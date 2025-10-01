<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-EventsArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            if ($null -ne $item) { $list.Add($item) | Out-Null }
        }
        return $list.ToArray()
    }

    return @($Value)
}

function ConvertTo-EventsDateTime {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    try {
        return [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
    } catch {
        try {
            return [datetime]::Parse($text)
        } catch {
            return $null
        }
    }
}

function Get-ServiceDependencyNamesFromRecord {
    param($Record)

    if (-not $Record) { return @() }

    $names = New-Object System.Collections.Generic.List[string]
    $dedup = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

    $addName = {
        param($value)

        if ($null -eq $value) { return }

        $candidate = ''
        if ($value -is [string]) {
            $candidate = $value
        } elseif ($value -is [System.ServiceProcess.ServiceController]) {
            $candidate = $value.ServiceName
        } elseif ($value.PSObject) {
            if ($value.PSObject.Properties['Name']) {
                $candidate = [string]$value.Name
            } elseif ($value.PSObject.Properties['ServiceName']) {
                $candidate = [string]$value.ServiceName
            } elseif ($value.PSObject.Properties['Id']) {
                $candidate = [string]$value.Id
            } else {
                $candidate = [string]$value
            }
        } else {
            $candidate = [string]$value
        }

        if ([string]::IsNullOrWhiteSpace($candidate)) { return }

        $normalized = $candidate.Trim()
        if (-not $dedup.Add($normalized)) { return }

        $names.Add($normalized.ToUpperInvariant()) | Out-Null
    }

    foreach ($propertyName in @('Dependencies','DependOnService','ServicesDependedOn','RequiredServices')) {
        if (-not $Record.PSObject.Properties[$propertyName]) { continue }
        $raw = $Record.$propertyName
        if ($null -eq $raw) { continue }

        if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
            foreach ($entry in $raw) { & $addName $entry }
        } else {
            & $addName $raw
        }
    }

    return $names.ToArray()
}

function Get-WindowsUpdateDependencyInfo {
    param($Context)

    $info = [ordered]@{
        HasData       = $false
        DependsOnBits = $false
        Dependencies  = @()
    }

    $serviceArtifact = Get-AnalyzerArtifact -Context $Context -Name 'service-baseline'
    if (-not $serviceArtifact) { return [pscustomobject]$info }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $serviceArtifact)
    if (-not $payload) { return [pscustomobject]$info }

    if (-not $payload.PSObject.Properties['Services']) { return [pscustomobject]$info }

    $services = ConvertTo-EventsArray $payload.Services
    if ($services.Count -eq 0) { return [pscustomobject]$info }

    $info['HasData'] = $true

    foreach ($service in $services) {
        if (-not $service) { continue }

        $name = $null
        if ($service.PSObject.Properties['Name']) {
            $name = [string]$service.Name
        } elseif ($service.PSObject.Properties['ServiceName']) {
            $name = [string]$service.ServiceName
        }

        if (-not $name) { continue }

        if ($name.Equals('wuauserv', [System.StringComparison]::OrdinalIgnoreCase)) {
            $dependencies = Get-ServiceDependencyNamesFromRecord -Record $service
            $info['Dependencies'] = $dependencies
            $info['DependsOnBits'] = ($dependencies | Where-Object { $_ -eq 'BITS' }).Count -gt 0
            break
        }
    }

    return [pscustomobject]$info
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

    $bitsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'bits-events'
    Write-HeuristicDebug -Source 'Events/BITS' -Message 'Resolved BITS artifact' -Data ([ordered]@{ Found = [bool]$bitsArtifact })
    if ($bitsArtifact) {
        $bitsPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $bitsArtifact)
        Write-HeuristicDebug -Source 'Events/BITS' -Message 'Resolved BITS payload' -Data ([ordered]@{ HasPayload = [bool]$bitsPayload })

        if ($bitsPayload) {
            $eventsNode = $null
            if ($bitsPayload.PSObject.Properties['Events']) { $eventsNode = $bitsPayload.Events }

            $eventsError = $null
            $events = @()
            if ($eventsNode) {
                if ($eventsNode.PSObject -and $eventsNode.PSObject.Properties['Error']) {
                    $eventsError = [string]$eventsNode.Error
                } else {
                    $events = ConvertTo-EventsArray $eventsNode
                }
            }

            if ($eventsError) {
                Write-HeuristicDebug -Source 'Events/BITS' -Message 'BITS events collector reported error' -Data ([ordered]@{
                    Error = $eventsError
                })
            } elseif ($events.Count -gt 0) {
                $failureIds = @(16392, 16398, 16402)

                $now = $null
                if ($bitsPayload.PSObject.Properties['CurrentTime']) {
                    $now = ConvertTo-EventsDateTime $bitsPayload.CurrentTime
                }
                if (-not $now) { $now = Get-Date }

                if ($now.Kind -eq [System.DateTimeKind]::Unspecified) {
                    $now = [datetime]::SpecifyKind($now, [System.DateTimeKind]::Local)
                }
                $nowUtc = if ($now.Kind -eq [System.DateTimeKind]::Utc) { $now } else { $now.ToUniversalTime() }
                $windowStart = $nowUtc.AddHours(-48)

                $recentEvents = [System.Collections.Generic.List[pscustomobject]]::new()
                foreach ($event in $events) {
                    if (-not $event -or -not $event.PSObject.Properties['Id']) { continue }

                    $idValue = $null
                    try { $idValue = [int]$event.Id } catch { continue }
                    if (-not ($failureIds -contains $idValue)) { continue }

                    $timeValue = $null
                    if ($event.PSObject.Properties['TimeCreated']) {
                        $timeValue = ConvertTo-EventsDateTime $event.TimeCreated
                    }
                    if (-not $timeValue) { continue }

                    if ($timeValue.Kind -eq [System.DateTimeKind]::Unspecified) {
                        $timeValue = [datetime]::SpecifyKind($timeValue, [System.DateTimeKind]::Local)
                    }
                    $timeUtc = if ($timeValue.Kind -eq [System.DateTimeKind]::Utc) { $timeValue } else { $timeValue.ToUniversalTime() }

                    if ($timeUtc -lt $windowStart) { continue }

                    $recentEvents.Add([pscustomobject]@{
                        Id      = $idValue
                        TimeUtc = $timeUtc
                    }) | Out-Null
                }

                $recentCount = $recentEvents.Count
                $uniqueIds = ($recentEvents | Select-Object -ExpandProperty Id | Sort-Object -Unique)
                Write-HeuristicDebug -Source 'Events/BITS' -Message ('BITS failure events (48h): {0}' -f $recentCount) -Data ([ordered]@{
                    Ids = if ($uniqueIds) { ($uniqueIds -join ',') } else { '(none)' }
                })

                if ($recentCount -ge 3) {
                    $grouped = $recentEvents | Group-Object -Property Id
                    $eventSummaries = [System.Collections.Generic.List[pscustomobject]]::new()
                    foreach ($group in ($grouped | Sort-Object -Property Name)) {
                        $latest = $group.Group | Sort-Object -Property TimeUtc -Descending | Select-Object -First 1
                        $summary = [ordered]@{
                            id    = [int]$group.Name
                            count = $group.Count
                        }
                        if ($latest -and $latest.TimeUtc) { $summary['lastUtc'] = $latest.TimeUtc.ToString('o') }
                        $eventSummaries.Add([pscustomobject]$summary) | Out-Null
                    }

                    $latestEvent = $recentEvents | Sort-Object -Property TimeUtc -Descending | Select-Object -First 1

                    $evidence = [ordered]@{
                        eventIds = $eventSummaries.ToArray()
                        count48h = $recentCount
                    }
                    if ($latestEvent -and $latestEvent.TimeUtc) { $evidence['lastUtc'] = $latestEvent.TimeUtc.ToString('o') }
                    $evidence['windowStartUtc'] = $windowStart.ToString('o')

                    $dependencyInfo = Get-WindowsUpdateDependencyInfo -Context $Context
                    if ($dependencyInfo) {
                        if ($dependencyInfo.Dependencies -and $dependencyInfo.Dependencies.Count -gt 0) {
                            $evidence['wuauservDependencies'] = $dependencyInfo.Dependencies
                        }

                        if ($dependencyInfo.DependsOnBits) {
                            $evidence['note'] = 'Windows Update (wuauserv) depends on BITS on this device.'
                        }
                    }

                    Write-HeuristicDebug -Source 'Events/BITS' -Message 'BITS job failure heuristic triggered' -Data ([ordered]@{
                        Count         = $recentCount
                        EventIds      = if ($uniqueIds) { ($uniqueIds -join ',') } else { '(none)' }
                        DependsOnBits = if ($dependencyInfo) { [bool]$dependencyInfo.DependsOnBits } else { $false }
                    })

                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'BITS job failures observed' -Evidence ([pscustomobject]$evidence) -Subcategory 'BITS Transfer Jobs'
                }
            }
        }
    }

    return $result
}
