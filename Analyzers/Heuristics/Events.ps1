<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-EventArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [pscustomobject] -and $Value.PSObject.Properties['Error']) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -ne $item) { $items += $item }
        }
        return $items
    }
    return @($Value)
}

function Get-EventPropertyValue {
    param(
        $Event,
        [string]$Name
    )

    if (-not $Event -or -not $Name) { return $null }
    if (-not ($Event.PSObject.Properties['Properties'])) { return $null }

    $props = $Event.Properties
    if (-not $props) { return $null }
    if (-not $props.PSObject.Properties[$Name]) { return $null }

    return $props.$Name
}

function ConvertTo-EventTime {
    param([string]$Text)

    if (-not $Text) { return $null }
    $trimmed = $Text.Trim()
    if (-not $trimmed) { return $null }

    $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
    try {
        return [datetime]::Parse($trimmed, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    } catch {
        try {
            return [datetime]::Parse($trimmed)
        } catch {
            return $null
        }
    }
}

function Get-MaskedCore {
    param([string]$Text)

    if (-not $Text) { return '***' }
    $clean = $Text.Trim()
    if (-not $clean) { return '***' }
    if ($clean.Length -eq 1) { return ($clean + '***') }
    if ($clean.Length -eq 2) { return ($clean.Substring(0, 1) + '***') }
    return ('{0}***{1}' -f $clean.Substring(0, 1), $clean.Substring($clean.Length - 1, 1))
}

function Mask-PrincipalValue {
    param([string]$Value)

    if (-not $Value) { return $null }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }

    $atIndex = $trimmed.IndexOf('@')
    if ($atIndex -gt 0 -and $atIndex -lt ($trimmed.Length - 1)) {
        $local = $trimmed.Substring(0, $atIndex)
        $domain = $trimmed.Substring($atIndex + 1)
        return ('{0}@{1}' -f (Get-MaskedCore $local), $domain)
    }

    $separatorIndex = $trimmed.LastIndexOf('\')
    if ($separatorIndex -lt 0) { $separatorIndex = $trimmed.LastIndexOf('/') }
    if ($separatorIndex -ge 0 -and $separatorIndex -lt ($trimmed.Length - 1)) {
        $prefix = $trimmed.Substring(0, $separatorIndex + 1)
        $core = $trimmed.Substring($separatorIndex + 1)
        return $prefix + (Get-MaskedCore $core)
    }

    return Get-MaskedCore $trimmed
}

function Mask-HostValue {
    param([string]$Value)

    if (-not $Value) { return $null }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }

    $candidate = $trimmed
    $ipv6Prefix = $null
    if ($candidate -like '::ffff:*') {
        $ipv6Prefix = '::ffff:'
        $candidate = $candidate.Substring(7)
    }

    if ($candidate -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        $masked = ('{0}.{1}.{2}.*' -f $matches[1], $matches[2], $matches[3])
        if ($ipv6Prefix) { return $ipv6Prefix + $masked }
        return $masked
    }

    if ($trimmed -match '^[0-9A-Fa-f:]+$' -and $trimmed.Contains(':')) {
        $segments = $trimmed.Split(':')
        if ($segments.Length -ge 2) {
            return ($segments[0] + ':' + $segments[1] + '::***')
        }
        return ($segments[0] + '::***')
    }

    $hyphenIndex = $trimmed.IndexOf('-')
    if ($hyphenIndex -gt 0) { return $trimmed.Substring(0, $hyphenIndex + 1) + '***' }

    $dotIndex = $trimmed.IndexOf('.')
    if ($dotIndex -gt 0) { return $trimmed.Substring(0, $dotIndex) + '.***' }

    $keep = [Math]::Min(4, $trimmed.Length)
    return $trimmed.Substring(0, $keep) + '***'
}

function Normalize-HostReference {
    param([string]$Value)

    if (-not $Value) { return $null }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }

    if ($trimmed -like '::ffff:*') {
        $trimmed = $trimmed.Substring(7)
    }

    if ($trimmed -match '^(\d{1,3}\.){3}\d{1,3}$') { return $trimmed }
    if ($trimmed -match '^[0-9A-Fa-f:]+$' -and $trimmed.Contains(':')) { return $trimmed.ToLowerInvariant() }

    $candidate = $trimmed.TrimEnd('$')
    if ($candidate.Contains('\')) { $candidate = ($candidate -split '\\')[-1] }
    if ($candidate.Contains('/')) { $candidate = ($candidate -split '/')[-1] }
    if ($candidate.Contains('@')) { $candidate = ($candidate -split '@')[0] }
    if ($candidate.Contains('.')) { $candidate = ($candidate -split '\.')[0] }

    if (-not $candidate) { return $null }
    return $candidate.ToLowerInvariant()
}

function Get-DeviceIdentityFromContext {
    param($Context)

    $deviceName = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload) {
            if ($payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
                if ($payload.OperatingSystem.PSObject.Properties['CSName']) { $deviceName = $payload.OperatingSystem.CSName }
                elseif ($payload.OperatingSystem.PSObject.Properties['PSComputerName']) { $deviceName = $payload.OperatingSystem.PSComputerName }
            }

            if (-not $deviceName -and $payload.ComputerSystem -and -not $payload.ComputerSystem.Error) {
                if ($payload.ComputerSystem.PSObject.Properties['Name']) { $deviceName = $payload.ComputerSystem.Name }
                elseif ($payload.ComputerSystem.PSObject.Properties['DNSHostName']) { $deviceName = $payload.ComputerSystem.DNSHostName }
                elseif ($payload.ComputerSystem.PSObject.Properties['PSComputerName']) { $deviceName = $payload.ComputerSystem.PSComputerName }
            }

            if (-not $deviceName -and $payload.SystemInfoText) {
                $lines = @()
                if ($payload.SystemInfoText -is [System.Collections.IEnumerable] -and -not ($payload.SystemInfoText -is [string])) {
                    foreach ($line in $payload.SystemInfoText) { if ($null -ne $line) { $lines += [string]$line } }
                } else {
                    $lines = ($payload.SystemInfoText -split "`r?`n")
                }

                foreach ($line in $lines) {
                    if ($line -match '(?i)^\s*Host Name\s*:\s*(.+)$') {
                        $candidate = $matches[1].Trim()
                        if ($candidate) { $deviceName = $candidate; break }
                    }
                }
            }
        }
    }

    if (-not $deviceName) {
        return [pscustomobject]@{ Name = $null; Normalized = $null }
    }

    return [pscustomobject]@{
        Name       = $deviceName
        Normalized = Normalize-HostReference $deviceName
    }
}

function Test-IsSelfSource {
    param(
        [string]$Source,
        $DeviceIdentity
    )

    if (-not $Source) { return $false }
    $trimmed = $Source.Trim()
    if (-not $trimmed) { return $false }

    if ($trimmed -match '^(127\.0\.0\.1|0\.0\.0\.0|::1)$') { return $true }

    if (-not $DeviceIdentity) { return $false }
    $normalizedDevice = $DeviceIdentity.Normalized
    if (-not $normalizedDevice) { return $false }

    $sourceNormalized = Normalize-HostReference $trimmed
    if (-not $sourceNormalized) { return $false }

    return ($sourceNormalized -eq $normalizedDevice)
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

    $authArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events-authentication'
    Write-HeuristicDebug -Source 'Events' -Message 'Resolved authentication events artifact' -Data ([ordered]@{
        Found = [bool]$authArtifact
    })

    if ($authArtifact) {
        $authPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $authArtifact)
        Write-HeuristicDebug -Source 'Events' -Message 'Resolved authentication events payload' -Data ([ordered]@{
            HasPayload = [bool]$authPayload
        })

        if ($authPayload) {
            $lockoutEvents = ConvertTo-EventArray $authPayload.LockoutEvents
            $failedEvents = ConvertTo-EventArray $authPayload.FailedLogonEvents

            Write-HeuristicDebug -Source 'Events' -Message 'Authentication events summary' -Data ([ordered]@{
                Lockouts = if ($lockoutEvents) { $lockoutEvents.Count } else { 0 }
                Failures = if ($failedEvents) { $failedEvents.Count } else { 0 }
            })

            if ($lockoutEvents -and $lockoutEvents.Count -gt 0 -and $failedEvents -and $failedEvents.Count -gt 0) {
                $deviceIdentity = Get-DeviceIdentityFromContext -Context $Context
                $failuresByUser = @{}

                foreach ($failure in $failedEvents) {
                    if (-not $failure) { continue }
                    $user = Get-EventPropertyValue -Event $failure -Name 'TargetUserName'
                    if (-not $user) { continue }
                    $userTrimmed = $user.Trim()
                    if (-not $userTrimmed) { continue }

                    $source = Get-EventPropertyValue -Event $failure -Name 'WorkstationName'
                    if (-not $source -or -not $source.Trim()) {
                        $source = Get-EventPropertyValue -Event $failure -Name 'IpAddress'
                    }
                    if (-not $source) { continue }
                    $sourceTrimmed = $source.Trim()
                    if (-not $sourceTrimmed) { continue }
                    if ($sourceTrimmed -eq '-' -or $sourceTrimmed -eq '::' -or $sourceTrimmed -eq '::0') { continue }
                    if ($sourceTrimmed -match '^(::ffff:)?0\.0\.0\.0$') { continue }

                    $time = ConvertTo-EventTime $failure.TimeCreated
                    if (-not $time) { continue }

                    $normalizedSource = Normalize-HostReference $sourceTrimmed
                    $sourceKey = if ($normalizedSource) { $normalizedSource } else { $sourceTrimmed.ToLowerInvariant() }

                    $userKey = $userTrimmed.ToLowerInvariant()
                    if (-not $userKey) { continue }

                    if (-not $failuresByUser.ContainsKey($userKey)) {
                        $failuresByUser[$userKey] = [ordered]@{
                            User    = $userTrimmed
                            Sources = @{}
                        }
                    } elseif (-not $failuresByUser[$userKey].User) {
                        $failuresByUser[$userKey].User = $userTrimmed
                    }

                    $sources = $failuresByUser[$userKey].Sources
                    if (-not $sources.ContainsKey($sourceKey)) {
                        $sources[$sourceKey] = [ordered]@{
                            Source = $sourceTrimmed
                            Events = [System.Collections.Generic.List[object]]::new()
                        }
                    }

                    $sources[$sourceKey].Events.Add([pscustomobject]@{
                        Time       = $time
                        Source     = $sourceTrimmed
                        Normalized = $normalizedSource
                    }) | Out-Null
                }

                foreach ($entry in $failuresByUser.GetEnumerator()) {
                    foreach ($key in @($entry.Value.Sources.Keys)) {
                        $eventsList = $entry.Value.Sources[$key].Events | Sort-Object Time
                        $entry.Value.Sources[$key].Events = @($eventsList)
                        if (-not $entry.Value.Sources[$key].Source -and $entry.Value.Sources[$key].Events.Count -gt 0) {
                            $entry.Value.Sources[$key].Source = $entry.Value.Sources[$key].Events[0].Source
                        }
                    }
                }

                $lockoutsByUser = @{}
                foreach ($lockout in $lockoutEvents) {
                    if (-not $lockout) { continue }
                    $user = Get-EventPropertyValue -Event $lockout -Name 'TargetUserName'
                    if (-not $user) { continue }
                    $userTrimmed = $user.Trim()
                    if (-not $userTrimmed) { continue }

                    $time = ConvertTo-EventTime $lockout.TimeCreated
                    if (-not $time) { continue }

                    $userKey = $userTrimmed.ToLowerInvariant()
                    if (-not $userKey) { continue }

                    if (-not $lockoutsByUser.ContainsKey($userKey)) {
                        $lockoutsByUser[$userKey] = [System.Collections.Generic.List[object]]::new()
                    }

                    $lockoutsByUser[$userKey].Add([pscustomobject]@{
                        Time = $time
                        User = $userTrimmed
                    }) | Out-Null
                }

                foreach ($key in @($lockoutsByUser.Keys)) {
                    $lockoutList = $lockoutsByUser[$key] | Sort-Object Time
                    $lockoutsByUser[$key] = @($lockoutList)
                }

                $processedCombos = @{}
                foreach ($userKey in $lockoutsByUser.Keys) {
                    $lockoutList = $lockoutsByUser[$userKey]
                    if (-not $lockoutList -or $lockoutList.Count -eq 0) { continue }

                    $userName = $lockoutList[0].User
                    if (-not $failuresByUser.ContainsKey($userKey)) { continue }
                    $failureEntry = $failuresByUser[$userKey]

                    foreach ($sourceKey in $failureEntry.Sources.Keys) {
                        $sourceEntry = $failureEntry.Sources[$sourceKey]
                        if (-not $sourceEntry -or -not $sourceEntry.Events) { continue }
                        $failuresList = @($sourceEntry.Events)
                        if ($failuresList.Count -lt 2) { continue }

                        $qualifies = $false
                        foreach ($lockout in $lockoutList) {
                            $priorFailures = $failuresList | Where-Object { $_.Time -lt $lockout.Time }
                            if ($priorFailures.Count -ge 2) { $qualifies = $true; break }
                        }

                        if (-not $qualifies) { continue }

                        $comboKey = ('{0}|{1}' -f $userKey, $sourceKey)
                        if ($processedCombos.ContainsKey($comboKey)) { continue }
                        $processedCombos[$comboKey] = $true

                        $sourceRaw = $sourceEntry.Source
                        if (-not $sourceRaw -and $failuresList.Count -gt 0) { $sourceRaw = $failuresList[0].Source }

                        $combined = @($failuresList + $lockoutList)
                        $firstTime = ($combined | Sort-Object Time | Select-Object -First 1).Time
                        $lastTime = ($combined | Sort-Object Time -Descending | Select-Object -First 1).Time

                        $severity = 'medium'
                        if (Test-IsSelfSource -Source $sourceRaw -DeviceIdentity $deviceIdentity) {
                            $severity = 'low'
                        }

                        $evidence = [ordered]@{
                            userMasked        = Mask-PrincipalValue $userName
                            sourceHostMasked  = Mask-HostValue $sourceRaw
                            lockoutCount      = $lockoutList.Count
                            failedSignInCount = $failuresList.Count
                            firstUtc          = if ($firstTime) { $firstTime.ToUniversalTime().ToString('o') } else { $null }
                            lastUtc           = if ($lastTime) { $lastTime.ToUniversalTime().ToString('o') } else { $null }
                        }

                        Write-HeuristicDebug -Source 'Events' -Message 'Authentication lockout candidate' -Data ([ordered]@{
                            User       = $userName
                            Source     = $sourceRaw
                            Severity   = $severity
                            Failures   = $failuresList.Count
                            Lockouts   = $lockoutList.Count
                            FirstEvent = $evidence.firstUtc
                            LastEvent  = $evidence.lastUtc
                        })

                        Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Repeated account lockouts (possibly from another host/session)' -Evidence ($evidence | ConvertTo-Json -Depth 3 -Compress) -Subcategory 'Authentication'
                    }
                }
            }
        }
    }

    return $result
}
