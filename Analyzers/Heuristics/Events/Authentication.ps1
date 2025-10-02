function Test-EventsHasAuthenticationFailuresElsewhere {
    param($Authentication)

    if (-not $Authentication) { return $false }

    try {
        if ($Authentication.PSObject.Properties['KerberosPreAuthFailures']) {
            $kerberos = $Authentication.KerberosPreAuthFailures
            if ($kerberos -and -not $kerberos.Error -and $kerberos.PSObject.Properties['Events']) {
                $kerberosEvents = @($kerberos.Events | Where-Object { $_ })
                if ($kerberosEvents.Count -gt 0) { return $true }
            }
        }

        if ($Authentication.PSObject.Properties['AccountLockouts']) {
            $accountData = $Authentication.AccountLockouts
            if ($accountData) {
                foreach ($propertyName in @('Lockouts','FailedLogons','NetworkLogons')) {
                    if (-not $accountData.PSObject.Properties[$propertyName]) { continue }
                    $subData = $accountData.$propertyName
                    if (-not $subData -or $subData.Error) { continue }
                    if (-not $subData.PSObject.Properties['Events']) { continue }
                    $events = @($subData.Events | Where-Object { $_ })
                    if ($events.Count -gt 0) { return $true }
                }
            }
        }
    } catch {
        Write-HeuristicDebug -Source 'Events/Auth' -Message 'Failed to evaluate authentication failure signals' -Data ([ordered]@{ Error = $_.Exception.Message })
    }

    return $false
}

function Invoke-EventsAuthenticationChecks {
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        $Authentication,

        [string]$DeviceName
    )

    Write-HeuristicDebug -Source 'Events/Auth' -Message 'Starting authentication heuristics evaluation'

    if (-not $Authentication) { return }

    $kerberosData = $null
    if ($Authentication.PSObject.Properties['KerberosPreAuthFailures']) {
        $kerberosData = $Authentication.KerberosPreAuthFailures
    }

    $timeServiceData = $null
    if ($Authentication.PSObject.Properties['TimeServiceEvents']) {
        $timeServiceData = $Authentication.TimeServiceEvents
    }

    $w32tmStatus = $null
    if ($Authentication.PSObject.Properties['W32tmStatus']) {
        $w32tmStatus = $Authentication.W32tmStatus
    }

    $kerberosEventsRaw = @()
    if ($kerberosData -and $kerberosData.PSObject.Properties['Events']) {
        $kerberosEventsRaw = @($kerberosData.Events)
    }

    $parsedKerberos = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($event in $kerberosEventsRaw) {
        if (-not $event) { continue }

        $timeUtc = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $timeUtc = ConvertTo-EventsDateTimeUtc -Value $event.TimeCreated
        }

        $eventData = $null
        if ($event.PSObject.Properties['EventData']) {
            $eventData = $event.EventData
        }

        $message = if ($event.PSObject.Properties['Message']) { [string]$event.Message } else { $null }

        $statusCandidates = New-Object System.Collections.Generic.List[string]
        foreach ($field in @('Status','FailureCode','ErrorCode')) {
            $value = Get-EventsEventDataValue -EventData $eventData -Name $field
            if ($value) {
                $statusCandidates.Add([string]$value) | Out-Null
            }
        }

        if ($message) {
            $patterns = @(
                '(?i)Failure\s+Code\s*:\s*(?<code>0x[0-9a-f]+|[-+]?\d+)',
                '(?i)Status\s*:\s*(?<code>0x[0-9a-f]+|[-+]?\d+)',
                '0x[0-9A-Fa-f]+'
            )

            foreach ($pattern in $patterns) {
                $matches = [regex]::Matches($message, $pattern)
                foreach ($match in $matches) {
                    if ($match.Groups['code'] -and $match.Groups['code'].Success) {
                        $statusCandidates.Add($match.Groups['code'].Value) | Out-Null
                    } elseif ($match.Value) {
                        $statusCandidates.Add($match.Value) | Out-Null
                    }
                }
            }
        }

        $codeSet = New-Object System.Collections.Generic.List[string]
        $hasKdc18 = $false
        foreach ($candidate in $statusCandidates) {
            $parsedCode = ConvertTo-EventsStatusCode -Code $candidate
            if (-not $parsedCode) { continue }
            $hex = $parsedCode.Hex.ToUpperInvariant()
            if (-not $codeSet.Contains($hex)) { $codeSet.Add($hex) | Out-Null }
            if ($parsedCode.UIntValue -eq 0x18) {
                $hasKdc18 = $true
            }
        }

        $isPreAuth = $true
        if ($message -and -not ($message -match '(?i)pre-?authentication failed')) {
            $isPreAuth = $false
        }

        $parsedKerberos.Add([pscustomobject]@{
            TimeUtc        = $timeUtc
            Codes          = $codeSet.ToArray()
            HasKdcError18  = $hasKdc18
            IsPreAuthEvent = $isPreAuth
        }) | Out-Null
    }

    $kerberosSummary = [ordered]@{
        TotalEvents     = $parsedKerberos.Count
        PreAuthEvents   = 0
        Kdc18Events     = 0
        Recent24h       = 0
        Correlated      = $false
        OffsetSeconds   = $null
    }

    $kdc18EventsAll = @($parsedKerberos | Where-Object { $_.HasKdcError18 -and $_.IsPreAuthEvent })
    $kerberosSummary.PreAuthEvents = ($parsedKerberos | Where-Object { $_.IsPreAuthEvent }).Count
    $kerberosSummary.Kdc18Events = $kdc18EventsAll.Count

    $kdc18WithTime = @($kdc18EventsAll | Where-Object { $_.TimeUtc })

    $nowUtc = (Get-Date).ToUniversalTime()
    $recent24h = @($kdc18WithTime | Where-Object { $_.TimeUtc -ge $nowUtc.AddHours(-24) })
    $kerberosSummary.Recent24h = $recent24h.Count
    $trigger24h = ($recent24h.Count -ge 3)

    $timeEventsRaw = @()
    if ($timeServiceData -and $timeServiceData.PSObject.Properties['Events']) {
        $timeEventsRaw = @($timeServiceData.Events)
    }

    $timeEvents = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($event in $timeEventsRaw) {
        if (-not $event) { continue }
        $timeUtc = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $timeUtc = ConvertTo-EventsDateTimeUtc -Value $event.TimeCreated
        }
        $id = $null
        if ($event.PSObject.Properties['Id']) {
            try { $id = [int]$event.Id } catch { $id = $event.Id }
        }
        $timeEvents.Add([pscustomobject]@{ TimeUtc = $timeUtc; Id = $id }) | Out-Null
    }

    $correlatedEventIds = New-Object System.Collections.Generic.List[int]
    $correlationDetected = $false

    foreach ($timeEvent in $timeEvents) {
        if (-not $timeEvent.TimeUtc) { continue }
        if ($timeEvent.Id -notin 36, 47, 50) { continue }
        $windowStart = $timeEvent.TimeUtc.AddMinutes(-30)
        $windowEnd = $timeEvent.TimeUtc.AddMinutes(30)
        $matches = @($kdc18WithTime | Where-Object { $_.TimeUtc -ge $windowStart -and $_.TimeUtc -le $windowEnd })
        if ($matches.Count -ge 2) {
            $correlationDetected = $true
            if (-not $correlatedEventIds.Contains([int]$timeEvent.Id)) {
                $correlatedEventIds.Add([int]$timeEvent.Id) | Out-Null
            }
        }
    }

    if ($correlationDetected) {
        $kerberosSummary.Correlated = $true
        if ($w32tmStatus) {
            $metrics = Get-EventsW32tmMetrics -Status $w32tmStatus
            if ($metrics.OffsetSeconds -ne $null) {
                $kerberosSummary.OffsetSeconds = $metrics.OffsetSeconds
            }
            if ($metrics.Source) {
                $kerberosSummary['TimeSource'] = $metrics.Source
            }
        }
    }

    if ($trigger24h -or $correlationDetected) {
        $evidence = [ordered]@{
            totalPreAuthFailures = $kerberosSummary.PreAuthEvents
            kdc18PreAuthFailures = $kerberosSummary.Kdc18Events
            recent24hFailures    = $kerberosSummary.Recent24h
            correlatedTimeEvents = $correlatedEventIds.ToArray()
        }

        if ($kerberosSummary.OffsetSeconds -ne $null) {
            $evidence['clockSkewSeconds'] = $kerberosSummary.OffsetSeconds
        }
        if ($kerberosSummary.ContainsKey('TimeSource')) {
            $evidence['timeSource'] = $kerberosSummary.TimeSource
        }

        $severity = if ($correlationDetected) { 'high' } else { 'medium' }
        $title = 'Kerberos pre-authentication failures detected, possibly due to clock skew.'
        Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Authentication'
    }

    $accountData = $null
    if ($Authentication.PSObject.Properties['AccountLockouts']) {
        $accountData = $Authentication.AccountLockouts
    }
    if (-not $accountData) { return }

    $lockoutData = $null
    if ($accountData.PSObject.Properties['Lockouts']) {
        $lockoutData = $accountData.Lockouts
    }
    $failedLogons = $null
    if ($accountData.PSObject.Properties['FailedLogons']) {
        $failedLogons = $accountData.FailedLogons
    }

    if (-not $lockoutData -or -not $failedLogons) { return }
    if (-not $lockoutData.PSObject.Properties['Events'] -or -not $failedLogons.PSObject.Properties['Events']) { return }

    $lockoutEvents = ConvertTo-EventsArray -Value $lockoutData.Events
    $failedEvents = ConvertTo-EventsArray -Value $failedLogons.Events

    $lockoutRecords = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($event in $lockoutEvents) {
        if (-not $event) { continue }

        $timeUtc = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $timeUtc = ConvertTo-EventsDateTimeUtc -Value $event.TimeCreated
        }

        $user = $null
        foreach ($field in @('TargetUserName','AccountName','User')) {
            $value = Get-EventsEventDataValue -EventData $event.EventData -Name $field
            if ($value) {
                $user = [string]$value
                break
            }
        }

        $normalizedUser = Normalize-EventsUserName -UserName $user

        $lockoutRecords.Add([pscustomobject]@{
            TimeUtc        = $timeUtc
            User           = $user
            UserNormalized = $normalizedUser
        }) | Out-Null
    }

    $failedRecords = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($event in $failedEvents) {
        if (-not $event) { continue }

        $userValue = $null
        foreach ($field in @('TargetUserName','TargetUser','AccountName','User','SubjectUserName')) {
            $value = Get-EventsEventDataValue -EventData $event.EventData -Name $field
            if ($value) {
                $userValue = [string]$value
                break
            }
        }
        $normalizedUser = Normalize-EventsUserName -UserName $userValue

        $sourceType = $null
        $sourceLabel = $null
        $sourceNormalized = $null

        foreach ($field in @('IpAddress','WorkstationName','ClientAddress','ClientName','SourceHost')) {
            $value = Get-EventsEventDataValue -EventData $event.EventData -Name $field
            if ($value) {
                $sourceLabel = [string]$value
                break
            }
        }

        if ($event.PSObject.Properties['Message'] -and -not $sourceLabel) {
            $message = [string]$event.Message
            if ($message -match '(?i)Client\s+Address\s*:\s*(?<addr>[^\s]+)') {
                $sourceLabel = $matches['addr']
            }
        }

        if ($sourceLabel) {
            $sourceLabel = $sourceLabel.Trim()
            if ($sourceLabel -match '^(?<ip>(?:\d{1,3}\.){3}\d{1,3})$') {
                $sourceType = 'IP'
                $sourceNormalized = $matches['ip']
            } elseif ($sourceLabel -match '^(?<host>[^\\\s]+)$') {
                $sourceType = 'Workstation'
                $sourceNormalized = Normalize-EventsHostName -HostName $matches['host']
                $sourceLabel = $matches['host']
            }
        }

        if (-not $sourceType -and $event.PSObject.Properties['IpAddress']) {
            $ipAddress = $event.IpAddress
            if ($ipAddress) {
                $sourceType = 'IP'
                $sourceLabel = ([string]$ipAddress).Trim()
                $sourceNormalized = $sourceLabel
                if ($sourceNormalized) {
                    $sourceNormalized = $sourceNormalized.ToLowerInvariant()
                }
            }
        }

        if (-not $sourceNormalized) { continue }

        $timeUtc = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $timeUtc = ConvertTo-EventsDateTimeUtc -Value $event.TimeCreated
        }

        $failedRecords.Add([pscustomobject]@{
            TimeUtc          = $timeUtc
            User             = $userValue
            UserNormalized   = $normalizedUser
            SourceType       = $sourceType
            SourceLabel      = $sourceLabel
            SourceNormalized = $sourceNormalized
            SourceKey        = ('{0}|{1}' -f $sourceType, $sourceNormalized)
        }) | Out-Null
    }

    if ($lockoutRecords.Count -eq 0 -or $failedRecords.Count -eq 0) { return }

    $localNormalized = $null
    if ($DeviceName) {
        $localNormalized = Normalize-EventsHostName -HostName $DeviceName
    }

    $userGroups = @($lockoutRecords | Where-Object { $_.UserNormalized }) | Group-Object -Property UserNormalized

    foreach ($userGroup in $userGroups) {
        if (-not $userGroup.Name) { continue }
        $userKey = $userGroup.Name
        $userLockouts = @($userGroup.Group | Sort-Object TimeUtc)
        if ($userLockouts.Count -eq 0) { continue }

        $userFailed = @($failedRecords | Where-Object { $_.UserNormalized -eq $userKey })
        if ($userFailed.Count -lt 2) { continue }

        $sourceGroups = $userFailed | Group-Object -Property SourceKey
        foreach ($sourceGroup in $sourceGroups) {
            if (-not $sourceGroup.Name) { continue }
            $sourceEvents = @($sourceGroup.Group | Where-Object { $_.SourceKey } | Sort-Object TimeUtc)
            if ($sourceEvents.Count -lt 2) { continue }

            $matchingLockouts = New-Object System.Collections.Generic.List[object]
            foreach ($lockout in $userLockouts) {
                if (-not $lockout.TimeUtc) { continue }
                $priorEvents = @($sourceEvents | Where-Object { $_.TimeUtc -and $_.TimeUtc -le $lockout.TimeUtc })
                if ($priorEvents.Count -ge 2) {
                    $matchingLockouts.Add($lockout) | Out-Null
                }
            }

            if ($matchingLockouts.Count -eq 0) { continue }

            $sourceSample = $sourceEvents[0]
            $sourceLabel = $sourceSample.SourceLabel
            $sourceType = $sourceSample.SourceType
            $sourceNormalized = $sourceSample.SourceNormalized

            $severity = 'medium'
            if ($sourceType -eq 'Workstation' -and $localNormalized -and $sourceNormalized -and ([string]::Equals($sourceNormalized, $localNormalized, [System.StringComparison]::OrdinalIgnoreCase))) {
                $severity = 'low'
            }

            $timeAccumulator = New-Object System.Collections.Generic.List[datetime]
            foreach ($evt in $sourceEvents) {
                if ($evt.TimeUtc) { $timeAccumulator.Add($evt.TimeUtc) | Out-Null }
            }
            foreach ($lockout in $matchingLockouts) {
                if ($lockout.TimeUtc) { $timeAccumulator.Add($lockout.TimeUtc) | Out-Null }
            }

            $firstUtc = $null
            $lastUtc = $null
            if ($timeAccumulator.Count -gt 0) {
                $orderedTimes = $timeAccumulator.ToArray() | Sort-Object
                $firstUtc = $orderedTimes[0]
                $lastUtc = $orderedTimes[$orderedTimes.Length - 1]
            }

            $userMasked = ConvertTo-EventsMaskedUser -Value ($matchingLockouts[0].User)
            $hostMasked = ConvertTo-EventsMaskedHost -Value $sourceLabel

            $firstUtcString = if ($firstUtc) { $firstUtc.ToString('o') } else { $null }
            $lastUtcString = if ($lastUtc) { $lastUtc.ToString('o') } else { $null }

            $evidence = [ordered]@{
                userMasked        = $userMasked
                sourceHostMasked  = $hostMasked
                lockoutCount      = $matchingLockouts.Count
                failedSignInCount = $sourceEvents.Count
                firstUtc          = $firstUtcString
                lastUtc           = $lastUtcString
            }

            $evidenceJson = $evidence | ConvertTo-Json -Depth 4 -Compress

            Write-HeuristicDebug -Source 'Events/Auth' -Message 'Account lockout pattern detected' -Data ([ordered]@{
                UserKey      = $userKey
                SourceKey    = $sourceGroup.Name
                Severity     = $severity
                Lockouts     = $matchingLockouts.Count
                Failures     = $sourceEvents.Count
                FirstUtc     = $firstUtcString
                LastUtc      = $lastUtcString
            })

            Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'Repeated account lockouts (possibly from another host/session)' -Evidence $evidenceJson -Subcategory 'Authentication'
        }
    }
}
