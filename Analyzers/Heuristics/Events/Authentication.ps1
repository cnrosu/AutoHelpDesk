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

    $failureGroups = @()
    $topAccounts = @()
    $topSources = @()
    $WindowMinutes = $null

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
        $severity = if ($correlationDetected) { 'high' } else { 'medium' }
        $title = 'Kerberos pre-authentication failures detected, possibly due to clock skew.'
        $kerberosWindowMinutes = 14 * 24 * 60
        $windowDays = [math]::Round($kerberosWindowMinutes / (24 * 60), 2)
        $uniqueCorrelatedIds = @($correlatedEventIds | Sort-Object -Unique)
        $correlatedText = if ($uniqueCorrelatedIds.Count -gt 0) {
            [string]::Join(', ', $uniqueCorrelatedIds)
        } else {
            'none'
        }

        $evidenceLines = New-Object System.Collections.Generic.List[string]
        $evidenceLines.Add(("Observation window: {0} minutes (~{1:N2} days)." -f $kerberosWindowMinutes, $windowDays)) | Out-Null
        $evidenceLines.Add(("Kerberos pre-auth failures: {0} total events, {1} with KDC 0x18 (recent 24h: {2})." -f $kerberosSummary.PreAuthEvents, $kerberosSummary.Kdc18Events, $kerberosSummary.Recent24h)) | Out-Null

        if ($kerberosSummary.OffsetSeconds -ne $null) {
            $evidenceLines.Add(("Observed clock skew offset: {0} seconds." -f $kerberosSummary.OffsetSeconds)) | Out-Null
        }
        if ($kerberosSummary.ContainsKey('TimeSource') -and $kerberosSummary.TimeSource) {
            $evidenceLines.Add(("Time source reported by w32tm: {0}." -f $kerberosSummary.TimeSource)) | Out-Null
        }

        $evidenceLines.Add(("Correlated time service event IDs: {0}." -f $correlatedText)) | Out-Null

        $summaryJson = $kerberosSummary | ConvertTo-Json -Depth 4 -Compress
        if ($summaryJson) {
            $evidenceLines.Add("Summary JSON: $summaryJson") | Out-Null
        }

        $evidence = [string]::Join("`n", $evidenceLines)

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

    if (-not $WindowMinutes) {
        $windowDays = $null
        if ($accountData -and $accountData.PSObject.Properties['WindowDays'] -and $accountData.WindowDays) {
            try { $windowDays = [int]$accountData.WindowDays } catch { $windowDays = $null }
        }

        if ($windowDays -and $windowDays -gt 0) {
            $WindowMinutes = [int]($windowDays * 24 * 60)
        } elseif ($failedLogons -and $failedLogons.PSObject.Properties['StartTime'] -and $failedLogons.StartTime) {
            $startTime = ConvertTo-EventsDateTimeUtc -Value $failedLogons.StartTime
            if ($startTime) {
                $WindowMinutes = [int][math]::Round(((Get-Date).ToUniversalTime() - $startTime).TotalMinutes)
            }
        }
    }

    if (-not $WindowMinutes) {
        $WindowMinutes = 7 * 24 * 60
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

        $eventData = $null
        if ($event.PSObject.Properties['EventData']) {
            $eventData = $event.EventData
        }

        $eventId = $null
        if ($event.PSObject.Properties['Id']) {
            try { $eventId = [int]$event.Id } catch { $eventId = $event.Id }
        }

        $userValue = $null
        foreach ($field in @('TargetUserName','TargetUser','AccountName','User','SubjectUserName')) {
            $value = Get-EventsEventDataValue -EventData $eventData -Name $field
            if ($value) {
                $userValue = [string]$value
                break
            }
        }
        $normalizedUser = Normalize-EventsUserName -UserName $userValue

        $logonType = $null
        $logonValue = Get-EventsEventDataValue -EventData $eventData -Name 'LogonType'
        if ($logonValue) { $logonType = [string]$logonValue }

        $sourceType = $null
        $sourceLabel = $null
        $sourceNormalized = $null

        foreach ($field in @('IpAddress','WorkstationName','ClientAddress','ClientName','SourceHost')) {
            $value = Get-EventsEventDataValue -EventData $eventData -Name $field
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
            EventId          = $eventId
            SourceType       = $sourceType
            SourceLabel      = $sourceLabel
            SourceNormalized = $sourceNormalized
            SourceKey        = ('{0}|{1}' -f $sourceType, $sourceNormalized)
            LogonType        = $logonType
        }) | Out-Null
    }

    if ($failedRecords.Count -gt 0) {
        $groupMap = @{}
        foreach ($record in $failedRecords) {
            $groupKey = if ($null -ne $record.EventId) { [string]$record.EventId } else { 'unknown' }
            if (-not $groupMap.ContainsKey($groupKey)) {
                $groupMap[$groupKey] = [ordered]@{
                    Id      = $record.EventId
                    Count   = 0
                    Samples = @()
                }
            }

            $bucket = $groupMap[$groupKey]
            if ($null -eq $bucket['Id'] -and $null -ne $record.EventId) { $bucket['Id'] = $record.EventId }
            $bucket['Count'] = [int]$bucket['Count'] + 1
            if ($bucket['Samples'].Count -lt 5) {
                $bucket['Samples'] += ,([pscustomobject]@{
                    TimeCreated   = if ($record.TimeUtc) { $record.TimeUtc.ToString('o') } else { $null }
                    Account       = $record.User
                    AccountMasked = ConvertTo-EventsMaskedUser -Value $record.User
                    Source        = $record.SourceLabel
                    SourceMasked  = ConvertTo-EventsMaskedHost -Value $record.SourceLabel
                    LogonType     = $record.LogonType
                })
            }
            $groupMap[$groupKey] = $bucket
        }

        $failureGroups = foreach ($entry in (@($groupMap.GetEnumerator()) | Sort-Object -Property @{ Expression = { $_.Value.Count }; Descending = $true })) {
            [pscustomobject]@{
                Id           = $entry.Value.Id
                Count        = [int]$entry.Value.Count
                SampleEvents = @($entry.Value.Samples)
            }
        }

        $accountMap = @{}
        foreach ($record in $failedRecords) {
            $accountKey = if ($record.UserNormalized) { $record.UserNormalized } else { 'unknown' }
            if (-not $accountMap.ContainsKey($accountKey)) {
                $accountMap[$accountKey] = [ordered]@{
                    Account = $record.User
                    Masked  = ConvertTo-EventsMaskedUser -Value $record.User
                    Count   = 0
                }
            }

            $accountEntry = $accountMap[$accountKey]
            if (-not $accountEntry['Account'] -and $record.User) { $accountEntry['Account'] = $record.User }
            if (-not $accountEntry['Masked'] -and $record.User) { $accountEntry['Masked'] = ConvertTo-EventsMaskedUser -Value $record.User }
            $accountEntry['Count'] = [int]$accountEntry['Count'] + 1
            $accountMap[$accountKey] = $accountEntry
        }

        $topAccounts = foreach ($entry in (@($accountMap.GetEnumerator()) | Sort-Object -Property @{ Expression = { $_.Value.Count }; Descending = $true } | Select-Object -First 5)) {
            [pscustomobject]@{
                Account       = $entry.Value.Account
                AccountMasked = $entry.Value.Masked
                Count         = [int]$entry.Value.Count
            }
        }

        $sourceMap = @{}
        foreach ($record in $failedRecords) {
            $sourceKey = if ($record.SourceKey) { $record.SourceKey } else { 'unknown' }
            if (-not $sourceMap.ContainsKey($sourceKey)) {
                $sourceMap[$sourceKey] = [ordered]@{
                    Source = $record.SourceLabel
                    Masked = ConvertTo-EventsMaskedHost -Value $record.SourceLabel
                    Count  = 0
                }
            }

            $sourceEntry = $sourceMap[$sourceKey]
            if (-not $sourceEntry['Source'] -and $record.SourceLabel) { $sourceEntry['Source'] = $record.SourceLabel }
            if (-not $sourceEntry['Masked'] -and $record.SourceLabel) { $sourceEntry['Masked'] = ConvertTo-EventsMaskedHost -Value $record.SourceLabel }
            $sourceEntry['Count'] = [int]$sourceEntry['Count'] + 1
            $sourceMap[$sourceKey] = $sourceEntry
        }

        $topSources = foreach ($entry in (@($sourceMap.GetEnumerator()) | Sort-Object -Property @{ Expression = { $_.Value.Count }; Descending = $true } | Select-Object -First 5)) {
            [pscustomobject]@{
                Source       = $entry.Value.Source
                SourceMasked = $entry.Value.Masked
                Count        = [int]$entry.Value.Count
            }
        }
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

            $windowDays = [math]::Round($WindowMinutes / (24 * 60), 2)
            $evidenceLines = New-Object System.Collections.Generic.List[string]
            $evidenceLines.Add(("Observation window: {0} minutes (~{1:N2} days)." -f $WindowMinutes, $windowDays)) | Out-Null
            $evidenceLines.Add(("Account {0} was locked out {1} time(s) following {2} failed sign-in(s) from {3}." -f $userMasked, $matchingLockouts.Count, $sourceEvents.Count, $hostMasked)) | Out-Null

            if ($firstUtcString) {
                $evidenceLines.Add("First observed UTC: $firstUtcString.") | Out-Null
            }
            if ($lastUtcString) {
                $evidenceLines.Add("Most recent UTC: $lastUtcString.") | Out-Null
            }

            if ($failureGroups.Count -gt 0) {
                $groupSummary = @($failureGroups | Select-Object -First 3 | ForEach-Object {
                        $label = if ($_.Id) { "Event $($_.Id)" } else { 'Unknown event' }
                        "${label}: $($_.Count) failure(s)"
                    })
                if ($groupSummary.Count -gt 0) {
                    $evidenceLines.Add("Bucketed failure summary: $([string]::Join('; ', $groupSummary)).") | Out-Null
                }
            }

            if ($topAccounts.Count -gt 0) {
                $accountSummary = @($topAccounts | Select-Object -First 3 | ForEach-Object {
                        $name = if ($_.AccountMasked) { $_.AccountMasked } elseif ($_.Account) { $_.Account } else { 'unknown' }
                        "$name ($($_.Count))"
                    })
                if ($accountSummary.Count -gt 0) {
                    $evidenceLines.Add("Top accounts by failure volume: $([string]::Join('; ', $accountSummary)).") | Out-Null
                }
            }

            if ($topSources.Count -gt 0) {
                $sourceSummary = @($topSources | Select-Object -First 3 | ForEach-Object {
                        $name = if ($_.SourceMasked) { $_.SourceMasked } elseif ($_.Source) { $_.Source } else { 'unknown source' }
                        "$name ($($_.Count))"
                    })
                if ($sourceSummary.Count -gt 0) {
                    $evidenceLines.Add("Top failure sources: $([string]::Join('; ', $sourceSummary)).") | Out-Null
                }
            }

            $supportPayload = [ordered]@{}
            if ($failureGroups.Count -gt 0) { $supportPayload['FailureGroups'] = $failureGroups }
            if ($topAccounts.Count -gt 0) { $supportPayload['TopAccounts'] = $topAccounts }
            if ($topSources.Count -gt 0) { $supportPayload['TopSources'] = $topSources }

            if ($supportPayload.Count -gt 0) {
                $supportJson = $supportPayload | ConvertTo-Json -Depth 4 -Compress
                if ($supportJson) {
                    $evidenceLines.Add("Supporting data JSON: $supportJson") | Out-Null
                }
            }

            $evidenceText = [string]::Join("`n", $evidenceLines)

            Write-HeuristicDebug -Source 'Events/Auth' -Message 'Account lockout pattern detected' -Data ([ordered]@{
                UserKey      = $userKey
                SourceKey    = $sourceGroup.Name
                Severity     = $severity
                Lockouts     = $matchingLockouts.Count
                Failures     = $sourceEvents.Count
                FirstUtc     = $firstUtcString
                LastUtc      = $lastUtcString
            })

            Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'Repeated account lockouts (possibly from another host/session)' -Evidence $evidenceText -Subcategory 'Authentication'
        }
    }
}
