<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-EventsDateTimeUtc {
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        try {
            return $Value.ToUniversalTime()
        } catch {
            return $Value
        }
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    [datetime]$parsedInvariant = [datetime]::MinValue
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsedInvariant)) {
        return $parsedInvariant.ToUniversalTime()
    }

    [datetime]$parsedDefault = [datetime]::MinValue
    if ([datetime]::TryParse($text, [ref]$parsedDefault)) {
        return $parsedDefault.ToUniversalTime()
    }

    return $null
}

function Get-EventsEventDataValue {
    param(
        [Parameter()]
        $EventData,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $EventData) { return $null }

    if ($EventData -is [System.Collections.IDictionary]) {
        foreach ($key in $EventData.Keys) {
            if ($null -eq $key) { continue }
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $EventData[$key]
            }
        }
    }

    try {
        if ($EventData.PSObject -and $EventData.PSObject.Properties[$Name]) {
            return $EventData.$Name
        }
    } catch {
    }

    return $null
}

function ConvertTo-EventsStatusCode {
    param(
        [Parameter(Mandatory)]
        [string]$Code
    )

    if ([string]::IsNullOrWhiteSpace($Code)) { return $null }
    $trimmed = $Code.Trim()

    if ($trimmed -match '^(?i)0x[0-9a-f]+$') {
        try {
            $uintValue = [System.Convert]::ToUInt32($trimmed.Substring(2), 16)
            $hex = ('0x{0:X}' -f $uintValue)
            return [pscustomobject]@{ UIntValue = [uint32]$uintValue; Hex = $hex }
        } catch {
            return $null
        }
    }

    [int]$intValue = 0
    if ([int]::TryParse($trimmed, [ref]$intValue)) {
        $uintValue = [uint32]$intValue
        $hex = ('0x{0:X}' -f $uintValue)
        return [pscustomobject]@{ UIntValue = $uintValue; Hex = $hex }
    }

    return $null
}

function Get-EventsW32tmMetrics {
    param(
        $Status
    )

    $metrics = [ordered]@{
        OffsetSeconds = $null
        Source        = $null
    }

    if (-not $Status) { return [pscustomobject]$metrics }

    $lines = @()
    if ($Status.PSObject.Properties['Output']) {
        $output = $Status.Output
        if ($output -is [System.Collections.IEnumerable] -and -not ($output -is [string])) {
            $lines = @($output)
        } elseif ($output) {
            $lines = @([string]$output)
        }
    }

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()

        if (-not $metrics.Source -and $trimmed -match '^(?i)Source\s*:\s*(?<value>.+)$') {
            $metrics.Source = $matches['value'].Trim()
        }

        if ($null -eq $metrics.OffsetSeconds -and $trimmed -match '(?i)(?:Phase\s+Offset|Clock\s+Skew|Clock\s+Offset|Offset)\s*:\s*(?<value>[-+]?\d+(?:\.\d+)?)(?<unit>\s*(?:ms|milliseconds|s|seconds)?)') {
            $numericValue = [double]$matches['value']
            $unit = $matches['unit']
            if ($unit) {
                $unit = $unit.Trim().ToLowerInvariant()
            }
            if ($unit -eq 'ms' -or $unit -eq 'milliseconds') {
                $numericValue = $numericValue / 1000.0
            }
            $metrics.OffsetSeconds = [int][math]::Round($numericValue)
        }
    }

    return [pscustomobject]$metrics
}

function Invoke-EventsAuthenticationChecks {
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        $Authentication
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

    $kerberosSummary.Correlated = $correlationDetected

    $w32tmMetrics = Get-EventsW32tmMetrics -Status $w32tmStatus
    $offsetSeconds = $w32tmMetrics.OffsetSeconds
    $kerberosSummary.OffsetSeconds = $offsetSeconds
    $offsetSevere = ($null -ne $offsetSeconds -and [math]::Abs($offsetSeconds) -gt 300)

    $hasEvents = ($kdc18EventsAll.Count -gt 0)
    $issueTriggered = ($hasEvents -and ($trigger24h -or $correlationDetected -or $offsetSevere))

    Write-HeuristicDebug -Source 'Events/Auth' -Message 'Kerberos analysis summary' -Data $kerberosSummary

    if ($issueTriggered) {
        $recentTimesUtc = @($kdc18WithTime | Sort-Object TimeUtc -Descending | Select-Object -First 10 | ForEach-Object { $_.TimeUtc.ToString('o') })
        $uniqueCodes = New-Object System.Collections.Generic.List[string]
        foreach ($evt in $kdc18EventsAll) {
            foreach ($code in $evt.Codes) {
                if ($code -and -not $uniqueCodes.Contains($code)) {
                    $uniqueCodes.Add($code) | Out-Null
                }
            }
        }

        $correlatedIds = @($correlatedEventIds.ToArray() | Sort-Object -Unique)
        $evidenceObject = [ordered]@{
            count          = $kdc18EventsAll.Count
            recentTimesUtc = $recentTimesUtc
            kdcErrorCodes  = $uniqueCodes.ToArray()
            correlation    = [ordered]@{ timeEvents = $correlatedIds }
        }

        if ($null -ne $offsetSeconds) {
            $evidenceObject['timeOffsetSec'] = $offsetSeconds
        }

        $evidenceJson = $evidenceObject | ConvertTo-Json -Depth 4 -Compress

        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Multiple Kerberos pre-auth failures (clock skew suspected)' -Evidence $evidenceJson -Subcategory 'Authentication'
        return
    }

    $kerberosError = $null
    if ($kerberosData -and $kerberosData.PSObject.Properties['Error']) {
        $kerberosError = $kerberosData.Error
    }

    if ($kerberosSummary.PreAuthEvents -eq 0 -and -not $kerberosError -and $w32tmStatus -and $w32tmStatus.Succeeded -and ($null -ne $offsetSeconds) -and ([math]::Abs($offsetSeconds) -le 60)) {
        $evidenceParts = New-Object System.Collections.Generic.List[string]
        $evidenceParts.Add(('Clock offset: {0}s' -f $offsetSeconds)) | Out-Null
        if ($w32tmMetrics.Source) {
            $evidenceParts.Add(('Source: {0}' -f $w32tmMetrics.Source)) | Out-Null
        }

        $evidenceText = $evidenceParts -join '; '
        Add-CategoryNormal -CategoryResult $Result -Title 'Time synchronization healthy — no 4771 pre-auth failures in last 14 days and absolute offset ≤60s.' -Evidence $evidenceText -Subcategory 'Authentication'
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

            if ($payload.PSObject.Properties['Authentication']) {
                Invoke-EventsAuthenticationChecks -Result $result -Authentication $payload.Authentication
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
