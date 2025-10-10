<#!
.SYNOPSIS
    Helper functions that normalize dsregcmd, time service, and conditional access artifacts for Intune heuristics.
#>

function Get-IntuneDsregText {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if (-not $Context) { return $null }

    $textCandidates = New-Object System.Collections.Generic.List[string]

    try {
        $identityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'identity'
        if ($identityArtifact) {
            $identityPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $identityArtifact)
            if ($identityPayload -and $identityPayload.PSObject.Properties['DsRegCmd']) {
                $raw = $identityPayload.DsRegCmd
                if ($raw) {
                    if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
                        $textCandidates.Add(($raw -join "`n")) | Out-Null
                    } else {
                        $textCandidates.Add([string]$raw) | Out-Null
                    }
                }
            }
        }
    } catch {
        # If parsing fails, fall back to file probes below.
    }

    if (-not $textCandidates -or $textCandidates.Count -eq 0) {
        $candidateNames = @(
            'dsregcmd_status.txt',
            'dsregcmd.txt',
            'dsreg_status.txt',
            'dsreg.txt'
        )

        foreach ($name in $candidateNames) {
            try {
                $path = Join-Path -Path $Context.InputFolder -ChildPath $name
                if (Test-Path -LiteralPath $path) {
                    $textCandidates.Add((Get-Content -LiteralPath $path -Raw -ErrorAction Stop)) | Out-Null
                    break
                }
            } catch {
            }
        }

        if (($textCandidates.Count -eq 0) -and $Context.InputFolder) {
            try {
                $match = Get-ChildItem -Path $Context.InputFolder -Filter 'dsregcmd*.txt' -Recurse -File -ErrorAction Stop | Select-Object -First 1
                if ($match) {
                    $textCandidates.Add((Get-Content -LiteralPath $match.FullName -Raw -ErrorAction Stop)) | Out-Null
                }
            } catch {
            }
        }
    }

    if ($textCandidates.Count -eq 0) { return $null }
    return $textCandidates[0]
}

function Parse-IntuneDsregStatus {
    param([string]$Text)

    $result = [ordered]@{
        AzureAdJoined    = $null
        PrimaryRefreshToken = $null
        WorkplaceJoined  = $null
        TenantName       = $null
        LastErrorCode    = $null
        LastErrorText    = $null
    }

    if (-not $Text) { return [pscustomobject]$result }

    $lines = [regex]::Split($Text, '\r?\n')
    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()

        if ($trimmed -match '^(?i)AzureAdJoined\s*:\s*(?<value>\S.+)$') {
            $result.AzureAdJoined = $matches['value'].Trim()
            continue
        }

        if ($trimmed -match '^(?i)WorkplaceJoined\s*:\s*(?<value>\S.+)$') {
            $result.WorkplaceJoined = $matches['value'].Trim()
            continue
        }

        if ($trimmed -match '^(?i)TenantName\s*:\s*(?<value>.+)$') {
            $result.TenantName = $matches['value'].Trim()
            continue
        }

        if ($trimmed -match '^(?i)PRT\s*:\s*(?<value>\S.+)$') {
            $result.PrimaryRefreshToken = $matches['value'].Trim()
            continue
        }

        if ($trimmed -match '^(?i)(Join\s+)?Error\s+code\s*:\s*(?<value>0x[0-9A-Fa-f]+|[-+]?\d+)') {
            $result.LastErrorCode = $matches['value'].Trim()
            continue
        }

        if ($trimmed -match '^(?i)(Join\s+)?Error\s+Detail\s*:\s*(?<value>.+)$') {
            $result.LastErrorText = $matches['value'].Trim()
            continue
        }

        if (-not $result.LastErrorText -and $trimmed -match '^(?i)Error\s+Detail\s*:\s*(?<value>.+)$') {
            $result.LastErrorText = $matches['value'].Trim()
            continue
        }
    }

    return [pscustomobject]$result
}

function Get-IntuneW32tmStatus {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if (-not $Context) { return $null }

    try {
        $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
        if ($eventsArtifact) {
            $eventsPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
            if ($eventsPayload -and $eventsPayload.PSObject.Properties['Authentication']) {
                $auth = $eventsPayload.Authentication
                if ($auth -and $auth.PSObject.Properties['W32tmStatus']) {
                    return $auth.W32tmStatus
                }
            }
        }
    } catch {
    }

    $candidateNames = @('w32tm-status.txt','time.txt','w32tm.txt')
    foreach ($name in $candidateNames) {
        try {
            $path = Join-Path -Path $Context.InputFolder -ChildPath $name
            if (Test-Path -LiteralPath $path) {
                return (Get-Content -LiteralPath $path -Raw -ErrorAction Stop)
            }
        } catch {
        }
    }

    if ($Context.InputFolder) {
        try {
            $match = Get-ChildItem -Path $Context.InputFolder -Filter 'w32tm*.txt' -Recurse -File -ErrorAction Stop | Select-Object -First 1
            if ($match) {
                return (Get-Content -LiteralPath $match.FullName -Raw -ErrorAction Stop)
            }
        } catch {
        }
    }

    return $null
}

function Parse-IntuneTimeSkew {
    param($Status)

    $result = [ordered]@{
        OffsetSeconds = $null
        Source        = $null
        Raw           = $null
    }

    if (-not $Status) { return [pscustomobject]$result }

    $text = $null

    if ($Status -is [string]) {
        $text = $Status
    } elseif ($Status.PSObject.Properties['Output']) {
        $output = $Status.Output
        if ($output -is [System.Collections.IEnumerable] -and -not ($output -is [string])) {
            $text = ($output -join "`n")
        } elseif ($output) {
            $text = [string]$output
        }
    } elseif ($Status.PSObject.Properties['RawText']) {
        $text = [string]$Status.RawText
    }

    if ($Status.PSObject.Properties['Source'] -and $Status.Source) {
        $result.Source = [string]$Status.Source
    }

    if (-not $text) { return [pscustomobject]$result }
    $result.Raw = $text

    $normalized = $text.Replace('±','')
    $pattern = '(?i)(?:Clock\s*(?:Skew|Offset|Dispersion)|Phase\s*Offset|Offset)\s*[:=]\s*(?<value>[-+]?\d+(?:\.\d+)?)(?<unit>\s*(?:ms|milliseconds|s|seconds)?)'
    $match = [regex]::Match($normalized, $pattern)
    if ($match.Success) {
        $numericValue = [double]$match.Groups['value'].Value
        $unit = $match.Groups['unit'].Value
        if ($unit) { $unit = $unit.Trim().ToLowerInvariant() }
        if ($unit -eq 'ms' -or $unit -eq 'milliseconds') {
            $numericValue = $numericValue / 1000.0
        }
        $result.OffsetSeconds = [int][math]::Round($numericValue)
    }

    return [pscustomobject]$result
}

function Get-IntuneConditionalAccessSummary {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if (-not $Context) { return $null }

    $artifactNames = @('conditional-access','conditionalaccess','ca-evaluation','caevaluation','ca-summary')
    foreach ($name in $artifactNames) {
        try {
            $artifact = Get-AnalyzerArtifact -Context $Context -Name $name
            if (-not $artifact) { continue }
            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
            if (-not $payload) { continue }

            $entries = @()
            if ($payload -is [System.Collections.IEnumerable] -and -not ($payload -is [string])) {
                $entries = @($payload)
            } else {
                $entries = @($payload)
            }

            foreach ($entry in $entries) {
                if (-not $entry) { continue }

                $scenario = $null
                $status = $null
                $policy = $null

                if ($entry.PSObject.Properties['Scenario']) { $scenario = [string]$entry.Scenario }
                if ($entry.PSObject.Properties['Status']) { $status = [string]$entry.Status }
                if ($entry.PSObject.Properties['PolicyName']) { $policy = [string]$entry.PolicyName }

                if (-not $scenario) {
                    if ($entry.PSObject.Properties['Name']) { $scenario = [string]$entry.Name }
                }

                if (-not $status) {
                    if ($entry.PSObject.Properties['Result']) { $status = [string]$entry.Result }
                }

                if ($scenario -and $status) {
                    return [pscustomobject]@{
                        Scenario   = $scenario
                        Status     = $status
                        PolicyName = $policy
                    }
                }
            }
        } catch {
        }
    }

    return $null
}

function Get-IntuneTokenFailureSummary {
    param(
        [Parameter(Mandatory)]
        $Context,

        [datetime]$CutoffUtc = $(Get-Date).ToUniversalTime().AddHours(-2)
    )

    $summary = [ordered]@{
        RecentCount = 0
        LastError   = $null
        LastTimeUtc = $null
    }

    if (-not $Context) { return [pscustomobject]$summary }

    $artifactNames = @('aad-operational','aad_operational','udr-admin','udr_admin','aadtokenfailures','aad-token-failures')
    foreach ($name in $artifactNames) {
        try {
            $artifact = Get-AnalyzerArtifact -Context $Context -Name $name
            if (-not $artifact) { continue }
            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
            if (-not $payload) { continue }

            $events = @()
            if ($payload.PSObject.Properties['Events']) {
                $events = @($payload.Events)
            } elseif ($payload -is [System.Collections.IEnumerable] -and -not ($payload -is [string])) {
                $events = @($payload)
            } else {
                $events = @($payload)
            }

            foreach ($event in $events) {
                if (-not $event) { continue }
                $timeUtc = $null
                if ($event.PSObject.Properties['TimeCreated']) {
                    $value = $event.TimeCreated
                    if ($value) {
                        try {
                            $parsed = ConvertFrom-Iso8601 -Text ([string]$value)
                        } catch {
                            $parsed = $null
                        }
                        if ($parsed) { $timeUtc = $parsed.ToUniversalTime() }
                    }
                }

                if (-not $timeUtc -and $event.PSObject.Properties['TimeCreatedUtc']) {
                    $valueUtc = $event.TimeCreatedUtc
                    if ($valueUtc) {
                        try {
                            $parsedUtc = ConvertFrom-Iso8601 -Text ([string]$valueUtc)
                        } catch {
                            $parsedUtc = $null
                        }
                        if ($parsedUtc) { $timeUtc = $parsedUtc.ToUniversalTime() }
                    }
                }

                if ($timeUtc -and $timeUtc -lt $CutoffUtc) { continue }

                $message = $null
                if ($event.PSObject.Properties['Message']) { $message = [string]$event.Message }
                if (-not $message -and $event.PSObject.Properties['RenderedDescription']) {
                    $message = [string]$event.RenderedDescription
                }

                $summary.RecentCount++
                if ($timeUtc) { $summary.LastTimeUtc = $timeUtc }
                if ($message) { $summary.LastError = $message }
            }

            if ($summary.RecentCount -gt 0) { break }
        } catch {
        }
    }

    return [pscustomobject]$summary
}

function ConvertTo-ImeLogTimestamp {
    param([string]$Text)

    if (-not $Text) { return $null }

    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $formats = @(
        'M/d/yyyy h:mm:ss tt',
        'M/d/yyyy h:mm:ss.fff tt',
        'M/d/yyyy H:mm:ss',
        'M/d/yyyy H:mm:ss.fff',
        'MM/dd/yyyy HH:mm:ss',
        'MM/dd/yyyy HH:mm:ss.fff',
        'dd/MM/yyyy HH:mm:ss',
        'dd/MM/yyyy HH:mm:ss.fff',
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-dd HH:mm:ss.fff',
        'yyyy-MM-ddTHH:mm:ss',
        'yyyy-MM-ddTHH:mm:ss.fff',
        'yyyy-MM-ddTHH:mm:ssK',
        'yyyy-MM-ddTHH:mm:ss.fffK'
    )

    foreach ($format in $formats) {
        try {
            return [datetime]::ParseExact($Text, $format, $culture, $styles)
        } catch {
        }
    }

    try {
        return [datetime]::Parse($Text, $culture, $styles)
    } catch {
    }

    return $null
}

function Get-IntuneImeLogRecords {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $records = [System.Collections.Generic.List[pscustomobject]]::new()

    if (-not $Context -or -not $Context.InputFolder) { return ,@($records.ToArray()) }

    $patterns = @('IntuneManagementExtension*.log*','AgentExecutor*.log*')
    foreach ($pattern in $patterns) {
        try {
            $files = Get-ChildItem -Path $Context.InputFolder -Filter $pattern -File -Recurse -ErrorAction Stop
        } catch {
            $files = @()
        }

        foreach ($file in $files) {
            $lines = @()
            try {
                $lines = Get-Content -LiteralPath $file.FullName -ErrorAction Stop
            } catch {
                continue
            }

            if ($lines.Count -gt 8000) {
                $lines = $lines[($lines.Count - 8000)..($lines.Count - 1)]
            }

            foreach ($line in $lines) {
                if (-not $line) { continue }

                $timestamp = $null
                $timestampPatterns = @(
                    '^(?<timestamp>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)',
                    '^(?<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[\+\-]\d{2}:?\d{2})?)',
                    '^(?<timestamp>\d{1,2}-\d{1,2}-\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)'
                )

                foreach ($patternCandidate in $timestampPatterns) {
                    $match = [regex]::Match($line, $patternCandidate)
                    if (-not $match.Success) { continue }
                    $candidate = $match.Groups['timestamp'].Value
                    $parsed = ConvertTo-ImeLogTimestamp -Text $candidate
                    if ($parsed) {
                        $timestamp = $parsed
                        break
                    }
                }

                $records.Add([pscustomobject]@{
                    Time    = $timestamp
                    Message = [string]$line
                    Source  = $file.Name
                }) | Out-Null
            }
        }
    }

    if ($records.Count -gt 1) {
        $sorted = $records | Sort-Object -Property @{ Expression = 'Time'; Descending = $false }, @{ Expression = 'Source'; Descending = $false }, @{ Expression = 'Message'; Descending = $false }
        return ,@($sorted)
    }

    return ,@($records.ToArray())
}

function Resolve-IntuneImeAppContext {
    param([string]$Line)

    if (-not $Line) { return [pscustomobject]@{ Name = $null; Id = $null } }

    $name = $null
    $id = $null

    $quotedPatterns = @(
        "(?i)app(?:lication)?\s*(?:name|')?\s*[:=]\s*'(?<value>[^']+)'",
        '"(?<value>[^"]+)"'
    )

    foreach ($pattern in $quotedPatterns) {
        $match = [regex]::Match($Line, $pattern)
        if ($match.Success) {
            $name = $match.Groups['value'].Value.Trim()
            break
        }
    }

    if (-not $name) {
        $match = [regex]::Match($Line, "(?i)app(?:lication)?\s*name\s*[:=]\s*(?<value>[A-Za-z0-9\._\-\s]+)")
        if ($match.Success) {
            $name = $match.Groups['value'].Value.Trim(" \t\r\n'\"")
        }
    }

    $guidPattern = '(?i)(?<value>[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})'
    $matchGuid = [regex]::Match($Line, "(?i)app(?:lication)?\s*(?:id|guid)\s*[:=]\s*$guidPattern")
    if ($matchGuid.Success) {
        $id = $matchGuid.Groups['value'].Value.ToLowerInvariant()
    } else {
        $matchGuid = [regex]::Match($Line, $guidPattern)
        if ($matchGuid.Success) {
            $id = $matchGuid.Groups['value'].Value.ToLowerInvariant()
        }
    }

    if ($name) {
        $name = $name.Trim(" \t\r\n'\"")
    }

    return [pscustomobject]@{
        Name = if ($name) { $name } else { $null }
        Id   = if ($id) { $id } else { $null }
    }
}

function Parse-IntuneImeWin32Status {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $records = Get-IntuneImeLogRecords -Context $Context
    $states = @{}
    $unmatchedContent = [System.Collections.Generic.List[string]]::new()

    $getOrCreateState = {
        param($ContextEntry)

        $key = $null
        if ($ContextEntry.Id) {
            $key = 'id:' + $ContextEntry.Id.ToLowerInvariant()
        } elseif ($ContextEntry.Name) {
            $key = 'name:' + $ContextEntry.Name.ToLowerInvariant()
        }

        if (-not $key) { return $null }

        if (-not $states.ContainsKey($key)) {
            $states[$key] = [ordered]@{
                Name            = $ContextEntry.Name
                Id              = $ContextEntry.Id
                FirstTime       = $null
                LastTime        = $null
                ExitCodes       = [System.Collections.Generic.List[pscustomobject]]::new()
                Detections      = [System.Collections.Generic.List[pscustomobject]]::new()
                ContentErrors   = [System.Collections.Generic.List[pscustomobject]]::new()
                TimeoutMentions = 0
            }
        } else {
            if ($ContextEntry.Name -and -not $states[$key].Name) { $states[$key].Name = $ContextEntry.Name }
            if ($ContextEntry.Id -and -not $states[$key].Id) { $states[$key].Id = $ContextEntry.Id }
        }

        return $key
    }

    $lastKey = $null
    foreach ($record in $records) {
        if (-not $record -or -not $record.Message) { continue }

        $contextEntry = Resolve-IntuneImeAppContext -Line $record.Message
        $key = & $getOrCreateState $contextEntry
        if ($key) { $lastKey = $key }

        $targetKey = if ($key) { $key } else { $lastKey }
        if (-not $targetKey -or -not $states.ContainsKey($targetKey)) { continue }

        $state = $states[$targetKey]

        if ($record.Time) {
            if (-not $state.FirstTime -or $record.Time -lt $state.FirstTime) { $state.FirstTime = $record.Time }
            if (-not $state.LastTime -or $record.Time -gt $state.LastTime) { $state.LastTime = $record.Time }
        }

        $line = $record.Message

        $detectionMatch = [regex]::Match($line, '(?i)detection\s*(?:status|result|=)\s*(?<value>true|false)')
        if ($detectionMatch.Success) {
            $value = $detectionMatch.Groups['value'].Value
            $state.Detections.Add([pscustomobject]@{
                Time    = $record.Time
                Value   = if ($value -and $value.Trim().ToLowerInvariant() -eq 'true') { $true } else { $false }
                Message = $line
                Source  = $record.Source
            }) | Out-Null
            continue
        }

        $exitMatch = [regex]::Match($line, '(?i)exit\s*code\s*(?:=|:|is)\s*(?<code>-?\d+)')
        if ($exitMatch.Success) {
            $code = [int]$exitMatch.Groups['code'].Value
            $state.ExitCodes.Add([pscustomobject]@{
                Time    = $record.Time
                Code    = $code
                Message = $line
                Source  = $record.Source
            }) | Out-Null
            continue
        }

        if ($line -match '(?i)(download|content|cdn|proxy).*?(error|fail|timeout|timed out|unavailable|denied|forbidden|tls)') {
            $state.ContentErrors.Add([pscustomobject]@{
                Time    = $record.Time
                Message = $line
                Source  = $record.Source
            }) | Out-Null

            if ($line -match '(?i)timeout|timed out|proxy|tls') {
                $state.TimeoutMentions++
            }
        }
    }

    $imeContentPath = $null
    if ($Context.InputFolder) {
        $imeContentPath = Join-Path -Path $Context.InputFolder -ChildPath 'ime_content.txt'
    }

    if ($imeContentPath -and (Test-Path -LiteralPath $imeContentPath)) {
        try {
            $contentLines = Get-Content -LiteralPath $imeContentPath -ErrorAction Stop
        } catch {
            $contentLines = @()
        }

        foreach ($line in $contentLines) {
            if (-not $line) { continue }
            if ($line -notmatch '(?i)(error|fail|timeout|denied|forbidden|unavailable|cannot|failed)') { continue }

            $contextEntry = Resolve-IntuneImeAppContext -Line $line
            $key = & $getOrCreateState $contextEntry

            if ($key -and $states.ContainsKey($key)) {
                $state = $states[$key]
                $state.ContentErrors.Add([pscustomobject]@{
                    Time    = $null
                    Message = $line
                    Source  = 'ime_content.txt'
                }) | Out-Null

                if ($line -match '(?i)timeout|timed out|proxy|tls') {
                    $state.TimeoutMentions++
                }
            } else {
                $unmatchedContent.Add($line) | Out-Null
            }
        }
    }

    $apps = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $states.GetEnumerator()) {
        $state = $entry.Value

        $first = $state.FirstTime
        $last = $state.LastTime
        $pendingMinutes = $null
        if ($first -and $last -and $last -ge $first) {
            $pendingMinutes = [math]::Round(($last - $first).TotalMinutes, 2)
        }

        $detectionsFalse = @($state.Detections | Where-Object { $_.Value -eq $false })
        $detectionsTrue = @($state.Detections | Where-Object { $_.Value -eq $true })
        $exitZero = @($state.ExitCodes | Where-Object { $_.Code -eq 0 })

        $hasMismatch = $false
        if ($detectionsFalse.Count -gt 0 -and $exitZero.Count -gt 0) {
            $hasMismatch = $true

            $falseAfterExit = $false
            foreach ($falseEvent in $detectionsFalse) {
                if (-not $falseEvent.Time) { $falseAfterExit = $true; break }
                foreach ($exitEvent in $exitZero) {
                    if (-not $exitEvent.Time -or $falseEvent.Time -ge $exitEvent.Time) {
                        $falseAfterExit = $true
                        break
                    }
                }
                if ($falseAfterExit) { break }
            }

            if (-not $falseAfterExit) {
                $hasMismatch = $false
            }
        }

        $apps.Add([pscustomobject]@{
            Name                 = $state.Name
            Id                   = $state.Id
            FirstSeen            = $first
            LastSeen             = $last
            PendingMinutes       = $pendingMinutes
            ExitCodes            = $state.ExitCodes
            Detections           = $state.Detections
            DetectionFalseCount  = $detectionsFalse.Count
            DetectionTrueCount   = $detectionsTrue.Count
            ExitZeroCount        = $exitZero.Count
            HasMismatch          = $hasMismatch
            ContentErrors        = $state.ContentErrors
            TimeoutMentions      = $state.TimeoutMentions
        }) | Out-Null
    }

    return [pscustomobject]@{
        Apps                     = $apps
        HasLogs                  = ($records.Count -gt 0)
        UnattributedContentLines = $unmatchedContent
    }
}
