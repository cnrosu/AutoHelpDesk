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
