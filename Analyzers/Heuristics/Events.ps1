<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Get-EventCollectorEntries {
    param($Bucket)

    if (-not $Bucket) { return @() }

    if ($Bucket.PSObject.Properties['Entries']) {
        return @($Bucket.Entries)
    }

    if ($Bucket -is [System.Collections.IEnumerable] -and -not ($Bucket -is [string])) {
        return @($Bucket)
    }

    return @()
}

function Get-EventMessageSnippet {
    param(
        [string]$Message,
        [int]$MaxLength = 220
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $normalized = ($Message -replace '\s+', ' ').Trim()
    if (-not $normalized) { return $null }

    if ($normalized.Length -le $MaxLength) { return $normalized }

    $snippet = $normalized.Substring(0, $MaxLength).TrimEnd()
    return '{0}…' -f $snippet
}

function Get-VpnNameFromEventMessage {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $ignoreCase = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $multiLine = [System.Text.RegularExpressions.RegexOptions]::Multiline

    $patterns = @(
        [regex]::new('connection named\s+["“”]?(?<Name>[^\r\n\.\"]+)', $ignoreCase),
        [regex]::new('Connection Name:\s*(?<Name>.+?)(?:\r?\n|$)', $ignoreCase -bor $multiLine),
        [regex]::new('VPN Connection:\s*(?<Name>.+?)(?:\r?\n|$)', $ignoreCase -bor $multiLine)
    )

    foreach ($pattern in $patterns) {
        $match = $pattern.Match($Message)
        if (-not $match.Success) { continue }

        $value = $match.Groups['Name'].Value
        if (-not $value) { continue }

        $value = $value.Trim()
        $value = $value.Trim([char[]]@('"', [char]0x201C, [char]0x201D))
        $value = $value.TrimEnd('.', ',', ';')
        $value = ($value -replace '\s+(which|that)\b.*$', '').Trim()

        if ($value) { return $value }
    }

    return $null
}

function Get-VpnServerFromEventMessage {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $ignoreCase = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $multiLine = [System.Text.RegularExpressions.RegexOptions]::Multiline

    $patterns = @(
        [regex]::new('Server Address:\s*(?<Server>[^\r\n;]+)', $ignoreCase -bor $multiLine),
        [regex]::new('Server:\s*(?<Server>[^\r\n;]+)', $ignoreCase -bor $multiLine),
        [regex]::new('Remote (?:Server|Address):\s*(?<Server>[^\r\n;]+)', $ignoreCase -bor $multiLine),
        [regex]::new('Peer:\s*(?<Server>[^\s\r\n;]+)', $ignoreCase),
        [regex]::new('for peer (?<Server>[^\s\.;]+)', $ignoreCase)
    )

    foreach ($pattern in $patterns) {
        $match = $pattern.Match($Message)
        if (-not $match.Success) { continue }

        $value = $match.Groups['Server'].Value
        if (-not $value) { continue }

        $value = $value.Trim()
        $value = $value.TrimEnd('.', ',', ';')

        if ($value) { return $value }
    }

    $ipMatch = [regex]::Match($Message, '(?<Server>(?:\d{1,3}\.){3}\d{1,3})')
    if ($ipMatch.Success) {
        $candidate = $ipMatch.Groups['Server'].Value
        if ($candidate) { return $candidate }
    }

    return $null
}

function Invoke-VpnAuthenticationHeuristic {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        $Payload
    )

    if (-not $Payload.PSObject.Properties['Vpn']) {
        Write-HeuristicDebug -Source 'Events/VPN' -Message 'VPN payload missing in events artifact'
        return
    }

    $vpnPayload = $Payload.Vpn

    Write-HeuristicDebug -Source 'Events/VPN' -Message 'Evaluating VPN payload' -Data ([ordered]@{
        HasRasClient     = [bool]($vpnPayload.PSObject.Properties['RasClient'])
        HasIkeOperational = [bool]($vpnPayload.PSObject.Properties['IkeOperational'])
        HasIkeSystem     = [bool]($vpnPayload.PSObject.Properties['IkeSystem'])
    })

    $rasEntries = Get-EventCollectorEntries -Bucket (if ($vpnPayload.PSObject.Properties['RasClient']) { $vpnPayload.RasClient } else { $null })
    $ikeOperationalEntries = Get-EventCollectorEntries -Bucket (if ($vpnPayload.PSObject.Properties['IkeOperational']) { $vpnPayload.IkeOperational } else { $null })
    $ikeSystemEntries = Get-EventCollectorEntries -Bucket (if ($vpnPayload.PSObject.Properties['IkeSystem']) { $vpnPayload.IkeSystem } else { $null })

    $ikeEntries = if ($ikeOperationalEntries.Count -gt 0) { $ikeOperationalEntries } else { $ikeSystemEntries }

    $rasFailures = @($rasEntries | Where-Object { $_ -and $_.Id -eq 20227 -and $_.Message -and $_.Message -match 'no valid certificate' })
    $ikeFailures = @($ikeEntries | Where-Object { $_ -and ($_.Id -eq 4653 -or $_.Id -eq 4654) })

    Write-HeuristicDebug -Source 'Events/VPN' -Message 'VPN event counts' -Data ([ordered]@{
        RasEntries  = $rasEntries.Count
        RasFailures = $rasFailures.Count
        IkeEntries  = $ikeEntries.Count
        IkeFailures = $ikeFailures.Count
    })

    $failures = @($rasFailures + $ikeFailures)
    if (-not $failures -or $failures.Count -eq 0) { return }

    $records = New-Object System.Collections.Generic.List[pscustomobject]
    $grouped = $failures | Group-Object -Property {
        $providerKey = if ($_.ProviderName) { $_.ProviderName } else { 'Unknown' }
        $vpnNameKey = Get-VpnNameFromEventMessage -Message $_.Message
        if (-not $vpnNameKey) { $vpnNameKey = '' }
        $serverKey = Get-VpnServerFromEventMessage -Message $_.Message
        if (-not $serverKey) { $serverKey = '' }
        '{0}|{1}|{2}|{3}' -f $providerKey, $_.Id, $vpnNameKey, $serverKey
    }

    foreach ($group in $grouped) {
        $latest = $group.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
        if (-not $latest) { continue }

        $provider = if ($latest.ProviderName) { $latest.ProviderName } else { 'Unknown' }
        $vpnName = Get-VpnNameFromEventMessage -Message $latest.Message
        $server = Get-VpnServerFromEventMessage -Message $latest.Message
        $snippet = Get-EventMessageSnippet -Message $latest.Message

        $recordData = [ordered]@{
            provider   = $provider
            eventId    = $latest.Id
            msgSnippet = $snippet
        }

        $sortKey = $null
        if ($latest.TimeCreated) {
            try {
                $utc = $latest.TimeCreated.ToUniversalTime()
            } catch {
                $utc = $latest.TimeCreated
            }

            if ($utc) {
                $sortKey = $utc
                $recordData['lastUtc'] = $utc.ToString('o')
            }
        }

        if ($vpnName) { $recordData['vpnName'] = $vpnName }
        if ($server) { $recordData['server'] = $server }

        $records.Add([pscustomobject]@{ SortKey = $sortKey; Data = [pscustomobject]$recordData }) | Out-Null
    }

    if ($records.Count -eq 0) { return }

    $orderedRecords = $records | Sort-Object -Property SortKey -Descending
    $evidenceEntries = @()
    foreach ($record in $orderedRecords) {
        if (-not $record -or -not $record.Data) { continue }
        $evidenceEntries += $record.Data
    }

    if ($evidenceEntries.Count -gt 5) {
        $evidenceEntries = $evidenceEntries[0..4]
    }

    $evidence = [ordered]@{
        Heuristic    = 'VPN authentication/certificate failures.'
        Matches      = $evidenceEntries
        MatchesTotal = $failures.Count
    }

    if ($vpnPayload.PSObject.Properties['WindowDays']) {
        $evidence['WindowDays'] = $vpnPayload.WindowDays
    }

    if ($vpnPayload.PSObject.Properties['WindowStartUtc'] -and $vpnPayload.WindowStartUtc) {
        $evidence['WindowStartUtc'] = [string]$vpnPayload.WindowStartUtc
    }

    Write-HeuristicDebug -Source 'Events/VPN' -Message 'Reporting VPN authentication failure heuristic' -Data ([ordered]@{
        MatchCount     = $failures.Count
        EvidenceEmitted = $evidenceEntries.Count
    })

    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'VPN authentication failing (certificate invalid or IKE SA failure)' -Evidence ([pscustomobject]$evidence) -Subcategory 'VPN / IKE'
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

            Invoke-VpnAuthenticationHeuristic -CategoryResult $result -Payload $payload
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
