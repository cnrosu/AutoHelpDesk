<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-EventArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string]) -and -not ($Value -is [hashtable])) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -ne $item) { $items += $item }
        }
        return $items
    }

    return @($Value)
}

function ConvertTo-TrimmedStringArray {
    param($Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [string]) {
        $trimmed = $Value.Trim()
        if ($trimmed) { return @($trimmed) }
        return @()
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $results = @()
        foreach ($item in $Value) {
            $results += ConvertTo-TrimmedStringArray $item
        }
        return $results | Where-Object { $_ -and $_.Trim() }
    }

    $text = [string]$Value
    if ($text) {
        $trimmed = $text.Trim()
        if ($trimmed) { return @($trimmed) }
    }

    return @()
}

function Resolve-EventDateTime {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        try { return $Value.ToUniversalTime() } catch { return $Value }
    }

    $text = [string]$Value
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        $parsed = $null
        if ([datetime]::TryParse($text, [ref]$parsed)) {
            try { return $parsed.ToUniversalTime() } catch { return $parsed }
        }
    }

    return $null
}

function Resolve-VpnBaselineState {
    param($Context)

    $artifactNames = @('vpn-baseline', 'vpn', 'network-baseline')
    foreach ($name in $artifactNames) {
        $artifact = Get-AnalyzerArtifact -Context $Context -Name $name
        if (-not $artifact) { continue }

        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
        if (-not $payload) { continue }

        $candidates = ConvertTo-EventArray $payload
        if ($payload.PSObject -and $payload.PSObject.Properties['Vpn']) {
            $candidates += ConvertTo-EventArray $payload.Vpn
        }
        if ($payload.PSObject -and $payload.PSObject.Properties['Baseline']) {
            $candidates += ConvertTo-EventArray $payload.Baseline
        }

        foreach ($candidate in $candidates) {
            if (-not $candidate) { continue }

            $propertyTable = @{}
            if ($candidate -is [hashtable]) {
                foreach ($key in $candidate.Keys) {
                    if ($null -eq $key) { continue }
                    $propertyTable[$key.ToString()] = $candidate[$key]
                }
            } elseif ($candidate.PSObject) {
                foreach ($prop in $candidate.PSObject.Properties) {
                    if (-not $prop) { continue }
                    $propertyTable[$prop.Name] = $prop.Value
                }
            }

            if ($propertyTable.Count -eq 0) { continue }

            $connectedValue = $null
            foreach ($key in @('Connected','IsConnected','Status')) {
                if ($propertyTable.ContainsKey($key)) {
                    $connectedValue = $propertyTable[$key]
                    break
                }
            }

            $corpServers = @()
            foreach ($key in @('CorporateDnsServers','CorporateDns','ExpectedDnsServers','DnsServers','Servers')) {
                if ($propertyTable.ContainsKey($key)) {
                    $corpServers = ConvertTo-TrimmedStringArray $propertyTable[$key]
                    if ($corpServers.Count -gt 0) { break }
                }
            }

            $connectedBool = $null
            if ($connectedValue -is [bool]) {
                $connectedBool = [bool]$connectedValue
            } elseif ($connectedValue -is [string]) {
                $normalized = $connectedValue.Trim().ToLowerInvariant()
                if ($normalized -in @('true','yes','connected','online','up')) { $connectedBool = $true }
                elseif ($normalized -in @('false','no','disconnected','offline','down')) { $connectedBool = $false }
            }

            if ($connectedBool -ne $null -or ($corpServers -and $corpServers.Count -gt 0)) {
                return [pscustomobject]@{
                    Connected           = $connectedBool
                    CorporateDnsServers = $corpServers
                }
            }
        }
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
            $vpnBaseline = $null
            $vpnBaselineChecked = $false

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

            if ($payload.PSObject.Properties['DnsClientOperational']) {
                $dnsEntriesRaw = $payload.DnsClientOperational
                $dnsError = $null
                if ($dnsEntriesRaw -and $dnsEntriesRaw.PSObject -and $dnsEntriesRaw.PSObject.Properties['Error']) {
                    $dnsError = $dnsEntriesRaw.Error
                }

                if ($dnsError) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to read Microsoft-Windows-DNS-Client/Operational log, so DNS resolution issues may be hidden.' -Evidence $dnsError -Subcategory 'DNS Client Events'
                } else {
                    $dnsEntries = ConvertTo-EventArray $dnsEntriesRaw
                    $nowUtc = (Get-Date).ToUniversalTime()
                    $cutoffUtc = $nowUtc.AddHours(-24)
                    $recentEvents = @()

                    foreach ($entry in $dnsEntries) {
                        if (-not $entry) { continue }
                        if ($entry.PSObject -and $entry.PSObject.Properties['Error'] -and $entry.Error) { continue }

                        $timeUtc = $null
                        if ($entry.PSObject -and $entry.PSObject.Properties['TimeCreated']) {
                            $timeUtc = Resolve-EventDateTime $entry.TimeCreated
                        } elseif ($entry.PSObject -and $entry.PSObject.Properties['Time']) {
                            $timeUtc = Resolve-EventDateTime $entry.Time
                        }

                        if (-not $timeUtc) { continue }
                        if ($timeUtc -lt $cutoffUtc -or $timeUtc -gt $nowUtc) { continue }

                        $name = $null
                        if ($entry.PSObject) {
                            foreach ($nameProperty in @('QueryName','Name','MessageSnippet')) {
                                if ($entry.PSObject.Properties[$nameProperty] -and $entry.$nameProperty) {
                                    $candidateName = [string]$entry.$nameProperty
                                    if ($candidateName) { $name = $candidateName.Trim() }
                                    if ($name) { break }
                                }
                            }

                            if (-not $name -and $entry.PSObject.Properties['Message'] -and $entry.Message) {
                                $candidateName = [string]$entry.Message
                                if ($candidateName) {
                                    $candidateName = $candidateName.Trim()
                                    if ($candidateName.Length -gt 150) { $candidateName = $candidateName.Substring(0,150) }
                                    if ($candidateName) { $name = $candidateName }
                                }
                            }
                        }

                        if (-not $name) { $name = 'Unknown query' }

                        $server = $null
                        if ($entry.PSObject) {
                            foreach ($serverProperty in @('ServerAddress','Server','ServerIp','ServerIPAddress')) {
                                if ($entry.PSObject.Properties[$serverProperty] -and $entry.$serverProperty) {
                                    $candidateServer = [string]$entry.$serverProperty
                                    if ($candidateServer) { $server = $candidateServer.Trim() }
                                    if ($server) { break }
                                }
                            }

                            if (-not $server -and $entry.PSObject.Properties['Servers'] -and $entry.Servers) {
                                $serverCandidates = ConvertTo-TrimmedStringArray $entry.Servers
                                if ($serverCandidates.Count -gt 0) { $server = $serverCandidates[0] }
                            }
                        }

                        if (-not $server) { $server = 'Unknown server' }

                        $recentEvents += [pscustomobject]@{
                            Name    = $name
                            Server  = $server
                            TimeUtc = $timeUtc
                        }
                    }

                    if ($recentEvents.Count -ge 5) {
                        $groups = $recentEvents | Group-Object -Property { '{0}|{1}' -f ($_.Name.ToLowerInvariant()), ($_.Server.ToLowerInvariant()) }
                        $groupEvidence = @()
                        foreach ($group in ($groups | Sort-Object Count -Descending)) {
                            if (-not $group) { continue }
                            $first = $group.Group | Select-Object -First 1
                            if (-not $first) { continue }
                            $groupEvidence += [ordered]@{
                                name   = $first.Name
                                server = $first.Server
                                count  = $group.Count
                            }
                            if ($groupEvidence.Count -ge 5) { break }
                        }

                        $sampleNames = ($recentEvents | Select-Object -ExpandProperty Name -Unique | Select-Object -First 5)
                        $servers = ($recentEvents | Select-Object -ExpandProperty Server -Unique | Select-Object -First 5)
                        $lastEvent = ($recentEvents | Sort-Object TimeUtc -Descending | Select-Object -First 1)
                        $lastUtcText = if ($lastEvent -and $lastEvent.TimeUtc) { $lastEvent.TimeUtc.ToString('u') } else { $null }

                        $evidence = [ordered]@{
                            occurrences24h = $recentEvents.Count
                            sampleNames    = $sampleNames
                            servers        = $servers
                            lastUtc        = $lastUtcText
                        }

                        if ($groupEvidence.Count -gt 0) { $evidence['groups'] = $groupEvidence }

                        if (-not $vpnBaselineChecked) {
                            $vpnBaseline = Resolve-VpnBaselineState $Context
                            $vpnBaselineChecked = $true
                        }

                        if ($vpnBaseline -and $vpnBaseline.Connected) {
                            $corpServers = ConvertTo-TrimmedStringArray $vpnBaseline.CorporateDnsServers
                            if ($corpServers.Count -gt 0) {
                                $normalizedServers = $servers | ForEach-Object {
                                    $candidate = if ($_ -is [string]) { $_ } else { [string]$_ }
                                    if ($candidate) {
                                        $trimmed = $candidate.Trim()
                                        if ($trimmed) { $trimmed.ToLowerInvariant() }
                                    }
                                }
                                $normalizedServers = $normalizedServers | Where-Object { $_ }
                                $normalizedCorp = $corpServers | ForEach-Object { $_.ToLowerInvariant() }
                                $overlap = $false
                                foreach ($serverValue in $normalizedServers) {
                                    if ($normalizedCorp -contains $serverValue) { $overlap = $true; break }
                                }
                                if (-not $overlap) {
                                    $evidence['tags'] = @('Possible DNS leak')
                                }
                            }
                        }

                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'DNS resolution timeouts observed' -Evidence $evidence -Subcategory 'DNS Client Events'
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
