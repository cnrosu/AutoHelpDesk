function Invoke-EventsVpnAuthenticationChecks {
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Events/VPN' -Message 'Evaluating VPN authentication telemetry'

    if (-not $Context) { return }

    $vpnEventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vpn-events'
    Write-HeuristicDebug -Source 'Events/VPN' -Message 'Resolved vpn-events artifact' -Data ([ordered]@{ Found = [bool]$vpnEventsArtifact })
    if (-not $vpnEventsArtifact) { return }

    $vpnEventsPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $vpnEventsArtifact)
    if (-not $vpnEventsPayload) { return }

    $rawEvents = @()
    if ($vpnEventsPayload.PSObject.Properties['events']) {
        $rawEvents = ConvertTo-EventsArray $vpnEventsPayload.events
    }

    if ($rawEvents.Count -eq 0) {
        Write-HeuristicDebug -Source 'Events/VPN' -Message 'vpn-events payload contained no records'
        return
    }

    $vpnBaselineArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vpn-baseline'
    $baselinePayload = $null
    if ($vpnBaselineArtifact) {
        $baselinePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $vpnBaselineArtifact)
    }

    $connections = @()
    if ($baselinePayload -and $baselinePayload.PSObject.Properties['connections']) {
        $connections = ConvertTo-EventsArray $baselinePayload.connections
    }

    $connectionSummaries = New-Object System.Collections.Generic.List[pscustomobject]
    $connectionLookup = @{}
    foreach ($conn in $connections) {
        if (-not $conn) { continue }
        $name = if ($conn.PSObject.Properties['name']) { [string]$conn.name } else { $null }
        $server = if ($conn.PSObject.Properties['serverAddress']) { [string]$conn.serverAddress } else { $null }
        $entry = [ordered]@{}
        if ($name) {
            $entry['name'] = $name
            $connectionLookup[$name.ToLowerInvariant()] = [pscustomobject]@{ Name = $name; Server = $server }
        }
        if ($server) { $entry['server'] = $server }
        if ($entry.Count -gt 0) {
            $connectionSummaries.Add([pscustomobject]$entry) | Out-Null
        }
    }

    $nowUtc = [datetime]::UtcNow
    $cutoffUtc = $nowUtc.AddDays(-7)
    $WindowMinutes = [int][math]::Round(($nowUtc - $cutoffUtc).TotalMinutes)
    $matches = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($event in $rawEvents) {
        if (-not $event) { continue }

        $eventId = $null
        if ($event.PSObject.Properties['eventId']) { $eventId = [int]$event.eventId }
        if (-not $eventId) { continue }

        $timeUtc = $null
        foreach ($field in @('timeCreatedUtc','timeCreated')) {
            if ($event.PSObject.Properties[$field] -and $event.$field) {
                $timeUtc = ConvertTo-EventsDateTimeUtc -Value $event.$field
                if ($timeUtc) { break }
            }
        }
        if (-not $timeUtc -or $timeUtc -lt $cutoffUtc) { continue }

        $provider = if ($event.PSObject.Properties['provider']) { [string]$event.provider } else { $null }
        $message = if ($event.PSObject.Properties['message']) { [string]$event.message } else { $null }
        $normalizedMessage = $null
        if ($message) {
            $normalizedMessage = ($message -replace '\s+', ' ').Trim()
        }

        $eventData = $null
        if ($event.PSObject.Properties['eventData']) {
            $eventData = $event.eventData
        }

        $matchType = $null
        if ($eventId -eq 20227) {
            $certificateHit = $false
            if ($normalizedMessage -and $normalizedMessage -match '(?i)no\s+valid\s+certificate') { $certificateHit = $true }
            if (-not $certificateHit -and $eventData -and $eventData.PSObject -and $eventData.PSObject.Properties['ErrorString']) {
                if ([string]$eventData.ErrorString -match '(?i)no\s+valid\s+certificate') { $certificateHit = $true }
            }
            if ($certificateHit) { $matchType = 'Certificate' }
        } elseif ($eventId -in @(4653,4654)) {
            if (-not $provider -or $provider -match '(?i)ike') {
                $matchType = 'IKE'
            }
        } else {
            continue
        }

        if (-not $matchType) { continue }

        $msgSnippet = $normalizedMessage
        if ($msgSnippet -and $msgSnippet.Length -gt 220) { $msgSnippet = $msgSnippet.Substring(0,220) + '...' }

        $vpnName = $null
        foreach ($key in @('ConnectionName','VPNName','Name','EntryName')) {
            if ($eventData -and $eventData.PSObject -and $eventData.PSObject.Properties[$key] -and $eventData.$key) {
                $vpnName = [string]$eventData.$key
                break
            }
        }

        $serverAddress = $null
        foreach ($key in @('ServerAddress','TunnelAddress','RemoteAddress')) {
            if ($eventData -and $eventData.PSObject -and $eventData.PSObject.Properties[$key] -and $eventData.$key) {
                $serverAddress = [string]$eventData.$key
                break
            }
        }

        if (-not $serverAddress -and $vpnName -and $connectionLookup.ContainsKey($vpnName.ToLowerInvariant())) {
            $serverAddress = $connectionLookup[$vpnName.ToLowerInvariant()].Server
        }

        $matches.Add([pscustomobject]@{
            EventId       = $eventId
            TimeUtc       = $timeUtc
            Provider      = $provider
            MsgSnippet    = $msgSnippet
            MatchType     = $matchType
            VpnName       = $vpnName
            ServerAddress = $serverAddress
        }) | Out-Null
    }

    if ($matches.Count -eq 0) {
        Write-HeuristicDebug -Source 'Events/VPN' -Message 'No VPN authentication failures detected within window'
        return
    }

    $sortedMatches = $matches | Sort-Object TimeUtc -Descending
    $eventEvidence = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($match in ($sortedMatches | Select-Object -First 5)) {
        $entry = [ordered]@{
            provider   = $match.Provider
            eventId    = $match.EventId
            lastUtc    = if ($match.TimeUtc) { $match.TimeUtc.ToString('o') } else { $null }
            msgSnippet = $match.MsgSnippet
        }
        if ($match.VpnName) { $entry['vpnName'] = $match.VpnName }
        if ($match.ServerAddress) { $entry['server'] = $match.ServerAddress }
        $eventEvidence.Add([pscustomobject]$entry) | Out-Null
    }

    $evidence = [ordered]@{
        events       = $eventEvidence
        windowDays   = 7
        totalMatches = $matches.Count
    }

    if ($connectionSummaries.Count -gt 0) {
        $evidence['vpnProfiles'] = ($connectionSummaries | Select-Object -First 5)
    }

    $bucketed = @()
    if ($matches.Count -gt 0) {
        $grouped = $matches | Group-Object -Property { '{0}|{1}' -f $_.EventId, $_.MatchType }
        $bucketed = foreach ($group in ($grouped | Sort-Object Count -Descending)) {
            $first = $group.Group | Select-Object -First 1
            $samples = foreach ($sample in ($group.Group | Sort-Object TimeUtc -Descending | Select-Object -First 5)) {
                [pscustomobject]@{
                    TimeCreated = if ($sample.TimeUtc) { $sample.TimeUtc.ToString('o') } else { $null }
                    Provider    = $sample.Provider
                    VpnName     = $sample.VpnName
                    Server      = $sample.ServerAddress
                    Message     = $sample.MsgSnippet
                }
            }

            [pscustomobject]@{
                EventId      = if ($first) { $first.EventId } else { $null }
                MatchType    = if ($first) { $first.MatchType } else { $null }
                Count        = $group.Count
                SampleEvents = @($samples)
            }
        }
    }

    $title = 'VPN authentication failing (certificate invalid or IKE SA failure)'
    $subcat = 'VPN / IKE'
    $kind = 'VPN'

    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title $title -Evidence $evidence -Subcategory $subcat -Data ([ordered]@{
        Area          = 'Events'
        Kind          = $kind
        WindowMinutes = $WindowMinutes
        Buckets       = @($bucketed)
    })
}
