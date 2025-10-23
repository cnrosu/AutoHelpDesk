function Invoke-EventsDnsChecks {
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        $DnsClient,

        $Context
    )

    Write-HeuristicDebug -Source 'Events/Dns' -Message 'Starting DNS client event analysis'

    if (-not $DnsClient) { return }

    if ($DnsClient.PSObject.Properties['Error'] -and $DnsClient.Error) {
        Write-HeuristicError -Source 'Events/Dns' -Message 'DNS client event query reported error' -Data ([ordered]@{ Error = $DnsClient.Error })
        return
    }

    $events = @()
    if ($DnsClient.PSObject.Properties['Events']) {
        $events = ConvertTo-EventsArray -Value $DnsClient.Events
    }

    if (-not $events -or $events.Count -eq 0) { return }

    $nowUtc = (Get-Date).ToUniversalTime()
    $cutoff = $nowUtc.AddHours(-24)
    $WindowMinutes = [int][math]::Round(($nowUtc - $cutoff).TotalMinutes)
    $groups = @{}

    foreach ($event in $events) {
        if (-not $event) { continue }

        $timeUtc = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $timeUtc = ConvertTo-EventsDateTimeUtc -Value $event.TimeCreated
        }

        if (-not $timeUtc -or $timeUtc -lt $cutoff) { continue }

        $eventData = $null
        if ($event.PSObject.Properties['EventData']) { $eventData = $event.EventData }

        $queryName = $null
        foreach ($field in @('QueryName','Name','Query','HostName')) {
            $value = Get-EventsEventDataValue -EventData $eventData -Name $field
            if ($value) {
                $queryName = [string]$value
                break
            }
        }
        if ($queryName) { $queryName = $queryName.Trim() }

        $serverAddress = $null
        foreach ($field in @('ServerAddress','Address','IP','IP4','IP6','DnsServerIpAddress')) {
            $value = Get-EventsEventDataValue -EventData $eventData -Name $field
            if ($value) {
                $serverAddress = [string]$value
                break
            }
        }
        if ($serverAddress) { $serverAddress = $serverAddress.Trim() }

        $messageSnippet = $null
        if ($event.PSObject.Properties['Message']) {
            $messageText = [string]$event.Message
            if ($messageText) {
                $trimmed = $messageText.Trim()
                if ($trimmed.Length -gt 150) {
                    $messageSnippet = $trimmed.Substring(0, 150)
                } else {
                    $messageSnippet = $trimmed
                }
            }
        }

        if (-not $queryName) { $queryName = $messageSnippet }

        $queryDisplay = if ($queryName) { $queryName } else { 'unknown query' }
        $serverDisplay = if ($serverAddress) { $serverAddress } else { 'unknown' }

        $queryKey = if ($queryName) { $queryName.ToLowerInvariant() } else { 'unknown' }
        $serverKey = if ($serverAddress) { $serverAddress.ToLowerInvariant() } else { 'unknown' }
        $key = ('{0}|{1}' -f $queryKey, $serverKey)

        if (-not $groups.ContainsKey($key)) {
            $samples = New-Object System.Collections.Generic.List[string]
            if ($queryDisplay -and -not $samples.Contains($queryDisplay)) { $null = $samples.Add($queryDisplay) }
            $groups[$key] = [pscustomobject]@{
                Query   = $queryDisplay
                Server  = $serverDisplay
                Count   = 0
                LastUtc = $null
                Samples = $samples
            }
        }

        $group = $groups[$key]
        $group.Count++
        if ($timeUtc -and (-not $group.LastUtc -or $timeUtc -gt $group.LastUtc)) { $group.LastUtc = $timeUtc }
        if ($queryDisplay -and -not $group.Samples.Contains($queryDisplay) -and $group.Samples.Count -lt 5) {
            $null = $group.Samples.Add($queryDisplay)
        }
        if (($group.Server -eq 'unknown' -or -not $group.Server) -and $serverAddress) {
            $group.Server = $serverAddress
        }
    }

    if ($groups.Count -eq 0) { return }

    $flagged = @($groups.Values | Where-Object { $_.Count -ge 5 })
    if ($flagged.Count -eq 0) { return }

    $occurrences = ($flagged | Measure-Object -Property Count -Sum).Sum
    if (-not $occurrences) { $occurrences = 0 }

    $sampleNamesList = New-Object System.Collections.Generic.List[string]
    $serversList = New-Object System.Collections.Generic.List[string]
    $lastUtc = $null

    foreach ($group in $flagged) {
        if ($group.LastUtc -and (-not $lastUtc -or $group.LastUtc -gt $lastUtc)) { $lastUtc = $group.LastUtc }

        if ($group.Server -and -not $serversList.Contains($group.Server) -and $serversList.Count -lt 5) {
            $null = $serversList.Add($group.Server)
        }

        foreach ($sample in $group.Samples) {
            if ($sample -and -not $sampleNamesList.Contains($sample) -and $sampleNamesList.Count -lt 5) {
                $null = $sampleNamesList.Add($sample)
            }
        }
    }

    $lastUtcString = if ($lastUtc) { $lastUtc.ToString('o') } else { $null }

    $vpnState = Get-EventsVpnState -Context $Context
    $tags = @()
    if ($vpnState.Connected -and $vpnState.DnsServers -and $vpnState.DnsServers.Count -gt 0) {
        $hasCorp = $false
        foreach ($server in $vpnState.DnsServers) {
            if (Test-EventsCorporateDnsServer -Server $server) {
                $hasCorp = $true
                break
            }
        }
        if (-not $hasCorp) {
            $tags += 'Possible DNS leak'
        }
    }

    Write-HeuristicDebug -Source 'Events/Dns' -Message 'DNS timeouts heuristic triggered' -Data ([ordered]@{
        Groups      = $flagged.Count
        Occurrences = $occurrences
        LastUtc     = $lastUtcString
        Tags        = $tags
    })

    $bucketed = @()
    if ($flagged.Count -gt 0) {
        $bucketed = foreach ($group in ($flagged | Sort-Object Count -Descending)) {
            [pscustomobject]@{
                Query       = $group.Query
                Server      = $group.Server
                Count       = $group.Count
                LastUtc     = if ($group.LastUtc) { $group.LastUtc.ToString('o') } else { $null }
                SampleNames = @($group.Samples)
            }
        }
    }

    $evidence = [ordered]@{
        area           = 'Events'
        kind           = $kind
        windowMinutes  = $WindowMinutes
        occurrences24h = [int]$occurrences
        lastUtc        = $lastUtcString
        servers        = $serversList.ToArray()
        sampleNames    = $sampleNamesList.ToArray()
        buckets        = @($bucketed)
    }

    if ($tags.Count -gt 0) { $evidence['tags'] = $tags }

    $evidenceJson = $evidence | ConvertTo-Json -Depth 6

    $title = 'DNS resolution timeouts observed'
    $subcat = 'Networking / DNS'
    $kind = 'DNS'

    Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title $title -Evidence $evidenceJson -Subcategory $subcat
}
