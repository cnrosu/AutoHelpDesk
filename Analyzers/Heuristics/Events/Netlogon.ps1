function Invoke-EventsNetlogonTrustChecks {
    param(
        [Parameter(Mandatory)]
        $Result,

        $SystemEntries,

        $Authentication
    )

    Write-HeuristicDebug -Source 'Events/Netlogon' -Message 'Evaluating Netlogon/LSA secure channel events'

    if (-not $SystemEntries) { return }

    $entries = @()
    if ($SystemEntries -is [System.Collections.IEnumerable] -and -not ($SystemEntries -is [string])) {
        foreach ($entry in $SystemEntries) {
            if (-not $entry) { continue }
            $entries += ,$entry
        }
    } else {
        $entries = @($SystemEntries)
    }

    if ($entries.Count -eq 0) { return }

    $nowUtc = (Get-Date).ToUniversalTime()
    $recentCutoff = $nowUtc.AddDays(-7)
    $extendedCutoff = $nowUtc.AddDays(-14)

    $eventMatches = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($entry in $entries) {
        if (-not $entry) { continue }
        if ($entry.PSObject.Properties['Error'] -and -not $entry.PSObject.Properties['Id']) { continue }

        $timeUtc = $null
        if ($entry.PSObject.Properties['TimeCreated']) {
            $timeUtc = ConvertTo-EventsDateTimeUtc -Value $entry.TimeCreated
        }

        if (-not $timeUtc) { continue }
        if ($timeUtc -lt $extendedCutoff) { continue }

        $id = $null
        if ($entry.PSObject.Properties['Id']) {
            try {
                $id = [int]$entry.Id
            } catch {
                $id = $entry.Id
            }
        }

        $provider = $null
        if ($entry.PSObject.Properties['ProviderName']) {
            $provider = [string]$entry.ProviderName
        }

        $message = $null
        if ($entry.PSObject.Properties['Message']) {
            $message = [string]$entry.Message
        }

        $level = $null
        if ($entry.PSObject.Properties['LevelDisplayName']) {
            $level = [string]$entry.LevelDisplayName
        }

        if ($level -and -not ($level -match '(?i)(error|warning|critical)')) {
            continue
        }

        $providerNormalized = $null
        if ($provider) {
            $providerNormalized = $provider.Trim()
        }

        $isNetlogonEvent = $false
        if ($id -eq 5719) {
            if (-not $providerNormalized -or $providerNormalized -match '(?i)NETLOGON') {
                $isNetlogonEvent = $true
            }
        }

        $isLsasrvEvent = $false
        if ($providerNormalized) {
            if ($providerNormalized -match '(?i)LSASRV') {
                $isLsasrvEvent = $true
            } elseif ($providerNormalized -match '(?i)Microsoft-Windows-Security-Kerberos') {
                $isLsasrvEvent = $true
            }
        }

        if (-not $isLsasrvEvent -and $message) {
            if ($message -match '(?i)LSASRV') {
                $isLsasrvEvent = $true
            }
        }

        if (-not $isNetlogonEvent -and -not $isLsasrvEvent) { continue }

        $eventMatches.Add([pscustomobject]@{
            Id       = $id
            TimeUtc  = $timeUtc
            Provider = $providerNormalized
        }
    }

    if ($eventMatches.Count -eq 0) { return }

    $recentMatches = @($eventMatches | Where-Object { $_.TimeUtc -ge $recentCutoff })
    if ($recentMatches.Count -lt 3) { return }

    $olderMatches = @($eventMatches | Where-Object { $_.TimeUtc -lt $recentCutoff })

    $eventIdSet = $recentMatches | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique
    $lastEvent = $recentMatches | Sort-Object TimeUtc -Descending | Select-Object -First 1

    $evidence = [ordered]@{
        eventIdSet = @($eventIdSet)
        count      = $recentMatches.Count
        lastUtc    = if ($lastEvent -and $lastEvent.TimeUtc) { $lastEvent.TimeUtc.ToString('o') } else { $null }
    }

    $severity = 'medium'
    $hasAuthFailures = Test-EventsHasAuthenticationFailuresElsewhere -Authentication $Authentication
    if ($olderMatches.Count -gt 0 -and $hasAuthFailures) {
        $severity = 'high'
    }

    Write-HeuristicDebug -Source 'Events/Netlogon' -Message 'Netlogon/LSA issues detected' -Data ([ordered]@{
        RecentCount = $recentMatches.Count
        OlderCount  = $olderMatches.Count
        Severity    = $severity
        EventIds    = @($eventIdSet)
    })

    $evidenceJson = $evidence | ConvertTo-Json -Depth 4 -Compress

    Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'Netlogon secure channel / domain reachability issues' -Evidence $evidenceJson -Subcategory 'Netlogon/LSA (Domain Join)'
}
