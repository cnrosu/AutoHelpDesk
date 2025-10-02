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

function ConvertTo-EventsArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $items = @()
        foreach ($item in $Value) { $items += $item }
        return $items
    }

    return @($Value)
}

function Test-EventsCorporateDnsServer {
    param([string]$Server)

    if ([string]::IsNullOrWhiteSpace($Server)) { return $false }

    $candidate = $Server.Trim()
    $candidate = $candidate.Split('%')[0]

    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($candidate, [ref]$parsed)) {
        $bytes = $parsed.GetAddressBytes()
        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            if ($bytes[0] -eq 10) { return $true }
            if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
            if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
            return $false
        }

        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            if (($bytes[0] -band 0xFE) -eq 0xFC) { return $true }
            return $false
        }

        return $false
    }

    return $true
}

function Get-EventsVpnState {
    param($Context)

    $state = [ordered]@{
        Connected = $false
        DnsServers = @()
    }

    if (-not $Context) { return [pscustomobject]$state }

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'vpn-baseline'
    if (-not $artifact) { return [pscustomobject]$state }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) { return [pscustomobject]$state }

    $connected = $false
    if ($payload.PSObject.Properties['connections']) {
        foreach ($connection in (ConvertTo-EventsArray -Value $payload.connections)) {
            if (-not $connection) { continue }
            if ($connection.PSObject.Properties['lastStatus']) {
                $status = $connection.lastStatus
                if ($status -and $status.PSObject.Properties['connected'] -and $status.connected -eq $true) {
                    $connected = $true
                    break
                }
            }
        }
    }

    $dnsServers = @()
    if ($payload.PSObject.Properties['network']) {
        $network = $payload.network
        if ($network -and $network.PSObject.Properties['effectiveDnsServers']) {
            $dnsServers = ConvertTo-EventsArray -Value $network.effectiveDnsServers | Where-Object { $_ }
        }
    }

    $state.Connected = $connected
    $state.DnsServers = @($dnsServers)

    return [pscustomobject]$state
}

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
        Write-HeuristicDebug -Source 'Events/Dns' -Message 'DNS client event query reported error' -Data ([ordered]@{ Error = $DnsClient.Error })
        return
    }

    $events = @()
    if ($DnsClient.PSObject.Properties['Events']) {
        $events = ConvertTo-EventsArray -Value $DnsClient.Events
    }

    if (-not $events -or $events.Count -eq 0) { return }

    $cutoff = (Get-Date).ToUniversalTime().AddHours(-24)
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
            if ($value) { $queryName = [string]$value; break }
        }
        if ($queryName) { $queryName = $queryName.Trim() }

        $serverAddress = $null
        foreach ($field in @('ServerAddress','Address','IP','IP4','IP6','DnsServerIpAddress')) {
            $value = Get-EventsEventDataValue -EventData $eventData -Name $field
            if ($value) { $serverAddress = [string]$value; break }
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

    $evidence = [ordered]@{
        occurrences24h = [int]$occurrences
        sampleNames    = $sampleNamesList.ToArray()
        servers        = $serversList.ToArray()
        lastUtc        = $lastUtcString
    }

    if ($tags.Count -gt 0) { $evidence['tags'] = $tags }

    Write-HeuristicDebug -Source 'Events/Dns' -Message 'DNS timeouts heuristic triggered' -Data ([ordered]@{
        Groups      = $flagged.Count
        Occurrences = $occurrences
        LastUtc     = $lastUtcString
        Tags        = $tags
    })

    $evidenceJson = $evidence | ConvertTo-Json -Depth 5 -Compress
    Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'DNS resolution timeouts observed' -Evidence $evidenceJson -Subcategory 'Networking / DNS'
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

function Normalize-EventsUserName {
    param([string]$UserName)

    if ([string]::IsNullOrWhiteSpace($UserName)) { return $null }

    $value = $UserName.Trim()

    if ($value -match '^[^\\]+\\(?<name>.+)$') {
        $value = $matches['name']
    }

    if ($value -match '^(?<name>[^@]+)@.+$') {
        $value = $matches['name']
    }

    return $value.ToUpperInvariant()
}

function Normalize-EventsHostName {
    param([string]$HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $null }

    $value = $HostName.Trim()
    if ($value -eq '-' -or $value -eq '--') { return $null }

    if ($value.EndsWith('$')) {
        $value = $value.Substring(0, $value.Length - 1)
    }

    if ($value.Contains('.')) {
        $value = $value.Split('.')[0]
    }

    return $value.ToUpperInvariant()
}

function ConvertTo-EventsMaskedUser {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $text = $Value.Trim()

    if ($text -match '^[^\\]+\\(?<name>.+)$') {
        $text = $matches['name']
    }

    if ($text -match '^(?<name>[^@]+)@.+$') {
        $text = $matches['name']
    }

    if ($text.Length -le 1) { return '***' }
    if ($text.Length -eq 2) { return ('{0}***' -f $text.Substring(0, 1)) }

    return ('{0}***{1}' -f $text.Substring(0, 1), $text.Substring($text.Length - 1))
}

function ConvertTo-EventsMaskedHost {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $text = $Value.Trim()
    if ($text -eq '-' -or $text -eq '--') { return $null }

    if ($text -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
        $octets = $text.Split('.')
        if ($octets.Length -ge 2) {
            return ('{0}.{1}.***' -f $octets[0], $octets[1])
        }

        return ('{0}.***' -f $octets[0])
    }

    if ($text -match '^[0-9a-fA-F:]+$' -and $text.Contains(':')) {
        $prefixLength = [math]::Min(4, $text.Length)
        return ('{0}***' -f $text.Substring(0, $prefixLength))
    }

    if ($text.Contains('-')) {
        $segment = $text.Split('-')[0]
        if ($segment) { return ('{0}-***' -f $segment) }
    }

    if ($text.Contains('.')) {
        $segment = $text.Split('.')[0]
        if ($segment) { return ('{0}.***' -f $segment) }
    }

    if ($text.Length -le 1) { return '***' }
    if ($text.Length -eq 2) { return ('{0}***' -f $text.Substring(0, 1)) }

    return ('{0}***{1}' -f $text.Substring(0, 1), $text.Substring($text.Length - 1))
}

function ConvertTo-EventsArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $items = @()
        foreach ($item in $Value) { $items += $item }
        return $items
    }

    return @($Value)
}

function Get-EventsCurrentDeviceName {
    param($Context)

    if (-not $Context) { return $null }

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if (-not $systemArtifact) { return $null }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
    if (-not $payload) { return $null }

    $systemInfo = $null
    if ($payload.PSObject.Properties['SystemInfoText']) {
        $systemInfo = $payload.SystemInfoText
    }

    if ($systemInfo -is [pscustomobject] -and $systemInfo.PSObject.Properties['Error']) {
        return $null
    }

    if ($systemInfo) {
        if ($systemInfo -isnot [string]) {
            if ($systemInfo -is [System.Collections.IEnumerable] -and -not ($systemInfo -is [string])) {
                $systemInfo = ($systemInfo -join "`n")
            } else {
                $systemInfo = [string]$systemInfo
            }
        }

        if ($systemInfo) {
            foreach ($line in [regex]::Split($systemInfo, '\r?\n')) {
                if ($line -match '^\s*Host\s+Name\s*:\s*(.+)$') {
                    return $matches[1].Trim()
                }
            }
        }
    }

    return $null
}

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

    $matches = New-Object System.Collections.Generic.List[pscustomobject]

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

        $matches.Add([pscustomobject]@{
            Id       = $id
            TimeUtc  = $timeUtc
            Provider = $providerNormalized
        }) | Out-Null
    }

    if ($matches.Count -eq 0) { return }

    $recentMatches = @($matches | Where-Object { $_.TimeUtc -ge $recentCutoff })
    if ($recentMatches.Count -lt 3) { return }

    $olderMatches = @($matches | Where-Object { $_.TimeUtc -lt $recentCutoff })

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
    } else {
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

    $accountLockoutData = $null
    if ($Authentication.PSObject.Properties['AccountLockouts']) {
        $accountLockoutData = $Authentication.AccountLockouts
    }

    if (-not $accountLockoutData) { return }

    $lockoutContainer = $null
    if ($accountLockoutData.PSObject.Properties['Lockouts']) {
        $lockoutContainer = $accountLockoutData.Lockouts
    }

    $failedContainer = $null
    if ($accountLockoutData.PSObject.Properties['FailedLogons']) {
        $failedContainer = $accountLockoutData.FailedLogons
    }

    if (-not $lockoutContainer -or -not $failedContainer) { return }

    if (($lockoutContainer.Error) -or ($failedContainer.Error)) { return }

    $lockoutEventsRaw = @()
    if ($lockoutContainer.PSObject.Properties['Events']) {
        $lockoutEventsRaw = @($lockoutContainer.Events)
    }

    $failedEventsRaw = @()
    if ($failedContainer.PSObject.Properties['Events']) {
        $failedEventsRaw = @($failedContainer.Events)
    }

    if (-not $lockoutEventsRaw -or -not $failedEventsRaw) { return }

    $lockoutRecords = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($event in $lockoutEventsRaw) {
        if (-not $event) { continue }

        $eventData = $null
        if ($event.PSObject.Properties['EventData']) {
            $eventData = $event.EventData
        }

        $userValue = $null
        foreach ($field in @('TargetUserName','TargetAccountName')) {
            $candidate = Get-EventsEventDataValue -EventData $eventData -Name $field
            if ($candidate) { $userValue = [string]$candidate; break }
        }

        if (-not $userValue) { continue }

        $normalizedUser = Normalize-EventsUserName -UserName $userValue
        if (-not $normalizedUser) { continue }

        $timeUtc = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $timeUtc = ConvertTo-EventsDateTimeUtc -Value $event.TimeCreated
        }

        $lockoutRecords.Add([pscustomobject]@{
            TimeUtc        = $timeUtc
            User           = $userValue
            UserNormalized = $normalizedUser
        }) | Out-Null
    }

    $failedRecords = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($event in $failedEventsRaw) {
        if (-not $event) { continue }

        $eventData = $null
        if ($event.PSObject.Properties['EventData']) {
            $eventData = $event.EventData
        }

        $userValue = $null
        foreach ($field in @('TargetUserName','TargetAccountName')) {
            $candidate = Get-EventsEventDataValue -EventData $eventData -Name $field
            if ($candidate) { $userValue = [string]$candidate; break }
        }

        if (-not $userValue) { continue }

        $normalizedUser = Normalize-EventsUserName -UserName $userValue
        if (-not $normalizedUser) { continue }

        $workstation = Get-EventsEventDataValue -EventData $eventData -Name 'WorkstationName'
        $ipAddress = Get-EventsEventDataValue -EventData $eventData -Name 'IpAddress'

        $sourceType = $null
        $sourceLabel = $null
        $sourceNormalized = $null

        if ($workstation -and $workstation -notin '', '-', '--') {
            $sourceType = 'Workstation'
            $sourceLabel = ([string]$workstation).Trim()
            $sourceNormalized = Normalize-EventsHostName -HostName $sourceLabel
        }

        if (-not $sourceNormalized -and $ipAddress -and $ipAddress -notin '', '-', '--') {
            $sourceType = 'IP'
            $sourceLabel = ([string]$ipAddress).Trim()
            $sourceNormalized = $sourceLabel
            if ($sourceNormalized) {
                $sourceNormalized = $sourceNormalized.ToLowerInvariant()
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

    $cutoffUtc = [datetime]::UtcNow.AddDays(-7)
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
        if ($event.PSObject.Properties['eventData']) { $eventData = $event.eventData }

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

        if (-not $vpnName -and $normalizedMessage -and $connectionLookup.Keys.Count -gt 0) {
            $messageLower = $null
            try { $messageLower = $normalizedMessage.ToLowerInvariant() } catch { $messageLower = $normalizedMessage.ToLower() }
            foreach ($key in $connectionLookup.Keys) {
                if ([string]::IsNullOrWhiteSpace($key)) { continue }
                if ($messageLower.Contains($key)) {
                    $matchInfo = $connectionLookup[$key]
                    if ($matchInfo) {
                        $vpnName = $matchInfo.Name
                        if (-not $serverAddress -and $matchInfo.PSObject.Properties['Server'] -and $matchInfo.Server) {
                            $serverAddress = [string]$matchInfo.Server
                        }
                    }
                    break
                }
            }
        }

        if (-not $vpnName -and $connectionSummaries.Count -eq 1) {
            $only = $connectionSummaries[0]
            if ($only.PSObject.Properties['name']) { $vpnName = [string]$only.name }
            if (-not $serverAddress -and $only.PSObject.Properties['server']) { $serverAddress = [string]$only.server }
        }

        $matches.Add([pscustomobject]@{
            Provider      = $provider
            EventId       = $eventId
            TimeUtc       = $timeUtc
            MsgSnippet    = $msgSnippet
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

    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'VPN authentication failing (certificate invalid or IKE SA failure)' -Evidence $evidence -Subcategory 'VPN / IKE'
}

function Invoke-EventsHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Events' -Message 'Starting event log heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $deviceName = Get-EventsCurrentDeviceName -Context $Context

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

            if ($payload.PSObject.Properties['System']) {
                Invoke-EventsNetlogonTrustChecks -Result $result -SystemEntries $payload.System -Authentication $payload.Authentication
            }

            if ($payload.PSObject.Properties['Authentication']) {
                Invoke-EventsAuthenticationChecks -Result $result -Authentication $payload.Authentication -DeviceName $deviceName
            }
            $dnsClientData = $null
            if ($payload.PSObject.Properties['Networking']) {
                $networking = $payload.Networking
                if ($networking -and $networking.PSObject.Properties['DnsClient']) {
                    $dnsClientData = $networking.DnsClient
                }
            } elseif ($payload.PSObject.Properties['DnsClient']) {
                $dnsClientData = $payload.DnsClient
            }

            if ($dnsClientData) {
                Invoke-EventsDnsChecks -Result $result -DnsClient $dnsClientData -Context $Context
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    Invoke-EventsVpnAuthenticationChecks -Result $result -Context $Context

    return $result
}
