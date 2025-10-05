<#!
.SYNOPSIS
    Builds high-level summary metadata for the diagnostics report UI.
#>

. (Join-Path -Path $PSScriptRoot -ChildPath 'AnalyzerCommon.ps1')

function Get-FirstNonEmptyString {
    param(
        [Parameter(ValueFromPipeline)]
        $Value
    )

    process {
        if ($null -eq $Value) { return }
        if ($Value -is [string]) {
            $trimmed = $Value.Trim()
            if ($trimmed) { return $trimmed }
            return
        }

        if ($Value -is [ValueType]) {
            $text = $Value.ToString().Trim()
            if ($text) { return $text }
            return
        }

        if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
            foreach ($item in $Value) {
                $candidate = Get-FirstNonEmptyString -Value $item
                if ($candidate) { return $candidate }
            }
            return
        }

        foreach ($prop in 'Name','Value','DisplayValue','NextHop','IPAddress','Address') {
            if ($Value.PSObject.Properties[$prop]) {
                $candidate = Get-FirstNonEmptyString -Value $Value.$prop
                if ($candidate) { return $candidate }
            }
        }

        $fallback = [string]$Value
        $fallback = $fallback.Trim()
        if ($fallback) { return $fallback }
    }
}

function Convert-ToUniqueStringArray {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Values
    )

    $ordered = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        $text = [string]$value
        if (-not $text) { continue }
        $trimmed = $text.Trim()
        if (-not $trimmed) { continue }
        if ($seen.Add($trimmed)) {
            $ordered.Add($trimmed) | Out-Null
        }
    }

    if ($ordered.Count -eq 0) { return @() }
    return $ordered.ToArray()
}

function Get-AllStrings {
    param(
        [Parameter(Mandatory)]
        $Value
    )

    $results = New-Object System.Collections.Generic.List[string]

    function Add-StringRecursive {
        param($InputValue)

        if ($null -eq $InputValue) { return }
        if ($InputValue -is [string]) {
            $text = $InputValue.Trim()
            if ($text) { $results.Add($text) | Out-Null }
            return
        }

        if ($InputValue -is [ValueType]) {
            $text = $InputValue.ToString().Trim()
            if ($text) { $results.Add($text) | Out-Null }
            return
        }

        if ($InputValue -is [System.Collections.IEnumerable] -and -not ($InputValue -is [string])) {
            foreach ($item in $InputValue) { Add-StringRecursive -InputValue $item }
            return
        }

        foreach ($prop in 'IPAddress','Address','NextHop','Value','DisplayValue','Name','ServerAddresses') {
            if ($InputValue.PSObject.Properties[$prop]) {
                Add-StringRecursive -InputValue $InputValue.$prop
                return
            }
        }

        $fallback = [string]$InputValue
        $fallback = $fallback.Trim()
        if ($fallback) { $results.Add($fallback) | Out-Null }
    }

    Add-StringRecursive -InputValue $Value
    return ($results | Select-Object -Unique)
}

function ConvertTo-WlanInterfaceSummaries {
    param($Raw)

    if ($null -eq $Raw) { return @() }

    $lines = @()

    if ($Raw -is [string]) {
        $lines = [regex]::Split($Raw, '\r?\n')
    } elseif ($Raw -is [System.Collections.IEnumerable] -and -not ($Raw -is [string])) {
        foreach ($item in $Raw) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if (-not [string]::IsNullOrEmpty($text)) {
                $lines += [regex]::Split($text, '\r?\n')
            }
        }
    } else {
        $lines = @([string]$Raw)
    }

    $interfaces = [System.Collections.Generic.List[pscustomobject]]::new()
    $current = $null

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^Name\s*:\s*(.+)$') {
            $current = [ordered]@{
                Name           = $Matches[1].Trim()
                State          = $null
                Ssid           = $null
                Bssid          = $null
                Authentication = $null
                Cipher         = $null
                RadioType      = $null
                ConnectionMode = $null
                Profile        = $null
            }
            $interfaces.Add([pscustomobject]$current) | Out-Null
            continue
        }

        if (-not $current) { continue }

        if ($trimmed -match '^State\s*:\s*(.+)$') {
            $current['State'] = $Matches[1].Trim()
            continue
        }

        if ($trimmed -match '^SSID(\s+\d+)?\s*:\s*(.*)$') {
            $current['Ssid'] = $Matches[2].Trim()
            continue
        }

        if ($trimmed -match '^BSSID(\s+\d+)?\s*:\s*(.*)$') {
            if (-not $current['Bssid']) {
                $current['Bssid'] = $Matches[2].Trim()
            }
            continue
        }

        if ($trimmed -match '^Authentication\s*:\s*(.+)$') {
            $current['Authentication'] = $Matches[1].Trim()
            continue
        }

        if ($trimmed -match '^Cipher\s*:\s*(.+)$') {
            $current['Cipher'] = $Matches[1].Trim()
            continue
        }

        if ($trimmed -match '^Radio type\s*:\s*(.+)$') {
            $current['RadioType'] = $Matches[1].Trim()
            continue
        }

        if ($trimmed -match '^Connection mode\s*:\s*(.+)$') {
            $current['ConnectionMode'] = $Matches[1].Trim()
            continue
        }

        if ($trimmed -match '^Profile\s*:\s*(.+)$') {
            $current['Profile'] = $Matches[1].Trim()
            continue
        }
    }

    if ($interfaces.Count -eq 0) { return @() }
    return $interfaces.ToArray()
}

function Get-NetworkStatusRank {
    param([string]$Status)

    if (-not $Status) { return 0 }

    $normalized = $Status.Trim()
    if (-not $normalized) { return 0 }

    try {
        $normalized = $normalized.ToLowerInvariant()
    } catch {
        $normalized = $normalized.ToLower()
    }

    if ($normalized -match '^(connected|up)') { return 3 }
    if ($normalized -match '^(disconnected|down|disabled)') { return 0 }
    return 1
}

function Get-NetworkConnectionKind {
    param(
        [string]$Alias,
        [string]$Description,
        [string[]]$WirelessAliases
    )

    if (-not $WirelessAliases) { $WirelessAliases = @() }

    foreach ($candidate in $WirelessAliases) {
        if (-not $candidate) { continue }
        if ($Alias -and $Alias.Equals($candidate, [System.StringComparison]::OrdinalIgnoreCase)) { return 'Wireless' }
        if ($Description -and $Description.Equals($candidate, [System.StringComparison]::OrdinalIgnoreCase)) { return 'Wireless' }
    }

    $combined = (($Alias, $Description) | Where-Object { $_ }) -join ' '
    if (-not $combined) { return 'Unknown' }

    try {
        $normalized = $combined.ToLowerInvariant()
    } catch {
        $normalized = $combined.ToLower()
    }

    if ($normalized -match 'wi[-\s]?fi' -or $normalized -match 'wireless' -or $normalized -match '\bwlan\b' -or $normalized -match '802\.11') {
        return 'Wireless'
    }

    if ($normalized -match 'bluetooth') { return 'Bluetooth' }

    if ($normalized -match '\b(vpn|virtual|loopback|hyper-v|vmware|tunnel|tap)\b') { return 'Virtual' }

    if ($normalized -match '\bethernet\b' -or $normalized -match '\bgigabit\b' -or $normalized -match '\bnic\b' -or $normalized -match 'network adapter' -or $normalized -match '\slan\b') {
        return 'Wired'
    }

    return 'Unknown'
}

function Parse-IpConfigNetworkValues {
    param([string]$IpConfigText)

    $ipv4 = New-Object System.Collections.Generic.List[string]
    $gateways = New-Object System.Collections.Generic.List[string]
    $dns = New-Object System.Collections.Generic.List[string]

    if ([string]::IsNullOrWhiteSpace($IpConfigText)) {
        return [pscustomobject]@{
            IPv4     = @()
            Gateways = @()
            Dns      = @()
        }
    }

    $lines = [regex]::Split($IpConfigText, '\r?\n')
    $collectingDns = $false
    $collectingGateway = $false

    foreach ($line in $lines) {
        $raw = if ($null -ne $line) { $line.Trim() } else { '' }
        if (-not $raw) { continue }

        if ($raw -match '^(?<label>[A-Za-z0-9\s\.-]+?):\s*(?<value>.*)$') {
            $label = $matches['label'].Trim()
            $value = $matches['value']
            if ($null -ne $value) { $value = $value.Trim() }

            $collectingDns = $false
            $collectingGateway = $false

            switch -Regex ($label) {
                'IPv4\s+Address' {
                    if ($value) {
                        $clean = ($value -replace '\(Preferred\)', '')
                        $clean = ($clean -replace '\s*\(.*$','').Trim()
                        if ($clean -and $clean -notmatch '^169\.254\.') {
                            $ipv4.Add($clean) | Out-Null
                        }
                    }
                }
                'Default\s+Gateway' {
                    if ($value) {
                        $gateways.Add($value) | Out-Null
                    } else {
                        $collectingGateway = $true
                    }
                }
                'DNS\s+Servers' {
                    if ($value) {
                        $dns.Add($value) | Out-Null
                    }
                    $collectingDns = $true
                }
            }

            continue
        }

        if ($collectingGateway) {
            $gateways.Add($raw) | Out-Null
            continue
        }

        if ($collectingDns) {
            $dns.Add($raw) | Out-Null
            continue
        }
    }

    $ipv4Array = Convert-ToUniqueStringArray -Values $ipv4
    $gatewayArray = Convert-ToUniqueStringArray -Values ($gateways | Where-Object { $_ -and $_ -ne '0.0.0.0' })
    $dnsArray = Convert-ToUniqueStringArray -Values $dns

    return [pscustomobject]@{
        IPv4     = $ipv4Array
        Gateways = $gatewayArray
        Dns      = $dnsArray
    }
}

function Format-DeviceState {
    param(
        [string]$Domain,
        [bool]$PartOfDomain,
        [bool]$IsAzureAdJoined
    )

    if ($PartOfDomain) {
        if ($Domain) { return "Domain joined ($Domain)" }
        return 'Domain joined'
    }

    $domainLabel = if ($Domain) { $Domain } else { 'Unknown domain' }
    if ($IsAzureAdJoined) {
        return "Azure AD joined ($domainLabel)"
    }

    return "Not domain joined (Domain: $domainLabel)"
}

function Parse-HostNameFromSystemInfo {
    param([string]$SystemInfoText)

    if (-not $SystemInfoText) { return $null }

    foreach ($line in [regex]::Split($SystemInfoText, '\r?\n')) {
        if ($line -match '^\s*Host\s+Name\s*:\s*(.+)$') {
            return $matches[1].Trim()
        }
    }

    return $null
}

function Test-IsWindowsServer {
    param([string]$Caption)

    if (-not $Caption) { return $null }
    return ($Caption -match '(?i)windows\s+server')
}

function Get-AzureAdJoinState {
    param([string]$DsRegCmdOutput)

    if (-not $DsRegCmdOutput) { return $false }

    foreach ($line in [regex]::Split($DsRegCmdOutput, '\r?\n')) {
        if ($line -match '^(?i)AzureAdJoined\s*:\s*(Yes|No)') {
            return ($matches[1].ToLowerInvariant() -eq 'yes')
        }
    }

    return $false
}

function Get-AnalyzerSummary {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $summary = [ordered]@{
        DeviceName      = $null
        DeviceState     = $null
        Domain          = $null
        IsDomainJoined  = $null
        IsAzureAdJoined = $false
        OperatingSystem = $null
        OSVersion       = $null
        OSBuild           = $null
        IsWindowsServer   = $null
        IPv4Addresses     = @()
        Gateways          = @()
        DnsServers        = @()
        NetworkConnections = @()
        PrimaryConnection  = $null
        WirelessConnection = $null
        GeneratedAt       = Get-Date
    }

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload) {
            if ($payload.SystemInfoText) {
                $systemInfoText = $payload.SystemInfoText
                if ($systemInfoText -isnot [string]) {
                    if ($systemInfoText -is [System.Collections.IEnumerable]) {
                        $systemInfoText = ($systemInfoText -join "`n")
                    } else {
                        $systemInfoText = [string]$systemInfoText
                    }
                }

                if ($systemInfoText) {
                    $summary.DeviceName = Parse-HostNameFromSystemInfo -SystemInfoText $systemInfoText
                }
            }

            if ($payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
                $os = $payload.OperatingSystem
                $summary.OperatingSystem = $os.Caption
                $summary.OSVersion = $os.Version
                $summary.OSBuild = $os.BuildNumber
                $summary.IsWindowsServer = Test-IsWindowsServer -Caption $os.Caption
            }

            if ($payload.ComputerSystem -and -not $payload.ComputerSystem.Error) {
                $cs = $payload.ComputerSystem
                if ($cs.Domain) { $summary.Domain = $cs.Domain }
                if ($null -ne $cs.PartOfDomain) { $summary.IsDomainJoined = [bool]$cs.PartOfDomain }
            }
        }
    }

    $identityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'identity'
    if ($identityArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $identityArtifact)
        if ($payload -and $payload.DsRegCmd -is [string]) {
            $summary.IsAzureAdJoined = Get-AzureAdJoinState -DsRegCmdOutput $payload.DsRegCmd
        }
    }

    if (-not $summary.DeviceName) {
        $hostnameArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network'
        if ($hostnameArtifact) {
            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $hostnameArtifact)
            if ($payload -and $payload.IpConfig) {
                $ipConfigText = $payload.IpConfig
                if ($ipConfigText -isnot [string]) {
                    if ($ipConfigText -is [System.Collections.IEnumerable]) {
                        $ipConfigText = ($ipConfigText -join "`n")
                    } else {
                        $ipConfigText = [string]$ipConfigText
                    }
                }

                if ($ipConfigText) {
                    $candidate = Parse-HostNameFromSystemInfo -SystemInfoText $ipConfigText
                    if ($candidate) { $summary.DeviceName = $candidate }
                }
            }
        }
    }

    $ipv4Aggregate = New-Object System.Collections.Generic.List[string]
    $gatewayAggregate = New-Object System.Collections.Generic.List[string]
    $dnsAggregate = New-Object System.Collections.Generic.List[string]
    $networkConnections = New-Object System.Collections.Generic.List[pscustomobject]
    $connectionMap = @{}

    $networkArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-adapters'
    if ($networkArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $networkArtifact)
        if ($payload) {
            $getConnectionEntry = {
                param([string]$Alias, [string]$Description)

                $lookup = $Alias
                if (-not $lookup) { $lookup = $Description }
                if (-not $lookup) { return $null }

                try {
                    $key = $lookup.ToLowerInvariant()
                } catch {
                    $key = $lookup.ToLower()
                }

                if (-not $connectionMap.ContainsKey($key)) {
                    $connectionMap[$key] = [ordered]@{
                        Alias            = $Alias
                        Description      = $Description
                        Status           = $null
                        LinkSpeedText    = $null
                        IPv4             = New-Object System.Collections.Generic.List[string]
                        IPv6             = New-Object System.Collections.Generic.List[string]
                        Gateways         = New-Object System.Collections.Generic.List[string]
                        Dns              = New-Object System.Collections.Generic.List[string]
                        MacAddress       = $null
                        DriverInformation = $null
                    }
                } else {
                    $entry = $connectionMap[$key]
                    if (-not $entry.Alias -and $Alias) { $entry.Alias = $Alias }
                    if (-not $entry.Description -and $Description) { $entry.Description = $Description }
                }

                return $connectionMap[$key]
            }

            if ($payload.IPConfig) {
                $configEntries = $payload.IPConfig
                $configError = $false
                if ($configEntries -is [pscustomobject] -and $configEntries.PSObject.Properties['Error'] -and $configEntries.Error) {
                    $configError = $true
                }

                if (-not $configError) {
                    if ($configEntries -isnot [System.Collections.IEnumerable] -or $configEntries -is [string]) {
                        $configEntries = @($configEntries)
                    }

                    foreach ($entry in $configEntries) {
                        if (-not $entry) { continue }

                        $alias = if ($entry.PSObject.Properties['InterfaceAlias']) { [string]$entry.InterfaceAlias } else { $null }
                        $description = if ($entry.PSObject.Properties['InterfaceDescription']) { [string]$entry.InterfaceDescription } else { $alias }
                        $connectionEntry = & $getConnectionEntry $alias $description

                        if ($entry.PSObject.Properties['IPv4Address']) {
                            foreach ($value in Get-AllStrings -Value $entry.IPv4Address) {
                                if (-not $value) { continue }
                                $trimmed = $value.Trim()
                                if (-not $trimmed) { continue }
                                if ($trimmed -match '^169\.254\.') { continue }
                                $ipv4Aggregate.Add($trimmed) | Out-Null
                                if ($connectionEntry) { $connectionEntry.IPv4.Add($trimmed) | Out-Null }
                            }
                        }

                        if ($entry.PSObject.Properties['IPv6Address']) {
                            foreach ($value in Get-AllStrings -Value $entry.IPv6Address) {
                                if (-not $value) { continue }
                                $trimmed = $value.Trim()
                                if (-not $trimmed) { continue }
                                if ($connectionEntry) { $connectionEntry.IPv6.Add($trimmed) | Out-Null }
                            }
                        }

                        if ($entry.PSObject.Properties['IPv4DefaultGateway']) {
                            foreach ($value in Get-AllStrings -Value $entry.IPv4DefaultGateway) {
                                if (-not $value) { continue }
                                $trimmed = $value.Trim()
                                if (-not $trimmed) { continue }
                                $gatewayAggregate.Add($trimmed) | Out-Null
                                if ($connectionEntry) { $connectionEntry.Gateways.Add($trimmed) | Out-Null }
                            }
                        }

                        if ($entry.PSObject.Properties['DNSServer']) {
                            foreach ($value in Get-AllStrings -Value $entry.DNSServer) {
                                if (-not $value) { continue }
                                $trimmed = $value.Trim()
                                if (-not $trimmed) { continue }
                                $dnsAggregate.Add($trimmed) | Out-Null
                                if ($connectionEntry) { $connectionEntry.Dns.Add($trimmed) | Out-Null }
                            }
                        }
                    }
                }
            }

            if ($payload.Adapters) {
                $adapterEntries = $payload.Adapters
                $adapterError = $false
                if ($adapterEntries -is [pscustomobject] -and $adapterEntries.PSObject.Properties['Error'] -and $adapterEntries.Error) {
                    $adapterError = $true
                }

                if (-not $adapterError) {
                    if ($adapterEntries -isnot [System.Collections.IEnumerable] -or $adapterEntries -is [string]) {
                        $adapterEntries = @($adapterEntries)
                    }

                    foreach ($adapter in $adapterEntries) {
                        if (-not $adapter) { continue }

                        $alias = if ($adapter.PSObject.Properties['Name']) { [string]$adapter.Name } else { $null }
                        $description = if ($adapter.PSObject.Properties['InterfaceDescription']) { [string]$adapter.InterfaceDescription } else { $alias }
                        $connectionEntry = & $getConnectionEntry $alias $description
                        if (-not $connectionEntry) { continue }

                        if ($adapter.PSObject.Properties['Status'] -and $adapter.Status) { $connectionEntry.Status = [string]$adapter.Status }
                        if ($adapter.PSObject.Properties['LinkSpeed'] -and $adapter.LinkSpeed) { $connectionEntry.LinkSpeedText = [string]$adapter.LinkSpeed }
                        if ($adapter.PSObject.Properties['MacAddress'] -and $adapter.MacAddress -and -not $connectionEntry.MacAddress) { $connectionEntry.MacAddress = [string]$adapter.MacAddress }
                        if ($adapter.PSObject.Properties['DriverInformation'] -and $adapter.DriverInformation -and -not $connectionEntry.DriverInformation) { $connectionEntry.DriverInformation = [string]$adapter.DriverInformation }
                    }
                }
            }
        }
    }

    if ($connectionMap.Count -gt 0) {
        foreach ($key in $connectionMap.Keys) {
            $entry = $connectionMap[$key]
            $ipv4Values = Convert-ToUniqueStringArray -Values $entry.IPv4
            $ipv6Values = Convert-ToUniqueStringArray -Values $entry.IPv6
            $gatewayValues = Convert-ToUniqueStringArray -Values ($entry.Gateways | Where-Object { $_ -and $_ -ne '0.0.0.0' })
            $dnsValues = Convert-ToUniqueStringArray -Values $entry.Dns
            $statusRank = Get-NetworkStatusRank -Status $entry.Status

            $connection = [pscustomobject]@{
                Alias             = $entry.Alias
                Description       = $entry.Description
                Status            = $entry.Status
                StatusRank        = $statusRank
                LinkSpeed         = if ($entry.LinkSpeedText) { $entry.LinkSpeedText } else { $null }
                IPv4              = $ipv4Values
                IPv6              = $ipv6Values
                Gateways          = $gatewayValues
                DnsServers        = $dnsValues
                HasGateway        = ($gatewayValues.Count -gt 0)
                MacAddress        = $entry.MacAddress
                DriverInformation = $entry.DriverInformation
                ConnectionKind    = $null
            }

            $networkConnections.Add($connection) | Out-Null
        }
    }

    if ($networkConnections.Count -gt 0) {
        $summary.NetworkConnections = $networkConnections.ToArray()
    }

    if ($ipv4Aggregate.Count -gt 0) { $summary.IPv4Addresses = Convert-ToUniqueStringArray -Values $ipv4Aggregate }
    if ($gatewayAggregate.Count -gt 0) { $summary.Gateways = Convert-ToUniqueStringArray -Values ($gatewayAggregate | Where-Object { $_ -and $_ -ne '0.0.0.0' }) }
    if ($dnsAggregate.Count -gt 0) { $summary.DnsServers = Convert-ToUniqueStringArray -Values $dnsAggregate }

    $hasIpv4 = ($summary.IPv4Addresses -and @($summary.IPv4Addresses).Count -gt 0)
    $hasGateway = ($summary.Gateways -and @($summary.Gateways).Count -gt 0)
    $hasDns = ($summary.DnsServers -and @($summary.DnsServers).Count -gt 0)

    if (-not ($hasIpv4 -and $hasGateway -and $hasDns)) {
        if (-not $hostnameArtifact) {
            $hostnameArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network'
        }

        if ($hostnameArtifact) {
            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $hostnameArtifact)
            if ($payload -and $payload.IpConfig) {
                $ipConfigText = $payload.IpConfig
                if ($ipConfigText -isnot [string]) {
                    if ($ipConfigText -is [System.Collections.IEnumerable]) {
                        $ipConfigText = ($ipConfigText -join "`n")
                    } else {
                        $ipConfigText = [string]$ipConfigText
                    }
                }

                if ($ipConfigText) {
                    $parsed = Parse-IpConfigNetworkValues -IpConfigText $ipConfigText
                    if ($parsed) {
                        if (-not $hasIpv4 -and $parsed.IPv4.Count -gt 0) { $summary.IPv4Addresses = $parsed.IPv4 }
                        if (-not $hasGateway -and $parsed.Gateways.Count -gt 0) { $summary.Gateways = $parsed.Gateways }
                        if (-not $hasDns -and $parsed.Dns.Count -gt 0) { $summary.DnsServers = $parsed.Dns }
                    }
                }
            }
        }
    }

    $wifiInterfaceNames = @()
    $wifiArtifact = Get-AnalyzerArtifact -Context $Context -Name 'wlan'
    if ($wifiArtifact) {
        $wifiPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wifiArtifact)
        if ($wifiPayload -and $wifiPayload.PSObject -and $wifiPayload.PSObject.Properties['Interfaces']) {
            $wifiInterfaces = ConvertTo-WlanInterfaceSummaries -Raw $wifiPayload.Interfaces
            if ($wifiInterfaces -and $wifiInterfaces.Count -gt 0) {
                $wifiInterfaceNames = @($wifiInterfaces | Where-Object { $_ -and $_.Name } | ForEach-Object { $_.Name })

                $connectedInterface = $null
                foreach ($interface in $wifiInterfaces) {
                    if (-not $interface) { continue }
                    $stateText = if ($interface.State) { [string]$interface.State } else { '' }
                    $normalizedState = ''
                    if ($stateText) {
                        try { $normalizedState = $stateText.ToLowerInvariant() } catch { $normalizedState = $stateText.ToLower() }
                    }
                    if ($normalizedState -like 'connected*') { $connectedInterface = $interface; break }
                }

                $selectedInterface = if ($connectedInterface) { $connectedInterface } else { $wifiInterfaces[0] }
                if ($selectedInterface) {
                    $summary.WirelessConnection = [pscustomobject]@{
                        Interface      = $selectedInterface.Name
                        State          = $selectedInterface.State
                        Ssid           = $selectedInterface.Ssid
                        Bssid          = $selectedInterface.Bssid
                        Authentication = $selectedInterface.Authentication
                        Cipher         = $selectedInterface.Cipher
                        RadioType      = $selectedInterface.RadioType
                        ConnectionMode = $selectedInterface.ConnectionMode
                        Profile        = $selectedInterface.Profile
                    }
                }
            }
        }
    }

    if (-not $wifiInterfaceNames) { $wifiInterfaceNames = @() }

    if ($summary.NetworkConnections -and $summary.NetworkConnections.Count -gt 0) {
        foreach ($connection in $summary.NetworkConnections) {
            $connection.ConnectionKind = Get-NetworkConnectionKind -Alias $connection.Alias -Description $connection.Description -WirelessAliases $wifiInterfaceNames
        }

        $sortedConnections = $summary.NetworkConnections | Sort-Object -Property `
            @{ Expression = { if ($_.HasGateway) { 1 } else { 0 } }; Descending = $true }, `
            @{ Expression = { if ($_.StatusRank) { $_.StatusRank } else { 0 } }; Descending = $true }, `
            @{ Expression = { switch ($_.ConnectionKind) { 'Wired' { 2 } 'Wireless' { 2 } 'Bluetooth' { 1 } default { 0 } } }; Descending = $true }, `
            @{ Expression = { if ($_.IPv4 -and ($_.IPv4 -is [array])) { $_.IPv4.Length } elseif ($_.IPv4) { 1 } else { 0 } }; Descending = $true }

        $sortedConnections = @($sortedConnections)
        if ($sortedConnections.Count -gt 0) {
            $summary.PrimaryConnection = $sortedConnections[0]
        }
    }

    $domainText = if ($summary.Domain) { $summary.Domain } else { 'Unknown' }
    $partOfDomain = if ($null -ne $summary.IsDomainJoined) { [bool]$summary.IsDomainJoined } else { $false }
    $summary.DeviceState = Format-DeviceState -Domain $domainText -PartOfDomain $partOfDomain -IsAzureAdJoined $summary.IsAzureAdJoined

    if (-not $summary.DeviceName) { $summary.DeviceName = 'Unknown' }
    if (-not $summary.OperatingSystem) { $summary.OperatingSystem = 'Unknown' }

    return [pscustomobject]$summary
}
