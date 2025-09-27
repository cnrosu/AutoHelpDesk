<#!
.SYNOPSIS
    Network diagnostics heuristics covering connectivity, DNS, proxy, and Outlook health.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Test-NetworkPrivateIpv4 {
    param([string]$Address)

    if (-not $Address) { return $false }
    if ($Address -match '^10\.') { return $true }
    if ($Address -match '^192\.168\.') { return $true }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.'){ return $true }
    return $false
}

function Test-NetworkLoopback {
    param([string]$Address)

    if (-not $Address) { return $false }
    return ($Address -match '^127\.')
}

function Test-NetworkValidIpv4Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $trimmed = $Address.Trim()
    if (-not $trimmed) { return $false }

    $clean = $trimmed -replace '/\d+$',''
    $clean = $clean -replace '%.*$',''

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    if ($clean -match '^(0\.0\.0\.0|169\.254\.)') { return $false }

    return $true
}

function Test-NetworkValidIpv6Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $trimmed = $Address.Trim()
    if (-not $trimmed) { return $false }

    $clean = $trimmed -replace '/\d+$',''
    $clean = $clean -replace '%.*$',''

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $false }
    if ($clean -match '^(?i)(::1|::|fe80:)') { return $false }

    return $true
}

function ConvertTo-NetworkArray {
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

function Get-NetworkValueText {
    param($Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [string]) {
        $trimmed = $Value.Trim()
        if ($trimmed) { return @($trimmed) }
        return @()
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $results = @()
        foreach ($item in $Value) { $results += Get-NetworkValueText $item }
        return $results
    }

    if ($Value -is [hashtable]) {
        $results = @()
        foreach ($item in $Value.Values) { $results += Get-NetworkValueText $item }
        return $results
    }

    if ($Value.PSObject) {
        $results = @()
        foreach ($name in @('IPAddress','IPv4Address','IPv6Address','Address','NextHop','Value')) {
            if ($Value.PSObject.Properties[$name]) {
                $results += Get-NetworkValueText ($Value.$name)
            }
        }

        if ($results.Count -gt 0) { return $results }
    }

    $text = [string]$Value
    if ($text) {
        $trimmed = $text.Trim()
        if ($trimmed) { return @($trimmed) }
    }

    return @()
}

function Test-NetworkPseudoInterface {
    param(
        [string]$Alias,
        [string]$Description
    )

    $candidates = @()
    if ($Alias) { $candidates += $Alias }
    if ($Description) { $candidates += $Description }

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }

        try {
            $normalized = $candidate.ToLowerInvariant()
        } catch {
            $normalized = [string]$candidate
            if ($normalized) { $normalized = $normalized.ToLowerInvariant() }
        }

        if (-not $normalized) { continue }

        $patterns = @(
            'loopback',
            'pseudo-interface',
            'local area connection\*',
            'isatap',
            'teredo',
            '6to4',
            'tunnel',
            'vethernet',
            'hyper-v',
            'wan miniport',
            'npcap',
            'wireshark',
            '\bwfp\b',
            'wireguard',
            'tailscale',
            'openvpn',
            'zerotier',
            'expressvpn',
            'protonvpn',
            'cloudflare warp',
            'docker',
            'container',
            'virtualbox',
            'vmware',
            'tap-',
            'l2tp',
            'pppoe',
            'teamviewer'
        )

        foreach ($pattern in $patterns) {
            if ($normalized -match $pattern) { return $true }
        }
    }

    return $false
}

function Test-NetworkErrorEntry {
    param($Value)

    if (-not $Value) { return $false }

    try {
        if ($Value.PSObject -and $Value.PSObject.Properties['Error'] -and $Value.Error) { return $true }
    } catch {
        return $false
    }

    return $false
}

function ConvertTo-NetworkDateTime {
    param([string]$Value)

    if (-not $Value) { return $null }

    try {
        $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
        return [datetime]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    } catch {
        try {
            return [datetime]::Parse($Value)
        } catch {
            return $null
        }
    }
}

function Get-NetworkWifiRoamSummary {
    param(
        [System.Collections.IEnumerable]$Events,
        [int]$LookbackMinutes = 30
    )

    $lookback = [math]::Abs($LookbackMinutes)
    $windowStart = (Get-Date).AddMinutes(-$lookback)

    $observations = New-Object System.Collections.Generic.List[pscustomobject]
    if (-not $Events) {
        return [pscustomobject]@{
            LookbackMinutes   = $lookback
            SampleCount       = 0
            RoamCount         = 0
            UniqueBssidCount  = 0
            Observations      = @()
        }
    }

    foreach ($event in $Events) {
        if (-not $event) { continue }

        $time = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $time = ConvertTo-NetworkDateTime -Value $event.TimeCreated
        }

        if (-not $time) { continue }
        if ($time -lt $windowStart) { continue }

        $bssid = $null
        foreach ($field in @('NewBssid','TargetBssid','Bssid')) {
            if ($event.PSObject.Properties[$field] -and $event.$field) {
                try {
                    $bssid = ([string]$event.$field).ToLowerInvariant()
                } catch {
                    $bssid = [string]$event.$field
                }
                if ($bssid) { $bssid = $bssid -replace '-', ':' }
                break
            }
        }

        if (-not $bssid -and $event.PSObject.Properties['Properties']) {
            $propertyValues = ConvertTo-NetworkArray $event.Properties
            foreach ($value in $propertyValues) {
                if (-not $value) { continue }
                if ($value -match '(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}') {
                    $candidate = ($value -replace '-', ':').ToLowerInvariant()
                    if ($candidate) { $bssid = $candidate; break }
                }
            }
        }

        if (-not $bssid) { continue }

        $ssidValue = $null
        if ($event.PSObject.Properties['Ssid'] -and $event.Ssid) {
            $ssidValue = [string]$event.Ssid
        }

        $observations.Add([pscustomobject]@{
                Time    = $time
                Bssid   = $bssid
                EventId = if ($event.PSObject.Properties['Id']) { try { [int]$event.Id } catch { $event.Id } } else { $null }
                Ssid    = $ssidValue
            }) | Out-Null
    }

    if ($observations.Count -eq 0) {
        return [pscustomobject]@{
            LookbackMinutes   = $lookback
            SampleCount       = 0
            RoamCount         = 0
            UniqueBssidCount  = 0
            Observations      = @()
        }
    }

    $sorted = $observations | Sort-Object -Property Time
    $lastBssid = $null
    $changes = 0
    $evidence = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($item in $sorted) {
        if ($item.Bssid) {
            if ($lastBssid -and $item.Bssid -ne $lastBssid) { $changes++ }
            $lastBssid = $item.Bssid
        }

        $evidence.Add([pscustomobject]@{
                TimeCreated = $item.Time.ToString('o')
                Bssid       = $item.Bssid
                EventId     = $item.EventId
                Ssid        = $item.Ssid
            }) | Out-Null
    }

    $uniqueBssids = ($evidence | Where-Object { $_.Bssid } | Select-Object -ExpandProperty Bssid -Unique)

    return [pscustomobject]@{
        LookbackMinutes   = $lookback
        SampleCount       = $evidence.Count
        RoamCount         = $changes
        UniqueBssidCount  = $uniqueBssids.Count
        Observations      = $evidence.ToArray()
    }
}

function Get-NetworkDnsInterfaceInventory {
    param($AdapterPayload)

    $map = @{}

    $statusMap = @{}
    $descriptionMap = @{}
    $aliasMap = @{}

    if ($AdapterPayload -and $AdapterPayload.Adapters -and -not $AdapterPayload.Adapters.Error) {
        $adapterEntries = ConvertTo-NetworkArray $AdapterPayload.Adapters
        foreach ($adapter in $adapterEntries) {
            if (-not $adapter) { continue }
            $name = if ($adapter.PSObject.Properties['Name']) { [string]$adapter.Name } else { $null }
            if (-not $name) { continue }

            $key = $name.ToLowerInvariant()
            $status = if ($adapter.PSObject.Properties['Status']) { [string]$adapter.Status } else { $null }
            $statusMap[$key] = $status
            $aliasMap[$key] = $name

            if ($adapter.PSObject.Properties['InterfaceDescription']) {
                $descriptionMap[$key] = [string]$adapter.InterfaceDescription
            }
        }
    }

    if ($AdapterPayload -and $AdapterPayload.IPConfig -and -not $AdapterPayload.IPConfig.Error) {
        $configEntries = ConvertTo-NetworkArray $AdapterPayload.IPConfig
        foreach ($entry in $configEntries) {
            if (-not $entry) { continue }
            $alias = if ($entry.PSObject.Properties['InterfaceAlias']) { [string]$entry.InterfaceAlias } else { $null }
            if (-not $alias) { continue }

            $key = $alias.ToLowerInvariant()
            if (-not $map.ContainsKey($key)) {
                $map[$key] = [ordered]@{
                    Alias       = $alias
                    Description = if ($entry.PSObject.Properties['InterfaceDescription']) { [string]$entry.InterfaceDescription } else { $null }
                    Status      = $null
                    IPv4        = @()
                    IPv6        = @()
                    Gateways    = @()
                }
            }

            $info = $map[$key]

            if (-not $info.Description -and $entry.PSObject.Properties['InterfaceDescription']) {
                $info.Description = [string]$entry.InterfaceDescription
            }

            if ($entry.PSObject.Properties['IPv4Address']) {
                foreach ($value in Get-NetworkValueText $entry.IPv4Address) {
                    if (-not ($info.IPv4 -contains $value)) { $info.IPv4 += $value }
                }
            }

            if ($entry.PSObject.Properties['IPv6Address']) {
                foreach ($value in Get-NetworkValueText $entry.IPv6Address) {
                    if (-not ($info.IPv6 -contains $value)) { $info.IPv6 += $value }
                }
            }

            if ($entry.PSObject.Properties['IPv4DefaultGateway']) {
                foreach ($value in Get-NetworkValueText $entry.IPv4DefaultGateway) {
                    if (-not ($info.Gateways -contains $value)) { $info.Gateways += $value }
                }
            }
        }
    }

    foreach ($key in $statusMap.Keys) {
        if (-not $map.ContainsKey($key)) {
            $alias = if ($aliasMap.ContainsKey($key)) { $aliasMap[$key] } else { $key }
            $map[$key] = [ordered]@{
                Alias       = $alias
                Description = if ($descriptionMap.ContainsKey($key)) { $descriptionMap[$key] } else { $null }
                Status      = $null
                IPv4        = @()
                IPv6        = @()
                Gateways    = @()
            }
        }

        $info = $map[$key]
        $info.Status = $statusMap[$key]
        if (-not $info.Description -and $descriptionMap.ContainsKey($key)) {
            $info.Description = $descriptionMap[$key]
        }
    }

    $eligible = New-Object System.Collections.Generic.List[string]
    $fallbackEligible = New-Object System.Collections.Generic.List[string]

    foreach ($key in $map.Keys) {
        $info = $map[$key]
        $statusText = if ($info.Status) { [string]$info.Status } else { '' }
        $normalizedStatus = if ($statusText) { $statusText.ToLowerInvariant() } else { '' }
        $isUp = ($normalizedStatus -eq 'up' -or $normalizedStatus -eq 'connected' -or $normalizedStatus -like 'up*')

        $hasIpv4 = ($info.IPv4 | Where-Object { Test-NetworkValidIpv4Address $_ }).Count -gt 0
        $hasIpv6 = ($info.IPv6 | Where-Object { Test-NetworkValidIpv6Address $_ }).Count -gt 0
        $hasGateway = ($info.Gateways | Where-Object { Test-NetworkValidIpv4Address $_ }).Count -gt 0
        $isPseudo = Test-NetworkPseudoInterface -Alias $info.Alias -Description $info.Description

        $info.IsUp = $isUp
        $info.HasValidAddress = ($hasIpv4 -or $hasIpv6)
        $info.HasGateway = $hasGateway
        $info.IsPseudo = $isPseudo
        $info.IsEligible = ($isUp -and ($hasIpv4 -or $hasIpv6) -and $hasGateway -and -not $isPseudo)
        $info.IsFallbackEligible = ($isUp -and ($hasIpv4 -or $hasIpv6) -and -not $isPseudo)

        if ($info.IsEligible) { $eligible.Add($info.Alias) | Out-Null }
        if ($info.IsFallbackEligible) { $fallbackEligible.Add($info.Alias) | Out-Null }
    }

    return [pscustomobject]@{
        Map                     = $map
        EligibleAliases         = $eligible.ToArray()
        FallbackEligibleAliases = $fallbackEligible.ToArray()
    }
}

function ConvertTo-NetworkAddressString {
    param($RemoteAddress)

    if (-not $RemoteAddress) { return $null }

    if ($RemoteAddress -is [string]) { return $RemoteAddress }
    if ($RemoteAddress -is [System.Net.IPAddress]) { return $RemoteAddress.ToString() }

    if ($RemoteAddress.PSObject -and $RemoteAddress.PSObject.Properties['Address']) {
        $addressValue = $RemoteAddress.Address

        if ($addressValue -is [string] -and $addressValue) { return $addressValue }
        if ($addressValue -is [byte[]] -and $addressValue.Length -gt 0) {
            try { return ([System.Net.IPAddress]::new($addressValue)).ToString() } catch {}
        }

        try {
            if ($null -ne $addressValue) {
                return ([System.Net.IPAddress]::new([int64]$addressValue)).ToString()
            }
        } catch {
            # fall through to default conversion
        }
    }

    return [string]$RemoteAddress
}

function ConvertTo-KebabCase {
    param([string]$Text)

    if (-not $Text) { return $Text }

    $normalized = $Text -replace '([a-z0-9])([A-Z])', '$1-$2'
    $normalized = $normalized -replace '([A-Z]+)([A-Z][a-z])', '$1-$2'

    return $normalized.ToLowerInvariant()
}

function Invoke-DhcpAnalyzers {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult
    )

    if (-not $Context -or -not $Context.Artifacts) { return }

    $dhcpKeys = @($Context.Artifacts.Keys | Where-Object { $_ -like 'dhcp-*' })
    if ($dhcpKeys.Count -eq 0) { return }

    $firstKey = $dhcpKeys | Select-Object -First 1
    if (-not $firstKey) { return }

    $firstEntry = $Context.Artifacts[$firstKey] | Select-Object -First 1
    if (-not $firstEntry -or -not $firstEntry.Path) { return }

    $inputFolder = Split-Path -Path $firstEntry.Path -Parent
    if (-not $inputFolder -or -not (Test-Path -LiteralPath $inputFolder)) { return }

    $analyzerRoot = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'Network/DHCP'
    if (-not (Test-Path -LiteralPath $analyzerRoot)) { return }

    $scriptFiles = Get-ChildItem -Path $analyzerRoot -Filter 'Analyze-Dhcp*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name
    if (-not $scriptFiles -or $scriptFiles.Count -eq 0) { return }

    $eligibleAnalyzers = @()
    foreach ($script in $scriptFiles) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script.Name)
        if (-not $baseName.StartsWith('Analyze-')) { continue }
        $suffix = $baseName.Substring(8)
        if (-not $suffix) { continue }

        $artifactBase = ConvertTo-KebabCase $suffix
        if (-not $artifactBase) { continue }

        $artifactPath = Join-Path -Path $inputFolder -ChildPath ($artifactBase + '.json')
        if (Test-Path -LiteralPath $artifactPath) {
            $eligibleAnalyzers += [pscustomobject]@{
                Script       = $script
                ArtifactBase = $artifactBase
                ArtifactPath = (Resolve-Path -LiteralPath $artifactPath).ProviderPath
            }
        }
    }

    if ($eligibleAnalyzers.Count -eq 0) { return }

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($analyzer in $eligibleAnalyzers) {
        try {
            $result = & $analyzer.Script.FullName -InputFolder $inputFolder
        } catch {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title ("DHCP analyzer failed: {0}" -f $analyzer.Script.Name) -Evidence $_.Exception.Message -Subcategory 'DHCP'
            continue
        }

        if ($null -eq $result) { continue }

        if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
            foreach ($item in $result) {
                if ($null -ne $item) { $findings.Add($item) | Out-Null }
            }
        } else {
            $findings.Add($result) | Out-Null
        }
    }

    if ($findings.Count -gt 0) {
        foreach ($finding in $findings) {
            if (-not $finding) { continue }

            $severity = if ($finding.PSObject.Properties['Severity'] -and $finding.Severity) { [string]$finding.Severity } else { 'info' }
            $title = if ($finding.PSObject.Properties['Message'] -and $finding.Message) {
                    [string]$finding.Message
                } elseif ($finding.PSObject.Properties['Check'] -and $finding.Check) {
                    [string]$finding.Check
                } else {
                    'DHCP finding'
                }
            $evidence = if ($finding.PSObject.Properties['Evidence']) { $finding.Evidence } else { $null }
            $subcategory = if ($finding.PSObject.Properties['Subcategory'] -and $finding.Subcategory) { [string]$finding.Subcategory } else { 'DHCP' }

            if ($severity -in @('good', 'ok', 'normal')) {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title $title -Evidence $evidence -Subcategory $subcategory
            } else {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title $title -Evidence $evidence -Subcategory $subcategory
            }
        }
    } else {
        $evidence = [ordered]@{
            Checks = ($eligibleAnalyzers | ForEach-Object { $_.ArtifactBase })
            Folder = $inputFolder
        }

        Add-CategoryNormal -CategoryResult $CategoryResult -Title ("DHCP diagnostics healthy ({0} checks)" -f $eligibleAnalyzers.Count) -Evidence $evidence -Subcategory 'DHCP'
    }
}

function Invoke-NetworkHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Network'

    $computerSystem = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($systemPayload -and $systemPayload.ComputerSystem -and -not $systemPayload.ComputerSystem.Error) {
            $computerSystem = $systemPayload.ComputerSystem
        }
    }

    $domainJoined = $null
    if ($computerSystem -and $computerSystem.PSObject.Properties['PartOfDomain']) {
        try {
            $domainJoined = [bool]$computerSystem.PartOfDomain
        } catch {
            $domainJoined = $computerSystem.PartOfDomain
        }
    }

    $adapterPayload = $null
    $adapterInventory = $null
    $adapterArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-adapters'
    if ($adapterArtifact) {
        $adapterPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $adapterArtifact)
    }
    $adapterInventory = Get-NetworkDnsInterfaceInventory -AdapterPayload $adapterPayload

    $profileArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-profiles'
    $connectionProfiles = @()
    if ($profileArtifact) {
        $profilePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $profileArtifact)
        if ($profilePayload) {
            if (-not $computerSystem -and $profilePayload.PSObject -and $profilePayload.PSObject.Properties['ComputerSystem'] -and $profilePayload.ComputerSystem -and -not $profilePayload.ComputerSystem.Error) {
                $computerSystem = $profilePayload.ComputerSystem
                if ($computerSystem.PSObject.Properties['PartOfDomain']) {
                    try {
                        $domainJoined = [bool]$computerSystem.PartOfDomain
                    } catch {
                        $domainJoined = $computerSystem.PartOfDomain
                    }
                }
            }

            if ($profilePayload.PSObject.Properties['ConnectionProfiles'] -and $profilePayload.ConnectionProfiles) {
                $profilesArray = ConvertTo-NetworkArray $profilePayload.ConnectionProfiles
                $profileErrors = $profilesArray | Where-Object { $_ -and $_.PSObject -and $_.PSObject.Properties['Error'] -and $_.Error }
                if ($profilesArray.Count -eq 1 -and $profileErrors.Count -eq 1) {
                    $source = if ($profileErrors[0].PSObject.Properties['Source']) { $profileErrors[0].Source } else { 'Get-NetConnectionProfile' }
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate network connection profiles' -Evidence ("{0}: {1}" -f $source, $profileErrors[0].Error) -Subcategory 'Network Profiles'
                } else {
                    foreach ($profile in $profilesArray) {
                        if (-not $profile) { continue }
                        if ($profile.PSObject.Properties['Error'] -and $profile.Error) { continue }
                        $connectionProfiles += $profile
                    }
                }
            }

            if (-not $domainJoined -and $profilePayload.PSObject.Properties['ComputerSystem'] -and $profilePayload.ComputerSystem) {
                $cs = $profilePayload.ComputerSystem
                if ($cs.PSObject.Properties['Error'] -and $cs.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to determine domain membership state' -Evidence $cs.Error -Subcategory 'Network Profiles'
                } elseif ($cs.PSObject.Properties['PartOfDomain']) {
                    try {
                        $domainJoined = [bool]$cs.PartOfDomain
                    } catch {
                        $domainJoined = $cs.PartOfDomain
                    }
                }
            }
        }
    }

    if ($connectionProfiles.Count -gt 0 -and $domainJoined -eq $true) {
        $profileEvidence = @()
        foreach ($profile in $connectionProfiles) {
            $profileEvidence += [pscustomobject]@{
                Name           = if ($profile.PSObject.Properties['Name']) { [string]$profile.Name } else { $null }
                InterfaceAlias = if ($profile.PSObject.Properties['InterfaceAlias']) { [string]$profile.InterfaceAlias } else { $null }
                NetworkCategory = if ($profile.PSObject.Properties['NetworkCategory']) { [string]$profile.NetworkCategory } else { $null }
            }
        }

        $publicProfiles = $profileEvidence | Where-Object { $_.NetworkCategory -eq 'Public' }
        if ($publicProfiles.Count -gt 0) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Domain-joined device connected to public network' -Evidence $profileEvidence -Subcategory 'Network Profiles'
            Add-CategoryCheck -CategoryResult $result -Name 'Network profile categories' -Status 'Issue' -Details 'Public network profile detected on a domain-joined device.' -CheckId 'Network/ProfileCategory'
        } else {
            Add-CategoryNormal -CategoryResult $result -Title 'Network profiles private or domain authenticated' -Evidence $profileEvidence -Subcategory 'Network Profiles'
            Add-CategoryCheck -CategoryResult $result -Name 'Network profile categories' -Status 'Good' -Details 'All active profiles are DomainAuthenticated or Private.' -CheckId 'Network/ProfileCategory'
        }
    } elseif ($connectionProfiles.Count -gt 0 -and $domainJoined -ne $true) {
        $profileEvidence = @()
        foreach ($profile in $connectionProfiles) {
            $profileEvidence += [pscustomobject]@{
                Name           = if ($profile.PSObject.Properties['Name']) { [string]$profile.Name } else { $null }
                InterfaceAlias = if ($profile.PSObject.Properties['InterfaceAlias']) { [string]$profile.InterfaceAlias } else { $null }
                NetworkCategory = if ($profile.PSObject.Properties['NetworkCategory']) { [string]$profile.NetworkCategory } else { $null }
            }
        }

        Add-CategoryCheck -CategoryResult $result -Name 'Network profile categories' -Status 'Not domain joined' -Details 'Device is not domain-joined; network profile category check skipped.' -CheckId 'Network/ProfileCategory'
    } elseif ($domainJoined -eq $true -and $connectionProfiles.Count -eq 0) {
        Add-CategoryCheck -CategoryResult $result -Name 'Network profile categories' -Status 'Unknown' -Details 'No network connection profiles were collected.' -CheckId 'Network/ProfileCategory'
    }

    $networkArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network'
    if ($networkArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $networkArtifact)
        if ($payload -and $payload.IpConfig) {
            $ipText = if ($payload.IpConfig -is [string[]]) { $payload.IpConfig -join "`n" } else { [string]$payload.IpConfig }
            if ($ipText -match 'IPv4 Address') {
                Add-CategoryNormal -CategoryResult $result -Title 'IPv4 addressing detected'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No IPv4 configuration found' -Evidence 'ipconfig /all output did not include IPv4 details.' -Subcategory 'IP Configuration'
            }
        }

        if ($payload -and $payload.Route) {
            $routeText = if ($payload.Route -is [string[]]) { $payload.Route -join "`n" } else { [string]$payload.Route }
            if ($routeText -notmatch '0\.0\.0\.0') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Routing table missing default route' -Evidence 'route print output did not include 0.0.0.0/0.' -Subcategory 'Routing'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Network base diagnostics not collected' -Subcategory 'Collection'
    }

    $dnsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'dns'
    if ($dnsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $dnsArtifact)
        if ($payload -and $payload.Resolution) {
            $failures = $payload.Resolution | Where-Object { $_.Success -eq $false }
            if ($failures.Count -gt 0) {
                $names = $failures | Select-Object -ExpandProperty Name
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('DNS lookup failures: {0}' -f ($names -join ', ')) -Subcategory 'DNS Resolution'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'DNS lookups succeeded'
            }
        }

        if ($payload -and $payload.Latency) {
            $latency = $payload.Latency
            if ($latency.PSObject.Properties['PingSucceeded']) {
                $remoteAddress = ConvertTo-NetworkAddressString $latency.RemoteAddress
                if (-not $remoteAddress) { $remoteAddress = 'DNS server' }
                if (-not $latency.PingSucceeded) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Ping to DNS {0} failed' -f $remoteAddress) -Subcategory 'Latency'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title ('Ping to DNS {0} succeeded' -f $remoteAddress)
                }
            } elseif ($latency -is [string] -and $latency -match 'Request timed out') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Latency test reported timeouts' -Subcategory 'Latency'
            }
        }

        if ($payload -and $payload.Autodiscover) {
            $autoErrors = $payload.Autodiscover | Where-Object { $_.Error }
            if ($autoErrors.Count -gt 0) {
                $details = $autoErrors | Select-Object -ExpandProperty Error -First 3
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Autodiscover DNS queries failed' -Evidence ($details -join "`n") -Subcategory 'DNS Autodiscover'
            }
        }

        if ($payload -and $payload.ClientServers) {
            $entries = ConvertTo-NetworkArray $payload.ClientServers
            $publicServers = New-Object System.Collections.Generic.List[string]
            $loopbackOnly = $true
            $missingInterfaces = @()
            $ignoredPseudo = @()

            $interfaceMap = if ($adapterInventory -and $adapterInventory.Map) { $adapterInventory.Map } else { @{} }
            $eligibleAliases = if ($adapterInventory -and $adapterInventory.EligibleAliases) { $adapterInventory.EligibleAliases } else { @() }
            $fallbackEligibleAliases = if ($adapterInventory -and $adapterInventory.FallbackEligibleAliases) { $adapterInventory.FallbackEligibleAliases } else { @() }
            $useFallbackEligibility = ($eligibleAliases.Count -eq 0 -and $fallbackEligibleAliases.Count -gt 0)

            foreach ($entry in $entries) {
                if ($entry -and $entry.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate DNS servers' -Evidence $entry.Error -Subcategory 'DNS Client'
                    continue
                }

                $alias = if ($entry.InterfaceAlias) { [string]$entry.InterfaceAlias } else { 'Interface' }
                $addresses = ConvertTo-NetworkArray $entry.ServerAddresses | Where-Object { $_ }
                $aliasKey = $null
                if ($alias) {
                    try { $aliasKey = $alias.ToLowerInvariant() } catch { $aliasKey = $alias }
                }
                $interfaceInfo = $null
                if ($aliasKey -and $interfaceMap.ContainsKey($aliasKey)) {
                    $interfaceInfo = $interfaceMap[$aliasKey]
                }

                $isEligible = $true
                if ($interfaceInfo) {
                    if ($useFallbackEligibility) {
                        $isEligible = $interfaceInfo.IsFallbackEligible
                    } else {
                        $isEligible = $interfaceInfo.IsEligible
                    }
                } else {
                    $isEligible = -not (Test-NetworkPseudoInterface -Alias $alias)
                }

                if (-not $addresses -or $addresses.Count -eq 0) {
                    if ($isEligible) {
                        if (-not ($missingInterfaces -contains $alias)) { $missingInterfaces += $alias }
                    } elseif (($interfaceInfo -and $interfaceInfo.IsPseudo) -or (Test-NetworkPseudoInterface -Alias $alias -Description $(if ($interfaceInfo) { $interfaceInfo.Description } else { $null }))) {
                        if (-not ($ignoredPseudo -contains $alias)) { $ignoredPseudo += $alias }
                    }
                    continue
                }

                $loopbackForInterface = $true
                foreach ($address in $addresses) {
                    if (-not (Test-NetworkLoopback $address)) { $loopbackForInterface = $false }
                    if (-not (Test-NetworkPrivateIpv4 $address) -and -not (Test-NetworkLoopback $address)) {
                        $publicServers.Add($address) | Out-Null
                    }
                }

                if (-not $loopbackForInterface) { $loopbackOnly = $false }
                Add-CategoryCheck -CategoryResult $result -Name ("DNS servers ({0})" -f $alias) -Status (($addresses | Select-Object -First 3) -join ', ')
            }

            if ($missingInterfaces.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Adapters missing DNS servers: {0}' -f ($missingInterfaces -join ', ')) -Subcategory 'DNS Client'
            }

            if ($ignoredPseudo.Count -gt 0) {
                $pseudoTitle = "Ignored {0} pseudo/virtual adapters (loopback/ICS/Hyper-V) without DNS — not used for normal name resolution." -f $ignoredPseudo.Count
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $pseudoTitle -Evidence ($ignoredPseudo -join ', ') -Subcategory 'DNS Client'
            }

            if ($publicServers.Count -gt 0) {
                $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                $unique = ($publicServers | Select-Object -Unique)
                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ('Public DNS servers detected: {0}' -f ($unique -join ', ')) -Evidence 'Prioritize internal DNS for domain services.' -Subcategory 'DNS Client'
            } elseif (-not $loopbackOnly) {
                Add-CategoryNormal -CategoryResult $result -Title 'Private DNS servers detected'
            }
        }

        if ($payload -and $payload.ClientPolicies) {
            $policies = ConvertTo-NetworkArray $payload.ClientPolicies
            foreach ($policy in $policies) {
                if ($policy -and $policy.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'DNS client policy query failed' -Evidence $policy.Error -Subcategory 'DNS Client'
                    continue
                }

                $alias = if ($policy.InterfaceAlias) { [string]$policy.InterfaceAlias } else { 'Interface' }
                $suffix = $policy.ConnectionSpecificSuffix
                if ($suffix) {
                    Add-CategoryCheck -CategoryResult $result -Name ("DNS suffix ({0})" -f $alias) -Status $suffix
                }

                if ($policy.PSObject.Properties['RegisterThisConnectionsAddress']) {
                    $register = $policy.RegisterThisConnectionsAddress
                    if ($register -eq $false -and $computerSystem -and $computerSystem.PartOfDomain -eq $true) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("DNS registration disabled on {0}" -f $alias) -Evidence 'RegisterThisConnectionsAddress = False' -Subcategory 'DNS Client'
                    }
                }
            }
        }
    }

    $outlookArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-connectivity'
    if ($outlookArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $outlookArtifact)
        if ($payload -and $payload.Connectivity) {
            $conn = $payload.Connectivity
            if ($conn.PSObject.Properties['TcpTestSucceeded']) {
                if (-not $conn.TcpTestSucceeded) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Outlook HTTPS connectivity failed' -Evidence ('TcpTestSucceeded reported False for {0}' -f $conn.RemoteAddress) -Subcategory 'Outlook Connectivity'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title 'Outlook HTTPS connectivity succeeded'
                }
            } elseif ($conn.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to test Outlook connectivity' -Evidence $conn.Error -Subcategory 'Outlook Connectivity'
            }
        }

        if ($payload -and $payload.OstFiles) {
            $largeOst = $payload.OstFiles | Where-Object { $_.Length -gt 25GB }
            if ($largeOst.Count -gt 0) {
                $names = $largeOst | Select-Object -ExpandProperty Name
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Large OST files detected: {0}' -f ($names -join ', ')) -Subcategory 'Outlook Data Files'
            } elseif ($payload.OstFiles.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('OST files present ({0})' -f $payload.OstFiles.Count)
            }
        }
    }

    $autodiscoverArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autodiscover-dns'
    if ($autodiscoverArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autodiscoverArtifact)
        if ($payload -and $payload.Results) {
            foreach ($domainEntry in (ConvertTo-NetworkArray $payload.Results)) {
                if (-not $domainEntry) { continue }
                $domain = $domainEntry.Domain
                $lookups = ConvertTo-NetworkArray $domainEntry.Lookups
                $autoRecord = $lookups | Where-Object { $_.Label -eq 'Autodiscover' } | Select-Object -First 1
                if (-not $autoRecord) { continue }

                $targetsRaw = ConvertTo-NetworkArray $autoRecord.Targets
                if ($autoRecord.Success -eq $true -and $targetsRaw.Count -gt 0) {
                    $targets = ($targetsRaw | Where-Object { $_ })
                    $targetText = $targets -join ', '
                    if ($targets -match 'autodiscover\.outlook\.com') {
                        Add-CategoryNormal -CategoryResult $result -Title ("Autodiscover healthy for {0}" -f $domain) -Evidence $targetText
                    } else {
                        $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'medium' } else { 'low' }
                        Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover for {0} targets {1}" -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.' -Subcategory 'Autodiscover DNS'
                    }
                } elseif ($autoRecord.Success -eq $false) {
                    $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                    $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover lookup failed for {0}" -f $domain) -Evidence $evidence -Subcategory 'Autodiscover DNS'
                }

                foreach ($additional in ($lookups | Where-Object { $_.Label -ne 'Autodiscover' })) {
                    if (-not $additional) { continue }
                    if ($additional.Success -eq $false -and $additional.Error) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("{0} record missing for {1}" -f $additional.Label, $domain) -Evidence $additional.Error -Subcategory 'Autodiscover DNS'
                    }
                }
            }
        }
    }

    if ($adapterPayload -and $adapterPayload.Adapters -and -not $adapterPayload.Adapters.Error) {
        $upAdapters = $adapterPayload.Adapters | Where-Object { $_.Status -eq 'Up' }
        if ($upAdapters.Count -gt 0) {
            Add-CategoryNormal -CategoryResult $result -Title ('Active adapters: {0}' -f ($upAdapters | Select-Object -ExpandProperty Name -join ', '))
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No active network adapters reported' -Subcategory 'Network Adapters'
        }
    }

    $proxyArtifact = Get-AnalyzerArtifact -Context $Context -Name 'proxy'
    if ($proxyArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $proxyArtifact)
        if ($payload -and $payload.Internet) {
            $internet = $payload.Internet
            if ($internet.ProxyEnable -eq 1 -and $internet.ProxyServer) {
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ('User proxy enabled: {0}' -f $internet.ProxyServer) -Subcategory 'Proxy Configuration'
            } elseif ($internet.ProxyEnable -eq 0) {
                Add-CategoryNormal -CategoryResult $result -Title 'User proxy disabled'
            }
        }

        if ($payload -and $payload.WinHttp) {
            $winHttpText = if ($payload.WinHttp -is [string[]]) { $payload.WinHttp -join "`n" } else { [string]$payload.WinHttp }
            if ($winHttpText -match 'Direct access') {
                Add-CategoryNormal -CategoryResult $result -Title 'WinHTTP proxy: Direct access'
            } elseif ($winHttpText) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WinHTTP proxy configured' -Evidence $winHttpText -Subcategory 'Proxy Configuration'
            }
        }
    }

    $wifiArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-wifi'
    if ($wifiArtifact) {
        $wifiPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wifiArtifact)

        $wifiInterfacesSection = $null
        if ($wifiPayload -and $wifiPayload.PSObject.Properties['Interfaces']) {
            $wifiInterfacesSection = $wifiPayload.Interfaces
        }

        $wifiRaw = $null
        if ($wifiInterfacesSection -and $wifiInterfacesSection.PSObject.Properties['Raw']) {
            $wifiRaw = $wifiInterfacesSection.Raw
        }

        if ($wifiRaw -and (Test-NetworkErrorEntry $wifiRaw)) {
            $rawError = if ($wifiRaw.PSObject.Properties['Error']) { [string]$wifiRaw.Error } else { 'Failed to query Wi-Fi interfaces.' }
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to collect Wi-Fi interface details' -Evidence $rawError -Subcategory 'Wi-Fi Quality'
        }

        $wifiSamples = @()
        if ($wifiInterfacesSection -and $wifiInterfacesSection.PSObject.Properties['Samples']) {
            $wifiSamples = ConvertTo-NetworkArray $wifiInterfacesSection.Samples | Where-Object { $_ }
        } elseif ($wifiPayload -and $wifiPayload.PSObject.Properties['Samples']) {
            $wifiSamples = ConvertTo-NetworkArray $wifiPayload.Samples | Where-Object { $_ }
        }

        $signalCandidates = @($wifiSamples | Where-Object { $_ -and $_.PSObject.Properties['SignalPercent'] -and $null -ne $_.SignalPercent })
        $connectedCandidates = @($signalCandidates | Where-Object {
                $state = $null
                if ($_.PSObject.Properties['State']) {
                    $state = [string]$_.State
                    if ($state) {
                        try { $state = $state.ToLowerInvariant() } catch { $state = $state.ToLower() }
                    }
                }
                return ($state -eq 'connected')
            })

        $consideredSamples = if ($connectedCandidates.Count -gt 0) { $connectedCandidates } else { $signalCandidates }

        $normalizedSamples = New-Object System.Collections.Generic.List[pscustomobject]
        foreach ($sample in $consideredSamples) {
            if (-not $sample) { continue }

            $percent = $null
            if ($sample.PSObject.Properties['SignalPercent']) {
                $percentRaw = $sample.SignalPercent
                if ($percentRaw -is [int]) {
                    $percent = [int]$percentRaw
                } else {
                    $percentText = [string]$percentRaw
                    if ($percentText -match '(\d+)') {
                        $percent = [int]$matches[1]
                    }
                }
            }

            if ($null -eq $percent) { continue }
            $percent = [math]::Max([math]::Min([int]$percent, 100), 0)

            $dbmValue = $null
            if ($sample.PSObject.Properties['SignalDbm'] -and $sample.SignalDbm -ne $null) {
                $dbmRaw = $sample.SignalDbm
                if ($dbmRaw -is [int]) {
                    $dbmValue = [int]$dbmRaw
                } else {
                    $dbmText = [string]$dbmRaw
                    if ($dbmText -match '(-?\d+)') {
                        $dbmValue = [int]$matches[1]
                    }
                }
            }

            $normalizedSamples.Add([pscustomobject]@{
                    Percent = $percent
                    Dbm     = $dbmValue
                    Sample  = $sample
                }) | Out-Null
        }

        if ($normalizedSamples.Count -gt 0) {
            $normalizedArray = $normalizedSamples.ToArray()
            $totalSamples = $normalizedArray.Count
            $below60 = ($normalizedArray | Where-Object { $_.Percent -lt 60 }).Count
            $below35 = ($normalizedArray | Where-Object { $_.Percent -lt 35 }).Count

            $share60 = if ($totalSamples -gt 0) { $below60 / $totalSamples } else { 0 }
            $share35 = if ($totalSamples -gt 0) { $below35 / $totalSamples } else { 0 }

            $sortedSamples = $normalizedArray | Sort-Object -Property Percent
            $worstSample = $sortedSamples | Select-Object -First 1

            $sampleEvidence = New-Object System.Collections.Generic.List[pscustomobject]
            foreach ($entry in $sortedSamples) {
                $sampleData = $entry.Sample
                $sampleEvidence.Add([pscustomobject]@{
                        Interface     = if ($sampleData.PSObject.Properties['Name']) { [string]$sampleData.Name } else { $null }
                        SSID          = if ($sampleData.PSObject.Properties['Ssid']) { [string]$sampleData.Ssid } else { $null }
                        SignalPercent = $entry.Percent
                        SignalDbm     = $entry.Dbm
                        Channel       = if ($sampleData.PSObject.Properties['Channel']) { $sampleData.Channel } else { $null }
                        Bssid         = if ($sampleData.PSObject.Properties['Bssid']) { $sampleData.Bssid } else { $null }
                        State         = if ($sampleData.PSObject.Properties['State']) { $sampleData.State } else { $null }
                        SampledAt     = if ($sampleData.PSObject.Properties['SampledAt']) { $sampleData.SampledAt } else { $null }
                    }) | Out-Null
            }

            $signalEvidence = [ordered]@{
                TotalSamples   = $totalSamples
                Below60Percent = $below60
                Below35Percent = $below35
                Samples        = $sampleEvidence.ToArray()
            }

            $worstPercentText = $null
            if ($worstSample) {
                if ($worstSample.Dbm -ne $null) {
                    $worstPercentText = '{0}% (~{1} dBm)' -f $worstSample.Percent, $worstSample.Dbm
                } else {
                    $worstPercentText = '{0}%' -f $worstSample.Percent
                }
            }

            if ($share35 -ge 0.6) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Wi-Fi signal quality critical' -Evidence $signalEvidence -Subcategory 'Wi-Fi Quality'
                $detail = ('{0}/{1} samples ({2:P1}) below 35% signal quality.' -f $below35, $totalSamples, $share35)
                Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiQuality' -Status 'High risk' -Details $detail
            } elseif ($share60 -ge 0.6) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Wi-Fi signal quality weak' -Evidence $signalEvidence -Subcategory 'Wi-Fi Quality'
                $detail = ('{0}/{1} samples ({2:P1}) below 60% signal quality.' -f $below60, $totalSamples, $share60)
                Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiQuality' -Status 'Medium risk' -Details $detail
            } else {
                $title = if ($worstSample -and $worstSample.Percent -ge 70) { 'Wi-Fi signal quality healthy (≥70%)' } else { 'Wi-Fi signal quality stable' }
                if ($worstPercentText) { $title = '{0} (worst {1})' -f $title, $worstPercentText }
                Add-CategoryNormal -CategoryResult $result -Title $title -Subcategory 'Wi-Fi Quality'
                $detail = if ($worstPercentText) { 'Worst recorded signal {0}.' -f $worstPercentText } else { 'Signal levels above 60% for collected samples.' }
                Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiQuality' -Status 'Healthy' -Details $detail
            }
        } else {
            $qualityDetail = if ($wifiRaw -and (Test-NetworkErrorEntry $wifiRaw) -and $wifiRaw.PSObject.Properties['Error']) {
                [string]$wifiRaw.Error
            } elseif ($wifiSamples.Count -gt 0) {
                'Wi-Fi samples lacked signal percentage values.'
            } else {
                'No Wi-Fi signal samples were collected (adapter may be disconnected).'
            }

            $qualityStatus = if ($wifiRaw -and (Test-NetworkErrorEntry $wifiRaw)) { 'Unavailable' } else { 'No data' }
            Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiQuality' -Status $qualityStatus -Details $qualityDetail
        }

        $roamSource = $null
        if ($wifiPayload -and $wifiPayload.PSObject.Properties['RoamEvents']) {
            $roamSource = $wifiPayload.RoamEvents
        }

        if ($roamSource) {
            if (Test-NetworkErrorEntry $roamSource) {
                $roamError = if ($roamSource.PSObject.Properties['Error']) { [string]$roamSource.Error } else { 'Failed to query Wi-Fi roam events.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to collect Wi-Fi roam events' -Evidence $roamError -Subcategory 'Wi-Fi Roaming'
                Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiRoamRate' -Status 'Unavailable' -Details $roamError
            } else {
                $roamEvents = ConvertTo-NetworkArray $roamSource | Where-Object { $_ }
                $roamSummary = Get-NetworkWifiRoamSummary -Events $roamEvents -LookbackMinutes 30

                if ($roamSummary.SampleCount -gt 0) {
                    $roamEvidence = [ordered]@{
                        LookbackMinutes  = $roamSummary.LookbackMinutes
                        RoamCount        = $roamSummary.RoamCount
                        SampleCount      = $roamSummary.SampleCount
                        UniqueBssidCount = $roamSummary.UniqueBssidCount
                        Observations     = $roamSummary.Observations
                    }

                    if ($roamSummary.RoamCount -ge 12) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Frequent Wi-Fi roaming detected' -Evidence $roamEvidence -Subcategory 'Wi-Fi Roaming'
                        $detail = ('{0} roam events within {1} minutes.' -f $roamSummary.RoamCount, $roamSummary.LookbackMinutes)
                        Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiRoamRate' -Status 'High risk' -Details $detail
                    } elseif ($roamSummary.RoamCount -ge 5) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Elevated Wi-Fi roaming rate' -Evidence $roamEvidence -Subcategory 'Wi-Fi Roaming'
                        $detail = ('{0} roam events within {1} minutes.' -f $roamSummary.RoamCount, $roamSummary.LookbackMinutes)
                        Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiRoamRate' -Status 'Medium risk' -Details $detail
                    } else {
                        Add-CategoryNormal -CategoryResult $result -Title 'Wi-Fi roaming rate normal' -Subcategory 'Wi-Fi Roaming'
                        $detail = ('{0} roam events within {1} minutes.' -f $roamSummary.RoamCount, $roamSummary.LookbackMinutes)
                        Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiRoamRate' -Status 'Healthy' -Details $detail
                    }
                } else {
                    Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiRoamRate' -Status 'Healthy' -Details 'No Wi-Fi roam events observed within the last 30 minutes.'
                }
            }
        } else {
            Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiRoamRate' -Status 'No data' -Details 'Wi-Fi roam event log entries were not included in the collection.'
        }
    } else {
        Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiQuality' -Status 'Not collected' -Details 'Wi-Fi diagnostics collector output not found.'
        Add-CategoryCheck -CategoryResult $result -Name 'Network/WiFiRoamRate' -Status 'Not collected' -Details 'Wi-Fi diagnostics collector output not found.'
    }

    Invoke-DhcpAnalyzers -Context $Context -CategoryResult $result

    return $result
}
