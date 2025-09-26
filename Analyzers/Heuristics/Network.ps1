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

function ConvertTo-LinkSpeedBits {
    param($Value)

    if ($null -eq $Value) { return $null }

    $text = if ($Value -is [string]) { $Value } else { [string]$Value }
    if (-not $text) { return $null }

    $normalized = $text.Trim()
    if (-not $normalized) { return $null }

    $normalized = $normalized -replace ',', '.'

    if ($normalized -match '(?i)(?<value>\d+(?:\.\d+)?)\s*(?<unit>t|g|m|k)?(?:b(?:it)?(?:ps|/s)?|bps)') {
        $value = [double]::Parse($matches['value'], [System.Globalization.CultureInfo]::InvariantCulture)
        $unit = $matches['unit']
        $factor = switch ($unit.ToLowerInvariant()) {
            't' { [math]::Pow(10, 12) }
            'g' { [math]::Pow(10, 9) }
            'm' { [math]::Pow(10, 6) }
            'k' { [math]::Pow(10, 3) }
            default { 1 }
        }
        return [double]($value * $factor)
    }

    if ($normalized -match '(?i)(?<value>\d+(?:\.\d+)?)\s*(?<unit>tbps|gbps|mbps|kbps)') {
        $value = [double]::Parse($matches['value'], [System.Globalization.CultureInfo]::InvariantCulture)
        $factor = switch ($matches['unit'].ToLowerInvariant()) {
            'tbps' { [math]::Pow(10, 12) }
            'gbps' { [math]::Pow(10, 9) }
            'mbps' { [math]::Pow(10, 6) }
            'kbps' { [math]::Pow(10, 3) }
            default { 1 }
        }
        return [double]($value * $factor)
    }

    return $null
}

function Format-LinkSpeedBits {
    param([double]$Bits)

    if ($null -eq $Bits -or $Bits -le 0) { return $null }

    if ($Bits -ge [math]::Pow(10, 9)) {
        return ('{0:0.##} Gbps' -f ($Bits / [math]::Pow(10, 9)))
    }

    if ($Bits -ge [math]::Pow(10, 6)) {
        return ('{0:0.##} Mbps' -f ($Bits / [math]::Pow(10, 6)))
    }

    if ($Bits -ge [math]::Pow(10, 3)) {
        return ('{0:0.##} Kbps' -f ($Bits / [math]::Pow(10, 3)))
    }

    return ('{0} bps' -f [math]::Round($Bits))
}

function Test-NetworkWirelessAdapter {
    param(
        [string]$Name,
        [string]$Description
    )

    $candidates = @()
    if ($Name) { $candidates += $Name }
    if ($Description) { $candidates += $Description }

    $text = ($candidates -join ' ')
    if (-not $text) { return $false }

    try {
        $normalized = $text.ToLowerInvariant()
    } catch {
        $normalized = [string]$text
        if ($normalized) { $normalized = $normalized.ToLowerInvariant() }
    }

    if (-not $normalized) { return $false }

    if ($normalized -match 'wi-?fi|wireless|wlan|wwan|bluetooth|cellular') { return $true }

    return $false
}

function Get-NetworkAdvancedPropertyInventory {
    param($Properties)

    $map = @{}

    if (-not $Properties -or ($Properties.PSObject -and $Properties.PSObject.Properties['Error'])) { return $map }

    $entries = ConvertTo-NetworkArray $Properties
    foreach ($entry in $entries) {
        if (-not $entry) { continue }
        $adapterName = if ($entry.PSObject.Properties['Name']) { [string]$entry.Name } else { $null }
        if (-not $adapterName) { continue }

        $key = $adapterName.ToLowerInvariant()
        if (-not $map.ContainsKey($key)) {
            $map[$key] = New-Object System.Collections.Generic.List[object]
        }

        $map[$key].Add($entry) | Out-Null
    }

    return $map
}

function Get-NetworkAdapterCapabilityBits {
    param(
        [string]$AdapterName,
        [string]$Description,
        [System.Collections.IDictionary]$AdvancedPropertyMap,
        [string]$DriverInformation
    )

    $candidates = New-Object System.Collections.Generic.List[double]

    if ($AdapterName -and $AdvancedPropertyMap -and $AdvancedPropertyMap.ContainsKey($AdapterName.ToLowerInvariant())) {
        $properties = $AdvancedPropertyMap[$AdapterName.ToLowerInvariant()]
        foreach ($prop in $properties) {
            if (-not $prop) { continue }
            $displayValue = if ($prop.PSObject.Properties['DisplayValue']) { [string]$prop.DisplayValue } else { $null }
            $speed = ConvertTo-LinkSpeedBits $displayValue
            if ($speed -and $speed -gt 0) { $candidates.Add([double]$speed) | Out-Null }
        }
    }

    $infoSegments = @($AdapterName, $Description, $DriverInformation)
    $combined = ($infoSegments | Where-Object { $_ }) -join ' '
    if ($combined) {
        if ($combined -match '(?i)(?:\b10\s*g|\b10g(?:b|e)?\b|10-?gig)') { $candidates.Add([double][math]::Pow(10, 10)) | Out-Null }
        if ($combined -match '(?i)(?:\b5\s*g|\b5g(?:b|e)?\b|5-?gig)') { $candidates.Add([double](5 * [math]::Pow(10, 9))) | Out-Null }
        if ($combined -match '(?i)(?:\b2\.5\s*g|\b2\.5g\b|\b2500\b|multi-?gig)') { $candidates.Add([double](2.5 * [math]::Pow(10, 9))) | Out-Null }
        if ($combined -match '(?i)(?:gigabit|\b1000\b|\b1g\b|1-?gig)') { $candidates.Add([double][math]::Pow(10, 9)) | Out-Null }
        if ($candidates.Count -eq 0 -and $combined -match '(?i)fast\s+ethernet') { $candidates.Add([double][math]::Pow(10, 8)) | Out-Null }
        if ($candidates.Count -eq 0 -and $combined -match '(?i)10\s*mb') { $candidates.Add([double][math]::Pow(10, 7)) | Out-Null }
    }

    if ($candidates.Count -eq 0) { return $null }

    return ($candidates | Measure-Object -Maximum).Maximum
}

function Test-NetworkPowerPolicyEnabled {
    param($AdvancedProperties)

    if (-not $AdvancedProperties) { return $false }

    foreach ($prop in $AdvancedProperties) {
        if (-not $prop) { continue }
        $displayName = if ($prop.PSObject.Properties['DisplayName']) { [string]$prop.DisplayName } else { $null }
        $displayValue = if ($prop.PSObject.Properties['DisplayValue']) { [string]$prop.DisplayValue } else { $null }
        if (-not $displayName -or -not $displayValue) { continue }

        try {
            $nameLower = $displayName.ToLowerInvariant()
        } catch {
            $nameLower = $displayName
            if ($nameLower) { $nameLower = $nameLower.ToLowerInvariant() }
        }

        try {
            $valueLower = $displayValue.ToLowerInvariant()
        } catch {
            $valueLower = $displayValue
            if ($valueLower) { $valueLower = $valueLower.ToLowerInvariant() }
        }

        if (-not $nameLower -or -not $valueLower) { continue }

        if ($nameLower -match 'power|energy|green|efficien' -and $valueLower -match 'enabled|on|active|medium|maximum') { return $true }
    }

    return $false
}

function Get-LinkEventDirection {
    param($Event)

    if (-not $Event) { return $null }

    $id = $null
    if ($Event.PSObject.Properties['Id']) {
        try { $id = [int]$Event.Id } catch { $id = $null }
    }

    switch ($id) {
        27 { return 'down' }
        10400 { return 'down' }
        10402 { return 'down' }
        8021 { return 'down' }
        32 { return 'up' }
        4201 { return 'up' }
        10401 { return 'up' }
        8026 { return 'up' }
    }

    $message = if ($Event.PSObject.Properties['Message']) { [string]$Event.Message } else { $null }
    if (-not $message) { return $null }

    if ($message -match '(?i)(?:link|network).*?(disconnected|down|lost|removed|fail)') { return 'down' }
    if ($message -match '(?i)(?:link|network).*?(connected|up|restored|negotiated|established)') { return 'up' }

    return $null
}

function Format-LinkEventSnippet {
    param($Event)

    if (-not $Event) { return $null }

    $timeText = $null
    if ($Event.PSObject.Properties['TimeCreated']) {
        try {
            $timeValue = [datetime]$Event.TimeCreated
            $timeText = $timeValue.ToString('u')
        } catch {
            $timeText = [string]$Event.TimeCreated
        }
    }

    $id = if ($Event.PSObject.Properties['Id']) { [string]$Event.Id } else { '' }
    $provider = if ($Event.PSObject.Properties['ProviderName']) { [string]$Event.ProviderName } else { '' }
    $message = if ($Event.PSObject.Properties['Message']) { [string]$Event.Message } else { '' }

    if ($message.Length -gt 200) {
        $message = $message.Substring(0, 200) + '…'
    }

    $components = @()
    if ($timeText) { $components += $timeText }
    if ($id) { $components += ('Id {0}' -f $id) }
    if ($provider) { $components += $provider }
    if ($message) { $components += $message }

    return ($components -join ' | ')
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

    $adapterPayload = $null
    $adapterInventory = $null
    $adapterArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-adapters'
    if ($adapterArtifact) {
        $adapterPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $adapterArtifact)
    }
    $adapterInventory = Get-NetworkDnsInterfaceInventory -AdapterPayload $adapterPayload

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
                    } elseif (($interfaceInfo -and $interfaceInfo.IsPseudo) -or (Test-NetworkPseudoInterface -Alias $alias -Description (if ($interfaceInfo) { $interfaceInfo.Description } else { $null }))) {
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

    $advancedPropertyMap = Get-NetworkAdvancedPropertyInventory -Properties (if ($adapterPayload) { $adapterPayload.Properties } else { $null })
    $adapterEntries = @()
    if ($adapterPayload -and $adapterPayload.Adapters -and -not $adapterPayload.Adapters.Error) {
        $adapterEntries = @(ConvertTo-NetworkArray $adapterPayload.Adapters | Where-Object { $_ })
    }

    $systemLinkEvents = @()
    $msftLinkEvents = @()
    $linkEventErrors = New-Object System.Collections.Generic.List[string]
    $systemEventsCollected = $false
    $msftEventsCollected = $false

    if ($adapterPayload -and $adapterPayload.LinkEvents) {
        $linkEventsData = $adapterPayload.LinkEvents

        if ($linkEventsData.PSObject.Properties['System']) {
            $systemValue = $linkEventsData.System
            if ($systemValue -and $systemValue.PSObject -and $systemValue.PSObject.Properties['Error']) {
                if ($systemValue.Error) { $linkEventErrors.Add(('System: {0}' -f $systemValue.Error)) | Out-Null }
            } else {
                $systemEventsCollected = $true
                $systemLinkEvents = @(ConvertTo-NetworkArray $systemValue | Where-Object { $_ })
            }
        }

        if ($linkEventsData.PSObject.Properties['MsftNetAdapter']) {
            foreach ($entry in (ConvertTo-NetworkArray $linkEventsData.MsftNetAdapter)) {
                if (-not $entry) { continue }
                $logName = if ($entry.PSObject.Properties['LogName']) { [string]$entry.LogName } else { 'MSFT-NetAdapter' }
                if ($entry.PSObject -and $entry.PSObject.Properties['Error'] -and $entry.Error) {
                    $linkEventErrors.Add(('{0}: {1}' -f $logName, $entry.Error)) | Out-Null
                    continue
                }
                if ($entry.PSObject -and $entry.PSObject.Properties['Events']) {
                    $msftEventsCollected = $true
                    $msftLinkEvents += (ConvertTo-NetworkArray $entry.Events | Where-Object { $_ })
                }
            }
            $msftLinkEvents = @($msftLinkEvents)
        }
    }

    $systemLinkEvents = @($systemLinkEvents)

    $linkCheckStatus = 'No data'
    $linkCheckDetails = 'Link event data not available.'
    $linkIssueDetected = $false

    $duplexCheckStatus = 'No data'
    $duplexCheckDetails = 'Link event data not available.'
    $duplexIssueDetected = $false

    $speedCheckStatus = 'No data'
    $speedCheckDetails = 'No wired adapters assessed.'
    $speedIssueDetected = $false

    $speedCheckDetailsList = New-Object System.Collections.Generic.List[string]
    $adapterSpeedSummaries = New-Object System.Collections.Generic.List[pscustomobject]
    $speedSummaryLabels = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $wiredAdaptersAnalyzed = $false

    foreach ($adapter in $adapterEntries) {
        if (-not $adapter) { continue }

        $adapterName = if ($adapter.PSObject.Properties['Name']) { [string]$adapter.Name } else { $null }
        $displayName = if ($adapter.PSObject.Properties['InterfaceDescription']) { [string]$adapter.InterfaceDescription } else { $adapterName }
        $linkSpeedText = if ($adapter.PSObject.Properties['LinkSpeed']) { [string]$adapter.LinkSpeed } else { $null }

        $summaryLabel = if ($adapterName) { $adapterName } elseif ($displayName) { $displayName } else { 'Adapter' }
        if ($summaryLabel -and $speedSummaryLabels.Add($summaryLabel)) {
            $summarySpeed = $linkSpeedText
            if (-not $summarySpeed) {
                $summaryBits = ConvertTo-LinkSpeedBits $linkSpeedText
                if ($summaryBits -and $summaryBits -gt 0) { $summarySpeed = Format-LinkSpeedBits $summaryBits }
            }
            $adapterSpeedSummaries.Add([pscustomobject]@{ Label = $summaryLabel; LinkSpeed = $summarySpeed }) | Out-Null
        }

        $status = if ($adapter.PSObject.Properties['Status']) { [string]$adapter.Status } else { '' }
        $mediaState = if ($adapter.PSObject.Properties['MediaConnectionState']) { [string]$adapter.MediaConnectionState } else { '' }

        $isConnected = $false
        if ($status) {
            try { $isConnected = ($status.ToLowerInvariant() -match '^(up|connected)') } catch { $isConnected = $false }
        }
        if (-not $isConnected -and $mediaState) {
            try { $isConnected = ($mediaState.ToLowerInvariant() -match 'connected|up') } catch { $isConnected = $false }
        }
        if (-not $isConnected) { continue }

        $isPseudo = Test-NetworkPseudoInterface -Alias $adapterName -Description $displayName
        if ($isPseudo) { continue }
        if (Test-NetworkWirelessAdapter -Name $adapterName -Description $displayName) { continue }

        $wiredAdaptersAnalyzed = $true

        $linkBits = ConvertTo-LinkSpeedBits $linkSpeedText
        if ($null -eq $linkBits -or $linkBits -le 0) { continue }

        $adapterKey = if ($adapterName) { $adapterName.ToLowerInvariant() } else { $null }
        $adapterProps = @()
        if ($adapterKey -and $advancedPropertyMap.ContainsKey($adapterKey)) {
            $adapterProps = $advancedPropertyMap[$adapterKey]
        }

        $driverInfo = if ($adapter.PSObject.Properties['DriverInformation']) { [string]$adapter.DriverInformation } else { $null }
        $capabilityBits = Get-NetworkAdapterCapabilityBits -AdapterName $adapterName -Description $displayName -AdvancedPropertyMap $advancedPropertyMap -DriverInformation $driverInfo
        if (-not $capabilityBits -or $capabilityBits -le 0) { continue }

        if ($linkBits -lt ($capabilityBits / 2)) {
            $powerPolicy = Test-NetworkPowerPolicyEnabled -AdvancedProperties $adapterProps
            $severity = 'medium'
            if ($capabilityBits -ge [math]::Pow(10, 9) -and $linkBits -le [math]::Pow(10, 8) -and -not $powerPolicy) { $severity = 'high' }

            $speedIssueDetected = $true
            $label = if ($adapterName) { $adapterName } elseif ($displayName) { $displayName } else { 'Adapter' }
            $reportedSpeed = if ($linkSpeedText) { $linkSpeedText } else { Format-LinkSpeedBits $linkBits }
            $capabilityText = Format-LinkSpeedBits $capabilityBits

            $evidence = New-Object System.Collections.Generic.List[string]
            $evidence.Add(('Reported link speed: {0}' -f $reportedSpeed)) | Out-Null
            if ($capabilityText) { $evidence.Add(('Estimated capability: {0}' -f $capabilityText)) | Out-Null }
            if ($mediaState) {
                $evidence.Add(('Media state: {0}' -f $mediaState)) | Out-Null
            } elseif ($status) {
                $evidence.Add(('Status: {0}' -f $status)) | Out-Null
            }
            if ($powerPolicy) { $evidence.Add('Power policy detected in adapter advanced settings.') | Out-Null }

            $recentSnippets = (($systemLinkEvents + $msftLinkEvents) | Sort-Object -Property TimeCreated -Descending | Select-Object -First 3 | ForEach-Object { Format-LinkEventSnippet $_ }) | Where-Object { $_ }
            $recentSnippets = @($recentSnippets)
            if ($recentSnippets.Count -gt 0) {
                $evidence.Add('Recent events:') | Out-Null
                foreach ($snippet in $recentSnippets) { $evidence.Add($snippet) | Out-Null }
            }

            $title = if ($label) { 'Link negotiating below expected speed on ' + $label } else { 'Link negotiating below expected speed' }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence ($evidence -join "`n") -Subcategory 'Speed Negotiation'

            $speedCheckDetailsList.Add(('{0}: {1}' -f $label, $reportedSpeed)) | Out-Null
        }
    }

    $speedSummaryText = $null
    if ($adapterSpeedSummaries.Count -gt 0) {
        $speedSummaryText = ($adapterSpeedSummaries | ForEach-Object {
                $label = if ($_.PSObject.Properties['Label']) { [string]$_.Label } else { 'Adapter' }
                $value = if ($_.PSObject.Properties['LinkSpeed'] -and $_.LinkSpeed) { [string]$_.LinkSpeed } else { 'Unknown' }
                '{0}: {1}' -f $label, $value
            }) -join '; '
    }

    if ($speedCheckDetailsList.Count -gt 0) {
        $speedCheckStatus = 'Issue'
        $speedCheckDetails = ($speedCheckDetailsList -join '; ')
    } elseif ($wiredAdaptersAnalyzed) {
        $speedCheckStatus = 'Good'
        $speedCheckDetails = 'All wired adapters negotiated expected speeds.'
    } elseif ($adapterEntries.Count -gt 0) {
        $speedCheckStatus = 'Good'
        $speedCheckDetails = 'No eligible wired adapters detected.'
    }

    $linkEventsAvailable = ($systemLinkEvents.Count -gt 0)
    if ($linkEventsAvailable) {
        $cutoff = (Get-Date).AddHours(-24)
        $recentEvents = @()
        foreach ($evt in $systemLinkEvents) {
            if (-not $evt) { continue }
            $eventTime = $null
            if ($evt.PSObject.Properties['TimeCreated']) {
                try { $eventTime = [datetime]$evt.TimeCreated } catch { $eventTime = $null }
            }
            if ($eventTime -and $eventTime -ge $cutoff) { $recentEvents += $evt }
        }

        $downCount = 0
        $upCount = 0
        foreach ($evt in $recentEvents) {
            $direction = Get-LinkEventDirection $evt
            if ($direction -eq 'down') { $downCount++ }
            elseif ($direction -eq 'up') { $upCount++ }
        }

        $flapCount = [math]::Min($downCount, $upCount)
        if ($flapCount -ge 3) {
            $linkIssueDetected = $true
            $severity = if ($flapCount -ge 10) { 'high' } else { 'medium' }
            $linkCheckStatus = 'Issue'
            $linkCheckDetails = ('Down {0} / Up {1} events (~{2} flaps)' -f $downCount, $upCount, $flapCount)

            $recentSnippets = (($recentEvents + $msftLinkEvents) | Sort-Object -Property TimeCreated -Descending | Select-Object -First 4 | ForEach-Object { Format-LinkEventSnippet $_ }) | Where-Object { $_ }
            $recentSnippets = @($recentSnippets)

            $evidence = New-Object System.Collections.Generic.List[string]
            $evidence.Add(('Link events (24h): down={0}, up={1}, ≈{2} flaps' -f $downCount, $upCount, $flapCount)) | Out-Null
            if ($speedSummaryText) { $evidence.Add(('Reported adapter speeds: {0}' -f $speedSummaryText)) | Out-Null }
            if ($recentSnippets.Count -gt 0) {
                $evidence.Add('Recent events:') | Out-Null
                foreach ($snippet in $recentSnippets) { $evidence.Add($snippet) | Out-Null }
            }

            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Network link flapping detected' -Evidence ($evidence -join "`n") -Subcategory 'Link Stability'
        } else {
            $linkCheckStatus = 'Good'
            if ($downCount -gt 0 -or $upCount -gt 0) {
                $linkCheckDetails = ('Link transitions within normal range ({0} down / {1} up).' -f $downCount, $upCount)
            } else {
                $linkCheckDetails = 'No link down/up transitions recorded in last 24h.'
            }
        }
    } elseif ($systemEventsCollected -or $msftEventsCollected) {
        $linkCheckStatus = 'Good'
        $linkCheckDetails = 'No link down/up transitions recorded in last 24h.'
    } elseif ($linkEventErrors.Count -gt 0) {
        $linkCheckStatus = 'No data'
        $linkCheckDetails = ($linkEventErrors -join '; ')
    }

    $duplexEvents = @(($systemLinkEvents + $msftLinkEvents) | Where-Object { $_ -and $_.PSObject.Properties['Message'] -and ([string]$_.Message) -match '(?i)duplex' })
    if ($duplexEvents.Count -gt 0) {
        $explicitMismatch = @($duplexEvents | Where-Object { $_.PSObject.Properties['Message'] -and ([string]$_.Message) -match '(?i)mismatch|incompat' })
        $halfEvents = @($duplexEvents | Where-Object { $_.PSObject.Properties['Message'] -and ([string]$_.Message) -match '(?i)half' })
        $fullEvents = @($duplexEvents | Where-Object { $_.PSObject.Properties['Message'] -and ([string]$_.Message) -match '(?i)full' })

        if ($explicitMismatch.Count -gt 0 -or ($halfEvents.Count -gt 0 -and $fullEvents.Count -gt 0)) {
            $duplexIssueDetected = $true
            $duplexCheckStatus = 'Issue'
            $duplexCheckDetails = 'Duplex mismatch warnings logged.'

            $evidence = New-Object System.Collections.Generic.List[string]
            $evidence.Add(('Duplex-related events observed: {0}' -f $duplexEvents.Count)) | Out-Null
            if ($speedSummaryText) { $evidence.Add(('Reported adapter speeds: {0}' -f $speedSummaryText)) | Out-Null }
            $duplexSnippets = ($duplexEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 4 | ForEach-Object { Format-LinkEventSnippet $_ }) | Where-Object { $_ }
            $duplexSnippets = @($duplexSnippets)
            if ($duplexSnippets.Count -gt 0) {
                $evidence.Add('Recent events:') | Out-Null
                foreach ($snippet in $duplexSnippets) { $evidence.Add($snippet) | Out-Null }
            }

            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Possible duplex mismatch detected' -Evidence ($evidence -join "`n") -Subcategory 'Duplex Negotiation'
        } elseif ($systemEventsCollected -or $msftEventsCollected) {
            $duplexCheckStatus = 'Good'
            $duplexCheckDetails = 'No duplex mismatch indicators detected.'
        }
    } elseif ($systemEventsCollected -or $msftEventsCollected) {
        $duplexCheckStatus = 'Good'
        $duplexCheckDetails = 'No duplex-related events captured.'
    } elseif ($linkEventErrors.Count -gt 0) {
        $duplexCheckStatus = 'No data'
        $duplexCheckDetails = ($linkEventErrors -join '; ')
    }

    if (-not $linkIssueDetected -and -not $duplexIssueDetected -and -not $speedIssueDetected -and $linkCheckStatus -eq 'Good' -and $duplexCheckStatus -eq 'Good' -and $speedCheckStatus -eq 'Good') {
        Add-CategoryNormal -CategoryResult $result -Title 'Stable link, expected speed, no mismatch hints.' -Evidence $speedSummaryText -Subcategory 'Link Health'
    }

    Add-CategoryCheck -CategoryResult $result -Name 'Network/LinkStability' -Status $linkCheckStatus -Details $linkCheckDetails
    Add-CategoryCheck -CategoryResult $result -Name 'Network/Duplex' -Status $duplexCheckStatus -Details $duplexCheckDetails
    Add-CategoryCheck -CategoryResult $result -Name 'Network/SpeedNegotiation' -Status $speedCheckStatus -Details $speedCheckDetails

    Invoke-DhcpAnalyzers -Context $Context -CategoryResult $result

    return $result
}
