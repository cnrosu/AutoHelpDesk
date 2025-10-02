<#!
.SYNOPSIS
    Network diagnostics heuristics covering connectivity, DNS, proxy, and Outlook health.
#>

$analyzersRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
. (Join-Path -Path $analyzersRoot -ChildPath 'AnalyzerCommon.ps1')

$vpnAnalyzerPath = Join-Path -Path $analyzersRoot -ChildPath 'Network/Analyze-Vpn.ps1'
if (Test-Path -LiteralPath $vpnAnalyzerPath) {
    . $vpnAnalyzerPath
}

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

function Normalize-NetworkMacAddress {
    param([string]$MacAddress)

    if (-not $MacAddress) { return $null }

    $trimmed = $MacAddress.Trim()
    if (-not $trimmed) { return $null }

    $hex = ($trimmed -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -lt 12) { return $null }
    $hex = $hex.Substring($hex.Length - 12)

    $parts = @()
    for ($i = 0; $i -lt 12; $i += 2) { $parts += $hex.Substring($i, 2) }

    return ($parts -join ':')
}

function Get-NetworkMacOui {
    param([string]$MacAddress)

    $normalized = Normalize-NetworkMacAddress $MacAddress
    if (-not $normalized) { return $null }

    return ($normalized.Substring(0, 8))
}

function Get-NetworkCanonicalIpv4 {
    param([string]$Text)

    if (-not $Text) { return $null }

    $match = [regex]::Match($Text, '\b(\d+\.\d+\.\d+\.\d+)\b')
    if ($match.Success) { return $match.Groups[1].Value }

    return $null
}

function ConvertTo-NetworkArpEntries {
    param($Value)

    $entries = New-Object System.Collections.Generic.List[pscustomobject]
    $lines = ConvertTo-NetworkArray $Value

    $currentInterface = $null
    foreach ($rawLine in $lines) {
        if (-not $rawLine) { continue }

        $line = if ($rawLine -is [string]) { $rawLine } else { [string]$rawLine }
        if (-not $line) { continue }

        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        $interfaceMatch = [regex]::Match($line, '^Interface:\s+([^\s]+)')
        if ($interfaceMatch.Success) {
            $currentInterface = $interfaceMatch.Groups[1].Value
            continue
        }

        if ($trimmed -match '^(Internet\s+Address|Address\s+Resolved)') { continue }

        $entryMatch = [regex]::Match($trimmed, '^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f\-]+)\s+([A-Za-z]+)$')
        if (-not $entryMatch.Success) { continue }

        $ip = $entryMatch.Groups[1].Value
        $macRaw = $entryMatch.Groups[2].Value
        $type = $entryMatch.Groups[3].Value

        $normalizedMac = Normalize-NetworkMacAddress $macRaw

        $entries.Add([pscustomobject]@{
            Interface       = $currentInterface
            InternetAddress = $ip
            PhysicalAddress = $macRaw
            NormalizedMac   = $normalizedMac
            Type            = $type
        }) | Out-Null
    }

    return $entries.ToArray()
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
    $macMap = @{}

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

            if ($adapter.PSObject.Properties['MacAddress'] -and $adapter.MacAddress) {
                $macMap[$key] = Normalize-NetworkMacAddress $adapter.MacAddress
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
                    MacAddress  = if ($macMap.ContainsKey($key)) { $macMap[$key] } else { $null }
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

            if (-not $info.MacAddress -and $macMap.ContainsKey($key)) {
                $info.MacAddress = $macMap[$key]
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
                MacAddress  = if ($macMap.ContainsKey($key)) { $macMap[$key] } else { $null }
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

    # Preserve your current null/empty behavior
    if (-not $Text) { return $Text }

    # Cache compiled regexes once per session for speed
    if (-not $script:__kebab_inited) {
        $opt = [System.Text.RegularExpressions.RegexOptions]::Compiled
        $script:rxCombiningMarks = [regex]::new('\p{Mn}+', $opt)                     # nonspacing marks (after FormD)
        $script:rxApostrophes    = [regex]::new("[\u2019']", $opt)                   # ’ and '
        $script:rxAcronymBreak   = [regex]::new('([A-Z]+)([A-Z][a-z])', $opt)        # ABCWord -> ABC-Word
        $script:rxLowerUpper     = [regex]::new('([a-z0-9])([A-Z])', $opt)           # fooBar -> foo-Bar, 1A -> 1-A
        $script:rxNonAlnum       = [regex]::new('[^A-Za-z0-9]+', $opt)               # any run of non-alnum -> -
        $script:rxTrimHyphens    = [regex]::new('^-+|-+$', $opt)                     # trim leading/trailing -
        $script:__kebab_inited   = $true
    }

    $s = [string]$Text

    # 1) Unicode normalize + strip diacritics
    $s = $s.Normalize([Text.NormalizationForm]::FormD)
    $s = $script:rxCombiningMarks.Replace($s, '')

    # Optional ligatures / special letters (kept minimal and predictable)
    $s = $s -replace 'ß','ss' -replace 'æ','ae' -replace 'Æ','AE' -replace 'œ','oe' -replace 'Œ','OE'

    # 2) Remove apostrophes so they don't create separators
    $s = $script:rxApostrophes.Replace($s, '')

    # 3) Insert boundaries for acronym→word and lower→Upper transitions
    $s = $script:rxAcronymBreak.Replace($s, '$1-$2')
    $s = $script:rxLowerUpper.Replace($s,  '$1-$2')

    # 4) Collapse non-alphanumerics to single hyphens
    $s = $script:rxNonAlnum.Replace($s, '-')

    # 5) Trim stray hyphens and lowercase invariantly
    $s = $script:rxTrimHyphens.Replace($s, '')
    $s = $s.ToLowerInvariant()

    return $s
}

function Get-DhcpAnalyzerDisplayName {
    param(
        $Analyzer
    )

    if (-not $Analyzer) { return 'DHCP check' }

    $scriptInfo = if ($Analyzer.PSObject.Properties['Script']) { $Analyzer.Script } else { $null }
    $scriptName = $null

    if ($scriptInfo) {
        if ($scriptInfo.PSObject -and $scriptInfo.PSObject.Properties['Name']) {
            $scriptName = [string]$scriptInfo.Name
        } else {
            try {
                $scriptName = [System.IO.Path]::GetFileName($scriptInfo)
            } catch {
                $scriptName = [string]$scriptInfo
            }
        }
    }

    if (-not $scriptName) { return 'DHCP check' }

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName)
    if ($baseName.StartsWith('Analyze-')) {
        $baseName = $baseName.Substring(8)
    }

    if (-not $baseName) { return 'DHCP check' }

    $kebab = ConvertTo-KebabCase $baseName
    if (-not $kebab) { $kebab = $baseName }

    $rawParts = $kebab -split '-'
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($part in $rawParts) {
        if (-not $part) { continue }

        $upper = $part.ToUpperInvariant()
        switch ($upper) {
            'DHCP' { $parts.Add('DHCP') | Out-Null; continue }
            'APIPA' { $parts.Add('APIPA') | Out-Null; continue }
        }

        $text = $part.Substring(0,1).ToUpperInvariant()
        if ($part.Length -gt 1) {
            $text += $part.Substring(1).ToLowerInvariant()
        }
        $parts.Add($text) | Out-Null
    }

    if ($parts.Count -eq 0) { return 'DHCP check' }
    return ($parts -join ' ')
}

function Invoke-DhcpAnalyzers {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult,

        [string]$InputFolder
    )

    Write-HeuristicDebug -Source 'Network' -Message 'Entering Invoke-DhcpAnalyzers' -Data ([ordered]@{
        InputFolder = $InputFolder
    })

    if (-not $InputFolder) {
        Write-Host 'DHCP analyzers skipped: no InputFolder provided.'
        return
    }
    if (-not (Test-Path -LiteralPath $InputFolder)) {
        Write-Host ("DHCP analyzers skipped: folder '{0}' not found." -f $InputFolder)
        return
    }

    $analyzerRoot = Join-Path -Path $PSScriptRoot -ChildPath 'DHCP'
    if (-not (Test-Path -LiteralPath $analyzerRoot)) {
        Write-Host ("DHCP analyzers skipped: analyzer root '{0}' not found." -f $analyzerRoot)
        return
    }

    $scriptFiles = Get-ChildItem -Path $analyzerRoot -Filter 'Analyze-Dhcp*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name
    if (-not $scriptFiles -or $scriptFiles.Count -eq 0) {
        Write-Host ("DHCP analyzers missing scripts: searched '{0}' for pattern 'Analyze-Dhcp*.ps1'." -f $analyzerRoot)
        return
    }

    Write-HeuristicDebug -Source 'Network' -Message 'Resolved DHCP analyzer scripts' -Data ([ordered]@{
        AnalyzerRoot = $analyzerRoot
        ScriptCount  = $scriptFiles.Count
    })

    $eligibleAnalyzers = @()
    foreach ($script in $scriptFiles) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script.Name)
        if (-not $baseName.StartsWith('Analyze-')) { continue }
        $suffix = $baseName.Substring(8)
        if (-not $suffix) { continue }

        $artifactBase = ConvertTo-KebabCase $suffix
        if (-not $artifactBase) { continue }

        $artifactPath = Join-Path -Path $InputFolder -ChildPath ($artifactBase + '.json')
        if (Test-Path -LiteralPath $artifactPath) {
            $eligibleAnalyzers += [pscustomobject]@{
                Script       = $script
                ArtifactBase = $artifactBase
                ArtifactPath = (Resolve-Path -LiteralPath $artifactPath).ProviderPath
            }
        } else {
            Write-Host (
                "DHCP analyzer '{0}' skipped: artifact '{1}.json' not found in '{2}'." -f 
                $script.Name,
                $artifactBase,
                $InputFolder
            )
        }
    }

    if ($eligibleAnalyzers.Count -eq 0) {
        Write-Host ("DHCP analyzers skipped: no eligible artifacts discovered in '{0}'." -f $InputFolder)
        return
    }

    Write-HeuristicDebug -Source 'Network' -Message 'Eligible DHCP analyzers' -Data ([ordered]@{
        EligibleCount = $eligibleAnalyzers.Count
        Artifacts     = ($eligibleAnalyzers | ForEach-Object { $_.ArtifactBase })
    })

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($analyzer in $eligibleAnalyzers) {
        try {
            $result = & $analyzer.Script.FullName -InputFolder $InputFolder -CategoryResult $CategoryResult -Context $Context
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
        foreach ($analyzer in $eligibleAnalyzers) {
            $checkName = Get-DhcpAnalyzerDisplayName -Analyzer $analyzer
            $evidence = [ordered]@{
                Check    = $checkName
                Artifact = "$($analyzer.ArtifactBase).json"
                Folder   = $InputFolder
            }

            if ($analyzer.Script -and $analyzer.Script.PSObject -and $analyzer.Script.PSObject.Properties['FullName']) {
                $evidence['Script'] = $analyzer.Script.FullName
            }

            Add-CategoryNormal -CategoryResult $CategoryResult -Title ("{0} check healthy" -f $checkName) -Evidence $evidence -Subcategory 'DHCP'
        }
    }
}


function Get-WlanLines {
    param($Value)

    $lines = @()
    foreach ($item in (ConvertTo-NetworkArray $Value)) {
        if ($null -ne $item) {
            $lines += [string]$item
        }
    }

    return $lines
}

function ConvertTo-WlanInterfaces {
    param($Raw)

    $interfaces = [System.Collections.Generic.List[object]]::new()
    $lines = Get-WlanLines $Raw
    $current = $null

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^Name\s*:\s*(.+)$') {
            $current = [ordered]@{ Name = $Matches[1].Trim() }
            $interfaces.Add([pscustomobject]$current) | Out-Null
            continue
        }

        if (-not $current) { continue }
        if ($trimmed -match '^([^:]+)\s*:\s*(.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()

            switch -Regex ($key) {
                '^Description$' { $current['Description'] = $value; continue }
                '^GUID$'        { $current['Guid'] = $value; continue }
                '^Physical address$' { $current['Mac'] = $value; continue }
                '^State$'       { $current['State'] = $value; continue }
                '^SSID$'        { $current['Ssid'] = $value; continue }
                '^BSSID$'       { $current['Bssid'] = $value; continue }
                '^Authentication$' { $current['Authentication'] = $value; continue }
                '^Cipher$'      { $current['Cipher'] = $value; continue }
                '^Connection mode$' { $current['ConnectionMode'] = $value; continue }
                '^Radio type$'  { $current['RadioType'] = $value; continue }
                '^Profile$'     { $current['Profile'] = $value; continue }
            }
        }
    }

    return $interfaces.ToArray()
}

function ConvertTo-WlanNetworks {
    param($Raw)

    $entries = [System.Collections.Generic.List[object]]::new()
    $lines = Get-WlanLines $Raw
    $current = $null

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^SSID\s+\d+\s*:\s*(.*)$') {
            $ssid = $Matches[1].Trim()
            $current = [ordered]@{
                Ssid            = $ssid
                Authentications = New-Object System.Collections.Generic.List[string]
                Encryptions     = New-Object System.Collections.Generic.List[string]
            }
            $entries.Add([pscustomobject]$current) | Out-Null
            continue
        }

        if (-not $current) { continue }

        if ($trimmed -match '^Authentication\s*:\s*(.+)$') {
            $value = $Matches[1].Trim()
            if ($value -and -not $current.Authentications.Contains($value)) {
                $current.Authentications.Add($value) | Out-Null
            }
            continue
        }

        if ($trimmed -match '^Encryption\s*:\s*(.+)$') {
            $value = $Matches[1].Trim()
            if ($value -and -not $current.Encryptions.Contains($value)) {
                $current.Encryptions.Add($value) | Out-Null
            }
            continue
        }
    }

    return $entries.ToArray()
}

function ConvertTo-WlanProfileInfo {
    param($Detail)

    if (-not $Detail) { return $null }

    $info = [ordered]@{
        Name                    = $Detail.Name
        Authentication          = $null
        AuthenticationFallback  = $null
        Encryption              = $null
        EncryptionFallback      = $null
        UseOneX                 = $null
        PassphraseMetrics       = $null
        PassphraseMetricsError  = $null
        EapConfigPresent        = $false
        XmlError                = $null
    }

    $xmlText = $null
    if ($Detail.PSObject.Properties['Xml'] -and $Detail.Xml) {
        $xmlText = [string]$Detail.Xml
    } elseif ($Detail.PSObject.Properties['XmlError'] -and $Detail.XmlError) {
        $info.XmlError = [string]$Detail.XmlError
    }

    if ($xmlText) {
        try {
            $xml = [xml]$xmlText
            $profileNode = $xml.WLANProfile
            if ($profileNode -and $profileNode.MSM -and $profileNode.MSM.security) {
                $security = $profileNode.MSM.security
                if ($security.authEncryption) {
                    $auth = $security.authEncryption
                    if ($auth.authentication) { $info.Authentication = [string]$auth.authentication }
                    if ($auth.encryption) { $info.Encryption = [string]$auth.encryption }
                    if ($auth.useOneX -ne $null) {
                        try {
                            $info.UseOneX = [System.Convert]::ToBoolean($auth.useOneX)
                        } catch {
                            $text = [string]$auth.useOneX
                            if ($text) {
                                $info.UseOneX = ($text.Trim().ToLowerInvariant() -eq 'true')
                            }
                        }
                    }
                }
            }

            $eapNode = $xml.SelectSingleNode("//*[local-name()='EAPConfig']")
            if ($eapNode) {
                $info.EapConfigPresent = $true
            }
        } catch {
            $info.XmlError = $_.Exception.Message
        }
    }

    $profileLines = Get-WlanLines ($Detail.PSObject.Properties['ShowProfile'] ? $Detail.ShowProfile : $null)
    foreach ($line in $profileLines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if (-not $info.AuthenticationFallback -and $trimmed -match '^Authentication\s*:\s*(.+)$') {
            $info.AuthenticationFallback = $Matches[1].Trim()
            continue
        }

        if (-not $info.EncryptionFallback -and $trimmed -match '^Cipher\s*:\s*(.+)$') {
            $info.EncryptionFallback = $Matches[1].Trim()
            continue
        }
        
        if ($info.UseOneX -eq $null -and $trimmed -match '^Security key\s*:\s*(.+)$') {
            $keyType = $Matches[1].Trim()
            if ($keyType -match '802\.1X|EAP') { $info.UseOneX = $true }
        }
    }

    if ($info.UseOneX -eq $null -and $info.EapConfigPresent) {
        $info.UseOneX = $true
    }
    
    if ($Detail.PSObject.Properties['PassphraseMetrics'] -and $Detail.PassphraseMetrics) {
        $info.PassphraseMetrics = $Detail.PassphraseMetrics
    }
    if ($Detail.PSObject.Properties['PassphraseMetricsError'] -and $Detail.PassphraseMetricsError) {
        $info.PassphraseMetricsError = [string]$Detail.PassphraseMetricsError
    }

    return [pscustomobject]$info
}

function ConvertTo-WlanProfileInfos {
    param($Profiles)

    $results = [System.Collections.Generic.List[object]]::new()
    if (-not $Profiles) { return $results.ToArray() }

    $details = $null
    if ($Profiles.PSObject -and $Profiles.PSObject.Properties['Details']) {
        $details = $Profiles.Details
    } elseif ($Profiles -is [System.Collections.IEnumerable]) {
        $details = $Profiles
    }

    foreach ($detail in (ConvertTo-NetworkArray $details)) {
        $info = ConvertTo-WlanProfileInfo $detail
        if ($info) { $results.Add($info) | Out-Null }
    }

    return $results.ToArray()
}

function Normalize-WlanAuthToken {
    param([string]$Text)

    if (-not $Text) { return $null }
    $token = $Text.Trim()
    if (-not $token) { return $null }

    try {
        $token = $token.ToUpperInvariant()
    } catch {
        $token = ([string]$token).ToUpperInvariant()
    }

    return ($token -replace '[^A-Z0-9]', '')
}

function Get-WlanSecurityCategoryFromToken {
    param(
        [string]$Token,
        [Nullable[bool]]$UseOneX
    )

    if (-not $Token) { return $null }

    if ($Token -match 'WPA3' -and $Token -match 'SAE' -and $Token -match 'TRANS') { return 'WPA3PersonalTransition' }
    if ($Token -match 'WPA3' -and $Token -match 'SAE') { return 'WPA3Personal' }
    if ($Token -match 'WPA3' -and ($Token -match 'ENT' -or $Token -match 'ENTERPRISE')) {
        if ($Token -match '192') { return 'WPA3Enterprise192' }
        if ($Token -match 'TRANS') { return 'WPA3EnterpriseTransition' }
        return 'WPA3Enterprise'
    }
    if ($Token -match 'WPA2' -and ($Token -match 'PSK' -or $Token -match 'PERSONAL')) { return 'WPA2Personal' }
    if ($Token -match 'WPA2' -and ($Token -match 'ENT' -or $Token -match 'ENTERPRISE')) { return 'WPA2Enterprise' }
    if ($Token -eq 'WPA2') {
        if ($UseOneX -ne $null) {
            if ($UseOneX) { return 'WPA2Enterprise' }
            return 'WPA2Personal'
        }
        return 'WPA2'
    }
    if ($Token -match 'WPA' -and ($Token -match 'PSK' -or $Token -match 'PERSONAL')) { return 'WPAPersonal' }
    if ($Token -match 'WPA' -and ($Token -match 'ENT' -or $Token -match 'ENTERPRISE')) { return 'WPAEnterprise' }
    if ($Token -match 'WEP') { return 'WEP' }
    if ($Token -match 'OPEN' -or $Token -match 'NONE') { return 'Open' }
    if ($Token -match 'SAE') { return 'WPA3Personal' }

    return $null
}

function Get-WlanSecurityCategory {
    param(
        [string[]]$AuthTexts,
        [Nullable[bool]]$UseOneX
    )

    foreach ($auth in $AuthTexts) {
        $token = Normalize-WlanAuthToken $auth
        $category = Get-WlanSecurityCategoryFromToken -Token $token -UseOneX $UseOneX
        if ($category) { return $category }
    }

    if ($UseOneX -ne $null) {
        if ($UseOneX) { return 'WPA2Enterprise' }
        return 'WPA2Personal'
    }

    return $null
}

function Test-WlanCipherIncludesTkip {
    param([string[]]$CipherTexts)

    foreach ($cipher in $CipherTexts) {
        if (-not $cipher) { continue }
        $token = Normalize-WlanAuthToken $cipher
        if ($token -match 'TKIP') { return $true }
    }

    return $false
}

function Invoke-NetworkHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context,

        [string]$InputFolder
    )

    Write-HeuristicDebug -Source 'Network' -Message 'Starting network heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
        InputFolder   = $InputFolder
    })

    $rootCandidate = $null
    $rootCandidateSource = 'context'
    if ($PSBoundParameters.ContainsKey('InputFolder') -and -not [string]::IsNullOrWhiteSpace($InputFolder)) {
        $rootCandidate = $InputFolder
        $rootCandidateSource = 'parameter'
    } elseif ($Context -and $Context.PSObject.Properties['InputFolder'] -and $Context.InputFolder) {
        $rootCandidate = $Context.InputFolder
    }

    Write-HeuristicDebug -Source 'Network' -Message 'Evaluating network collection root candidate' -Data ([ordered]@{
        Source        = $rootCandidateSource
        RootCandidate = $rootCandidate
    })

    $resolvedRoot = $null
    if ($rootCandidate) {
        try {
            $resolvedRoot = (Resolve-Path -LiteralPath $rootCandidate -ErrorAction Stop).ProviderPath
        } catch {
            Write-Warning ("Network: unable to resolve InputFolder '{0}'" -f $rootCandidate)
            $resolvedRoot = $rootCandidate
        }
    } else {
        Write-Warning 'Network: missing InputFolder'
    }

    Write-HeuristicDebug -Source 'Network' -Message 'Resolved network collection root' -Data ([ordered]@{
        RequestedRoot = $rootCandidate
        ResolvedRoot  = $resolvedRoot
        Resolved      = [bool]$resolvedRoot
    })

    $dhcpFolder = if ($resolvedRoot) { Join-Path -Path $resolvedRoot -ChildPath 'DHCP' } else { $null }

    Write-HeuristicDebug -Source 'Network' -Message 'Computed DHCP folder path' -Data ([ordered]@{
        CollectionRoot = $resolvedRoot
        DhcpFolder     = $dhcpFolder
        Exists         = if ($dhcpFolder) { Test-Path -LiteralPath $dhcpFolder } else { $false }
    })

    $result = New-CategoryResult -Name 'Network'

    $computerSystem = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved system artifact' -Data ([ordered]@{
        Found = [bool]$systemArtifact
    })
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating system payload for network context' -Data ([ordered]@{
            HasPayload = [bool]$systemPayload
        })
        if ($systemPayload -and $systemPayload.ComputerSystem -and -not $systemPayload.ComputerSystem.Error) {
            $computerSystem = $systemPayload.ComputerSystem
        }
    }

    $adapterPayload = $null
    $adapterInventory = $null
    $adapterArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-adapters'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved network-adapters artifact' -Data ([ordered]@{
        Found = [bool]$adapterArtifact
    })
    if ($adapterArtifact) {
        $adapterPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $adapterArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating adapter payload' -Data ([ordered]@{
            HasPayload = [bool]$adapterPayload
        })
    }
    $adapterInventory = Get-NetworkDnsInterfaceInventory -AdapterPayload $adapterPayload

    $networkArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved network artifact' -Data ([ordered]@{
        Found = [bool]$networkArtifact
    })
    if ($networkArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $networkArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating network payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        $arpEntries = @()
        if ($payload -and $payload.Arp) {
            $arpEntries = ConvertTo-NetworkArpEntries -Value $payload.Arp
        }
        Write-HeuristicDebug -Source 'Network' -Message 'Parsed ARP entries' -Data ([ordered]@{
            Count = if ($arpEntries) { $arpEntries.Count } else { 0 }
        })

        $gatewayInventory = $null
        if ($adapterInventory -and $adapterInventory.Map) {
            $gatewayInventory = $adapterInventory.Map
        }

        if ($arpEntries.Count -gt 0 -and $gatewayInventory) {
            $gatewayMap = @{}
            $localMacs = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            $localIps = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($adapterInfo in $gatewayInventory.Values) {
                if (-not $adapterInfo) { continue }
                if ($adapterInfo.MacAddress) { $localMacs.Add($adapterInfo.MacAddress) | Out-Null }

                foreach ($ipText in $adapterInfo.IPv4) {
                    $canon = Get-NetworkCanonicalIpv4 $ipText
                    if ($canon) { $localIps.Add($canon) | Out-Null }
                }

                foreach ($gwText in $adapterInfo.Gateways) {
                    $gw = Get-NetworkCanonicalIpv4 $gwText
                    if (-not $gw) { continue }

                    if (-not $gatewayMap.ContainsKey($gw)) {
                        $gatewayMap[$gw] = [pscustomobject]@{
                            Gateway        = $gw
                            Interfaces     = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                            ArpMatches     = New-Object System.Collections.Generic.List[pscustomobject]
                        }
                    }

                    $gatewayMap[$gw].Interfaces.Add($adapterInfo.Alias) | Out-Null
                }
            }

            foreach ($entry in $arpEntries) {
                if (-not $entry -or -not $entry.InternetAddress) { continue }
                $gw = Get-NetworkCanonicalIpv4 $entry.InternetAddress
                if (-not $gw) { continue }
                if (-not $gatewayMap.ContainsKey($gw)) { continue }

                $gatewayMap[$gw].ArpMatches.Add($entry) | Out-Null
            }

            $observedGatewayEntries = New-Object System.Collections.Generic.List[pscustomobject]
            $macToGateways = @{}

            foreach ($gateway in $gatewayMap.Keys) {
                $detail = $gatewayMap[$gateway]
                if (-not $detail) { continue }

                $match = $detail.ArpMatches | Select-Object -First 1
                if (-not $match) { continue }

                $entryRecord = [pscustomobject]@{
                    Gateway      = $gateway
                    Interfaces   = $detail.Interfaces.ToArray()
                    NormalizedMac = $match.NormalizedMac
                    Type         = $match.Type
                }

                $observedGatewayEntries.Add($entryRecord) | Out-Null

                if ($match.NormalizedMac) {
                    if (-not $macToGateways.ContainsKey($match.NormalizedMac)) {
                        $macToGateways[$match.NormalizedMac] = New-Object System.Collections.Generic.List[string]
                    }

                    $macToGateways[$match.NormalizedMac].Add($gateway) | Out-Null
                }
            }

            $baselineSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

            $baselineArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-gateway-baseline'
            if ($baselineArtifact) {
                $baselinePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $baselineArtifact)
                if ($baselinePayload) {
                    $baselineValues = if ($baselinePayload.PSObject.Properties['GatewayMacs']) { ConvertTo-NetworkArray $baselinePayload.GatewayMacs } else { ConvertTo-NetworkArray $baselinePayload }
                    foreach ($baselineValue in $baselineValues) {
                        $normalizedBaseline = Normalize-NetworkMacAddress $baselineValue
                        if ($normalizedBaseline) { $baselineSet.Add($normalizedBaseline) | Out-Null }
                    }
                }
            }

            if ($Context -and $Context.PSObject.Properties['NetworkAnalyzerState'] -and $Context.NetworkAnalyzerState -and $Context.NetworkAnalyzerState.PSObject.Properties['GatewayMacs']) {
                foreach ($historicalMac in (ConvertTo-NetworkArray $Context.NetworkAnalyzerState.GatewayMacs)) {
                    $normalizedHistorical = Normalize-NetworkMacAddress $historicalMac
                    if ($normalizedHistorical) { $baselineSet.Add($normalizedHistorical) | Out-Null }
                }
            }

            $observedMacs = New-Object System.Collections.Generic.List[string]
            foreach ($entry in $observedGatewayEntries) {
                if ($entry.NormalizedMac) { $observedMacs.Add($entry.NormalizedMac) | Out-Null }
            }

            $unexpected = @()
            if ($baselineSet.Count -gt 0) {
                foreach ($mac in $observedMacs) {
                    if (-not $baselineSet.Contains($mac)) { $unexpected += $mac }
                }
            }

            if ($unexpected.Count -gt 0) {
                $gatewayText = ($observedGatewayEntries | Where-Object { $_.NormalizedMac -and ($unexpected -contains $_.NormalizedMac) } | ForEach-Object { "{0}→{1}" -f $_.Gateway, $_.NormalizedMac } | Sort-Object)
                $evidence = if ($gatewayText) { $gatewayText -join '; ' } else { $unexpected -join ', ' }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Gateway MAC address changed, so users could be routed through an untrusted device.' -Evidence $evidence -Subcategory 'ARP Cache'
            }

            $duplicateGatewayMacs = @()
            foreach ($mac in $macToGateways.Keys) {
                $gateways = $macToGateways[$mac]
                if ($gateways.Count -gt 1) {
                    $duplicateGatewayMacs += [pscustomobject]@{
                        Mac      = $mac
                        Gateways = ($gateways | Sort-Object -Unique)
                    }
                }
            }

            if ($duplicateGatewayMacs.Count -gt 0) {
                $evidence = ($duplicateGatewayMacs | ForEach-Object { "{0} used by {1}" -f $_.Mac, ($_.Gateways -join ', ') }) -join '; '
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Multiple gateways share the same MAC, so traffic may be hijacked by a spoofing bridge.' -Evidence $evidence -Subcategory 'ARP Cache'
            }

            $suspiciousOuiMap = @{
                '00:00:00' = 'all-zero'
                'FF:FF:FF' = 'broadcast'
                '08:00:27' = 'VirtualBox'
                '00:05:69' = 'VMware'
                '00:0C:29' = 'VMware'
                '00:1C:14' = 'VMware'
                '00:50:56' = 'VMware'
                '00:15:5D' = 'Hyper-V'
                '00:16:3E' = 'Xen'
                '00:1C:42' = 'Parallels'
            }

            $suspiciousEntries = @()
            foreach ($entry in $observedGatewayEntries) {
                if (-not $entry.NormalizedMac) { continue }
                $oui = Get-NetworkMacOui $entry.NormalizedMac
                if (-not $oui) { continue }
                if ($suspiciousOuiMap.ContainsKey($oui)) {
                    $descriptor = $suspiciousOuiMap[$oui]
                    $suspiciousEntries += "{0}→{1} ({2})" -f $entry.Gateway, $entry.NormalizedMac, $descriptor
                }
            }

            if ($suspiciousEntries.Count -gt 0) {
                $evidence = $suspiciousEntries -join '; '
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Gateway resolved to a suspicious vendor MAC, so users may be redirected through a malicious host.' -Evidence $evidence -Subcategory 'ARP Cache'
            }

            $poisonCandidates = @()
            foreach ($entry in $arpEntries) {
                if (-not $entry) { continue }
                $mac = $entry.NormalizedMac
                $typeText = if ($entry.Type) { [string]$entry.Type } else { '' }

                if (($mac -and ($mac -eq 'FF:FF:FF:FF:FF:FF' -or $mac -eq '00:00:00:00:00:00')) -or ($typeText -and $typeText.ToLowerInvariant() -match 'invalid|incomplete')) {
                    $macDisplay = if ($mac) { $mac } else { 'unknown' }
                    $typeDisplay = if ($typeText) { $typeText } else { 'unknown type' }
                    $poisonCandidates += "{0}→{1} ({2})" -f $entry.InternetAddress, $macDisplay, $typeDisplay
                }
            }

            if ($poisonCandidates.Count -gt 0) {
                $evidence = $poisonCandidates -join '; '
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'ARP cache includes broadcast or invalid MAC replies, so endpoint connectivity may flap from poisoning attempts.' -Evidence $evidence -Subcategory 'ARP Cache'
            }

            $localMacAlerts = @()
            foreach ($mac in $localMacs) {
                $matches = $arpEntries | Where-Object { $_.NormalizedMac -and $_.NormalizedMac.Equals($mac, [System.StringComparison]::OrdinalIgnoreCase) }
                if (-not $matches) { continue }

                $remoteIps = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($match in $matches) {
                    $ip = Get-NetworkCanonicalIpv4 $match.InternetAddress
                    if (-not $ip) { continue }
                    if ($localIps.Contains($ip)) { continue }
                    $remoteIps.Add($ip) | Out-Null
                }

                if ($remoteIps.Count -gt 1) {
                    $localMacAlerts += "{0} impersonates IPs {1}" -f $mac, ($remoteIps.ToArray() -join ', ')
                }
            }

            if ($localMacAlerts.Count -gt 0) {
                $evidence = $localMacAlerts -join '; '
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Host MAC responds for multiple IPs, so neighbors may lose connectivity to their addresses.' -Evidence $evidence -Subcategory 'ARP Cache'
            }

            if ($Context) {
                if (-not $Context.PSObject.Properties['NetworkAnalyzerState'] -or -not $Context.NetworkAnalyzerState) {
                    $Context | Add-Member -NotePropertyName 'NetworkAnalyzerState' -NotePropertyValue ([pscustomobject]@{ GatewayMacs = New-Object System.Collections.Generic.List[string] }) -Force
                } elseif (-not $Context.NetworkAnalyzerState.PSObject.Properties['GatewayMacs']) {
                    $Context.NetworkAnalyzerState | Add-Member -NotePropertyName 'GatewayMacs' -NotePropertyValue (New-Object System.Collections.Generic.List[string]) -Force
                }

                $existingSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($existingMac in $Context.NetworkAnalyzerState.GatewayMacs) {
                    $normalizedExisting = Normalize-NetworkMacAddress $existingMac
                    if ($normalizedExisting) { $existingSet.Add($normalizedExisting) | Out-Null }
                }

                foreach ($mac in $observedMacs) {
                    if (-not $mac) { continue }
                    if ($existingSet.Add($mac)) {
                        $Context.NetworkAnalyzerState.GatewayMacs.Add($mac) | Out-Null
                    }
                }
            }
        }

        if ($payload -and $payload.IpConfig) {
            $ipText = if ($payload.IpConfig -is [string[]]) { $payload.IpConfig -join "`n" } else { [string]$payload.IpConfig }
            if ($ipText -match 'IPv4 Address') {
                Add-CategoryNormal -CategoryResult $result -Title 'IPv4 addressing detected' -Subcategory 'IP Configuration'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No IPv4 configuration found, so connectivity will fail without valid addressing.' -Evidence 'ipconfig /all output did not include IPv4 details.' -Subcategory 'IP Configuration'
            }
        }

        if ($payload -and $payload.Route) {
            $routeText = if ($payload.Route -is [string[]]) { $payload.Route -join "`n" } else { [string]$payload.Route }
            if ($routeText -notmatch '0\.0\.0\.0') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Routing table missing default route, so outbound connectivity will fail.' -Evidence 'route print output did not include 0.0.0.0/0.' -Subcategory 'Routing'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Network base diagnostics not collected, so connectivity failures may go undetected.' -Subcategory 'Collection'
    }

    $dnsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'dns'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved dns artifact' -Data ([ordered]@{
        Found = [bool]$dnsArtifact
    })
    if ($dnsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $dnsArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating DNS payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        if ($payload -and $payload.Resolution) {
            $failures = $payload.Resolution | Where-Object { $_.Success -eq $false }
            if ($failures.Count -gt 0) {
                $names = $failures.Name
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('DNS lookup failures: {0} — DNS resolution is failing.' -f ($names -join ', ')) -Subcategory 'DNS Resolution'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'DNS lookups succeeded' -Subcategory 'DNS Resolution'
            }
        }

        if ($payload -and $payload.Latency) {
            $latency = $payload.Latency
            if ($latency.PSObject.Properties['PingSucceeded']) {
                $remoteAddress = ConvertTo-NetworkAddressString $latency.RemoteAddress
                if (-not $remoteAddress) { $remoteAddress = 'DNS server' }
                if (-not $latency.PingSucceeded) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Ping to DNS {0} failed, showing DNS resolution is failing.' -f $remoteAddress) -Subcategory 'Latency'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title ('Ping to DNS {0} succeeded' -f $remoteAddress) -Subcategory 'Latency'
                }
            } elseif ($latency -is [string] -and $latency -match 'Request timed out') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Latency test reported timeouts, showing DNS resolution is failing.' -Subcategory 'Latency'
            }
        }

        if ($payload -and $payload.Autodiscover) {
            $autoErrors = $payload.Autodiscover | Where-Object { $_.Error }
            if ($autoErrors.Count -gt 0) {
                $details = $autoErrors | Select-Object -ExpandProperty Error -First 3
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Autodiscover DNS queries failed, so missing or invalid records can cause mail setup failures.' -Evidence ($details -join "`n") -Subcategory 'DNS Autodiscover'
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
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate DNS servers, so name resolution may fail on domain devices.' -Evidence $entry.Error -Subcategory 'DNS Client'
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
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Adapters missing DNS servers: {0}, so name resolution may fail on domain devices.' -f ($missingInterfaces -join ', ')) -Subcategory 'DNS Client'
            }

            if ($ignoredPseudo.Count -gt 0) {
                $pseudoTitle = "Ignored {0} pseudo/virtual adapters (loopback/ICS/Hyper-V) without DNS — not used for normal name resolution." -f $ignoredPseudo.Count
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $pseudoTitle -Evidence ($ignoredPseudo -join ', ') -Subcategory 'DNS Client'
            }

            if ($publicServers.Count -gt 0) {
                $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                $unique = ($publicServers | Select-Object -Unique)
                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ('Public DNS servers detected: {0}, risking resolution failures on domain devices.' -f ($unique -join ', ')) -Evidence 'Prioritize internal DNS for domain services.' -Subcategory 'DNS Client'
            } elseif (-not $loopbackOnly) {
                Add-CategoryNormal -CategoryResult $result -Title 'Private DNS servers detected' -Subcategory 'DNS Client'
            }
        }

        if ($payload -and $payload.ClientPolicies) {
            $policies = ConvertTo-NetworkArray $payload.ClientPolicies
            foreach ($policy in $policies) {
                if ($policy -and $policy.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'DNS client policy query failed, so name resolution policy issues may be hidden and cause failures.' -Evidence $policy.Error -Subcategory 'DNS Client'
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
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("DNS registration disabled on {0}, so name resolution may fail on domain devices." -f $alias) -Evidence 'RegisterThisConnectionsAddress = False' -Subcategory 'DNS Client'
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'DNS diagnostics not collected, so latency and name resolution issues may be missed.' -Subcategory 'DNS Resolution'
    }

    $outlookArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-connectivity'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved outlook-connectivity artifact' -Data ([ordered]@{
        Found = [bool]$outlookArtifact
    })
    if ($outlookArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $outlookArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating Outlook connectivity payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        if ($payload -and $payload.Connectivity) {
            $conn = $payload.Connectivity
                if ($conn.PSObject.Properties['TcpTestSucceeded']) {
                    if (-not $conn.TcpTestSucceeded) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title "Outlook HTTPS connectivity failed, so Outlook can't connect to Exchange Online." -Evidence ('TcpTestSucceeded reported False for {0}' -f $conn.RemoteAddress) -Subcategory 'Outlook Connectivity'
                    } else {
                        Add-CategoryNormal -CategoryResult $result -Title 'Outlook HTTPS connectivity succeeded' -Subcategory 'Outlook Connectivity'
                }
            } elseif ($conn.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to test Outlook connectivity, leaving potential loss of access to Exchange Online unverified.' -Evidence $conn.Error -Subcategory 'Outlook Connectivity'
            }
        }

    }

    $autodiscoverArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autodiscover-dns'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved autodiscover-dns artifact' -Data ([ordered]@{
        Found = [bool]$autodiscoverArtifact
    })
    if ($autodiscoverArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autodiscoverArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating autodiscover payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
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
                        Add-CategoryNormal -CategoryResult $result -Title ("Autodiscover healthy for {0}" -f $domain) -Evidence $targetText -Subcategory 'Autodiscover DNS'
                    } else {
                        $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'medium' } else { 'low' }
                        Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover for {0} targets {1}, so mail setup may fail for Exchange Online." -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.' -Subcategory 'Autodiscover DNS'
                    }
                } elseif ($autoRecord.Success -eq $false) {
                    $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                    $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover lookup failed for {0}, so mail setup may fail." -f $domain) -Evidence $evidence -Subcategory 'Autodiscover DNS'
                }

                foreach ($additional in ($lookups | Where-Object { $_.Label -ne 'Autodiscover' })) {
                    if (-not $additional) { continue }
                    if ($additional.Success -eq $false -and $additional.Error) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("{0} record missing for {1}, so mail setup may fail." -f $additional.Label, $domain) -Evidence $additional.Error -Subcategory 'Autodiscover DNS'
                    }
                }
            }
        }
    }

    if ($adapterPayload -and $adapterPayload.PSObject.Properties['Adapters']) {
        $adapters = ConvertTo-NetworkArray $adapterPayload.Adapters
        if ($adapters.Count -eq 1 -and ($adapters[0] -is [pscustomobject]) -and $adapters[0].PSObject.Properties['Error'] -and $adapters[0].Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate network adapters, so link status is unknown.' -Evidence $adapters[0].Error -Subcategory 'Network Adapters'
        } elseif ($adapters.Count -gt 0) {
            $upAdapters = $adapters | Where-Object { $_ -and $_.Status -eq 'Up' }
            if ($upAdapters.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Active adapters: {0}' -f ($upAdapters.Name -join ', ')) -Subcategory 'Network Adapters'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No active network adapters reported, so the device has no path for network connectivity.' -Subcategory 'Network Adapters'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Network adapter inventory incomplete, so link status is unknown.' -Subcategory 'Network Adapters'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Network adapter inventory not collected, so link status is unknown.' -Subcategory 'Network Adapters'
    }

    $proxyArtifact = Get-AnalyzerArtifact -Context $Context -Name 'proxy'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved proxy artifact' -Data ([ordered]@{
        Found = [bool]$proxyArtifact
    })
    if ($proxyArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $proxyArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating proxy payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        if ($payload -and $payload.Internet) {
            $internet = $payload.Internet
            if ($internet.ProxyEnable -eq 1 -and $internet.ProxyServer) {
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ('User proxy enabled: {0}' -f $internet.ProxyServer) -Subcategory 'Proxy Configuration'
            } elseif ($internet.ProxyEnable -eq 0) {
                Add-CategoryNormal -CategoryResult $result -Title 'User proxy disabled' -Subcategory 'Proxy Configuration'
            }
        }

        if ($payload -and $payload.WinHttp) {
            $winHttpText = if ($payload.WinHttp -is [string[]]) { $payload.WinHttp -join "`n" } else { [string]$payload.WinHttp }
            if ($winHttpText -match 'Direct access') {
                Add-CategoryNormal -CategoryResult $result -Title 'WinHTTP proxy: Direct access' -Subcategory 'Proxy Configuration'
            } elseif ($winHttpText) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WinHTTP proxy configured' -Evidence $winHttpText -Subcategory 'Proxy Configuration'
            }
        }
    }

    $wlanArtifact = Get-AnalyzerArtifact -Context $Context -Name 'wlan'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved wlan artifact' -Data ([ordered]@{
        Found = [bool]$wlanArtifact
    })
    if ($wlanArtifact) {
        $wlanPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wlanArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating wlan payload' -Data ([ordered]@{
            HasPayload = [bool]$wlanPayload
        })
        if ($wlanPayload -and $wlanPayload.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Wireless diagnostics unavailable, so Wi-Fi security posture is unknown.' -Evidence $wlanPayload.Error -Subcategory 'Security'
        } else {
            $interfaces = @()
            $profiles = @()
            $visibleNetworks = @()

            if ($wlanPayload.PSObject -and $wlanPayload.PSObject.Properties['Interfaces']) {
                $interfaces = ConvertTo-WlanInterfaces $wlanPayload.Interfaces
            }
            if ($wlanPayload.PSObject -and $wlanPayload.PSObject.Properties['Profiles']) {
                $profiles = ConvertTo-WlanProfileInfos $wlanPayload.Profiles
            }
            if ($wlanPayload.PSObject -and $wlanPayload.PSObject.Properties['Networks']) {
                $visibleNetworks = ConvertTo-WlanNetworks $wlanPayload.Networks
            }

            if ($interfaces.Count -eq 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Wireless interface inventory empty, so Wi-Fi security posture cannot be evaluated.' -Subcategory 'Security'
            } else {
                $connectedInterfaces = $interfaces | Where-Object { $_.State -and $_.State -match '(?i)connected' }
                if ($connectedInterfaces.Count -eq 0) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Not connected to Wi-Fi, so wireless encryption state is unknown.' -Subcategory 'Security'
                } else {
                    $primaryInterface = $connectedInterfaces | Select-Object -First 1

                    $profileName = if ($primaryInterface.Profile) { [string]$primaryInterface.Profile } elseif ($primaryInterface.Ssid) { [string]$primaryInterface.Ssid } else { $null }
                    $profileInfo = $null
                    if ($profileName) {
                        $profileInfo = $profiles | Where-Object { $_.Name -eq $profileName } | Select-Object -First 1
                    }
                    if (-not $profileInfo -and $profiles.Count -eq 1) { $profileInfo = $profiles[0] }

                    $authCandidates = New-Object System.Collections.Generic.List[string]
                    if ($primaryInterface.Authentication) { $authCandidates.Add([string]$primaryInterface.Authentication) | Out-Null }
                    if ($profileInfo -and $profileInfo.Authentication) { $authCandidates.Add([string]$profileInfo.Authentication) | Out-Null }
                    if ($profileInfo -and $profileInfo.AuthenticationFallback) { $authCandidates.Add([string]$profileInfo.AuthenticationFallback) | Out-Null }
                    $useOneX = if ($profileInfo) { $profileInfo.UseOneX } else { $null }
                    $securityCategory = Get-WlanSecurityCategory -AuthTexts $authCandidates.ToArray() -UseOneX $useOneX

                    $cipherCandidates = New-Object System.Collections.Generic.List[string]
                    if ($primaryInterface.Cipher) {
                        $splits = [regex]::Split([string]$primaryInterface.Cipher, '[,;/]+')
                        if (-not $splits -or $splits.Count -eq 0) { $splits = @([string]$primaryInterface.Cipher) }
                        foreach ($item in $splits) {
                            $trim = $item.Trim()
                            if ($trim) { $cipherCandidates.Add($trim) | Out-Null }
                        }
                    }
                    if ($profileInfo) {
                        foreach ($candidate in @($profileInfo.Encryption, $profileInfo.EncryptionFallback)) {
                            if ($candidate) { $cipherCandidates.Add([string]$candidate) | Out-Null }
                        }
                    }
                    $tkipAllowed = Test-WlanCipherIncludesTkip -CipherTexts $cipherCandidates.ToArray()

                    $ssid = if ($primaryInterface.Ssid) { [string]$primaryInterface.Ssid } else { $profileName }
                    $authenticationText = $null
                    foreach ($candidate in $authCandidates) {
                        if ($candidate) { $authenticationText = $candidate; break }
                    }
                    if (-not $authenticationText -and $securityCategory) { $authenticationText = $securityCategory }

                    $cipherText = if ($primaryInterface.Cipher) { [string]$primaryInterface.Cipher } elseif ($profileInfo -and $profileInfo.Encryption) { $profileInfo.Encryption } else { $null }

                    $profileEvidenceText = $null
                    if ($profileInfo -and ($profileInfo.Authentication -or $profileInfo.Encryption)) {
                        $profileParts = @()
                        if ($profileInfo.Authentication) { $profileParts += ('Auth={0}' -f $profileInfo.Authentication) }
                        if ($profileInfo.Encryption) { $profileParts += ('Encryption={0}' -f $profileInfo.Encryption) }
                        if ($profileParts.Count -gt 0) { $profileEvidenceText = 'netsh wlan export/show profile → ' + ($profileParts -join '; ') }
                    }

                    $interfaceEvidenceParts = New-Object System.Collections.Generic.List[string]
                    if ($ssid) { $interfaceEvidenceParts.Add(('SSID "{0}"' -f $ssid)) | Out-Null }
                    if ($authenticationText) { $interfaceEvidenceParts.Add(('Authentication={0}' -f $authenticationText)) | Out-Null }
                    if ($cipherText) { $interfaceEvidenceParts.Add(('Cipher={0}' -f $cipherText)) | Out-Null }
                    if ($primaryInterface.Profile -and $primaryInterface.Profile -ne $ssid) { $interfaceEvidenceParts.Add(('Profile={0}' -f $primaryInterface.Profile)) | Out-Null }
                    $interfaceEvidence = 'netsh wlan show interfaces → ' + ($interfaceEvidenceParts.ToArray() -join '; ')

                    $apMatches = @()
                    if ($ssid -and $visibleNetworks.Count -gt 0) {
                        $apMatches = $visibleNetworks | Where-Object { $_.Ssid -eq $ssid }
                    }
                    $apAuthValues = @()
                    $apAuthTokens = New-Object System.Collections.Generic.List[string]
                    foreach ($entry in $apMatches) {
                        foreach ($authValue in (ConvertTo-NetworkArray $entry.Authentications)) {
                            if (-not $authValue) { continue }
                            $apAuthValues += $authValue
                            $token = Normalize-WlanAuthToken $authValue
                            if ($token) { $apAuthTokens.Add($token) | Out-Null }
                        }
                    }
                    if ($apAuthValues.Count -gt 0) {
                        $apAuthValues = $apAuthValues | Sort-Object -Unique
                    }

                    $apSupportsWpa3 = ($apAuthTokens | Where-Object { $_ -match 'WPA3' }).Count -gt 0
                    $apSupportsWpa2 = ($apAuthTokens | Where-Object { $_ -match 'WPA2' }).Count -gt 0

                    $passphraseMetrics = if ($profileInfo) { $profileInfo.PassphraseMetrics } else { $null }
                    $passphraseMetricsError = if ($profileInfo) { $profileInfo.PassphraseMetricsError } else { $null }

                    $subcategory = 'Security'

                    $apEvidence = $null
                    if ($apAuthValues.Count -gt 0) {
                        $apEvidence = ('netsh wlan show networks mode=bssid → Authentication={0}' -f ($apAuthValues -join ', '))
                    }

                    $handledBasic = $false
                    if ($securityCategory -eq 'Open') {
                        $handledBasic = $true
                        $evidence = [ordered]@{
                            Interface = $interfaceEvidence
                        }
                        if ($apEvidence) { $evidence['AccessPoint'] = $apEvidence }
                        Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'Open (unencrypted) Wi-Fi network' -Evidence $evidence -Subcategory $subcategory
                    } elseif ($securityCategory -eq 'WEP') {
                        $handledBasic = $true
                        $evidence = [ordered]@{
                            Interface = $interfaceEvidence
                        }
                        if ($apEvidence) { $evidence['AccessPoint'] = $apEvidence }
                        Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'WEP network detected' -Evidence $evidence -Subcategory $subcategory
                    }

                    if (-not $handledBasic) {
                        if ($tkipAllowed) {
                            $tkipEvidence = [ordered]@{
                                Interface = $interfaceEvidence
                            }
                            if ($profileEvidenceText) { $tkipEvidence['Profile'] = $profileEvidenceText }
                            Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'WPA2 using TKIP (legacy cipher enabled)' -Evidence $tkipEvidence -Subcategory $subcategory
                        }

                        $isWpa3Personal = ($securityCategory -eq 'WPA3Personal' -or $securityCategory -eq 'WPA3PersonalTransition')
                        $isWpa3Enterprise = ($securityCategory -eq 'WPA3Enterprise' -or $securityCategory -eq 'WPA3EnterpriseTransition' -or $securityCategory -eq 'WPA3Enterprise192')

                        if ($isWpa3Personal) {
                            $evidence = [ordered]@{
                                Interface = $interfaceEvidence
                            }
                            if ($profileEvidenceText) { $evidence['Profile'] = $profileEvidenceText }
                            if ($apEvidence) { $evidence['AccessPoint'] = $apEvidence }
                            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WPA3-Personal active (SAE)' -Evidence $evidence -Subcategory $subcategory
                        }

                        if ($isWpa3Enterprise) {
                            $evidence = [ordered]@{
                                Interface = $interfaceEvidence
                            }
                            if ($profileEvidenceText) { $evidence['Profile'] = $profileEvidenceText }
                            if ($profileInfo -and $profileInfo.EapConfigPresent) { $evidence['EAP'] = 'Profile includes EAPConfig (certificate/802.1X)' }
                            if ($apEvidence) { $evidence['AccessPoint'] = $apEvidence }
                            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WPA3-Enterprise active' -Evidence $evidence -Subcategory $subcategory
                        }

                        if ($securityCategory -eq 'WPA2Enterprise') {
                            $evidence = [ordered]@{
                                Interface = $interfaceEvidence
                            }
                            if ($profileEvidenceText) { $evidence['Profile'] = $profileEvidenceText }
                            if ($profileInfo -and $profileInfo.EapConfigPresent) { $evidence['EAP'] = 'Profile shows 802.1X/EAP configuration' }
                            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'WPA2-Enterprise (802.1X/EAP)' -Evidence $evidence -Subcategory $subcategory
                        }

                        if ($securityCategory -eq 'WPA2Personal') {
                            $profileLabel = if ($profileName) { $profileName } elseif ($ssid) { $ssid } else { 'Wi-Fi profile' }
                            
                            if ($passphraseMetrics) {
                                $scoreValue = $null
                                $scoreCategory = 'Unknown'
                                if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['Score']) {
                                    try {
                                        $scoreValue = [int]$passphraseMetrics.Score
                                    } catch {
                                        $scoreValue = $null
                                    }
                                }
                                if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['Category'] -and $passphraseMetrics.Category) {
                                    $scoreCategory = [string]$passphraseMetrics.Category
                                }

                                $severity = 'medium'
                                if ($scoreValue -ne $null) {
                                    switch ($scoreValue) {
                                        { $_ -is [int] -and $_ -le 1 } { $severity = 'high'; break }
                                        2 { $severity = 'medium'; break }
                                        3 { $severity = 'low'; break }
                                        4 { $severity = 'low'; break }
                                        default { $severity = 'medium' }
                                    }
                                }

                                $parts = New-Object System.Collections.Generic.List[string]
                                if ($scoreValue -ne $null) { $parts.Add(('Score {0} ({1})' -f $scoreValue, $scoreCategory)) | Out-Null }
                                elseif ($scoreCategory) { $parts.Add(('Score category {0}' -f $scoreCategory)) | Out-Null }
                                if ($passphraseMetrics.PSObject.Properties['Length'] -and $passphraseMetrics.Length -ne $null) {
                                    $parts.Add(('Length {0}' -f $passphraseMetrics.Length)) | Out-Null
                                }
                                if ($passphraseMetrics.PSObject.Properties['EstimatedBits'] -and $passphraseMetrics.EstimatedBits -ne $null) {
                                    $parts.Add(('Estimated bits {0}' -f $passphraseMetrics.EstimatedBits)) | Out-Null
                                }
                                if ($passphraseMetrics.PSObject.Properties['EstimatedGuesses'] -and $passphraseMetrics.EstimatedGuesses) {
                                    $parts.Add(('Est. guesses {0}' -f $passphraseMetrics.EstimatedGuesses)) | Out-Null
                                }
                                if ($passphraseMetrics.PSObject.Properties['CrackTimeOnline'] -and $passphraseMetrics.CrackTimeOnline) {
                                    $parts.Add(('Online crack time {0}' -f $passphraseMetrics.CrackTimeOnline)) | Out-Null
                                }
                                if ($passphraseMetrics.PSObject.Properties['CrackTimeOffline'] -and $passphraseMetrics.CrackTimeOffline) {
                                    $parts.Add(('Offline crack time {0}' -f $passphraseMetrics.CrackTimeOffline)) | Out-Null
                                }
                                $signalsArray = @()
                                if ($passphraseMetrics.PSObject.Properties['Signals']) {
                                    $signalsArray = ConvertTo-NetworkArray $passphraseMetrics.Signals
                                }
                                if ($signalsArray.Count -gt 0) {
                                    $parts.Add(('Signals: {0}' -f ($signalsArray -join ', '))) | Out-Null
                                }

                                $evidence = [ordered]@{
                                    Interface          = $interfaceEvidence
                                    PassphraseMetrics  = ('Derived from netsh wlan profile "{0}" → {1}' -f $profileLabel, ($parts.ToArray() -join '; '))
                                }
                                $warningsArray = @()
                                if ($passphraseMetrics.PSObject.Properties['Warnings']) {
                                    $warningsArray = ConvertTo-NetworkArray $passphraseMetrics.Warnings
                                }
                                if ($warningsArray.Count -gt 0) {
                                    $evidence['Warnings'] = $warningsArray -join '; '
                                }
                                $suggestionsArray = @()
                                if ($passphraseMetrics.PSObject.Properties['Suggestions']) {
                                    $suggestionsArray = ConvertTo-NetworkArray $passphraseMetrics.Suggestions
                                }
                                if ($suggestionsArray.Count -gt 0) {
                                    $evidence['Suggestions'] = $suggestionsArray -join '; '
                                }

                                $titleScore = if ($scoreValue -ne $null) { $scoreValue } else { 'n/a' }
                                $titleCategory = if ($scoreCategory) { $scoreCategory } else { 'Unknown' }
                                $title = 'WPA2-Personal passphrase score {0} ({1})' -f $titleScore, $titleCategory

                                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory $subcategory
                            } elseif ($passphraseMetricsError) {
                                $evidence = [ordered]@{
                                    Interface = $interfaceEvidence
                                    Error     = $passphraseMetricsError
                                }
                                if ($profileEvidenceText) { $evidence['Profile'] = $profileEvidenceText }
                                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'WPA2-Personal passphrase strength unknown (scoring failed)' -Evidence $evidence -Subcategory $subcategory
                            }
                        }

                        $transitionDetected = $false
                        if ($securityCategory -eq 'WPA3PersonalTransition' -or $securityCategory -eq 'WPA3EnterpriseTransition') { $transitionDetected = $true }
                        if (-not $transitionDetected -and $apSupportsWpa3 -and $apSupportsWpa2) { $transitionDetected = $true }

                        if ($transitionDetected) {
                            $transitionEvidence = [ordered]@{
                                Interface = $interfaceEvidence
                            }
                            if ($apEvidence) { $transitionEvidence['AccessPoint'] = $apEvidence }
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'WPA2/WPA3 transition (mixed) mode' -Evidence $transitionEvidence -Subcategory $subcategory
                        }

                        if (($securityCategory -eq 'WPA2Personal' -or $securityCategory -eq 'WPA2Enterprise') -and $apSupportsWpa3) {
                            $fallbackEvidence = [ordered]@{
                                Interface = $interfaceEvidence
                            }
                            if ($apEvidence) { $fallbackEvidence['AccessPoint'] = $apEvidence }
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'AP supports WPA3 but client connected as WPA2' -Evidence $fallbackEvidence -Subcategory $subcategory
                        }
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Wireless diagnostics not collected, so Wi-Fi security posture cannot be evaluated.' -Subcategory 'Security'
    }

    $dhcpFolderPath = if ($dhcpFolder) { $dhcpFolder } else { $null }
    $dhcpFolderExists = if ($dhcpFolderPath) { Test-Path -LiteralPath $dhcpFolderPath } else { $false }
    $dhcpFileCount = if ($dhcpFolderExists) { (Get-ChildItem -Path $dhcpFolderPath -Filter 'dhcp-*.json' -ErrorAction SilentlyContinue | Measure-Object).Count } else { 'n/a' }
    Write-Host ("DBG DHCP ENTRY: dhcpFolder={0} exists={1} files={2} keys={3}" -f $dhcpFolderPath,$dhcpFolderExists,$dhcpFileCount,($Context.Artifacts.Keys | Where-Object { $_ -like 'dhcp-*.json' } | Measure-Object).Count)
    Invoke-DhcpAnalyzers -Context $Context -CategoryResult $result -InputFolder $dhcpFolderPath

    $categories = New-Object System.Collections.Generic.List[object]
    $categories.Add($result) | Out-Null

    $vpnCategory = $null
    if (Get-Command -Name 'Invoke-NetworkVpnAnalysis' -ErrorAction SilentlyContinue) {
        try {
            $vpnCategory = Invoke-NetworkVpnAnalysis -Context $Context
        } catch {
            Write-HeuristicDebug -Source 'Network' -Message 'Invoke-NetworkVpnAnalysis failed' -Data ([ordered]@{ Error = $_.Exception.Message })
        }
    }

    if ($vpnCategory) {
        $categories.Add($vpnCategory) | Out-Null
    }

    if ($categories.Count -eq 1) {
        return $result
    }

    return $categories.ToArray()
}
