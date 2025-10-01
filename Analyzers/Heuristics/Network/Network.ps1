<#!
.SYNOPSIS
    Network diagnostics heuristics covering connectivity, DNS, proxy, and Outlook health.
#>

$analyzersRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
. (Join-Path -Path $analyzersRoot -ChildPath 'AnalyzerCommon.ps1')

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

    if ($adapterPayload -and $adapterPayload.Adapters -and -not $adapterPayload.Adapters.Error) {
        $upAdapters = $adapterPayload.Adapters | Where-Object { $_.Status -eq 'Up' }
        if ($upAdapters.Count -gt 0) {
            Add-CategoryNormal -CategoryResult $result -Title ('Active adapters: {0}' -f ($upAdapters.Name -join ', ')) -Subcategory 'Network Adapters'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No active network adapters reported, so the device has no path for network connectivity.' -Subcategory 'Network Adapters'
        }
    } elseif ($adapterPayload -and $adapterPayload.PSObject.Properties['Adapters']) {
        $adapterNode = $adapterPayload.Adapters
        if ($adapterNode -is [pscustomobject] -and $adapterNode.PSObject.Properties['Error'] -and $adapterNode.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate network adapters, so link status is unknown.' -Evidence $adapterNode.Error -Subcategory 'Network Adapters'
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

    $dhcpFolderPath = if ($dhcpFolder) { $dhcpFolder } else { $null }
    $dhcpFolderExists = if ($dhcpFolderPath) { Test-Path -LiteralPath $dhcpFolderPath } else { $false }
    $dhcpFileCount = if ($dhcpFolderExists) { (Get-ChildItem -Path $dhcpFolderPath -Filter 'dhcp-*.json' -ErrorAction SilentlyContinue | Measure-Object).Count } else { 'n/a' }
    Write-Host ("DBG DHCP ENTRY: dhcpFolder={0} exists={1} files={2} keys={3}" -f $dhcpFolderPath,$dhcpFolderExists,$dhcpFileCount,($Context.Artifacts.Keys | Where-Object { $_ -like 'dhcp-*.json' } | Measure-Object).Count)
    Invoke-DhcpAnalyzers -Context $Context -CategoryResult $result -InputFolder $dhcpFolderPath

    return $result
}
