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
            try { return ([System.Net.IPAddress]::new($addressValue)).ToString() } catch {
                Write-Verbose -Message ("Failed to convert byte[] network address to string: {0}" -f $_.Exception.Message)
            }
        }

        try {
            if ($null -ne $addressValue) {
                return ([System.Net.IPAddress]::new([int64]$addressValue)).ToString()
            }
        } catch {
            Write-Verbose -Message ("Failed to convert numeric network address to string: {0}" -f $_.Exception.Message)
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
        $CategoryResult,

        [string]$InputFolder
    )

    Write-Verbose -Message ("Invoke-DhcpAnalyzers entry: PSCommandPath={0}; PSScriptRoot={1}; MyInvocation.PSCommandPath={2}" -f $PSCommandPath, $PSScriptRoot, $MyInvocation.PSCommandPath)

    $resolvedInputFolder = $null
    $inputExists = $false
    if ($InputFolder) {
        try {
            $resolvedInputFolder = (Resolve-Path -LiteralPath $InputFolder -ErrorAction Stop).ProviderPath
            $inputExists = $true
        } catch {
            $resolvedInputFolder = $InputFolder
            $inputExists = Test-Path -LiteralPath $InputFolder
        }
    }

    $inputFolderDisplay = if ($InputFolder) { $InputFolder } else { '[null]' }
    $resolvedInputDisplay = if ($resolvedInputFolder) { $resolvedInputFolder } else { '[null]' }
    Write-Verbose -Message ("Invoke-DhcpAnalyzers input: Raw={0}; Resolved={1}; Exists={2}" -f $inputFolderDisplay, $resolvedInputDisplay, [bool]$inputExists)

    if (-not $InputFolder) { Write-Verbose -Message 'Invoke-DhcpAnalyzers exiting: InputFolder not provided'; return }
    if (-not $inputExists) { Write-Verbose -Message ("Invoke-DhcpAnalyzers exiting: InputFolder missing '{0}'" -f $resolvedInputFolder); return }

    $dhcpFolderPath = Join-Path -Path $resolvedInputFolder -ChildPath 'DHCP'
    $rootDhcpJsonCount = 0
    $dhcpSubfolderJsonCount = 0
    try {
        $rootDhcpJsonCount = @(Get-ChildItem -Path $resolvedInputFolder -Filter 'dhcp-*.json' -File -ErrorAction SilentlyContinue).Count
    } catch {
        $rootDhcpJsonCount = 0
    }
    if (Test-Path -LiteralPath $dhcpFolderPath) {
        $dhcpSubfolderJsonCount = @(Get-ChildItem -Path $dhcpFolderPath -Filter 'dhcp-*.json' -File -ErrorAction SilentlyContinue).Count
    }
    $dhcpFolderResolved = $dhcpFolderPath
    if (Test-Path -LiteralPath $dhcpFolderPath) {
        try { $dhcpFolderResolved = (Resolve-Path -LiteralPath $dhcpFolderPath -ErrorAction Stop).ProviderPath } catch { $dhcpFolderResolved = $dhcpFolderPath }
    }
    Write-Verbose -Message ("Invoke-DhcpAnalyzers artifacts: InputFolder={0}; DHCPFolder={1}; RootDhcpJsonCount={2}; DhcpFolderJsonCount={3}" -f $resolvedInputFolder, $dhcpFolderResolved, $rootDhcpJsonCount, $dhcpSubfolderJsonCount)

    $analyzerRoot = Join-Path -Path $PSScriptRoot -ChildPath 'DHCP'
    Write-Verbose -Message ("Invoke-DhcpAnalyzers analyzer root: {0}" -f $analyzerRoot)
    if (-not (Test-Path -LiteralPath $analyzerRoot)) { Write-Verbose -Message 'Invoke-DhcpAnalyzers exiting: analyzer root missing'; return }

    $scriptPattern = 'Analyze-Dhcp*.ps1'
    Write-Verbose -Message ("Invoke-DhcpAnalyzers script pattern: {0}" -f $scriptPattern)

    $scriptFiles = @(Get-ChildItem -Path $analyzerRoot -Filter $scriptPattern -File -ErrorAction SilentlyContinue | Sort-Object Name)
    $foundScriptsCount = if ($scriptFiles) { $scriptFiles.Count } else { 0 }
    Write-Verbose -Message ("Invoke-DhcpAnalyzers FoundScriptsCount={0}" -f $foundScriptsCount)

    if ($foundScriptsCount -eq 0) {
        $parentOfScriptRoot = $null
        try { $parentOfScriptRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..') -ErrorAction Stop).ProviderPath } catch { $parentOfScriptRoot = $null }

        $fallbackBases = @{
            'SplitPath_PSCommandPath' = Split-Path -Parent $PSCommandPath
            'SplitPath_PSScriptRoot'  = Split-Path -Parent $PSScriptRoot
            'ParentOfPSScriptRoot'    = $parentOfScriptRoot
        }

        foreach ($key in $fallbackBases.Keys) {
            $basePath = $fallbackBases[$key]
            if (-not $basePath) { Write-Verbose -Message ("Invoke-DhcpAnalyzers fallback[{0}]: base path unavailable" -f $key); continue }

            $expectedPath = [System.IO.Path]::Combine($basePath, 'Analyzers', 'Heuristics', 'Network', 'DHCP')
            if (-not (Test-Path -LiteralPath $expectedPath)) { Write-Verbose -Message ("Invoke-DhcpAnalyzers fallback[{0}]: expected path missing" -f $key); continue }

            $resolvedExpectedPath = $expectedPath
            try { $resolvedExpectedPath = (Resolve-Path -LiteralPath $expectedPath -ErrorAction Stop).ProviderPath } catch { $resolvedExpectedPath = $expectedPath }

            $fallbackHits = @(Get-ChildItem -Path $resolvedExpectedPath -Filter $scriptPattern -File -ErrorAction SilentlyContinue)
            if ($fallbackHits.Count -gt 0) {
                Write-Verbose -Message ("Invoke-DhcpAnalyzers fallback[{0}] found {1} script(s): {2}" -f $key, $fallbackHits.Count, [string]::Join('; ', ($fallbackHits | Select-Object -First 5 | ForEach-Object { $_.FullName })))
            } else {
                Write-Verbose -Message ("Invoke-DhcpAnalyzers fallback[{0}] found 0 script(s) at {1}" -f $key, $resolvedExpectedPath)
            }
        }

        $repoRoot = $null
        $repoRootCandidate = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..')
        if (Test-Path -LiteralPath $repoRootCandidate) {
            try { $repoRoot = (Resolve-Path -LiteralPath $repoRootCandidate -ErrorAction Stop).ProviderPath } catch { $repoRoot = $repoRootCandidate }
        }
        if ($repoRoot) {
            $repoHits = @(Get-ChildItem -Path $repoRoot -Recurse -Filter $scriptPattern -File -ErrorAction SilentlyContinue | Select-Object -First 5)
            if ($repoHits.Count -gt 0) {
                Write-Verbose -Message ("Invoke-DhcpAnalyzers fallback[repo] first {0} hit(s): {1}" -f $repoHits.Count, [string]::Join('; ', ($repoHits | ForEach-Object { $_.FullName })))
            } else {
                Write-Verbose -Message ("Invoke-DhcpAnalyzers fallback[repo]: no scripts found under {0}" -f $repoRoot)
            }
        } else {
            Write-Verbose -Message 'Invoke-DhcpAnalyzers fallback[repo]: unable to determine repository root'
        }

        return
    }

    Write-Verbose -Message ("Invoke-DhcpAnalyzers discovered {0} DHCP analyzer script(s)" -f $scriptFiles.Count)

    $eligibleAnalyzers = @()
    $scriptIndex = 0
    foreach ($script in $scriptFiles) {
        $scriptIndex++
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script.Name)
        $artifactBase = $null
        $artifactPath = $null
        $artifactExists = $false
        $chosenCandidate = $null

        Write-Verbose -Message ("Invoke-DhcpAnalyzers script mapping: Index={0}; ScriptName={1}; BaseName={2}" -f $scriptIndex, $script.FullName, $baseName)

        if ($baseName.StartsWith('Analyze-')) {
            $suffix = $baseName.Substring(8)
            if ($suffix) {
                $artifactBase = ConvertTo-KebabCase $suffix
                if ($artifactBase) {
                    $artifactCandidates = @(
                        [pscustomobject]@{
                            Label = 'DHCPSubfolder'
                            Path  = Join-Path -Path (Join-Path -Path $resolvedInputFolder -ChildPath 'DHCP') -ChildPath ($artifactBase + '.json')
                        },
                        [pscustomobject]@{
                            Label = 'InputRoot'
                            Path  = Join-Path -Path $resolvedInputFolder -ChildPath ($artifactBase + '.json')
                        }
                    )

                    foreach ($candidate in $artifactCandidates) {
                        $exists = Test-Path -LiteralPath $candidate.Path
                        Write-Verbose -Message ("Invoke-DhcpAnalyzers artifact candidate: Script={0}; Base={1}; Label={2}; Path={3}; Exists={4}" -f $script.FullName, $artifactBase, $candidate.Label, $candidate.Path, [bool]$exists)
                        if (-not $artifactExists -and $exists) {
                            $artifactExists = $true
                            $artifactPath = $candidate.Path
                            $chosenCandidate = $candidate.Label
                        }
                    }
                }
            }
        }

        $artifactResolvedPath = $artifactPath
        if ($artifactExists) {
            try { $artifactResolvedPath = (Resolve-Path -LiteralPath $artifactPath -ErrorAction Stop).ProviderPath } catch { $artifactResolvedPath = $artifactPath }
            Write-Verbose -Message ("Invoke-DhcpAnalyzers artifact selection: Script={0}; Base={1}; Pick={2}; Path={3}" -f $script.FullName, $artifactBase, $chosenCandidate, $artifactResolvedPath)
        } else {
            Write-Verbose -Message ("Invoke-DhcpAnalyzers artifact selection: Script={0}; Base={1}; Pick=<none>" -f $script.FullName, $artifactBase)
        }

        if ($artifactExists) {
            $eligibleAnalyzers += [pscustomobject]@{
                Script       = $script
                ArtifactBase = $artifactBase
                ArtifactPath = $artifactResolvedPath
                Candidate    = $chosenCandidate
            }
        }
    }

    if ($eligibleAnalyzers.Count -eq 0) { return }

    Write-Verbose -Message ("Invoke-DhcpAnalyzers eligible analyzer count: {0}" -f $eligibleAnalyzers.Count)

    $findings = New-Object System.Collections.Generic.List[object]
    $invokedAnalyzerCount = 0

    foreach ($analyzer in $eligibleAnalyzers) {
        try {
            Write-Verbose -Message ("Invoke-DhcpAnalyzers invoking: Script={0}; Base={1}; Artifact={2}" -f $analyzer.Script.FullName, $analyzer.ArtifactBase, $analyzer.ArtifactPath)
            $invokedAnalyzerCount++
            $result = & $analyzer.Script.FullName -InputFolder $InputFolder -CategoryResult $CategoryResult -Context $Context
        } catch {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title ("DHCP analyzer failed: {0}" -f $analyzer.Script.Name) -Evidence $_.Exception.Message -Subcategory 'DHCP'
            Write-Verbose -Message ("Invoke-DhcpAnalyzers invocation failed: Script={0}; Error={1}" -f $analyzer.Script.FullName, $_.Exception.Message)
            continue
        }

        if ($null -eq $result) { continue }

        $resultItems = @()
        if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
            foreach ($item in $result) {
                if ($null -ne $item) { $resultItems += $item }
            }
        } else {
            if ($null -ne $result) { $resultItems += $result }
        }

        $issueCount = 0
        $normalCount = 0
        foreach ($item in $resultItems) {
            $findings.Add($item) | Out-Null
            if ($item.PSObject.Properties['Severity'] -and $item.Severity) {
                if ($item.Severity -in @('good', 'ok', 'normal')) {
                    $normalCount++
                } else {
                    $issueCount++
                }
            } else {
                $issueCount++
            }
        }

        Write-Verbose -Message ("Invoke-DhcpAnalyzers returned: Script={0}; Count={1}; Issues={2}; Normals={3}" -f $analyzer.Script.FullName, $resultItems.Count, $issueCount, $normalCount)
    }

    Write-Verbose -Message ("Invoke-DhcpAnalyzers produced {0} result(s)" -f $findings.Count)

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

    Write-Verbose -Message ("Invoke-DhcpAnalyzers summary: Scripts={0}; Eligible={1}; Invoked={2}; TotalFindings={3}" -f $foundScriptsCount, $eligibleAnalyzers.Count, $invokedAnalyzerCount, $findings.Count)
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
    if ($PSBoundParameters.ContainsKey('InputFolder') -and -not [string]::IsNullOrWhiteSpace($InputFolder)) {
        $rootCandidate = $InputFolder
    } elseif ($Context -and $Context.PSObject.Properties['InputFolder'] -and $Context.InputFolder) {
        $rootCandidate = $Context.InputFolder
    }

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

    $dhcpFolder = if ($resolvedRoot) { Join-Path -Path $resolvedRoot -ChildPath 'DHCP' } else { $null }

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
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Outlook HTTPS connectivity failed' -Evidence ('TcpTestSucceeded reported False for {0}' -f $conn.RemoteAddress) -Subcategory 'Outlook Connectivity'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title 'Outlook HTTPS connectivity succeeded'
                }
            } elseif ($conn.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to test Outlook connectivity' -Evidence $conn.Error -Subcategory 'Outlook Connectivity'
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

    $dhcpFolderPath = if ($dhcpFolder) { $dhcpFolder } else { $null }
    $dhcpFolderExists = if ($dhcpFolderPath) { Test-Path -LiteralPath $dhcpFolderPath } else { $false }
    $dhcpFileCount = if ($dhcpFolderExists) { (Get-ChildItem -Path $dhcpFolderPath -Filter 'dhcp-*.json' -ErrorAction SilentlyContinue | Measure-Object).Count } else { 'n/a' }
    Write-Host ("DBG DHCP ENTRY: dhcpFolder={0} exists={1} files={2} keys={3}" -f $dhcpFolderPath,$dhcpFolderExists,$dhcpFileCount,($Context.Artifacts.Keys | Where-Object { $_ -like 'dhcp-*.json' } | Measure-Object).Count)
    Invoke-DhcpAnalyzers -Context $Context -CategoryResult $result -InputFolder $dhcpFolderPath

    return $result
}
