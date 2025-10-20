function Resolve-WifiPmfStatusFromText {
    param([string]$Text)

    if (-not $Text) { return $null }

    $normalized = $Text.Trim()
    if (-not $normalized) { return $null }

    if ($normalized -match '(?i)require|mandatory') { return 'Required' }
    if ($normalized -match '(?i)disable|not\s+enabled|none') { return 'Disabled' }
    if ($normalized -match '(?i)optional|capable|support') { return 'Optional' }

    return $null
}

function Get-WifiPmfStatus {
    param(
        $Interface,
        $ProfileInfo
    )

    $candidates = New-Object System.Collections.Generic.List[string]

    if ($ProfileInfo -and $ProfileInfo.PSObject -and $ProfileInfo.PSObject.Properties['PmfSetting'] -and $ProfileInfo.PmfSetting) {
        $candidates.Add([string]$ProfileInfo.PmfSetting) | Out-Null
    }

    if ($Interface -and $Interface.PSObject -and $Interface.PSObject.Properties['RawLines'] -and $Interface.RawLines) {
        foreach ($line in (ConvertTo-NetworkArray $Interface.RawLines)) {
            if (-not $line) { continue }
            $text = [string]$line
            if ($text -match '(?i)(pmf|802\.11w|management frame protection)') {
                $candidates.Add($text) | Out-Null
            }
        }
    }

    if ($ProfileInfo -and $ProfileInfo.PSObject -and $ProfileInfo.PSObject.Properties['ShowProfile'] -and $ProfileInfo.ShowProfile) {
        foreach ($line in (ConvertTo-NetworkArray $ProfileInfo.ShowProfile)) {
            if (-not $line) { continue }
            $text = [string]$line
            if ($text -match '(?i)(pmf|802\.11w|management frame protection)') {
                $candidates.Add($text) | Out-Null
            }
        }
    }

    $resolved = $null
    foreach ($candidate in $candidates) {
        $status = Resolve-WifiPmfStatusFromText -Text $candidate
        if (-not $status) { continue }
        if ($status -eq 'Disabled') { return 'Disabled' }
        if ($status -eq 'Required') { return 'Required' }
        if (-not $resolved) { $resolved = $status }
    }

    return ($resolved ? $resolved : 'Unknown')
}

function Get-WifiWpsStatus {
    param(
        $Interface,
        $ProfileInfo
    )

    $candidates = New-Object System.Collections.Generic.List[string]

    if ($Interface -and $Interface.PSObject -and $Interface.PSObject.Properties['RawLines'] -and $Interface.RawLines) {
        foreach ($line in (ConvertTo-NetworkArray $Interface.RawLines)) {
            if (-not $line) { continue }
            $text = [string]$line
            if ($text -match '(?i)\bWPS\b') {
                $candidates.Add($text) | Out-Null
            }
        }
    }

    if ($ProfileInfo -and $ProfileInfo.PSObject) {
        foreach ($property in @('ShowProfile','Xml')) {
            if ($ProfileInfo.PSObject.Properties[$property] -and $ProfileInfo.$property) {
                foreach ($line in (ConvertTo-NetworkArray $ProfileInfo.$property)) {
                    if (-not $line) { continue }
                    $text = [string]$line
                    if ($text -match '(?i)\bWPS\b') {
                        $candidates.Add($text) | Out-Null
                    }
                }
            }
        }
    }

    foreach ($candidate in $candidates) {
        if ($candidate -match '(?i)(disable|off|not\s+configured)') { return 'Off' }
        if ($candidate -match '(?i)(enable|pin|push)') { return 'On' }
    }

    return 'Unknown'
}

function Get-WifiSeverityWorsen {
    param([string]$Severity)

    switch -Regex ($Severity) {
        '^(?i)low$'     { return 'Medium' }
        '^(?i)medium$'  { return 'High' }
        '^(?i)high$'    { return 'Critical' }
        default         { return ($Severity ? $Severity : 'Critical') }
    }
}

function Test-NetworkInternalDnsAddress {
    param([string]$Address)

    if (-not $Address) { return $false }

    $trimmed = $Address.Trim()
    if (-not $trimmed) { return $false }

    if (Test-NetworkLoopback $trimmed) { return $true }
    if (Test-NetworkPrivateIpv4 $trimmed) { return $true }

    if ($trimmed -match '^(?i)(fc|fd)[0-9a-f]{2}:') { return $true }
    if ($trimmed -match '^(?i)fe80:') { return $true }

    return $false
}

function Get-NetworkDsregStatus {
    param($Context)

    $text = $null
    if (Get-Command -Name 'Get-IntuneDsregText' -ErrorAction SilentlyContinue) {
        try { $text = Get-IntuneDsregText -Context $Context } catch { $text = $null }
    }

    if (-not $text) {
        try {
            $identityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'identity'
            if ($identityArtifact) {
                $identityPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $identityArtifact)
                if ($identityPayload -and $identityPayload.PSObject.Properties['DsRegCmd']) {
                    $raw = $identityPayload.DsRegCmd
                    if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
                        $text = ($raw -join "`n")
                    } elseif ($raw) {
                        $text = [string]$raw
                    }
                }
            }
        } catch {
            $text = $null
        }
    }

    $azure = $null
    $domainJoined = $null
    $tenantName = $null

    if ($text) {
        foreach ($line in [regex]::Split($text, '\r?\n')) {
            if (-not $line) { continue }
            $trimmed = $line.Trim()
            if (-not $trimmed) { continue }

            if ($null -eq $azure -and $trimmed -match '^(?i)AzureAdJoined\s*:\s*(.+)$') {
                $value = $matches[1].Trim()
                if ($value) {
                    $upper = $value.ToUpperInvariant()
                    if ($upper -eq 'YES' -or $upper -eq 'TRUE') { $azure = $true }
                    elseif ($upper -eq 'NO' -or $upper -eq 'FALSE') { $azure = $false }
                    else { $azure = $null }
                }
                continue
            }

            if ($null -eq $domainJoined -and $trimmed -match '^(?i)DomainJoined\s*:\s*(.+)$') {
                $value = $matches[1].Trim()
                if ($value) {
                    $upper = $value.ToUpperInvariant()
                    if ($upper -eq 'YES' -or $upper -eq 'TRUE') { $domainJoined = $true }
                    elseif ($upper -eq 'NO' -or $upper -eq 'FALSE') { $domainJoined = $false }
                    else { $domainJoined = $null }
                }
                continue
            }

            if (-not $tenantName -and $trimmed -match '^(?i)TenantName\s*:\s*(.+)$') {
                $tenantName = $matches[1].Trim()
                continue
            }
        }
    }

    return [pscustomobject]@{
        Text          = $text
        AzureAdJoined = $azure
        DomainJoined  = $domainJoined
        TenantName    = $tenantName
    }
}

function Get-NetworkDnsJoinContext {
    param(
        $Context,
        $MsinfoIdentity
    )

    $domainName = $null
    $domainRoleInt = $null
    $domainRoleLabel = $null
    $domainJoined = $null

    if ($MsinfoIdentity) {
        if ($MsinfoIdentity.PSObject.Properties['Domain'] -and $MsinfoIdentity.Domain) {
            $domainName = [string]$MsinfoIdentity.Domain
        }
        if ($MsinfoIdentity.PSObject.Properties['PartOfDomain']) {
            try { $domainJoined = [bool]$MsinfoIdentity.PartOfDomain } catch { $domainJoined = $null }
        }
        if ($MsinfoIdentity.PSObject.Properties['DomainRole']) {
            $domainRoleLabel = [string]$MsinfoIdentity.DomainRole
            $roleValue = $MsinfoIdentity.DomainRole
            try { $domainRoleInt = [int]$roleValue } catch {
                $normalized = $domainRoleLabel.ToLowerInvariant()
                if ($normalized -match 'primary') { $domainRoleInt = 5 }
                elseif ($normalized -match 'backup') { $domainRoleInt = 4 }
                elseif ($normalized -match 'member\s+server') { $domainRoleInt = 3 }
                elseif ($normalized -match 'standalone\s+server') { $domainRoleInt = 2 }
                elseif ($normalized -match 'member\s+workstation') { $domainRoleInt = 1 }
                elseif ($normalized -match 'standalone\s+workstation') { $domainRoleInt = 0 }
            }
        }
    }

    $dsregStatus = Get-NetworkDsregStatus -Context $Context
    if ($null -eq $domainJoined -and $dsregStatus.DomainJoined -ne $null) {
        $domainJoined = [bool]$dsregStatus.DomainJoined
    }

    $azureJoined = if ($dsregStatus.AzureAdJoined -ne $null) { [bool]$dsregStatus.AzureAdJoined } else { $false }

    $joinCategory = 'Workgroup'
    $joinTitle = 'non-domain'
    $needsInternalZones = $false

    if ($domainRoleInt -in @(4,5)) {
        $joinCategory = 'DomainController'
        $joinTitle = 'domain controller'
        $needsInternalZones = $true
    } elseif ($domainJoined) {
        if ($azureJoined) {
            $joinCategory = 'Hybrid'
            $joinTitle = 'Hybrid AADJ'
        } else {
            $joinCategory = 'DomainJoined'
            $joinTitle = 'AD-joined'
        }
        $needsInternalZones = $true
    } elseif ($azureJoined) {
        $joinCategory = 'AzureAd'
        $joinTitle = 'Azure AD-joined'
    }

    return [pscustomobject]@{
        DomainName        = $domainName
        DomainRoleInt     = $domainRoleInt
        DomainRoleLabel   = $domainRoleLabel
        DomainJoined      = $domainJoined
        AzureAdJoined     = $azureJoined
        TenantName        = $dsregStatus.TenantName
        JoinCategory      = $joinCategory
        JoinTitle         = $joinTitle
        NeedsInternalZones = $needsInternalZones
    }
}

function Get-NetworkDnsSuffixList {
    param($DnsPayload)

    $suffixes = New-Object System.Collections.Generic.List[string]

    if ($DnsPayload -and $DnsPayload.PSObject.Properties['ClientPolicies']) {
        foreach ($policy in (ConvertTo-NetworkArray $DnsPayload.ClientPolicies)) {
            if (-not $policy) { continue }
            if ($policy.PSObject.Properties['ConnectionSpecificSuffix'] -and $policy.ConnectionSpecificSuffix) {
                $value = [string]$policy.ConnectionSpecificSuffix
                if (-not [string]::IsNullOrWhiteSpace($value) -and -not $suffixes.Contains($value)) {
                    $suffixes.Add($value) | Out-Null
                }
            }
        }
    }

    return $suffixes.ToArray()
}

function Get-NetworkDnsInternalZones {
    param(
        $JoinContext,
        [string[]]$Suffixes
    )

    $set = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $addZone = {
        param([string]$Zone)
        if ([string]::IsNullOrWhiteSpace($Zone)) { return }
        $trimmed = $Zone.Trim()
        if (-not $trimmed) { return }
        $null = $set.Add($trimmed)
    }

    if ($JoinContext -and $JoinContext.DomainName) {
        & $addZone $JoinContext.DomainName
        & $addZone ('*.{0}' -f $JoinContext.DomainName)
    }

    if ($Suffixes) {
        foreach ($suffix in $Suffixes) {
            if (-not $suffix) { continue }
            & $addZone $suffix
            & $addZone ('*.{0}' -f $suffix)
        }
    }

    return $set.ToArray()
}

function Get-NetworkPrimaryGateway {
    param($AdapterInventory)

    if (-not $AdapterInventory -or -not $AdapterInventory.Map) { return $null }

    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($info in $AdapterInventory.Map.Values) { if ($info) { $candidates.Add($info) | Out-Null } }

    $preferred = $candidates | Where-Object { $_.IsEligible -and $_.Gateways -and $_.Gateways.Count -gt 0 }
    if (-not $preferred) { $preferred = $candidates | Where-Object { $_.HasGateway -and $_.Gateways -and $_.Gateways.Count -gt 0 } }

    foreach ($entry in $preferred) {
        foreach ($gateway in $entry.Gateways) {
            if ($gateway) { return [string]$gateway }
        }
    }

    foreach ($entry in $candidates) {
        if (-not $entry.Gateways) { continue }
        foreach ($gateway in $entry.Gateways) {
            if ($gateway) { return [string]$gateway }
        }
    }

    return $null
}

function Get-NetworkDnsActiveSsid {
    param($Context)

    try {
        $wlanArtifact = Get-AnalyzerArtifact -Context $Context -Name 'wlan'
        if (-not $wlanArtifact) { return $null }
        $wlanPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wlanArtifact)
        if (-not $wlanPayload) { return $null }

        if ($wlanPayload.PSObject -and $wlanPayload.PSObject.Properties['Interfaces']) {
            $interfaces = ConvertTo-WlanInterfaces $wlanPayload.Interfaces
            if ($interfaces) {
                $connected = $interfaces | Where-Object { Test-WlanInterfaceConnected -Interface $_ } | Select-Object -First 1
                if ($connected -and $connected.PSObject.Properties['Ssid'] -and $connected.Ssid) {
                    return [string]$connected.Ssid
                }
            }
        }
    } catch {
    }

    return $null
}

function Get-NetworkDnsNetworkContext {
    param(
        $Context,
        $AdapterInventory,
        [string[]]$Suffixes,
        $JoinContext
    )

    $ssid = Get-NetworkDnsActiveSsid -Context $Context
    $gateway = Get-NetworkPrimaryGateway -AdapterInventory $AdapterInventory

    $contextKey = 'offsite'
    $label = 'offsite network'

    $hasSuffix = ($Suffixes -and $Suffixes.Count -gt 0)

    if ($ssid -and $ssid -match '(?i)guest') {
        $contextKey = 'guest'
        $label = 'guest network'
    } elseif ($JoinContext.JoinCategory -eq 'DomainController' -or $JoinContext.DomainJoined -eq $true -or $hasSuffix) {
        $contextKey = 'corp'
        $label = 'corp LAN'
    }

    return [pscustomobject]@{
        Key      = $contextKey
        Label    = $label
        Ssid     = $ssid
        Gateway  = $gateway
        HasSuffix = $hasSuffix
    }
}

function Get-NetworkSecureChannelStatus {
    param($Context)

    $status = 'Unknown'
    $artifact = $null
    try { $artifact = Get-AnalyzerArtifact -Context $Context -Name 'ad-health' } catch { $artifact = $null }
    if ($artifact) {
        try {
            $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
            if ($payload -and $payload.PSObject.Properties['Secure'] -and $payload.Secure -and $payload.Secure.PSObject.Properties['TestComputerSecureChannel']) {
                $test = $payload.Secure.TestComputerSecureChannel
                if ($test.PSObject.Properties['Succeeded'] -and $test.Succeeded -eq $true) {
                    if ($test.PSObject.Properties['IsSecure'] -and $test.IsSecure -eq $true) {
                        $status = 'OK'
                    } else {
                        $status = 'Fail'
                    }
                } elseif ($test.PSObject.Properties['Error'] -and $test.Error) {
                    $status = 'Error'
                }
            }
        } catch {
        }
    }

    return [pscustomobject]@{ Status = $status }
}

function Get-NetworkDnsRemediation {
    param(
        $JoinContext,
        [bool]$NeedsInternalZones,
        [pscustomobject]$NetworkContext
    )

    $steps = New-Object System.Collections.Generic.List[string]

    switch ($JoinContext.JoinCategory) {
        'DomainController' {
            $steps.Add('Use only AD-integrated DNS servers on each NIC (DHCP option 006); remove public resolvers.') | Out-Null
            $steps.Add('Verify domain controller/DNS reachability and repair the machine secure channel if needed.') | Out-Null
            $steps.Add('Block outbound access to public DNS resolvers on the host and at network egress where feasible.') | Out-Null
        }
        'DomainJoined' {
            $steps.Add('Use AD-integrated DNS servers on the NIC (DHCP option 006) and remove public resolvers.') | Out-Null
            $steps.Add('Ensure domain controllers are reachable and the secure channel remains healthy.') | Out-Null
            $steps.Add('Push NRPT rules or enforce always-on VPN split DNS so corporate zones resolve internally.') | Out-Null
            $steps.Add('Disable unmanaged DoH/DoT endpoints or enforce the approved resolver to prevent bypass.') | Out-Null
        }
        'Hybrid' {
            $steps.Add('Use AD-integrated DNS servers on the NIC (DHCP option 006) and remove public resolvers.') | Out-Null
            $steps.Add('Ensure domain controllers are reachable and the secure channel remains healthy.') | Out-Null
            $steps.Add('Push NRPT rules or enforce always-on VPN split DNS so corporate zones resolve internally.') | Out-Null
            $steps.Add('Disable unmanaged DoH/DoT endpoints or enforce the approved resolver to prevent bypass.') | Out-Null
        }
        'AzureAd' {
            if ($NeedsInternalZones) {
                $steps.Add('Deploy NRPT rules or always-on VPN split DNS for corporate zones via Intune.') | Out-Null
                $steps.Add('Move the device onto the managed staff SSID that hands out internal DNS, or require corporate VPN when onsite.') | Out-Null
                $steps.Add('Disable unmanaged DoH/DoT that bypasses corporate resolvers or point clients to the approved endpoint.') | Out-Null
            } else {
                $steps.Add('If corporate resources are required, enroll the device and apply NRPT or VPN policies before relying on public DNS.') | Out-Null
            }
        }
        default {
            if ($NetworkContext -and $NetworkContext.Key -eq 'corp') {
                $steps.Add('Onboard the device to management or connect using the staff SSID that provides internal DNS servers.') | Out-Null
                $steps.Add('Remove hard-coded public DNS so corporate hostnames are not leaked to external resolvers.') | Out-Null
            } else {
                $steps.Add('Use the corporate VPN or staff SSID with split DNS when corporate resources are needed.') | Out-Null
            }
        }
    }

    if ($steps.Count -eq 0) {
        $steps.Add('Replace public resolvers with the corporate DNS servers provided by DHCP or VPN policies.') | Out-Null
    }

    return 'Recommended actions:' + "`n" + ($steps.ToArray() -join "`n")
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

    Invoke-NetworkFirewallProfileAnalysis -Context $Context -CategoryResult $result

    $connectivityContext = @{
        Interfaces = @()
        Dns        = $null
        Gateway    = $null
        Proxy      = $null
        Vpn        = $null
        Outlook    = $null
    }

    $createConnectivityData = {
        param($ctx)

        return @{
            Area      = 'Network'
            Kind      = 'Connectivity'
            Interfaces = if ($ctx.Interfaces) { $ctx.Interfaces } else { @() }
            Dns       = $ctx.Dns
            Gateway   = $ctx.Gateway
            Proxy     = $ctx.Proxy
            Vpn       = $ctx.Vpn
            Outlook   = $ctx.Outlook
        }
    }

    $devicePartOfDomain = $null
    $msinfoIdentity = Get-MsinfoSystemIdentity -Context $Context
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved msinfo identity' -Data ([ordered]@{
        Found        = [bool]$msinfoIdentity
        PartOfDomain = if ($msinfoIdentity) { $msinfoIdentity.PartOfDomain } else { $null }
    })
    if ($msinfoIdentity -and $msinfoIdentity.PSObject.Properties['PartOfDomain']) {
        $devicePartOfDomain = $msinfoIdentity.PartOfDomain
    }

    $dnsJoinContext = Get-NetworkDnsJoinContext -Context $Context -MsinfoIdentity $msinfoIdentity

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
    $adapterLinkInventory = Get-NetworkAdapterLinkInventory -AdapterPayload $adapterPayload

    if ($adapterInventory -and $adapterInventory.Map) {
        $interfaceRecords = New-Object System.Collections.Generic.List[object]
        foreach ($adapterInfo in $adapterInventory.Map.Values) {
            if (-not $adapterInfo) { continue }

            $info = if ($adapterInfo -is [pscustomobject]) { $adapterInfo } else { [pscustomobject]$adapterInfo }
            $macAddress = if ($info.PSObject.Properties['MacAddress'] -and $info.MacAddress) { [string]$info.MacAddress } else { $null }

            $record = [ordered]@{
                Name          = if ($info.PSObject.Properties['Alias']) { [string]$info.Alias } else { $null }
                Description   = if ($info.PSObject.Properties['Description']) { [string]$info.Description } else { $null }
                IfIndex       = if ($info.PSObject.Properties['IfIndex']) {
                    try { [int]$info.IfIndex } catch { $info.IfIndex }
                } else { $null }
                Status        = if ($info.PSObject.Properties['Status']) { [string]$info.Status } else { $null }
                IsUp          = if ($info.PSObject.Properties['IsUp']) { [bool]$info.IsUp } else { $null }
                IsPseudo      = if ($info.PSObject.Properties['IsPseudo']) { [bool]$info.IsPseudo } else { $false }
                Mac           = $macAddress
                Oui           = if ($macAddress) { Get-NetworkMacOui $macAddress } else { $null }
                IPv4          = @()
                IPv6          = @()
                Gateways      = @()
                IPv6Gateways  = @()
                IsEligible    = if ($info.PSObject.Properties['IsEligible']) { [bool]$info.IsEligible } else { $null }
                HasGateway    = if ($info.PSObject.Properties['HasGateway']) { [bool]$info.HasGateway } else { $null }
            }

            if ($info.PSObject.Properties['IPv4']) {
                $record.IPv4 = @(ConvertTo-NetworkArray $info.IPv4 | Where-Object { $_ })
            }
            if ($info.PSObject.Properties['IPv6']) {
                $record.IPv6 = @(ConvertTo-NetworkArray $info.IPv6 | Where-Object { $_ })
            }
            if ($info.PSObject.Properties['Gateways']) {
                $record.Gateways = @(ConvertTo-NetworkArray $info.Gateways | Where-Object { $_ })
            }
            if ($info.PSObject.Properties['IPv6Gateways']) {
                $record.IPv6Gateways = @(ConvertTo-NetworkArray $info.IPv6Gateways | Where-Object { $_ })
            }

            $interfaceRecords.Add([pscustomobject]$record) | Out-Null
        }

        $connectivityContext.Interfaces = $interfaceRecords.ToArray()
    }

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
                    Interfaces   = if ($detail.Interfaces.Count -gt 0) { [System.Linq.Enumerable]::ToArray($detail.Interfaces) } else { @() }
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

            $broadcastEntries = @()
            $multicastEntries = @()
            $unicastInvalidEntries = @()
            $gatewayArpEntries = New-Object System.Collections.Generic.List[object]

            foreach ($entry in $arpEntries) {
                if (-not $entry -or -not $entry.InternetAddress) { continue }

                $ipAddress = Get-NetworkCanonicalIpv4 $entry.InternetAddress
                if (-not $ipAddress) { continue }

                if (Test-NetworkBroadcastIpv4Address $ipAddress) {
                    $broadcastEntries += $entry
                    continue
                }

                if (Test-NetworkMulticastIpv4Address $ipAddress) {
                    $multicastEntries += $entry
                    continue
                }

                $macForEvaluation = if ($entry.NormalizedMac) { $entry.NormalizedMac } else { $entry.PhysicalAddress }
                if (Test-NetworkInvalidUnicastMac $macForEvaluation) {
                    $unicastInvalidEntries += $entry
                }
            }

            foreach ($gateway in $gatewayMap.Keys) {
                $detail = $gatewayMap[$gateway]
                if (-not $detail -or -not $detail.ArpMatches) { continue }
                $match = $detail.ArpMatches | Select-Object -First 1
                if (-not $match) { continue }
                $gatewayArpEntries.Add($match) | Out-Null
            }

            $gatewayAlerts = New-Object System.Collections.Generic.List[object]
            foreach ($gatewayEntry in $gatewayArpEntries) {
                $macForEvaluation = if ($gatewayEntry.NormalizedMac) { $gatewayEntry.NormalizedMac } else { $gatewayEntry.PhysicalAddress }
                if (Test-NetworkInvalidUnicastMac $macForEvaluation) {
                    $gatewayAlerts.Add($gatewayEntry) | Out-Null
                }
            }

            $severity = 'info'
            if ($gatewayAlerts.Count -gt 0) {
                $severity = 'high'
            } elseif ($unicastInvalidEntries.Count -gt 0) {
                $severity = 'medium'
            }

            $formatArpEntry = {
                param($entry)

                if (-not $entry) { return $null }

                $ipDisplay = Get-NetworkCanonicalIpv4 $entry.InternetAddress
                if (-not $ipDisplay) { $ipDisplay = $entry.InternetAddress }

                $macDisplay = if ($entry.NormalizedMac) { $entry.NormalizedMac } elseif ($entry.PhysicalAddress) { $entry.PhysicalAddress } else { 'unknown' }
                $typeDisplay = if ($entry.Type) { [string]$entry.Type } else { 'unknown' }

                return "{0}→{1} [{2}]" -f $ipDisplay, $macDisplay, $typeDisplay
            }

            $gatewaySummary = @()
            foreach ($gatewayEntry in $gatewayArpEntries) {
                $formatted = & $formatArpEntry $gatewayEntry
                if ($formatted) { $gatewaySummary += $formatted }
            }

            $suppressedEvidence = @()
            if ($broadcastEntries.Count -gt 0) {
                $sample = $broadcastEntries | Select-Object -First 2
                $formattedSample = ($sample | ForEach-Object { & $formatArpEntry $_ }) -join '; '
                if ($broadcastEntries.Count -gt 2) { $formattedSample = "{0}; …" -f $formattedSample }
                if ($formattedSample) {
                    $suppressedEvidence += "Suppressed broadcast entries (expected): $formattedSample"
                }
            }

            if ($multicastEntries.Count -gt 0) {
                $sample = $multicastEntries | Select-Object -First 2
                $formattedSample = ($sample | ForEach-Object { & $formatArpEntry $_ }) -join '; '
                if ($multicastEntries.Count -gt 2) { $formattedSample = "{0}; …" -f $formattedSample }
                if ($formattedSample) {
                    $suppressedEvidence += "Suppressed multicast entries (expected): $formattedSample"
                }
            }

            $primaryEvidence = @()
            switch ($severity) {
                'high' {
                    $title = 'Default gateway resolved to an invalid MAC, so users may be routed through a spoofed device.'
                    $remediation = 'Investigate ARP for default gateway. Clear ARP cache (arp -d *), power-cycle router/switch, and verify gateway MAC against device label/UI. If it returns or flaps, check for ARP spoofing.'
                    foreach ($entry in $gatewayAlerts) {
                        $formatted = & $formatArpEntry $entry
                        if ($formatted) { $primaryEvidence += $formatted }
                    }
                }
                'medium' {
                    $title = 'Unicast neighbors resolved to broadcast or zero MACs, so their traffic may be intercepted or dropped.'
                    $remediation = 'Clear ARP cache (arp -d *). Re-check neighbors. If unicast entries keep resolving to FF:FF:FF:FF:FF:FF or 00:00:00:00:00:00, isolate the suspect IP or segment and review switch CAM/port security.'
                    foreach ($entry in $unicastInvalidEntries) {
                        $formatted = & $formatArpEntry $entry
                        if ($formatted) { $primaryEvidence += $formatted }
                    }
                }
                default {
                    $title = 'We suppress broadcast and multicast ARP entries, so warnings apply only to unicast neighbors with invalid MACs or evidence of flapping.'
                    $remediation = 'No action needed. Broadcast/multicast ARP entries are expected. Monitor gateway mapping for changes.'
                }
            }

            $evidence = @()
            if ($primaryEvidence.Count -gt 0) { $evidence += $primaryEvidence }
            if ($gatewaySummary.Count -gt 0) { $evidence += "Gateway ARP: $($gatewaySummary -join '; ')" }
            if ($suppressedEvidence.Count -gt 0) { $evidence += $suppressedEvidence }

            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'ARP Cache' -Remediation $remediation

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
                    $localMacAlerts += "{0} impersonates IPs {1}" -f $mac, (([System.Linq.Enumerable]::ToArray($remoteIps)) -join ', ')
                }
            }

            if ($localMacAlerts.Count -gt 0) {
                $evidence = $localMacAlerts -join '; '
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Host MAC responds for multiple IPs, so neighbors may lose connectivity to their addresses.' -Evidence $evidence -Subcategory 'ARP Cache'
            }

            $observedGatewayData = New-Object System.Collections.Generic.List[object]
            foreach ($entry in $observedGatewayEntries) {
                if (-not $entry) { continue }
                $observedGatewayData.Add([pscustomobject]@{
                    Address    = $entry.Gateway
                    Interfaces = if ($entry.Interfaces) { $entry.Interfaces } else { @() }
                    Mac        = $entry.NormalizedMac
                    Type       = $entry.Type
                }) | Out-Null
            }

            $baselineArray = @()
            foreach ($mac in $baselineSet) {
                if ($mac) { $baselineArray += $mac }
            }

            $duplicateSummaries = @()
            foreach ($duplicate in $duplicateGatewayMacs) {
                if (-not $duplicate) { continue }
                $duplicateSummaries += [pscustomobject]@{
                    Mac      = $duplicate.Mac
                    Gateways = if ($duplicate.Gateways) { $duplicate.Gateways } else { @() }
                }
            }

            $alertSummaries = @()
            foreach ($alert in $gatewayAlerts) {
                $formatted = & $formatArpEntry $alert
                if ($formatted) { $alertSummaries += $formatted }
            }

            $connectivityContext.Gateway = @{
                Observed       = $observedGatewayData.ToArray()
                BaselineMacs   = $baselineArray
                UnexpectedMacs = ($unexpected | Sort-Object -Unique)
                DuplicateMacs  = $duplicateSummaries
                SuspiciousMacs = $suspiciousEntries
                Alerts         = $alertSummaries
                LocalMacAlerts = $localMacAlerts
            }

            if ($Context) {
                if (-not $Context.PSObject.Properties['NetworkAnalyzerState'] -or -not $Context.NetworkAnalyzerState) {
                    $Context | Add-Member -NotePropertyName 'NetworkAnalyzerState' -NotePropertyValue ([pscustomobject]@{
                        GatewayMacs = New-Object System.Collections.Generic.List[string]
                        RouterMacs  = New-Object System.Collections.Generic.List[string]
                    }) -Force
                } else {
                    if (-not $Context.NetworkAnalyzerState.PSObject.Properties['GatewayMacs']) {
                        $Context.NetworkAnalyzerState | Add-Member -NotePropertyName 'GatewayMacs' -NotePropertyValue (New-Object System.Collections.Generic.List[string]) -Force
                    }
                    if (-not $Context.NetworkAnalyzerState.PSObject.Properties['RouterMacs']) {
                        $Context.NetworkAnalyzerState | Add-Member -NotePropertyName 'RouterMacs' -NotePropertyValue (New-Object System.Collections.Generic.List[string]) -Force
                    }
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

        $ipv6RoutingArtifact = Get-AnalyzerArtifact -Context $Context -Name 'ipv6-routing'
        Write-HeuristicDebug -Source 'Network' -Message 'Resolved ipv6-routing artifact' -Data ([ordered]@{
            Found = [bool]$ipv6RoutingArtifact
        })

        $ipv6Payload = $null
        if ($ipv6RoutingArtifact) {
            $ipv6Payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $ipv6RoutingArtifact)
        }

        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating IPv6 routing payload' -Data ([ordered]@{
            HasPayload = [bool]$ipv6Payload
        })

        $ipv6Neighbors = @()
        $ipv6Routers = @()
        $ipv6Sections = @()
        $neighborPayloadError = $false
        $routerPayloadError = $false

        if ($ipv6Payload) {
            if ($ipv6Payload.PSObject.Properties['Neighbors']) {
                $neighborsRaw = $ipv6Payload.Neighbors
                if ($neighborsRaw -is [psobject] -and $neighborsRaw.PSObject.Properties['Error']) {
                    $neighborPayloadError = $true
                } elseif ($neighborsRaw) {
                    $ipv6Neighbors = ConvertTo-Ipv6NeighborEntries -Value $neighborsRaw
                }
            }

            if ($ipv6Payload.PSObject.Properties['Routers']) {
                $routersRaw = $ipv6Payload.Routers
                if ($routersRaw -is [psobject] -and $routersRaw.PSObject.Properties['Error']) {
                    $routerPayloadError = $true
                } elseif ($routersRaw) {
                    $ipv6Routers = ConvertTo-Ipv6RouterEntries -Value $routersRaw
                }
            }

            if ($ipv6Payload.PSObject.Properties['IpConfigIpv6']) {
                $sectionsRaw = $ipv6Payload.IpConfigIpv6
                if (-not ($sectionsRaw -is [psobject] -and $sectionsRaw.PSObject.Properties['Error'])) {
                    $ipv6Sections = ConvertTo-NetworkArray $sectionsRaw
                }
            }
        }

        Write-HeuristicDebug -Source 'Network' -Message 'Parsed IPv6 routing data' -Data ([ordered]@{
            NeighborCount = if ($ipv6Neighbors) { $ipv6Neighbors.Count } else { 0 }
            RouterCount   = if ($ipv6Routers) { $ipv6Routers.Count } else { 0 }
            NeighborError = $neighborPayloadError
            RouterError   = $routerPayloadError
        })

        $globalIpv6Records = New-Object System.Collections.Generic.List[pscustomobject]
        if ($adapterInventory -and $adapterInventory.Map) {
            foreach ($entry in $adapterInventory.Map.Values) {
                if (-not $entry) { continue }

                $addressSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($ipText in $entry.IPv6) {
                    if (Test-NetworkValidIpv6Address $ipText) {
                        $addressSet.Add($ipText) | Out-Null
                    }
                }

                if ($addressSet.Count -gt 0) {
                    $aliasLabel = if ($entry.PSObject.Properties['Alias']) { [string]$entry.Alias } else { $null }
                    $globalIpv6Records.Add([pscustomobject]@{
                        Alias     = $aliasLabel
                        Addresses = if ($addressSet.Count -gt 0) { [System.Linq.Enumerable]::ToArray($addressSet) } else { @() }
                    }) | Out-Null
                }
            }
        }

        $hasIpv6Gateways = $false
        if ($adapterInventory -and $adapterInventory.Map) {
            foreach ($entry in $adapterInventory.Map.Values) {
                if (-not $entry) { continue }
                foreach ($gatewayValue in $entry.IPv6Gateways) {
                    if ($gatewayValue) { $hasIpv6Gateways = $true; break }
                }
                if ($hasIpv6Gateways) { break }
            }
        }

        if ($globalIpv6Records.Count -gt 0 -and $ipv6RoutingArtifact -and -not $routerPayloadError -and $ipv6Routers.Count -eq 0 -and -not $hasIpv6Gateways) {
            $evidenceItems = $globalIpv6Records | ForEach-Object {
                $aliasLabel = if ($_.Alias) { $_.Alias } else { 'Interface' }
                $addresses = $_.Addresses | Sort-Object -Unique
                if ($addresses.Count -gt 0) {
                    '{0}: {1}' -f $aliasLabel, ($addresses -join ', ')
                }
            }

            $evidenceText = $evidenceItems | Where-Object { $_ } | Sort-Object
            $evidence = if ($evidenceText) { $evidenceText -join '; ' } else { 'Global IPv6 addresses were assigned.' }
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Global IPv6 addresses appeared on an IPv4-only network, so rogue router advertisements may break connectivity.' -Evidence $evidence -Subcategory 'IPv6 Routing'
        }

        $neighborMap = @{}
        foreach ($neighbor in $ipv6Neighbors) {
            if (-not $neighbor -or -not $neighbor.CanonicalAddress) { continue }
            $key = $neighbor.CanonicalAddress.ToLowerInvariant()
            if (-not $neighborMap.ContainsKey($key)) {
                $neighborMap[$key] = New-Object System.Collections.Generic.List[object]
            }
            $neighborMap[$key].Add($neighbor) | Out-Null
        }

        $routerMacRecords = New-Object System.Collections.Generic.List[pscustomobject]
        foreach ($router in $ipv6Routers) {
            if (-not $router) { continue }

            $key = if ($router.CanonicalAddress) { $router.CanonicalAddress.ToLowerInvariant() } else { $null }
            $macs = New-Object System.Collections.Generic.List[string]
            if ($key -and $neighborMap.ContainsKey($key)) {
                foreach ($neighbor in $neighborMap[$key]) {
                    if ($neighbor.NormalizedMac) { $macs.Add($neighbor.NormalizedMac) | Out-Null }
                }
            }

            $routerMacRecords.Add([pscustomobject]@{
                InterfaceName = if ($router.InterfaceName) { [string]$router.InterfaceName } else { $null }
                Address       = if ($router.Address) { [string]$router.Address } else { $null }
                Macs          = ($macs | Sort-Object -Unique)
            }) | Out-Null
        }

        $observedRouterMacSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $routerMacRecords) {
            foreach ($mac in $record.Macs) {
                if ($mac) { $observedRouterMacSet.Add($mac) | Out-Null }
            }
        }

        $routerBaselineSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        $routerBaselineArtifact = Get-AnalyzerArtifact -Context $Context -Name 'ipv6-router-baseline'
        if ($routerBaselineArtifact) {
            $baselinePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $routerBaselineArtifact)
            if ($baselinePayload) {
                $baselineValues = if ($baselinePayload.PSObject.Properties['RouterMacs']) { ConvertTo-NetworkArray $baselinePayload.RouterMacs } else { ConvertTo-NetworkArray $baselinePayload }
                foreach ($baselineValue in $baselineValues) {
                    $normalizedBaseline = Normalize-NetworkMacAddress $baselineValue
                    if ($normalizedBaseline) { $routerBaselineSet.Add($normalizedBaseline) | Out-Null }
                }
            }
        }

        if ($Context -and $Context.PSObject.Properties['NetworkAnalyzerState'] -and $Context.NetworkAnalyzerState -and $Context.NetworkAnalyzerState.PSObject.Properties['RouterMacs']) {
            foreach ($historical in (ConvertTo-NetworkArray $Context.NetworkAnalyzerState.RouterMacs)) {
                $normalizedHistorical = Normalize-NetworkMacAddress $historical
                if ($normalizedHistorical) { $routerBaselineSet.Add($normalizedHistorical) | Out-Null }
            }
        }

        $observedRouterMacs = @()
        foreach ($mac in $observedRouterMacSet) {
            if ($mac) { $observedRouterMacs += $mac }
        }

        $unexpectedRouterMacs = @()
        if ($routerBaselineSet.Count -gt 0) {
            foreach ($mac in $observedRouterMacs) {
                if (-not $routerBaselineSet.Contains($mac)) { $unexpectedRouterMacs += $mac }
            }
        }

        if ($unexpectedRouterMacs.Count -gt 0) {
            $evidence = ($unexpectedRouterMacs | Sort-Object -Unique) -join ', '
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'IPv6 router MAC changed, so clients may follow rogue router advertisements unless RA Guard blocks them.' -Evidence $evidence -Subcategory 'IPv6 Routing'
        }

        if ($observedRouterMacs.Count -gt 1) {
            $evidenceParts = $routerMacRecords | ForEach-Object {
                $macText = if ($_.Macs -and $_.Macs.Count -gt 0) { $_.Macs -join ', ' } else { 'no MAC learned' }
                $labelParts = @()
                if ($_.InterfaceName) { $labelParts += $_.InterfaceName }
                if ($_.Address) { $labelParts += $_.Address }
                $label = if ($labelParts.Count -gt 0) { $labelParts -join ' → ' } else { 'Router' }
                '{0} = {1}' -f $label, $macText
            }

            $evidence = ($evidenceParts | Where-Object { $_ }) -join '; '
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Multiple IPv6 router MACs detected, so rogue router advertisements may hijack clients unless RA Guard is enforced.' -Evidence $evidence -Subcategory 'IPv6 Routing'
        }

        if ($Context) {
            if (-not $Context.PSObject.Properties['NetworkAnalyzerState'] -or -not $Context.NetworkAnalyzerState) {
                $Context | Add-Member -NotePropertyName 'NetworkAnalyzerState' -NotePropertyValue ([pscustomobject]@{
                    GatewayMacs = New-Object System.Collections.Generic.List[string]
                    RouterMacs  = New-Object System.Collections.Generic.List[string]
                }) -Force
            } elseif (-not $Context.NetworkAnalyzerState.PSObject.Properties['RouterMacs']) {
                $Context.NetworkAnalyzerState | Add-Member -NotePropertyName 'RouterMacs' -NotePropertyValue (New-Object System.Collections.Generic.List[string]) -Force
            }
        }

        if ($Context -and $Context.NetworkAnalyzerState -and $Context.NetworkAnalyzerState.PSObject.Properties['RouterMacs']) {
            $existingRouterSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($existingMac in $Context.NetworkAnalyzerState.RouterMacs) {
                $normalizedExisting = Normalize-NetworkMacAddress $existingMac
                if ($normalizedExisting) { $existingRouterSet.Add($normalizedExisting) | Out-Null }
            }

            foreach ($mac in $observedRouterMacSet) {
                if (-not $mac) { continue }
                if ($existingRouterSet.Add($mac)) {
                    $Context.NetworkAnalyzerState.RouterMacs.Add($mac) | Out-Null
                }
            }
        }

        if ($payload -and $payload.IpConfig) {
            $ipText = if ($payload.IpConfig -is [string[]]) { $payload.IpConfig -join "`n" } else { [string]$payload.IpConfig }
            if ($ipText -match 'IPv4 Address') {
                Add-CategoryNormal -CategoryResult $result -Title 'IPv4 addressing detected' -Subcategory 'IP Configuration'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No IPv4 configuration found, so connectivity will fail without valid addressing.' -Evidence 'ipconfig /all output did not include IPv4 details.' -Subcategory 'IP Configuration' -Data (& $createConnectivityData $connectivityContext)
            }
        }

        if ($payload -and $payload.Route) {
            $routeText = if ($payload.Route -is [string[]]) { $payload.Route -join "`n" } else { [string]$payload.Route }
            if ($routeText -notmatch '0\.0\.0\.0') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Routing table missing default route, so outbound connectivity will fail.' -Evidence 'route print output did not include 0.0.0.0/0.' -Subcategory 'Routing' -Data (& $createConnectivityData $connectivityContext)
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Network base diagnostics not collected, so connectivity failures may go undetected.' -Subcategory 'Collection' -Data (& $createConnectivityData $connectivityContext)
    }

    if ($adapterLinkInventory -and $adapterLinkInventory.Map -and $adapterLinkInventory.Map.Keys.Count -gt 0) {
        $linkEntries = @()
        foreach ($key in $adapterLinkInventory.Map.Keys) {
            $linkEntries += $adapterLinkInventory.Map[$key]
        }

        foreach ($linkEntry in $linkEntries) {
            if (-not $linkEntry) { continue }

            $alias = if ($linkEntry.PSObject.Properties['Alias']) { [string]$linkEntry.Alias } else { $null }
            if (-not $alias) { continue }

            $aliasKey = if ($linkEntry.PSObject.Properties['Key'] -and $linkEntry.Key) { [string]$linkEntry.Key } else { $null }
            if (-not $aliasKey) {
                try { $aliasKey = $alias.ToLowerInvariant() } catch { $aliasKey = $alias }
            }

            $interfaceInfo = $null
            if ($aliasKey -and $adapterInventory -and $adapterInventory.Map -and $adapterInventory.Map.ContainsKey($aliasKey)) {
                $interfaceInfo = $adapterInventory.Map[$aliasKey]
            }

            $isPseudo = $false
            if ($interfaceInfo -and $interfaceInfo.PSObject.Properties['IsPseudo']) {
                $isPseudo = [bool]$interfaceInfo.IsPseudo
            } else {
                $description = if ($linkEntry.PSObject.Properties['Description']) { $linkEntry.Description } else { $null }
                $isPseudo = Test-NetworkPseudoInterface -Alias $alias -Description $description
            }
            if ($isPseudo) { continue }

            $isUp = $false
            if ($interfaceInfo -and $interfaceInfo.PSObject.Properties['IsUp']) {
                $isUp = [bool]$interfaceInfo.IsUp
            } else {
                $statusText = if ($linkEntry.PSObject.Properties['Status']) { [string]$linkEntry.Status } else { $null }
                $normalizedStatus = if ($statusText) {
                    try { $statusText.ToLowerInvariant() } catch { $statusText }
                } else { '' }
                if ($normalizedStatus -eq 'up' -or $normalizedStatus -eq 'connected' -or $normalizedStatus -like 'up*') {
                    $isUp = $true
                }
            }
            if (-not $isUp) { continue }

            $linkMetrics = if ($linkEntry.PSObject.Properties['LinkSpeed']) { $linkEntry.LinkSpeed } else { $null }
            $linkBits = if ($linkMetrics) { $linkMetrics.BitsPerSecond } else { $null }
            if ($linkBits -and $linkBits -le 0) { $linkBits = $null }

            $policy = if ($linkEntry.PSObject.Properties['SpeedPolicy']) { $linkEntry.SpeedPolicy } else { $null }
            $policyBits = if ($policy) { $policy.BitsPerSecond } else { $null }
            $policyDuplex = if ($policy -and $policy.Duplex) { [string]$policy.Duplex } else { $null }

            $linkText = $null
            if ($linkMetrics -and $linkMetrics.Text) { $linkText = $linkMetrics.Text }
            elseif ($linkEntry.PSObject.Properties['LinkSpeedText']) { $linkText = [string]$linkEntry.LinkSpeedText }

            $policyText = if ($linkEntry.PSObject.Properties['SpeedPolicyText']) { [string]$linkEntry.SpeedPolicyText } else { $null }
            $descriptionText = if ($linkEntry.PSObject.Properties['Description']) { [string]$linkEntry.Description } else { $null }

            $isGigabitCapable = if ($linkEntry.PSObject.Properties['IsGigabitCapable']) { [bool]$linkEntry.IsGigabitCapable } else { $false }

            $isHundredMegLink = ($linkBits -and $linkBits -ge 90000000 -and $linkBits -le 120000000)
            $isHundredMegPolicy = ($policyBits -and $policyBits -ge 90000000 -and $policyBits -le 120000000)

            if ($isGigabitCapable -and $isHundredMegLink -and $isHundredMegPolicy -and $policyDuplex -eq 'Half') {
                $evidence = [ordered]@{}
                $evidence['Adapter'] = $alias
                if ($descriptionText) { $evidence['Description'] = $descriptionText }
                if ($linkText) { $evidence['LinkSpeed'] = $linkText }
                if ($policyText) { $evidence['Policy'] = $policyText }
                $remediation = 'Re-enable auto-negotiation on the NIC and replace the cable or switch port until it links at gigabit full duplex.'

                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Adapter {0} stuck at 100 Mb half duplex, so users will hit collisions and slow LAN throughput." -f $alias) -Evidence $evidence -Subcategory 'Adapters' -Remediation $remediation
                continue
            }

            if ($policyBits -and $linkBits -and ([math]::Abs($policyBits - $linkBits) -gt 1000000)) {
                $policyLabel = if ($policyText) { $policyText } elseif ($policyBits) { ('{0:N0} bps' -f $policyBits) } else { 'policy' }
                $linkLabel = if ($linkText) { $linkText } elseif ($linkBits) { ('{0:N0} bps' -f $linkBits) } else { 'link speed' }

                $evidence = [ordered]@{}
                $evidence['Adapter'] = $alias
                if ($descriptionText) { $evidence['Description'] = $descriptionText }
                if ($policyText) { $evidence['Policy'] = $policyText } elseif ($policyBits) { $evidence['Policy'] = ('{0:N0} bps' -f $policyBits) }
                if ($linkText) { $evidence['LinkSpeed'] = $linkText } elseif ($linkBits) { $evidence['LinkSpeed'] = ('{0:N0} bps' -f $linkBits) }
                $remediation = 'Set the NIC and switch port to matching speed/duplex or leave both on auto-negotiation so the link meets policy.'

                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("Adapter {0} policy {1} disagrees with negotiated {2}, so throughput and stability will suffer until they match." -f $alias, $policyLabel, $linkLabel) -Evidence $evidence -Subcategory 'Adapters' -Remediation $remediation
            }
        }
    }

    $lldpSubcategory = 'Switch Port Mapping'
    $lldpArtifact = Get-AnalyzerArtifact -Context $Context -Name 'network-lldp'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved network-lldp artifact' -Data ([ordered]@{
        Found = [bool]$lldpArtifact
    })
    if ($lldpArtifact) {
        $lldpPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lldpArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating network-lldp payload' -Data ([ordered]@{
            HasPayload = [bool]$lldpPayload
        })

        $lldpNeighbors = ConvertTo-LldpNeighborRecords -Payload $lldpPayload
        $neighborCount = if ($lldpNeighbors) { $lldpNeighbors.Count } else { 0 }
        Write-HeuristicDebug -Source 'Network' -Message 'Parsed LLDP neighbors' -Data ([ordered]@{
            Count = $neighborCount
        })

        $switchPortExpectations = Get-NetworkSwitchPortExpectations -Context $Context
        $expectationCount = if ($switchPortExpectations -and $switchPortExpectations.Records) { $switchPortExpectations.Records.Count } else { 0 }
        Write-HeuristicDebug -Source 'Network' -Message 'Resolved switch port expectations' -Data ([ordered]@{
            Count   = $expectationCount
            Sources = if ($switchPortExpectations -and $switchPortExpectations.Sources) { ($switchPortExpectations.Sources -join ', ') } else { '(none)' }
        })

        if ($neighborCount -eq 0) {
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'LLDP neighbors missing, so switch port documentation cannot be verified and mispatches may go unnoticed.' -Subcategory $lldpSubcategory
        } else {
            $neighborMap = @{}
            foreach ($neighbor in $lldpNeighbors) {
                if (-not $neighbor) { continue }
                $keys = @()
                if ($neighbor.PSObject.Properties['AliasKeys'] -and $neighbor.AliasKeys) {
                    $keys = $neighbor.AliasKeys
                } elseif ($neighbor.PSObject.Properties['InterfaceAlias'] -and $neighbor.InterfaceAlias) {
                    $aliasKey = $neighbor.InterfaceAlias
                    try { $keys = @($aliasKey.ToLowerInvariant()) } catch { $keys = @([string]$aliasKey) }
                }

                foreach ($key in $keys) {
                    if (-not $key) { continue }
                    if (-not $neighborMap.ContainsKey($key)) {
                        $neighborMap[$key] = New-Object System.Collections.Generic.List[pscustomobject]
                    }
                    $neighborMap[$key].Add($neighbor) | Out-Null
                }
            }

            if ($expectationCount -gt 0 -and $switchPortExpectations -and $switchPortExpectations.Records) {
                foreach ($expected in $switchPortExpectations.Records) {
                    if (-not $expected) { continue }

                    $alias = if ($expected.PSObject.Properties['Alias']) { [string]$expected.Alias } else { 'Interface' }
                    $aliasKeys = if ($expected.PSObject.Properties['AliasKeys'] -and $expected.AliasKeys) { $expected.AliasKeys } else { @() }

                    $candidateNeighbors = New-Object System.Collections.Generic.List[pscustomobject]
                    foreach ($aliasKey in $aliasKeys) {
                        if (-not $aliasKey) { continue }
                        if ($neighborMap.ContainsKey($aliasKey)) {
                            foreach ($neighbor in $neighborMap[$aliasKey]) { $candidateNeighbors.Add($neighbor) | Out-Null }
                        }
                    }

                    $selectedNeighbor = $null
                    if ($candidateNeighbors.Count -gt 0) {
                        $candidateArray = $candidateNeighbors.ToArray()
                        $selectedNeighbor = $candidateArray | Where-Object { $_.Source -eq 'Get-NetAdapterLldpAgent' } | Select-Object -First 1
                        if (-not $selectedNeighbor) {
                            $selectedNeighbor = $candidateArray | Select-Object -First 1
                        }
                    }

                    $interfaceInfo = $null
                    if ($adapterInventory -and $adapterInventory.Map -and $aliasKeys) {
                        foreach ($aliasKey in $aliasKeys) {
                            if ($adapterInventory.Map.ContainsKey($aliasKey)) { $interfaceInfo = $adapterInventory.Map[$aliasKey]; break }
                        }
                    }

                    $isPseudo = $false
                    if ($interfaceInfo -and $interfaceInfo.PSObject.Properties['IsPseudo']) { $isPseudo = [bool]$interfaceInfo.IsPseudo }

                    if (-not $selectedNeighbor) {
                        if ($isPseudo) { continue }

                        $expectedLabel = if ($expected.PSObject.Properties['ExpectedLabel'] -and $expected.ExpectedLabel) { [string]$expected.ExpectedLabel } else { $null }
                        if (-not $expectedLabel) {
                            $parts = @()
                            if ($expected.PSObject.Properties['ExpectedSwitch'] -and $expected.ExpectedSwitch) { $parts += [string]$expected.ExpectedSwitch }
                            if ($expected.PSObject.Properties['ExpectedPort'] -and $expected.ExpectedPort) { $parts += [string]$expected.ExpectedPort }
                            if ($parts.Count -gt 0) { $expectedLabel = ($parts -join ' ') }
                        }
                        if (-not $expectedLabel) { $expectedLabel = 'the documented switch port' }

                        $evidence = [ordered]@{ Adapter = $alias }
                        if ($expected.PSObject.Properties['ExpectedSwitch'] -and $expected.ExpectedSwitch) { $evidence['ExpectedSwitch'] = [string]$expected.ExpectedSwitch }
                        if ($expected.PSObject.Properties['ExpectedPort'] -and $expected.ExpectedPort) { $evidence['ExpectedPort'] = [string]$expected.ExpectedPort }
                        if ($expected.PSObject.Properties['ExpectedLabel'] -and $expected.ExpectedLabel -and -not $evidence.Contains('ExpectedPort')) { $evidence['ExpectedLabel'] = [string]$expected.ExpectedLabel }
                        if ($expected.PSObject.Properties['Source'] -and $expected.Source) { $evidence['InventorySource'] = [string]$expected.Source }

                        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title ("Adapter {0} lacks LLDP neighbor data, so {1} cannot be verified and mispatches may go unnoticed." -f $alias, $expectedLabel) -Evidence $evidence -Subcategory $lldpSubcategory
                        continue
                    }

                    $observedSwitchNormalized = if ($selectedNeighbor.PSObject.Properties['NormalizedSwitch']) { $selectedNeighbor.NormalizedSwitch } else { $null }
                    if (-not $observedSwitchNormalized -and $selectedNeighbor.PSObject.Properties['NeighborSystemDescription']) {
                        $observedSwitchNormalized = Normalize-NetworkInventoryText $selectedNeighbor.NeighborSystemDescription
                    }

                    $observedPortNormalized = if ($selectedNeighbor.PSObject.Properties['NormalizedPort']) { $selectedNeighbor.NormalizedPort } else { $null }
                    if (-not $observedPortNormalized -and $selectedNeighbor.PSObject.Properties['NeighborPortDescription']) {
                        $observedPortNormalized = Normalize-NetworkInventoryText $selectedNeighbor.NeighborPortDescription
                    }

                    $observedLabelNormalized = if ($selectedNeighbor.PSObject.Properties['NormalizedObservedLabel']) { $selectedNeighbor.NormalizedObservedLabel } else { $null }

                    $expectedSwitchNormalized = if ($expected.PSObject.Properties['NormalizedSwitch']) { $expected.NormalizedSwitch } else { $null }
                    $expectedPortNormalized = if ($expected.PSObject.Properties['NormalizedPort']) { $expected.NormalizedPort } else { $null }
                    $expectedLabelNormalized = if ($expected.PSObject.Properties['NormalizedLabel']) { $expected.NormalizedLabel } else { $null }

                    $switchMatches = $true
                    if ($expectedSwitchNormalized) {
                        $switchMatches = ($observedSwitchNormalized -eq $expectedSwitchNormalized)
                        if (-not $switchMatches -and $observedLabelNormalized) {
                            $switchMatches = $observedLabelNormalized.Contains($expectedSwitchNormalized)
                        }
                    }

                    $portMatches = $true
                    if ($expectedPortNormalized) {
                        $portMatches = ($observedPortNormalized -eq $expectedPortNormalized)
                        if (-not $portMatches -and $observedLabelNormalized) {
                            $portMatches = $observedLabelNormalized.Contains($expectedPortNormalized)
                        }
                    }

                    $labelMatches = $true
                    if ($expectedLabelNormalized) {
                        $labelMatches = ($observedLabelNormalized -eq $expectedLabelNormalized)
                    }

                    if (-not ($switchMatches -and $portMatches -and $labelMatches)) {
                        $expectedDisplay = $null
                        if ($expected.PSObject.Properties['ExpectedLabel'] -and $expected.ExpectedLabel) {
                            $expectedDisplay = [string]$expected.ExpectedLabel
                        } else {
                            $parts = @()
                            if ($expected.PSObject.Properties['ExpectedSwitch'] -and $expected.ExpectedSwitch) { $parts += [string]$expected.ExpectedSwitch }
                            if ($expected.PSObject.Properties['ExpectedPort'] -and $expected.ExpectedPort) { $parts += [string]$expected.ExpectedPort }
                            if ($parts.Count -gt 0) { $expectedDisplay = ($parts -join ' ') }
                        }
                        if (-not $expectedDisplay) { $expectedDisplay = 'the documented switch port' }

                        $observedDisplay = if ($selectedNeighbor.PSObject.Properties['ObservedLabel'] -and $selectedNeighbor.ObservedLabel) { [string]$selectedNeighbor.ObservedLabel } else { $null }
                        if (-not $observedDisplay) {
                            $parts = @()
                            if ($selectedNeighbor.PSObject.Properties['NeighborSystemName'] -and $selectedNeighbor.NeighborSystemName) { $parts += [string]$selectedNeighbor.NeighborSystemName }
                            elseif ($selectedNeighbor.PSObject.Properties['NeighborSystemDescription'] -and $selectedNeighbor.NeighborSystemDescription) { $parts += [string]$selectedNeighbor.NeighborSystemDescription }
                            if ($selectedNeighbor.PSObject.Properties['NeighborPortId'] -and $selectedNeighbor.NeighborPortId) { $parts += [string]$selectedNeighbor.NeighborPortId }
                            elseif ($selectedNeighbor.PSObject.Properties['NeighborPortDescription'] -and $selectedNeighbor.NeighborPortDescription) { $parts += [string]$selectedNeighbor.NeighborPortDescription }
                            if ($parts.Count -gt 0) { $observedDisplay = ($parts -join ' ') }
                        }
                        if (-not $observedDisplay) { $observedDisplay = 'an unknown switch port' }

                        $evidence = [ordered]@{ Adapter = $alias }
                        if ($expected.PSObject.Properties['ExpectedSwitch'] -and $expected.ExpectedSwitch) { $evidence['ExpectedSwitch'] = [string]$expected.ExpectedSwitch }
                        if ($expected.PSObject.Properties['ExpectedPort'] -and $expected.ExpectedPort) { $evidence['ExpectedPort'] = [string]$expected.ExpectedPort }
                        if ($expected.PSObject.Properties['ExpectedLabel'] -and $expected.ExpectedLabel) { $evidence['ExpectedLabel'] = [string]$expected.ExpectedLabel }
                        if ($expected.PSObject.Properties['Source'] -and $expected.Source) { $evidence['InventorySource'] = [string]$expected.Source }
                        if ($selectedNeighbor.PSObject.Properties['NeighborSystemName'] -and $selectedNeighbor.NeighborSystemName) { $evidence['ObservedSwitch'] = [string]$selectedNeighbor.NeighborSystemName }
                        elseif ($selectedNeighbor.PSObject.Properties['NeighborSystemDescription'] -and $selectedNeighbor.NeighborSystemDescription) { $evidence['ObservedSwitch'] = [string]$selectedNeighbor.NeighborSystemDescription }
                        if ($selectedNeighbor.PSObject.Properties['NeighborPortId'] -and $selectedNeighbor.NeighborPortId) { $evidence['ObservedPort'] = [string]$selectedNeighbor.NeighborPortId }
                        elseif ($selectedNeighbor.PSObject.Properties['NeighborPortDescription'] -and $selectedNeighbor.NeighborPortDescription) { $evidence['ObservedPort'] = [string]$selectedNeighbor.NeighborPortDescription }
                        if ($selectedNeighbor.PSObject.Properties['Source'] -and $selectedNeighbor.Source) { $evidence['ObservationSource'] = [string]$selectedNeighbor.Source }

                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("Adapter {0} is patched to {1} instead of documented {2}, so cabling records are wrong and technicians may troubleshoot the wrong switch port." -f $alias, $observedDisplay, $expectedDisplay) -Evidence $evidence -Subcategory $lldpSubcategory
                    }
                }
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Switch port inventory missing, so LLDP data cannot confirm wiring and mispatches may linger.' -Subcategory $lldpSubcategory
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'LLDP collector missing, so switch port documentation cannot be verified and mispatches may go unnoticed.' -Subcategory $lldpSubcategory
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
        $dnsContext = @{
            Resolution    = if ($payload -and $payload.PSObject.Properties['Resolution']) { ConvertTo-NetworkArray $payload.Resolution } else { @() }
            Latency       = if ($payload -and $payload.PSObject.Properties['Latency']) { $payload.Latency } else { $null }
            Autodiscover  = if ($payload -and $payload.PSObject.Properties['Autodiscover']) { ConvertTo-NetworkArray $payload.Autodiscover } else { @() }
            ClientServers = if ($payload -and $payload.PSObject.Properties['ClientServers']) { ConvertTo-NetworkArray $payload.ClientServers } else { @() }
            ClientPolicies = if ($payload -and $payload.PSObject.Properties['ClientPolicies']) { ConvertTo-NetworkArray $payload.ClientPolicies } else { @() }
        }
        $connectivityContext.Dns = $dnsContext
        if ($payload -and $payload.Resolution) {
            $failures = $payload.Resolution | Where-Object { $_.Success -eq $false }
            if ($failures.Count -gt 0) {
                $names = $failures.Name
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('DNS lookup failures: {0} — DNS resolution is failing.' -f ($names -join ', ')) -Subcategory 'DNS Resolution' -Data (& $createConnectivityData $connectivityContext)
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
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Ping to DNS {0} failed, showing DNS resolution is failing.' -f $remoteAddress) -Subcategory 'Latency' -Data (& $createConnectivityData $connectivityContext)
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title ('Ping to DNS {0} succeeded' -f $remoteAddress) -Subcategory 'Latency'
                }
            } elseif ($latency -is [string] -and $latency -match 'Request timed out') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Latency test reported timeouts, showing DNS resolution is failing.' -Subcategory 'Latency' -Data (& $createConnectivityData $connectivityContext)
            }
        }

        if ($payload -and $payload.Autodiscover) {
            $entries = ConvertTo-NetworkArray $payload.Autodiscover
            $primaryErrors = New-Object System.Collections.Generic.List[string]

            foreach ($entry in $entries) {
                if (-not ($entry -and $entry.PSObject.Properties['Error'] -and $entry.Error)) { continue }

                $query = if ($entry.PSObject.Properties['Query']) { [string]$entry.Query } else { $null }
                $source = if ($entry.PSObject.Properties['DomainSource']) { [string]$entry.DomainSource } else { $null }
                $isPrimary = $false

                if ($entry.PSObject.Properties['IsPrimary']) {
                    $flag = $entry.IsPrimary
                    if ($flag -is [bool]) {
                        $isPrimary = $flag
                    } elseif ($flag -is [string]) {
                        $trimmed = $flag.Trim()
                        if ($trimmed) {
                            $upper = $trimmed.ToUpperInvariant()
                            if ($upper -in @('TRUE','YES','1')) { $isPrimary = $true }
                        }
                    }
                }

                if (-not $isPrimary -and $source) {
                    $normalizedSource = $source.Trim()
                    if ($normalizedSource) {
                        try { $normalizedSource = $normalizedSource.ToUpperInvariant() } catch { }
                        if ($normalizedSource -eq 'UPN') { $isPrimary = $true }
                    }
                }

                if (-not $isPrimary) { continue }

                if ($query -and $query -match '^(?i)(enterpriseenrollment|enterpriseregistration)\.outlook\.com$') { continue }

                $message = [string]$entry.Error
                if (-not $message) { continue }

                $display = if ($query) { '{0} : {1}' -f $query, $message } else { $message }
                $primaryErrors.Add($display) | Out-Null
            }

            if ($primaryErrors.Count -gt 0) {
                $details = $primaryErrors | Select-Object -First 3
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Autodiscover DNS queries failed, so missing or invalid records can cause mail setup failures.' -Evidence ($details -join "`n") -Subcategory 'DNS Autodiscover' -Data (& $createConnectivityData $connectivityContext)
            }
        }

        if ($payload -and $payload.ClientServers) {
            $entries = ConvertTo-NetworkArray $payload.ClientServers
            $publicServers = New-Object System.Collections.Generic.List[string]
            $privateServers = New-Object System.Collections.Generic.List[string]
            $allServerSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            $loopbackOnly = $true
            $missingInterfaces = @()
            $ignoredPseudo = @()

            $interfaceMap = if ($adapterInventory -and $adapterInventory.Map) { $adapterInventory.Map } else { @{} }
            $eligibleAliases = if ($adapterInventory -and $adapterInventory.EligibleAliases) { $adapterInventory.EligibleAliases } else { @() }
            $fallbackEligibleAliases = if ($adapterInventory -and $adapterInventory.FallbackEligibleAliases) { $adapterInventory.FallbackEligibleAliases } else { @() }
            $useFallbackEligibility = ($eligibleAliases.Count -eq 0 -and $fallbackEligibleAliases.Count -gt 0)

            foreach ($entry in $entries) {
                if ($entry -and $entry.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Unable to enumerate DNS servers, so name resolution may fail on domain devices.' -Evidence $entry.Error -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
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
                    if (-not $address) { continue }
                    $addressText = [string]$address
                    if (-not $addressText) { continue }
                    if (-not (Test-NetworkLoopback $addressText)) { $loopbackForInterface = $false }
                    if ($allServerSet) { [void]$allServerSet.Add($addressText) }
                    if (Test-NetworkInternalDnsAddress $addressText) {
                        $privateServers.Add($addressText) | Out-Null
                    } elseif (-not (Test-NetworkLoopback $addressText)) {
                        $publicServers.Add($addressText) | Out-Null
                    }
                }

                if (-not $loopbackForInterface) { $loopbackOnly = $false }
                Add-CategoryCheck -CategoryResult $result -Name ("DNS servers ({0})" -f $alias) -Status (($addresses | Select-Object -First 3) -join ', ')
            }

            if ($missingInterfaces.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Adapters missing DNS servers: {0}, so name resolution may fail on domain devices.' -f ($missingInterfaces -join ', ')) -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
            }

            if ($ignoredPseudo.Count -gt 0) {
                $pseudoTitle = "Ignored {0} pseudo/virtual adapters (loopback/ICS/Hyper-V) without DNS — not used for normal name resolution." -f $ignoredPseudo.Count
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $pseudoTitle -Evidence ($ignoredPseudo -join ', ') -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
            }

            if ($publicServers.Count -gt 0) {
                $uniquePublic = ($publicServers | Select-Object -Unique)
                $allServers = ConvertTo-NetworkArray $allServerSet
                $hasInternalDns = ($privateServers.Count -gt 0)

                $suffixList = Get-NetworkDnsSuffixList -DnsPayload $payload
                $internalZones = Get-NetworkDnsInternalZones -JoinContext $dnsJoinContext -Suffixes $suffixList
                $networkContextInfo = Get-NetworkDnsNetworkContext -Context $Context -AdapterInventory $adapterInventory -Suffixes $suffixList -JoinContext $dnsJoinContext
                $secureChannelStatus = Get-NetworkSecureChannelStatus -Context $Context

                $needsInternalZones = $dnsJoinContext.NeedsInternalZones
                if (-not $needsInternalZones -and $dnsJoinContext.JoinCategory -eq 'AzureAd' -and $internalZones.Count -gt 0) {
                    $needsInternalZones = $true
                }

                $hasCoverage = $hasInternalDns

                $severity = 'info'
                switch ($dnsJoinContext.JoinCategory) {
                    'DomainController' { $severity = 'critical' }
                    'DomainJoined' { $severity = ($hasCoverage ? 'low' : 'high') }
                    'Hybrid'        { $severity = ($hasCoverage ? 'low' : 'high') }
                    'AzureAd' {
                        if ($needsInternalZones) {
                            $severity = ($hasCoverage ? 'low' : 'high')
                        } elseif ($networkContextInfo.Key -eq 'corp') {
                            $severity = 'medium'
                        } elseif ($networkContextInfo.Key -eq 'guest') {
                            $severity = 'info'
                        } else {
                            $severity = 'info'
                        }
                    }
                    default {
                        if ($needsInternalZones) {
                            $severity = ($hasCoverage ? 'low' : 'high')
                        } elseif ($networkContextInfo.Key -eq 'corp') {
                            $severity = 'medium'
                        } elseif ($networkContextInfo.Key -eq 'guest') {
                            $severity = 'info'
                        } else {
                            $severity = 'info'
                        }
                    }
                }

                $severityTitle = [System.Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($severity)
                $coverageWord = if ($hasCoverage) { 'do' } else { 'do not' }
                $summary = 'Public DNS can break AD service discovery and split-DNS for internal apps; on this {0} device in {1}, internal zones {2} have NRPT/VPN coverage.' -f $dnsJoinContext.JoinTitle, $networkContextInfo.Label, $coverageWord

                $domainLabel = if ($dnsJoinContext.DomainName) { $dnsJoinContext.DomainName } else { 'Workgroup' }
                $secureChannelText = if ($secureChannelStatus -and $secureChannelStatus.Status) { [string]$secureChannelStatus.Status } else { 'Unknown' }
                $ssidText = if ($networkContextInfo.Ssid) { $networkContextInfo.Ssid } else { 'N/A' }
                $gatewayText = if ($networkContextInfo.Gateway) { $networkContextInfo.Gateway } else { 'Unknown' }
                $suffixText = if ($suffixList -and $suffixList.Count -gt 0) { $suffixList -join ', ' } else { 'none' }
                $internalZoneText = if ($internalZones -and $internalZones.Count -gt 0) { $internalZones -join ', ' } else { 'none detected' }
                $coverageText = if ($hasCoverage) { 'Present' } else { 'Missing' }

                $evidence = [ordered]@{
                    'Join/Identity'     = ('Domain={0}; Join={1}; SecureChannel={2}' -f $domainLabel, $dnsJoinContext.JoinTitle, $secureChannelText)
                    'Network Context'   = ('Context={0}; SSID={1}; Gateway={2}' -f $networkContextInfo.Label, $ssidText, $gatewayText)
                    'DNS Servers'       = ('{0}' -f ($allServers -join ', '))
                    'Public Resolvers'  = ('{0}' -f ($uniquePublic -join ', '))
                    'Search Suffixes'   = ('{0}' -f $suffixText)
                    'Internal Zones'    = ('{0}' -f $internalZoneText)
                    'NRPT/VPN Coverage' = ('{0}' -f $coverageText)
                }

                $data = [ordered]@{
                    'Join.DomainName'           = $dnsJoinContext.DomainName
                    'Join.JoinCategory'         = $dnsJoinContext.JoinCategory
                    'Join.JoinTitle'            = $dnsJoinContext.JoinTitle
                    'Join.DomainJoined'         = $dnsJoinContext.DomainJoined
                    'Join.AzureAdJoined'        = $dnsJoinContext.AzureAdJoined
                    'Join.SecureChannel'        = $secureChannelText
                    'Network.Context'           = $networkContextInfo.Label
                    'Network.Ssid'              = $networkContextInfo.Ssid
                    'Network.DefaultGateway'    = $networkContextInfo.Gateway
                    'Dns.Servers'               = $allServers
                    'Dns.PublicServers'         = $uniquePublic
                    'Dns.PrivateServersPresent' = $hasInternalDns
                    'Dns.SearchSuffixList'      = $suffixList
                    'Dns.InternalZones'         = $internalZones
                    'Dns.NrptVpnCoverage'       = $hasCoverage
                    'Dns.NeedsInternalZones'    = $needsInternalZones
                }

                $remediation = Get-NetworkDnsRemediation -JoinContext $dnsJoinContext -NeedsInternalZones $needsInternalZones -NetworkContext $networkContextInfo
                $title = 'DNS: Public resolvers detected on {0} device in {1} → {2}' -f $dnsJoinContext.JoinTitle, $networkContextInfo.Label, $severityTitle

                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Explanation $summary -Subcategory 'DNS Client' -Remediation $remediation -Data $data
            } elseif (-not $loopbackOnly) {
                Add-CategoryNormal -CategoryResult $result -Title 'Private DNS servers detected' -Subcategory 'DNS Client'
            }
        }

        if ($payload -and $payload.ClientPolicies) {
            $policies = ConvertTo-NetworkArray $payload.ClientPolicies
            foreach ($policy in $policies) {
                if ($policy -and $policy.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'DNS client policy query failed, so name resolution policy issues may be hidden and cause failures.' -Evidence $policy.Error -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
                    continue
                }

                $alias = if ($policy.InterfaceAlias) { [string]$policy.InterfaceAlias } else { 'Interface' }
                $suffix = $policy.ConnectionSpecificSuffix
                if ($suffix) {
                    Add-CategoryCheck -CategoryResult $result -Name ("DNS suffix ({0})" -f $alias) -Status $suffix
                }

                if ($policy.PSObject.Properties['RegisterThisConnectionsAddress']) {
                    $register = $policy.RegisterThisConnectionsAddress
                    if ($register -eq $false -and $devicePartOfDomain -eq $true) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("DNS registration disabled on {0}, so name resolution may fail on domain devices." -f $alias) -Evidence 'RegisterThisConnectionsAddress = False' -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'DNS diagnostics not collected, so latency and name resolution issues may be missed.' -Subcategory 'DNS Resolution' -Data (& $createConnectivityData $connectivityContext)
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
        $connectivityContext.Outlook = if ($payload -and $payload.PSObject.Properties['Connectivity']) { $payload.Connectivity } else { $null }
        if ($payload -and $payload.Connectivity) {
            $conn = $payload.Connectivity
                if ($conn.PSObject.Properties['TcpTestSucceeded']) {
                    if (-not $conn.TcpTestSucceeded) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title "Outlook HTTPS connectivity failed, so Outlook can't connect to Exchange Online." -Evidence ('TcpTestSucceeded reported False for {0}' -f $conn.RemoteAddress) -Subcategory 'Outlook Connectivity' -Data (& $createConnectivityData $connectivityContext)
                    } else {
                        Add-CategoryNormal -CategoryResult $result -Title 'Outlook HTTPS connectivity succeeded' -Subcategory 'Outlook Connectivity'
                }
            } elseif ($conn.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to test Outlook connectivity, leaving potential loss of access to Exchange Online unverified.' -Evidence $conn.Error -Subcategory 'Outlook Connectivity' -Data (& $createConnectivityData $connectivityContext)
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
                        $severity = if ($devicePartOfDomain -eq $true) { 'medium' } else { 'low' }
                        Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover for {0} targets {1}, so mail setup may fail for Exchange Online." -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.' -Subcategory 'Autodiscover DNS' -Data (& $createConnectivityData $connectivityContext)
                    }
                } elseif ($autoRecord.Success -eq $false) {
                    $severity = if ($devicePartOfDomain -eq $true) { 'high' } else { 'medium' }
                    $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover lookup failed for {0}, so mail setup may fail." -f $domain) -Evidence $evidence -Subcategory 'Autodiscover DNS' -Data (& $createConnectivityData $connectivityContext)
                }

                $dnsWarningLabels = @('EnterpriseRegistration','EnterpriseEnrollment')
                foreach ($additional in $lookups) {
                    if (-not $additional) { continue }
                    if (-not $additional.Label) { continue }
                    if ($additional.Label -eq 'Autodiscover') { continue }
                    if ($dnsWarningLabels -notcontains $additional.Label) { continue }
                    if ($additional.Success -eq $false -and $additional.Error) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("{0} record missing for {1}, so mail setup may fail." -f $additional.Label, $domain) -Evidence $additional.Error -Subcategory 'Autodiscover DNS' -Data (& $createConnectivityData $connectivityContext)
                    }
                }
            }
        }
    }

    if ($adapterPayload -and $adapterPayload.PSObject.Properties['Adapters']) {
        $adapters = ConvertTo-NetworkArray $adapterPayload.Adapters
        if ($adapters.Count -eq 1 -and ($adapters[0] -is [pscustomobject]) -and $adapters[0].PSObject.Properties['Error'] -and $adapters[0].Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Unable to enumerate network adapters, so link status is unknown.' -Evidence $adapters[0].Error -Subcategory 'Network Adapters'
        } elseif ($adapters.Count -gt 0) {
            $activeAdapterNames = New-Object System.Collections.Generic.List[string]
            $addActiveAdapter = {
                param([string]$Alias)

                if (-not $Alias) { return }
                if (-not ($activeAdapterNames -contains $Alias)) { $null = $activeAdapterNames.Add($Alias) }
            }

            foreach ($adapter in $adapters) {
                if (-not $adapter) { continue }

                $name = if ($adapter.PSObject.Properties['Name']) { [string]$adapter.Name } else { $null }
                $statusText = if ($adapter.PSObject.Properties['Status']) { [string]$adapter.Status } else { $null }
                $normalizedStatus = if ($statusText) { $statusText.Trim().ToLowerInvariant() } else { '' }
                $isReportedUp = ($normalizedStatus -eq 'up' -or $normalizedStatus -eq 'connected' -or $normalizedStatus -like 'up*')

                if ($isReportedUp -and $name) { & $addActiveAdapter $name }
            }

            if ($adapterInventory -and $adapterInventory.PSObject.Properties['Map'] -and $adapterInventory.Map) {
                foreach ($entry in $adapterInventory.Map.GetEnumerator()) {
                    if (-not $entry) { continue }

                    $info = $entry.Value
                    if (-not $info) { continue }

                    $alias = if ($info.PSObject.Properties['Alias']) { [string]$info.Alias } else { $null }
                    if (-not $alias) { continue }

                    $hasValidAddress = if ($info.PSObject.Properties['HasValidAddress']) { [bool]$info.HasValidAddress } else { $false }
                    $hasGateway = if ($info.PSObject.Properties['HasGateway']) { [bool]$info.HasGateway } else { $false }
                    $isPseudo = if ($info.PSObject.Properties['IsPseudo']) { [bool]$info.IsPseudo } else { $false }
                    $isEligible = if ($info.PSObject.Properties['IsEligible']) { [bool]$info.IsEligible } else { $false }
                    $isFallbackEligible = if ($info.PSObject.Properties['IsFallbackEligible']) { [bool]$info.IsFallbackEligible } else { $false }
                    $ipv6GatewayCount = 0
                    if ($info.PSObject.Properties['IPv6Gateways'] -and $info.IPv6Gateways) {
                        $ipv6GatewayCount = (@($info.IPv6Gateways | Where-Object { $_ })).Count
                    }

                    if ($isEligible -or $isFallbackEligible -or ($hasValidAddress -and -not $isPseudo -and ($hasGateway -or $ipv6GatewayCount -gt 0))) {
                        & $addActiveAdapter $alias
                    }
                }
            }

            if ($activeAdapterNames.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Active adapters: {0}' -f ($activeAdapterNames -join ', ')) -Subcategory 'Network Adapters'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No active network adapters reported, so the device has no path for network connectivity.' -Subcategory 'Network Adapters' -Remediation 'Confirm the NIC is enabled and cabled, then reload or reinstall the network drivers to restore link; replace the adapter if it stays offline.'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Network adapter inventory incomplete, so link status is unknown.' -Subcategory 'Network Adapters'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Network adapter inventory not collected, so link status is unknown.' -Subcategory 'Network Adapters'
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
        $proxyContext = @{
            Internet = if ($payload -and $payload.PSObject.Properties['Internet']) { $payload.Internet } else { $null }
            WinHttp  = if ($payload -and $payload.PSObject.Properties['WinHttp']) { $payload.WinHttp } else { $null }
        }
        $connectivityContext.Proxy = $proxyContext
        if ($payload -and $payload.Internet) {
            $internet = $payload.Internet
            if ($internet.ProxyEnable -eq 1 -and $internet.ProxyServer) {
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ('User proxy enabled: {0}' -f $internet.ProxyServer) -Subcategory 'Proxy Configuration' -Data (& $createConnectivityData $connectivityContext)
            } elseif ($internet.ProxyEnable -eq 0) {
                Add-CategoryNormal -CategoryResult $result -Title 'User proxy disabled' -Subcategory 'Proxy Configuration'
            }
        }

        if ($payload -and $payload.WinHttp) {
            $winHttpText = if ($payload.WinHttp -is [string[]]) { $payload.WinHttp -join "`n" } else { [string]$payload.WinHttp }
            if ($winHttpText -match 'Direct access') {
                Add-CategoryNormal -CategoryResult $result -Title 'WinHTTP proxy: Direct access' -Subcategory 'Proxy Configuration'
            } elseif ($winHttpText) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WinHTTP proxy configured' -Evidence $winHttpText -Subcategory 'Proxy Configuration' -Data (& $createConnectivityData $connectivityContext)
            }
        }
    }

    $lan8021xArtifact = Get-AnalyzerArtifact -Context $Context -Name 'lan-8021x'
    $wiredSubcategory = 'Wired 802.1X'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved lan-8021x artifact' -Data ([ordered]@{
        Found = [bool]$lan8021xArtifact
    })
    if ($lan8021xArtifact) {
        $lanPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lan8021xArtifact)
        Write-HeuristicDebug -Source 'Network' -Message 'Evaluating lan-8021x payload' -Data ([ordered]@{
            HasPayload = [bool]$lanPayload
        })

        if (-not $lanPayload) {
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Wired 802.1X diagnostics returned no payload, so port authentication posture is unknown.' -Subcategory $wiredSubcategory
        } elseif ($lanPayload.PSObject.Properties['Error'] -and $lanPayload.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Wired 802.1X diagnostics unavailable, so port authentication posture is unknown.' -Evidence $lanPayload.Error -Subcategory $wiredSubcategory
        } else {
            $netshData = if ($lanPayload.PSObject.Properties['Netsh']) { $lanPayload.Netsh } else { $null }
            $interfaces = @()
            $interfaceError = $null
            if ($netshData -and $netshData.PSObject.Properties['Interfaces']) {
                $interfacesRaw = $netshData.Interfaces
                if ($interfacesRaw -is [pscustomobject] -and $interfacesRaw.PSObject.Properties['Error'] -and $interfacesRaw.Error) {
                    $interfaceError = if ($interfacesRaw.PSObject.Properties['Source'] -and $interfacesRaw.Source) { [string]$interfacesRaw.Source + ': ' + $interfacesRaw.Error } else { [string]$interfacesRaw.Error }
                } elseif ($interfacesRaw) {
                    $interfaceLines = if ($interfacesRaw.PSObject -and $interfacesRaw.PSObject.Properties['Lines']) { ConvertTo-Lan8021xLines $interfacesRaw.Lines } else { ConvertTo-Lan8021xLines $interfacesRaw }
                    $interfaces = ConvertTo-Lan8021xInterfaceRecords -Lines $interfaceLines
                }
            }

            $profiles = @()
            if ($netshData -and $netshData.PSObject.Properties['Profiles']) {
                $profilesRaw = $netshData.Profiles
                if ($profilesRaw -and -not ($profilesRaw -is [pscustomobject] -and $profilesRaw.PSObject.Properties['Error'] -and $profilesRaw.Error)) {
                    $profileLines = if ($profilesRaw.PSObject -and $profilesRaw.PSObject.Properties['Lines']) { ConvertTo-Lan8021xLines $profilesRaw.Lines } else { ConvertTo-Lan8021xLines $profilesRaw }
                    $profiles = ConvertTo-Lan8021xProfileRecords -Lines $profileLines
                }
            }

            $profileLookup = @{}
            foreach ($profile in $profiles) {
                if ($profile -and $profile.PSObject.Properties['Name'] -and $profile.Name) {
                    $nameKey = [string]$profile.Name
                    if (-not $profileLookup.ContainsKey($nameKey)) { $profileLookup[$nameKey] = $profile }
                }
            }

            if ($interfaceError) {
                Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'netsh failed to enumerate wired interfaces, so 802.1X status is unknown.' -Evidence $interfaceError -Subcategory $wiredSubcategory
            } elseif ($interfaces.Count -eq 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'No wired interfaces reported by netsh, so 802.1X status is unknown.' -Subcategory $wiredSubcategory
            } else {
                foreach ($interface in $interfaces) {
                    if (-not $interface) { continue }
                    $name = if ($interface.PSObject.Properties['Name']) { [string]$interface.Name } else { $null }

                    $evidence = [ordered]@{}
                    if ($name) { $evidence['Interface'] = $name }
                    if ($interface.PSObject.Properties['State'] -and $interface.State) { $evidence['State'] = [string]$interface.State }
                    if ($interface.PSObject.Properties['AuthenticationState'] -and $interface.AuthenticationState) { $evidence['AuthenticationState'] = [string]$interface.AuthenticationState }
                    if ($interface.PSObject.Properties['Profile'] -and $interface.Profile) { $evidence['Profile'] = [string]$interface.Profile }
                    if ($interface.PSObject.Properties['EapType'] -and $interface.EapType) { $evidence['EapType'] = [string]$interface.EapType }
                    if ($interface.PSObject.Properties['AuthenticationMethod'] -and $interface.AuthenticationMethod) { $evidence['AuthenticationMethod'] = [string]$interface.AuthenticationMethod }

                    $authState = if ($interface.PSObject.Properties['AuthenticationState']) { [string]$interface.AuthenticationState } else { $null }
                    if ($authState -and $authState -match '(?i)not\s+auth') {
                        $title = if ($name) { "Wired interface $name reports 'Not authenticated', so the device cannot reach the secured LAN." } else { "A wired interface reports 'Not authenticated', so the device cannot reach the secured LAN." }
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title $title -Evidence $evidence -Subcategory $wiredSubcategory
                    }

                    $guestValue = $null
                    foreach ($candidate in @($interface.GuestVlanId, $interface.GuestVlan)) {
                        if (-not $candidate) { continue }
                        $text = [string]$candidate
                        if (-not $text) { continue }
                        $trim = $text.Trim()
                        if (-not $trim) { continue }
                        if ($trim -match '(?i)(not\s+in\s+use|not\s+configured|disabled|none)') { continue }
                        $guestValue = $trim
                        break
                    }

                    if ($guestValue) {
                        $evidence['GuestVlan'] = $guestValue
                        $title = if ($name) { "Wired interface $name is using the guest VLAN ($guestValue), so the port has fallen back to an isolated network." } else { "A wired interface is using the guest VLAN ($guestValue), so the port has fallen back to an isolated network." }
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence $evidence -Subcategory $wiredSubcategory
                    }

                    $profileDetails = $null
                    if ($interface.PSObject.Properties['Profile'] -and $interface.Profile) {
                        $profileName = [string]$interface.Profile
                        if ($profileName -and $profileLookup.ContainsKey($profileName)) { $profileDetails = $profileLookup[$profileName] }
                    }

                    $msChapDetected = $false
                    if ($interface.PSObject.Properties['AuthenticationMethod'] -and $interface.AuthenticationMethod) {
                        if (Test-Lan8021xContainsMsChap -Values $interface.AuthenticationMethod) { $msChapDetected = $true }
                    }
                    if (-not $msChapDetected -and $interface.PSObject.Properties['EapType'] -and $interface.EapType) {
                        if (Test-Lan8021xContainsMsChap -Values $interface.EapType) { $msChapDetected = $true }
                    }
                    if (-not $msChapDetected -and $interface.PSObject.Properties['RawLines'] -and $interface.RawLines) {
                        if (Test-Lan8021xContainsMsChap -Values $interface.RawLines) { $msChapDetected = $true }
                    }
                    if (-not $msChapDetected -and $profileDetails) {
                        $profileValues = @()
                        foreach ($prop in @('AuthenticationMethod','AuthenticationMode','EapType','RawLines')) {
                            if ($profileDetails.PSObject.Properties[$prop]) { $profileValues += $profileDetails.$prop }
                        }
                        if ($profileValues.Count -gt 0 -and (Test-Lan8021xContainsMsChap -Values $profileValues)) { $msChapDetected = $true }
                    }

                    if ($msChapDetected) {
                        $title = if ($name) { "Wired interface $name relies on MSCHAPv2, so attackers can capture or crack the 802.1X credentials." } else { 'A wired interface relies on MSCHAPv2, so attackers can capture or crack the 802.1X credentials.' }
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title $title -Evidence $evidence -Subcategory $wiredSubcategory
                    }
                }
            }

            $machineCerts = @()
            $certError = $null
            if ($lanPayload.PSObject.Properties['Certificates'] -and $lanPayload.Certificates -and $lanPayload.Certificates.PSObject.Properties['Machine']) {
                $machinePayload = $lanPayload.Certificates.Machine
                if ($machinePayload -is [pscustomobject] -and $machinePayload.PSObject.Properties['Error'] -and $machinePayload.Error) {
                    $certError = if ($machinePayload.PSObject.Properties['Source'] -and $machinePayload.Source) { [string]$machinePayload.Source + ': ' + $machinePayload.Error } else { [string]$machinePayload.Error }
                } else {
                    $machineCerts = ConvertTo-Lan8021xCertificateRecords -Value $machinePayload
                }
            }

            if ($certError) {
                Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Machine certificate inventory failed, so 802.1X certificate health is unknown.' -Evidence $certError -Subcategory $wiredSubcategory
            } else {
                $nowUtc = (Get-Date).ToUniversalTime()
                $validCerts = @()
                foreach ($cert in $machineCerts) {
                    if (-not $cert) { continue }
                    if (-not $cert.HasPrivateKey) { continue }
                    if (-not $cert.ClientAuthCapable) { continue }
                    if ($cert.PSObject.Properties['NotAfter'] -and $cert.NotAfter) {
                        if ($cert.NotAfter -le $nowUtc) { continue }
                    } else {
                        continue
                    }
                    if ($cert.PSObject.Properties['NotBefore'] -and $cert.NotBefore -gt $nowUtc) { continue }
                    $validCerts += $cert
                }

                if ($validCerts.Count -eq 0) {
                    $evidence = [ordered]@{
                        CertificatesFound = $machineCerts.Count
                    }
                    if ($machineCerts.Count -gt 0) {
                        $evidence['FirstCertificate'] = if ($machineCerts[0].PSObject.Properties['Subject']) { [string]$machineCerts[0].Subject } else { 'n/a' }
                    }
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No valid machine certificate is installed, so wired 802.1X authentication cannot succeed.' -Evidence $evidence -Subcategory $wiredSubcategory
                } else {
                    foreach ($cert in $validCerts) {
                        if (-not $cert.PSObject.Properties['NotAfter'] -or -not $cert.NotAfter) { continue }
                        $remaining = $cert.NotAfter - $nowUtc
                        $daysRemaining = [math]::Ceiling($remaining.TotalDays)
                        if ($daysRemaining -lt 0) { continue }

                        $certEvidence = [ordered]@{}
                        if ($cert.PSObject.Properties['Subject'] -and $cert.Subject) { $certEvidence['Subject'] = [string]$cert.Subject }
                        if ($cert.PSObject.Properties['Thumbprint'] -and $cert.Thumbprint) { $certEvidence['Thumbprint'] = [string]$cert.Thumbprint }
                        $certEvidence['ExpiresUtc'] = $cert.NotAfter.ToString('o')
                        if ($cert.EnhancedKeyUsageText -and $cert.EnhancedKeyUsageText.Count -gt 0) { $certEvidence['EnhancedKeyUsage'] = $cert.EnhancedKeyUsageText -join '; ' }

                        if ($remaining.TotalDays -le 7) {
                            $title = if ($cert.Subject) { "Machine certificate '$($cert.Subject)' expires in $daysRemaining day(s), so wired 802.1X will fail imminently without renewal." } else { 'A machine certificate expires within seven days, so wired 802.1X will fail imminently without renewal.' }
                            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title $title -Evidence $certEvidence -Subcategory $wiredSubcategory
                        } elseif ($remaining.TotalDays -le 30) {
                            $title = if ($cert.Subject) { "Machine certificate '$($cert.Subject)' expires in $daysRemaining day(s), so wired 802.1X will fail soon without renewal." } else { 'A machine certificate expires within thirty days, so wired 802.1X will fail soon without renewal.' }
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence $certEvidence -Subcategory $wiredSubcategory
                        }
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Wired 802.1X diagnostics not collected, so port authentication posture is unknown.' -Subcategory $wiredSubcategory
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
            Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Wireless diagnostics unavailable, so Wi-Fi security posture is unknown.' -Evidence $wlanPayload.Error -Subcategory 'Security'
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
                Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Wireless interface inventory empty, so Wi-Fi security posture cannot be evaluated.' -Subcategory 'Security'
            } else {
                $connectedInterfaces = $interfaces | Where-Object { Test-WlanInterfaceConnected -Interface $_ }
                if ($connectedInterfaces.Count -eq 0) {
                    $interfaceSummaries = New-Object System.Collections.Generic.List[string]
                    foreach ($interface in $interfaces) {
                        $parts = New-Object System.Collections.Generic.List[string]
                        if ($interface.Name) { $parts.Add(('Name={0}' -f $interface.Name)) | Out-Null }
                        if ($interface.State) { $parts.Add(('State={0}' -f $interface.State)) | Out-Null }
                        if ($interface.Ssid) { $parts.Add(('SSID={0}' -f $interface.Ssid)) | Out-Null }
                        if ($interface.Bssid) { $parts.Add(('BSSID={0}' -f $interface.Bssid)) | Out-Null }
                        if ($parts.Count -eq 0) { $parts.Add('No interface details reported') | Out-Null }
                        $interfaceSummaries.Add($parts.ToArray() -join '; ') | Out-Null
                    }
                    if ($interfaceSummaries.Count -eq 0) { $interfaceSummaries.Add('No wireless interfaces returned by collector') | Out-Null }
                    $evidence = [ordered]@{
                        'netsh wlan show interfaces' = $interfaceSummaries.ToArray() -join ' | '
                    }
                    $remediation = 'Reconnect to the intended Wi-Fi network, then re-run wireless diagnostics after confirming "netsh wlan show interfaces" reports the adapter as connected.'
                    Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Not connected to Wi-Fi, so wireless encryption state is unknown.' -Evidence $evidence -Subcategory 'Security' -Remediation $remediation
                } else {
                    $primaryInterface = $connectedInterfaces | Select-Object -First 1

                    $profileName = $null
                    if ($primaryInterface.Profile) {
                        $profileName = [string]$primaryInterface.Profile
                    } elseif ($primaryInterface.Ssid) {
                        $profileName = [string]$primaryInterface.Ssid
                    }
                    $profileInfo = $null
                    if ($profileName) {
                        $profileInfo = $profiles | Where-Object { $_.Name -eq $profileName } | Select-Object -First 1
                    }
                    if (-not $profileInfo -and $profiles.Count -eq 1) { $profileInfo = $profiles[0] }

                    $authCandidates = New-Object System.Collections.Generic.List[string]
                    if ($primaryInterface.Authentication) { $authCandidates.Add([string]$primaryInterface.Authentication) | Out-Null }
                    if ($profileInfo -and $profileInfo.Authentication) { $authCandidates.Add([string]$profileInfo.Authentication) | Out-Null }
                    if ($profileInfo -and $profileInfo.AuthenticationFallback) { $authCandidates.Add([string]$profileInfo.AuthenticationFallback) | Out-Null }
                    $useOneX = $null
                    if ($profileInfo) { $useOneX = $profileInfo.UseOneX }
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

                    $ssid = $profileName
                    if ($primaryInterface.Ssid) { $ssid = [string]$primaryInterface.Ssid }
                    $authenticationText = $null
                    foreach ($candidate in $authCandidates) {
                        if ($candidate) { $authenticationText = $candidate; break }
                    }
                    if (-not $authenticationText -and $securityCategory) { $authenticationText = $securityCategory }

                    $cipherText = $null
                    if ($primaryInterface.Cipher) {
                        $cipherText = [string]$primaryInterface.Cipher
                    } elseif ($profileInfo -and $profileInfo.Encryption) {
                        $cipherText = $profileInfo.Encryption
                    }

                    $currentEncryptionMethod = 'unknown security'
                    if ($authenticationText -and $cipherText) {
                        $currentEncryptionMethod = '{0} / {1}' -f $authenticationText, $cipherText
                    } elseif ($authenticationText) {
                        $currentEncryptionMethod = $authenticationText
                    } elseif ($cipherText) {
                        $currentEncryptionMethod = $cipherText
                    }
                    $currentSecurityDisplay = 'the current security mode'
                    if ($currentEncryptionMethod -and $currentEncryptionMethod -ne 'unknown security') {
                        $currentSecurityDisplay = $currentEncryptionMethod
                    }

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

                    $passphraseMetrics = $null
                    $passphraseMetricsError = $null
                    if ($profileInfo) {
                        $passphraseMetrics = $profileInfo.PassphraseMetrics
                        $passphraseMetricsError = $profileInfo.PassphraseMetricsError
                    }

                    $subcategory = 'Security'

                    $apEvidence = $null
                    if ($apAuthValues.Count -gt 0) {
                        $apEvidence = ('netsh wlan show networks mode=bssid → Authentication={0}' -f ($apAuthValues -join ', '))
                    }

                    $pmfStatus = Get-WifiPmfStatus -Interface $primaryInterface -ProfileInfo $profileInfo
                    $wpsStatus = Get-WifiWpsStatus -Interface $primaryInterface -ProfileInfo $profileInfo

                    $cipherTokens = New-Object System.Collections.Generic.List[string]
                    foreach ($candidate in $cipherCandidates) {
                        if (-not $candidate) { continue }
                        $token = Normalize-WlanAuthToken $candidate
                        if ($token) { $cipherTokens.Add($token) | Out-Null }
                    }
                    $hasCcmp = ($cipherTokens | Where-Object { $_ -match 'CCMP' -or $_ -match 'AES' -or $_ -match 'GCMP' }).Count -gt 0
                    $hasGcmp = ($cipherTokens | Where-Object { $_ -match 'GCMP' }).Count -gt 0

                    $isWpa3Personal = ($securityCategory -eq 'WPA3Personal' -or $securityCategory -eq 'WPA3PersonalTransition')
                    $isWpa3Enterprise = ($securityCategory -eq 'WPA3Enterprise' -or $securityCategory -eq 'WPA3EnterpriseTransition' -or $securityCategory -eq 'WPA3Enterprise192')
                    $isEnterpriseSecurity = ($securityCategory -eq 'WPA2Enterprise' -or $isWpa3Enterprise)
                    $isPersonalPsk = $securityCategory -in 'WPA2Personal','WPA2PersonalTransition','WPA3Personal','WPA3PersonalTransition'

                    $transitionDetected = $false
                    if ($securityCategory -eq 'WPA3PersonalTransition' -or $securityCategory -eq 'WPA3EnterpriseTransition') { $transitionDetected = $true }
                    if (-not $transitionDetected -and $apSupportsWpa3 -and $apSupportsWpa2) { $transitionDetected = $true }

                    $encryptionGroup = 'WPA2-PSK'
                    $encryptionDisplay = 'WPA2-Personal'
                    if ($currentEncryptionMethod -ne 'unknown security') { $encryptionDisplay = $currentEncryptionMethod }
                    $encryptionRationale = 'Shared PSK controls access'

                    if ($securityCategory -eq 'Open') {
                        $encryptionGroup = 'Open/WEP/TKIP'
                        $encryptionDisplay = 'Open Network'
                        $encryptionRationale = 'No encryption in use'
                    } elseif ($securityCategory -eq 'WEP' -or $securityCategory -eq 'WPAPersonal' -or $tkipAllowed) {
                        $encryptionGroup = 'Open/WEP/TKIP'
                        $encryptionDisplay = 'WEP/TKIP'
                        $encryptionRationale = 'Legacy WEP/TKIP permitted'
                    } elseif ($isEnterpriseSecurity -and -not $isWpa3Enterprise) {
                        $encryptionGroup = 'WPA2-Enterprise'
                        $encryptionDisplay = 'WPA2-Enterprise'
                        $encryptionRationale = '802.1X/EAP controls access'
                    } elseif ($isWpa3Enterprise) {
                        $encryptionGroup = 'WPA3-Enterprise'
                        $encryptionDisplay = 'WPA3-Enterprise'
                        if ($securityCategory -eq 'WPA3Enterprise192') { $encryptionDisplay = 'WPA3-Enterprise (Suite-B 192)' }
                        $encryptionRationale = '802.1X with WPA3 crypto suites'
                    } elseif ($isWpa3Personal) {
                        $encryptionGroup = 'WPA3-Personal'
                        $encryptionDisplay = 'WPA3-Personal (SAE)'
                        if ($pmfStatus -eq 'Required') { $encryptionDisplay = 'WPA3-Personal (SAE, PMF required)' }
                        $encryptionRationale = 'SAE resists offline guessing'
                    } else {
                        $encryptionGroup = 'WPA2-PSK'
                        if ($hasGcmp) {
                            $encryptionDisplay = 'WPA2-Personal (GCMP)'
                        } elseif ($hasCcmp) {
                            $encryptionDisplay = 'WPA2-Personal (CCMP)'
                        } else {
                            $encryptionDisplay = 'WPA2-Personal'
                        }
                        $encryptionRationale = 'Shared PSK controls access'
                    }

                    $encryptionScore = switch ($encryptionGroup) {
                        'Open/WEP/TKIP'   { 4 }
                        'WPA2-PSK'        { 2 }
                        'WPA2-Enterprise' { 3 }
                        'WPA3-Personal'   { 3 }
                        'WPA3-Enterprise' { 4 }
                        default           { 2 }
                    }

                    $encryptionModifiers = New-Object System.Collections.Generic.List[string]
                    if ($transitionDetected) {
                        $encryptionScore = [math]::Max(1, $encryptionScore - 1)
                        $encryptionModifiers.Add('Transition mode allows WPA2 clients') | Out-Null
                    }
                    if ($pmfStatus -eq 'Optional' -or $pmfStatus -eq 'Disabled') {
                        $encryptionScore = [math]::Max(1, $encryptionScore - 1)
                        $encryptionModifiers.Add('PMF not enforced') | Out-Null
                    }
                    $wpsPenaltyApplies = ($encryptionGroup -in @('WPA2-PSK','WPA3-Personal'))
                    if ($wpsPenaltyApplies -and $wpsStatus -eq 'On') {
                        $encryptionScore = [math]::Max(1, $encryptionScore - 1)
                        $encryptionModifiers.Add('WPS enabled') | Out-Null
                    }

                    $entropyBits = 0.0
                    $entropyKnown = $false
                    $lengthValue = $null
                    $classesUsed = @()
                    $classesDescription = 'unknown character mix'
                    $patternReasons = New-Object System.Collections.Generic.List[string]
                    $patternPenaltyApplied = $false
                    $passphraseScore = 1
                    $passphraseRatingLabel = 'Weak'
                    $passphraseMetricsNote = $null

                    if ($isEnterpriseSecurity) {
                        $passphraseScore = 4
                        $passphraseRatingLabel = 'Very Strong'
                        $passphraseMetricsNote = '802.1X credentials'
                    } elseif ($encryptionGroup -eq 'Open/WEP/TKIP') {
                        $passphraseScore = 1
                        $passphraseRatingLabel = 'Weak'
                        $passphraseMetricsNote = 'No encryption'
                    } elseif ($passphraseMetrics) {
                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['EntropyBits']) {
                            try { $entropyBits = [double]$passphraseMetrics.EntropyBits; $entropyKnown = $true } catch { $entropyBits = 0.0 }
                        } elseif ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['EstimatedBits']) {
                            try { $entropyBits = [double]$passphraseMetrics.EstimatedBits; $entropyKnown = $true } catch { $entropyBits = 0.0 }
                        }

                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['Length']) {
                            try { $lengthValue = [int]$passphraseMetrics.Length } catch { $lengthValue = $null }
                        }

                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['CharacterClasses']) {
                            $classesUsed = ConvertTo-NetworkArray $passphraseMetrics.CharacterClasses
                        }
                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['CharacterClassesDescription'] -and $passphraseMetrics.CharacterClassesDescription) {
                            $classesDescription = [string]$passphraseMetrics.CharacterClassesDescription
                        } elseif ($classesUsed.Count -gt 0) {
                            $classesDescription = $classesUsed -join ', '
                        }

                        $entropyScore = 1
                        if ($entropyBits -ge 96) {
                            $entropyScore = 4
                        } elseif ($entropyBits -ge 72) {
                            $entropyScore = 3
                        } elseif ($entropyBits -ge 60) {
                            $entropyScore = 2
                        }
                        $passphraseScore = $entropyScore
                        $passphraseRatingLabel = @('Weak','Average','Strong','Very Strong')[$passphraseScore - 1]

                        $scoreSignals = @()
                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['Signals']) {
                            $scoreSignals = ConvertTo-NetworkArray $passphraseMetrics.Signals
                        }

                        $commonPassword = $false
                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['CommonPassword']) {
                            $commonPassword = ConvertTo-NetworkBoolean -Value $passphraseMetrics.CommonPassword
                        } elseif ($scoreSignals -contains 'Blocklisted') {
                            $commonPassword = $true
                        }
                        if ($commonPassword) { $patternReasons.Add('Common/compromised password detected') | Out-Null }

                        $hasSsidSubstring = $false
                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['HasSSIDSubstring']) {
                            $hasSsidSubstring = ConvertTo-NetworkBoolean -Value $passphraseMetrics.HasSSIDSubstring
                        }
                        if ($hasSsidSubstring) { $patternReasons.Add('Contains SSID/profile naming') | Out-Null }

                        foreach ($signal in $scoreSignals) {
                            if ($signal -match '(Dictionary|Sequence|Keyboard|Repeated)') {
                                $patternReasons.Add('Pattern heuristics flagged: {0}' -f $signal) | Out-Null
                            }
                        }

                        if ($passphraseMetrics.PSObject -and $passphraseMetrics.PSObject.Properties['CharacterClassesCount']) {
                            try {
                                $classesCount = [int]$passphraseMetrics.CharacterClassesCount
                                if ($classesCount -le 2 -and $lengthValue -ne $null -and $lengthValue -lt 16) {
                                    $patternReasons.Add('Limited character variety used') | Out-Null
                                }
                            } catch { }
                        }

                        if ($patternReasons.Count -gt 0) {
                            $patternPenaltyApplied = $true
                            $passphraseScore = [math]::Max(1, $passphraseScore - 1)
                            $passphraseRatingLabel = @('Weak','Average','Strong','Very Strong')[$passphraseScore - 1]
                        }
                    } elseif ($passphraseMetricsError) {
                        $passphraseScore = 1
                        $passphraseRatingLabel = 'Unknown'
                        $passphraseMetricsNote = $passphraseMetricsError
                    } else {
                        $passphraseScore = 1
                        $passphraseRatingLabel = 'Unknown'
                        $passphraseMetricsNote = 'No metrics collected'
                    }

                    $patternSummary = 'No - No pattern weaknesses detected'
                    if ($patternReasons.Count -gt 0) {
                        $patternSummary = 'Yes - ' + ($patternReasons.ToArray() -join '; ')
                    } elseif ($passphraseMetricsError) {
                        $patternSummary = 'No - scoring failed: ' + $passphraseMetricsError
                    }

                    $matrix = @{
                        'Open/WEP/TKIP'   = @('Critical','Critical','Critical','High')
                        'WPA2-PSK'        = @('High','High','Medium','Low')
                        'WPA2-Enterprise' = @('High','Medium','Low','Low')
                        'WPA3-Personal'   = @('High','Medium','Low','Low')
                        'WPA3-Enterprise' = @('Medium','Low','Low','Low')
                    }

                    $passphraseIndex = [math]::Min(4, [math]::Max(1, $passphraseScore)) - 1
                    $matrixResult = 'High'
                    if ($matrix.ContainsKey($encryptionGroup)) {
                        $matrixResult = $matrix[$encryptionGroup][$passphraseIndex]
                    }
                    $finalSeverity = $matrixResult

                    if ($transitionDetected) { $finalSeverity = Get-WifiSeverityWorsen $finalSeverity }
                    if ($pmfStatus -eq 'Optional' -or $pmfStatus -eq 'Disabled') { $finalSeverity = Get-WifiSeverityWorsen $finalSeverity }
                    if ($wpsPenaltyApplies -and $wpsStatus -eq 'On') { $finalSeverity = Get-WifiSeverityWorsen $finalSeverity }

                    $modifierNotes = New-Object System.Collections.Generic.List[string]
                    foreach ($item in $encryptionModifiers) { $modifierNotes.Add($item) | Out-Null }
                    if ($patternPenaltyApplied) { $modifierNotes.Add('Passphrase pattern penalty applied') | Out-Null }
                    if ($passphraseRatingLabel -eq 'Unknown' -and $passphraseMetricsNote) { $modifierNotes.Add('Passphrase metrics unavailable') | Out-Null }

                    $severityLower = switch ($finalSeverity) {
                        'Critical' { 'critical' }
                        'High'     { 'high' }
                        'Medium'   { 'medium' }
                        'Low'      { 'low' }
                        default    { 'medium' }
                    }

                    $passphraseTitleSegment = switch ($encryptionGroup) {
                        'Open/WEP/TKIP'   { if ($securityCategory -eq 'Open') { 'No Encryption' } else { 'Passphrase ' + $passphraseRatingLabel } }
                        'WPA2-Enterprise' { 'Passphrase N/A' }
                        'WPA3-Enterprise' { 'Passphrase N/A' }
                        default           { 'Passphrase ' + $passphraseRatingLabel }
                    }
                    if (-not $passphraseTitleSegment) { $passphraseTitleSegment = 'Passphrase ' + $passphraseRatingLabel }
                    $title = 'Wi-Fi: {0}; {1} → {2}' -f $encryptionDisplay, $passphraseTitleSegment, $finalSeverity

                    if ($entropyKnown) {
                        $entropyDisplay = [string]([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.0}' -f $entropyBits)
                    } else {
                        $entropyDisplay = '0.0'
                    }

                    if ($lengthValue -ne $null) {
                        $lengthDisplay = [string]$lengthValue
                    } else {
                        $lengthDisplay = '0'
                    }

                    $classesDisplay = $classesDescription
                    if ($classesUsed -and $classesUsed.Count -gt 0) {
                        $classesDisplay = $classesUsed -join ', '
                    }

                    $baseSummary = switch ($encryptionGroup) {
                        'Open/WEP/TKIP'   {
                            if ($securityCategory -eq 'Open') {
                                'Open Wi-Fi lets anyone nearby join and inspect traffic, so risk is Critical.'
                            } else {
                                'Legacy WEP/TKIP encryption is broken and enables rapid compromise, so risk is ' + $finalSeverity + '.'
                            }
                        }
                        'WPA2-Enterprise' {
                            'WPA2-Enterprise uses per-user 802.1X credentials, keeping risk ' + $finalSeverity + '.'
                        }
                        'WPA3-Enterprise' {
                            'WPA3-Enterprise applies strong 802.1X crypto, resulting in ' + $finalSeverity + ' risk.'
                        }
                        'WPA3-Personal'   {
                            if ($passphraseRatingLabel -eq 'Unknown') {
                                'WPA3-SAE resists offline guessing, but passphrase strength is unknown, so risk is ' + $finalSeverity + '.'
                            } else {
                                'WPA3-SAE resists offline guessing; the passphrase is ' + $passphraseRatingLabel + ' (' + $entropyDisplay + ' bits), so risk is ' + $finalSeverity + '.'
                            }
                        }
                        default {
                            if ($passphraseRatingLabel -eq 'Unknown') {
                                'WPA2-PSK allows offline guessing of captured handshakes, and passphrase strength is unknown, so risk is ' + $finalSeverity + '.'
                            } else {
                                'WPA2-PSK allows offline guessing of captured handshakes; the passphrase is ' + $passphraseRatingLabel + ' (' + $entropyDisplay + ' bits), so risk is ' + $finalSeverity + '.'
                            }
                        }
                    }
                    $summaryNotes = New-Object System.Collections.Generic.List[string]
                    if ($transitionDetected) { $summaryNotes.Add('Transition mode keeps downgrade paths open') | Out-Null }
                    if ($pmfStatus -eq 'Optional' -or $pmfStatus -eq 'Disabled') { $summaryNotes.Add('PMF is not enforced, enabling deauth/disassoc abuse') | Out-Null }
                    if ($wpsPenaltyApplies -and $wpsStatus -eq 'On') { $summaryNotes.Add('WPS enabled invites PIN brute-force attacks') | Out-Null }
                    if ($patternPenaltyApplied) { $summaryNotes.Add('Detected patterns reduce effective passphrase strength') | Out-Null }
                    if ($passphraseMetricsError) { $summaryNotes.Add('Passphrase scoring failed (' + $passphraseMetricsError + ')') | Out-Null }

                    $summary = $baseSummary
                    if ($summaryNotes.Count -gt 0) {
                        $summary = $summary.TrimEnd('.')
                        $summary += '; ' + ($summaryNotes.ToArray() -join '; ') + '.'
                    }

                    $interfaceLines = New-Object System.Collections.Generic.List[string]
                    if ($ssid) { $interfaceLines.Add(('SSID: "{0}"' -f $ssid)) | Out-Null }
                    if ($authenticationText) { $interfaceLines.Add(('Authentication: {0}' -f $authenticationText)) | Out-Null }
                    if ($cipherText) { $interfaceLines.Add(('Cipher: {0}' -f $cipherText)) | Out-Null }
                    $interfaceLines.Add(('PMF: {0}' -f $pmfStatus)) | Out-Null

                    $apLines = New-Object System.Collections.Generic.List[string]
                    $apWpa3Text = 'No'
                    if ($apSupportsWpa3) { $apWpa3Text = 'Yes' }

                    $apWpa2Text = 'No'
                    if ($apSupportsWpa2) { $apWpa2Text = 'Yes' }

                    $transitionModeText = 'No'
                    if ($transitionDetected) { $transitionModeText = 'Yes' }
                    $apLines.Add(('WPA3 support: {0}' -f $apWpa3Text)) | Out-Null
                    $apLines.Add(('WPA2 support: {0}' -f $apWpa2Text)) | Out-Null
                    $apLines.Add(('Transition mode: {0}' -f $transitionModeText)) | Out-Null
                    $apLines.Add(('PMF policy: {0}' -f $pmfStatus)) | Out-Null

                    $clientLines = @('Actual method used: ' + $currentEncryptionMethod)

                    $passphraseLines = @(
                        'EntropyBits: ' + $entropyDisplay,
                        'Length: ' + $lengthDisplay,
                        'ClassesUsed: ' + $classesDisplay,
                        'PatternPenaltyApplied: ' + $patternSummary,
                        'FinalRating: ' + $passphraseRatingLabel
                    )
                    if ($passphraseMetricsNote) { $passphraseLines += ('Note: ' + $passphraseMetricsNote) }

                    $riskTransitionMode = 'Off'
                    if ($transitionDetected) { $riskTransitionMode = 'On' }
                    $riskModifierLines = @(
                        'WPS: ' + $wpsStatus,
                        'TransitionMode: ' + $riskTransitionMode,
                        'PMF: ' + $pmfStatus
                    )

                    $determinationLines = New-Object System.Collections.Generic.List[string]
                    $determinationLines.Add(('EncryptionScore (E): {0} ({1})' -f $encryptionScore, $encryptionRationale)) | Out-Null
                    $determinationLines.Add(('PassphraseScore (P): {0} ({1})' -f $passphraseScore, $passphraseRatingLabel)) | Out-Null
                    $modifierSummary = 'None'
                    if ($modifierNotes.Count -gt 0) { $modifierSummary = $modifierNotes.ToArray() -join '; ' }
                    $determinationLines.Add('Modifiers applied: ' + $modifierSummary) | Out-Null
                    $determinationLines.Add('MatrixResult: ' + $matrixResult) | Out-Null

                    $evidence = [ordered]@{
                        'Interface'              = $interfaceLines.ToArray()
                        'AP Capabilities (scan)' = $apLines.ToArray()
                        'Client Association'     = $clientLines
                        'Passphrase Metrics'     = $passphraseLines
                        'Risk Modifiers'         = $riskModifierLines
                        'Determination'          = $determinationLines.ToArray()
                    }
                    if ($profileEvidenceText) { $evidence['Profile'] = $profileEvidenceText }
                    if ($apEvidence) { $evidence['AccessPoint'] = $apEvidence }

                    $wpsBool = $null
                    if ($wpsStatus -eq 'On') { $wpsBool = $true } elseif ($wpsStatus -eq 'Off') { $wpsBool = $false }

                    $passphraseLengthNumeric = 0
                    if ($lengthValue -ne $null) { $passphraseLengthNumeric = [int]$lengthValue }

                    $passphraseClassesArray = @()
                    if ($classesUsed) { $passphraseClassesArray = @($classesUsed) }

                    $data = [ordered]@{
                        Category                    = 'Network/Security'
                        Subcategory                 = 'Wi-Fi'
                        SSID                        = $ssid
                        SecurityMethod              = $encryptionDisplay
                        Cipher                      = $cipherText
                        PMF                         = $pmfStatus
                        TransitionMode              = [bool]$transitionDetected
                        WPS                         = $wpsBool
                        'Passphrase.EntropyBits'    = [double]$entropyBits
                        'Passphrase.Length'         = $passphraseLengthNumeric
                        'Passphrase.Classes'        = $passphraseClassesArray
                        'Passphrase.PatternPenalty' = [bool]$patternPenaltyApplied
                        'Passphrase.FinalRating'    = $passphraseRatingLabel
                        'Scores.E'                  = [int]$encryptionScore
                        'Scores.P'                  = [int]$passphraseScore
                        Severity                    = $finalSeverity
                    }
                    if (-not $data['Cipher']) {
                        if ($cipherText) { $data['Cipher'] = $cipherText } else { $data['Cipher'] = 'Unknown' }
                    }

                    $recommendations = 'Recommended Actions (priority order):' + "`n" + (@(
                        'Prefer WPA3-Personal (SAE) or WPA2/3-Enterprise (802.1X) with PMF Required.',
                        'If remaining on PSK: enforce >=16 truly random characters (target >=96-bit entropy), rotate PSK, disable WPS.',
                        'If transition mode is required for legacy, isolate legacy devices on a separate SSID/VLAN with stricter egress controls and plan a deprecation timeline.'
                    ) -join "`n")

                    Add-CategoryIssue -CategoryResult $result -Severity $severityLower -Title $title -Evidence $evidence -Subcategory $subcategory -Remediation $recommendations -Explanation $summary -Data $data
                    }
                }
            }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Wireless diagnostics not collected, so Wi-Fi security posture cannot be evaluated.' -Subcategory 'Security'
    }

    if ($interfaceEvidence) {
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

    $dhcpFolderPath = $null
    if ($dhcpFolder) { $dhcpFolderPath = $dhcpFolder }

    $dhcpFolderExists = $false
    if ($dhcpFolderPath) { $dhcpFolderExists = Test-Path -LiteralPath $dhcpFolderPath }

    $dhcpFileCount = 'n/a'
    if ($dhcpFolderExists) {
        $dhcpFileCount = (Get-ChildItem -Path $dhcpFolderPath -Filter 'dhcp-*.json' -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    Write-Host ("DHCP ENTRY: dhcpFolder={0} exists={1} files={2} keys={3}" -f $dhcpFolderPath,$dhcpFolderExists,$dhcpFileCount,($Context.Artifacts.Keys | Where-Object { $_ -like 'dhcp-*.json' } | Measure-Object).Count)
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
        $vpnName = $null
        if ($vpnCategory -and $vpnCategory.PSObject -and $vpnCategory.PSObject.Properties['Name']) {
            $vpnName = [string]$vpnCategory.Name
        }
        $connectivityContext.Vpn = @{
            Category = $vpnName
        }
        $categories.Add($vpnCategory) | Out-Null
    }

    if ($categories.Count -eq 1) {
        return $result
    }

    return $categories.ToArray()
}
