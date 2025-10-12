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

function Test-NetworkBroadcastIpv4Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $canonical = Get-NetworkCanonicalIpv4 $Address
    if (-not $canonical) { return $false }

    if ($canonical -eq '255.255.255.255') { return $true }

    return ($canonical -match '^\d+\.\d+\.\d+\.255$')
}

function Test-NetworkMulticastIpv4Address {
    param([string]$Address)

    if (-not $Address) { return $false }

    $canonical = Get-NetworkCanonicalIpv4 $Address
    if (-not $canonical) { return $false }

    $segments = $canonical.Split('.')
    if ($segments.Count -lt 1) { return $false }

    $firstOctet = $null
    if (-not [int]::TryParse($segments[0], [ref]$firstOctet)) { return $false }

    return ($firstOctet -ge 224 -and $firstOctet -le 239)
}

function Test-NetworkInvalidUnicastMac {
    param([string]$MacAddress)

    if ([string]::IsNullOrWhiteSpace($MacAddress)) { return $true }

    $normalized = Normalize-NetworkMacAddress $MacAddress
    if (-not $normalized) { return $true }

    return ($normalized -eq 'FF:FF:FF:FF:FF:FF' -or $normalized -eq '00:00:00:00:00:00')
}

function Test-NetworkStandardMulticastMac {
    param([string]$MacAddress)

    if ([string]::IsNullOrWhiteSpace($MacAddress)) { return $false }

    $normalized = Normalize-NetworkMacAddress $MacAddress
    if (-not $normalized) { return $false }

    return $normalized -like '01:00:5E:*'
}

function Get-NetworkCanonicalIpv6 {
    param([string]$Text)

    if (-not $Text) { return $null }

    $trimmed = $Text.Trim()
    if (-not $trimmed) { return $null }

    $clean = $trimmed -replace '/\d+$',''
    if ($clean -match '%') {
        $clean = $clean.Split('%')[0]
    }

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$parsed)) { return $null }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }

    return $parsed.ToString()
}

function Get-NetworkAliasKeys {
    param([string]$Alias)

    if (-not $Alias) { return @() }

    $set = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $ordered = New-Object System.Collections.Generic.List[string]

    $addKey = {
        param([string]$Key)
        if (-not $Key) { return }
        if ($set.Add($Key)) { $ordered.Add($Key) | Out-Null }
    }

    & $addKey $Alias

    $lower = $null
    try { $lower = $Alias.ToLowerInvariant() } catch { $lower = $Alias.ToLower() }
    & $addKey $lower

    $compact = if ($lower) { [regex]::Replace($lower, '[^a-z0-9]', '') } else { $null }
    & $addKey $compact

    $noSpaces = if ($lower) { [regex]::Replace($lower, '\s+', '') } else { $null }
    & $addKey $noSpaces

    return $ordered.ToArray()
}

function Normalize-NetworkInventoryText {
    param([string]$Text)

    if (-not $Text) { return $null }

    $trimmed = $Text.Trim()
    if (-not $trimmed) { return $null }

    $single = [regex]::Replace($trimmed, '\s+', ' ')

    try { return $single.ToUpperInvariant() } catch { return $single.ToUpper() }
}

function Get-NetworkObjectPropertyValue {
    param(
        [object]$InputObject,
        [string[]]$PropertyNames
    )

    if (-not $InputObject -or -not $PropertyNames) { return $null }

    foreach ($name in $PropertyNames) {
        if (-not $name) { continue }
        if ($InputObject.PSObject -and $InputObject.PSObject.Properties[$name]) {
            $value = $InputObject.$name
            if ($null -ne $value -and $value -ne '') { return $value }
        }
    }

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

function ConvertTo-Ipv6NeighborEntries {
    param($Value)

    $entries = New-Object System.Collections.Generic.List[pscustomobject]
    $lines = ConvertTo-NetworkArray $Value

    $currentInterfaceIndex = $null
    $currentInterfaceName = $null

    foreach ($rawLine in $lines) {
        if (-not $rawLine) { continue }

        $line = if ($rawLine -is [string]) { $rawLine } else { [string]$rawLine }
        if (-not $line) { continue }

        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        $interfaceMatch = [regex]::Match($trimmed, '^Interface\s+(\d+)\s*:\s*(.+)$')
        if ($interfaceMatch.Success) {
            $currentInterfaceIndex = $interfaceMatch.Groups[1].Value
            $currentInterfaceName = $interfaceMatch.Groups[2].Value.Trim()
            continue
        }

        if ($trimmed -match '^(Internet\s+Address|Address\s+Type)') { continue }
        if ($trimmed -match '^-{3,}') { continue }

        $segments = @($trimmed -split '\s{2,}' | Where-Object { $_ })
        if ($segments.Count -lt 2) {
            $segments = @($trimmed -split '\s+' | Where-Object { $_ })
        }

        if ($segments.Count -lt 2) { continue }

        $address = $segments[0].Trim()
        $physical = if ($segments.Count -ge 2) { $segments[1].Trim() } else { $null }
        $type = if ($segments.Count -ge 3) { $segments[2].Trim() } else { $null }

        $entries.Add([pscustomobject]@{
            InterfaceIndex   = $currentInterfaceIndex
            InterfaceName    = $currentInterfaceName
            Address          = $address
            CanonicalAddress = Get-NetworkCanonicalIpv6 $address
            PhysicalAddress  = $physical
            NormalizedMac    = Normalize-NetworkMacAddress $physical
            Type             = $type
        }) | Out-Null
    }

    return $entries.ToArray()
}

function ConvertTo-Ipv6RouterEntries {
    param($Value)

    $entries = New-Object System.Collections.Generic.List[pscustomobject]
    $lines = ConvertTo-NetworkArray $Value

    $currentInterfaceIndex = $null
    $currentInterfaceName = $null

    foreach ($rawLine in $lines) {
        if (-not $rawLine) { continue }

        $line = if ($rawLine -is [string]) { $rawLine } else { [string]$rawLine }
        if (-not $line) { continue }

        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        $interfaceMatch = [regex]::Match($trimmed, '^Interface\s+(\d+)\s*:\s*(.+)$')
        if ($interfaceMatch.Success) {
            $currentInterfaceIndex = $interfaceMatch.Groups[1].Value
            $currentInterfaceName = $interfaceMatch.Groups[2].Value.Trim()
            continue
        }

        if ($trimmed -match '^(Address\s+Type|Address\s+|Type\s+Preference)') { continue }
        if ($trimmed -match '^-{3,}') { continue }

        $segments = @($trimmed -split '\s{2,}' | Where-Object { $_ })
        if ($segments.Count -lt 2) {
            $segments = @($trimmed -split '\s+' | Where-Object { $_ })
        }

        if ($segments.Count -lt 2) { continue }

        $address = $segments[0].Trim()
        $type = if ($segments.Count -ge 2) { $segments[1].Trim() } else { $null }
        $preference = if ($segments.Count -ge 3) { $segments[2].Trim() } else { $null }
        $lifetime = if ($segments.Count -ge 4) { $segments[3].Trim() } else { $null }
        $state = if ($segments.Count -ge 5) { $segments[4].Trim() } else { $null }

        $entries.Add([pscustomobject]@{
            InterfaceIndex   = $currentInterfaceIndex
            InterfaceName    = $currentInterfaceName
            Address          = $address
            CanonicalAddress = Get-NetworkCanonicalIpv6 $address
            Type             = $type
            Preference       = $preference
            Lifetime         = $lifetime
            State            = $state
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

function Invoke-NetworkFirewallProfileAnalysis {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult
    )

    $subcategory = 'Windows Firewall'
    $collectorMissingCheckId = 'fw.collector.missing'
    $disabledCheckId = 'fw.profile.disabled'
    $enabledCheckId = 'fw.profile.enabled'
    $errorCheckId = 'fw.profile.error'
    $unparsedCheckId = 'fw.profile.unparsed'

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'firewall.profile'
    Write-HeuristicDebug -Source 'Network' -Message 'Resolved firewall.profile artifact' -Data ([ordered]@{
        Found = [bool]$artifact
    })

    $usingFirewallAggregate = $false
    if (-not $artifact) {
        $firewallAggregate = Get-AnalyzerArtifact -Context $Context -Name 'firewall'
        Write-HeuristicDebug -Source 'Network' -Message 'Resolved firewall aggregate artifact fallback' -Data ([ordered]@{
            Found = [bool]$firewallAggregate
        })

        if ($firewallAggregate) {
            $artifact = $firewallAggregate
            $usingFirewallAggregate = $true
        }
    }

    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Firewall profile collector missing, so firewall enforcement is unknown until the firewall profile collector runs.' -Subcategory $subcategory -CheckId $collectorMissingCheckId
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    Write-HeuristicDebug -Source 'Network' -Message 'Evaluating firewall.profile payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
        UsingAggregateFallback = $usingFirewallAggregate
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Firewall profile data missing, so firewall enforcement is unknown.' -Subcategory $subcategory -CheckId $errorCheckId
        return
    }

    $profilesRaw = $payload
    if ($payload.PSObject -and $payload.PSObject.Properties['Profiles']) {
        $profilesRaw = $payload.Profiles
    }

    $payloadError = $null
    if ($profilesRaw -and $profilesRaw.PSObject -and $profilesRaw.PSObject.Properties['Error'] -and $profilesRaw.Error) {
        $payloadError = [string]$profilesRaw.Error
    } elseif ($payload.PSObject -and $payload.PSObject.Properties['Error'] -and $payload.Error) {
        $payloadError = [string]$payload.Error
    }

    if ($payloadError) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Firewall profile query failed, so firewall enforcement is unknown until the error is resolved.' -Evidence $payloadError -Subcategory $subcategory -CheckId $errorCheckId
        return
    }

    $profileEntries = ConvertTo-NetworkArray $profilesRaw
    Write-HeuristicDebug -Source 'Network' -Message 'Parsed firewall profile entries' -Data ([ordered]@{
        Count = $profileEntries.Count
    })

    if ($profileEntries.Count -eq 0) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Firewall profile data empty, so firewall enforcement is unknown.' -Subcategory $subcategory -CheckId $unparsedCheckId
        return
    }

    $recognizedProfiles = New-Object System.Collections.Generic.List[pscustomobject]
    $disabledProfiles = New-Object System.Collections.Generic.List[string]
    $unparsedEntries = New-Object System.Collections.Generic.List[object]

    foreach ($profile in $profileEntries) {
        if (-not $profile) { continue }

        $hasNameProperty = ($profile.PSObject -and $profile.PSObject.Properties['Name'])
        if (-not $hasNameProperty) {
            $unparsedEntries.Add($profile) | Out-Null
            continue
        }

        $name = if ($profile.Name) { [string]$profile.Name } else { 'Profile' }

        $enabledState = $null
        if ($profile.PSObject.Properties['Enabled']) {
            $enabledValue = $profile.Enabled
            if ($enabledValue -is [bool]) {
                $enabledState = $enabledValue
            } elseif ($enabledValue -is [int]) {
                $enabledState = ($enabledValue -ne 0)
            } else {
                $enabledText = [string]$enabledValue
                if (-not [string]::IsNullOrWhiteSpace($enabledText)) {
                    $normalized = $enabledText.Trim()
                    try {
                        $normalized = $normalized.ToLowerInvariant()
                    } catch {
                        $normalized = $normalized.ToLower()
                    }

                    if ($normalized -in @('true', '1', 'enabled', 'on', 'yes')) {
                        $enabledState = $true
                    } elseif ($normalized -in @('false', '0', 'disabled', 'off', 'no')) {
                        $enabledState = $false
                    }
                }
            }
        }

        if ($enabledState -eq $false) {
            $disabledProfiles.Add($name) | Out-Null
        }

        $summary = [ordered]@{
            Name    = $name
            Enabled = if ($profile.PSObject.Properties['Enabled']) { $profile.Enabled } else { $null }
        }

        if ($profile.PSObject.Properties['DefaultInboundAction']) {
            $summary['DefaultInboundAction'] = [string]$profile.DefaultInboundAction
        }
        if ($profile.PSObject.Properties['DefaultOutboundAction']) {
            $summary['DefaultOutboundAction'] = [string]$profile.DefaultOutboundAction
        }
        if ($profile.PSObject.Properties['NotifyOnListen']) {
            $summary['NotifyOnListen'] = $profile.NotifyOnListen
        }
        if ($profile.PSObject.Properties['AllowInboundRules']) {
            $summary['AllowInboundRules'] = $profile.AllowInboundRules
        }
        if ($profile.PSObject.Properties['AllowLocalFirewallRules']) {
            $summary['AllowLocalFirewallRules'] = $profile.AllowLocalFirewallRules
        }
        if ($profile.PSObject.Properties['AllowLocalIPsecRules']) {
            $summary['AllowLocalIPsecRules'] = $profile.AllowLocalIPsecRules
        }

        $recognizedProfiles.Add([pscustomobject]$summary) | Out-Null
    }

    if ($recognizedProfiles.Count -eq 0) {
        $unparsedEvidence = if ($unparsedEntries.Count -gt 0) { $unparsedEntries.ToArray() } else { $profilesRaw }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Firewall profile data could not be parsed, so firewall enforcement is unknown.' -Evidence $unparsedEvidence -Subcategory $subcategory -CheckId $unparsedCheckId
        return
    }

    $evidence = [ordered]@{
        Profiles = $recognizedProfiles.ToArray()
        Artifact = $profilesRaw
    }

    if ($disabledProfiles.Count -gt 0) {
        $evidence['DisabledProfiles'] = $disabledProfiles.ToArray()
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'critical' -Title 'Windows Firewall is disabled for one or more profiles — the endpoint is unprotected from network attacks.' -Evidence $evidence -Subcategory $subcategory -CheckId $disabledCheckId
    } else {
        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'All firewall profiles enabled (Domain, Private, Public).' -Evidence $evidence -Subcategory $subcategory -CheckId $enabledCheckId
    }
}

function ConvertTo-LldpNeighborRecords {
    param($Payload)

    $records = New-Object System.Collections.Generic.List[pscustomobject]

    $entries = @()
    if ($Payload -and $Payload.PSObject.Properties['Neighbors']) {
        $entries = ConvertTo-NetworkArray $Payload.Neighbors
    }

    foreach ($entry in $entries) {
        if (-not $entry) { continue }

        $source = if ($entry.PSObject.Properties['Source']) { [string]$entry.Source } else { $null }
        if (-not $source) { $source = 'LLDP' }

        $alias = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('InterfaceAlias','Alias','Interface','InterfaceName','Name'))
        $localPort = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('LocalPortId','LocalInterface','LocalInterfaceId'))
        if (-not $alias -and $localPort) { $alias = $localPort }

        $interfaceDescription = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('InterfaceDescription','Description'))
        $localChassis = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('LocalChassisId','LocalMacAddress','LocalChassis'))
        $neighborChassis = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('NeighborChassisId','ChassisId','PeerChassisId'))
        $neighborSwitch = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('NeighborSystemName','SystemName','PeerSystemName'))
        $neighborSwitchDescription = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('NeighborSystemDescription','SystemDescription','PeerSystemDescription'))
        $neighborPortId = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('NeighborPortId','PortId','PeerPortId'))
        $neighborPortDescription = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('NeighborPortDescription','PortDescription','PeerPortDescription'))
        $neighborPortSubtype = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('NeighborPortIdSubtype','PortIdSubtype','PeerPortIdType'))
        $neighborTtl = [string](Get-NetworkObjectPropertyValue -InputObject $entry -PropertyNames @('NeighborTtl','Ttl'))

        $capabilityRaw = $null
        foreach ($name in @('NeighborCapabilities','Capabilities','Capability','PeerCapability')) {
            if ($entry.PSObject.Properties[$name]) { $capabilityRaw = $entry.$name; break }
        }
        $capabilities = Get-NetworkValueText $capabilityRaw

        $managementRaw = $null
        foreach ($name in @('NeighborManagementAddresses','ManagementAddresses','ManagementAddress','PeerManagementAddress')) {
            if ($entry.PSObject.Properties[$name]) { $managementRaw = $entry.$name; break }
        }
        $managementAddresses = Get-NetworkValueText $managementRaw

        $aliasSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        $aliasList = New-Object System.Collections.Generic.List[string]
        $addAliasKey = {
            param([string]$Text)
            if (-not $Text) { return }
            foreach ($key in (Get-NetworkAliasKeys $Text)) {
                if ($aliasSet.Add($key)) { $aliasList.Add($key) | Out-Null }
            }
        }

        & $addAliasKey $alias
        & $addAliasKey $localPort
        & $addAliasKey $interfaceDescription

        $observedLabelParts = New-Object System.Collections.Generic.List[string]
        if ($neighborSwitch) { $observedLabelParts.Add($neighborSwitch) | Out-Null }
        elseif ($neighborSwitchDescription) { $observedLabelParts.Add($neighborSwitchDescription) | Out-Null }
        if ($neighborPortId) { $observedLabelParts.Add($neighborPortId) | Out-Null }
        elseif ($neighborPortDescription) { $observedLabelParts.Add($neighborPortDescription) | Out-Null }
        $observedLabel = if ($observedLabelParts.Count -gt 0) { $observedLabelParts -join ' ' } else { $null }

        $record = [pscustomobject]@{
            Source                    = $source
            InterfaceAlias            = $alias
            InterfaceDescription      = $interfaceDescription
            AliasKeys                 = $aliasList.ToArray()
            LocalPortId               = $localPort
            LocalChassisId            = $localChassis
            NeighborChassisId         = $neighborChassis
            NeighborSystemName        = $neighborSwitch
            NeighborSystemDescription = $neighborSwitchDescription
            NeighborPortId            = $neighborPortId
            NeighborPortDescription   = $neighborPortDescription
            NeighborPortSubtype       = $neighborPortSubtype
            NeighborTtl               = $neighborTtl
            NeighborCapabilities      = $capabilities
            NeighborManagementAddresses = $managementAddresses
            ObservedLabel             = $observedLabel
            NormalizedSwitch          = Normalize-NetworkInventoryText $neighborSwitch
            NormalizedPort            = Normalize-NetworkInventoryText $neighborPortId
            NormalizedObservedLabel   = Normalize-NetworkInventoryText $observedLabel
            Raw                       = $entry
        }

        $records.Add($record) | Out-Null
    }

    return $records.ToArray()
}

function Get-NetworkSwitchPortExpectations {
    param($Context)

    $records = New-Object System.Collections.Generic.List[pscustomobject]
    $aliasLookup = @{}
    $sourcesUsed = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $addRecord = {
        param(
            [string]$AliasValue,
            [string]$SwitchValue,
            [string]$PortValue,
            [string]$LabelValue,
            [string]$SourceLabel,
            $RawValue
        )

        if (-not $AliasValue) { return }

        $aliasText = [string]$AliasValue

        $aliasSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        $aliasList = New-Object System.Collections.Generic.List[string]
        foreach ($key in (Get-NetworkAliasKeys $aliasText)) {
            if ($aliasSet.Add($key)) { $aliasList.Add($key) | Out-Null }
        }
        if ($aliasList.Count -eq 0) {
            $aliasList.Add($aliasText) | Out-Null
        }

        $primaryKey = $aliasList[0]
        if ($aliasLookup.ContainsKey($primaryKey)) { return }

        $displayLabel = $LabelValue
        if (-not $displayLabel) {
            $parts = New-Object System.Collections.Generic.List[string]
            if ($SwitchValue) { $parts.Add([string]$SwitchValue) | Out-Null }
            if ($PortValue) { $parts.Add([string]$PortValue) | Out-Null }
            if ($parts.Count -gt 0) { $displayLabel = ($parts -join ' ') }
        }

        $record = [pscustomobject]@{
            Alias            = $aliasText
            AliasKeys        = $aliasList.ToArray()
            ExpectedSwitch   = if ($SwitchValue) { [string]$SwitchValue } else { $null }
            ExpectedPort     = if ($PortValue) { [string]$PortValue } else { $null }
            ExpectedLabel    = if ($displayLabel) { [string]$displayLabel } else { $null }
            Source           = $SourceLabel
            Raw              = $RawValue
            NormalizedSwitch = Normalize-NetworkInventoryText $SwitchValue
            NormalizedPort   = Normalize-NetworkInventoryText $PortValue
            NormalizedLabel  = Normalize-NetworkInventoryText $displayLabel
        }

        $records.Add($record) | Out-Null

        foreach ($key in $aliasList) {
            if (-not $aliasLookup.ContainsKey($key)) { $aliasLookup[$key] = $record }
        }

        if ($SourceLabel) { $sourcesUsed.Add($SourceLabel) | Out-Null }
    }

    $extractFields = {
        param($Item)

        $aliasCandidate = $null
        $switchCandidate = $null
        $portCandidate = $null
        $labelCandidate = $null

        if ($Item -is [System.Collections.IDictionary]) {
            if ($Item.Contains('Alias')) { $aliasCandidate = [string]$Item['Alias'] }
            elseif ($Item.Contains('InterfaceAlias')) { $aliasCandidate = [string]$Item['InterfaceAlias'] }
            elseif ($Item.Contains('Interface')) { $aliasCandidate = [string]$Item['Interface'] }
            elseif ($Item.Contains('Adapter')) { $aliasCandidate = [string]$Item['Adapter'] }
            elseif ($Item.Contains('Name')) { $aliasCandidate = [string]$Item['Name'] }

            foreach ($name in @('Switch','SwitchName','ExpectedSwitch','Device','Chassis','ExpectedDevice','SwitchHost','SwitchHostname')) {
                if ($Item.Contains($name) -and $Item[$name]) { $switchCandidate = [string]$Item[$name]; break }
            }

            foreach ($name in @('Port','PortId','SwitchPort','ExpectedPort','Jack','PatchPort','PatchPanelPort','PortLabel')) {
                if ($Item.Contains($name) -and $Item[$name]) { $portCandidate = [string]$Item[$name]; break }
            }

            foreach ($name in @('Label','ExpectedLabel','DocumentedPort','Expected','Display','Location','FullLabel','Notes')) {
                if ($Item.Contains($name) -and $Item[$name]) { $labelCandidate = [string]$Item[$name]; break }
            }
        } elseif ($Item.PSObject) {
            $aliasCandidate = [string](Get-NetworkObjectPropertyValue -InputObject $Item -PropertyNames @('Alias','InterfaceAlias','Interface','Adapter','Name'))
            $switchCandidate = [string](Get-NetworkObjectPropertyValue -InputObject $Item -PropertyNames @('Switch','SwitchName','ExpectedSwitch','Device','Chassis','ExpectedDevice','SwitchHost','SwitchHostname'))
            $portCandidate = [string](Get-NetworkObjectPropertyValue -InputObject $Item -PropertyNames @('Port','PortId','SwitchPort','ExpectedPort','Jack','PatchPort','PatchPanelPort','PortLabel'))
            $labelCandidate = [string](Get-NetworkObjectPropertyValue -InputObject $Item -PropertyNames @('Label','ExpectedLabel','DocumentedPort','Expected','Display','Location','FullLabel','Notes'))
        } elseif ($Item -is [string]) {
            $labelCandidate = [string]$Item
        } elseif ($Item -is [ValueType]) {
            $labelCandidate = $Item.ToString()
        }

        return [pscustomobject]@{
            Alias = $aliasCandidate
            Switch = $switchCandidate
            Port = $portCandidate
            Label = $labelCandidate
        }
    }

    $addCandidate = {
        param([string]$SourceLabel, $Value)

        if ($null -eq $Value) { return }

        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) {
                $rawItem = $Value[$key]
                $fields = & $extractFields $rawItem
                $aliasText = if ($fields.Alias) { $fields.Alias } else { [string]$key }
                $label = $fields.Label
                if (-not $label -and $fields.Switch -and $fields.Port) { $label = ('{0} {1}' -f $fields.Switch, $fields.Port).Trim() }
                & $addRecord $aliasText $fields.Switch $fields.Port $label $SourceLabel $rawItem
            }
            return
        }

        $items = ConvertTo-NetworkArray $Value
        foreach ($item in $items) {
            if ($null -eq $item) { continue }

            $fields = & $extractFields $item
            $aliasText = $fields.Alias
            if (-not $aliasText) { continue }
            $label = $fields.Label
            if (-not $label -and $fields.Switch -and $fields.Port) { $label = ('{0} {1}' -f $fields.Switch, $fields.Port).Trim() }
            & $addRecord $aliasText $fields.Switch $fields.Port $label $SourceLabel $item
        }
    }

    if ($Context) {
        if ($Context.PSObject.Properties['SwitchPortInventory']) { & $addCandidate 'Context.SwitchPortInventory' $Context.SwitchPortInventory }
        if ($Context.PSObject.Properties['SwitchPorts']) { & $addCandidate 'Context.SwitchPorts' $Context.SwitchPorts }
        if ($Context.PSObject.Properties['ExpectedSwitchPorts']) { & $addCandidate 'Context.ExpectedSwitchPorts' $Context.ExpectedSwitchPorts }
        if ($Context.PSObject.Properties['NetworkSwitchPorts']) { & $addCandidate 'Context.NetworkSwitchPorts' $Context.NetworkSwitchPorts }

        if ($Context.PSObject.Properties['Inventory'] -and $Context.Inventory) {
            $inventory = $Context.Inventory
            if ($inventory.PSObject.Properties['SwitchPorts']) { & $addCandidate 'Context.Inventory.SwitchPorts' $inventory.SwitchPorts }
            if ($inventory.PSObject.Properties['PortExpectations']) { & $addCandidate 'Context.Inventory.PortExpectations' $inventory.PortExpectations }
            if ($inventory.PSObject.Properties['SwitchPortInventory']) { & $addCandidate 'Context.Inventory.SwitchPortInventory' $inventory.SwitchPortInventory }

            if ($inventory.PSObject.Properties['Network'] -and $inventory.Network) {
                $networkInventory = $inventory.Network
                if ($networkInventory.PSObject.Properties['SwitchPorts']) { & $addCandidate 'Context.Inventory.Network.SwitchPorts' $networkInventory.SwitchPorts }
                if ($networkInventory.PSObject.Properties['PortExpectations']) { & $addCandidate 'Context.Inventory.Network.PortExpectations' $networkInventory.PortExpectations }
                if ($networkInventory.PSObject.Properties['SwitchPortInventory']) { & $addCandidate 'Context.Inventory.Network.SwitchPortInventory' $networkInventory.SwitchPortInventory }
                if ($networkInventory.PSObject.Properties['ExpectedSwitchPorts']) { & $addCandidate 'Context.Inventory.Network.ExpectedSwitchPorts' $networkInventory.ExpectedSwitchPorts }
            }
        }
    }

    return [pscustomobject]@{
        Records = $records.ToArray()
        Map     = $aliasLookup
        Sources = if ($sourcesUsed.Count -gt 0) { [System.Linq.Enumerable]::ToArray($sourcesUsed) } else { @() }
        Count   = $records.Count
    }
}

function ConvertTo-Lan8021xLines {
    param($Value)

    $results = New-Object System.Collections.Generic.List[string]
    foreach ($item in (ConvertTo-NetworkArray $Value)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if ($null -eq $text) { continue }
        $results.Add($text) | Out-Null
    }

    return $results.ToArray()
}

function ConvertTo-Lan8021xInterfaceRecords {
    param([string[]]$Lines)

    if (-not $Lines) { return @() }

    $records = New-Object System.Collections.Generic.List[object]
    $current = $null
    $currentLines = $null

    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        $text = [string]$line
        if (-not $text) { continue }

        if ($text -match '^\s*Name\s*:\s*(.+)$') {
            if ($current) {
                if ($currentLines) { $current['RawLines'] = $currentLines.ToArray() }
                $records.Add([pscustomobject]$current) | Out-Null
            }

            $nameValue = $Matches[1].Trim()
            $current = [ordered]@{ Name = $nameValue }
            $currentLines = New-Object System.Collections.Generic.List[string]
            $currentLines.Add($text.TrimEnd()) | Out-Null
            continue
        }

        if (-not $current) { continue }
        if (-not $currentLines) { $currentLines = New-Object System.Collections.Generic.List[string] }
        $currentLines.Add($text.TrimEnd()) | Out-Null

        if ($text -match '^\s*([^:]+?)\s*:\s*(.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            if (-not $key) { continue }

            try { $keyLower = $key.ToLowerInvariant() } catch { $keyLower = $key }

            switch ($keyLower) {
                'description'           { $current['Description'] = $value }
                'state'                  { $current['State'] = $value }
                'authentication state'   { $current['AuthenticationState'] = $value }
                'authentication mode'    { $current['AuthenticationMode'] = $value }
                'authentication method'  { $current['AuthenticationMethod'] = $value }
                'eap type'               { $current['EapType'] = $value }
                '802.1x profile'         { $current['Profile'] = $value }
                'guest vlan'             { $current['GuestVlan'] = $value }
                'guest vlan id'          { $current['GuestVlanId'] = $value }
                'vlan'                   { if (-not $current.Contains('Vlan')) { $current['Vlan'] = $value } }
            }
        }
    }

    if ($current) {
        if ($currentLines) { $current['RawLines'] = $currentLines.ToArray() }
        $records.Add([pscustomobject]$current) | Out-Null
    }

    return $records.ToArray()
}

function ConvertTo-Lan8021xProfileRecords {
    param([string[]]$Lines)

    if (-not $Lines) { return @() }

    $records = New-Object System.Collections.Generic.List[object]
    $current = $null
    $currentLines = $null
    $currentInterface = $null

    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        $text = [string]$line
        if (-not $text) { continue }

        $trimmed = $text.Trim()
        if ($trimmed -match '^(?i)Profiles\s+on\s+interface\s+(.+?):\s*$') {
            $currentInterface = $Matches[1].Trim()
            continue
        }

        if ($trimmed -match '^(?i)Profile\s+name\s*:\s*(.+)$') {
            if ($current) {
                if ($currentLines) { $current['RawLines'] = $currentLines.ToArray() }
                $records.Add([pscustomobject]$current) | Out-Null
            }

            $nameValue = $Matches[1].Trim()
            $current = [ordered]@{ Name = $nameValue }
            if ($currentInterface) { $current['Interface'] = $currentInterface }
            $currentLines = New-Object System.Collections.Generic.List[string]
            $currentLines.Add($text.TrimEnd()) | Out-Null
            continue
        }

        if (-not $current) { continue }
        if (-not $currentLines) { $currentLines = New-Object System.Collections.Generic.List[string] }
        $currentLines.Add($text.TrimEnd()) | Out-Null

        if ($trimmed -match '^(?i)(Authentication(?:\s+mode|\s+method)?|EAP\s*type)\s*:\s*(.+)$') {
            $key = $Matches[1].ToLowerInvariant()
            $value = $Matches[2].Trim()
            switch ($key) {
                'authentication'        { $current['Authentication'] = $value }
                'authentication mode'   { $current['AuthenticationMode'] = $value }
                'authentication method' { $current['AuthenticationMethod'] = $value }
                'eap type'              { $current['EapType'] = $value }
            }
        }
    }

    if ($current) {
        if ($currentLines) { $current['RawLines'] = $currentLines.ToArray() }
        $records.Add([pscustomobject]$current) | Out-Null
    }

    return $records.ToArray()
}

function Test-Lan8021xContainsMsChap {
    param($Values)

    foreach ($item in (ConvertTo-NetworkArray $Values)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if (-not $text) { continue }
        if ($text -match '(?i)ms\s*-?chap\s*v?2') { return $true }
    }

    return $false
}

function ConvertTo-Lan8021xBoolean {
    param($Value)

    if ($Value -is [bool]) { return [bool]$Value }
    if ($null -eq $Value) { return $false }

    $text = [string]$Value
    if (-not $text) { return $false }

    $trim = $text.Trim()
    if (-not $trim) { return $false }

    return ($trim -match '^(?i)(true|yes|enabled|1)$')
}

function ConvertTo-Lan8021xDate {
    param([string]$Value)

    if (-not $Value) { return $null }

    try {
        return [datetime]::Parse($Value, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
    } catch {
        try { return [datetime]::Parse($Value) } catch { return $null }
    }
}

function ConvertTo-Lan8021xCertificateRecords {
    param($Value)

    $records = New-Object System.Collections.Generic.List[object]

    foreach ($item in (ConvertTo-NetworkArray $Value)) {
        if (-not $item) { continue }

        $subject = $null
        $thumbprint = $null
        $issuer = $null
        $notBefore = $null
        $notAfter = $null
        $hasPrivateKey = $false
        $ekuValues = @()

        if ($item.PSObject.Properties['Subject']) { $subject = [string]$item.Subject }
        if ($item.PSObject.Properties['Thumbprint']) { $thumbprint = [string]$item.Thumbprint }
        if ($item.PSObject.Properties['Issuer']) { $issuer = [string]$item.Issuer }
        if ($item.PSObject.Properties['NotBeforeUtc']) { $notBefore = ConvertTo-Lan8021xDate -Value $item.NotBeforeUtc }
        if (-not $notBefore -and $item.PSObject.Properties['NotBefore']) { $notBefore = ConvertTo-Lan8021xDate -Value $item.NotBefore }
        if ($item.PSObject.Properties['NotAfterUtc']) { $notAfter = ConvertTo-Lan8021xDate -Value $item.NotAfterUtc }
        if (-not $notAfter -and $item.PSObject.Properties['NotAfter']) { $notAfter = ConvertTo-Lan8021xDate -Value $item.NotAfter }
        if ($item.PSObject.Properties['HasPrivateKey']) { $hasPrivateKey = ConvertTo-Lan8021xBoolean -Value $item.HasPrivateKey }
        if ($item.PSObject.Properties['EnhancedKeyUsage']) { $ekuValues = ConvertTo-NetworkArray $item.EnhancedKeyUsage }

        $ekuText = New-Object System.Collections.Generic.List[string]
        $clientAuthCapable = $false

        foreach ($eku in $ekuValues) {
            if (-not $eku) { continue }
            $friendly = $null
            $oid = $null

            if ($eku.PSObject) {
                if ($eku.PSObject.Properties['FriendlyName']) { $friendly = [string]$eku.FriendlyName }
                if ($eku.PSObject.Properties['friendlyName']) { $friendly = [string]$eku.friendlyName }
                if ($eku.PSObject.Properties['Oid']) { $oid = [string]$eku.Oid }
                if ($eku.PSObject.Properties['oid']) { $oid = [string]$eku.oid }
            }

            if (-not $friendly) { $friendly = [string]$eku }
            if (-not $oid -and $eku.PSObject -and $eku.PSObject.Properties['Value']) { $oid = [string]$eku.Value }

            $display = $null
            if ($friendly -and $oid) { $display = ('{0} ({1})' -f $friendly, $oid) }
            elseif ($friendly) { $display = $friendly }
            elseif ($oid) { $display = $oid }
            else { $display = [string]$eku }

            if ($display) { $ekuText.Add($display) | Out-Null }

            if ($oid) {
                if ($oid -eq '1.3.6.1.5.5.7.3.2' -or $oid -eq '1.3.6.1.4.1.311.20.2.2' -or $oid -eq '1.3.6.1.5.2.3.4') {
                    $clientAuthCapable = $true
                }
            } elseif ($friendly -and $friendly -match '(?i)client\s+auth') {
                $clientAuthCapable = $true
            }
        }

        $records.Add([pscustomobject]@{
            Subject              = $subject
            Issuer               = $issuer
            Thumbprint           = $thumbprint
            NotBefore            = $notBefore
            NotAfter             = $notAfter
            HasPrivateKey        = $hasPrivateKey
            ClientAuthCapable    = $clientAuthCapable
            EnhancedKeyUsageText = $ekuText.ToArray()
            Raw                  = $item
        }) | Out-Null
    }

    return $records.ToArray()
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

function ConvertTo-NetworkBitsPerSecond {
    param([string]$Text)

    if (-not $Text) { return $null }

    $normalized = $Text.Trim()
    if (-not $normalized) { return $null }

    $normalized = $normalized -replace ',', ''

    if ($normalized -match '(?i)(disconnected|disabled|not\s+present|not\s+available|unavailable|no\s+link)') { return 0 }

    $speedMatch = [regex]::Match($normalized, '([0-9]+(?:\.[0-9]+)?)\s*(g|m|k)?\s*(?:b(?:it)?s?)(?:/s|ps)?', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($speedMatch.Success) {
        $value = [double]::Parse($speedMatch.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        $unit = $speedMatch.Groups[2].Value.ToLowerInvariant()
        switch ($unit) {
            'g' { $factor = 1000000000 }
            'm' { $factor = 1000000 }
            'k' { $factor = 1000 }
            default { $factor = 1 }
        }
        return [int64][math]::Round($value * $factor)
    }

    $wordMatch = [regex]::Match($normalized, '([0-9]+(?:\.[0-9]+)?)\s*(gigabit|megabit|kilobit)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($wordMatch.Success) {
        $value = [double]::Parse($wordMatch.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        switch ($wordMatch.Groups[2].Value.ToLowerInvariant()) {
            'gigabit' { $factor = 1000000000 }
            'megabit' { $factor = 1000000 }
            'kilobit' { $factor = 1000 }
            default { $factor = 1 }
        }
        return [int64][math]::Round($value * $factor)
    }

    $numericMatch = [regex]::Match($normalized, '^[0-9]+$')
    if ($numericMatch.Success) {
        return [int64]$numericMatch.Value
    }

    return $null
}

function ConvertTo-NetworkLinkSpeedMetrics {
    param([string]$Text)

    $bits = ConvertTo-NetworkBitsPerSecond -Text $Text
    $label = if ($Text) { $Text.Trim() } else { $null }

    return [pscustomobject]@{
        Text          = if ($label) { $label } else { $null }
        BitsPerSecond = $bits
    }
}

function ConvertTo-NetworkSpeedSetting {
    param([string]$Text)

    if (-not $Text) { return $null }

    $trimmed = $Text.Trim()
    if (-not $trimmed) { return $null }

    $bits = ConvertTo-NetworkBitsPerSecond -Text $trimmed
    $duplex = $null
    if ($trimmed -match '(?i)half') { $duplex = 'Half' }
    elseif ($trimmed -match '(?i)full') { $duplex = 'Full' }

    $mode = $null
    if ($trimmed -match '(?i)auto') { $mode = 'Auto' }

    return [pscustomobject]@{
        Text          = $trimmed
        BitsPerSecond = $bits
        Duplex        = $duplex
        Mode          = $mode
    }
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
                    IPv6Gateways = @()
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

            if ($entry.PSObject.Properties['IPv6DefaultGateway']) {
                foreach ($value in Get-NetworkValueText $entry.IPv6DefaultGateway) {
                    if (-not ($info.IPv6Gateways -contains $value)) { $info.IPv6Gateways += $value }
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
                IPv6Gateways = @()
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

function Get-NetworkAdapterLinkInventory {
    param($AdapterPayload)

    $map = @{}

    if ($AdapterPayload -and $AdapterPayload.Adapters -and -not $AdapterPayload.Adapters.Error) {
        $adapterEntries = ConvertTo-NetworkArray $AdapterPayload.Adapters
        foreach ($adapter in $adapterEntries) {
            if (-not $adapter) { continue }

            $alias = $null
            if ($adapter.PSObject.Properties['Name']) { $alias = [string]$adapter.Name }
            if (-not $alias -and $adapter.PSObject.Properties['InterfaceAlias']) { $alias = [string]$adapter.InterfaceAlias }
            if (-not $alias) { continue }

            try {
                $key = $alias.ToLowerInvariant()
            } catch {
                $key = $alias
            }

            $linkSpeedValue = if ($adapter.PSObject.Properties['LinkSpeed']) { [string]$adapter.LinkSpeed } else { $null }

            if (-not $map.ContainsKey($key)) {
                $map[$key] = [ordered]@{
                    Alias            = $alias
                    Description      = if ($adapter.PSObject.Properties['InterfaceDescription']) { [string]$adapter.InterfaceDescription } else { $null }
                    Status           = if ($adapter.PSObject.Properties['Status']) { [string]$adapter.Status } else { $null }
                    LinkSpeedText    = $linkSpeedValue
                    LinkSpeed        = ConvertTo-NetworkLinkSpeedMetrics $linkSpeedValue
                    DriverInformation = if ($adapter.PSObject.Properties['DriverInformation']) { [string]$adapter.DriverInformation } else { $null }
                    Properties       = New-Object System.Collections.Generic.List[object]
                    Key              = $key
                }
            } else {
                $info = $map[$key]
                if (-not $info.Description -and $adapter.PSObject.Properties['InterfaceDescription']) { $info.Description = [string]$adapter.InterfaceDescription }
                if (-not $info.Status -and $adapter.PSObject.Properties['Status']) { $info.Status = [string]$adapter.Status }
                if (-not $info.LinkSpeedText -and $adapter.PSObject.Properties['LinkSpeed']) {
                    $info.LinkSpeedText = $linkSpeedValue
                    $info.LinkSpeed = ConvertTo-NetworkLinkSpeedMetrics $linkSpeedValue
                }
                if (-not $info.DriverInformation -and $adapter.PSObject.Properties['DriverInformation']) { $info.DriverInformation = [string]$adapter.DriverInformation }
            }
        }
    }

    if ($AdapterPayload -and $AdapterPayload.Properties -and -not $AdapterPayload.Properties.Error) {
        $propertyEntries = ConvertTo-NetworkArray $AdapterPayload.Properties
        foreach ($property in $propertyEntries) {
            if (-not $property) { continue }

            $alias = if ($property.PSObject.Properties['Name']) { [string]$property.Name } else { $null }
            if (-not $alias) { continue }

            try {
                $key = $alias.ToLowerInvariant()
            } catch {
                $key = $alias
            }

            if (-not $map.ContainsKey($key)) {
                $map[$key] = [ordered]@{
                    Alias             = $alias
                    Description       = $null
                    Status            = $null
                    LinkSpeedText     = $null
                    LinkSpeed         = ConvertTo-NetworkLinkSpeedMetrics $null
                    DriverInformation = $null
                    Properties        = New-Object System.Collections.Generic.List[object]
                    Key               = $key
                }
            }

            $map[$key].Properties.Add($property) | Out-Null
        }
    }

    foreach ($key in @($map.Keys)) {
        $info = $map[$key]
        $properties = if ($info.Properties) { $info.Properties } else { @() }

        $speedProperty = $null
        foreach ($property in $properties) {
            $displayName = if ($property.PSObject.Properties['DisplayName']) { [string]$property.DisplayName } else { $null }
            if (-not $displayName) { continue }

            $normalized = $null
            try { $normalized = $displayName.ToLowerInvariant() } catch { $normalized = $displayName }

            if ($normalized -match 'speed' -and $normalized -match 'duplex') { $speedProperty = $property; break }
            if (-not $speedProperty -and $normalized -match 'duplex' -and $normalized -match 'mode') { $speedProperty = $property }
        }

        if (-not $speedProperty) {
            foreach ($property in $properties) {
                $values = Get-NetworkValueText ($property.PSObject.Properties['DisplayValue'] ? $property.DisplayValue : $null)
                if (($values | Where-Object { $_ -match '(?i)duplex' }).Count -gt 0) { $speedProperty = $property; break }
            }
        }

        $policyText = $null
        if ($speedProperty) {
            $valueTexts = Get-NetworkValueText ($speedProperty.PSObject.Properties['DisplayValue'] ? $speedProperty.DisplayValue : $null)
            if ($valueTexts.Count -gt 0) {
                $policyText = $valueTexts[0]
            } elseif ($speedProperty.PSObject.Properties['DisplayValue']) {
                $policyText = [string]$speedProperty.DisplayValue
            } elseif ($speedProperty.PSObject.Properties['Value']) {
                $valueTexts = Get-NetworkValueText $speedProperty.Value
                if ($valueTexts.Count -gt 0) { $policyText = $valueTexts[0] }
            }
        }

        $speedPolicy = if ($policyText) { ConvertTo-NetworkSpeedSetting $policyText } else { $null }

        $info.SpeedPolicy = $speedPolicy
        $info.SpeedPolicyText = $policyText
        $info.SpeedPolicyDisplayName = if ($speedProperty -and $speedProperty.PSObject.Properties['DisplayName']) { [string]$speedProperty.DisplayName } else { $null }

        if (-not $info.LinkSpeed) { $info.LinkSpeed = ConvertTo-NetworkLinkSpeedMetrics $info.LinkSpeedText }

        $isGigabitCapable = $false
        if ($speedPolicy -and $speedPolicy.BitsPerSecond -ge 1000000000) {
            $isGigabitCapable = $true
        } elseif ($info.LinkSpeed -and $info.LinkSpeed.BitsPerSecond -ge 1000000000) {
            $isGigabitCapable = $true
        } else {
            $capabilityTexts = @($info.Description, $info.DriverInformation, $policyText)
            foreach ($candidate in $capabilityTexts) {
                if (-not $candidate) { continue }
                if ($candidate -match '(?i)(gigabit|10/100/1000|\b1\s*g\b|1000base|gbe|gige|1\.0\s*g)') { $isGigabitCapable = $true; break }
                if ($candidate -match '(?i)1000\s*(mbps|megabit)') { $isGigabitCapable = $true; break }
            }
        }

        $info.IsGigabitCapable = $isGigabitCapable
    }

    return [pscustomobject]@{
        Map = $map
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
            $rawLines = New-Object System.Collections.Generic.List[string]
            $rawLines.Add($trimmed) | Out-Null
            $current = [pscustomobject]([ordered]@{
                Name     = $Matches[1].Trim()
                RawLines = $rawLines
            })
            $interfaces.Add($current) | Out-Null
            continue
        }

        if (-not $current) { continue }

        if ($current.PSObject.Properties['RawLines'] -and $current.RawLines) {
            $current.RawLines.Add($trimmed) | Out-Null
        }

        if ($trimmed -match '^([^:]+)\s*:\s*(.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()

            switch -Regex ($key) {
                '^Description$'        { $current | Add-Member -NotePropertyName 'Description' -NotePropertyValue $value -Force; continue }
                '^GUID$'               { $current | Add-Member -NotePropertyName 'Guid' -NotePropertyValue $value -Force; continue }
                '^Physical address$'   { $current | Add-Member -NotePropertyName 'Mac' -NotePropertyValue $value -Force; continue }
                '^State$'              { $current | Add-Member -NotePropertyName 'State' -NotePropertyValue $value -Force; continue }
                '^SSID(\s+name)?$'    { $current | Add-Member -NotePropertyName 'Ssid' -NotePropertyValue $value -Force; continue }
                '^BSSID(\s+\d+)?$'   { $current | Add-Member -NotePropertyName 'Bssid' -NotePropertyValue $value -Force; continue }
                '^Authentication$'     { $current | Add-Member -NotePropertyName 'Authentication' -NotePropertyValue $value -Force; continue }
                '^Cipher$'             { $current | Add-Member -NotePropertyName 'Cipher' -NotePropertyValue $value -Force; continue }
                '^Connection mode$'    { $current | Add-Member -NotePropertyName 'ConnectionMode' -NotePropertyValue $value -Force; continue }
                '^Radio type$'         { $current | Add-Member -NotePropertyName 'RadioType' -NotePropertyValue $value -Force; continue }
                '^Profile$'            { $current | Add-Member -NotePropertyName 'Profile' -NotePropertyValue $value -Force; continue }
            }
        }
    }

    foreach ($interface in $interfaces) {
        if ($interface -and $interface.PSObject.Properties['RawLines'] -and $interface.RawLines -is [System.Collections.IEnumerable]) {
            try {
                $interface.RawLines = @($interface.RawLines.ToArray())
            } catch {
                $interface.RawLines = @(ConvertTo-NetworkArray $interface.RawLines)
            }
        }
    }

    return $interfaces.ToArray()
}

function Test-WlanInterfaceConnected {
    param(
        [Parameter(Mandatory)]
        $Interface
    )

    if (-not $Interface) { return $false }

    $stateValues = New-Object System.Collections.Generic.List[string]

    if ($Interface.PSObject.Properties['State'] -and $Interface.State) {
        $stateValues.Add([string]$Interface.State) | Out-Null
    }

    if ($Interface.PSObject.Properties['RawLines'] -and $Interface.RawLines) {
        foreach ($rawLine in (ConvertTo-NetworkArray $Interface.RawLines)) {
            if (-not $rawLine) { continue }
            $text = [string]$rawLine
            if (-not $text) { continue }
            if ($text -match ':[\s]*(.+)$') {
                $stateValues.Add($Matches[1].Trim()) | Out-Null
            }
        }
    }

    $connectedPattern = '(?i)\b(connected|verbunden|conectad[oa]|connect[ée]|conness[oa]|collegat[oa]|ligad[oa]|verbonden|anslutet|ansluten|tilsluttet|tilkoblet|yhdistetty|připojeno|połączono|подключен(?:о|а)?|bağland[ıi]|bağl[ıi]|已连接|已連線|已連接|接続済み|연결됨|đã\s*kết\s*nối)\b'
    foreach ($candidate in $stateValues) {
        if ($candidate -and $candidate -match $connectedPattern) {
            return $true
        }
    }

    if ($Interface.PSObject.Properties['Ssid'] -and $Interface.Ssid) { return $true }
    if ($Interface.PSObject.Properties['Bssid'] -and $Interface.Bssid) { return $true }
    if ($Interface.PSObject.Properties['Profile'] -and $Interface.Profile) { return $true }
    if ($Interface.PSObject.Properties['Authentication'] -and $Interface.Authentication) { return $true }
    if ($Interface.PSObject.Properties['Cipher'] -and $Interface.Cipher) { return $true }

    return $false
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
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Network base diagnostics not collected, so connectivity failures may go undetected.' -Subcategory 'Collection' -Data (& $createConnectivityData $connectivityContext)
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
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'LLDP neighbors missing, so switch port documentation cannot be verified and mispatches may go unnoticed.' -Subcategory $lldpSubcategory
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

                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title ("Adapter {0} lacks LLDP neighbor data, so {1} cannot be verified and mispatches may go unnoticed." -f $alias, $expectedLabel) -Evidence $evidence -Subcategory $lldpSubcategory
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
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Switch port inventory missing, so LLDP data cannot confirm wiring and mispatches may linger.' -Subcategory $lldpSubcategory
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'LLDP collector missing, so switch port documentation cannot be verified and mispatches may go unnoticed.' -Subcategory $lldpSubcategory
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
            $autoErrors = $payload.Autodiscover | Where-Object { $_.Error }
            if ($autoErrors.Count -gt 0) {
                $details = $autoErrors | Select-Object -ExpandProperty Error -First 3
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Autodiscover DNS queries failed, so missing or invalid records can cause mail setup failures.' -Evidence ($details -join "`n") -Subcategory 'DNS Autodiscover' -Data (& $createConnectivityData $connectivityContext)
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
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to enumerate DNS servers, so name resolution may fail on domain devices.' -Evidence $entry.Error -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
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
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Adapters missing DNS servers: {0}, so name resolution may fail on domain devices.' -f ($missingInterfaces -join ', ')) -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
            }

            if ($ignoredPseudo.Count -gt 0) {
                $pseudoTitle = "Ignored {0} pseudo/virtual adapters (loopback/ICS/Hyper-V) without DNS — not used for normal name resolution." -f $ignoredPseudo.Count
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $pseudoTitle -Evidence ($ignoredPseudo -join ', ') -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
            }

            if ($publicServers.Count -gt 0) {
                $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                $unique = ($publicServers | Select-Object -Unique)
                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ('Public DNS servers detected: {0}, risking resolution failures on domain devices.' -f ($unique -join ', ')) -Evidence 'Prioritize internal DNS for domain services.' -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
            } elseif (-not $loopbackOnly) {
                Add-CategoryNormal -CategoryResult $result -Title 'Private DNS servers detected' -Subcategory 'DNS Client'
            }
        }

        if ($payload -and $payload.ClientPolicies) {
            $policies = ConvertTo-NetworkArray $payload.ClientPolicies
            foreach ($policy in $policies) {
                if ($policy -and $policy.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'DNS client policy query failed, so name resolution policy issues may be hidden and cause failures.' -Evidence $policy.Error -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
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
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("DNS registration disabled on {0}, so name resolution may fail on domain devices." -f $alias) -Evidence 'RegisterThisConnectionsAddress = False' -Subcategory 'DNS Client' -Data (& $createConnectivityData $connectivityContext)
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'DNS diagnostics not collected, so latency and name resolution issues may be missed.' -Subcategory 'DNS Resolution' -Data (& $createConnectivityData $connectivityContext)
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
                        $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'medium' } else { 'low' }
                        Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover for {0} targets {1}, so mail setup may fail for Exchange Online." -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.' -Subcategory 'Autodiscover DNS' -Data (& $createConnectivityData $connectivityContext)
                    }
                } elseif ($autoRecord.Success -eq $false) {
                    $severity = if ($computerSystem -and $computerSystem.PartOfDomain -eq $true) { 'high' } else { 'medium' }
                    $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ("Autodiscover lookup failed for {0}, so mail setup may fail." -f $domain) -Evidence $evidence -Subcategory 'Autodiscover DNS' -Data (& $createConnectivityData $connectivityContext)
                }

                foreach ($additional in ($lookups | Where-Object { $_.Label -ne 'Autodiscover' })) {
                    if (-not $additional) { continue }
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
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Wired 802.1X diagnostics returned no payload, so port authentication posture is unknown.' -Subcategory $wiredSubcategory
        } elseif ($lanPayload.PSObject.Properties['Error'] -and $lanPayload.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Wired 802.1X diagnostics unavailable, so port authentication posture is unknown.' -Evidence $lanPayload.Error -Subcategory $wiredSubcategory
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
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'netsh failed to enumerate wired interfaces, so 802.1X status is unknown.' -Evidence $interfaceError -Subcategory $wiredSubcategory
            } elseif ($interfaces.Count -eq 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'No wired interfaces reported by netsh, so 802.1X status is unknown.' -Subcategory $wiredSubcategory
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
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Machine certificate inventory failed, so 802.1X certificate health is unknown.' -Evidence $certError -Subcategory $wiredSubcategory
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
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Wired 802.1X diagnostics not collected, so port authentication posture is unknown.' -Subcategory $wiredSubcategory
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
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Not connected to Wi-Fi, so wireless encryption state is unknown.' -Evidence $evidence -Subcategory 'Security' -Remediation $remediation
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
