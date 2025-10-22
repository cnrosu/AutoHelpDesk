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
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $null = $items.Add($item)
        }
        return $items.ToArray()
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

    $profileCollectorRemediation = @'
Firewall Profile Collector / Data Missing

Treat this as a collection pre-req: rerun the collector from an elevated PowerShell session and confirm the Windows Firewall service (mpssvc) is running.

Baseline fix:

```powershell
Set-NetFirewallProfile -All -Enabled True
Get-Service mpssvc | Set-Service -StartupType Automatic
```
'@

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
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Firewall profile collector missing, so firewall enforcement is unknown until the firewall profile collector runs.' -Subcategory $subcategory -CheckId $collectorMissingCheckId -Remediation $profileCollectorRemediation
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    Write-HeuristicDebug -Source 'Network' -Message 'Evaluating firewall.profile payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
        UsingAggregateFallback = $usingFirewallAggregate
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Firewall profile data missing, so firewall enforcement is unknown.' -Subcategory $subcategory -CheckId $errorCheckId -Remediation $profileCollectorRemediation
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
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Firewall profile query failed, so firewall enforcement is unknown until the error is resolved.' -Evidence $payloadError -Subcategory $subcategory -CheckId $errorCheckId
        return
    }

    $profileEntries = ConvertTo-NetworkArray $profilesRaw
    Write-HeuristicDebug -Source 'Network' -Message 'Parsed firewall profile entries' -Data ([ordered]@{
        Count = $profileEntries.Count
    })

    if ($profileEntries.Count -eq 0) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Firewall profile data empty, so firewall enforcement is unknown.' -Subcategory $subcategory -CheckId $unparsedCheckId
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
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Firewall profile data could not be parsed, so firewall enforcement is unknown.' -Evidence $unparsedEvidence -Subcategory $subcategory -CheckId $unparsedCheckId
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
