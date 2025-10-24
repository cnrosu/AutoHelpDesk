<#!
.SYNOPSIS
    Collects Windows Firewall configuration and rules into a structured JSON artifact.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function ConvertTo-Array {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $items.Add($item) | Out-Null }
        return $items.ToArray()
    }

    return @($Value)
}

function Add-FirewallFilterLookupEntry {
    param(
        [hashtable]$Lookup,
        [string]$InstanceId,
        $Filters
    )

    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return }
    if (-not $Lookup.ContainsKey($InstanceId)) {
        $Lookup[$InstanceId] = [System.Collections.Generic.List[object]]::new()
    }

    $list = $Lookup[$InstanceId]
    foreach ($filter in (ConvertTo-Array $Filters)) {
        if ($null -eq $filter) { continue }
        $list.Add($filter) | Out-Null
    }
}

function Get-FirewallRuleInstanceId {
    param($Rule)

    if (-not $Rule) { return $null }

    foreach ($propertyName in @('InstanceID', 'InstanceId')) {
        if ($Rule.PSObject.Properties[$propertyName]) {
            $value = [string]$Rule.$propertyName
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
        }
    }

    return $null
}

function Get-FirewallRulePolicyStore {
    param($Rule)

    if (-not $Rule) { return $null }

    foreach ($propertyName in @('PolicyStoreSource', 'PolicyStore')) {
        if ($Rule.PSObject.Properties[$propertyName]) {
            $value = [string]$Rule.$propertyName
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
        }
    }

    return $null
}

function New-FirewallFilterLookup {
    param(
        [object[]]$Rules,
        [string]$CommandName
    )

    $lookup = @{}
    $failedStores = @{}
    $commandAvailable = $false
    $supportsPolicyStore = $false

    $command = $null
    try {
        $command = Get-Command -Name $CommandName -ErrorAction Stop
        $commandAvailable = $null -ne $command
    } catch {
        $command = $null
    }

    if (-not $command) {
        return [pscustomobject]@{
            Lookup              = $lookup
            FailedStores        = $failedStores
            CommandAvailable    = $commandAvailable
            SupportsPolicyStore = $supportsPolicyStore
        }
    }

    if ($command.Parameters.ContainsKey('PolicyStore')) {
        $supportsPolicyStore = $true
    }

    if (-not $supportsPolicyStore) {
        return [pscustomobject]@{
            Lookup              = $lookup
            FailedStores        = $failedStores
            CommandAvailable    = $commandAvailable
            SupportsPolicyStore = $supportsPolicyStore
        }
    }

    $stores = @{}
    foreach ($rule in (ConvertTo-Array $Rules)) {
        if (-not $rule) { continue }
        $store = Get-FirewallRulePolicyStore -Rule $rule
        if ([string]::IsNullOrWhiteSpace($store)) { continue }
        $stores[$store] = $true
    }

    foreach ($store in $stores.Keys) {
        try {
            $filters = & $CommandName -PolicyStore $store -ErrorAction Stop
        } catch {
            $failedStores[$store] = $true
            continue
        }

        foreach ($filter in (ConvertTo-Array $filters)) {
            if (-not $filter) { continue }
            if (-not $filter.PSObject.Properties['InstanceID']) { continue }
            $instanceId = [string]$filter.InstanceID
            if ([string]::IsNullOrWhiteSpace($instanceId)) { continue }
            Add-FirewallFilterLookupEntry -Lookup $lookup -InstanceId $instanceId -Filters $filter
        }
    }

    return [pscustomobject]@{
        Lookup              = $lookup
        FailedStores        = $failedStores
        CommandAvailable    = $commandAvailable
        SupportsPolicyStore = $supportsPolicyStore
    }
}

function Invoke-FirewallFilterQuery {
    param(
        $Rule,
        [string]$CommandName,
        [bool]$CommandAvailable
    )

    if (-not $CommandAvailable) { return $null }
    if (-not $Rule) { return $null }

    try {
        return & $CommandName -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-FirewallFiltersForRule {
    param(
        $Rule,
        [pscustomobject]$Resolver,
        [string]$CommandName
    )

    if (-not $Rule) { return $null }
    if (-not $Resolver) { return $null }

    $instanceId = Get-FirewallRuleInstanceId -Rule $Rule
    if ($instanceId -and $Resolver.Lookup.ContainsKey($instanceId)) {
        $filters = $Resolver.Lookup[$instanceId]
        return ConvertTo-Array $filters
    }

    if (-not $Resolver.CommandAvailable) { return $null }

    if (-not $Resolver.SupportsPolicyStore) {
        $fallback = Invoke-FirewallFilterQuery -Rule $Rule -CommandName $CommandName -CommandAvailable $Resolver.CommandAvailable
        if ($fallback -and $instanceId) {
            Add-FirewallFilterLookupEntry -Lookup $Resolver.Lookup -InstanceId $instanceId -Filters $fallback
        }
        return $fallback
    }

    $store = Get-FirewallRulePolicyStore -Rule $Rule
    if ([string]::IsNullOrWhiteSpace($store) -or $Resolver.FailedStores.ContainsKey($store)) {
        $fallback = Invoke-FirewallFilterQuery -Rule $Rule -CommandName $CommandName -CommandAvailable $Resolver.CommandAvailable
        if ($fallback -and $instanceId) {
            Add-FirewallFilterLookupEntry -Lookup $Resolver.Lookup -InstanceId $instanceId -Filters $fallback
        }
        return $fallback
    }

    return $null
}

function ConvertTo-StringArray {
    param($Value)

    $strings = [System.Collections.Generic.List[string]]::new()

    foreach ($item in (ConvertTo-Array $Value)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $strings.Add($text.Trim()) | Out-Null
    }

    return $strings.ToArray()
}

function Merge-FirewallFilterValues {
    param(
        $Filter,
        [string]$PropertyName
    )

    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in (ConvertTo-Array $Filter)) {
        if (-not $entry) { continue }
        if (-not $entry.PSObject.Properties[$PropertyName]) { continue }

        foreach ($token in (ConvertTo-StringArray $entry.$PropertyName)) {
            if ($values.Contains($token)) { continue }
            $values.Add($token) | Out-Null
        }
    }

    if ($values.Count -eq 0) { return $null }
    if ($values.Count -eq 1) { return $values[0] }
    return $values.ToArray()
}

function Get-FirewallProfiles {
    try {
        return Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules
    } catch {
        Write-Verbose "Get-NetFirewallProfile failed: $($_.Exception.Message)"
        try {
            $raw = & netsh advfirewall show allprofiles 2>$null
            return [PSCustomObject]@{
                Source    = 'netsh'
                RawOutput = $raw -join [Environment]::NewLine
                Error     = $null
            }
        } catch {
            return [PSCustomObject]@{
                Source    = 'netsh'
                RawOutput = $null
                Error     = $_.Exception.Message
            }
        }
    }
}

function Get-FirewallRules {
    try {
        $rules = Get-NetFirewallRule -All -ErrorAction Stop
    } catch {
        Write-Verbose "Get-NetFirewallRule failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Source = 'Get-NetFirewallRule'
            Error  = $_.Exception.Message
        }
    }

    $portFilterResolver = New-FirewallFilterLookup -Rules $rules -CommandName 'Get-NetFirewallPortFilter'
    $addressFilterResolver = New-FirewallFilterLookup -Rules $rules -CommandName 'Get-NetFirewallAddressFilter'

    $result = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($rule in $rules) {
        if (-not $rule) { continue }

        $portFilter = Get-FirewallFiltersForRule -Rule $rule -Resolver $portFilterResolver -CommandName 'Get-NetFirewallPortFilter'
        $addressFilter = Get-FirewallFiltersForRule -Rule $rule -Resolver $addressFilterResolver -CommandName 'Get-NetFirewallAddressFilter'

        $protocol = Merge-FirewallFilterValues -Filter $portFilter -PropertyName 'Protocol'
        $localPort = Merge-FirewallFilterValues -Filter $portFilter -PropertyName 'LocalPort'
        $remotePort = Merge-FirewallFilterValues -Filter $portFilter -PropertyName 'RemotePort'

        $localAddressValues = [System.Collections.Generic.List[string]]::new()
        $remoteAddressValues = [System.Collections.Generic.List[string]]::new()

        foreach ($filter in (ConvertTo-Array $addressFilter)) {
            if (-not $filter) { continue }

            if ($filter.PSObject.Properties['LocalAddress']) {
                foreach ($value in (ConvertTo-StringArray $filter.LocalAddress)) {
                    if ($localAddressValues.Contains($value)) { continue }
                    $localAddressValues.Add($value) | Out-Null
                }
            }

            if ($filter.PSObject.Properties['RemoteAddress']) {
                foreach ($value in (ConvertTo-StringArray $filter.RemoteAddress)) {
                    if ($remoteAddressValues.Contains($value)) { continue }
                    $remoteAddressValues.Add($value) | Out-Null
                }
            }
        }

        $record = [ordered]@{
            Name         = if ($rule.PSObject.Properties['Name']) { [string]$rule.Name } else { $null }
            DisplayName  = if ($rule.PSObject.Properties['DisplayName']) { [string]$rule.DisplayName } else { $null }
            Direction    = if ($rule.PSObject.Properties['Direction']) { [string]$rule.Direction } else { $null }
            Action       = if ($rule.PSObject.Properties['Action']) { [string]$rule.Action } else { $null }
            Enabled      = if ($rule.PSObject.Properties['Enabled']) { $rule.Enabled } else { $null }
            Profile      = if ($rule.PSObject.Properties['Profile']) { [string]$rule.Profile } else { $null }
            PolicyStore  = if ($rule.PSObject.Properties['PolicyStoreSourceType']) { [string]$rule.PolicyStoreSourceType } else { $null }
            Program      = if ($rule.PSObject.Properties['Program']) { [string]$rule.Program } else { $null }
            Service      = if ($rule.PSObject.Properties['Service']) { [string]$rule.Service } else { $null }
            Group        = if ($rule.PSObject.Properties['DisplayGroup']) { [string]$rule.DisplayGroup } else { $null }
            Description  = if ($rule.PSObject.Properties['Description']) { [string]$rule.Description } else { $null }
            Protocol     = $protocol
            LocalPort    = $localPort
            RemotePort   = $remotePort
            LocalAddress = if ($localAddressValues.Count -gt 0) { $localAddressValues.ToArray() } else { $null }
            RemoteAddress = if ($remoteAddressValues.Count -gt 0) { $remoteAddressValues.ToArray() } else { $null }
        }

        $result.Add([pscustomobject]$record) | Out-Null
    }

    return $result.ToArray()
}

function Invoke-Main {
    $profiles = Get-FirewallProfiles
    $rules = Get-FirewallRules

    $payload = [ordered]@{
        Profiles = $profiles
        Rules    = $rules
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'firewall.json' -Data $result -Depth 6

    $profileResult = New-CollectorMetadata -Payload $profiles
    $profilePath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'firewall-profile.json' -Data $profileResult -Depth 6

    Write-Output $outputPath
    Write-Output $profilePath
}

Invoke-Main
