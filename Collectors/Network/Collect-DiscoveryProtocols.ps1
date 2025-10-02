<#!
.SYNOPSIS
    Collects discovery protocol surface data including firewall rules, registry policies, connection profiles, and UDP listeners.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Test-DiscoveryPortMatch {
    param(
        [Parameter(Mandatory)]
        $PortValue,

        [Parameter(Mandatory)]
        [int[]]$TargetPorts
    )

    if ($null -eq $PortValue) { return $false }

    if ($PortValue -is [int]) {
        return ($TargetPorts -contains [int]$PortValue)
    }

    $values = @()
    if ($PortValue -is [string]) {
        $values = $PortValue -split ','
    } elseif ($PortValue -is [System.Collections.IEnumerable] -and -not ($PortValue -is [string])) {
        foreach ($item in $PortValue) {
            if ($item -ne $null) { $values += [string]$item }
        }
    } else {
        $values = @([string]$PortValue)
    }

    foreach ($value in $values) {
        $text = ($value | Out-String).Trim()
        if (-not $text) { continue }
        if ($text -eq 'Any' -or $text -eq '*') { continue }

        $range = [regex]::Match($text, '^(?<start>\d+)\s*-\s*(?<end>\d+)$')
        if ($range.Success) {
            $start = [int]$range.Groups['start'].Value
            $end = [int]$range.Groups['end'].Value
            foreach ($target in $TargetPorts) {
                if ($target -ge $start -and $target -le $end) { return $true }
            }
            continue
        }

        $number = $null
        if ([int]::TryParse($text, [ref]$number)) {
            if ($TargetPorts -contains $number) { return $true }
        }
    }

    return $false
}

function Get-DiscoveryFirewallRules {
    $targetPorts = @(137, 5353, 5355)
    $results = New-Object System.Collections.Generic.List[object]

    try {
        $rules = Get-NetFirewallRule -All -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetFirewallRule'
            Error  = $_.Exception.Message
        }
    }

    foreach ($rule in $rules) {
        try {
            $filters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        } catch {
            $results.Add([PSCustomObject]@{
                Source   = 'Get-NetFirewallPortFilter'
                RuleName = $rule.Name
                Error    = $_.Exception.Message
            }) | Out-Null
            continue
        }

        foreach ($filter in $filters) {
            if (-not $filter) { continue }

            $protocol = if ($filter.PSObject.Properties['Protocol']) { [string]$filter.Protocol } else { $null }
            if ($protocol -and $protocol -ne 'UDP' -and $protocol -ne 'Any') { continue }

            $localPort = $null
            if ($filter.PSObject.Properties['LocalPort']) { $localPort = $filter.LocalPort }
            if (-not (Test-DiscoveryPortMatch -PortValue $localPort -TargetPorts $targetPorts)) { continue }

            $results.Add([PSCustomObject]@{
                DisplayName = $rule.DisplayName
                Name        = $rule.Name
                Direction   = if ($rule.PSObject.Properties['Direction']) { [string]$rule.Direction } else { $null }
                Action      = if ($rule.PSObject.Properties['Action']) { [string]$rule.Action } else { $null }
                Enabled     = if ($rule.PSObject.Properties['Enabled']) { $rule.Enabled } else { $null }
                Profile     = if ($rule.PSObject.Properties['Profile']) { [string]$rule.Profile } else { $null }
                PolicyStore = if ($rule.PSObject.Properties['PolicyStoreSourceType']) { [string]$rule.PolicyStoreSourceType } else { $null }
                Protocol    = $protocol
                LocalPort   = $localPort
                RemotePort  = if ($filter.PSObject.Properties['RemotePort']) { $filter.RemotePort } else { $null }
            }) | Out-Null
        }
    }

    return $results
}

function Get-RegistryPolicyValues {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) { return $null }

    try {
        return Get-ItemProperty -Path $Path -ErrorAction Stop |
            Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
    } catch {
        return [PSCustomObject]@{
            Source = $Path
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetbtInterfaceState {
    $rootPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    if (-not (Test-Path -Path $rootPath)) { return @() }

    $interfaces = @()
    try {
        $interfaces = Get-ChildItem -Path $rootPath -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Source = $rootPath
            Error  = $_.Exception.Message
        }
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($item in $interfaces) {
        try {
            $values = Get-ItemProperty -Path $item.PSPath -ErrorAction Stop
            $netbios = $null
            if ($values.PSObject.Properties['NetbiosOptions']) { $netbios = $values.NetbiosOptions }
            $dhcpNetbios = $null
            if ($values.PSObject.Properties['DhcpNetbiosOptions']) { $dhcpNetbios = $values.DhcpNetbiosOptions }
            $guidText = $item.PSChildName
            $normalized = $guidText
            if ($normalized) {
                $normalized = $normalized -replace '^Tcpip_', ''
                $normalized = $normalized.Trim('{}')
            }

            $results.Add([PSCustomObject]@{
                InterfaceKey        = $item.PSChildName
                InterfaceGuid       = $normalized
                NetbiosOptions      = $netbios
                DhcpNetbiosOptions  = $dhcpNetbios
            }) | Out-Null
        } catch {
            $results.Add([PSCustomObject]@{
                InterfaceKey = $item.PSChildName
                Error        = $_.Exception.Message
            }) | Out-Null
        }
    }

    return $results
}

function Get-DiscoveryUdpListeners {
    $targetPorts = @(137, 5353, 5355)
    try {
        $listeners = Get-NetUDPEndpoint -ErrorAction Stop |
            Where-Object {
                if (-not $_) { return $false }
                $port = $null
                if ($_.PSObject.Properties['LocalPort']) { $port = $_.LocalPort }
                if ($port -is [int]) { return $targetPorts -contains $port }
                $parsed = $null
                if ([int]::TryParse([string]$port, [ref]$parsed)) {
                    return $targetPorts -contains $parsed
                }
                return $false
            }

        return $listeners | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime, LocalAddressInterfaceAlias
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetUDPEndpoint'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DiscoveryConnectionProfiles {
    try {
        return Get-NetConnectionProfile -ErrorAction Stop |
            Select-Object Name, InterfaceAlias, InterfaceIndex, InterfaceDescription, NetworkCategory, IPv4Connectivity, IPv6Connectivity
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetConnectionProfile'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DiscoveryAdapterMap {
    try {
        return Get-NetAdapter -ErrorAction Stop |
            Select-Object Name, InterfaceDescription, InterfaceGuid, Status
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapter'
            Error  = $_.Exception.Message
        }
    }
}

function Get-RegistryDiscoveryPolicies {
    $llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $nbnsPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\NetBT'

    return [ordered]@{
        Llmnr = Get-RegistryPolicyValues -Path $llmnrPath
        Nbns  = Get-RegistryPolicyValues -Path $nbnsPath
        Netbt = Get-NetbtInterfaceState
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        FirewallRules      = Get-DiscoveryFirewallRules
        Registry           = Get-RegistryDiscoveryPolicies
        UdpListeners       = Get-DiscoveryUdpListeners
        ConnectionProfiles = Get-DiscoveryConnectionProfiles
        AdapterGuids       = Get-DiscoveryAdapterMap
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'discovery-protocols.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
