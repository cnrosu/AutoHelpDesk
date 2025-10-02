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

function ConvertTo-StringArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $items.Add([string]$item) | Out-Null
        }
        return $items.ToArray()
    }

    return @([string]$Value)
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

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($rule in $rules) {
        if (-not $rule) { continue }

        $record = [ordered]@{
            DisplayName = $rule.DisplayName
            Direction   = $rule.Direction
            Action      = $rule.Action
            Enabled     = $rule.Enabled
            Profile     = $rule.Profile
            PolicyStore = $rule.PolicyStoreSourceType
            Program     = $rule.Program
            Service     = $rule.Service
            Group       = $rule.Group
            Description = $rule.Description
        }

        try {
            $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            if ($portFilters) {
                $serialized = [System.Collections.Generic.List[object]]::new()
                foreach ($filter in $portFilters) {
                    if (-not $filter) { continue }
                    $serialized.Add([ordered]@{
                        Protocol    = $filter.Protocol
                        LocalPort   = ConvertTo-StringArray $filter.LocalPort
                        RemotePort  = ConvertTo-StringArray $filter.RemotePort
                        IcmpType    = ConvertTo-StringArray $filter.IcmpType
                        DynamicTarget = $filter.DynamicTarget
                    }) | Out-Null
                }
                if ($serialized.Count -gt 0) {
                    $record['PortFilters'] = $serialized.ToArray()
                }
            }
        } catch {
            $record['PortFilterError'] = $_.Exception.Message
        }

        try {
            $addressFilters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            if ($addressFilters) {
                $serialized = [System.Collections.Generic.List[object]]::new()
                foreach ($filter in $addressFilters) {
                    if (-not $filter) { continue }
                    $serialized.Add([ordered]@{
                        LocalAddress  = ConvertTo-StringArray $filter.LocalAddress
                        RemoteAddress = ConvertTo-StringArray $filter.RemoteAddress
                    }) | Out-Null
                }
                if ($serialized.Count -gt 0) {
                    $record['AddressFilters'] = $serialized.ToArray()
                }
            }
        } catch {
            $record['AddressFilterError'] = $_.Exception.Message
        }

        $results.Add([PSCustomObject]$record) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        Profiles = Get-FirewallProfiles
        Rules    = Get-FirewallRules
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'firewall.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
