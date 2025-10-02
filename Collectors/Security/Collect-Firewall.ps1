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

    $result = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($rule in $rules) {
        if (-not $rule) { continue }

        $portFilter = $null
        $addressFilter = $null

        try {
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        } catch {
            $portFilter = $null
        }

        try {
            $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        } catch {
            $addressFilter = $null
        }

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
    $payload = [ordered]@{
        Profiles = Get-FirewallProfiles
        Rules    = Get-FirewallRules
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'firewall.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
