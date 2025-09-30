<#!
.SYNOPSIS
    Collects network adapter configuration, IP assignments, and operational state.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-AdapterConfigurations {
    try {
        return Get-NetAdapter -ErrorAction Stop | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, DriverInformation
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapter'
            Error  = $_.Exception.Message
        }
    }
}

function Convert-ToNetworkStringArray {
    param($Value)

    $results = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $addText = {
        param([string]$Text)

        if (-not $Text) { return }
        $trimmed = $Text.Trim()
        if (-not $trimmed) { return }
        if ($seen.Add($trimmed)) { $results.Add($trimmed) | Out-Null }
    }

    $addNetworkValue = $null
    $addNetworkValue = {
        param($InputValue)

        if ($null -eq $InputValue) { return }

        if ($InputValue -is [string]) {
            & $addText $InputValue
            return
        }

        if ($InputValue -is [ValueType]) {
            & $addText ($InputValue.ToString())
            return
        }

        if ($InputValue -is [System.Collections.IEnumerable] -and -not ($InputValue -is [string])) {
            foreach ($item in $InputValue) { & $addNetworkValue $item }
            return
        }

        foreach ($prop in 'IPAddress','IPv4Address','IPv6Address','Address','NextHop','ServerAddresses','DisplayValue','Value','Name') {
            if ($InputValue.PSObject.Properties[$prop]) {
                & $addNetworkValue $InputValue.$prop
                return
            }
        }

        & $addText ([string]$InputValue)
    }

    & $addNetworkValue $Value
    return $results.ToArray()
}

function Get-NetIPAssignments {
    try {
        $configurations = Get-NetIPConfiguration -ErrorAction Stop

        return $configurations | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias       = $_.InterfaceAlias
                InterfaceDescription = $_.InterfaceDescription
                IPv4Address          = Convert-ToNetworkStringArray -Value $_.IPv4Address
                IPv6Address          = Convert-ToNetworkStringArray -Value $_.IPv6Address
                DNSServer            = Convert-ToNetworkStringArray -Value $_.DNSServer
                IPv4DefaultGateway   = Convert-ToNetworkStringArray -Value $_.IPv4DefaultGateway
            }
        }
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetIPConfiguration'
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetworkAdapterState {
    try {
        return Get-NetAdapterAdvancedProperty -ErrorAction Stop | Select-Object Name, DisplayName, DisplayValue
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapterAdvancedProperty'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Adapters   = Get-AdapterConfigurations
        IPConfig   = Get-NetIPAssignments
        Properties = Get-NetworkAdapterState
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-adapters.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
