<#!
.SYNOPSIS
    Collects DNS diagnostic data including resolution tests and connectivity checks.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Test-DnsResolution {
    param(
        [string[]]$Names = @('www.microsoft.com','outlook.office365.com','autodiscover.outlook.com')
    )

    $results = @()
    foreach ($name in $Names) {
        try {
            $records = Resolve-DnsName -Name $name -ErrorAction Stop
            $results += [PSCustomObject]@{
                Name    = $name
                Success = $true
                Records = $records | Select-Object Name, Type, IPAddress
            }
        } catch {
            $results += [PSCustomObject]@{
                Name    = $name
                Success = $false
                Error   = $_.Exception.Message
            }
        }
    }
    return $results
}

function Trace-NetworkPath {
    param([string]$Target = 'outlook.office365.com')
    try {
        return tracert.exe $Target 2>$null
    } catch {
        return [PSCustomObject]@{
            Target = $Target
            Error  = $_.Exception.Message
        }
    }
}

function Test-Latency {
    param([string]$Target = '8.8.8.8')
    try {
        return Test-NetConnection -ComputerName $Target -WarningAction SilentlyContinue
    } catch {
        try {
            return ping.exe $Target 2>$null
        } catch {
            return [PSCustomObject]@{
                Target = $Target
                Error  = $_.Exception.Message
            }
        }
    }
}

function Resolve-AutodiscoverRecords {
    param(
        [string[]]$Domains = @('autodiscover', 'enterpriseenrollment', 'enterpriseregistration')
    )

    $results = @()
    foreach ($domain in $Domains) {
        try {
            $records = Resolve-DnsName -Type CNAME -Name "$domain.outlook.com" -ErrorAction Stop
            $results += [PSCustomObject]@{
                Query   = "$domain.outlook.com"
                Records = $records | Select-Object Name, Type, NameHost
            }
        } catch {
            $results += [PSCustomObject]@{
                Query = "$domain.outlook.com"
                Error = $_.Exception.Message
            }
        }
    }

    return $results
}

function Get-DnsClientServerInventory {
    try {
        return Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-DnsClientServerAddress'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DnsClientPolicies {
    try {
        return Get-DnsClient -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex, ConnectionSpecificSuffix, UseSuffixWhenRegistering, RegisterThisConnectionsAddress
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-DnsClient'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Resolution      = Test-DnsResolution
        Traceroute      = Trace-NetworkPath
        Latency         = Test-Latency
        Autodiscover    = Resolve-AutodiscoverRecords
        ClientServers   = Get-DnsClientServerInventory
        ClientPolicies  = Get-DnsClientPolicies
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'dns.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
