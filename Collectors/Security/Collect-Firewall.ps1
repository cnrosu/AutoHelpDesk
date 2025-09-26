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

function Get-FirewallRules {
    try {
        return Get-NetFirewallRule -All -ErrorAction Stop |
            Select-Object DisplayName, Direction, Action, Enabled, Profile, @{Name='PolicyStore';Expression={$_.PolicyStoreSourceType}}, Program, Service, Group, Description
    } catch {
        Write-Verbose "Get-NetFirewallRule failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Source = 'Get-NetFirewallRule'
            Error  = $_.Exception.Message
        }
    }
}

function Get-ConnectionProfiles {
    try {
        return Get-NetConnectionProfile -ErrorAction Stop |
            Select-Object Name, InterfaceAlias, NetworkCategory, DomainAuthenticationSucceeded
    } catch {
        Write-Verbose "Get-NetConnectionProfile failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Source = 'Get-NetConnectionProfile'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Profiles = Get-FirewallProfiles
        Rules    = Get-FirewallRules
        Connections = Get-ConnectionProfiles
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'firewall.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
