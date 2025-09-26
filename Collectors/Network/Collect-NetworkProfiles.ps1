<#!
.SYNOPSIS
    Collects network connection profiles and domain membership status for heuristic analysis.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-NetworkConnectionProfiles {
    try {
        return Get-NetConnectionProfile -ErrorAction Stop | Select-Object Name, InterfaceAlias, NetworkCategory
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetConnectionProfile'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DomainMembershipStatus {
    try {
        return Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop | Select-Object PartOfDomain
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-CimInstance Win32_ComputerSystem'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        ConnectionProfiles = Get-NetworkConnectionProfiles
        ComputerSystem     = Get-DomainMembershipStatus
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-profiles.json' -Data $result -Depth 4
    Write-Output $outputPath
}

Invoke-Main
