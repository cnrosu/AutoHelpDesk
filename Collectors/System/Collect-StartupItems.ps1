<#!
.SYNOPSIS
    Collects startup program configuration from Win32_StartupCommand.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-StartupCommands {
    try {
        return Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop |
            Select-Object Name, Command, Description, Location, User, UserSID
    } catch {
        try {
            return Get-WmiObject -Class Win32_StartupCommand -ErrorAction Stop |
                Select-Object Name, Command, Description, Location, User, UserSID
        } catch {
            return [PSCustomObject]@{
                Source = 'Win32_StartupCommand'
                Error  = $_.Exception.Message
            }
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        StartupCommands = Get-StartupCommands
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'startup.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
