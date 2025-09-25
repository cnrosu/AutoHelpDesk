<#!
.SYNOPSIS
    Collects Windows service configuration and current state.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-ServiceMatrix {
    try {
        return Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, StartMode, State, Status, StartName, ServiceType
    } catch {
        try {
            return Get-Service | Select-Object Name, DisplayName, Status, StartType
        } catch {
            return [PSCustomObject]@{
                Source = 'ServiceQuery'
                Error  = $_.Exception.Message
            }
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Services = Get-ServiceMatrix
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'services.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
