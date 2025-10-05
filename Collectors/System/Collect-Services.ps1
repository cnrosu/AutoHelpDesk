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
    $inventory = Get-CollectorServiceInventory

    if ($inventory.Errors -and $inventory.Errors.Count -gt 0) {
        Write-Verbose ("Service inventory warnings: {0}" -f ($inventory.Errors -join '; '))
    }

    if ($inventory.Items -and $inventory.Items.Count -gt 0) {
        return $inventory.Items | Select-Object Name, DisplayName, StartMode, State, Status, StartName, ServiceType
    }

    if ($inventory.Errors -and $inventory.Errors.Count -gt 0) {
        return [PSCustomObject]@{
            Source = if ($inventory.Source) { $inventory.Source } else { 'ServiceInventory' }
            Error  = ($inventory.Errors -join '; ')
        }
    }

    return @()
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
