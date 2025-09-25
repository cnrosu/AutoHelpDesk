<#!
.SYNOPSIS
    Collects installed driver inventory with signing details.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-DriverInventory {
    try {
        $temp = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString() + '.txt')
        driverquery.exe /v /fo list > $temp
        $content = Get-Content -Path $temp -ErrorAction Stop
        Remove-Item -Path $temp -ErrorAction SilentlyContinue
        return $content
    } catch {
        return [PSCustomObject]@{
            Source = 'driverquery.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        DriverQuery = Get-DriverInventory
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'drivers.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
