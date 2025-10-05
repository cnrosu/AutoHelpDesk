<#!
.SYNOPSIS
    Collects device uptime details.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-Uptime {
    $os = Get-CollectorOperatingSystem

    if (Test-CollectorResultHasError -Value $os) {
        return $os
    }

    if (-not $os) { return $null }

    $lastBoot = $os.LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    return [PSCustomObject]@{
        LastBootUpTime = $lastBoot
        Uptime         = $uptime.ToString()
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Uptime = Get-Uptime
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'uptime.json' -Data $result -Depth 4
    Write-Output $outputPath
}

Invoke-Main
