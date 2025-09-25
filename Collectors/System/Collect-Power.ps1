<#!
.SYNOPSIS
    Collects power configuration including sleep state availability and fast startup settings.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-PowerStates {
    try {
        return powercfg.exe /a 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'powercfg /a'
            Error  = $_.Exception.Message
        }
    }
}

function Get-FastStartupConfig {
    try {
        $values = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop | Select-Object HiberbootEnabled, HibernateEnabled, HiberFileType
        return $values
    } catch {
        return [PSCustomObject]@{
            Source = 'Power Registry'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        SleepStates    = Get-PowerStates
        FastStartup    = Get-FastStartupConfig
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'power.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
