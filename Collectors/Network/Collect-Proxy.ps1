<#!
.SYNOPSIS
    Collects proxy configuration for WinHTTP and Windows settings.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-WinHttpProxy {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'winhttp','show','proxy' -SourceLabel 'netsh winhttp'
}

function Get-InternetSettings {
    try {
        $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if (Test-Path -Path $path) {
            return Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
        }
        return $null
    } catch {
        return [PSCustomObject]@{
            Source = 'InternetSettings'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        WinHttp  = Get-WinHttpProxy
        Internet = Get-InternetSettings
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'proxy.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
