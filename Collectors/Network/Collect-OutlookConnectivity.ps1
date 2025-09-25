<#!
.SYNOPSIS
    Collects Outlook connectivity diagnostics including HTTPS tests, OST inventory, and Autodiscover SCP entries.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Test-Outlook443 {
    param([string]$Target = 'outlook.office365.com')
    try {
        return Test-NetConnection -ComputerName $Target -Port 443 -WarningAction SilentlyContinue
    } catch {
        return [PSCustomObject]@{
            Target = $Target
            Error  = $_.Exception.Message
        }
    }
}

function Get-OstInventory {
    try {
        $profilesPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Outlook'
        if (Test-Path -Path $profilesPath) {
            return Get-ChildItem -Path $profilesPath -Filter '*.ost' -Recurse -ErrorAction Stop | Select-Object Name, FullName, Length, LastWriteTime
        }
        return @()
    } catch {
        return [PSCustomObject]@{
            Source = 'OSTInventory'
            Error  = $_.Exception.Message
        }
    }
}

function Get-AutodiscoverScp {
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover'
        if (Test-Path -Path $regPath) {
            return Get-ItemProperty -Path $regPath | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
        }
        return $null
    } catch {
        return [PSCustomObject]@{
            Source = 'AutodiscoverSCP'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Connectivity = Test-Outlook443
        OstFiles     = Get-OstInventory
        Autodiscover = Get-AutodiscoverScp
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'outlook-connectivity.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
