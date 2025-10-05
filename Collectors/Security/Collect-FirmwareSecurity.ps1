<#!
.SYNOPSIS
    Collects firmware and chassis security metadata.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-ComputerSystemSecurity {
    $system = Get-CollectorComputerSystem

    if (Test-CollectorResultHasError -Value $system) {
        return $system
    }

    if (-not $system) { return $null }

    return $system | Select-Object Manufacturer, Model, Domain, PartOfDomain, NumberOfProcessors, TotalPhysicalMemory
}

function Get-BiosInformation {
    try {
        return Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop | Select-Object Manufacturer, Name, Version, SMBIOSBIOSVersion, SerialNumber, ReleaseDate
    } catch {
        return [PSCustomObject]@{
            Source = 'Win32_BIOS'
            Error  = $_.Exception.Message
        }
    }
}

function Get-SystemEnclosure {
    try {
        return Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop | Select-Object ChassisTypes, SecurityStatus, SerialNumber, SMBIOSAssetTag, LockPresent
    } catch {
        return [PSCustomObject]@{
            Source = 'Win32_SystemEnclosure'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        ComputerSystem = Get-ComputerSystemSecurity
        Bios           = Get-BiosInformation
        Enclosure      = Get-SystemEnclosure
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'firmware.json' -Data $result -Depth 5
    Write-Output $outputPath
}

Invoke-Main
