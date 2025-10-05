<#!
.SYNOPSIS
    Collects core system inventory information including OS details and hardware metadata.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-SystemInfoText {
    try {
        $output = systeminfo.exe 2>$null
        return $output
    } catch {
        return [PSCustomObject]@{
            Source = 'systeminfo.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Get-OperatingSystemInventory {
    $os = Get-CollectorOperatingSystem

    if (Test-CollectorResultHasError -Value $os) {
        return $os
    }

    if (-not $os) { return $null }

    return $os | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, RegisteredUser, SerialNumber
}

function Get-ComputerSystemInventory {
    $system = Get-CollectorComputerSystem

    if (Test-CollectorResultHasError -Value $system) {
        return $system
    }

    if (-not $system) { return $null }

    return $system | Select-Object Manufacturer, Model, Domain, PartOfDomain, DomainRole, TotalPhysicalMemory, NumberOfLogicalProcessors, NumberOfProcessors
}

function Invoke-Main {
    $payload = [ordered]@{
        SystemInfoText = Get-SystemInfoText
        OperatingSystem = Get-OperatingSystemInventory
        ComputerSystem  = Get-ComputerSystemInventory
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'system.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
