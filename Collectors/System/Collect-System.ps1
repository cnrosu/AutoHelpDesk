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
    try {
        return Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, RegisteredUser, SerialNumber
    } catch {
        return [PSCustomObject]@{
            Source = 'Win32_OperatingSystem'
            Error  = $_.Exception.Message
        }
    }
}

function Get-ComputerSystemInventory {
    try {
        return Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop | Select-Object Manufacturer, Model, Domain, PartOfDomain, DomainRole, TotalPhysicalMemory, NumberOfLogicalProcessors, NumberOfProcessors
    } catch {
        return [PSCustomObject]@{
            Source = 'Win32_ComputerSystem'
            Error  = $_.Exception.Message
        }
    }
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
