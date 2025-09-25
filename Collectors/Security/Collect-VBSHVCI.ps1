<#!
.SYNOPSIS
    Collects virtualization-based security and HVCI configuration details.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-DeviceGuardState {
    try {
        $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        return $dg | Select-Object SecurityServicesRunning, SecurityServicesConfigured, RequiredSecurityProperties, AvailableSecurityProperties
    } catch {
        return [PSCustomObject]@{
            Source = 'Win32_DeviceGuard'
            Error  = $_.Exception.Message
        }
    }
}

function Get-WDACRegistry {
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\CI',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\SmartScreen'
    )

    $result = @()
    foreach ($path in $paths) {
        try {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
            $result += [PSCustomObject]@{
                Path   = $path
                Values = $values
            }
        } catch {
            $result += [PSCustomObject]@{
                Path  = $path
                Error = $_.Exception.Message
            }
        }
    }

    return $result
}

function Invoke-Main {
    $payload = [ordered]@{
        DeviceGuard = Get-DeviceGuardState
        Registry    = Get-WDACRegistry
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'vbshvci.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
