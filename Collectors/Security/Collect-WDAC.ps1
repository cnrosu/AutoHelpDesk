<#!
.SYNOPSIS
    Collects Windows Defender Application Control (WDAC) configuration data.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-DeviceGuardPolicy {
    try {
        $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        return $dg | Select-Object SecurityServicesRunning, SecurityServicesConfigured, RequiredSecurityProperties, AvailableSecurityProperties, Version
    } catch {
        return [PSCustomObject]@{
            Source = 'Win32_DeviceGuard'
            Error  = $_.Exception.Message
        }
    }
}

function Get-WdacRegistrySnapshot {
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy',
        'HKLM:\SYSTEM\CurrentControlSet\Control\CI'
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

function Get-SmartAppControlState {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartAppControl'
    try {
        if (-not (Test-Path -Path $path)) {
            return $null
        }

        $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
        return [ordered]@{
            Path   = $path
            Values = $values
        }
    } catch {
        return [ordered]@{
            Path  = $path
            Error = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        DeviceGuard       = Get-DeviceGuardPolicy
        Registry          = Get-WdacRegistrySnapshot
        SmartAppControl   = Get-SmartAppControlState
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'wdac.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
