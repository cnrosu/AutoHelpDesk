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

function Get-PnpProblemDevices {
    try {
        $temp = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString() + '.txt')
        pnputil.exe /enum-devices /problem > $temp
        $content = Get-Content -Path $temp -ErrorAction Stop
        Remove-Item -Path $temp -ErrorAction SilentlyContinue
        return $content
    } catch {
        return [PSCustomObject]@{
            Source = 'pnputil.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Get-BluetoothDeviceSnapshot {
    try {
        $devices = Get-PnpDevice -Class Bluetooth -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($device in $devices) {
            if (-not $device) { continue }

            $instanceId = if ($device.PSObject.Properties['InstanceId'] -and $device.InstanceId) { [string]$device.InstanceId } else { $null }
            $status = if ($device.PSObject.Properties['Status'] -and $device.Status) { ([string]$device.Status).Trim() } else { $null }
            $class = if ($device.PSObject.Properties['Class'] -and $device.Class) { [string]$device.Class } else { $null }
            $friendly = $null
            if ($device.PSObject.Properties['FriendlyName'] -and $device.FriendlyName) { $friendly = [string]$device.FriendlyName }
            elseif ($device.PSObject.Properties['Name'] -and $device.Name) { $friendly = [string]$device.Name }

            $presentValue = $null
            if ($device.PSObject.Properties['Present']) {
                try { $presentValue = [bool]$device.Present } catch { $presentValue = $null }
            }

            $problemCode = $null
            foreach ($property in @('ProblemCode','Problem')) {
                if ($device.PSObject.Properties[$property] -and $device.$property -ne $null -and $device.$property -ne '') {
                    try { $problemCode = [int]$device.$property } catch { $problemCode = [string]$device.$property }
                    break
                }
            }

            $items.Add([pscustomobject]@{
                InstanceId   = $instanceId
                Status       = $status
                Class        = $class
                FriendlyName = $friendly
                Present      = $presentValue
                ProblemCode  = $problemCode
            }) | Out-Null
        }

        return [pscustomobject]@{
            Source = 'Get-PnpDevice -Class Bluetooth'
            Items  = $items.ToArray()
        }
    } catch {
        return [pscustomobject]@{
            Source = 'Get-PnpDevice -Class Bluetooth'
            Error  = $_.Exception.Message
            Items  = @()
        }
    }
}

function Get-BluetoothServiceSnapshot {
    try {
        $service = Get-Service -Name 'bthserv' -ErrorAction Stop
        return [pscustomobject]@{
            Source      = 'Get-Service'
            Name        = 'bthserv'
            Status      = if ($service.Status) { ([string]$service.Status).Trim() } else { $null }
            DisplayName = if ($service.DisplayName) { [string]$service.DisplayName } else { $null }
            Exists      = $true
        }
    } catch [System.InvalidOperationException] {
        return [pscustomobject]@{
            Source = 'Get-Service'
            Name   = 'bthserv'
            Exists = $false
            Status = 'NotFound'
        }
    } catch {
        return [pscustomobject]@{
            Source = 'Get-Service'
            Name   = 'bthserv'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        DriverQuery       = Get-DriverInventory
        PnpProblems       = Get-PnpProblemDevices
        BluetoothDevices  = Get-BluetoothDeviceSnapshot
        BluetoothService  = Get-BluetoothServiceSnapshot
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'drivers.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
