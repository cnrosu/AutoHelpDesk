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

function Get-BillboardDeviceSnapshot {
    $source = "Get-PnpDevice -FriendlyName '*Billboard*'"

    try {
        $devices = Get-PnpDevice -FriendlyName '*Billboard*' -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($device in @($devices)) {
            if (-not $device) { continue }

            $friendly = $null
            if ($device.PSObject.Properties['FriendlyName'] -and $device.FriendlyName) {
                $friendly = [string]$device.FriendlyName
            } elseif ($device.PSObject.Properties['Name'] -and $device.Name) {
                $friendly = [string]$device.Name
            }

            $instanceId = if ($device.PSObject.Properties['InstanceId'] -and $device.InstanceId) { [string]$device.InstanceId } else { $null }
            $className = if ($device.PSObject.Properties['Class'] -and $device.Class) { [string]$device.Class } else { $null }
            $manufacturer = if ($device.PSObject.Properties['Manufacturer'] -and $device.Manufacturer) { [string]$device.Manufacturer } else { $null }
            $status = if ($device.PSObject.Properties['Status'] -and $device.Status) { ([string]$device.Status).Trim() } else { $null }

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
                FriendlyName = $friendly
                InstanceId   = $instanceId
                Class        = $className
                Manufacturer = $manufacturer
                Status       = $status
                Present      = $presentValue
                ProblemCode  = $problemCode
            }) | Out-Null
        }

        return [pscustomobject]@{
            Source = $source
            Items  = $items.ToArray()
        }
    } catch {
        return [pscustomobject]@{
            Source = $source
            Error  = $_.Exception.Message
            Items  = @()
        }
    }
}

function Get-DockDeviceSnapshot {
    $source = "Get-PnpDevice -Class 'System','USB','Net' (dock filter)"

    try {
        $devices = Get-PnpDevice -Class 'System','USB','Net' -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]
        $keywords = @('dock','thunderbolt','usb4','router')

        foreach ($device in @($devices)) {
            if (-not $device) { continue }

            $friendly = $null
            if ($device.PSObject.Properties['FriendlyName'] -and $device.FriendlyName) {
                $friendly = [string]$device.FriendlyName
            } elseif ($device.PSObject.Properties['Name'] -and $device.Name) {
                $friendly = [string]$device.Name
            }

            $instanceId = if ($device.PSObject.Properties['InstanceId'] -and $device.InstanceId) { [string]$device.InstanceId } else { $null }
            $friendlySafe = if ($friendly) { $friendly } else { '' }
            $instanceSafe = if ($instanceId) { $instanceId } else { '' }
            $combined = "$friendlySafe $instanceSafe"

            $match = $false
            foreach ($keyword in $keywords) {
                if ($combined -and ($combined -match $keyword)) { $match = $true; break }
            }

            if (-not $match) { continue }

            $status = if ($device.PSObject.Properties['Status'] -and $device.Status) { ([string]$device.Status).Trim() } else { $null }
            $className = if ($device.PSObject.Properties['Class'] -and $device.Class) { [string]$device.Class } else { $null }

            $items.Add([pscustomobject]@{
                FriendlyName = $friendly
                InstanceId   = $instanceId
                Class        = $className
                Status       = $status
            }) | Out-Null
        }

        return [pscustomobject]@{
            Source = $source
            Items  = $items.ToArray()
        }
    } catch {
        return [pscustomobject]@{
            Source = $source
            Error  = $_.Exception.Message
            Items  = @()
        }
    }
}

function Get-MonitorConnectionSnapshot {
    $source = 'Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams'

    try {
        $instances = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($instance in @($instances)) {
            if (-not $instance) { continue }

            $instanceName = if ($instance.PSObject.Properties['InstanceName'] -and $instance.InstanceName) { [string]$instance.InstanceName } else { $null }
            $technology = $null
            if ($instance.PSObject.Properties['VideoOutputTechnology']) {
                try { $technology = [int64]$instance.VideoOutputTechnology } catch { $technology = $instance.VideoOutputTechnology }
            }

            $items.Add([pscustomobject]@{
                InstanceName          = $instanceName
                VideoOutputTechnology = $technology
            }) | Out-Null
        }

        return [pscustomobject]@{
            Source = $source
            Items  = $items.ToArray()
        }
    } catch {
        return [pscustomobject]@{
            Source = $source
            Error  = $_.Exception.Message
            Items  = @()
        }
    }
}

function Get-MonitorIdentitySnapshot {
    $source = 'Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID'

    try {
        $instances = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($instance in @($instances)) {
            if (-not $instance) { continue }

            $instanceName = if ($instance.PSObject.Properties['InstanceName'] -and $instance.InstanceName) { [string]$instance.InstanceName } else { $null }
            $manufacturer = $null
            $productCode = $null
            $serialNumber = $null

            if ($instance.PSObject.Properties['ManufacturerName']) { $manufacturer = $instance.ManufacturerName }
            if ($instance.PSObject.Properties['ProductCodeID']) { $productCode = $instance.ProductCodeID }
            if ($instance.PSObject.Properties['SerialNumberID']) { $serialNumber = $instance.SerialNumberID }

            $items.Add([pscustomobject]@{
                InstanceName    = $instanceName
                ManufacturerName = $manufacturer
                ProductCodeID    = $productCode
                SerialNumberID   = $serialNumber
            }) | Out-Null
        }

        return [pscustomobject]@{
            Source = $source
            Items  = $items.ToArray()
        }
    } catch {
        return [pscustomobject]@{
            Source = $source
            Error  = $_.Exception.Message
            Items  = @()
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        DriverQuery       = Get-DriverInventory
        PnpProblems       = Get-PnpProblemDevices
        BluetoothDevices  = Get-BluetoothDeviceSnapshot
        BluetoothService  = Get-BluetoothServiceSnapshot
        BillboardDevices  = Get-BillboardDeviceSnapshot
        DockDevices       = Get-DockDeviceSnapshot
        DisplayTransports = Get-MonitorConnectionSnapshot
        MonitorIdentities = Get-MonitorIdentitySnapshot
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'drivers.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
