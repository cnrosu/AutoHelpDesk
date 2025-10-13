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

function ConvertTo-PnpDeviceRecord {
    param(
        [Parameter(Mandatory)]
        $Device
    )

    if (-not $Device) { return $null }

    $instanceId = if ($Device.PSObject.Properties['InstanceId'] -and $Device.InstanceId) { [string]$Device.InstanceId } else { $null }
    $status = if ($Device.PSObject.Properties['Status'] -and $Device.Status) { ([string]$Device.Status).Trim() } else { $null }
    $class = if ($Device.PSObject.Properties['Class'] -and $Device.Class) { [string]$Device.Class } else { $null }
    $friendly = $null
    if ($Device.PSObject.Properties['FriendlyName'] -and $Device.FriendlyName) { $friendly = [string]$Device.FriendlyName }
    elseif ($Device.PSObject.Properties['Name'] -and $Device.Name) { $friendly = [string]$Device.Name }

    $presentValue = $null
    if ($Device.PSObject.Properties['Present']) {
        try { $presentValue = [bool]$Device.Present } catch { $presentValue = $null }
    }

    $problemCode = $null
    foreach ($property in @('ProblemCode','Problem')) {
        if ($Device.PSObject.Properties[$property] -and $Device.$property -ne $null -and $Device.$property -ne '') {
            try { $problemCode = [int]$Device.$property } catch { $problemCode = [string]$Device.$property }
            break
        }
    }

    return [pscustomobject]@{
        InstanceId   = $instanceId
        Status       = $status
        Class        = $class
        FriendlyName = $friendly
        Present      = $presentValue
        ProblemCode  = $problemCode
    }
}

function Test-PnpDeviceMatch {
    param(
        [Parameter(Mandatory)]
        $Device,

        [Parameter(Mandatory)]
        [string[]]$Patterns
    )

    if (-not $Device) { return $false }
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }

    foreach ($property in @('FriendlyName','InstanceId','Name','Class','Manufacturer')) {
        if (-not $Device.PSObject.Properties[$property]) { continue }
        $value = $Device.$property
        if (-not $value) { continue }
        $text = [string]$value
        foreach ($pattern in $Patterns) {
            if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
            if ([System.Text.RegularExpressions.Regex]::IsMatch($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                return $true
            }
        }
    }

    return $false
}

function Get-BluetoothDeviceSnapshot {
    try {
        $devices = Get-PnpDevice -Class Bluetooth -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($device in $devices) {
            $record = ConvertTo-PnpDeviceRecord -Device $device
            if ($record) { $items.Add($record) | Out-Null }
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

function Get-ThunderboltDeviceSnapshot {
    try {
        $devices = Get-PnpDevice -PresentOnly -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($device in $devices) {
            if (-not (Test-PnpDeviceMatch -Device $device -Patterns @('thunderbolt', 'usb4'))) { continue }
            $record = ConvertTo-PnpDeviceRecord -Device $device
            if ($record) { $items.Add($record) | Out-Null }
        }

        return [pscustomobject]@{
            Source = 'Get-PnpDevice -PresentOnly (Thunderbolt filter)'
            Items  = $items.ToArray()
        }
    } catch {
        return [pscustomobject]@{
            Source = 'Get-PnpDevice -PresentOnly (Thunderbolt filter)'
            Error  = $_.Exception.Message
            Items  = @()
        }
    }
}

function Get-DisplayLinkDeviceSnapshot {
    try {
        $devices = Get-PnpDevice -PresentOnly -ErrorAction Stop
        $items = New-Object System.Collections.Generic.List[pscustomobject]

        foreach ($device in $devices) {
            if (-not (Test-PnpDeviceMatch -Device $device -Patterns @('displaylink', 'vid_17e9'))) { continue }
            $record = ConvertTo-PnpDeviceRecord -Device $device
            if ($record) { $items.Add($record) | Out-Null }
        }

        return [pscustomobject]@{
            Source = 'Get-PnpDevice -PresentOnly (DisplayLink filter)'
            Items  = $items.ToArray()
        }
    } catch {
        return [pscustomobject]@{
            Source = 'Get-PnpDevice -PresentOnly (DisplayLink filter)'
            Error  = $_.Exception.Message
            Items  = @()
        }
    }
}

function Get-ServiceSnapshotByName {
    param(
        [Parameter(Mandatory)]
        [string[]]$CandidateNames
    )

    $names = @($CandidateNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($names.Count -eq 0) { $names = @('') }

    foreach ($name in $names) {
        try {
            $service = Get-Service -Name $name -ErrorAction Stop
            return [pscustomobject]@{
                Source      = 'Get-Service'
                Name        = $name
                Status      = if ($service.Status) { ([string]$service.Status).Trim() } else { $null }
                DisplayName = if ($service.DisplayName) { [string]$service.DisplayName } else { $null }
                Exists      = $true
                QueriedNames = $names
            }
        } catch [System.InvalidOperationException] {
            continue
        } catch {
            return [pscustomobject]@{
                Source       = 'Get-Service'
                Name         = $name
                Error        = $_.Exception.Message
                QueriedNames = $names
            }
        }
    }

    return [pscustomobject]@{
        Source       = 'Get-Service'
        Name         = $names[0]
        Status       = 'NotFound'
        Exists       = $false
        QueriedNames = $names
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

function Get-ThunderboltServiceSnapshot {
    return Get-ServiceSnapshotByName -CandidateNames @('ThunderboltService','TbtService')
}

function Get-DisplayLinkServiceSnapshot {
    return Get-ServiceSnapshotByName -CandidateNames @('DisplayLinkManager')
}

function Invoke-Main {
    $payload = [ordered]@{
        DriverQuery       = Get-DriverInventory
        PnpProblems       = Get-PnpProblemDevices
        BluetoothDevices  = Get-BluetoothDeviceSnapshot
        BluetoothService  = Get-BluetoothServiceSnapshot
        ThunderboltDevices = Get-ThunderboltDeviceSnapshot
        ThunderboltService = Get-ThunderboltServiceSnapshot
        DisplayLinkDevices = Get-DisplayLinkDeviceSnapshot
        DisplayLinkService = Get-DisplayLinkServiceSnapshot
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'drivers.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
