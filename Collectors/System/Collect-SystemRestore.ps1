<#!
.SYNOPSIS
    Collects System Restore configuration and available restore points.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-SystemRestoreRegistryConfig {
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'

    try {
        if (-not (Test-Path -LiteralPath $registryPath)) {
            return $null
        }

        $item = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
        $properties = @(
            'DisableSR',
            'DisableConfig',
            'RPGlobalInterval',
            'RPLifeInterval',
            'RPSessionInterval',
            'DSMax',
            'DSMin',
            'DiskPercent'
        )

        $result = [ordered]@{}
        foreach ($name in $properties) {
            if ($item.PSObject.Properties[$name]) {
                $value = $item.$name
                if ($null -ne $value) {
                    $result[$name] = $value
                }
            }
        }

        if ($result.Count -eq 0) {
            return $null
        }

        return [pscustomobject]$result
    } catch {
        return [pscustomobject]@{
            Source = $registryPath
            Error  = $_.Exception.Message
        }
    }
}

function Get-SystemRestoreDriveConfigurations {
    $basePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\Cfg'

    try {
        if (-not (Test-Path -LiteralPath $basePath)) {
            return @()
        }

        $drives = Get-ChildItem -LiteralPath $basePath -ErrorAction Stop
        $results = [System.Collections.Generic.List[object]]::new()

        foreach ($driveKey in $drives) {
            if (-not $driveKey) { continue }

            $drivePath = $driveKey.PSPath
            $driveName = if ($driveKey.PSObject.Properties['PSChildName'] -and $driveKey.PSChildName) {
                [string]$driveKey.PSChildName
            } else {
                Split-Path -Path $driveKey.Name -Leaf
            }

            try {
                $driveItem = Get-ItemProperty -LiteralPath $drivePath -ErrorAction Stop
            } catch {
                $results.Add([pscustomobject]@{
                    Drive  = $driveName
                    Source = $drivePath
                    Error  = $_.Exception.Message
                }) | Out-Null
                continue
            }

            $entry = [ordered]@{
                Drive = $driveName
            }

            foreach ($property in @('DisableSR', 'DisableConfig', 'DiskPercent', 'DSMax', 'DSMin')) {
                if ($driveItem.PSObject.Properties[$property]) {
                    $entry[$property] = $driveItem.$property
                }
            }

            $results.Add([pscustomobject]$entry) | Out-Null
        }

        return $results.ToArray()
    } catch {
        return [pscustomobject]@{
            Source = $basePath
            Error  = $_.Exception.Message
        }
    }
}

function Get-SystemRestoreEventTypeName {
    param([int]$Value)

    switch ($Value) {
        1 { return 'Begin' }
        2 { return 'End' }
        12 { return 'System checkpoint' }
        default { return $null }
    }
}

function Get-SystemRestorePointTypeName {
    param([int]$Value)

    switch ($Value) {
        0 { return 'Application install' }
        1 { return 'Application uninstall' }
        7 { return 'Device driver install' }
        10 { return 'Windows Update' }
        12 { return 'Checkpoint' }
        13 { return 'Manual' }
        14 { return 'Scheduled checkpoint' }
        default { return $null }
    }
}

function Convert-SystemRestorePoint {
    param($Point)

    if (-not $Point) { return $null }

    $creationTime = $null
    if ($Point.PSObject.Properties['CreationTime'] -and $Point.CreationTime) {
        $rawTime = [string]$Point.CreationTime
        try {
            $creationTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($rawTime).ToString('o')
        } catch {
            $creationTime = $rawTime
        }
    }

    $eventType = $null
    if ($Point.PSObject.Properties['EventType']) {
        $eventType = [int]$Point.EventType
    }

    $restorePointType = $null
    if ($Point.PSObject.Properties['RestorePointType']) {
        $restorePointType = [int]$Point.RestorePointType
    }

    return [pscustomobject]@{
        SequenceNumber     = if ($Point.PSObject.Properties['SequenceNumber']) { [int]$Point.SequenceNumber } else { $null }
        Description        = if ($Point.PSObject.Properties['Description']) { [string]$Point.Description } else { $null }
        CreationTime       = $creationTime
        EventType          = $eventType
        EventTypeName      = if ($eventType -ne $null) { Get-SystemRestoreEventTypeName -Value $eventType } else { $null }
        RestorePointType   = $restorePointType
        RestorePointTypeName = if ($restorePointType -ne $null) { Get-SystemRestorePointTypeName -Value $restorePointType } else { $null }
    }
}

function Get-SystemRestorePoints {
    $points = $null

    try {
        $points = Get-CimInstance -Namespace 'root/default' -ClassName SystemRestore -ErrorAction Stop
    } catch {
        try {
            $points = Get-ComputerRestorePoint -ErrorAction Stop
        } catch {
            return [pscustomobject]@{
                Source = 'SystemRestore'
                Error  = $_.Exception.Message
            }
        }
    }

    if (-not $points) {
        return @()
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($point in $points) {
        $converted = Convert-SystemRestorePoint -Point $point
        if ($converted) {
            $results.Add($converted) | Out-Null
        }
    }

    return $results.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        RegistryConfig      = Get-SystemRestoreRegistryConfig
        DriveConfigurations = Get-SystemRestoreDriveConfigurations
        RestorePoints       = Get-SystemRestorePoints
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'systemrestore.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
