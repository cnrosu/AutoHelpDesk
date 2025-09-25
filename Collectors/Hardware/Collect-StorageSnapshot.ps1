<#!
.SYNOPSIS
    Collects disk, volume, and storage health information referenced by the analyzer.
.DESCRIPTION
    Captures the same storage evidence consumed by AutoL1/Analyze-Diagnostics.ps1,
    including SMART status (disk drive inventory), Get-Disk health details, and
    Get-Volume summaries used for free-space calculations.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-WmicDiskDriveOutput {
    $wmic = $null
    try {
        $wmic = Get-Command -Name 'wmic.exe' -ErrorAction Stop
    } catch {
        return $null
    }

    try {
        $output = & $wmic.Path diskdrive get model,serialNumber,status,size 2>$null | Out-String -Width 400
        if ($output) { return $output.TrimEnd() }
        return $null
    } catch {
        return $null
    }
}

function Get-DiskDriveStatus {
    $wmicOutput = Get-WmicDiskDriveOutput
    if ($wmicOutput) { return $wmicOutput }

    try {
        $drives = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
        if (-not $drives) { return 'No disk drive data returned.' }
        return ($drives | Select-Object Model, SerialNumber, Status, Size | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()
    } catch {
        return [pscustomobject]@{
            Source = 'Win32_DiskDrive'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DiskInventory {
    try {
        $text = Get-Disk -ErrorAction Stop | Format-List * | Out-String -Width 200
        if ($text) { return $text.TrimEnd() }
    } catch {
        $errorMessage = $_.Exception.Message
        try {
            $cim = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
            if ($cim) {
                $fallback = ($cim | Select-Object DeviceID, Model, SerialNumber, InterfaceType, Status | Format-List * | Out-String -Width 200).TrimEnd()
                return $fallback
            }
        } catch {}
        return [pscustomobject]@{
            Source = 'Get-Disk'
            Error  = $errorMessage
        }
    }

    return 'No disk data returned.'
}

function Get-VolumeSummary {
    try {
        $volumes = Get-Volume -ErrorAction Stop | Sort-Object DriveLetter
        if (-not $volumes) { return 'No volume data returned.' }
        return ($volumes | Select-Object DriveLetter, FileSystem, HealthStatus, SizeRemaining, Size | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()
    } catch {
        $errorMessage = $_.Exception.Message
        try {
            $cim = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop
            if ($cim) {
                $fallback = ($cim | Select-Object DriveLetter, FileSystem, Status, Capacity, FreeSpace | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()
                return $fallback
            }
        } catch {}
        return [pscustomobject]@{
            Source = 'Get-Volume'
            Error  = $errorMessage
        }
    }
}

function Get-PhysicalDiskSnapshot {
    try {
        $disks = Get-PhysicalDisk -ErrorAction Stop
        if (-not $disks) { return 'No physical disk data returned.' }
        return ($disks | Select-Object DeviceId, FriendlyName, MediaType, CanPool, HealthStatus, OperationalStatus, Size | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()
    } catch {
        return $null
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        DiskDrives    = Get-DiskDriveStatus
        Disks         = Get-DiskInventory
        Volumes       = Get-VolumeSummary
    }

    $physical = Get-PhysicalDiskSnapshot
    if ($physical) {
        $payload['PhysicalDisks'] = $physical
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'storage-snapshot.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
