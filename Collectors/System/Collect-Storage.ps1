<#!
.SYNOPSIS
    Collects disk, volume, and physical storage inventory.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-DiskInventory {
    try {
        return Get-Disk -ErrorAction Stop | Select-Object Number, FriendlyName, SerialNumber, HealthStatus, OperationalStatus, Size, PartitionStyle, IsBoot, IsSystem, IsReadOnly, WriteCacheEnabled
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-Disk'
            Error  = $_.Exception.Message
        }
    }
}

function Get-VolumeLayout {
    try {
        return Get-Volume -ErrorAction Stop | Select-Object DriveLetter, FileSystem, FileSystemLabel, HealthStatus, SizeRemaining, Size
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-Volume'
            Error  = $_.Exception.Message
        }
    }
}

function Get-PhysicalDisks {
    try {
        return Get-PhysicalDisk -ErrorAction Stop | Select-Object DeviceId, FriendlyName, SerialNumber, MediaType, CanPool, Size, HealthStatus, OperationalStatus
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-PhysicalDisk'
            Error  = $_.Exception.Message
        }
    }
}

function Get-StorageReliabilityData {
    $cmd = Get-Command -Name Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return [PSCustomObject]@{
            Source = 'Get-StorageReliabilityCounter'
            Error  = 'Get-StorageReliabilityCounter cmdlet not available'
        }
    }

    try {
        $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-PhysicalDisk'
            Error  = $_.Exception.Message
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($disk in $physicalDisks) {
        try {
            $counter = $disk | Get-StorageReliabilityCounter -ErrorAction Stop | Select-Object *
            $results.Add([PSCustomObject]@{
                    DeviceId      = if ($disk.PSObject.Properties['DeviceId']) { $disk.DeviceId } else { $null }
                    FriendlyName  = if ($disk.PSObject.Properties['FriendlyName']) { $disk.FriendlyName } else { $null }
                    SerialNumber  = if ($disk.PSObject.Properties['SerialNumber']) { $disk.SerialNumber } else { $null }
                    MediaType     = if ($disk.PSObject.Properties['MediaType']) { $disk.MediaType } else { $null }
                    Counters      = $counter
                }) | Out-Null
        } catch {
            $results.Add([PSCustomObject]@{
                    DeviceId     = if ($disk.PSObject.Properties['DeviceId']) { $disk.DeviceId } else { $null }
                    FriendlyName = if ($disk.PSObject.Properties['FriendlyName']) { $disk.FriendlyName } else { $null }
                    SerialNumber = if ($disk.PSObject.Properties['SerialNumber']) { $disk.SerialNumber } else { $null }
                    MediaType    = if ($disk.PSObject.Properties['MediaType']) { $disk.MediaType } else { $null }
                    Source       = 'Get-StorageReliabilityCounter'
                    Error        = $_.Exception.Message
                }) | Out-Null
        }
    }

    return $results
}

function Get-WmiDiskDrives {
    try {
        return Get-WmiObject -Class Win32_DiskDrive -ErrorAction Stop | Select-Object DeviceID, Model, SerialNumber, Size, MediaType, InterfaceType
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-WmiObject Win32_DiskDrive'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Disks                 = Get-DiskInventory
        Volumes               = Get-VolumeLayout
        PhysicalDisks         = Get-PhysicalDisks
        ReliabilityCounters   = Get-StorageReliabilityData
        DiskDriveInformation  = Get-WmiDiskDrives
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'storage.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
