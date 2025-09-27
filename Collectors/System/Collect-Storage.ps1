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

function Invoke-Main {
    $payload = [ordered]@{
        Disks        = Get-DiskInventory
        Volumes      = Get-VolumeLayout
        PhysicalDisks = Get-PhysicalDisks
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'storage.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
