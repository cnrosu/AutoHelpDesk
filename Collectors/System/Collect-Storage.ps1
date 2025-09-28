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
        return Get-Disk -ErrorAction Stop | Select-Object Number, FriendlyName, SerialNumber, HealthStatus, OperationalStatus, Size, PartitionStyle
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

function Get-StorageReliabilityCounters {
    try {
        [void](Get-Command -Name 'Get-StorageReliabilityCounter' -ErrorAction Stop)
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-StorageReliabilityCounter'
            Error  = 'Get-StorageReliabilityCounter cmdlet is unavailable.'
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

    $results = @()
    foreach ($disk in $physicalDisks) {
        $entry = [ordered]@{
            DeviceId      = $disk.DeviceId
            FriendlyName  = $disk.FriendlyName
        }

        if ($disk.PSObject.Properties['SerialNumber']) {
            $entry['SerialNumber'] = $disk.SerialNumber
        }
        if ($disk.PSObject.Properties['MediaType']) {
            $entry['MediaType'] = $disk.MediaType
        }

        try {
            $counters = Get-StorageReliabilityCounter -PhysicalDisk $disk -ErrorAction Stop
            if ($null -eq $counters) {
                $entry['Error'] = 'No reliability data returned.'
            } else {
                if ($counters.PSObject.Properties['Wear']) {
                    $wearValue = $counters.Wear
                    if ($wearValue -is [double] -or $wearValue -is [single] -or $wearValue -is [int]) {
                        $entry['Wear'] = [double]$wearValue
                    } elseif ($wearValue) {
                        $parsed = 0.0
                        if ([double]::TryParse([string]$wearValue, [ref]$parsed)) {
                            $entry['Wear'] = [double]$parsed
                        } else {
                            $entry['Wear'] = $wearValue
                        }
                    }
                }
                if ($counters.PSObject.Properties['Temperature']) {
                    $temperature = $counters.Temperature
                    if ($temperature -is [double] -or $temperature -is [single] -or $temperature -is [int]) {
                        $entry['TemperatureCelsius'] = [double]$temperature
                    } elseif ($temperature) {
                        $parsedTemp = 0.0
                        if ([double]::TryParse([string]$temperature, [ref]$parsedTemp)) {
                            $entry['TemperatureCelsius'] = [double]$parsedTemp
                        } else {
                            $entry['TemperatureCelsius'] = $temperature
                        }
                    }
                }
            }
        } catch {
            $entry['Error'] = $_.Exception.Message
        }

        $results += [pscustomobject]$entry
    }

    return $results
}

function Invoke-Main {
    $payload = [ordered]@{
        Disks        = Get-DiskInventory
        Volumes      = Get-VolumeLayout
        PhysicalDisks = Get-PhysicalDisks
        WearCounters  = Get-StorageReliabilityCounters
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'storage.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
