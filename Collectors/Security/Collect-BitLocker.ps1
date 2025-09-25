<#!
.SYNOPSIS
    Collects BitLocker drive protection status for all volumes.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-BitLockerVolumes {
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        return $volumes | Select-Object MountPoint, VolumeType, CapacityGB, EncryptionMethod, ProtectionStatus, LockStatus, AutoUnlockEnabled, KeyProtector
    } catch {
        Write-Verbose "Get-BitLockerVolume failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Source = 'Get-BitLockerVolume'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Volumes = Get-BitLockerVolumes
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'bitlocker.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
