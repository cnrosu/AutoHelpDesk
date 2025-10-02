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
        return $volumes | ForEach-Object {
            $volume = $_
            $keyProtectors = @()

            if ($null -ne $volume.KeyProtector) {
                foreach ($protector in @($volume.KeyProtector)) {
                    if ($null -eq $protector) { continue }

                    $entry = [ordered]@{}

                    if ($protector.PSObject.Properties['KeyProtectorId']) {
                        $entry['KeyProtectorId'] = $protector.KeyProtectorId
                    }

                    if ($protector.PSObject.Properties['KeyProtectorType']) {
                        $entry['KeyProtectorType'] = $protector.KeyProtectorType
                    }

                    if ($protector.PSObject.Properties['KeyProtectorFriendlyName']) {
                        $entry['KeyProtectorFriendlyName'] = $protector.KeyProtectorFriendlyName
                    }

                    if ($entry.Count -eq 0) {
                        $keyProtectors += $protector
                    } else {
                        $keyProtectors += [pscustomobject]$entry
                    }
                }
            }

            [pscustomobject][ordered]@{
                MountPoint        = $volume.MountPoint
                VolumeType        = $volume.VolumeType
                CapacityGB        = $volume.CapacityGB
                EncryptionMethod  = $volume.EncryptionMethod
                ProtectionStatus  = $volume.ProtectionStatus
                LockStatus        = $volume.LockStatus
                AutoUnlockEnabled = $volume.AutoUnlockEnabled
                KeyProtector      = $keyProtectors
            }
        }
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
