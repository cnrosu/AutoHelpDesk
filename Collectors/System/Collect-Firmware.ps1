<#!
.SYNOPSIS
    Collects structured firmware and Secure Boot signals for Windows 11 readiness checks.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-UefiSignals {
    $result = [ordered]@{
        UefiDetected           = $null
        PEFirmwareType         = $null
        UefiSources            = @()
        EspDetected            = $null
        EspPartitions          = @()
        Error                  = $null
    }

    $errors = [System.Collections.Generic.List[string]]::new()
    $sources = [System.Collections.Generic.List[string]]::new()

    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control'
    try {
        $value = Get-ItemPropertyValue -Path $registryPath -Name 'PEFirmwareType' -ErrorAction Stop
        if ($null -ne $value) {
            $numeric = [int]$value
            $result.PEFirmwareType = $numeric
            if ($numeric -eq 2) {
                $result.UefiDetected = $true
                $sources.Add('Registry PEFirmwareType=2 (UEFI)') | Out-Null
            } elseif ($numeric -eq 1) {
                $result.UefiDetected = $false
                $sources.Add('Registry PEFirmwareType=1 (Legacy BIOS)') | Out-Null
            } else {
                $sources.Add("Registry PEFirmwareType=$numeric") | Out-Null
            }
        }
    } catch {
        $errors.Add("PEFirmwareType registry query failed: $($_.Exception.Message)") | Out-Null
    }

    try {
        $partitions = Get-Partition -ErrorAction Stop
        if ($partitions) {
            $espPartitions = $partitions | Where-Object {
                $_.GptType -and $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}'
            }

            if (-not $espPartitions) {
                $espPartitions = $partitions | Where-Object {
                    $_.Type -and $_.Type -match '(?i)efi'
                }
            }

            if ($espPartitions) {
                $result.EspDetected = $true
                $sources.Add('EFI system partition present') | Out-Null
                $espList = [System.Collections.Generic.List[object]]::new()
                foreach ($partition in $espPartitions) {
                    if (-not $partition) { continue }
                    $entry = [ordered]@{}
                    if ($partition.PSObject.Properties['DiskNumber']) { $entry['DiskNumber'] = $partition.DiskNumber }
                    if ($partition.PSObject.Properties['PartitionNumber']) { $entry['PartitionNumber'] = $partition.PartitionNumber }
                    if ($partition.PSObject.Properties['DriveLetter'] -and $partition.DriveLetter) { $entry['DriveLetter'] = $partition.DriveLetter }
                    if ($partition.PSObject.Properties['GptType'] -and $partition.GptType) { $entry['GptType'] = $partition.GptType }
                    if ($partition.PSObject.Properties['Size']) { $entry['SizeBytes'] = [UInt64]$partition.Size }
                    if ($entry.Count -gt 0) { $espList.Add([pscustomobject]$entry) | Out-Null }
                }
                $result.EspPartitions = $espList.ToArray()
                if ($null -eq $result.UefiDetected) {
                    $result.UefiDetected = $true
                }
            } elseif ($null -eq $result.EspDetected) {
                $result.EspDetected = $false
            }
        }
    } catch {
        $errors.Add("Get-Partition failed: $($_.Exception.Message)") | Out-Null
    }

    $result.UefiSources = $sources.ToArray()
    if ($errors.Count -gt 0) {
        $result.Error = ($errors.ToArray() -join '; ')
    }

    return [pscustomobject]$result
}

function Get-SecureBootSignals {
    $result = [ordered]@{
        ConfirmSecureBootUEFI = $null
        MS_SecureBootEnabled  = $null
        RegistryEnabled       = $null
        Error                 = $null
    }

    $errors = [System.Collections.Generic.List[string]]::new()

    $cmd = Get-Command -Name 'Confirm-SecureBootUEFI' -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $result.ConfirmSecureBootUEFI = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        } catch {
            $errors.Add("Confirm-SecureBootUEFI failed: $($_.Exception.Message)") | Out-Null
        }
    } else {
        $errors.Add('Confirm-SecureBootUEFI command unavailable on this system.') | Out-Null
    }

    try {
        $secureBoot = Get-CimInstance -Namespace 'root\wmi' -ClassName 'MS_SecureBoot' -ErrorAction Stop
        if ($secureBoot -and $null -ne $secureBoot.SecureBootEnabled) {
            $result.MS_SecureBootEnabled = [bool]$secureBoot.SecureBootEnabled
        }
    } catch {
        $errors.Add("MS_SecureBoot query failed: $($_.Exception.Message)") | Out-Null
    }

    $registryStatePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    try {
        $stateValue = Get-ItemPropertyValue -Path $registryStatePath -Name 'UEFISecureBootEnabled' -ErrorAction Stop
        if ($null -ne $stateValue) {
            $result.RegistryEnabled = ([int]$stateValue -eq 1)
        }
    } catch {
        $errors.Add("Secure Boot registry query failed: $($_.Exception.Message)") | Out-Null
    }

    if ($errors.Count -gt 0) {
        $result.Error = ($errors.ToArray() -join '; ')
    }

    return [pscustomobject]$result
}

function Get-FirmwareSignals {
    $uefiSignals = Get-UefiSignals
    $secureBootSignals = Get-SecureBootSignals

    $payload = [ordered]@{
        UefiDetected   = $uefiSignals.UefiDetected
        PEFirmwareType = $uefiSignals.PEFirmwareType
        UefiSources    = $uefiSignals.UefiSources
        EspDetected    = $uefiSignals.EspDetected
        EspPartitions  = $uefiSignals.EspPartitions
        Error          = $uefiSignals.Error
        SecureBoot     = $secureBootSignals
    }

    return [pscustomobject]$payload
}

function Invoke-Main {
    $payload = [ordered]@{
        Firmware = Get-FirmwareSignals
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'firmware.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
