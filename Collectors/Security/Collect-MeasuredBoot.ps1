<#!
.SYNOPSIS
    Collects measured boot evidence including PCR bindings, Secure Boot status, and TPM attestation events.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function ConvertTo-Array {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $null = $list.Add($item) }
        return $list.ToArray()
    }

    return @($Value)
}

function Get-BitLockerPcrBindings {
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-BitLockerVolume'
            Error  = $_.Exception.Message
        }
    }

    $volumeResults = [System.Collections.Generic.List[object]]::new()

    foreach ($volume in $volumes) {
        if (-not $volume) { continue }

        $volumeEntry = [ordered]@{}
        if ($volume.PSObject.Properties['MountPoint']) { $volumeEntry['MountPoint'] = $volume.MountPoint }
        if ($volume.PSObject.Properties['VolumeType']) { $volumeEntry['VolumeType'] = $volume.VolumeType }
        if ($volume.PSObject.Properties['CapacityGB']) { $volumeEntry['CapacityGB'] = $volume.CapacityGB }
        if ($volume.PSObject.Properties['EncryptionMethod']) { $volumeEntry['EncryptionMethod'] = $volume.EncryptionMethod }

        $protectorList = [System.Collections.Generic.List[object]]::new()
        foreach ($protector in (ConvertTo-Array $volume.KeyProtector)) {
            if (-not $protector) { continue }

            $protectorEntry = [ordered]@{}
            if ($protector.PSObject.Properties['KeyProtectorId']) { $protectorEntry['KeyProtectorId'] = $protector.KeyProtectorId }
            if ($protector.PSObject.Properties['KeyProtectorType']) { $protectorEntry['KeyProtectorType'] = $protector.KeyProtectorType }
            if ($protector.PSObject.Properties['AutoUnlockEnabled']) { $protectorEntry['AutoUnlockEnabled'] = $protector.AutoUnlockEnabled }
            if ($protector.PSObject.Properties['PcrBinding']) {
                $bindingValues = ConvertTo-Array $protector.PcrBinding
                if ($bindingValues.Count -gt 0) {
                    $protectorEntry['PcrBinding'] = $bindingValues
                }
            }
            if ($protector.PSObject.Properties['PcrHashAlgorithm']) {
                $protectorEntry['PcrHashAlgorithm'] = $protector.PcrHashAlgorithm
            } elseif ($protector.PSObject.Properties['PcrAlgorithmId']) {
                $protectorEntry['PcrHashAlgorithm'] = $protector.PcrAlgorithmId
            }
            if ($protector.PSObject.Properties['TpmKeyId']) { $protectorEntry['TpmKeyId'] = $protector.TpmKeyId }
            if ($protector.PSObject.Properties['RecoveryPasswordId']) { $protectorEntry['RecoveryPasswordId'] = $protector.RecoveryPasswordId }

            $protectorList.Add([PSCustomObject]$protectorEntry) | Out-Null
        }

        $volumeEntry['KeyProtectors'] = $protectorList.ToArray()
        $volumeResults.Add([PSCustomObject]$volumeEntry) | Out-Null
    }

    return $volumeResults.ToArray()
}

function Get-SecureBootVerification {
    $cmd = Get-Command -Name 'Confirm-SecureBootUEFI' -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return [PSCustomObject]@{
            Source = 'Confirm-SecureBootUEFI'
            Error  = 'Confirm-SecureBootUEFI not available on this system.'
        }
    }

    try {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        return [PSCustomObject]@{
            Source  = 'Confirm-SecureBootUEFI'
            Enabled = [bool]$enabled
        }
    } catch {
        return [PSCustomObject]@{
            Source = 'Confirm-SecureBootUEFI'
            Error  = $_.Exception.Message
        }
    }
}

function Get-MeasuredBootAttestation {
    $logName = 'Microsoft-Windows-TPM-WMI/Operational'

    try {
        $null = Get-WinEvent -ListLog $logName -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Source  = 'Get-WinEvent'
            LogName = $logName
            Error   = $_.Exception.Message
        }
    }

    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents 50 -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Source  = 'Get-WinEvent'
            LogName = $logName
            Error   = $_.Exception.Message
        }
    }

    $eventSummaries = [System.Collections.Generic.List[object]]::new()
    foreach ($event in $events) {
        if (-not $event) { continue }

        $entry = [ordered]@{}
        if ($event.Id) { $entry['Id'] = [int]$event.Id }
        if ($event.RecordId) { $entry['RecordId'] = [long]$event.RecordId }
        if ($event.TimeCreated) { $entry['TimeCreated'] = $event.TimeCreated.ToString('o') }
        if ($event.LevelDisplayName) { $entry['Level'] = [string]$event.LevelDisplayName }
        if ($event.ProviderName) { $entry['Provider'] = [string]$event.ProviderName }
        $message = $null
        try {
            if ($event.Message) {
                $message = [string]$event.Message
                if ($message) { $message = $message.Trim() }
            }
        } catch {
            $message = $null
        }
        if ($message) { $entry['Message'] = $message }

        $eventSummaries.Add([PSCustomObject]$entry) | Out-Null
    }

    return [PSCustomObject]@{
        LogName = $logName
        Events  = $eventSummaries.ToArray()
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        BitLocker  = [ordered]@{ Volumes = Get-BitLockerPcrBindings }
        SecureBoot = Get-SecureBootVerification
        Attestation = Get-MeasuredBootAttestation
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'measured-boot.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
