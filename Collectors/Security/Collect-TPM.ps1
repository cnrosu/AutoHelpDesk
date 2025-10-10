<#!
.SYNOPSIS
    Collects Trusted Platform Module (TPM) status information.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-TpmSignals {
    $signals = [ordered]@{
        GetTpm    = $null
        Win32_Tpm = $null
        Error     = $null
    }

    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        $tpm = Get-Tpm -ErrorAction Stop | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, SpecVersion, ManagedAuthLevel, ManufacturerId, ManufacturerVersion, LockoutHealTime, LockoutCount, LockedOut
        $signals.GetTpm = $tpm
    } catch {
        $errors.Add("Get-Tpm: $($_.Exception.Message)") | Out-Null
    }

    try {
        $win32 = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -ErrorAction Stop |
            Select-Object IsActivated_InitialValue, IsEnabled_InitialValue, IsOwned_InitialValue, SpecVersion, ManufacturerId, ManufacturerVersion, PhysicalPresenceVersionInfo, ManagedAuthLevel, SelfTest, LockoutHealTime, LockoutCount, LockedOut
        if ($win32) {
            $signals.Win32_Tpm = $win32
        }
    } catch {
        $errors.Add("Win32_Tpm: $($_.Exception.Message)") | Out-Null
    }

    if ($errors.Count -gt 0) {
        $signals.Error = ($errors.ToArray() -join '; ')
    }

    return [pscustomobject]$signals
}

function Invoke-Main {
    $payload = [ordered]@{
        Tpm = Get-TpmSignals
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'tpm.json' -Data $result -Depth 4
    Write-Output $outputPath
}

Invoke-Main
