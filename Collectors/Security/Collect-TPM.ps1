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

function Get-TpmStatus {
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        return $tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManagedAuthLevel, ManufacturerId, ManufacturerVersion, LockoutHealTime, LockoutCount, LockedOut
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-Tpm'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Tpm = Get-TpmStatus
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'tpm.json' -Data $result -Depth 4
    Write-Output $outputPath
}

Invoke-Main
