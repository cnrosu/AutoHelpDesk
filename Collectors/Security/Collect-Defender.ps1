<#!
.SYNOPSIS
    Collects Microsoft Defender Antivirus health and configuration data.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-DefenderStatus {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        return $status | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, IoavProtectionEnabled, RealTimeProtectionEnabled, TamperProtectionEnabled, IsTamperProtected, NISEnabled, QuickScanEndTime, FullScanEndTime, ProductStatus, AntivirusSignatureVersion, AntispywareSignatureVersion
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-MpComputerStatus'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DefenderThreatStatistics {
    try {
        return Get-MpThreat -ErrorAction Stop | Select-Object ThreatID, ThreatName, SeverityID, CategoryID, Resources, ActionSuccess, LastThreatStatusChangeTime
    } catch {
        if ($_.Exception -and $_.Exception.Message -like '*No threats found*') {
            return @()
        }

        return [PSCustomObject]@{
            Source = 'Get-MpThreat'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DefenderPreferences {
    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        return $prefs | Select-Object DisableRealtimeMonitoring, DisableIOAVProtection, DisablePrivacyMode, DisableIntrusionPreventionSystem, DisableScriptScanning, ScanScheduleDay, ScanScheduleTime, SignatureScheduleDay, SignatureScheduleTime, MAPSReporting, SubmitSamplesConsent, EnableNetworkProtection, UILockdownMode
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-MpPreference'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Status       = Get-DefenderStatus
        Threats      = Get-DefenderThreatStatistics
        Preferences  = Get-DefenderPreferences
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'defender.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
