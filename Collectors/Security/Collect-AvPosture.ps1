<#!
.SYNOPSIS
    Collects antivirus posture details from Security Center and Microsoft Defender.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function ConvertTo-UtcIso8601 {
    param($Value)

    if (-not $Value) { return $null }

    try {
        if ($Value -is [datetime]) {
            return $Value.ToUniversalTime().ToString('o')
        }

        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }

        $parsed = [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($parsed.Kind -eq [System.DateTimeKind]::Unspecified) {
            $parsed = [datetime]::SpecifyKind($parsed, [System.DateTimeKind]::Local)
        }

        return $parsed.ToUniversalTime().ToString('o')
    } catch {
        return $null
    }
}

function ConvertTo-NullableBoolValue {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    switch -Regex ($text.Trim()) {
        '^(?i)(1|true|yes|on)$'  { return $true }
        '^(?i)(0|false|no|off)$' { return $false }
        default                  { return $null }
    }
}

function ConvertTo-NullableIntValue {
    param($Value)

    if ($Value -is [int]) { return [int]$Value }
    if ($Value -is [long]) { return [int][long]$Value }
    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $trimmed = $text.Trim()

    if ($trimmed -match '^(?i)0x[0-9a-f]+$') {
        try {
            return [Convert]::ToInt32($trimmed.Substring(2), 16)
        } catch {
            return $null
        }
    }

    $parsed = 0
    if ([int]::TryParse($trimmed, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function Get-AntivirusInventory {
    try {
        $items = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
        $products = @()

        foreach ($item in $items) {
            if (-not $item) { continue }

            $name = $null
            if ($item.PSObject.Properties['displayName'] -and $item.displayName) {
                $name = [string]$item.displayName
            } elseif ($item.PSObject.Properties['Name'] -and $item.Name) {
                $name = [string]$item.Name
            }

            $stateValue = $null
            if ($item.PSObject.Properties['productState']) {
                $stateValue = ConvertTo-NullableIntValue $item.productState
            } elseif ($item.PSObject.Properties['ProductState']) {
                $stateValue = ConvertTo-NullableIntValue $item.ProductState
            }

            $path = $null
            if ($item.PSObject.Properties['pathToSignedProductExe'] -and $item.pathToSignedProductExe) {
                $path = [string]$item.pathToSignedProductExe
            } elseif ($item.PSObject.Properties['Path'] -and $item.Path) {
                $path = [string]$item.Path
            }

            $products += [pscustomobject][ordered]@{
                Name         = if ($name) { $name } else { $null }
                ProductState = if ($null -ne $stateValue) { $stateValue } else { $null }
                Path         = if ($path) { $path } else { $null }
            }
        }

        return [ordered]@{
            Products = $products
        }
    } catch {
        return [ordered]@{
            Products = @()
            Source   = 'Get-CimInstance AntiVirusProduct'
            Error    = $_.Exception.Message
        }
    }
}

function Get-DefenderStatusSnapshot {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop

        $mode = $null
        if ($status.PSObject.Properties['AMRunningMode'] -and $status.AMRunningMode) {
            $mode = [string]$status.AMRunningMode
        }

        $realTime = $null
        if ($status.PSObject.Properties['RealTimeProtectionEnabled']) {
            $realTime = ConvertTo-NullableBoolValue $status.RealTimeProtectionEnabled
        }

        $signaturesOutOfDate = $null
        if ($status.PSObject.Properties['DefenderSignaturesOutOfDate']) {
            $signaturesOutOfDate = ConvertTo-NullableBoolValue $status.DefenderSignaturesOutOfDate
        }

        $tamperProtected = $null
        if ($status.PSObject.Properties['IsTamperProtected']) {
            $tamperProtected = ConvertTo-NullableBoolValue $status.IsTamperProtected
        }

        $signatureUpdatedUtc = $null
        if ($status.PSObject.Properties['AntivirusSignatureLastUpdated']) {
            $signatureUpdatedUtc = ConvertTo-UtcIso8601 $status.AntivirusSignatureLastUpdated
        }

        return [ordered]@{
            AMRunningMode                   = if ($mode) { $mode } else { $null }
            RealTimeProtectionEnabled       = $realTime
            DefenderSignaturesOutOfDate     = $signaturesOutOfDate
            AntivirusSignatureLastUpdatedUtc = $signatureUpdatedUtc
            IsTamperProtected               = $tamperProtected
        }
    } catch {
        return [ordered]@{
            Source = 'Get-MpComputerStatus'
            Error  = $_.Exception.Message
        }
    }
}

function Get-DefenderPreferencesSnapshot {
    try {
        $preferences = Get-MpPreference -ErrorAction Stop

        $disableRealtime = $null
        if ($preferences.PSObject.Properties['DisableRealtimeMonitoring']) {
            $disableRealtime = ConvertTo-NullableBoolValue $preferences.DisableRealtimeMonitoring
        }

        $mapsReporting = $null
        if ($preferences.PSObject.Properties['MAPSReporting']) {
            $mapsReporting = ConvertTo-NullableIntValue $preferences.MAPSReporting
        }

        $submitSamples = $null
        if ($preferences.PSObject.Properties['SubmitSamplesConsent']) {
            $submitSamples = ConvertTo-NullableIntValue $preferences.SubmitSamplesConsent
        }

        return [ordered]@{
            DisableRealtimeMonitoring = $disableRealtime
            MAPSReporting             = $mapsReporting
            SubmitSamplesConsent      = $submitSamples
        }
    } catch {
        return [ordered]@{
            Source = 'Get-MpPreference'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        SecurityCenter = Get-AntivirusInventory
        Defender       = Get-DefenderStatusSnapshot
        Preferences    = Get-DefenderPreferencesSnapshot
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'av-posture.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
