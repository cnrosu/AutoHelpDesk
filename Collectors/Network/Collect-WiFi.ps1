<#!
.SYNOPSIS
    Collects Wi-Fi interface statistics and recent roaming events.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-WifiInterfaceOutput {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'wlan','show','interfaces' -SourceLabel 'netsh wlan'
}

function Normalize-MacLikeValue {
    param([string]$Value)

    if (-not $Value) { return $null }

    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }

    $normalized = $trimmed.ToLowerInvariant()
    $normalized = $normalized -replace '[^0-9a-f]', ':'
    $normalized = $normalized -replace ':+', ':'
    $normalized = $normalized.Trim(':')

    if (-not $normalized) { return $null }
    if ($normalized -notmatch '^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$') { return $trimmed.ToLowerInvariant() }

    return $normalized
}

function ConvertTo-WifiInterfaceSamples {
    param(
        [Parameter(Mandatory)]
        $Lines
    )

    if (-not $Lines) { return @() }

    $lineItems = @()
    if ($Lines -is [string]) {
        $lineItems = @($Lines)
    } elseif ($Lines -is [System.Collections.IEnumerable] -and -not ($Lines -is [string])) {
        foreach ($line in $Lines) { $lineItems += [string]$line }
    } else {
        return @()
    }

    $samples = New-Object System.Collections.Generic.List[pscustomobject]
    $current = $null
    $timestamp = (Get-Date).ToString('o')

    foreach ($rawLine in $lineItems) {
        if (-not $rawLine) { continue }
        $line = [string]$rawLine
        if (-not $line.Contains(':')) { continue }

        $parts = $line.Split(':', 2)
        if ($parts.Count -lt 2) { continue }

        $key = ($parts[0]).Trim()
        $value = ($parts[1]).Trim()
        if (-not $key) { continue }

        $normalized = ($key -replace '\s+', ' ').Trim().ToLowerInvariant()

        switch -Wildcard ($normalized) {
            'name' {
                if ($current) { $samples.Add([pscustomobject]$current) | Out-Null }
                $current = [ordered]@{
                    Name      = $value
                    SampledAt = $timestamp
                }
                continue
            }
            'guid' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $current['InterfaceGuid'] = $value
                continue
            }
            'description' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $current['Description'] = $value
                continue
            }
            'state' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $current['State'] = $value
                continue
            }
            'ssid' {
                if ($normalized -eq 'ssid' -or $normalized -eq 'ssid name') {
                    if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                    $current['Ssid'] = $value
                }
                continue
            }
            'bssid' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $current['Bssid'] = Normalize-MacLikeValue -Value $value
                continue
            }
            'network type' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $current['NetworkType'] = $value
                continue
            }
            'radio type' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $current['RadioType'] = $value
                continue
            }
            'channel' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $parsedChannel = $null
                if ([int]::TryParse($value, [ref]$parsedChannel)) { $current['Channel'] = $parsedChannel } else { $current['Channel'] = $value }
                continue
            }
            'receive rate (mbps)' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $parsed = $null
                if ([double]::TryParse($value, [ref]$parsed)) { $current['ReceiveRateMbps'] = $parsed } else { $current['ReceiveRateMbps'] = $value }
                continue
            }
            'transmit rate (mbps)' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $parsed = $null
                if ([double]::TryParse($value, [ref]$parsed)) { $current['TransmitRateMbps'] = $parsed } else { $current['TransmitRateMbps'] = $value }
                continue
            }
            'signal' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $percent = $null
                if ($value -match '(\d+)\s*%') {
                    $percent = [int]$matches[1]
                    $current['SignalPercent'] = $percent
                }
                if ($value -match '(-?\d+)\s*dBm') {
                    $current['SignalDbm'] = [int]$matches[1]
                } elseif ($percent -ne $null) {
                    $estimate = [math]::Round(-100 + ($percent * 0.55))
                    $current['SignalDbm'] = [int]$estimate
                }
                continue
            }
            'profile' {
                if (-not $current) { $current = [ordered]@{ SampledAt = $timestamp } }
                $current['Profile'] = $value
                continue
            }
            default {
                continue
            }
        }
    }

    if ($current) { $samples.Add([pscustomobject]$current) | Out-Null }
    return $samples.ToArray()
}

function Get-WifiRoamEvents {
    try {
        $events = Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational' -MaxEvents 500 -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-WinEvent'
            Log    = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
            Error  = $_.Exception.Message
        }
    }

    $results = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($event in $events) {
        if (-not $event) { continue }

        $entry = [ordered]@{
            Id          = $event.Id
            Level       = $event.LevelDisplayName
            TimeCreated = if ($event.TimeCreated) { $event.TimeCreated.ToString('o') } else { $null }
        }

        $message = $null
        try { $message = $event.Message } catch { $message = $null }
        if ($message) { $entry['Message'] = $message.Trim() }

        if ($event.Properties) {
            $props = @()
            foreach ($prop in $event.Properties) {
                if ($null -eq $prop) { continue }
                $value = $prop.Value
                if ($null -eq $value) { $props += $null; continue }
                $props += [string]$value
            }
            if ($props.Count -gt 0) { $entry['Properties'] = $props }
        }

        if ($message) {
            $patterns = @(
                @{ Key = 'NewBssid'; Pattern = '(?i)\bNew\s+BSSID\s*[:=]\s*([0-9A-Fa-f:\-]{12,})' },
                @{ Key = 'TargetBssid'; Pattern = '(?i)\bTarget\s+BSSID\s*[:=]\s*([0-9A-Fa-f:\-]{12,})' },
                @{ Key = 'OldBssid'; Pattern = '(?i)\bOld\s+BSSID\s*[:=]\s*([0-9A-Fa-f:\-]{12,})' },
                @{ Key = 'Bssid'; Pattern = '(?i)\bBSSID\s*[:=]\s*([0-9A-Fa-f:\-]{12,})' }
            )

            foreach ($pattern in $patterns) {
                if ($entry.Contains($pattern.Key)) { continue }
                if ($message -match $pattern.Pattern) {
                    $entry[$pattern.Key] = Normalize-MacLikeValue -Value $matches[1]
                }
            }

            if (-not $entry.Contains('Ssid') -and $message -match '(?i)(?<!B)SSID\s*[:=]\s*([^\r\n]+)') {
                $entry['Ssid'] = ($matches[1]).Trim()
            }
        }

        $results.Add([pscustomobject]$entry) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $interfaceOutput = Get-WifiInterfaceOutput
    $samples = $null
    if ($interfaceOutput -and -not ($interfaceOutput.PSObject -and $interfaceOutput.PSObject.Properties['Error'])) {
        $samples = ConvertTo-WifiInterfaceSamples -Lines $interfaceOutput
    }

    $roamEvents = Get-WifiRoamEvents

    $payload = [ordered]@{
        Interfaces = [ordered]@{
            Raw     = $interfaceOutput
            Samples = $samples
        }
        RoamEvents = $roamEvents
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-wifi.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
