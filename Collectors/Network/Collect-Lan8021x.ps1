<#!
.SYNOPSIS
    Collects wired 802.1X diagnostics including interface state, profiles, Dot3Svc events, and machine certificates.
.DESCRIPTION
    Executes Windows netsh commands for the LAN context, exports recent Dot3Svc operational events, and inventories
    machine certificates that can be used for 802.1X authentication. When run on non-Windows platforms, the collector
    records a placeholder message so analyzers know that wired diagnostics are unavailable.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Test-IsWindows {
    try {
        return [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    } catch {
        return $false
    }
}

function ConvertTo-Lan8021xLines {
    param($Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [string]) { return @($Value) }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $lines = @()
        foreach ($item in $Value) {
            if ($null -ne $item) { $lines += [string]$item }
        }
        return $lines
    }

    if ($Value.PSObject -and $Value.PSObject.Properties['Lines']) {
        return ConvertTo-Lan8021xLines -Value $Value.Lines
    }

    return @([string]$Value)
}

function Get-Lan8021xInterfacesRaw {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'lan','show','interfaces' -SourceLabel 'netsh lan show interfaces'
}

function Get-Lan8021xProfilesRaw {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'lan','show','profiles' -SourceLabel 'netsh lan show profiles'
}

function Get-Lan8021xDot3Events {
    $cutoff = (Get-Date).AddDays(-7)
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Dot3Svc/Operational'; StartTime = $cutoff } -ErrorAction Stop -MaxEvents 200
    } catch {
        return [pscustomobject]@{
            Source = 'Get-WinEvent Microsoft-Windows-Dot3Svc/Operational'
            Error  = $_.Exception.Message
        }
    }

    $results = @()
    foreach ($event in $events) {
        if (-not $event) { continue }

        $timeCreatedUtc = $null
        if ($event.PSObject.Properties['TimeCreated'] -and $event.TimeCreated) {
            try { $timeCreatedUtc = $event.TimeCreated.ToUniversalTime().ToString('o') } catch { $timeCreatedUtc = $null }
        }

        $message = $null
        try { $message = $event.Message } catch { $message = $null }

        $results += [ordered]@{
            timeCreatedUtc = $timeCreatedUtc
            level          = $( if ($event.PSObject.Properties['LevelDisplayName']) { [string]$event.LevelDisplayName } else { $null } )
            eventId        = $( if ($event.PSObject.Properties['Id']) { [int]$event.Id } else { $null } )
            provider       = $( if ($event.PSObject.Properties['ProviderName']) { [string]$event.ProviderName } else { $null } )
            message        = $message
        }
    }

    return $results
}

function Get-Lan8021xMachineCertificates {
    try {
        $certs = Get-ChildItem -Path 'Cert:\\LocalMachine\\My' -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Source = 'Cert:\\LocalMachine\\My'
            Error  = $_.Exception.Message
        }
    }

    $results = @()
    foreach ($cert in $certs) {
        if (-not $cert) { continue }

        $notBeforeUtc = $null
        if ($cert.PSObject.Properties['NotBefore']) {
            try { $notBeforeUtc = $cert.NotBefore.ToUniversalTime().ToString('o') } catch { $notBeforeUtc = $null }
        }

        $notAfterUtc = $null
        if ($cert.PSObject.Properties['NotAfter']) {
            try { $notAfterUtc = $cert.NotAfter.ToUniversalTime().ToString('o') } catch { $notAfterUtc = $null }
        }

        $ekuDetails = @()
        if ($cert.PSObject.Properties['EnhancedKeyUsageList']) {
            foreach ($eku in $cert.EnhancedKeyUsageList) {
                if (-not $eku) { continue }
                $ekuDetails += [ordered]@{
                    friendlyName = $( if ($eku.PSObject.Properties['FriendlyName']) { [string]$eku.FriendlyName } else { $null } )
                    oid          = $( if ($eku.PSObject.Properties['Value']) { [string]$eku.Value } else { $null } )
                }
            }
        }

        $results += [ordered]@{
            subject         = $( if ($cert.PSObject.Properties['Subject']) { [string]$cert.Subject } else { $null } )
            issuer          = $( if ($cert.PSObject.Properties['Issuer']) { [string]$cert.Issuer } else { $null } )
            thumbprint      = $( if ($cert.PSObject.Properties['Thumbprint']) { [string]$cert.Thumbprint } else { $null } )
            notBeforeUtc    = $notBeforeUtc
            notAfterUtc     = $notAfterUtc
            hasPrivateKey   = $( if ($cert.PSObject.Properties['HasPrivateKey']) { [bool]$cert.HasPrivateKey } else { $null } )
            enhancedKeyUsage = $ekuDetails
        }
    }

    return $results
}

function Invoke-Main {
    $payload = [ordered]@{
        schemaVersion = '1.0'
        generatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
    }

    if (-not (Test-IsWindows)) {
        $payload['platform'] = 'NonWindows'
        $payload['error'] = 'Wired 802.1X diagnostics require Windows netsh and certificate APIs.'
    } else {
        $payload['platform'] = 'Windows'

        $interfacesRaw = Get-Lan8021xInterfacesRaw
        $profilesRaw   = Get-Lan8021xProfilesRaw
        $dot3Events    = Get-Lan8021xDot3Events
        $machineCerts  = Get-Lan8021xMachineCertificates

        $payload['netsh'] = [ordered]@{
            interfaces = $( if ($interfacesRaw) {
                if ($interfacesRaw -is [pscustomobject] -and $interfacesRaw.PSObject.Properties['Error'] -and $interfacesRaw.Error) {
                    $interfacesRaw
                } else {
                    [ordered]@{ lines = ConvertTo-Lan8021xLines -Value $interfacesRaw }
                }
            } else {
                $null
            } )
            profiles = $( if ($profilesRaw) {
                if ($profilesRaw -is [pscustomobject] -and $profilesRaw.PSObject.Properties['Error'] -and $profilesRaw.Error) {
                    $profilesRaw
                } else {
                    [ordered]@{ lines = ConvertTo-Lan8021xLines -Value $profilesRaw }
                }
            } else {
                $null
            } )
        }

        $payload['events'] = [ordered]@{
            dot3svcOperational = $dot3Events
        }

        $payload['certificates'] = [ordered]@{
            machine = $machineCerts
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'lan-8021x.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
