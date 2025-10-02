<#!
.SYNOPSIS
    Collects wireless LAN diagnostics including interface status, stored profiles, and visible network capabilities.
.DESCRIPTION
    Executes Windows netsh commands (requires administrative privileges) to gather Wi-Fi security details used by analyzers
    to evaluate encryption posture. When run on non-Windows platforms, the collector returns a placeholder payload noting that
    wireless data is unavailable.
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

function Get-WlanInterfacesRaw {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'wlan','show','interfaces' -SourceLabel 'netsh wlan show interfaces'
}

function Get-WlanNetworksRaw {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'wlan','show','networks','mode=bssid' -SourceLabel 'netsh wlan show networks'
}

function Get-WlanProfilesRaw {
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'wlan','show','profiles' -SourceLabel 'netsh wlan show profiles'
}

function Get-WlanProfileNames {
    param([object]$ProfilesRaw)

    $names = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $ProfilesRaw) { return $names.ToArray() }

    $lines = @()
    if ($ProfilesRaw -is [string]) {
        $lines = @($ProfilesRaw)
    } elseif ($ProfilesRaw -is [System.Collections.IEnumerable]) {
        foreach ($line in $ProfilesRaw) {
            if ($null -ne $line) { $lines += [string]$line }
        }
    }

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -match '^(All User Profile|User Profile)\s*:\s*(.+)$') {
            $value = $Matches[2].Trim()
            if ($value -and -not $names.Contains($value)) { $names.Add($value) }
        }
    }

    return $names.ToArray()
}

function Get-WlanProfileDetail {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $nameArg = ('name="{0}"' -f $Name)
    return Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'wlan','show','profile',$nameArg,'key=clear' -SourceLabel 'netsh wlan show profile'
}

function Get-WlanProfileXml {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $tempFolder = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString())
    try {
        $null = New-Item -Path $tempFolder -ItemType Directory -Force -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ Xml = $null; Error = $_.Exception.Message }
    }

    $nameArg = ('name="{0}"' -f $Name)
    $folderArg = ('folder="{0}"' -f $tempFolder)
    $exportResult = Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList 'wlan','export','profile',$nameArg,$folderArg,'key=clear' -SourceLabel 'netsh wlan export profile'

    $xmlContent = $null
    $errorMessage = $null

    if ($exportResult -is [pscustomobject] -and $exportResult.PSObject.Properties['Error'] -and $exportResult.Error) {
        $errorMessage = $exportResult.Error
    } else {
        try {
            $files = Get-ChildItem -Path $tempFolder -Filter '*.xml' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending
            $file = $files | Select-Object -First 1
            if ($file) {
                $xmlContent = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            } else {
                $errorMessage = 'Profile export did not create an XML file.'
            }
        } catch {
            $errorMessage = $_.Exception.Message
        }
    }

    try {
        Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
    }

    return [pscustomobject]@{
        Xml   = $xmlContent
        Error = $errorMessage
    }
}

function Invoke-Main {
    if (-not (Test-IsWindows)) {
        $payload = [ordered]@{
            Error = 'Wireless diagnostics require Windows netsh (collector skipped).'
        }
        $result = New-CollectorMetadata -Payload $payload
        $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'wlan.json' -Data $result -Depth 4
        Write-Output $outputPath
        return
    }

    $interfaces = Get-WlanInterfacesRaw
    $networks = Get-WlanNetworksRaw
    $profilesSummary = Get-WlanProfilesRaw
    $profileNames = Get-WlanProfileNames -ProfilesRaw $profilesSummary

    $details = [System.Collections.Generic.List[object]]::new()
    foreach ($profileName in $profileNames) {
        $detail = [ordered]@{ Name = $profileName }

        $profileOutput = Get-WlanProfileDetail -Name $profileName
        if ($profileOutput) { $detail['ShowProfile'] = $profileOutput }

        $xmlInfo = Get-WlanProfileXml -Name $profileName
        if ($xmlInfo.Xml) { $detail['Xml'] = $xmlInfo.Xml }
        if ($xmlInfo.Error) { $detail['XmlError'] = $xmlInfo.Error }

        $details.Add([pscustomobject]$detail) | Out-Null
    }

    $payload = [ordered]@{
        Interfaces = $interfaces
        Networks   = $networks
        Profiles   = [ordered]@{
            Summary = $profilesSummary
            Details = $details.ToArray()
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'wlan.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
