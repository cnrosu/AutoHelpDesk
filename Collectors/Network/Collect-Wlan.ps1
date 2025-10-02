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

$collectorRoot = Split-Path -Path $PSScriptRoot -Parent
$repositoryRoot = Split-Path -Path $collectorRoot -Parent
$passwordStrengthModule = Join-Path -Path $repositoryRoot -ChildPath 'Modules\\PasswordStrength\\PasswordStrength.psm1'
if (Test-Path -LiteralPath $passwordStrengthModule) {
    Import-Module -Name $passwordStrengthModule -ErrorAction Stop
}

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

function ConvertTo-WlanLines {
    param($Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [string]) { return @($Value) }

    if ($Value -is [System.Collections.IEnumerable]) {
        $lines = @()
        foreach ($item in $Value) {
            if ($null -ne $item) { $lines += [string]$item }
        }
        return $lines
    }

    return @([string]$Value)
}

function Sanitize-WlanProfileOutput {
    param($Output)

    $lines = ConvertTo-WlanLines $Output
    $sanitized = @()
    $passphrase = $null

    foreach ($line in $lines) {
        if ($null -eq $line) { continue }
        $text = [string]$line
        if ($text -match '^(\s*Key\s+Content\s*:\s*)(.+)$') {
            if (-not $passphrase) { $passphrase = $Matches[2].Trim() }
            $sanitized += ($Matches[1] + '[REDACTED]')
        } else {
            $sanitized += $text
        }
    }

    return [pscustomobject]@{
        Lines      = $sanitized
        Passphrase = $passphrase
    }
}

function Sanitize-WlanProfileXml {
    param([string]$Xml)

    if (-not $Xml) {
        return [pscustomobject]@{ Text = $null; Passphrase = $null }
    }

    $captured = $null
    $pattern = '(?is)(<\s*keyMaterial\s*>)(.*?)(<\s*/\s*keyMaterial\s*>)'

    $sanitized = [regex]::Replace($Xml, $pattern, {
        param($match)
        if (-not $captured) {
            $captured = $match.Groups[2].Value.Trim()
        }
        return $match.Groups[1].Value + '[REDACTED]' + $match.Groups[3].Value
    })

    return [pscustomobject]@{
        Text       = $sanitized
        Passphrase = $captured
    }
}

function Format-WlanStrengthValue {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [double]) {
        if ([double]::IsNaN($Value)) { return 'NaN' }
        if ([double]::IsInfinity($Value)) { return 'Inf' }
        if ([math]::Abs($Value) -ge 1e6) {
            return [string]([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.###E+0}' -f $Value)
        }
        return [string]([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.###}' -f $Value)
    }

    return $Value
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

        $passphrase = $null

        $profileOutput = Get-WlanProfileDetail -Name $profileName
        if ($profileOutput) {
            $sanitizedOutput = Sanitize-WlanProfileOutput -Output $profileOutput
            if ($sanitizedOutput -and $sanitizedOutput.Lines) {
                $detail['ShowProfile'] = $sanitizedOutput.Lines
            }
            if (-not $passphrase -and $sanitizedOutput.Passphrase) {
                $passphrase = $sanitizedOutput.Passphrase
            }
        }

        $xmlInfo = Get-WlanProfileXml -Name $profileName
        if ($xmlInfo.Xml) {
            $sanitizedXml = Sanitize-WlanProfileXml -Xml $xmlInfo.Xml
            if ($sanitizedXml -and $sanitizedXml.Text) {
                $detail['Xml'] = $sanitizedXml.Text
            }
            if (-not $passphrase -and $sanitizedXml.Passphrase) {
                $passphrase = $sanitizedXml.Passphrase
            }
        }
        if ($xmlInfo.Error) { $detail['XmlError'] = $xmlInfo.Error }

        if ($passphrase) {
            try {
                $strength = Test-PasswordStrength -Password $passphrase
                if ($strength) {
                    $metrics = [ordered]@{
                        Score              = $strength.Score
                        Category           = $strength.Category
                        Length             = $strength.Length
                        AlphabetSizeUsed   = $strength.AlphabetSizeUsed
                        EstimatedBits      = $strength.EstimatedBits
                        EstimatedGuesses   = $strength.EstimatedGuesses
                        CrackTimeOnline    = Format-WlanStrengthValue -Value $strength.CrackTimeOnline_s
                        CrackTimeOffline   = Format-WlanStrengthValue -Value $strength.CrackTimeOffline_s
                        Warnings           = $strength.Warnings
                        Suggestions        = $strength.Suggestions
                        Signals            = $strength.Signals
                        BaselineBits       = $strength.BaselineBits
                        PenaltyBits        = $strength.PenaltyBits
                        Notes              = $strength.Notes
                    }
                    $detail['PassphraseMetrics'] = $metrics
                }
            } catch {
                $detail['PassphraseMetricsError'] = $_.Exception.Message
            }
        }
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
