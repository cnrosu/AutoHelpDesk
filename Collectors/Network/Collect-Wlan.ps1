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
    Import-Module -Name $passwordStrengthModule -ErrorAction Stop -Verbose:$false
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

    $lines = [System.Collections.Generic.List[string]]::new()
    if ($ProfilesRaw -is [string]) {
        [void]$lines.Add([string]$ProfilesRaw)
    } elseif ($ProfilesRaw -is [System.Collections.IEnumerable]) {
        foreach ($line in $ProfilesRaw) {
            if ($null -ne $line) { [void]$lines.Add([string]$line) }
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

$script:WlanProfileXmlExportState = $null

function Initialize-WlanProfileXmlExport {
    if ($script:WlanProfileXmlExportState -and $script:WlanProfileXmlExportState.Initialized) { return }

    $state = [ordered]@{
        Initialized = $true
        Folder      = $null
        ExportError = $null
        Profiles    = @{}
        Errors      = [System.Collections.Generic.List[string]]::new()
    }

    $tempFolder = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString())
    try {
        $null = New-Item -Path $tempFolder -ItemType Directory -Force -ErrorAction Stop
    } catch {
        $state.ExportError = $_.Exception.Message
        [void]$state.Errors.Add($state.ExportError)
        $script:WlanProfileXmlExportState = $state
        return
    }

    $state.Folder = $tempFolder

    $folderArg = ('folder="{0}"' -f $tempFolder)
    $argumentList = @('wlan','export','profile',$folderArg,'key=clear')
    $exportResult = Invoke-CollectorNativeCommand -FilePath 'netsh.exe' -ArgumentList $argumentList -SourceLabel 'netsh wlan export profile'

    if ($exportResult -is [pscustomobject] -and $exportResult.PSObject.Properties['Error'] -and $exportResult.Error) {
        $state.ExportError = $exportResult.Error
        [void]$state.Errors.Add($state.ExportError)
        $script:WlanProfileXmlExportState = $state
        return
    }

    try {
        $files = Get-ChildItem -Path $tempFolder -Filter '*.xml' -File -ErrorAction Stop
        if (-not $files -or $files.Count -eq 0) {
            $state.ExportError = 'Profile export did not create an XML file.'
            [void]$state.Errors.Add($state.ExportError)
            $script:WlanProfileXmlExportState = $state
            return
        }

        foreach ($file in $files) {
            if (-not $file) { continue }

            $xmlContent = $null
            try {
                $xmlContent = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            } catch {
                $profileKey = $file.BaseName.ToLowerInvariant()
                if (-not $state.Profiles.ContainsKey($profileKey)) {
                    $state.Profiles[$profileKey] = [pscustomobject]@{ Xml = $null; Error = $_.Exception.Message }
                }
                [void]$state.Errors.Add($_.Exception.Message)
                continue
            }

            $profileName = $null
            try {
                $xmlDoc = [xml]$xmlContent
                if ($xmlDoc -and $xmlDoc.WLANProfile -and $xmlDoc.WLANProfile.name) {
                    $profileName = [string]$xmlDoc.WLANProfile.name
                }
            } catch {
                $profileKey = $file.BaseName.ToLowerInvariant()
                if (-not $state.Profiles.ContainsKey($profileKey)) {
                    $state.Profiles[$profileKey] = [pscustomobject]@{ Xml = $null; Error = $_.Exception.Message }
                }
                [void]$state.Errors.Add($_.Exception.Message)
                continue
            }

            if ($profileName) {
                $profileKey = $profileName.Trim().ToLowerInvariant()
                if (-not $state.Profiles.ContainsKey($profileKey)) {
                    $state.Profiles[$profileKey] = [pscustomobject]@{ Xml = $xmlContent; Error = $null }
                }
            }
        }
    } catch {
        $state.ExportError = $_.Exception.Message
        [void]$state.Errors.Add($_.Exception.Message)
    }

    $script:WlanProfileXmlExportState = $state
}

function Get-WlanProfileXml {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    Initialize-WlanProfileXmlExport

    $state = $script:WlanProfileXmlExportState
    if (-not $state) {
        return [pscustomobject]@{ Xml = $null; Error = 'Profile export state was not initialized.' }
    }

    if ($state.ExportError) {
        return [pscustomobject]@{ Xml = $null; Error = $state.ExportError }
    }

    $profileKey = $Name.Trim().ToLowerInvariant()
    if ($state.Profiles.ContainsKey($profileKey)) {
        return $state.Profiles[$profileKey]
    }

    $errorMessage = 'Profile export did not create an XML file for profile "{0}".' -f $Name
    if ($state.Errors -and $state.Errors.Count -gt 0) {
        try {
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            $unique = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in $state.Errors) {
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }
                if ($seen.Add($entry)) {
                    [void]$unique.Add($entry)
                }
            }
            if ($unique.Count -gt 0) {
                $errorMessage = '{0} Additional errors: {1}' -f $errorMessage, ($unique.ToArray() -join '; ')
            }
        } catch {
        }
    }

    return [pscustomobject]@{
        Xml   = $null
        Error = $errorMessage
    }
}

function Dispose-WlanProfileXmlExport {
    if ($script:WlanProfileXmlExportState -and $script:WlanProfileXmlExportState.Folder) {
        try {
            Remove-Item -Path $script:WlanProfileXmlExportState.Folder -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }

    $script:WlanProfileXmlExportState = $null
}

function ConvertTo-WlanLines {
    param($Value)

    if ($null -eq $Value) { return @() }

    if ($Value -is [string]) { return ,([string]$Value) }

    if ($Value -is [System.Collections.IEnumerable]) {
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) {
            if ($null -ne $item) { [void]$lines.Add([string]$item) }
        }
        return $lines.ToArray()
    }

    return ,([string]$Value)
}

function Sanitize-WlanProfileOutput {
    param($Output)

    $lines = ConvertTo-WlanLines $Output
    $sanitized = [System.Collections.Generic.List[string]]::new()
    $passphrase = $null

    foreach ($line in $lines) {
        if ($null -eq $line) { continue }
        $text = [string]$line
        if ($text -match '^(\s*Key\s+Content\s*:\s*)(.+)$') {
            if (-not $passphrase) { $passphrase = $Matches[2].Trim() }
            [void]$sanitized.Add($Matches[1] + '[REDACTED]')
        } else {
            [void]$sanitized.Add($text)
        }
    }

    return [pscustomobject]@{
        Lines      = $sanitized.ToArray()
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

    try {
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
    } finally {
        Dispose-WlanProfileXmlExport
    }
}

Invoke-Main
