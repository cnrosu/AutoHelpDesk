function Normalize-Windows11CpuName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    $normalized = $Name.ToLowerInvariant()
    $normalized = $normalized -replace '\(r\)', ''
    $normalized = $normalized -replace '\(tm\)', ''
    $normalized = $normalized -replace '®', ''
    $normalized = $normalized -replace '™', ''
    $normalized = $normalized -replace '\b\d+(st|nd|rd|th)\s+gen(eration)?\b', ''
    $normalized = $normalized -replace '\bgeneration\s+\d+\b', ''
    $normalized = $normalized -replace '\bgen\s+\d+\b', ''
    $normalized = $normalized -replace '\bintel\b', ''
    $normalized = $normalized -replace '\bamd\b', ''
    $normalized = $normalized -replace '\bqualcomm\b', ''
    $normalized = $normalized -replace '\bsnapdragon\b', ''
    $normalized = $normalized -replace '\bapu\b', ''
    $normalized = $normalized -replace '\bprocessor\b', ''
    $normalized = $normalized -replace '\bcpu\b', ''
    $normalized = $normalized -replace '\bwith\s+radeon\s+graphics\b', ''
    $normalized = $normalized -replace '\bwith\s+vega\s+graphics\b', ''
    $normalized = $normalized -replace '\bwith\s+radeon\s+vega\s+graphics\b', ''
    $normalized = $normalized -replace '\bwith\s+intel\s+uhd\s+graphics\b', ''
    $normalized = $normalized -replace '\bwith\s+intel\s+iris\s+xe\s+graphics\b', ''
    $normalized = $normalized -replace '\bwith\s+intel\s+iris\s+graphics\b', ''
    $normalized = $normalized -replace '\bwith\s+radeon\s+graphics\s+\d+\w*\b', ''
    $normalized = $normalized -replace '\b[0-9]+\s*-?core\b', ''
    $normalized = $normalized -replace '\b[0-9]+\s*-?thread\b', ''
    $normalized = $normalized -replace '@\s*[0-9\.]+\s*ghz', ''
    $normalized = $normalized -replace '\s+', ' '
    $normalized = $normalized.Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) { return $null }
    return $normalized
}

$script:Windows11CpuCatalog = $null
$script:Windows11CpuCatalogLookup = $null
$script:Windows11CpuCatalogError = $null

function Initialize-Windows11CpuCatalog {
    if ($script:Windows11CpuCatalog -or $script:Windows11CpuCatalogError) { return }

    $heuristicsRoot = Split-Path -Path $PSScriptRoot -Parent
    $analyzerRoot = Split-Path -Path $heuristicsRoot -Parent
    $catalogPath = Join-Path -Path $analyzerRoot -ChildPath 'Data/Windows11SupportedCpus.json'

    if (-not (Test-Path -LiteralPath $catalogPath)) {
        $script:Windows11CpuCatalogError = "Windows 11 CPU catalog not found at '$catalogPath'."
        return
    }

    try {
        $raw = Get-Content -LiteralPath $catalogPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            $script:Windows11CpuCatalogError = 'Windows 11 CPU catalog file is empty.'
            return
        }

        $script:Windows11CpuCatalog = $raw | ConvertFrom-Json -ErrorAction Stop
        $lookup = @{}
        if ($script:Windows11CpuCatalog) {
            foreach ($property in $script:Windows11CpuCatalog.PSObject.Properties) {
                $vendor = $property.Name
                foreach ($entry in @($property.Value)) {
                    if (-not $entry) { continue }
                    $normalized = Normalize-Windows11CpuName -Name ([string]$entry)
                    if (-not $normalized) { continue }
                    if (-not $lookup.ContainsKey($normalized)) {
                        $lookup[$normalized] = $vendor
                    }
                }
            }
        }
        $script:Windows11CpuCatalogLookup = $lookup
    } catch {
        $script:Windows11CpuCatalogError = $_.Exception.Message
    }
}

function Test-Windows11CpuSupported {
    param([string]$Name)

    Initialize-Windows11CpuCatalog

    if ($script:Windows11CpuCatalogError) {
        return [pscustomobject]@{
            Supported = $null
            Vendor    = $null
            Message   = $script:Windows11CpuCatalogError
        }
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return [pscustomobject]@{ Supported = $null; Vendor = $null; Message = 'Processor name unavailable.' }
    }

    $normalized = Normalize-Windows11CpuName -Name $Name
    if (-not $normalized) {
        return [pscustomobject]@{ Supported = $null; Vendor = $null; Message = 'Processor name normalization failed.' }
    }

    if ($script:Windows11CpuCatalogLookup -and $script:Windows11CpuCatalogLookup.ContainsKey($normalized)) {
        return [pscustomobject]@{
            Supported = $true
            Vendor    = $script:Windows11CpuCatalogLookup[$normalized]
            Message   = $null
        }
    }

    return [pscustomobject]@{
        Supported = $false
        Vendor    = $null
        Message   = $null
    }
}

function ConvertTo-Windows11Array {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }

    return @($Value)
}

function Invoke-SystemWindows11UpgradeChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Win11' -Message 'Starting Windows 11 upgrade readiness evaluation'

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved system artifact' -Data ([ordered]@{ Found = [bool]$systemArtifact })

    if (-not $systemArtifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Windows 11 readiness data missing, so upgrade blockers may be hidden.' -Subcategory 'Windows 11 Upgrade'
        return
    }

    $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved system payload' -Data ([ordered]@{ HasPayload = [bool]$systemPayload })

    $firmwareArtifact = Get-AnalyzerArtifact -Context $Context -Name 'firmware'
    $firmwarePayload = $null
    if ($firmwareArtifact) {
        $firmwarePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $firmwareArtifact)
    }
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved firmware payload' -Data ([ordered]@{ HasPayload = [bool]$firmwarePayload })

    $storageArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage'
    $storagePayload = $null
    if ($storageArtifact) {
        $storagePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $storageArtifact)
    }
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved storage payload' -Data ([ordered]@{ HasPayload = [bool]$storagePayload })

    $tpmArtifact = Get-AnalyzerArtifact -Context $Context -Name 'tpm'
    $tpmPayload = $null
    if ($tpmArtifact) {
        $tpmPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $tpmArtifact)
    }
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved TPM payload' -Data ([ordered]@{ HasPayload = [bool]$tpmPayload })

    $vbArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vbshvci'
    $vbPayload = $null
    if ($vbArtifact) {
        $vbPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $vbArtifact)
    }
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved VBS payload' -Data ([ordered]@{ HasPayload = [bool]$vbPayload })

    $measuredBootArtifact = Get-AnalyzerArtifact -Context $Context -Name 'measuredboot'
    $measuredBootPayload = $null
    if ($measuredBootArtifact) {
        $measuredBootPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $measuredBootArtifact)
    }
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved measured boot payload' -Data ([ordered]@{ HasPayload = [bool]$measuredBootPayload })

    $bitlockerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'bitlocker'
    $bitlockerPayload = $null
    if ($bitlockerArtifact) {
        $bitlockerPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $bitlockerArtifact)
    }
    Write-HeuristicDebug -Source 'System/Win11' -Message 'Resolved BitLocker payload' -Data ([ordered]@{ HasPayload = [bool]$bitlockerPayload })

    $requirementFailures = New-Object System.Collections.Generic.List[pscustomobject]
    $severityRank = @{ critical = 5; high = 4; medium = 3; low = 2; info = 1 }
    $highestSeverity = $null

    $os = $null
    $computerSystem = $null
    $processors = @()
    $alreadyWindows11 = $false
    if ($systemPayload) {
        if ($systemPayload.PSObject.Properties['OperatingSystem'] -and -not $systemPayload.OperatingSystem.Error) {
            $os = $systemPayload.OperatingSystem
        }
        if ($systemPayload.PSObject.Properties['ComputerSystem'] -and -not $systemPayload.ComputerSystem.Error) {
            $computerSystem = $systemPayload.ComputerSystem
        }
        if ($systemPayload.PSObject.Properties['Processors']) {
            $processors = ConvertTo-Windows11Array $systemPayload.Processors
        }
    }

    $systemInfoLines = Get-SystemInfoLines -Payload $systemPayload

    $systemDrive = 'C'
    if ($os -and $os.PSObject.Properties['SystemDrive'] -and $os.SystemDrive) {
        $driveText = [string]$os.SystemDrive
        if (-not [string]::IsNullOrWhiteSpace($driveText)) {
            $normalizedDrive = $driveText.Trim()
            $normalizedDrive = $normalizedDrive.TrimEnd(':')
            if ($normalizedDrive) { $systemDrive = $normalizedDrive }
        }
    }

    $updateSeverity = {
        param([ref]$Current, [hashtable]$Rank, [string]$Candidate)
        if (-not $Candidate) { return }
        if (-not $Rank.ContainsKey($Candidate)) { return }
        if (-not $Current.Value) {
            $Current.Value = $Candidate
            return
        }
        $existing = $Current.Value
        if (-not $Rank.ContainsKey($existing)) {
            $Current.Value = $Candidate
            return
        }
        if ($Rank[$Candidate] -gt $Rank[$existing]) {
            $Current.Value = $Candidate
        }
    }

    $highestSeverityRef = [ref]$highestSeverity
    $cpuStatus = 'Unknown'
    $cpuDetailsBuilder = [System.Text.StringBuilder]::new()
    $cpuMet = $null
    $cpuErrors = [System.Collections.Generic.List[string]]::new()

    if ($processors.Count -eq 0) {
        $cpuErrors.Add('Processor inventory not collected.') | Out-Null
    } else {
        $unsupported = [System.Collections.Generic.List[string]]::new()
        $supportedNames = [System.Collections.Generic.List[string]]::new()
        foreach ($processor in $processors) {
            if (-not $processor) { continue }
            if ($processor.PSObject.Properties['Error'] -and $processor.Error) {
                $cpuErrors.Add([string]$processor.Error) | Out-Null
                continue
            }
            $name = $null
            if ($processor.PSObject.Properties['Name']) { $name = [string]$processor.Name }
            $check = Test-Windows11CpuSupported -Name $name
            if ($check.Message) { $cpuErrors.Add($check.Message) | Out-Null }
            if ($check.Supported -eq $true) {
                $supportedNames.Add($name) | Out-Null
            } elseif ($check.Supported -eq $false) {
                $label = if ($name) { $name } else { 'Unnamed processor' }
                $unsupported.Add($label) | Out-Null
            }
        }

        if ($cpuErrors.Count -gt 0 -and $unsupported.Count -eq 0 -and $supportedNames.Count -eq 0) {
            $cpuMet = $null
        } elseif ($unsupported.Count -gt 0) {
            $cpuMet = $false
        } elseif ($supportedNames.Count -gt 0) {
            $cpuMet = $true
        }

        if ($supportedNames.Count -gt 0) {
            [void]$cpuDetailsBuilder.Append('Supported CPU(s): ')
            [void]$cpuDetailsBuilder.Append(($supportedNames.ToArray() -join ', '))
        }
        if ($unsupported.Count -gt 0) {
            if ($cpuDetailsBuilder.Length -gt 0) { [void]$cpuDetailsBuilder.Append('; ') }
            [void]$cpuDetailsBuilder.Append('Unsupported CPU(s): ')
            [void]$cpuDetailsBuilder.Append(($unsupported.ToArray() -join ', '))
        }
    }

    if ($cpuErrors.Count -gt 0) {
        if ($cpuDetailsBuilder.Length -gt 0) { [void]$cpuDetailsBuilder.Append('; ') }
        [void]$cpuDetailsBuilder.Append(("Errors: {0}" -f ($cpuErrors.ToArray() -join '; ')))
    }

    $cpuStatus = if ($cpuMet -eq $true) { 'Pass' } elseif ($cpuMet -eq $false) { 'Fail' } else { 'Unknown' }
    $cpuDetails = if ($cpuDetailsBuilder.Length -gt 0) { $cpuDetailsBuilder.ToString() } else { 'Processor compatibility assessment inconclusive.' }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: CPU compatibility' -Status $cpuStatus -Details $cpuDetails
    if ($cpuMet -eq $false) {
        $severity = 'critical'
        $description = if ($cpuDetailsBuilder.Length -gt 0) {
            'Windows 11 setup blocks unsupported CPUs. ' + $cpuDetailsBuilder.ToString()
        } else {
            'Windows 11 setup blocks unsupported CPUs, and the processor was not found in the Microsoft-supported catalog.'
        }
        $remediation = 'Replace the processor or move the workload to hardware with a Microsoft-supported CPU before upgrading.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'CPU compatibility'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }
    $architectureStatus = 'Unknown'
    $architectureDetails = 'Operating system architecture not reported.'
    $architectureMet = $null
    if ($os) {
        $architecture = $null
        if ($os.PSObject.Properties['OSArchitecture']) { $architecture = [string]$os.OSArchitecture }
        if ($architecture) {
            $archLower = $architecture.ToLowerInvariant()
            if ($archLower -match '64') {
                $architectureMet = $true
                $architectureStatus = 'Pass'
                $architectureDetails = "Reported architecture: $architecture"
            } elseif ($archLower -match 'arm') {
                $architectureMet = $true
                $architectureStatus = 'Pass'
                $architectureDetails = "Reported architecture: $architecture"
            } else {
                $architectureMet = $false
                $architectureStatus = 'Fail'
                $architectureDetails = "Reported architecture: $architecture"
            }
        }
    }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: 64-bit operating system' -Status $architectureStatus -Details $architectureDetails
    if ($architectureMet -eq $false) {
        $severity = 'critical'
        $description = 'Windows 11 requires a 64-bit operating system, but the collected data shows a non-64-bit build.'
        $remediation = 'Install a supported 64-bit edition of Windows before attempting the upgrade.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = '64-bit operating system'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $upgradeStatus = 'Unknown'
    $upgradeDetails = 'Unable to identify the current Windows edition.'
    $upgradeMet = $null
    if ($os) {
        $caption = if ($os.PSObject.Properties['Caption']) { [string]$os.Caption } else { $null }
        if ($caption) {
            $captionLower = $caption.ToLowerInvariant()
            if ($captionLower -match 'windows\s+11') {
                $upgradeMet = $true
                $upgradeStatus = 'Pass'
                $upgradeDetails = "Current OS already Windows 11 ($caption)."
                $alreadyWindows11 = $true
            } elseif ($captionLower -match 'windows\s+10' -or $captionLower -match 'windows\s+8(\.1)?') {
                $upgradeMet = $true
                $upgradeStatus = 'Pass'
                $upgradeDetails = "Detected upgrade-supported OS: $caption"
            } else {
                $upgradeMet = $false
                $upgradeStatus = 'Fail'
                $upgradeDetails = "Detected OS '$caption' is not on a supported upgrade path."
            }
        }
    }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: Supported upgrade path' -Status $upgradeStatus -Details $upgradeDetails
    if ($upgradeMet -eq $false) {
        $severity = 'critical'
        $description = $upgradeDetails
        $remediation = 'Upgrade to Windows 10, Windows 8, or Windows 8.1 64-bit before moving to Windows 11.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'Supported upgrade path'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    if ($alreadyWindows11) {
        Add-CategoryNormal -CategoryResult $Result -Title 'Already on Windows 11' -Evidence "Detected $caption." -Subcategory 'Windows 11 Upgrade'
        return $Result
    }

    $measuredSecureBoot = $null
    $measuredSecureBootEnabled = $null
    $measuredSecureBootError = $null
    if ($measuredBootPayload -and $measuredBootPayload.PSObject.Properties['SecureBoot']) {
        $measuredSecureBoot = $measuredBootPayload.SecureBoot
        if ($measuredSecureBoot) {
            if ($measuredSecureBoot.PSObject.Properties['Error'] -and $measuredSecureBoot.Error) {
                $measuredSecureBootError = [string]$measuredSecureBoot.Error
            } elseif ($measuredSecureBoot.PSObject.Properties['Enabled']) {
                $measuredSecureBootEnabled = [bool]$measuredSecureBoot.Enabled
            }
        }
    }

    $firm = $null
    if ($firmwarePayload -and $firmwarePayload.PSObject.Properties['Firmware']) {
        $firm = $firmwarePayload.Firmware
    }

    $firmwareMet = $null
    $firmwareStatus = 'Unknown'
    $firmwareDetailParts = [System.Collections.Generic.List[string]]::new()

    $uefi = $null
    if ($firm -and $firm.PSObject.Properties['UefiDetected']) {
        $uefiValue = $firm.UefiDetected
        if ($null -ne $uefiValue) { $uefi = [bool]$uefiValue }
    }

    if ($uefi -eq $true) {
        $firmwareMet = $true
        $firmwareStatus = 'Pass'
    } elseif ($uefi -eq $false) {
        $firmwareMet = $false
        $firmwareStatus = 'Fail'
    }

    if ($firm) {
        if ($firm.PSObject.Properties['PEFirmwareType']) {
            $peValue = $firm.PEFirmwareType
            if ($null -ne $peValue) { $firmwareDetailParts.Add("PEFirmwareType registry value: $peValue") | Out-Null }
        }
        if ($firm.PSObject.Properties['UefiSources']) {
            $sources = ConvertTo-Windows11Array $firm.UefiSources
            if ($sources.Count -gt 0) {
                $firmwareDetailParts.Add("UEFI sources: " + ($sources -join ', ')) | Out-Null
            }
        }
        if ($firm.PSObject.Properties['EspDetected']) {
            $espDetected = $firm.EspDetected
            if ($espDetected -eq $true) {
                $firmwareDetailParts.Add('EFI system partition detected.') | Out-Null
                if ($null -eq $firmwareMet) {
                    $firmwareMet = $true
                    $firmwareStatus = 'Pass'
                }
            } elseif ($espDetected -eq $false) {
                $firmwareDetailParts.Add('EFI system partition not detected.') | Out-Null
            }
        }
        if ($firm.PSObject.Properties['Error'] -and $firm.Error) {
            $firmwareDetailParts.Add("Firmware detection error: $($firm.Error)") | Out-Null
        }
    }

    if ($null -eq $firmwareMet) {
        $biosMode = Get-SystemInfoValue -Lines $systemInfoLines -Label 'BIOS Mode'
        if ($biosMode) {
            $firmwareDetailParts.Add("BIOS Mode (systeminfo): $biosMode") | Out-Null
            if ($biosMode -match '(?i)uefi') {
                $firmwareMet = $true
                $firmwareStatus = 'Pass'
            } elseif ($biosMode -match '(?i)legacy|bios') {
                $firmwareMet = $false
                $firmwareStatus = 'Fail'
            }
        }
    }

    if ($firmwareDetailParts.Count -eq 0) {
        $firmwareDetailParts.Add('Firmware mode not reported.') | Out-Null
    }

    $firmwareDetails = $firmwareDetailParts.ToArray() -join '; '
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: UEFI firmware' -Status $firmwareStatus -Details $firmwareDetails
    if ($firmwareMet -eq $false) {
        $severity = 'critical'
        $description = 'Windows 11 setup requires UEFI firmware, but the device appears to be running in legacy BIOS mode.'
        $remediation = 'Switch the system firmware to UEFI mode before starting the Windows 11 upgrade.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'UEFI firmware'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $secureBootMet = $null
    $secureBootStatus = 'Unknown'
    $secureBootDetailParts = [System.Collections.Generic.List[string]]::new()

    $sb = $firm?.SecureBoot
    $sbConfirm = $null
    $sbWmi = $null
    $sbReg = $null
    $sbErr = $null
    if ($sb) {
        if ($sb.PSObject.Properties['ConfirmSecureBootUEFI']) {
            $sbConfirmValue = $sb.ConfirmSecureBootUEFI
            if ($null -ne $sbConfirmValue) { $sbConfirm = [bool]$sbConfirmValue }
        }
        if ($sb.PSObject.Properties['MS_SecureBootEnabled']) {
            $sbWmiValue = $sb.MS_SecureBootEnabled
            if ($null -ne $sbWmiValue) { $sbWmi = [bool]$sbWmiValue }
        }
        if ($sb.PSObject.Properties['RegistryEnabled']) {
            $sbRegValue = $sb.RegistryEnabled
            if ($null -ne $sbRegValue) { $sbReg = [bool]$sbRegValue }
        }
        if ($sb.PSObject.Properties['Error'] -and $sb.Error) {
            $sbErr = [string]$sb.Error
        }
    }

    if ($sbConfirm -is [bool]) {
        $secureBootMet = $sbConfirm
        $secureBootStatus = if ($sbConfirm) { 'Pass' } else { 'Fail' }
        $secureBootDetailParts.Add("Confirm-SecureBootUEFI: $sbConfirm") | Out-Null
    } elseif ($sbWmi -is [bool]) {
        $secureBootMet = $sbWmi
        $secureBootStatus = if ($sbWmi) { 'Pass' } else { 'Fail' }
        $secureBootDetailParts.Add("MS_SecureBoot.SecureBootEnabled: $sbWmi") | Out-Null
    } elseif ($sbReg -is [bool]) {
        $secureBootMet = $sbReg
        $secureBootStatus = if ($sbReg) { 'Pass' } else { 'Fail' }
        $secureBootDetailParts.Add("Registry UEFISecureBootEnabled: $sbReg") | Out-Null
    }

    if ($null -eq $secureBootMet -and $measuredSecureBootEnabled -ne $null) {
        $secureBootMet = [bool]$measuredSecureBootEnabled
        $secureBootStatus = if ($secureBootMet) { 'Pass' } else { 'Fail' }
        $secureBootDetailParts.Add("Measured boot Secure Boot enabled: $measuredSecureBootEnabled") | Out-Null
    }

    if ($null -eq $secureBootMet) {
        $secureBootState = Get-SystemInfoValue -Lines $systemInfoLines -Label 'Secure Boot State'
        if ($secureBootState) {
            $secureBootDetailParts.Add("Secure Boot State (systeminfo): $secureBootState") | Out-Null
            if ($secureBootState -match '^(?i)(on|enabled|active)$') {
                $secureBootMet = $true
                $secureBootStatus = 'Pass'
            } elseif ($secureBootState -match '^(?i)(off|disabled)$') {
                $secureBootMet = $false
                $secureBootStatus = 'Fail'
            }
        }
    }

    if ($sbErr) {
        $secureBootDetailParts.Add("Secure Boot verification error: $sbErr") | Out-Null
    }
    if ($measuredSecureBootError) {
        $secureBootDetailParts.Add("Measured boot Secure Boot error: $measuredSecureBootError") | Out-Null
    }
    if ($secureBootDetailParts.Count -eq 0) {
        $secureBootDetailParts.Add('Secure Boot signals not reported.') | Out-Null
    }

    $secureBootDetails = $secureBootDetailParts.ToArray() -join '; '
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: Secure Boot' -Status $secureBootStatus -Details $secureBootDetails
    if ($secureBootMet -eq $false) {
        $severity = 'high'
        $description = 'Secure Boot appears disabled, so Windows 11 setup will block the upgrade until firmware protections are enabled.'
        $remediation = 'Enable Secure Boot in UEFI firmware before attempting the upgrade.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'Secure Boot'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $tpmMet = $null
    $tpmStatus = 'Unknown'
    $tpmDetailsLines = [System.Collections.Generic.List[string]]::new()

    $tp = $null
    if ($tpmPayload -and $tpmPayload.PSObject.Properties['Tpm']) {
        $tp = $tpmPayload.Tpm
    }

    if (-not $tp) {
        $tpmDetailsLines.Add('TPM artifact missing.') | Out-Null
    } else {
        if ($tp.PSObject.Properties['Error'] -and $tp.Error) {
            $tpmDetailsLines.Add("TPM query error: $($tp.Error)") | Out-Null
        }

        $tpm = $null
        if ($tp.PSObject.Properties['GetTpm']) { $tpm = $tp.GetTpm }
        $win32 = $null
        if ($tp.PSObject.Properties['Win32_Tpm']) { $win32 = $tp.Win32_Tpm }

        $present = $null
        $ready = $null
        $enabled = $null
        $activated = $null
        $specVersion = $null

        if ($tpm) {
            if ($tpm.PSObject.Properties['TpmPresent'] -and $tpm.TpmPresent -ne $null) { $present = [bool]$tpm.TpmPresent }
            if ($tpm.PSObject.Properties['TpmReady'] -and $tpm.TpmReady -ne $null) { $ready = [bool]$tpm.TpmReady }
            if ($tpm.PSObject.Properties['TpmEnabled'] -and $tpm.TpmEnabled -ne $null) { $enabled = [bool]$tpm.TpmEnabled }
            if ($tpm.PSObject.Properties['TpmActivated'] -and $tpm.TpmActivated -ne $null) { $activated = [bool]$tpm.TpmActivated }
            if ($tpm.PSObject.Properties['SpecVersion'] -and $tpm.SpecVersion) { $specVersion = [string]$tpm.SpecVersion }
        }

        $win32Entries = @()
        if ($win32) {
            if ($win32 -is [System.Collections.IEnumerable] -and -not ($win32 -is [string])) {
                $win32Entries = @($win32)
            } else {
                $win32Entries = @($win32)
            }
        }

        foreach ($entry in $win32Entries) {
            if (-not $entry) { continue }
            if ($null -eq $present) {
                if ($entry.PSObject.Properties['IsEnabled_InitialValue'] -and $entry.IsEnabled_InitialValue -ne $null) {
                    $present = $true
                } elseif ($entry.PSObject.Properties['ManufacturerId'] -and $entry.ManufacturerId -ne $null) {
                    $present = $true
                }
            }
            if ($entry.PSObject.Properties['IsEnabled_InitialValue'] -and $entry.IsEnabled_InitialValue -ne $null) {
                $enabled = if ($entry.IsEnabled_InitialValue) { $true } elseif ($enabled -ne $true) { $false } else { $enabled }
            }
            if ($entry.PSObject.Properties['IsActivated_InitialValue'] -and $entry.IsActivated_InitialValue -ne $null) {
                $activated = if ($entry.IsActivated_InitialValue) { $true } elseif ($activated -ne $true) { $false } else { $activated }
            }
            if ($null -eq $specVersion -and $entry.PSObject.Properties['SpecVersion'] -and $entry.SpecVersion) {
                $specVersion = [string]$entry.SpecVersion
            }
        }

        if ($specVersion) { $tpmDetailsLines.Add("SpecVersion: $specVersion") | Out-Null }
        if ($present -ne $null) { $tpmDetailsLines.Add("Present: $present") | Out-Null }
        if ($ready -ne $null) { $tpmDetailsLines.Add("Ready: $ready") | Out-Null }
        if ($enabled -ne $null) { $tpmDetailsLines.Add("Enabled: $enabled") | Out-Null }
        if ($activated -ne $null) { $tpmDetailsLines.Add("Activated: $activated") | Out-Null }

        $hasVersion2 = $false
        if ($specVersion) { $hasVersion2 = ($specVersion -match '2\.0') }

        if ($present -eq $false -or $ready -eq $false -or $enabled -eq $false -or $activated -eq $false -or ($specVersion -and -not $hasVersion2)) {
            $tpmMet = $false
            $tpmStatus = 'Fail'
        } elseif ($present -eq $true -and $enabled -eq $true -and $activated -eq $true -and $hasVersion2 -and ($ready -ne $false)) {
            $tpmMet = $true
            $tpmStatus = 'Pass'
        }
    }

    $tpmStatus = if ($tpmMet -eq $true) { 'Pass' } elseif ($tpmMet -eq $false) { 'Fail' } else { 'Unknown' }
    $tpmDetails = $tpmDetailsLines.ToArray() -join '; '
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: TPM 2.0' -Status $tpmStatus -Details $tpmDetails
    if ($tpmMet -eq $false) {
        $severity = 'high'
        $description = 'Windows 11 requires TPM 2.0 capabilities, but the collected data shows they are disabled or missing.'
        $remediation = 'Enable and initialize TPM 2.0 (present, ready, enabled, activated) before upgrading.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'TPM 2.0'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $ramMet = $null
    $ramStatus = 'Unknown'
    $ramDetails = 'Installed memory not reported.'
    if ($computerSystem -and $computerSystem.PSObject.Properties['TotalPhysicalMemory']) {
        $totalMemory = [double]$computerSystem.TotalPhysicalMemory
        if ($totalMemory -gt 0) {
            $ramGb = [math]::Round($totalMemory / 1GB, 2)
            if ($ramGb -ge 4) {
                $ramMet = $true
                $ramStatus = 'Pass'
            } else {
                $ramMet = $false
                $ramStatus = 'Fail'
            }
            $ramDetails = "Installed RAM: $ramGb GB"
        }
    }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: Installed RAM' -Status $ramStatus -Details $ramDetails
    if ($ramMet -eq $false) {
        $severity = 'critical'
        $description = 'Windows 11 requires at least 4 GB of RAM, but the collected data shows this device below that threshold.'
        $remediation = 'Install at least 4 GB of RAM before upgrading.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'Installed RAM'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $systemVolume = $null
    $volumeEntries = @()
    if ($storagePayload -and $storagePayload.PSObject.Properties['Volumes']) {
        $volumeEntries = ConvertTo-Windows11Array $storagePayload.Volumes
    }
    foreach ($volume in $volumeEntries) {
        if (-not $volume) { continue }
        $driveLetter = $null
        if ($volume.PSObject.Properties['DriveLetter']) { $driveLetter = [string]$volume.DriveLetter }
        if ($driveLetter) {
            $normalized = $driveLetter.Trim()
            $normalized = $normalized.TrimEnd(':')
            if ($normalized -and $normalized.ToUpperInvariant() -eq $systemDrive.ToUpperInvariant()) {
                $systemVolume = $volume
                break
            }
        }
    }

    if (-not $systemVolume -and $volumeEntries.Count -gt 0) {
        $fallback = $volumeEntries | Where-Object { $_ -and $_.DriveLetter } | Select-Object -First 1
        if ($fallback) { $systemVolume = $fallback }
    }

    $capacityMet = $null
    $capacityStatus = 'Unknown'
    $capacityDetails = 'System volume not captured.'
    $freeMet = $null
    $freeStatus = 'Unknown'
    $freeDetails = 'System volume not captured.'
    $healthMet = $null
    $healthStatus = 'Unknown'
    $healthDetails = 'System volume health not reported.'

    if ($systemVolume) {
        $size = if ($systemVolume.PSObject.Properties['Size']) { [double]$systemVolume.Size } else { 0 }
        $free = if ($systemVolume.PSObject.Properties['SizeRemaining']) { [double]$systemVolume.SizeRemaining } else { 0 }
        $health = if ($systemVolume.PSObject.Properties['HealthStatus']) { [string]$systemVolume.HealthStatus } else { $null }

        if ($size -gt 0) {
            $sizeGb = [math]::Round($size / 1GB, 2)
            if ($sizeGb -ge 64) {
                $capacityMet = $true
                $capacityStatus = 'Pass'
            } else {
                $capacityMet = $false
                $capacityStatus = 'Fail'
            }
            $capacityDetails = "System volume size: $sizeGb GB"
        }

        if ($free -ge 0) {
            $freeGb = [math]::Round($free / 1GB, 2)
            if ($freeGb -ge 20) {
                $freeMet = $true
                $freeStatus = 'Pass'
            } else {
                $freeMet = $false
                $freeStatus = 'Fail'
            }
            $freeDetails = "Free space: $freeGb GB"
        }

        if ($health) {
            if ($health -match '^(?i)healthy$') {
                $healthMet = $true
                $healthStatus = 'Pass'
            } else {
                $healthMet = $false
                $healthStatus = 'Fail'
            }
            $healthDetails = "Volume health: $health"
        }
    }

    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: System drive capacity' -Status $capacityStatus -Details $capacityDetails
    if ($capacityMet -eq $false) {
        $severity = 'critical'
        $description = 'Windows 11 setup requires 64 GB or more on the system drive, but the collected size falls below that minimum.'
        $remediation = 'Expand or replace the system drive to provide at least 64 GB before upgrading.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'System drive capacity'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: System drive free space' -Status $freeStatus -Details $freeDetails
    if ($freeMet -eq $false) {
        $severity = 'critical'
        $description = 'Windows 11 setup needs 20 GB of free space on the system volume, but the collected reading is below that requirement.'
        $remediation = 'Free at least 20 GB on the system volume before running setup.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'System drive free space'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: System drive health' -Status $healthStatus -Details $healthDetails
    if ($healthMet -eq $false) {
        $severity = 'high'
        $description = 'Windows 11 upgrade should not proceed while the system volume reports a degraded health state.'
        $remediation = 'Resolve disk health issues (e.g., replace failing drive or repair volume) before upgrading.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'System drive health'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }
    $partitionMet = $null
    $partitionStatus = 'Unknown'
    $partitionDetails = 'Partition style not reported.'
    $diskEntries = @()
    if ($storagePayload -and $storagePayload.PSObject.Properties['Disks']) {
        $diskEntries = ConvertTo-Windows11Array $storagePayload.Disks
    }
    if ($diskEntries.Count -gt 0) {
        $gptCount = 0
        $diskSummaries = [System.Collections.Generic.List[string]]::new()
        foreach ($disk in $diskEntries) {
            if (-not $disk) { continue }
            $number = if ($disk.PSObject.Properties['Number']) { $disk.Number } else { $null }
            $style = if ($disk.PSObject.Properties['PartitionStyle']) { [string]$disk.PartitionStyle } else { $null }
            if ($style) {
                if ($style -match '^(?i)gpt$') { $gptCount++ }
                $diskSummaries.Add(("Disk {0}: {1}" -f ($number ?? '?'), $style)) | Out-Null
            }
        }
        if ($diskSummaries.Count -gt 0) { $partitionDetails = $diskSummaries.ToArray() -join '; ' }
        if ($gptCount -gt 0) {
            $partitionMet = $true
            $partitionStatus = 'Pass'
        } else {
            $partitionMet = $false
            $partitionStatus = 'Fail'
        }
    }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: GPT system disk' -Status $partitionStatus -Details $partitionDetails
    if ($partitionMet -eq $false) {
        $severity = 'critical'
        $description = 'Windows 11 requires the system disk to use GPT so UEFI features can operate, but no GPT disks were reported.'
        $remediation = 'Convert the system disk to GPT (or reinstall in UEFI mode) before upgrading.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'GPT system disk'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $bitlockerMet = $true
    $bitlockerStatus = 'Pass'
    $bitlockerDetails = 'BitLocker volume status not captured.'
    if ($bitlockerPayload -and $bitlockerPayload.Volumes) {
        $bitlockerVolumes = ConvertTo-Windows11Array $bitlockerPayload.Volumes
        $systemBitLocker = $bitlockerVolumes | Where-Object {
            $_ -and $_.MountPoint -and ([string]$_.MountPoint).Trim().ToUpperInvariant().StartsWith($systemDrive.ToUpperInvariant())
        } | Select-Object -First 1
        if (-not $systemBitLocker -and $bitlockerVolumes.Count -gt 0) {
            $systemBitLocker = $bitlockerVolumes | Select-Object -First 1
        }
        if ($systemBitLocker) {
            $statusValue = $systemBitLocker.ProtectionStatus
            $bitlockerDetails = "System BitLocker status: $statusValue"
            $isProtected = $false
            if ($statusValue -is [int]) {
                $isProtected = ($statusValue -eq 1)
            } elseif ($statusValue) {
                $statusText = [string]$statusValue
                if ($statusText -match '(?i)on|protected') { $isProtected = $true }
            }
            if ($isProtected) {
                $bitlockerMet = $false
                $bitlockerStatus = 'Fail'
            }
        } else {
            $bitlockerDetails = 'No BitLocker volume data for system drive.'
            $bitlockerMet = $null
            $bitlockerStatus = 'Unknown'
        }
    } elseif ($bitlockerPayload -and $bitlockerPayload.PSObject.Properties['Error']) {
        $bitlockerMet = $null
        $bitlockerStatus = 'Unknown'
        $bitlockerDetails = [string]$bitlockerPayload.Error
    }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: BitLocker suspension' -Status $bitlockerStatus -Details $bitlockerDetails
    if ($bitlockerMet -eq $false) {
        $severity = 'medium'
        $description = 'Windows 11 setup halts when BitLocker remains active on the system drive, so suspend protection before upgrading.'
        $remediation = 'Suspend BitLocker protection on the system drive before starting the Windows 11 setup.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'BitLocker suspension'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $vbsMet = $null
    $vbsStatus = 'Unknown'
    $vbsDetailsLines = [System.Collections.Generic.List[string]]::new()
    if ($vbPayload -and $vbPayload.DeviceGuard) {
        if ($vbPayload.DeviceGuard.PSObject.Properties['Error'] -and $vbPayload.DeviceGuard.Error) {
            $vbsDetailsLines.Add($vbPayload.DeviceGuard.Error) | Out-Null
        } else {
            $dg = $vbPayload.DeviceGuard
            $running = ConvertTo-IntArray $dg.SecurityServicesRunning
            $configured = ConvertTo-IntArray $dg.SecurityServicesConfigured
            $available = ConvertTo-IntArray $dg.AvailableSecurityProperties
            $required = ConvertTo-IntArray $dg.RequiredSecurityProperties
            if ($running) { $vbsDetailsLines.Add("Running: $($running -join ',')") | Out-Null }
            if ($configured) { $vbsDetailsLines.Add("Configured: $($configured -join ',')") | Out-Null }
            if ($available) { $vbsDetailsLines.Add("Available: $($available -join ',')") | Out-Null }
            if ($required) { $vbsDetailsLines.Add("Required: $($required -join ',')") | Out-Null }
            $vbsActive = ($running -contains 1) -or ($running -contains 2)
            $vbsAvailable = ($available -contains 1) -or ($available -contains 2) -or ($required -contains 1) -or ($required -contains 2)
            if ($vbsActive) {
                $vbsMet = $true
                $vbsStatus = 'Pass'
            } elseif ($vbsAvailable) {
                $vbsMet = $false
                $vbsStatus = 'Fail'
            } else {
                $vbsMet = $null
            }
        }
    } else {
        $vbsDetailsLines.Add('VBS diagnostics not collected.') | Out-Null
    }

    $vbsDetails = $vbsDetailsLines.ToArray() -join '; '
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: Virtualization-based security' -Status $vbsStatus -Details $vbsDetails
    if ($vbsMet -eq $false) {
        $severity = 'medium'
        $description = 'Windows 11 enables virtualization-based security by default, so turn on Credential Guard or Memory Integrity to avoid the upgrade disabling protection.'
        $remediation = 'Enable Credential Guard or Memory Integrity so VBS remains on after the upgrade.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'Virtualization-based security'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    if ($requirementFailures.Count -eq 0) {
        $summaryEvidence = @()
        if ($cpuDetails) { $summaryEvidence += $cpuDetails }
        if ($firmwareDetails) { $summaryEvidence += $firmwareDetails }
        if ($ramDetails) { $summaryEvidence += $ramDetails }
        if ($capacityDetails) { $summaryEvidence += $capacityDetails }
        if ($freeDetails) { $summaryEvidence += $freeDetails }
        if ($secureBootDetails) { $summaryEvidence += $secureBootDetails }
        if ($tpmDetails) { $summaryEvidence += $tpmDetails }
        if ($vbsDetails) { $summaryEvidence += $vbsDetails }
        $evidenceText = if ($summaryEvidence.Count -gt 0) { $summaryEvidence -join "`n" } else { $null }
        Add-CategoryNormal -CategoryResult $Result -Title 'Windows 11 upgrade readiness check passed, so the device meets Microsoft requirements for in-place upgrades.' -Evidence $evidenceText -Subcategory 'Windows 11 Upgrade'
    } else {
        if (-not $highestSeverity) { $highestSeverity = 'info' }
        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        foreach ($failure in $requirementFailures) {
            if (-not $failure) { continue }
            $evidenceLines.Add(("{0}: {1}" -f $failure.Name, $failure.Description)) | Out-Null
            if ($failure.Remediation) {
                $evidenceLines.Add("Remediation: $($failure.Remediation)") | Out-Null
            }
            $evidenceLines.Add('') | Out-Null
        }
        $evidence = ($evidenceLines | Where-Object { $_ }) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity $highestSeverity -Title 'Windows 11 upgrade readiness check failed, so the in-place upgrade will be blocked until these requirements are resolved.' -Evidence $evidence -Subcategory 'Windows 11 Upgrade'
    }
}
