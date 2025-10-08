function Normalize-Windows11CpuName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    $normalized = $Name.ToLowerInvariant()
    $normalized = $normalized -replace '\(r\)', ''
    $normalized = $normalized -replace '\(tm\)', ''
    $normalized = $normalized -replace '®', ''
    $normalized = $normalized -replace '™', ''
    $normalized = $normalized -replace '\s+', ' '
    return $normalized.Trim()
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
    if ($cpuMet -ne $true) {
        $severity = if ($cpuMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($cpuMet -eq $false) {
            if ($cpuDetailsBuilder.Length -gt 0) { $cpuDetailsBuilder.ToString() } else { 'Installed processor not in Microsoft-supported catalog.' }
        } else {
            'Processor compatibility could not be confirmed from collected data.'
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
    if ($architectureMet -ne $true) {
        $severity = if ($architectureMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($architectureMet -eq $false) {
            "Operating system architecture '$architectureDetails' is not 64-bit."
        } else {
            'Operating system architecture could not be verified.'
        }
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
    if ($upgradeMet -ne $true) {
        $severity = if ($upgradeMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($upgradeMet -eq $false) { $upgradeDetails } else { 'Operating system version could not be determined.' }
        $remediation = 'Upgrade to Windows 10, Windows 8, or Windows 8.1 64-bit before moving to Windows 11.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'Supported upgrade path'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $biosMode = Get-SystemInfoValue -Lines $systemInfoLines -Label 'BIOS Mode'
    $firmwareMet = $null
    $firmwareStatus = 'Unknown'
    $firmwareDetails = 'Firmware mode not reported.'
    if ($biosMode) {
        if ($biosMode -match '(?i)uefi') {
            $firmwareMet = $true
            $firmwareStatus = 'Pass'
            $firmwareDetails = "BIOS Mode: $biosMode"
        } else {
            $firmwareMet = $false
            $firmwareStatus = 'Fail'
            $firmwareDetails = "BIOS Mode: $biosMode"
        }
    }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: UEFI firmware' -Status $firmwareStatus -Details $firmwareDetails
    if ($firmwareMet -ne $true) {
        $severity = if ($firmwareMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($biosMode) { "Device reports BIOS Mode '$biosMode', which is not UEFI." } else { 'Firmware mode could not be determined from system information.' }
        $remediation = 'Switch the system firmware to UEFI mode before starting the Windows 11 upgrade.'
        $requirementFailures.Add([pscustomobject]@{
            Name        = 'UEFI firmware'
            Description = $description
            Remediation = $remediation
            Severity    = $severity
        }) | Out-Null
        & $updateSeverity $highestSeverityRef $severityRank $severity
    }

    $secureBootState = Get-SystemInfoValue -Lines $systemInfoLines -Label 'Secure Boot State'
    $secureBootMet = $null
    $secureBootStatus = 'Unknown'
    $secureBootDetails = 'Secure Boot state not reported.'
    if ($secureBootState) {
        if ($secureBootState -match '^(?i)(on|enabled|active)$') {
            $secureBootMet = $true
            $secureBootStatus = 'Pass'
            $secureBootDetails = "Secure Boot state: $secureBootState"
        } else {
            $secureBootMet = $false
            $secureBootStatus = 'Fail'
            $secureBootDetails = "Secure Boot state: $secureBootState"
        }
    }
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: Secure Boot' -Status $secureBootStatus -Details $secureBootDetails
    if ($secureBootMet -ne $true) {
        $severity = if ($secureBootMet -eq $false) { 'high' } else { 'info' }
        $description = if ($secureBootState) { "Secure Boot reported as '$secureBootState'." } else { 'Secure Boot status unavailable from system information.' }
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
    if ($tpmPayload -and $tpmPayload.Tpm) {
        if ($tpmPayload.Tpm.PSObject.Properties['Error'] -and $tpmPayload.Tpm.Error) {
            $tpmDetailsLines.Add($tpmPayload.Tpm.Error) | Out-Null
        } else {
            $tpm = $tpmPayload.Tpm
            $present = $null
            $ready = $null
            $enabled = $null
            $activated = $null
            $specVersion = $null
            if ($tpm.PSObject.Properties['TpmPresent']) { $present = [bool]$tpm.TpmPresent }
            if ($tpm.PSObject.Properties['TpmReady']) { $ready = [bool]$tpm.TpmReady }
            if ($tpm.PSObject.Properties['TpmEnabled']) { $enabled = [bool]$tpm.TpmEnabled }
            if ($tpm.PSObject.Properties['TpmActivated']) { $activated = [bool]$tpm.TpmActivated }
            if ($tpm.PSObject.Properties['SpecVersion']) { $specVersion = [string]$tpm.SpecVersion }

            $tpmDetailsLines.Add("Present: $present") | Out-Null
            $tpmDetailsLines.Add("Ready: $ready") | Out-Null
            $tpmDetailsLines.Add("Enabled: $enabled") | Out-Null
            $tpmDetailsLines.Add("Activated: $activated") | Out-Null
            if ($specVersion) { $tpmDetailsLines.Add("SpecVersion: $specVersion") | Out-Null }

            $hasVersion2 = $false
            if ($specVersion) {
                $hasVersion2 = ($specVersion -match '2\.0')
            }

            if ($present -and $ready -and $enabled -and $activated -and $hasVersion2) {
                $tpmMet = $true
            } else {
                $tpmMet = $false
            }
        }
    } elseif ($tpmPayload -and $tpmPayload.Tpm -eq $null) {
        $tpmDetailsLines.Add('TPM payload empty.') | Out-Null
    } else {
        $tpmDetailsLines.Add('TPM artifact missing.') | Out-Null
    }

    $tpmStatus = if ($tpmMet -eq $true) { 'Pass' } elseif ($tpmMet -eq $false) { 'Fail' } else { 'Unknown' }
    $tpmDetails = $tpmDetailsLines.ToArray() -join '; '
    Add-CategoryCheck -CategoryResult $Result -Name 'Windows 11: TPM 2.0' -Status $tpmStatus -Details $tpmDetails
    if ($tpmMet -ne $true) {
        $severity = if ($tpmMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($tpmMet -eq $false) { 'TPM did not report as present, ready, enabled, activated, and version 2.0.' } else { 'TPM status could not be confirmed.' }
        $remediation = 'Enable and initialize TPM 2.0 in firmware before upgrading.'
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
    if ($ramMet -ne $true) {
        $severity = if ($ramMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($ramMet -eq $false) { "$ramDetails is below the 4 GB minimum." } else { 'Unable to determine installed RAM capacity.' }
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
    if ($capacityMet -ne $true) {
        $severity = if ($capacityMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($capacityMet -eq $false) { "$capacityDetails is below the 64 GB minimum." } else { 'Unable to determine system drive size.' }
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
    if ($freeMet -ne $true) {
        $severity = if ($freeMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($freeMet -eq $false) { "$freeDetails is below the 20 GB setup minimum." } else { 'Unable to determine free space on the system volume.' }
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
    if ($healthMet -ne $true) {
        $severity = if ($healthMet -eq $false) { 'high' } else { 'info' }
        $description = if ($healthMet -eq $false) { "$healthDetails indicates the system volume is not healthy." } else { 'Unable to verify system volume health.' }
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
    if ($partitionMet -ne $true) {
        $severity = if ($partitionMet -eq $false) { 'critical' } else { 'info' }
        $description = if ($partitionMet -eq $false) { 'No disks reported with GPT partition style.' } else { 'Unable to determine disk partition style.' }
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
    if ($bitlockerMet -ne $true) {
        $severity = if ($bitlockerMet -eq $false) { 'medium' } else { 'info' }
        $description = if ($bitlockerMet -eq $false) { 'BitLocker protection is active on the system volume and must be suspended before upgrade.' } else { 'Unable to confirm BitLocker status for the system volume.' }
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
    if ($vbsMet -ne $true) {
        $severity = if ($vbsMet -eq $false) { 'medium' } else { 'info' }
        $description = if ($vbsMet -eq $false) { 'Virtualization-based security features are available but not running.' } else { 'Unable to verify virtualization-based security state.' }
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
