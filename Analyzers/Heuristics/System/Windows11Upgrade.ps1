function ConvertTo-Windows11List {
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }

    return @($Value)
}

function ConvertTo-Windows11Double {
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [double] -or $Value -is [single]) { return [double]$Value }
    if ($Value -is [decimal]) { return [double]$Value }
    if ($Value -is [long] -or $Value -is [int] -or $Value -is [uint64] -or $Value -is [uint32]) {
        return [double]$Value
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $parsed = 0.0
    if ([double]::TryParse($text, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function Normalize-Windows11CatalogValue {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $normalized = $Value -replace '[\u00AE\u2122]', ''
    $normalized = $normalized -replace '\(tm\)', '', 'IgnoreCase'
    $normalized = $normalized -replace '\(r\)', '', 'IgnoreCase'
    $normalized = $normalized -replace '\bwith\s+ipu\b', '', 'IgnoreCase'
    $normalized = $normalized -replace '\bwith\s+radeon\s+graphics\b', '', 'IgnoreCase'
    $normalized = $normalized -replace '\s+', ' '
    return $normalized.Trim().ToLowerInvariant()
}

function Normalize-Windows11CpuName {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $normalized = $Value -replace '[\u00AE\u2122]', ''
    $normalized = $normalized -replace '\(tm\)', '', 'IgnoreCase'
    $normalized = $normalized -replace '\(r\)', '', 'IgnoreCase'
    $normalized = $normalized -replace 'CPU', '', 'IgnoreCase'
    $normalized = $normalized -replace 'Processor', '', 'IgnoreCase'
    $normalized = $normalized -replace 'GenuineIntel', 'Intel', 'IgnoreCase'
    $normalized = $normalized -replace '@.*$', ''
    $normalized = $normalized -replace '\s+', ' '
    return $normalized.Trim().ToLowerInvariant()
}

function Get-Windows11CpuManufacturer {
    param(
        [AllowNull()]
        [string]$CpuName
    )

    if ([string]::IsNullOrWhiteSpace($CpuName)) { return $null }

    $normalized = Normalize-Windows11CpuName $CpuName
    if ([string]::IsNullOrWhiteSpace($normalized)) { return $null }

    if ($normalized -match 'intel') { return 'intel' }
    if ($normalized -match 'amd') { return 'amd' }
    if ($normalized -match 'qualcomm') { return 'qualcomm' }

    return $null
}

$script:Windows11CpuCatalog = $null

function Get-Windows11CpuCatalog {
    if ($null -ne $script:Windows11CpuCatalog) { return $script:Windows11CpuCatalog }

    $catalogPath = Join-Path -Path $PSScriptRoot -ChildPath 'Data/cpus.json'
    $catalog = @()
    if (Test-Path -LiteralPath $catalogPath) {
        try {
            $json = Get-Content -LiteralPath $catalogPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $entries = [System.Collections.Generic.List[pscustomobject]]::new()
            foreach ($item in (ConvertTo-Windows11List $json)) {
                if (-not $item) { continue }
                $manufacturer = Normalize-Windows11CatalogValue ($item.manufacturer)
                $brand = Normalize-Windows11CatalogValue ($item.brand)
                $model = Normalize-Windows11CatalogValue ($item.model)
                $modelCompact = if ($model) { $model -replace '\s+', '' } else { $null }
                $entry = [pscustomobject]@{
                    Manufacturer         = $item.manufacturer
                    Brand                = $item.brand
                    Model                = $item.model
                    NormalizedManufacturer = $manufacturer
                    NormalizedBrand        = $brand
                    NormalizedModel        = $model
                    NormalizedModelCompact = $modelCompact
                }
                $entries.Add($entry) | Out-Null
            }
            $catalog = $entries.ToArray()
        } catch {
            Write-HeuristicDebug -Source 'System/Upgrade' -Message 'Failed to load Windows 11 CPU catalog' -Data ([ordered]@{ Error = $_.Exception.Message })
            $catalog = @()
        }
    } else {
        Write-HeuristicDebug -Source 'System/Upgrade' -Message 'Windows 11 CPU catalog not found' -Data ([ordered]@{ Path = $catalogPath })
    }

    $script:Windows11CpuCatalog = $catalog
    return $catalog
}

function Test-Windows11CpuCompatibility {
    param(
        [AllowNull()]
        [string]$CpuName
    )

    $result = [ordered]@{
        CpuName       = $CpuName
        Manufacturer  = $null
        IsSupported   = $null
        EvidenceLines = @()
    }

    if (-not $CpuName) { return [pscustomobject]$result }

    $catalog = Get-Windows11CpuCatalog
    if (-not $catalog -or $catalog.Count -eq 0) {
        $result.EvidenceLines = @('CPU compatibility catalog unavailable.')
        return [pscustomobject]$result
    }

    $manufacturer = Get-Windows11CpuManufacturer -CpuName $CpuName
    $result.Manufacturer = $manufacturer

    $normalized = Normalize-Windows11CpuName $CpuName
    if (-not $normalized) {
        $result.EvidenceLines = @('Unable to normalize CPU name for comparison.')
        return [pscustomobject]$result
    }
    $normalizedCompact = $normalized -replace '\s+', ''

    $candidates = if ($manufacturer) {
        $catalog | Where-Object { $_.NormalizedManufacturer -eq $manufacturer }
    } else {
        $catalog
    }

    foreach ($entry in $candidates) {
        if (-not $entry) { continue }
        $model = $entry.NormalizedModel
        $modelCompact = $entry.NormalizedModelCompact
        if ([string]::IsNullOrWhiteSpace($model) -and [string]::IsNullOrWhiteSpace($modelCompact)) { continue }

        $modelMatch = $false
        if ($model -and ($normalized -like ("*{0}*" -f $model))) {
            $modelMatch = $true
        } elseif ($modelCompact) {
            if ($normalizedCompact -like ("*{0}*" -f $modelCompact)) {
                $modelMatch = $true
            }
        }

        if ($modelMatch) {
            $result.IsSupported = $true
            $result.EvidenceLines = @(
                "Matched catalog entry: {0} {1} {2}" -f $entry.Manufacturer, $entry.Brand, $entry.Model
            )
            return [pscustomobject]$result
        }
    }

    $result.IsSupported = $false
    $result.EvidenceLines = @(
        "No Windows 11 supported CPU catalog match found for '{0}'." -f $CpuName
    )
    return [pscustomobject]$result
}

function Get-SystemInfoLinesFromPayload {
    param(
        $Payload
    )

    if (-not $Payload -or -not $Payload.SystemInfoText) { return @() }

    $systemInfo = $Payload.SystemInfoText
    if ($systemInfo -is [System.Collections.IEnumerable] -and -not ($systemInfo -is [string])) {
        $text = ($systemInfo | ForEach-Object { [string]$_ }) -join "`n"
        return $text -split "\r?\n"
    }

    $raw = [string]$systemInfo
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    return $raw -split "\r?\n"
}

function Get-SystemInfoValue {
    param(
        [string[]]$Lines,
        [string]$Label
    )

    if (-not $Lines -or -not $Label) { return $null }

    $pattern = '^[\s\u00A0]*{0}[\s\u00A0]*:[\s\u00A0]*(?<value>.+)$' -f [regex]::Escape($Label)
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        $match = [regex]::Match($line, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success) {
            return $match.Groups['value'].Value.Trim()
        }
    }

    return $null
}

function Get-SystemProcessorNames {
    param(
        [string[]]$Lines
    )

    $results = [System.Collections.Generic.List[string]]::new()
    if (-not $Lines) { return $results.ToArray() }

    $inSection = $false
    foreach ($line in $Lines) {
        if (-not $inSection) {
            if ($line -match '^[\s\u00A0]*Processor\(s\)[\s\u00A0]*:') {
                $inSection = $true
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($line)) { break }
        if ($line -notmatch '^[\s\u00A0]*\[') { break }

        $value = $line -replace '^[\s\u00A0]*\[\d+\][\s\u00A0]*:?\s*', ''
        if ($value) {
            $results.Add($value.Trim()) | Out-Null
        }
    }

    return $results.ToArray()
}

function Get-SystemDriveLetter {
    param(
        [string[]]$Lines
    )

    $drive = Get-SystemInfoValue -Lines $Lines -Label 'System Drive'
    if (-not [string]::IsNullOrWhiteSpace($drive)) {
        $normalized = $drive.Trim()
        if ($normalized.Length -ge 2) {
            if ($normalized[-1] -eq ':') { return $normalized.ToUpperInvariant() }
            if ($normalized.Length -ge 3 -and $normalized[1] -eq ':' ) { return $normalized.Substring(0,2).ToUpperInvariant() }
        }
    }

    return 'C:'
}

function Normalize-DriveLetter {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $trimmed = $Value.Trim()
    if ($trimmed.Length -ge 2) {
        if ($trimmed[1] -eq ':') { return $trimmed.Substring(0,2).ToUpperInvariant() }
        if ($trimmed.Length -ge 3 -and $trimmed[2] -eq ':') { return $trimmed.Substring(0,3).ToUpperInvariant() }
    }

    if ($trimmed.Length -eq 1) {
        return ('{0}:' -f $trimmed.ToUpperInvariant())
    }

    return $trimmed.ToUpperInvariant()
}

function Get-Windows11SystemVolumeInfo {
    param(
        $StoragePayload,
        [string]$SystemDriveLetter
    )

    $result = [ordered]@{
        Volume   = $null
        Disk     = $null
        Evidence = $null
    }

    if (-not $StoragePayload) { return [pscustomobject]$result }

    $volumes = ConvertTo-Windows11List $StoragePayload.Volumes
    $disks = ConvertTo-Windows11List $StoragePayload.Disks
    $targetDrive = Normalize-DriveLetter $SystemDriveLetter
    if (-not $targetDrive) { $targetDrive = 'C:' }

    foreach ($volume in $volumes) {
        if (-not $volume) { continue }
        $candidateLetters = @()
        if ($volume.PSObject.Properties['DriveLetter']) { $candidateLetters += $volume.DriveLetter }
        if ($volume.PSObject.Properties['MountPoint']) { $candidateLetters += $volume.MountPoint }
        if ($candidateLetters.Count -eq 0 -and $volume.PSObject.Properties['Path']) { $candidateLetters += $volume.Path }
        $matches = $false
        foreach ($candidate in $candidateLetters) {
            if (-not $candidate) { continue }
            $normalized = Normalize-DriveLetter $candidate
            if ($normalized -and $normalized -eq $targetDrive) {
                $matches = $true
                break
            }
        }
        if ($matches) {
            $result.Volume = $volume
            break
        }
    }

    if (-not $result.Volume -and $volumes.Count -gt 0) {
        $result.Volume = $volumes | Select-Object -First 1
    }

    if ($disks.Count -gt 0) {
        $candidateDisk = $null
        $volumeSize = $null
        if ($result.Volume -and $result.Volume.PSObject.Properties['Size']) {
            $volumeSize = ConvertTo-Windows11Double $result.Volume.Size
        }

        foreach ($disk in $disks) {
            if (-not $disk) { continue }
            $diskSize = $null
            if ($disk.PSObject.Properties['Size']) {
                $diskSize = ConvertTo-Windows11Double $disk.Size
            }
            if ($null -eq $diskSize) { continue }

            if ($null -eq $candidateDisk) {
                $candidateDisk = $disk
                continue
            }

            if ($null -ne $volumeSize -and $diskSize -ge $volumeSize) {
                $currentCandidateSize = $null
                if ($candidateDisk.PSObject.Properties['Size']) {
                    $currentCandidateSize = ConvertTo-Windows11Double $candidateDisk.Size
                }
                if ($null -eq $currentCandidateSize -or $diskSize -lt $currentCandidateSize) {
                    $candidateDisk = $disk
                }
            }
        }

        if (-not $candidateDisk) {
            $candidateDisk = $disks | Select-Object -First 1
        }

        $result.Disk = $candidateDisk
    }

    $evidenceLines = [System.Collections.Generic.List[string]]::new()
    if ($result.Volume) {
        if ($result.Volume.PSObject.Properties['DriveLetter']) {
            $evidenceLines.Add("Volume drive letter: {0}" -f $result.Volume.DriveLetter) | Out-Null
        }
        if ($result.Volume.PSObject.Properties['Size']) {
            $size = ConvertTo-Windows11Double $result.Volume.Size
            if ($null -ne $size) { $evidenceLines.Add("Volume size (bytes): {0}" -f [math]::Round($size)) | Out-Null }
        }
        if ($result.Volume.PSObject.Properties['SizeRemaining']) {
            $free = ConvertTo-Windows11Double $result.Volume.SizeRemaining
            if ($null -ne $free) { $evidenceLines.Add("Volume free space (bytes): {0}" -f [math]::Round($free)) | Out-Null }
        }
        if ($result.Volume.PSObject.Properties['HealthStatus']) {
            $evidenceLines.Add("Volume health: {0}" -f $result.Volume.HealthStatus) | Out-Null
        }
        if ($result.Volume.PSObject.Properties['FileSystem']) {
            $evidenceLines.Add("Volume filesystem: {0}" -f $result.Volume.FileSystem) | Out-Null
        }
    }
    if ($result.Disk) {
        if ($result.Disk.PSObject.Properties['Number']) {
            $evidenceLines.Add("Disk number: {0}" -f $result.Disk.Number) | Out-Null
        }
        if ($result.Disk.PSObject.Properties['PartitionStyle']) {
            $evidenceLines.Add("Disk partition style: {0}" -f $result.Disk.PartitionStyle) | Out-Null
        }
        if ($result.Disk.PSObject.Properties['HealthStatus']) {
            $evidenceLines.Add("Disk health: {0}" -f $result.Disk.HealthStatus) | Out-Null
        }
    }

    if ($evidenceLines.Count -gt 0) {
        $result.Evidence = ($evidenceLines.ToArray() -join "`n")
    }

    return [pscustomobject]$result
}

function Get-Windows11DeviceGuardStatus {
    param(
        $Context
    )

    $vbArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vbshvci'
    if (-not $vbArtifact) { return $null }
    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $vbArtifact)
    if (-not $payload -or -not $payload.DeviceGuard) { return $null }
    if ($payload.DeviceGuard.Error) { return [pscustomobject]@{ Error = $payload.DeviceGuard.Error } }

    $running = ConvertTo-Windows11List $payload.DeviceGuard.SecurityServicesRunning
    $configured = ConvertTo-Windows11List $payload.DeviceGuard.SecurityServicesConfigured
    $available = ConvertTo-Windows11List $payload.DeviceGuard.AvailableSecurityProperties
    $required = ConvertTo-Windows11List $payload.DeviceGuard.RequiredSecurityProperties

    return [pscustomobject]@{
        Running   = $running
        Configured = $configured
        Available  = $available
        Required   = $required
    }
}

function Get-Windows11BitLockerStatus {
    param(
        $Context,
        [string]$SystemDriveLetter
    )

    $bitlockerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'bitlocker'
    if (-not $bitlockerArtifact) { return $null }
    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $bitlockerArtifact)
    if (-not $payload -or -not $payload.Volumes) { return $null }

    $targetDrive = Normalize-DriveLetter $SystemDriveLetter
    if (-not $targetDrive) { $targetDrive = 'C:' }

    foreach ($volume in (ConvertTo-Windows11List $payload.Volumes)) {
        if (-not $volume) { continue }
        $mountPoint = $null
        if ($volume.PSObject.Properties['MountPoint']) { $mountPoint = $volume.MountPoint }
        elseif ($volume.PSObject.Properties['VolumeMountPoint']) { $mountPoint = $volume.VolumeMountPoint }
        if (-not $mountPoint -and $volume.PSObject.Properties['MountPoint']) { $mountPoint = $volume.MountPoint }
        $normalized = Normalize-DriveLetter $mountPoint
        if (-not $normalized -and $volume.PSObject.Properties['MountPoint']) {
            $normalized = Normalize-DriveLetter $volume.MountPoint
        }
        if (-not $normalized -and $volume.PSObject.Properties['VolumeType']) {
            if ([string]$volume.VolumeType -eq 'OperatingSystem') {
                $normalized = $targetDrive
            }
        }
        if ($normalized -and $normalized -eq $targetDrive) {
            return $volume
        }
    }

    return $null
}

function Invoke-SystemWindows11UpgradeChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Upgrade' -Message 'Starting Windows 11 upgrade readiness checks'

    $subcategory = 'Windows 11 Upgrade'

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    Write-HeuristicDebug -Source 'System/Upgrade' -Message 'Resolved system artifact' -Data ([ordered]@{ Found = [bool]$systemArtifact })
    if (-not $systemArtifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Windows 11 readiness could not be evaluated because the system inventory artifact is missing.' -Subcategory $subcategory
        return
    }

    $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
    if (-not $systemPayload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Windows 11 readiness could not be evaluated because the system inventory payload is empty.' -Subcategory $subcategory
        return
    }

    $systemInfoLines = Get-SystemInfoLinesFromPayload -Payload $systemPayload
    $processorNames = Get-SystemProcessorNames -Lines $systemInfoLines
    $cpuName = if ($processorNames.Count -gt 0) { $processorNames[0] } else { $null }
    if ($cpuName) {
        Add-CategoryCheck -CategoryResult $Result -Name 'Detected CPU' -Status $cpuName
        $cpuCompatibility = Test-Windows11CpuCompatibility -CpuName $cpuName
        $cpuEvidenceLines = [System.Collections.Generic.List[string]]::new()
        $cpuEvidenceLines.Add("Detected CPU: {0}" -f $cpuName) | Out-Null
        foreach ($line in (ConvertTo-Windows11List $cpuCompatibility.EvidenceLines)) {
            if ($line) { $cpuEvidenceLines.Add([string]$line) | Out-Null }
        }
        Write-HeuristicDebug -Source 'System/Upgrade' -Message 'CPU compatibility evaluation' -Data ([ordered]@{
            CpuName     = $cpuName
            Manufacturer = $cpuCompatibility.Manufacturer
            Supported    = $cpuCompatibility.IsSupported
        })
        if ($cpuCompatibility.IsSupported -eq $true) {
            Add-CategoryNormal -CategoryResult $Result -Title 'CPU supported for Windows 11 upgrade, so the processor meets Microsoft''s compatibility list.' -Evidence ($cpuEvidenceLines.ToArray() -join "`n") -Subcategory $subcategory
        } elseif ($cpuCompatibility.IsSupported -eq $false) {
            $cpuEvidenceLines.Add('Requirement: CPU must appear on the Windows 11 supported processor list.') | Out-Null
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'CPU unsupported for Windows 11, so the upgrade cannot proceed on this processor.' -Evidence ($cpuEvidenceLines.ToArray() -join "`n") -Subcategory $subcategory -Remediation 'Replace the processor or device with a Windows 11 supported CPU model before attempting the upgrade.'
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'CPU compatibility with Windows 11 could not be confirmed.' -Evidence ($cpuEvidenceLines.ToArray() -join "`n") -Subcategory $subcategory
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'CPU model not captured, so Windows 11 processor compatibility is unknown.' -Subcategory $subcategory -Evidence 'System inventory did not include processor details.'
    }

    $os = $systemPayload.OperatingSystem
    if ($os -and -not $os.Error) {
        $caption = if ($os.PSObject.Properties['Caption']) { [string]$os.Caption } else { $null }
        $architecture = if ($os.PSObject.Properties['OSArchitecture']) { [string]$os.OSArchitecture } else { $null }
        if ($architecture) {
            Add-CategoryCheck -CategoryResult $Result -Name 'OS architecture' -Status $architecture
            if ($architecture -match '(?i)(64-bit|x64|arm64)') {
                Add-CategoryNormal -CategoryResult $Result -Title 'Operating system is 64-bit, so it satisfies Windows 11 architecture requirements.' -Evidence $architecture -Subcategory $subcategory
            } else {
                Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Operating system is 32-bit, so Windows 11 cannot be installed in-place.' -Evidence ("Detected architecture: {0}. Requirement: Windows 11 requires a 64-bit (x64 or ARM64) OS." -f $architecture) -Subcategory $subcategory -Remediation 'Install a 64-bit edition of Windows 10 or Windows 11 and migrate data before proceeding.'
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'OS architecture not reported, so Windows 11 upgrade readiness is unclear.' -Subcategory $subcategory
        }

        if ($caption) {
            $captionLower = $caption.ToLowerInvariant()
            $supported = ($captionLower -match 'windows\s+10') -or ($captionLower -match 'windows\s+8(\.1)?') -or ($captionLower -match 'windows\s+11')
            if ($supported) {
                Add-CategoryNormal -CategoryResult $Result -Title ('Current OS version {0} supports Windows 11 upgrade paths.' -f $caption) -Subcategory $subcategory
            } else {
                Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ('Current OS {0} is not on a supported Windows 11 upgrade path, so setup will fail.' -f $caption) -Evidence ("Requirement: Windows 11 supports upgrades from Windows 8, 8.1, or 10. Detected: {0}." -f $caption) -Subcategory $subcategory -Remediation 'Upgrade the device to Windows 10 first or perform a clean Windows 11 installation.'
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'OS version not reported, so Windows 11 upgrade path cannot be confirmed.' -Subcategory $subcategory
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Operating system details unavailable, so Windows 11 upgrade readiness cannot be confirmed.' -Subcategory $subcategory
    }

    $biosMode = Get-SystemInfoValue -Lines $systemInfoLines -Label 'BIOS Mode'
    if ($biosMode) {
        $biosEvidence = "BIOS Mode reported: {0}" -f $biosMode
        if ($biosMode -match '(?i)uefi') {
            Add-CategoryNormal -CategoryResult $Result -Title 'UEFI firmware detected, so Windows 11 boot requirements are met.' -Evidence $biosEvidence -Subcategory $subcategory
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Firmware is in Legacy BIOS mode, so Windows 11 cannot boot on this configuration.' -Evidence ($biosEvidence + "`nRequirement: Windows 11 requires UEFI firmware with Secure Boot support.") -Subcategory $subcategory -Remediation 'Reconfigure the device to use UEFI firmware (including disk conversion to GPT) before upgrading.'
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Firmware mode not reported, so Windows 11 UEFI requirement is unverified.' -Subcategory $subcategory
    }

    $secureBootState = Get-SystemInfoValue -Lines $systemInfoLines -Label 'Secure Boot State'
    if ($secureBootState) {
        $secureBootEvidence = "Secure Boot State: {0}" -f $secureBootState
        if ($secureBootState -match '^(?i)on$') {
            Add-CategoryNormal -CategoryResult $Result -Title 'Secure Boot is enabled, so firmware integrity protections required by Windows 11 are active.' -Evidence $secureBootEvidence -Subcategory $subcategory
        } elseif ($secureBootState -match '^(?i)off$') {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot is disabled, so Windows 11 security requirements are not satisfied.' -Evidence ($secureBootEvidence + "`nRequirement: Secure Boot must be enabled for Windows 11.") -Subcategory $subcategory -Remediation 'Enable Secure Boot in UEFI firmware and ensure required keys are installed before upgrading.'
        } elseif ($secureBootState -match '^(?i)unsupported$') {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot is unsupported on this hardware, so Windows 11 firmware protections cannot run.' -Evidence $secureBootEvidence -Subcategory $subcategory -Remediation 'Deploy hardware with Secure Boot support or add firmware updates that enable it before upgrading.'
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ("Secure Boot reported unexpected state '{0}', so Windows 11 firmware protections may fail." -f $secureBootState) -Evidence $secureBootEvidence -Subcategory $subcategory -Remediation 'Verify Secure Boot configuration in UEFI firmware and correct the setting before upgrading.'
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Secure Boot state not reported, so Windows 11 firmware requirement is unverified.' -Subcategory $subcategory
    }

    $tpmArtifact = Get-AnalyzerArtifact -Context $Context -Name 'tpm'
    if ($tpmArtifact) {
        $tpmPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $tpmArtifact)
        if ($tpmPayload -and $tpmPayload.Tpm -and -not $tpmPayload.Tpm.Error) {
            $tpm = $tpmPayload.Tpm
            $present = $tpm.TpmPresent
            $ready = $tpm.TpmReady
            $enabled = if ($tpm.PSObject.Properties['TpmEnabled']) { $tpm.TpmEnabled } else { $null }
            $activated = if ($tpm.PSObject.Properties['TpmActivated']) { $tpm.TpmActivated } else { $null }
            $specVersion = if ($tpm.PSObject.Properties['SpecVersion']) { [string]$tpm.SpecVersion } else { $null }
            $tpmEvidenceLines = [System.Collections.Generic.List[string]]::new()
            foreach ($prop in 'TpmPresent','TpmReady','TpmEnabled','TpmActivated','SpecVersion') {
                if ($tpm.PSObject.Properties[$prop]) {
                    $tpmEvidenceLines.Add(("{0}: {1}" -f $prop, $tpm.$prop)) | Out-Null
                }
            }
            $maxVersion = $null
            if ($specVersion) {
                $matches = [regex]::Matches($specVersion, '(?<ver>\d+(?:\.\d+)?)')
                foreach ($match in $matches) {
                    if (-not $match.Success) { continue }
                    $value = $match.Groups['ver'].Value
                    $parsedVersion = 0.0
                    if ([double]::TryParse($value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsedVersion)) {
                        if ($null -eq $maxVersion -or $parsedVersion -gt $maxVersion) {
                            $maxVersion = $parsedVersion
                        }
                    }
                }
            }
            $tpmEvidence = ($tpmEvidenceLines.ToArray() -join "`n")
            $tpmReady = ($present -eq $true) -and ($ready -eq $true) -and ($enabled -ne $false) -and ($activated -ne $false)
            $specRequirementMet = ($null -ne $maxVersion -and $maxVersion -ge 2.0)
            if ($tpmReady -and $specRequirementMet) {
                Add-CategoryNormal -CategoryResult $Result -Title 'TPM 2.0 is present, enabled, and ready for Windows 11.' -Evidence $tpmEvidence -Subcategory $subcategory
            } else {
                if ($present -ne $true) {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'No TPM detected, so Windows 11 hardware security requirements fail.' -Evidence $tpmEvidence -Subcategory $subcategory -Remediation 'Enable the platform TPM 2.0 module in firmware or install a compatible TPM before upgrading.'
                } elseif ($specRequirementMet -ne $true) {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'TPM version below 2.0, so Windows 11 hardware security requirements are not met.' -Evidence ($tpmEvidence + "`nRequirement: TPM 2.0 must be available and active.") -Subcategory $subcategory -Remediation 'Upgrade or replace the TPM hardware with a version 2.0 module before upgrading.'
                } elseif ($ready -ne $true -or $enabled -ne $true -or $activated -ne $true) {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'TPM is not fully initialized, so Windows 11 cannot use hardware-backed security.' -Evidence $tpmEvidence -Subcategory $subcategory -Remediation 'Initialize and activate the TPM in Windows or firmware before attempting the upgrade.'
                }
            }
        } elseif ($tpmPayload -and $tpmPayload.Tpm -and $tpmPayload.Tpm.Error) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to query TPM status, so Windows 11 TPM requirement is unknown.' -Evidence $tpmPayload.Tpm.Error -Subcategory $subcategory
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'TPM inventory missing, so Windows 11 TPM requirement cannot be verified.' -Subcategory $subcategory
    }

    $systemDrive = Get-SystemDriveLetter -Lines $systemInfoLines
    $storageArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage'
    Write-HeuristicDebug -Source 'System/Upgrade' -Message 'Resolved storage artifact' -Data ([ordered]@{ Found = [bool]$storageArtifact })
    if ($storageArtifact) {
        $storagePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $storageArtifact)
        if ($storagePayload) {
            $volumeInfo = Get-Windows11SystemVolumeInfo -StoragePayload $storagePayload -SystemDriveLetter $systemDrive
            $volume = $volumeInfo.Volume
            $disk = $volumeInfo.Disk
            $volumeEvidence = $volumeInfo.Evidence
            if ($volume) {
                $sizeBytes = if ($volume.PSObject.Properties['Size']) { ConvertTo-Windows11Double $volume.Size } else { $null }
                $freeBytes = if ($volume.PSObject.Properties['SizeRemaining']) { ConvertTo-Windows11Double $volume.SizeRemaining } else { $null }
                $healthStatus = if ($volume.PSObject.Properties['HealthStatus']) { [string]$volume.HealthStatus } else { $null }
                if ($sizeBytes -ne $null) {
                    $sizeGb = [math]::Round($sizeBytes / 1GB, 2)
                    Add-CategoryCheck -CategoryResult $Result -Name 'System volume capacity (GB)' -Status ([string]$sizeGb)
                    if ($sizeBytes -ge 64GB) {
                        Add-CategoryNormal -CategoryResult $Result -Title ('System drive has {0:N2} GB capacity, meeting Windows 11 storage requirements.' -f ($sizeBytes / 1GB)) -Evidence $volumeEvidence -Subcategory $subcategory
                    } else {
                        $capacityEvidence = if ($volumeEvidence) { $volumeEvidence + "`nRequirement: Windows 11 requires at least 64 GB system drive capacity." } else { 'Requirement: Windows 11 requires at least 64 GB system drive capacity.' }
                        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'System drive capacity below 64 GB, so Windows 11 cannot be installed.' -Evidence $capacityEvidence -Subcategory $subcategory -Remediation 'Expand or replace the system drive so at least 64 GB of capacity is available before upgrading.'
                    }
                } else {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System drive size unknown, so Windows 11 storage requirement cannot be confirmed.' -Subcategory $subcategory
                }

                if ($freeBytes -ne $null) {
                    $freeGb = [math]::Round($freeBytes / 1GB, 2)
                    Add-CategoryCheck -CategoryResult $Result -Name 'System volume free space (GB)' -Status ([string]$freeGb)
                    if ($freeBytes -ge 20GB) {
                        Add-CategoryNormal -CategoryResult $Result -Title ('System drive has {0:N2} GB free, so setup has working room.' -f ($freeBytes / 1GB)) -Subcategory $subcategory
                    } else {
                        $freeEvidence = if ($volumeEvidence) { $volumeEvidence + "`nRequirement: Reserve at least 20 GB of free space for the upgrade." } else { 'Requirement: Reserve at least 20 GB of free space for the upgrade.' }
                        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'System drive free space below 20 GB, so the Windows 11 setup workspace is insufficient.' -Evidence $freeEvidence -Subcategory $subcategory -Remediation 'Free at least 20 GB on the system drive or expand the volume before starting the upgrade.'
                    }
                } else {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System drive free space unknown, so Windows 11 setup space cannot be verified.' -Subcategory $subcategory
                }

                if ($healthStatus) {
                    if ($healthStatus -match '^(?i)healthy$') {
                        Add-CategoryNormal -CategoryResult $Result -Title 'System volume reports healthy status, so disk integrity should not block the upgrade.' -Evidence $volumeEvidence -Subcategory $subcategory
                    } else {
                        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ('System volume health is {0}, so disk issues could derail the upgrade.' -f $healthStatus) -Evidence $volumeEvidence -Subcategory $subcategory -Remediation 'Repair the system volume (for example with chkdsk or vendor diagnostics) or replace the disk before upgrading.'
                    }
                } else {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System volume health not reported, so disk integrity for the upgrade is unknown.' -Subcategory $subcategory
                }
            } else {
                Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System volume not identified, so Windows 11 storage checks could not run.' -Subcategory $subcategory
            }

            if ($disk) {
                $partitionStyle = if ($disk.PSObject.Properties['PartitionStyle']) { [string]$disk.PartitionStyle } else { $null }
                if ($partitionStyle) {
                    if ($partitionStyle -match '^(?i)gpt$') {
                        Add-CategoryNormal -CategoryResult $Result -Title 'System disk uses GPT partitioning, so Windows 11 UEFI requirements are met.' -Evidence $volumeEvidence -Subcategory $subcategory
                    } else {
                        $partitionEvidence = if ($volumeEvidence) { $volumeEvidence + "`nRequirement: Windows 11 requires the system disk to use GPT." } else { 'Requirement: Windows 11 requires the system disk to use GPT.' }
                        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ('System disk partition style is {0}, so Windows 11 UEFI boot requirements fail.' -f $partitionStyle) -Evidence $partitionEvidence -Subcategory $subcategory -Remediation 'Convert the system disk to GPT (for example with MBR2GPT) and configure UEFI boot before upgrading.'
                    }
                } else {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System disk partition style not reported, so GPT compliance is unknown.' -Subcategory $subcategory
                }
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Storage payload missing, so Windows 11 disk requirements cannot be evaluated.' -Subcategory $subcategory
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Storage inventory artifact missing, so Windows 11 disk requirements cannot be evaluated.' -Subcategory $subcategory
    }

    $computerSystem = $systemPayload.ComputerSystem
    if ($computerSystem -and -not $computerSystem.Error) {
        $memoryBytes = if ($computerSystem.PSObject.Properties['TotalPhysicalMemory']) { ConvertTo-Windows11Double $computerSystem.TotalPhysicalMemory } else { $null }
        if ($null -ne $memoryBytes) {
            $memoryGb = [math]::Round($memoryBytes / 1GB, 2)
            Add-CategoryCheck -CategoryResult $Result -Name 'Installed RAM (GB)' -Status ([string]$memoryGb)
            if ($memoryBytes -ge 4GB) {
                Add-CategoryNormal -CategoryResult $Result -Title ('Installed RAM totals {0:N2} GB, satisfying the Windows 11 minimum of 4 GB.' -f ($memoryBytes / 1GB)) -Subcategory $subcategory
            } else {
                Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Installed RAM below 4 GB, so Windows 11 will not install.' -Evidence ("Detected memory: {0:N2} GB. Requirement: Windows 11 needs at least 4 GB of RAM." -f ($memoryBytes / 1GB)) -Subcategory $subcategory -Remediation 'Add physical memory to bring the system to at least 4 GB before upgrading.'
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Installed RAM not reported, so Windows 11 memory requirement cannot be confirmed.' -Subcategory $subcategory
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Computer system inventory missing, so Windows 11 memory requirement cannot be evaluated.' -Subcategory $subcategory
    }

    $deviceGuardStatus = Get-Windows11DeviceGuardStatus -Context $Context
    if ($deviceGuardStatus) {
        if ($deviceGuardStatus.Error) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Virtualization-based security status unavailable, so Windows 11 security posture is unknown.' -Evidence $deviceGuardStatus.Error -Subcategory $subcategory
        } else {
            $running = @($deviceGuardStatus.Running | ForEach-Object { [string]$_ })
            $evidenceLines = [System.Collections.Generic.List[string]]::new()
            if ($running.Count -gt 0) { $evidenceLines.Add("SecurityServicesRunning: {0}" -f ($running -join ',')) | Out-Null }
            if ($deviceGuardStatus.Configured) { $evidenceLines.Add("SecurityServicesConfigured: {0}" -f (@($deviceGuardStatus.Configured | ForEach-Object { [string]$_ }) -join ',')) | Out-Null }
            if ($deviceGuardStatus.Available) { $evidenceLines.Add("AvailableSecurityProperties: {0}" -f (@($deviceGuardStatus.Available | ForEach-Object { [string]$_ }) -join ',')) | Out-Null }
            if ($deviceGuardStatus.Required) { $evidenceLines.Add("RequiredSecurityProperties: {0}" -f (@($deviceGuardStatus.Required | ForEach-Object { [string]$_ }) -join ',')) | Out-Null }
            $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }
            $servicesRunning = $running | ForEach-Object { $_ } | Where-Object { $_ }
            $vbsActive = $false
            foreach ($value in $servicesRunning) {
                $parsed = 0
                if ([int]::TryParse($value, [ref]$parsed)) {
                    if ($parsed -eq 1 -or $parsed -eq 2) { $vbsActive = $true; break }
                }
            }
            if ($vbsActive) {
                Add-CategoryNormal -CategoryResult $Result -Title 'Virtualization-based security services are running, preserving Windows 11 post-upgrade protections.' -Evidence $evidence -Subcategory $subcategory
            } else {
                $vbsEvidence = if ($evidence) { $evidence + "`nRequirement: Enable VBS (Credential Guard or Memory Integrity)." } else { 'Requirement: Enable VBS (Credential Guard or Memory Integrity).' }
                Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Virtualization-based security is not running, so Windows 11 will lack required post-upgrade protections.' -Evidence $vbsEvidence -Subcategory $subcategory -Remediation 'Enable virtualization-based security (Memory Integrity and Credential Guard) before or after upgrading to Windows 11.'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Virtualization-based security data missing, so Windows 11 post-upgrade protections cannot be confirmed.' -Subcategory $subcategory
    }

    $bitLockerVolume = Get-Windows11BitLockerStatus -Context $Context -SystemDriveLetter $systemDrive
    if ($bitLockerVolume) {
        $status = if ($bitLockerVolume.PSObject.Properties['ProtectionStatus']) { [string]$bitLockerVolume.ProtectionStatus } else { $null }
        $mountPoint = if ($bitLockerVolume.PSObject.Properties['MountPoint']) { [string]$bitLockerVolume.MountPoint } else { $systemDrive }
        $bitlockerEvidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($mountPoint) { $bitlockerEvidenceLines.Add("MountPoint: {0}" -f $mountPoint) | Out-Null }
        if ($status) { $bitlockerEvidenceLines.Add("ProtectionStatus: {0}" -f $status) | Out-Null }
        $bitlockerEvidence = if ($bitlockerEvidenceLines.Count -gt 0) { $bitlockerEvidenceLines.ToArray() -join "`n" } else { $null }
        if ($status -match '^(?i)on|1$') {
            $bitlockerRemediation = "Run 'Suspend-BitLocker -MountPoint {0}' or suspend BitLocker in Control Panel prior to upgrading." -f $mountPoint
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'BitLocker protection is active on the system drive, so suspend it before running the Windows 11 upgrade.' -Evidence $bitlockerEvidence -Subcategory $subcategory -Remediation $bitlockerRemediation
        } elseif ($status) {
            Add-CategoryNormal -CategoryResult $Result -Title 'BitLocker is not actively protecting the system drive, so the upgrade can proceed after verifying recovery keys.' -Evidence $bitlockerEvidence -Subcategory $subcategory
        }
    }

    $graphicsDataCollected = $false
    $directxVersion = Get-SystemInfoValue -Lines $systemInfoLines -Label 'DirectX Version'
    if ($directxVersion) {
        $graphicsDataCollected = $true
        if ($directxVersion -match '(?i)12') {
            Add-CategoryNormal -CategoryResult $Result -Title 'DirectX 12 detected, aligning with Windows 11 graphics requirements.' -Evidence ("DirectX Version: {0}" -f $directxVersion) -Subcategory $subcategory
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title ('DirectX version {0} detected, so Windows 11 graphics requirements may not be met.' -f $directxVersion) -Evidence 'Requirement: DirectX 12 compatible GPU and WDDM 2.0 driver.' -Subcategory $subcategory -Remediation 'Update GPU hardware or drivers to support DirectX 12 and WDDM 2.0 before upgrading.'
        }
    }

    if (-not $graphicsDataCollected) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'GPU capability data missing, so DirectX 12 and WDDM 2.0 compliance for Windows 11 is unknown.' -Evidence 'Collect dxdiag or GPU driver details to verify DirectX 12 and WDDM 2.0 support.' -Subcategory $subcategory
    }
}
