<#!
.SYNOPSIS
    Security-focused heuristic evaluations based on collected JSON artifacts.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-List {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) { $items += $item }
        return $items
    }
    return @($Value)
}

function ConvertTo-IntArray {
    param($Value)

    $list = @()
    foreach ($item in (ConvertTo-List $Value)) {
        if ($null -eq $item) { continue }
        $text = $item.ToString()
        $parsed = 0
        if ([int]::TryParse($text, [ref]$parsed)) {
            $list += $parsed
        }
    }
    return $list
}

function ConvertTo-VersionValue {
    param($Value)

    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if (-not $text) { return $null }

    $trimmed = $text.Trim()
    if (-not $trimmed) { return $null }

    $match = [regex]::Match($trimmed, '\d+(?:\.\d+)+')
    $candidate = if ($match.Success) { $match.Value } else { $trimmed }

    $parsed = $null
    if ([version]::TryParse($candidate, [ref]$parsed)) { return $parsed }

    try {
        return [version]$candidate
    } catch {
        return $null
    }
}

function Get-DefenderPlatformMinimumValue {
    param($Config)

    if ($null -eq $Config) { return $null }

    if ($Config -is [string]) { return $Config }

    if ($Config -is [System.Collections.IEnumerable] -and -not ($Config -is [string])) {
        foreach ($item in $Config) {
            $candidate = Get-DefenderPlatformMinimumValue $item
            if ($candidate) { return $candidate }
        }
        return $null
    }

    if (-not ($Config | Get-Member -ErrorAction SilentlyContinue)) { return $null }

    $propertyNames = @(
        'DefenderPlatformMinimum',
        'MinimumDefenderPlatformVersion',
        'MinDefenderPlatformVersion',
        'DefenderPlatformVersionMinimum',
        'MinimumDefenderPlatform',
        'MinDefenderPlatform',
        'DefenderPlatform',
        'DefenderPlatformVersion',
        'MinimumPlatformVersion',
        'MinPlatformVersion'
    )

    foreach ($name in $propertyNames) {
        if ($Config.PSObject.Properties[$name]) {
            $value = $Config.$name
            if ($value) { return [string]$value }
        }
    }

    foreach ($child in @('Payload','Minimums','Defender','MicrosoftDefender','Security','Baseline','SecurityBaseline','DefenderBaseline')) {
        if ($Config.PSObject.Properties[$child]) {
            $candidate = Get-DefenderPlatformMinimumValue $Config.$child
            if ($candidate) { return $candidate }
        }
    }

    return $null
}

function Format-BitLockerVolume {
    param($Volume)

    $parts = @()
    if ($Volume.MountPoint) { $parts += ("Mount: {0}" -f $Volume.MountPoint) }
    if ($Volume.VolumeType) { $parts += ("Type: {0}" -f $Volume.VolumeType) }
    if ($Volume.ProtectionStatus -ne $null) { $parts += ("Protection: {0}" -f $Volume.ProtectionStatus) }
    if ($Volume.EncryptionMethod) { $parts += ("Method: {0}" -f $Volume.EncryptionMethod) }
    if ($Volume.LockStatus) { $parts += ("Lock: {0}" -f $Volume.LockStatus) }
    if ($Volume.AutoUnlockEnabled -ne $null) { $parts += ("AutoUnlock: {0}" -f $Volume.AutoUnlockEnabled) }
    return ($parts -join '; ')
}

function Get-RegistryValueFromEntries {
    param(
        $Entries,
        [string]$PathPattern,
        [string]$Name
    )

    foreach ($entry in (ConvertTo-List $Entries)) {
        if (-not $entry) { continue }
        if ($entry.Path -and $entry.Path -match $PathPattern) {
            if ($entry.Values -and $entry.Values.PSObject.Properties[$Name]) {
                return $entry.Values.$Name
            }
        }
    }

    return $null
}

function Get-ArtifactRootData {
    param($Artifact)

    if ($null -eq $Artifact) { return $null }

    if ($Artifact -is [System.Collections.IEnumerable] -and -not ($Artifact -is [string])) {
        foreach ($entry in $Artifact) {
            $candidate = Get-ArtifactRootData $entry
            if ($candidate) { return $candidate }
        }
        return $null
    }

    $payload = Get-ArtifactPayload -Artifact $Artifact
    $resolved = Resolve-SinglePayload -Payload $payload

    if ($resolved -and $resolved.PSObject.Properties['Payload']) {
        $resolved = $resolved.Payload
    }

    if ($resolved) { return $resolved }

    if ($Artifact.PSObject -and $Artifact.PSObject.Properties['Data']) {
        $data = $Artifact.Data
        if ($data) {
            if ($data.PSObject -and $data.PSObject.Properties['Payload']) { return $data.Payload }
            return $data
        }
    }

    return $null
}

function Invoke-SecurityHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Security'

    $operatingSystem = $null
    $isWindows11 = $false
    $systemPayload = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($systemPayload -and $systemPayload.OperatingSystem -and -not $systemPayload.OperatingSystem.Error) {
            $operatingSystem = $systemPayload.OperatingSystem
            if ($operatingSystem.Caption -and $operatingSystem.Caption -match 'Windows\s*11') {
                $isWindows11 = $true
            }
        }
    }

    $defenderBaselineMinimumText = $null
    $baselineArtifactNames = @('security-baseline','defender-baseline','defender-config','security-config')
    foreach ($baselineName in $baselineArtifactNames) {
        if ($defenderBaselineMinimumText) { break }
        $baselineArtifact = Get-AnalyzerArtifact -Context $Context -Name $baselineName
        if (-not $baselineArtifact) { continue }
        $baselineData = Get-ArtifactRootData $baselineArtifact
        if (-not $baselineData) { continue }
        $candidate = Get-DefenderPlatformMinimumValue $baselineData
        if ($candidate) { $defenderBaselineMinimumText = $candidate }
    }
    $defenderBaselineMinimumVersion = ConvertTo-VersionValue $defenderBaselineMinimumText

    $securityServicesRunning = @()
    $securityServicesConfigured = @()
    $availableSecurityProperties = @()
    $requiredSecurityProperties = @()

    $vbshvciArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vbshvci'
    if ($vbshvciArtifact) {
        $vbPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $vbshvciArtifact)
        if ($vbPayload -and $vbPayload.DeviceGuard -and -not $vbPayload.DeviceGuard.Error) {
            $dg = $vbPayload.DeviceGuard
            $securityServicesRunning = ConvertTo-IntArray $dg.SecurityServicesRunning
            $securityServicesConfigured = ConvertTo-IntArray $dg.SecurityServicesConfigured
            $availableSecurityProperties = ConvertTo-IntArray $dg.AvailableSecurityProperties
            $requiredSecurityProperties = ConvertTo-IntArray $dg.RequiredSecurityProperties
        }
    }

    $lsaEntries = @()
    $lsaArtifact = Get-AnalyzerArtifact -Context $Context -Name 'lsa'
    if ($lsaArtifact) {
        $lsaPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lsaArtifact)
        if ($lsaPayload -and $lsaPayload.Registry) {
            $lsaEntries = ConvertTo-List $lsaPayload.Registry
        }
    }

    $defenderArtifact = Get-AnalyzerArtifact -Context $Context -Name 'defender'
    if ($defenderArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $defenderArtifact)
        if ($payload -and $payload.Status -and -not $payload.Status.Error) {
            $status = $payload.Status
            $rtp = ConvertTo-NullableBool $status.RealTimeProtectionEnabled
            if ($rtp -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Defender real-time protection disabled' -Evidence 'Get-MpComputerStatus reports RealTimeProtectionEnabled = False.' -Subcategory 'Microsoft Defender'
            }

            $av = ConvertTo-NullableBool $status.AntivirusEnabled
            if ($av -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'Defender antivirus engine disabled' -Evidence 'Get-MpComputerStatus reports AntivirusEnabled = False.' -Subcategory 'Microsoft Defender'
            }

            $tamper = ConvertTo-NullableBool $status.TamperProtectionEnabled
            if ($tamper -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Tamper protection not enabled' -Evidence 'Get-MpComputerStatus indicates tamper protection is disabled.' -Subcategory 'Microsoft Defender'
            }

            $platformVersionText = $null
            if ($status.PSObject.Properties['AMProductVersion']) { $platformVersionText = [string]$status.AMProductVersion }
            elseif ($status.PSObject.Properties['ProductVersion']) { $platformVersionText = [string]$status.ProductVersion }

            $engineVersionText = $null
            if ($status.PSObject.Properties['AMEngineVersion']) { $engineVersionText = [string]$status.AMEngineVersion }
            elseif ($status.PSObject.Properties['AntimalwareEngineVersion']) { $engineVersionText = [string]$status.AntimalwareEngineVersion }

            $nisPlatformVersionText = $null
            if ($status.PSObject.Properties['NISPlatformVersion']) { $nisPlatformVersionText = [string]$status.NISPlatformVersion }

            $platformVersion = ConvertTo-VersionValue $platformVersionText

            if ($defenderBaselineMinimumVersion -and $platformVersion) {
                $evidenceLines = @()
                if ($platformVersionText) { $evidenceLines += "AMProductVersion: $platformVersionText" }
                if ($engineVersionText) { $evidenceLines += "AMEngineVersion: $engineVersionText" }
                if ($nisPlatformVersionText) { $evidenceLines += "NISPlatformVersion: $nisPlatformVersionText" }
                $evidenceLines += "Minimum required: $defenderBaselineMinimumText"

                if ($payload.OperatingSystem) {
                    $osSection = $payload.OperatingSystem
                    if ($osSection.Error) {
                        $evidenceLines += "Operating system query error: $($osSection.Error)"
                    } else {
                        if ($osSection.PSObject.Properties['Version'] -and $osSection.Version) { $evidenceLines += "OS Version: $($osSection.Version)" }
                        if ($osSection.PSObject.Properties['BuildNumber'] -and $osSection.BuildNumber) { $evidenceLines += "OS Build: $($osSection.BuildNumber)" }
                        if ($osSection.PSObject.Properties['Caption'] -and $osSection.Caption) { $evidenceLines += "OS Caption: $($osSection.Caption)" }
                    }
                }

                $evidenceText = $evidenceLines -join "`n"

                if ($platformVersion -lt $defenderBaselineMinimumVersion) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Defender platform below baseline ({0} < {1}). Update the platform package.' -f $platformVersionText, $defenderBaselineMinimumText) -Evidence $evidenceText -Subcategory 'Microsoft Defender'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title ('Defender platform meets baseline ({0} ≥ {1}).' -f $platformVersionText, $defenderBaselineMinimumText) -Evidence $evidenceText -Subcategory 'Microsoft Defender'
                }
            }

            $definitions = @($status.AntivirusSignatureVersion, $status.AntispywareSignatureVersion) | Where-Object { $_ }
            if ($definitions.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Defender signatures present ({0})' -f ($definitions -join ', '))
            }

            if ($payload.Threats -and $payload.Threats.Count -gt 0 -and -not ($payload.Threats[0] -is [string])) {
                $threatNames = $payload.Threats | Where-Object { $_.ThreatName } | Select-Object -First 5 -ExpandProperty ThreatName
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Recent threats detected: {0}' -f ($threatNames -join ', ')) -Evidence 'Get-MpThreat returned recent detections; confirm remediation.' -Subcategory 'Microsoft Defender'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'No recent Defender detections'
            }
        } elseif ($payload -and $payload.Status -and $payload.Status.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to query Defender status' -Evidence $payload.Status.Error -Subcategory 'Microsoft Defender'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Defender artifact missing expected structure' -Subcategory 'Microsoft Defender'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Defender artifact not collected' -Subcategory 'Microsoft Defender'
    }

    $firewallArtifact = Get-AnalyzerArtifact -Context $Context -Name 'firewall'
    if ($firewallArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $firewallArtifact)
        if ($payload -and $payload.Profiles) {
            $disabledProfiles = @()
            foreach ($profile in $payload.Profiles) {
                if ($profile.PSObject.Properties['Enabled']) {
                    $enabled = ConvertTo-NullableBool $profile.Enabled
                    if ($enabled -eq $false) {
                        $disabledProfiles += $profile.Name
                    }
                    Add-CategoryCheck -CategoryResult $result -Name ("Firewall profile: {0}" -f $profile.Name) -Status ($(if ($enabled) { 'Enabled' } elseif ($enabled -eq $false) { 'Disabled' } else { 'Unknown' })) -Details ("Inbound: {0}; Outbound: {1}" -f $profile.DefaultInboundAction, $profile.DefaultOutboundAction)
                }
            }

            if ($disabledProfiles.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Firewall profiles disabled: {0}' -f ($disabledProfiles -join ', ')) -Subcategory 'Windows Firewall'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'All firewall profiles enabled'
            }
        } elseif ($payload -and $payload.Profiles -and $payload.Profiles.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Firewall profile query failed' -Evidence $payload.Profiles.Error -Subcategory 'Windows Firewall'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Firewall not captured. Collect firewall profile configuration.' -Subcategory 'Windows Firewall'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Firewall not captured. Collect firewall profile configuration.' -Subcategory 'Windows Firewall'
    }

    $bitlockerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'bitlocker'
    if ($bitlockerArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $bitlockerArtifact)
        if ($payload -and $payload.Volumes) {
            $volumes = ConvertTo-List $payload.Volumes
            $osVolumes = @()
            $osUnprotected = @()
            $osProtectedEvidence = @()
            $hasRecoveryProtector = $false

            foreach ($volume in $volumes) {
                if (-not $volume) { continue }
                $mount = if ($volume.MountPoint) { [string]$volume.MountPoint } else { '' }
                $type = if ($volume.VolumeType) { [string]$volume.VolumeType } else { '' }
                $isOs = $false
                if ($type -and $type -match '(?i)(OperatingSystem|System)') { $isOs = $true }
                if (-not $isOs -and $mount) {
                    if ($mount.Trim().ToUpperInvariant() -eq 'C:') { $isOs = $true }
                }
                if ($isOs) { $osVolumes += $volume }

                foreach ($protector in (ConvertTo-List $volume.KeyProtector)) {
                    if ($null -eq $protector) { continue }
                    $protectorText = $protector.ToString()
                    if ($protector.PSObject -and $protector.PSObject.Properties['KeyProtectorType']) {
                        $protectorText = [string]$protector.KeyProtectorType
                    }
                    if ($protectorText -match '(?i)RecoveryPassword') {
                        $hasRecoveryProtector = $true
                    }
                }
            }

            foreach ($osVolume in $osVolumes) {
                $status = if ($osVolume.ProtectionStatus) { $osVolume.ProtectionStatus.ToString() } else { '' }
                $isProtected = $false
                if ($status) {
                    $isProtected = -not ($status -match '(?i)off|0')
                }
                if ($isProtected) {
                    $osProtectedEvidence += (Format-BitLockerVolume $osVolume)
                } else {
                    $osUnprotected += $osVolume
                }
            }

            if ($osUnprotected.Count -gt 0) {
                $mountList = ($osUnprotected | ForEach-Object { $_.MountPoint } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
                if (-not $mountList) { $mountList = 'Unknown volume' }
                $evidence = ($osUnprotected | ForEach-Object { Format-BitLockerVolume $_ }) -join "`n"
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title ("BitLocker is OFF for system volume(s): {0}." -f $mountList) -Evidence $evidence -Subcategory 'BitLocker'
            } elseif ($osProtectedEvidence.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title 'BitLocker protection active for system volume(s).' -Evidence ($osProtectedEvidence -join "`n")
            }

            if (-not $hasRecoveryProtector) {
                $volumeEvidence = ($volumes | ForEach-Object { Format-BitLockerVolume $_ }) -join "`n"
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No BitLocker recovery password protector detected. Ensure recovery keys are escrowed.' -Evidence $volumeEvidence -Subcategory 'BitLocker'
            }
        } elseif ($payload -and $payload.Volumes -and $payload.Volumes.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'BitLocker query failed' -Evidence $payload.Volumes.Error -Subcategory 'BitLocker'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker data missing expected structure' -Subcategory 'BitLocker'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker artifact not collected' -Subcategory 'BitLocker'
    }

    $tpmArtifact = Get-AnalyzerArtifact -Context $Context -Name 'tpm'
    if ($tpmArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $tpmArtifact)
        if ($payload -and $payload.Tpm -and -not $payload.Tpm.Error) {
            $tpm = $payload.Tpm
            $present = ConvertTo-NullableBool $tpm.TpmPresent
            $ready = ConvertTo-NullableBool $tpm.TpmReady
            if ($present -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No TPM detected' -Evidence 'Get-Tpm reported TpmPresent = False.' -Subcategory 'TPM'
            } elseif ($ready -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'TPM not initialized' -Evidence 'Get-Tpm reported TpmReady = False.' -Subcategory 'TPM'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'TPM present and ready'
            }
        } elseif ($payload -and $payload.Tpm -and $payload.Tpm.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to query TPM status' -Evidence $payload.Tpm.Error -Subcategory 'TPM'
        }
    }

    $kernelDmaArtifact = Get-AnalyzerArtifact -Context $Context -Name 'kerneldma'
    if ($kernelDmaArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $kernelDmaArtifact)
        $registryValues = $null
        if ($payload -and $payload.Registry -and $payload.Registry.Values) {
            $registryValues = $payload.Registry.Values
        }
        $allowValue = $null
        if ($registryValues -and $registryValues.PSObject.Properties['AllowDmaUnderLock']) {
            $allowValue = ConvertTo-NullableInt $registryValues.AllowDmaUnderLock
        }
        $evidenceLines = @()
        if ($payload.DeviceGuard) {
            $dg = $payload.DeviceGuard
            if ($dg.Status) { $evidenceLines += "DeviceGuard.Status: $($dg.Status)" }
            if ($dg.Message) { $evidenceLines += "DeviceGuard.Message: $($dg.Message)" }
        }
        if ($payload.Registry -and $payload.Registry.Status) { $evidenceLines += "Registry.Status: $($payload.Registry.Status)" }
        if ($payload.Registry -and $payload.Registry.Message) { $evidenceLines += "Registry.Message: $($payload.Registry.Message)" }
        if ($payload.MsInfo -and $payload.MsInfo.Status) { $evidenceLines += "MsInfo.Status: $($payload.MsInfo.Status)" }
        if ($payload.MsInfo -and $payload.MsInfo.Message) { $evidenceLines += "MsInfo.Message: $($payload.MsInfo.Message)" }
        $dmaEvidence = ($evidenceLines | Where-Object { $_ }) -join "`n"

        if ($allowValue -eq 0) {
            Add-CategoryNormal -CategoryResult $result -Title 'Kernel DMA protection enforced' -Evidence $dmaEvidence
        } elseif ($allowValue -eq 1) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Kernel DMA protection allows DMA while locked on this device (AllowDmaUnderLock = 1).' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Kernel DMA protection unknown. Confirm DMA protection capabilities.' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Kernel DMA protection unknown. Confirm DMA protection capabilities.' -Subcategory 'Kernel DMA'
    }

    $asrArtifact = Get-AnalyzerArtifact -Context $Context -Name 'asr'
    if ($asrArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $asrArtifact)
        $ruleMap = @{}
        if ($payload -and $payload.Policy -and -not $payload.Policy.Error -and $payload.Policy.Rules) {
            foreach ($rule in (ConvertTo-List $payload.Policy.Rules)) {
                if (-not $rule) { continue }
                $id = $rule.RuleId
                if (-not $id) { $id = $rule.Id }
                if (-not $id) { continue }
                $normalized = $id.ToString().ToUpperInvariant()
                $action = $null
                if ($rule.PSObject.Properties['Action']) { $action = ConvertTo-NullableInt $rule.Action }
                $ruleMap[$normalized] = $action
            }
            $requiredRules = @(
                @{ Label = 'Block Office macros from Internet'; Ids = @('3B576869-A4EC-4529-8536-B80A7769E899') },
                @{ Label = 'Block Win32 API calls from Office'; Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A') },
                @{ Label = 'Block executable content from email/WebDAV'; Ids = @('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550','D3E037E1-3EB8-44C8-A917-57927947596D') },
                @{ Label = 'Block credential stealing from LSASS'; Ids = @('9E6C4E1F-7D60-472F-B5E9-2D3BEEB1BF0E') }
            )
            foreach ($set in $requiredRules) {
                $missing = @()
                $nonBlocking = @()
                foreach ($id in $set.Ids) {
                    $lookup = $id.ToUpperInvariant()
                    if (-not $ruleMap.ContainsKey($lookup)) {
                        $missing += $lookup
                        continue
                    }
                    if ($ruleMap[$lookup] -ne 1) {
                        $nonBlocking += "{0} => {1}" -f $lookup, $ruleMap[$lookup]
                    }
                }
                if ($missing.Count -eq 0 -and $nonBlocking.Count -eq 0) {
                    $evidence = ($set.Ids | ForEach-Object { "{0} => 1" -f $_ }) -join "`n"
                    Add-CategoryNormal -CategoryResult $result -Title ("ASR blocking enforced: {0}" -f $set.Label) -Evidence $evidence
                } else {
                    $detailParts = @()
                    if ($missing.Count -gt 0) { $detailParts += ("Missing rule(s): {0}" -f ($missing -join ', ')) }
                    if ($nonBlocking.Count -gt 0) { $detailParts += ("Non-blocking: {0}" -f ($nonBlocking -join '; ')) }
                    $detailText = if ($detailParts.Count -gt 0) { $detailParts -join '; ' } else { 'Rule not enforced.' }
                    $evidenceLines = @()
                    foreach ($id in $set.Ids) {
                        $lookup = $id.ToUpperInvariant()
                        if ($ruleMap.ContainsKey($lookup)) {
                            $evidenceLines += "{0} => {1}" -f $lookup, $ruleMap[$lookup]
                        } else {
                            $evidenceLines += "{0} => (missing)" -f $lookup
                        }
                    }
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("ASR rule not enforced: {0}. Configure to Block (1)." -f $set.Label) -Evidence ($evidenceLines -join "`n") -Subcategory 'Attack Surface Reduction'
                }
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'ASR policy data missing. Configure required Attack Surface Reduction rules.' -Subcategory 'Attack Surface Reduction'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'ASR policy data missing. Configure required Attack Surface Reduction rules.' -Subcategory 'Attack Surface Reduction'
    }

    $exploitArtifact = Get-AnalyzerArtifact -Context $Context -Name 'exploit-protection'
    if ($exploitArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $exploitArtifact)
        if ($payload -and $payload.Mitigations -and -not $payload.Mitigations.Error) {
            $mitigations = $payload.Mitigations
            $cfgEnabled = ConvertTo-NullableBool ($mitigations.CFG.Enable)
            $depEnabled = ConvertTo-NullableBool ($mitigations.DEP.Enable)
            $aslrEnabled = ConvertTo-NullableBool ($mitigations.ASLR.Enable)
            $evidence = @()
            if ($mitigations.CFG.Enable -ne $null) { $evidence += "CFG.Enable: $($mitigations.CFG.Enable)" }
            if ($mitigations.DEP.Enable -ne $null) { $evidence += "DEP.Enable: $($mitigations.DEP.Enable)" }
            if ($mitigations.ASLR.Enable -ne $null) { $evidence += "ASLR.Enable: $($mitigations.ASLR.Enable)" }
            $evidenceText = $evidence -join "`n"
            if (($cfgEnabled -eq $true) -and ($depEnabled -eq $true) -and ($aslrEnabled -eq $true)) {
                Add-CategoryNormal -CategoryResult $result -Title 'Exploit protection mitigations enforced (CFG/DEP/ASLR)' -Evidence $evidenceText
            } else {
                $details = @()
                if ($cfgEnabled -ne $true) { $details += 'CFG disabled' }
                if ($depEnabled -ne $true) { $details += 'DEP disabled' }
                if ($aslrEnabled -ne $true) { $details += 'ASLR disabled' }
                $detailText = if ($details.Count -gt 0) { $details -join '; ' } else { 'Mitigation status unknown.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Exploit protection mitigations not fully enabled ({0}).' -f $detailText) -Evidence $evidenceText -Subcategory 'Exploit Protection'
            }
        } elseif ($payload -and $payload.Mitigations -and $payload.Mitigations.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Exploit Protection not captured. Collect Get-ProcessMitigation output.' -Evidence $payload.Mitigations.Error -Subcategory 'Exploit Protection'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Exploit Protection not captured. Collect Get-ProcessMitigation output.' -Subcategory 'Exploit Protection'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Exploit Protection not captured. Collect Get-ProcessMitigation output.' -Subcategory 'Exploit Protection'
    }

    $wdacArtifact = Get-AnalyzerArtifact -Context $Context -Name 'wdac'
    if ($wdacArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wdacArtifact)
        $wdacEvidenceLines = @()
        if ($payload -and $payload.DeviceGuard -and -not $payload.DeviceGuard.Error) {
            $dgSection = $payload.DeviceGuard
            $wdacEvidenceLines += "SecurityServicesRunning: $($dgSection.SecurityServicesRunning)"
            $wdacEvidenceLines += "SecurityServicesConfigured: $($dgSection.SecurityServicesConfigured)"
            if ($securityServicesRunning.Count -eq 0) { $securityServicesRunning = ConvertTo-IntArray $dgSection.SecurityServicesRunning }
            if ($securityServicesConfigured.Count -eq 0) { $securityServicesConfigured = ConvertTo-IntArray $dgSection.SecurityServicesConfigured }
            if ($availableSecurityProperties.Count -eq 0) { $availableSecurityProperties = ConvertTo-IntArray $dgSection.AvailableSecurityProperties }
            if ($requiredSecurityProperties.Count -eq 0) { $requiredSecurityProperties = ConvertTo-IntArray $dgSection.RequiredSecurityProperties }
        }

        $wdacEnforced = $false
        if ($securityServicesRunning -contains 4 -or $securityServicesConfigured -contains 4) { $wdacEnforced = $true }

        if ($payload -and $payload.Registry) {
            foreach ($entry in (ConvertTo-List $payload.Registry)) {
                if ($entry.Path -and $entry.Path -match 'Control\\CI') {
                    foreach ($prop in $entry.Values.PSObject.Properties) {
                        if ($prop.Name -match '^PS') { continue }
                        $wdacEvidenceLines += ("{0}: {1}" -f $prop.Name, $prop.Value)
                        if ($prop.Name -match 'PolicyEnforcement' -and (ConvertTo-NullableInt $prop.Value) -ge 1) {
                            $wdacEnforced = $true
                        }
                    }
                }
            }
        }

        if ($wdacEnforced) {
            Add-CategoryNormal -CategoryResult $result -Title 'WDAC policy enforcement detected' -Evidence ($wdacEvidenceLines -join "`n")
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'No WDAC policy enforcement detected. Evaluate Application Control requirements.' -Evidence ($wdacEvidenceLines -join "`n") -Subcategory 'Windows Defender Application Control'
        }

        $smartAppEvidence = @()
        $smartAppState = $null
        if ($payload -and $payload.SmartAppControl) {
            $entry = $payload.SmartAppControl
            if ($entry.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to query Smart App Control state' -Evidence $entry.Error -Subcategory 'Smart App Control'
            } elseif ($entry.Values) {
                foreach ($prop in $entry.Values.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $smartAppEvidence += ("{0}: {1}" -f $prop.Name, $prop.Value)
                    $candidate = $prop.Value
                    if ($null -ne $candidate) {
                        $parsed = 0
                        if ([int]::TryParse($candidate.ToString(), [ref]$parsed)) {
                            if ($prop.Name -match 'Enabled' -or $prop.Name -match 'State') {
                                $smartAppState = $parsed
                            }
                        }
                    }
                }
            }
        }

        $evidenceText = if ($smartAppEvidence.Count -gt 0) { $smartAppEvidence -join "`n" } else { '' }
        if ($smartAppState -eq 1) {
            Add-CategoryNormal -CategoryResult $result -Title 'Smart App Control enforced' -Evidence $evidenceText
        } elseif ($smartAppState -eq 2) {
            $severity = if ($isWindows11) { 'low' } else { 'info' }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Smart App Control in evaluation mode' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($isWindows11) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Smart App Control is not enabled on Windows 11 device.' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($smartAppState -ne $null) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Smart App Control disabled' -Evidence $evidenceText -Subcategory 'Smart App Control'
        }
    }

    $lapsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'laps_localadmin'
    if (-not $lapsArtifact) {
        $lapsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'laps'
    }
    if ($lapsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lapsArtifact)
        $lapsPolicies = $null
        if ($payload -and $payload.LapsPolicies) {
            $lapsPolicies = $payload.LapsPolicies
        } elseif ($payload -and $payload.Policy) {
            $lapsPolicies = $payload.Policy
        }

        $lapsEnabled = $false
        $lapsEvidenceLines = @()
        if ($lapsPolicies) {
            foreach ($prop in $lapsPolicies.PSObject.Properties) {
                if ($prop.Name -match '^PS') { continue }
                $value = $prop.Value
                if ($null -eq $value) { continue }
                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                    foreach ($inner in $value) {
                        $lapsEvidenceLines += ("{0}: {1}" -f $prop.Name, $inner)
                    }
                } else {
                    $lapsEvidenceLines += ("{0}: {1}" -f $prop.Name, $value)
                }
                if ($prop.Name -match 'Enabled' -and (ConvertTo-NullableInt $value) -eq 1) { $lapsEnabled = $true }
                if ($prop.Name -match 'BackupDirectory' -and -not [string]::IsNullOrWhiteSpace($value.ToString())) { $lapsEnabled = $true }
            }
        }

        if ($lapsEnabled) {
            Add-CategoryNormal -CategoryResult $result -Title 'LAPS/PLAP policy detected' -Evidence ($lapsEvidenceLines -join "`n")
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'LAPS/PLAP not detected. Enforce password management policy.' -Evidence ($lapsEvidenceLines -join "`n") -Subcategory 'Credential Management'
        }
    }

    $runAsPpl = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RunAsPPL')
    $runAsPplBoot = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RunAsPPLBoot')
    $credentialGuardRunning = ($securityServicesRunning -contains 1)
    $lsaEvidenceLines = @()
    if ($credentialGuardRunning) { $lsaEvidenceLines += 'SecurityServicesRunning includes 1 (Credential Guard).' }
    if ($runAsPpl -ne $null) { $lsaEvidenceLines += "RunAsPPL: $runAsPpl" }
    if ($runAsPplBoot -ne $null) { $lsaEvidenceLines += "RunAsPPLBoot: $runAsPplBoot" }
    $lsaEvidence = $lsaEvidenceLines -join "`n"
    if ($credentialGuardRunning -and $runAsPpl -eq 1) {
        Add-CategoryNormal -CategoryResult $result -Title 'Credential Guard with LSA protection enabled' -Evidence $lsaEvidence
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Credential Guard or LSA protection is not enforced. Enable RunAsPPL and Credential Guard.' -Evidence $lsaEvidence -Subcategory 'Credential Guard'
    }

    $deviceGuardEvidenceLines = @()
    if ($securityServicesConfigured.Count -gt 0) { $deviceGuardEvidenceLines += "Configured: $($securityServicesConfigured -join ',')" }
    if ($securityServicesRunning.Count -gt 0) { $deviceGuardEvidenceLines += "Running: $($securityServicesRunning -join ',')" }
    if ($availableSecurityProperties.Count -gt 0) { $deviceGuardEvidenceLines += "Available: $($availableSecurityProperties -join ',')" }
    if ($requiredSecurityProperties.Count -gt 0) { $deviceGuardEvidenceLines += "Required: $($requiredSecurityProperties -join ',')" }
    $hvciEvidence = $deviceGuardEvidenceLines -join "`n"
    $hvciRunning = ($securityServicesRunning -contains 2)
    $hvciAvailable = ($availableSecurityProperties -contains 2) -or ($requiredSecurityProperties -contains 2)
    if ($hvciRunning) {
        Add-CategoryNormal -CategoryResult $result -Title 'Memory integrity (HVCI) running' -Evidence $hvciEvidence
    } elseif ($hvciAvailable) {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Memory integrity (HVCI) is available but not running. Enable virtualization-based protection.' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Memory integrity (HVCI) not captured. Collect Device Guard diagnostics.' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    }

    $uacArtifact = Get-AnalyzerArtifact -Context $Context -Name 'uac'
    if ($uacArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $uacArtifact)
        if ($payload -and $payload.Policy -and -not $payload.Policy.Error) {
            $policy = $payload.Policy
            $enableLua = ConvertTo-NullableInt $policy.EnableLUA
            $consentPrompt = ConvertTo-NullableInt $policy.ConsentPromptBehaviorAdmin
            $secureDesktop = ConvertTo-NullableInt $policy.PromptOnSecureDesktop
            $evidence = ($policy.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "{0} = {1}" -f $_.Name, $_.Value }) -join "`n"
            if ($enableLua -eq 1 -and ($secureDesktop -eq $null -or $secureDesktop -eq 1) -and ($consentPrompt -eq $null -or $consentPrompt -ge 2)) {
                Add-CategoryNormal -CategoryResult $result -Title 'UAC configured with secure prompts' -Evidence $evidence
            } else {
                $findings = @()
                if ($enableLua -ne 1) { $findings += 'EnableLUA=0' }
                if ($consentPrompt -ne $null -and $consentPrompt -lt 2) { $findings += "ConsentPrompt=$consentPrompt" }
                if ($secureDesktop -ne $null -and $secureDesktop -eq 0) { $findings += 'PromptOnSecureDesktop=0' }
                $detail = if ($findings.Count -gt 0) { $findings -join '; ' } else { 'UAC configuration unclear.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('UAC configuration is insecure ({0}). Enforce secure UAC prompts.' -f $detail) -Evidence $evidence -Subcategory 'User Account Control'
            }
        }
    }

    $psLoggingArtifact = Get-AnalyzerArtifact -Context $Context -Name 'powershell-logging'
    if ($psLoggingArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $psLoggingArtifact)
        if ($payload -and $payload.Policies) {
            $scriptBlockEnabled = $false
            $moduleLoggingEnabled = $false
            $transcriptionEnabled = $false
            $evidenceLines = @()
            foreach ($policy in (ConvertTo-List $payload.Policies)) {
                if (-not $policy -or -not $policy.Values) { continue }
                foreach ($prop in $policy.Values.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $evidenceLines += ("{0} ({1}): {2}" -f $prop.Name, $policy.Path, $prop.Value)
                    switch -Regex ($prop.Name) {
                        'EnableScriptBlockLogging' { if ((ConvertTo-NullableInt $prop.Value) -eq 1) { $scriptBlockEnabled = $true } }
                        'EnableModuleLogging'     { if ((ConvertTo-NullableInt $prop.Value) -eq 1) { $moduleLoggingEnabled = $true } }
                        'EnableTranscripting'     { if ((ConvertTo-NullableInt $prop.Value) -eq 1) { $transcriptionEnabled = $true } }
                    }
                }
            }
            if ($scriptBlockEnabled -and $moduleLoggingEnabled) {
                Add-CategoryNormal -CategoryResult $result -Title 'PowerShell logging policies enforced' -Evidence ($evidenceLines -join "`n")
            } else {
                $detailParts = @()
                if (-not $scriptBlockEnabled) { $detailParts += 'Script block logging disabled' }
                if (-not $moduleLoggingEnabled) { $detailParts += 'Module logging disabled' }
                if (-not $transcriptionEnabled) { $detailParts += 'Transcription not enabled' }
                $detail = if ($detailParts.Count -gt 0) { $detailParts -join '; ' } else { 'Logging state unknown.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('PowerShell logging is incomplete ({0}). Enable required logging for auditing.' -f $detail) -Evidence ($evidenceLines -join "`n") -Subcategory 'PowerShell Logging'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'PowerShell logging is incomplete (Script block logging disabled; Module logging disabled; Transcription not enabled). Enable required logging for auditing.' -Subcategory 'PowerShell Logging'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'PowerShell logging is incomplete (Script block logging disabled; Module logging disabled; Transcription not enabled). Enable required logging for auditing.' -Subcategory 'PowerShell Logging'
    }

    $restrictSendingLsa = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RestrictSendingNTLMTraffic')
    $msvEntry = Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa\\\\MSV1_0$' -Name 'RestrictSendingNTLMTraffic'
    $restrictSendingMsv = ConvertTo-NullableInt $msvEntry
    $restrictReceivingMsv = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa\\\\MSV1_0$' -Name 'RestrictReceivingNTLMTraffic')
    $auditReceivingMsv = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa\\\\MSV1_0$' -Name 'AuditReceivingNTLMTraffic')
    $ntlmEvidenceLines = @()
    if ($restrictSendingLsa -ne $null) { $ntlmEvidenceLines += "Lsa RestrictSendingNTLMTraffic: $restrictSendingLsa" }
    if ($restrictSendingMsv -ne $null) { $ntlmEvidenceLines += "MSV1_0 RestrictSendingNTLMTraffic: $restrictSendingMsv" }
    if ($restrictReceivingMsv -ne $null) { $ntlmEvidenceLines += "MSV1_0 RestrictReceivingNTLMTraffic: $restrictReceivingMsv" }
    if ($auditReceivingMsv -ne $null) { $ntlmEvidenceLines += "MSV1_0 AuditReceivingNTLMTraffic: $auditReceivingMsv" }
    $ntlmEvidence = $ntlmEvidenceLines -join "`n"
    $ntlmRestricted = ($restrictSendingLsa -ge 2) -or ($restrictSendingMsv -ge 2)
    $ntlmAudited = ($auditReceivingMsv -ge 2)
    if ($ntlmRestricted -and $ntlmAudited) {
        Add-CategoryNormal -CategoryResult $result -Title 'NTLM hardening policies enforced' -Evidence $ntlmEvidence
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'NTLM hardening policies are not configured. Enforce RestrictSending/Audit NTLM settings.' -Evidence $ntlmEvidence -Subcategory 'NTLM Hardening'
    }

    return $result
}
