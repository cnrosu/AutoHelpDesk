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
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $items.Add($item) }
        return $items.ToArray()
    }
    return @($Value)
}

function ConvertTo-IntArray {
    param($Value)

    $list = [System.Collections.Generic.List[int]]::new()
    foreach ($item in (ConvertTo-List $Value)) {
        if ($null -eq $item) { continue }
        $text = $item.ToString()
        $parsed = 0
        if ([int]::TryParse($text, [ref]$parsed)) {
            $list.Add($parsed)
        }
    }
    return $list.ToArray()
}

function Get-ObjectPropertyString {
    param(
        $Object,
        [string]$PropertyName,
        [string]$NullPlaceholder = 'null'
    )

    if (-not $Object) { return $NullPlaceholder }
    if (-not $PropertyName) { return $NullPlaceholder }

    $property = $Object.PSObject.Properties[$PropertyName]
    if (-not $property) { return $NullPlaceholder }

    $value = $property.Value
    if ($null -eq $value) { return $NullPlaceholder }

    if ($value -is [bool]) {
        if ($value) { return 'True' }
        return 'False'
    }
    return [string]$value
}

function Format-BitLockerVolume {
    param($Volume)

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($Volume.MountPoint) { $parts.Add(("Mount: {0}" -f $Volume.MountPoint)) }
    if ($Volume.VolumeType) { $parts.Add(("Type: {0}" -f $Volume.VolumeType)) }
    if ($Volume.ProtectionStatus -ne $null) { $parts.Add(("Protection: {0}" -f $Volume.ProtectionStatus)) }
    if ($Volume.EncryptionMethod) { $parts.Add(("Method: {0}" -f $Volume.EncryptionMethod)) }
    if ($Volume.LockStatus) { $parts.Add(("Lock: {0}" -f $Volume.LockStatus)) }
    if ($Volume.AutoUnlockEnabled -ne $null) { $parts.Add(("AutoUnlock: {0}" -f $Volume.AutoUnlockEnabled)) }
    return ($parts.ToArray() -join '; ')
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

function ConvertTo-NullablePolicyInt {
    param($Value)

    if ($Value -is [int]) { return [int]$Value }
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

function Get-AutorunPolicyValue {
    param(
        $Entries,
        [string[]]$PreferredPaths,
        [string]$Name
    )

    if (-not $Entries) { return $null }

    foreach ($path in $PreferredPaths) {
        foreach ($entry in (ConvertTo-List $Entries)) {
            if (-not $entry) { continue }
            if ($entry.Path -ne $path) { continue }
            if ($entry.Error) { continue }
            if ($entry.PSObject.Properties['Exists'] -and -not $entry.Exists) { continue }
            if (-not $entry.Values) { continue }

            $property = $entry.Values.PSObject.Properties[$Name]
            if (-not $property) { continue }

            $converted = ConvertTo-NullablePolicyInt $property.Value
            return [pscustomobject]@{
                Path    = $entry.Path
                Value   = $converted
                RawValue = $property.Value
            }
        }
    }

    foreach ($entry in (ConvertTo-List $Entries)) {
        if (-not $entry) { continue }
        if ($entry.Error) { continue }
        if ($entry.PSObject.Properties['Exists'] -and -not $entry.Exists) { continue }
        if (-not $entry.Values) { continue }

        $property = $entry.Values.PSObject.Properties[$Name]
        if (-not $property) { continue }

        $converted = ConvertTo-NullablePolicyInt $property.Value
        return [pscustomobject]@{
            Path    = $entry.Path
            Value   = $converted
            RawValue = $property.Value
        }
    }

    return $null
}

function Invoke-SecurityHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Security' -Message 'Starting security heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Security'

    $operatingSystem = $null
    $isWindows11 = $false
    $systemPayload = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved system artifact' -Data ([ordered]@{
        Found = [bool]$systemArtifact
    })
    if ($systemArtifact) {
        $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating system payload for OS details' -Data ([ordered]@{
            HasPayload = [bool]$systemPayload
        })
        if ($systemPayload -and $systemPayload.OperatingSystem -and -not $systemPayload.OperatingSystem.Error) {
            $operatingSystem = $systemPayload.OperatingSystem
            if ($operatingSystem.Caption -and $operatingSystem.Caption -match 'Windows\s*11') {
                $isWindows11 = $true
            }
        }
    }

    $securityServicesRunning = @()
    $securityServicesConfigured = @()
    $availableSecurityProperties = @()
    $requiredSecurityProperties = @()

    $vbshvciArtifact = Get-AnalyzerArtifact -Context $Context -Name 'vbshvci'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved VBS/HVCI artifact' -Data ([ordered]@{
        Found = [bool]$vbshvciArtifact
    })
    if ($vbshvciArtifact) {
        $vbPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $vbshvciArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating VBS/HVCI payload' -Data ([ordered]@{
            HasPayload = [bool]$vbPayload
        })
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
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved LSA artifact' -Data ([ordered]@{
        Found = [bool]$lsaArtifact
    })
    if ($lsaArtifact) {
        $lsaPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lsaArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating LSA payload' -Data ([ordered]@{
            HasRegistry = [bool]($lsaPayload -and $lsaPayload.Registry)
        })
        if ($lsaPayload -and $lsaPayload.Registry) {
            $lsaEntries = ConvertTo-List $lsaPayload.Registry
        }
    }

    $defenderArtifact = Get-AnalyzerArtifact -Context $Context -Name 'defender'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved Defender artifact' -Data ([ordered]@{
        Found = [bool]$defenderArtifact
    })
    if ($defenderArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $defenderArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating Defender payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        $statusTamper = $null
        if ($payload -and $payload.Status -and -not $payload.Status.Error) {
            $status = $payload.Status
            $rtp = ConvertTo-NullableBool $status.RealTimeProtectionEnabled
            if ($rtp -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Defender real-time protection disabled, creating antivirus protection gaps.' -Evidence 'Get-MpComputerStatus reports RealTimeProtectionEnabled = False.' -Subcategory 'Microsoft Defender'
            }

            $av = ConvertTo-NullableBool $status.AntivirusEnabled
            if ($av -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'Defender antivirus engine disabled, creating antivirus protection gaps.' -Evidence 'Get-MpComputerStatus reports AntivirusEnabled = False.' -Subcategory 'Microsoft Defender'
            }
            $statusTamper = ConvertTo-NullableBool $status.TamperProtectionEnabled

            $definitions = @($status.AntivirusSignatureVersion, $status.AntispywareSignatureVersion) | Where-Object { $_ }
            if ($definitions.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Defender signatures present ({0})' -f ($definitions -join ', ')) -Subcategory 'Microsoft Defender'
            }

            if ($payload.Threats -and $payload.Threats.Count -gt 0 -and -not ($payload.Threats[0] -is [string])) {
                $threatNames = $payload.Threats | Where-Object { $_.ThreatName } | Select-Object -First 5 -ExpandProperty ThreatName
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Recent threats detected: {0}' -f ($threatNames -join ', ')) -Evidence 'Get-MpThreat returned recent detections; confirm remediation.' -Subcategory 'Microsoft Defender'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'No recent Defender detections' -Subcategory 'Microsoft Defender'
            }
        } elseif ($payload -and $payload.Status -and $payload.Status.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to query Defender status, leaving antivirus protection gaps unverified.' -Evidence $payload.Status.Error -Subcategory 'Microsoft Defender'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Defender artifact missing expected structure, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender'
        }

        if ($payload -and $payload.PSObject.Properties['Preferences']) {
            $preferencesEntry = Resolve-SinglePayload -Payload $payload.Preferences
            if ($preferencesEntry -and $preferencesEntry.PSObject.Properties['Error'] -and $preferencesEntry.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to query Defender preferences, leaving antivirus protection gaps unverified.' -Evidence $preferencesEntry.Error -Subcategory 'Microsoft Defender'
            } elseif ($preferencesEntry) {
                $prefEvidence = 'DisableTamperProtection={0}; MAPSReporting={1}; SubmitSamplesConsent={2}; CloudBlockLevel={3}' -f `
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'DisableTamperProtection'),
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'MAPSReporting'),
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'SubmitSamplesConsent'),
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'CloudBlockLevel')

                $prefTamperDisabled = $null
                if ($preferencesEntry.PSObject.Properties['DisableTamperProtection']) {
                    $prefTamperDisabled = ConvertTo-NullableBool $preferencesEntry.DisableTamperProtection
                }

                $tamperProtectionOff = $false
                if ($prefTamperDisabled -eq $true -or $statusTamper -eq $false) {
                    $tamperProtectionOff = $true
                }

                if ($tamperProtectionOff) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Defender tamper protection disabled, creating antivirus protection gaps.' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderTamper'
                } elseif (($prefTamperDisabled -eq $false) -or ($statusTamper -eq $true)) {
                    Add-CategoryNormal -CategoryResult $result -Title 'Defender tamper protection enabled' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderTamper'
                }

                $mapsEnabled = $null
                if ($preferencesEntry.PSObject.Properties['MAPSReporting']) {
                    $mapsRaw = $preferencesEntry.MAPSReporting
                    if ($null -ne $mapsRaw) {
                        $mapsText = [string]$mapsRaw
                        $mapsTrimmed = $mapsText.Trim()
                        if ($mapsTrimmed) {
                            $mapsInt = 0
                            if ([int]::TryParse($mapsTrimmed, [ref]$mapsInt)) {
                                $mapsEnabled = ($mapsInt -gt 0)
                            } else {
                                try {
                                    $mapsLower = $mapsTrimmed.ToLowerInvariant()
                                } catch {
                                    $mapsLower = $mapsTrimmed
                                    if ($mapsLower) { $mapsLower = $mapsLower.ToLowerInvariant() }
                                }
                                if ($mapsLower -in @('0', 'off', 'disable', 'disabled')) {
                                    $mapsEnabled = $false
                                } elseif ($mapsLower -in @('basic', 'advanced')) {
                                    $mapsEnabled = $true
                                } else {
                                    $mapsEnabled = $null
                                }
                            }
                        }
                    }
                }

                $cloudDisabled = $null
                if ($preferencesEntry.PSObject.Properties['CloudBlockLevel']) {
                    $cloudRaw = $preferencesEntry.CloudBlockLevel
                    if ($null -ne $cloudRaw) {
                        $cloudText = [string]$cloudRaw
                        $cloudTrimmed = $cloudText.Trim()
                        if ($cloudTrimmed) {
                            try {
                                $cloudLower = $cloudTrimmed.ToLowerInvariant()
                            } catch {
                                $cloudLower = $cloudTrimmed
                                if ($cloudLower) { $cloudLower = $cloudLower.ToLowerInvariant() }
                            }

                            if ($cloudLower -in @('0', 'off', 'disable', 'disabled')) {
                                $cloudDisabled = $true
                            } elseif ($cloudLower -in @('high', 'highplus', 'high+') -or ($cloudLower -match '^[1-4]$')) {
                                $cloudDisabled = $false
                            }
                        }
                    }
                }

                $cloudProtectionOff = $false
                if ($mapsEnabled -eq $false -or $cloudDisabled -eq $true) {
                    $cloudProtectionOff = $true
                }

                if ($cloudProtectionOff) {
                    $cloudSeverity = 'medium'
                    if (($mapsEnabled -eq $false) -and ($cloudDisabled -eq $true)) {
                        $cloudSeverity = 'high'
                    }

                    Add-CategoryIssue -CategoryResult $result -Severity $cloudSeverity -Title 'Defender cloud-delivered protection disabled, creating antivirus protection gaps.' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderCloudProt'
                } elseif (($mapsEnabled -eq $true) -or ($cloudDisabled -eq $false)) {
                    Add-CategoryNormal -CategoryResult $result -Title 'Defender cloud-delivered protection enabled' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderCloudProt'
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Defender artifact not collected, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender'
    }

    $firewallArtifact = Get-AnalyzerArtifact -Context $Context -Name 'firewall'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved firewall artifact' -Data ([ordered]@{
        Found = [bool]$firewallArtifact
    })
    if ($firewallArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $firewallArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating firewall payload' -Data ([ordered]@{
            HasProfiles = [bool]($payload -and $payload.Profiles)
        })
        if ($payload -and $payload.Profiles) {
            $disabledProfiles = [System.Collections.Generic.List[string]]::new()
            foreach ($profile in $payload.Profiles) {
                if ($profile.PSObject.Properties['Enabled']) {
                    $enabled = ConvertTo-NullableBool $profile.Enabled
                    if ($enabled -eq $false) {
                        $disabledProfiles.Add($profile.Name)
                    }
                    Add-CategoryCheck -CategoryResult $result -Name ("Firewall profile: {0}" -f $profile.Name) -Status ($(if ($enabled) { 'Enabled' } elseif ($enabled -eq $false) { 'Disabled' } else { 'Unknown' })) -Details ("Inbound: {0}; Outbound: {1}" -f $profile.DefaultInboundAction, $profile.DefaultOutboundAction)
                }
            }

            if ($disabledProfiles.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Firewall profiles disabled: {0}, leaving the system unprotected.' -f ($disabledProfiles -join ', ')) -Subcategory 'Windows Firewall'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'All firewall profiles enabled' -Subcategory 'Windows Firewall'
            }
        } elseif ($payload -and $payload.Profiles -and $payload.Profiles.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Firewall profile query failed, so the network defense posture is unknown.' -Evidence $payload.Profiles.Error -Subcategory 'Windows Firewall'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Firewall not captured, so the network defense posture is unknown.' -Subcategory 'Windows Firewall'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Firewall not captured, so the network defense posture is unknown.' -Subcategory 'Windows Firewall'
    }

    $bitlockerArtifact = Get-AnalyzerArtifact -Context $Context -Name 'bitlocker'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved BitLocker artifact' -Data ([ordered]@{
        Found = [bool]$bitlockerArtifact
    })
    if ($bitlockerArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $bitlockerArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating BitLocker payload' -Data ([ordered]@{
            HasVolumes = [bool]($payload -and $payload.Volumes)
        })
        if ($payload -and $payload.Volumes) {
            $volumes = ConvertTo-List $payload.Volumes
            $osVolumeDetails = [System.Collections.Generic.List[object]]::new()
            $osUnprotected = [System.Collections.Generic.List[object]]::new()
            $osProtectedEvidence = [System.Collections.Generic.List[string]]::new()
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
                $protectorTypes = [System.Collections.Generic.List[string]]::new()

                foreach ($protector in (ConvertTo-List $volume.KeyProtector)) {
                    if ($null -eq $protector) { continue }
                    $protectorText = $protector.ToString()
                    if ($protector.PSObject -and $protector.PSObject.Properties['KeyProtectorType']) {
                        $protectorText = [string]$protector.KeyProtectorType
                    }
                    if ($protectorText -match '(?i)RecoveryPassword') {
                        $hasRecoveryProtector = $true
                    }
                    if (-not [string]::IsNullOrWhiteSpace($protectorText)) {
                        $null = $protectorTypes.Add($protectorText)
                    }
                }

                $distinctProtectorTypes = @($protectorTypes.ToArray() | Sort-Object -Unique)
                if ($null -eq $distinctProtectorTypes) { $distinctProtectorTypes = @() }
                if ($isOs) {
                    $osVolumeDetails.Add([pscustomobject]@{
                        Volume          = $volume
                        MountPoint      = $mount
                        ProtectorTypes  = $distinctProtectorTypes
                    })
                }
            }

            $osPasswordOrRecoveryOnly = [System.Collections.Generic.List[object]]::new()
            $osTpmVolumes = [System.Collections.Generic.List[object]]::new()
            $osTpmPinVolumes = [System.Collections.Generic.List[object]]::new()

            foreach ($detail in $osVolumeDetails) {
                $osVolume = $detail.Volume
                $status = if ($osVolume.ProtectionStatus) { $osVolume.ProtectionStatus.ToString() } else { '' }
                $isProtected = $false
                if ($status) {
                    $isProtected = -not ($status -match '(?i)off|0')
                }
                if ($isProtected) {
                    $osProtectedEvidence.Add((Format-BitLockerVolume $osVolume))
                } else {
                    $osUnprotected.Add($osVolume)
                }

                $types = if ($detail.ProtectorTypes) { @($detail.ProtectorTypes) } else { @() }
                $nonPasswordRecovery = @($types | Where-Object { $_ -notmatch '(?i)^(password|recovery.*)$' })
                if ($types.Count -gt 0 -and $nonPasswordRecovery.Count -eq 0) {
                    $osPasswordOrRecoveryOnly.Add($detail)
                }

                $hasTpm = $false
                $hasTpmPin = $false
                foreach ($protectorType in $types) {
                    if ($protectorType -match '(?i)tpm.*pin') {
                        $hasTpm = $true
                        $hasTpmPin = $true
                    } elseif ($protectorType -match '(?i)^tpm$') {
                        $hasTpm = $true
                    }
                }

                if ($hasTpmPin) {
                    $osTpmPinVolumes.Add($detail)
                } elseif ($hasTpm) {
                    $osTpmVolumes.Add($detail)
                }
            }

            if ($osUnprotected.Count -gt 0) {
                $mountPoints = [System.Collections.Generic.List[string]]::new()
                foreach ($volume in $osUnprotected) {
                    if ($volume.MountPoint) {
                        $null = $mountPoints.Add([string]$volume.MountPoint)
                    }
                }

                $mountList = ($mountPoints | Sort-Object -Unique) -join ', '
                if (-not $mountList) { $mountList = 'Unknown volume' }
                $evidence = ($osUnprotected | ForEach-Object { Format-BitLockerVolume $_ }) -join "`n"
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title ("BitLocker is OFF for system volume(s): {0}, risking data exposure." -f $mountList) -Evidence $evidence -Subcategory 'BitLocker'
            } elseif ($osProtectedEvidence.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title 'BitLocker protection active for system volume(s).' -Evidence ($osProtectedEvidence.ToArray() -join "`n") -Subcategory 'BitLocker'
            }

            if ($osPasswordOrRecoveryOnly.Count -gt 0) {
                $mountSummary = [System.Collections.Generic.List[string]]::new()
                $evidenceLines = [System.Collections.Generic.List[string]]::new()
                foreach ($detail in $osPasswordOrRecoveryOnly) {
                    $mountLabel = if ($detail.MountPoint) { $detail.MountPoint } else { 'Unknown volume' }
                    $protectorSummary = if ($detail.ProtectorTypes -and $detail.ProtectorTypes.Count -gt 0) { $detail.ProtectorTypes -join ', ' } else { 'None' }
                    $null = $mountSummary.Add($mountLabel)
                    $null = $evidenceLines.Add(('{0} -> Protectors: {1}' -f $mountLabel, $protectorSummary))
                }
                $null = $evidenceLines.Add('Remediation: Configure TPM+PIN BitLocker protectors where mandated by policy to enforce strong pre-boot authentication.')
                $volumeList = ($mountSummary | Sort-Object -Unique) -join ', '
                if (-not $volumeList) { $volumeList = 'Unknown volume' }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("System volume(s) {0} only use password-based BitLocker protectors, so attackers who obtain those secrets can unlock the device." -f $volumeList) -Evidence ($evidenceLines.ToArray() -join "`n") -Subcategory 'BitLocker'
            }

            if ($osTpmPinVolumes.Count -gt 0) {
                $evidence = ($osTpmPinVolumes | ForEach-Object {
                        $label = if ($_.MountPoint) { $_.MountPoint } else { 'Unknown volume' }
                        $types = if ($_.ProtectorTypes -and $_.ProtectorTypes.Count -gt 0) { $_.ProtectorTypes -join ', ' } else { 'None' }
                        '{0} -> Protectors: {1}' -f $label, $types
                    }) -join "`n"
                Add-CategoryNormal -CategoryResult $result -Title 'System volume(s) configured with TPM+PIN BitLocker protectors, reducing pre-boot compromise risk.' -Evidence $evidence -Subcategory 'BitLocker'
            }

            if ($osTpmVolumes.Count -gt 0) {
                $evidence = ($osTpmVolumes | ForEach-Object {
                        $label = if ($_.MountPoint) { $_.MountPoint } else { 'Unknown volume' }
                        $types = if ($_.ProtectorTypes -and $_.ProtectorTypes.Count -gt 0) { $_.ProtectorTypes -join ', ' } else { 'None' }
                        '{0} -> Protectors: {1}' -f $label, $types
                    }) -join "`n"
                Add-CategoryNormal -CategoryResult $result -Title 'System volume(s) protected with TPM-backed BitLocker keys, limiting exposure if the drive is removed.' -Evidence $evidence -Subcategory 'BitLocker'
            }

            if (-not $hasRecoveryProtector) {
                $volumeEvidence = ($volumes | ForEach-Object { Format-BitLockerVolume $_ }) -join "`n"
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No BitLocker recovery password protector detected, risking data exposure if recovery is needed.' -Evidence $volumeEvidence -Subcategory 'BitLocker'
            }
        } elseif ($payload -and $payload.Volumes -and $payload.Volumes.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'BitLocker query failed, so the encryption state and data exposure risk are unknown.' -Evidence $payload.Volumes.Error -Subcategory 'BitLocker'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker data missing expected structure, so the encryption state and data exposure risk are unknown.' -Subcategory 'BitLocker'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker artifact not collected, so the encryption state and data exposure risk are unknown.' -Subcategory 'BitLocker'
    }

    $measuredBootArtifact = Get-AnalyzerArtifact -Context $Context -Name 'measured-boot'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved measured boot artifact' -Data ([ordered]@{
        Found = [bool]$measuredBootArtifact
    })
    if ($measuredBootArtifact) {
        $measuredPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $measuredBootArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating measured boot payload' -Data ([ordered]@{
            HasPayload = [bool]$measuredPayload
        })

        if ($measuredPayload) {
            $bitlockerSection = $null
            if ($measuredPayload.PSObject.Properties['BitLocker']) { $bitlockerSection = $measuredPayload.BitLocker }

            $pcrHandled = $false
            if ($bitlockerSection -and $bitlockerSection.PSObject.Properties['Volumes']) {
                $pcrHandled = $true
                $volumeData = $bitlockerSection.Volumes
                if ($volumeData -and $volumeData.PSObject -and $volumeData.PSObject.Properties['Error'] -and $volumeData.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker PCR binding query failed, so boot integrity attestation cannot be confirmed.' -Evidence $volumeData.Error -Subcategory 'Measured Boot'
                } else {
                    $volumes = ConvertTo-List $volumeData
                    $pcrEvidence = [System.Collections.Generic.List[string]]::new()
                    foreach ($volume in $volumes) {
                        if (-not $volume) { continue }
                        $mount = $null
                        if ($volume.PSObject.Properties['MountPoint'] -and $volume.MountPoint) {
                            $mount = [string]$volume.MountPoint
                        }
                        if (-not $mount) { $mount = 'Unknown volume' }

                        $protectors = @()
                        if ($volume.PSObject.Properties['KeyProtectors']) {
                            $protectors = ConvertTo-List $volume.KeyProtectors
                        } elseif ($volume.PSObject.Properties['KeyProtector']) {
                            $protectors = ConvertTo-List $volume.KeyProtector
                        }

                        foreach ($protector in $protectors) {
                            if (-not $protector) { continue }
                            $bindingValues = @()
                            if ($protector.PSObject.Properties['PcrBinding'] -and $protector.PcrBinding) {
                                $bindingValues = ConvertTo-List $protector.PcrBinding
                            }
                            if (-not $bindingValues -or $bindingValues.Count -eq 0) { continue }

                            $protectorType = $null
                            if ($protector.PSObject.Properties['KeyProtectorType'] -and $protector.KeyProtectorType) {
                                $protectorType = [string]$protector.KeyProtectorType
                            }
                            if (-not $protectorType) { $protectorType = 'Unknown protector' }

                            $hashAlgorithm = $null
                            if ($protector.PSObject.Properties['PcrHashAlgorithm'] -and $protector.PcrHashAlgorithm) {
                                $hashAlgorithm = [string]$protector.PcrHashAlgorithm
                            }

                            $line = [System.Text.StringBuilder]::new()
                            $null = $line.AppendFormat('Mount {0}: {1} bound to PCRs {2}', $mount, $protectorType, ($bindingValues -join ', '))
                            if ($hashAlgorithm) {
                                $null = $line.AppendFormat(' (Hash={0})', $hashAlgorithm)
                            }

                            $pcrEvidence.Add($line.ToString()) | Out-Null
                        }
                    }

                    if ($pcrEvidence.Count -gt 0) {
                        Add-CategoryNormal -CategoryResult $result -Title 'BitLocker PCR bindings captured for TPM-protected volumes.' -Evidence ($pcrEvidence.ToArray() -join "`n") -Subcategory 'Measured Boot'
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker PCR binding data unavailable, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
                    }
                }
            }

            if (-not $pcrHandled) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BitLocker PCR binding data unavailable, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
            }

            $attestationHandled = $false
            if ($measuredPayload.PSObject.Properties['Attestation']) {
                $attestationHandled = $true
                $attestation = $measuredPayload.Attestation
                if ($attestation -and $attestation.PSObject.Properties['Error'] -and $attestation.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Measured boot attestation query failed (MDM required), so remote health attestations cannot be confirmed.' -Evidence $attestation.Error -Subcategory 'Measured Boot'
                } else {
                    $events = @()
                    if ($attestation -and $attestation.PSObject.Properties['Events']) {
                        $events = ConvertTo-List $attestation.Events
                    }

                    $validEvents = @($events | Where-Object { $_ })
                    if ($validEvents.Count -gt 0) {
                        $sampleEvents = $validEvents | Select-Object -First 3
                        $eventLines = [System.Collections.Generic.List[string]]::new()
                        foreach ($evt in $sampleEvents) {
                            $idText = 'ID ?'
                            if ($evt.PSObject.Properties['Id'] -and $evt.Id -ne $null) { $idText = 'ID ' + $evt.Id }
                            $timeText = 'Unknown time'
                            if ($evt.PSObject.Properties['TimeCreated'] -and $evt.TimeCreated) { $timeText = [string]$evt.TimeCreated }
                            $levelText = 'Unknown level'
                            if ($evt.PSObject.Properties['Level'] -and $evt.Level) { $levelText = [string]$evt.Level }
                            $eventLines.Add(('{0} at {1} ({2})' -f $idText, $timeText, $levelText)) | Out-Null
                        }

                        $evidence = [System.Collections.Generic.List[string]]::new()
                        if ($attestation -and $attestation.PSObject.Properties['LogName'] -and $attestation.LogName) {
                            $evidence.Add('Log: ' + [string]$attestation.LogName) | Out-Null
                        }
                        foreach ($line in $eventLines) { $evidence.Add($line) | Out-Null }

                        Add-CategoryNormal -CategoryResult $result -Title 'Measured boot attestation events captured from TPM WMI log.' -Evidence ($evidence.ToArray() -join "`n") -Subcategory 'Measured Boot'
                    } else {
                        $noEventEvidence = 'No attestation events were returned by the collector.'
                        if ($attestation -and $attestation.PSObject.Properties['LogName'] -and $attestation.LogName) {
                            $noEventEvidence = 'Log: ' + [string]$attestation.LogName + ' returned 0 events.'
                        }

                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Measured boot attestation events missing (MDM required), so remote health attestations cannot be confirmed.' -Evidence $noEventEvidence -Subcategory 'Measured Boot'
                    }
                }
            }

            if (-not $attestationHandled) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Measured boot attestation events missing (MDM required), so remote health attestations cannot be confirmed.' -Subcategory 'Measured Boot'
            }

            $secureBootHandled = $false
            if ($measuredPayload.PSObject.Properties['SecureBoot']) {
                $secureBootHandled = $true
                $secureBoot = $measuredPayload.SecureBoot
                if ($secureBoot -and $secureBoot.PSObject.Properties['Error'] -and $secureBoot.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Evidence $secureBoot.Error -Subcategory 'Measured Boot'
                } else {
                    $enabled = $null
                    if ($secureBoot -and $secureBoot.PSObject.Properties['Enabled']) {
                        $enabled = ConvertTo-NullableBool $secureBoot.Enabled
                    }

                    if ($enabled -eq $true) {
                        Add-CategoryNormal -CategoryResult $result -Title 'Secure Boot confirmed by firmware.' -Evidence 'Confirm-SecureBootUEFI returned True.' -Subcategory 'Measured Boot'
                    } elseif ($enabled -eq $false) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Secure Boot reported disabled, so firmware integrity checks are bypassed.' -Evidence 'Confirm-SecureBootUEFI returned False.' -Subcategory 'Measured Boot'
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Subcategory 'Measured Boot'
                    }
                }
            }

            if (-not $secureBootHandled) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Subcategory 'Measured Boot'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Measured boot artifact missing expected structure, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Measured boot artifact not collected (MDM required), so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
    }

    $tpmArtifact = Get-AnalyzerArtifact -Context $Context -Name 'tpm'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved TPM artifact' -Data ([ordered]@{
        Found = [bool]$tpmArtifact
    })
    if ($tpmArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $tpmArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating TPM payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        if ($payload -and $payload.Tpm -and -not $payload.Tpm.Error) {
            $tpm = $payload.Tpm
            $present = ConvertTo-NullableBool $tpm.TpmPresent
            $ready = ConvertTo-NullableBool $tpm.TpmReady
            $specVersionText = $null
            $legacySpecVersion = $false
            if ($tpm.PSObject.Properties['SpecVersion']) {
                $specVersionText = [string]$tpm.SpecVersion
                if (-not [string]::IsNullOrWhiteSpace($specVersionText)) {
                    $specVersionMatches = [regex]::Matches($specVersionText, '(?<num>\d+(?:\.\d+)?)')
                    $maxSpecVersion = $null
                    foreach ($match in $specVersionMatches) {
                        if (-not $match.Success) { continue }
                        $numText = $match.Groups['num'].Value
                        if (-not $numText) { continue }
                        $parsedVersion = 0.0
                        if ([double]::TryParse($numText, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsedVersion)) {
                            if ($null -eq $maxSpecVersion -or $parsedVersion -gt $maxSpecVersion) {
                                $maxSpecVersion = $parsedVersion
                            }
                        }
                    }
                    if ($null -ne $maxSpecVersion -and $maxSpecVersion -lt 2.0) {
                        $legacySpecVersion = $true
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("TPM spec version {0} reported, so modern key protection features that require TPM 2.0 are unavailable." -f $specVersionText) -Evidence ("Get-Tpm reported SpecVersion = {0}." -f $specVersionText) -Subcategory 'TPM'
                    }
                }
            }
            if ($present -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No TPM detected, so hardware-based key protection is unavailable.' -Evidence 'Get-Tpm reported TpmPresent = False.' -Subcategory 'TPM'
            } elseif ($ready -eq $false) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'TPM not initialized, so hardware-based key protection is unavailable.' -Evidence 'Get-Tpm reported TpmReady = False.' -Subcategory 'TPM'
            } elseif (-not $legacySpecVersion) {
                Add-CategoryNormal -CategoryResult $result -Title 'TPM present and ready' -Subcategory 'TPM'
            }
        } elseif ($payload -and $payload.Tpm -and $payload.Tpm.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Unable to query TPM status, so hardware-based key protection availability is unknown.' -Evidence $payload.Tpm.Error -Subcategory 'TPM'
        }
    }

    $kernelDmaArtifact = Get-AnalyzerArtifact -Context $Context -Name 'kerneldma'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved Kernel DMA artifact' -Data ([ordered]@{
        Found = [bool]$kernelDmaArtifact
    })
    if ($kernelDmaArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $kernelDmaArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating Kernel DMA payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        $registryValues = $null
        if ($payload -and $payload.Registry -and $payload.Registry.Values) {
            $registryValues = $payload.Registry.Values
        }
        $allowValue = $null
        if ($registryValues -and $registryValues.PSObject.Properties['AllowDmaUnderLock']) {
            $allowValue = ConvertTo-NullableInt $registryValues.AllowDmaUnderLock
        }
        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($payload.DeviceGuard) {
            $dg = $payload.DeviceGuard
            if ($dg.Status) { $evidenceLines.Add("DeviceGuard.Status: $($dg.Status)") }
            if ($dg.Message) { $evidenceLines.Add("DeviceGuard.Message: $($dg.Message)") }
        }
        if ($payload.Registry -and $payload.Registry.Status) { $evidenceLines.Add("Registry.Status: $($payload.Registry.Status)") }
        if ($payload.Registry -and $payload.Registry.Message) { $evidenceLines.Add("Registry.Message: $($payload.Registry.Message)") }
        if ($payload.MsInfo -and $payload.MsInfo.Status) { $evidenceLines.Add("MsInfo.Status: $($payload.MsInfo.Status)") }
        if ($payload.MsInfo -and $payload.MsInfo.Message) { $evidenceLines.Add("MsInfo.Message: $($payload.MsInfo.Message)") }
        $dmaEvidence = ($evidenceLines.ToArray() | Where-Object { $_ }) -join "`n"

        if ($allowValue -eq 0) {
            Add-CategoryNormal -CategoryResult $result -Title 'Kernel DMA protection enforced' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
        } elseif ($allowValue -eq 1) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Kernel DMA protection allows DMA while locked on this device (AllowDmaUnderLock = 1), enabling DMA attacks via peripherals.' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Kernel DMA protection unknown, leaving potential DMA attacks via peripherals unchecked.' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Kernel DMA protection unknown, leaving potential DMA attacks via peripherals unchecked.' -Subcategory 'Kernel DMA'
    }

    $asrArtifact = Get-AnalyzerArtifact -Context $Context -Name 'asr'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved ASR artifact' -Data ([ordered]@{
        Found = [bool]$asrArtifact
    })
    if ($asrArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $asrArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating ASR payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
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
                $missing = [System.Collections.Generic.List[string]]::new()
                $nonBlocking = [System.Collections.Generic.List[string]]::new()
                foreach ($id in $set.Ids) {
                    $lookup = $id.ToUpperInvariant()
                    if (-not $ruleMap.ContainsKey($lookup)) {
                        $missing.Add($lookup)
                        continue
                    }
                    if ($ruleMap[$lookup] -ne 1) {
                        $nonBlocking.Add("{0} => {1}" -f $lookup, $ruleMap[$lookup])
                    }
                }
                if ($missing.Count -eq 0 -and $nonBlocking.Count -eq 0) {
                    $evidence = ($set.Ids | ForEach-Object { "{0} => 1" -f $_ }) -join "`n"
                    Add-CategoryNormal -CategoryResult $result -Title ("ASR blocking enforced: {0}" -f $set.Label) -Evidence $evidence -Subcategory 'Attack Surface Reduction'
                } else {
                    $detailParts = [System.Collections.Generic.List[string]]::new()
                    if ($missing.Count -gt 0) { $detailParts.Add(("Missing rule(s): {0}" -f ($missing.ToArray() -join ', '))) }
                    if ($nonBlocking.Count -gt 0) { $detailParts.Add(("Non-blocking: {0}" -f ($nonBlocking.ToArray() -join '; '))) }
                    $detailText = if ($detailParts.Count -gt 0) { $detailParts.ToArray() -join '; ' } else { 'Rule not enforced.' }
                    $evidenceLines = [System.Collections.Generic.List[string]]::new()
                    foreach ($id in $set.Ids) {
                        $lookup = $id.ToUpperInvariant()
                        if ($ruleMap.ContainsKey($lookup)) {
                            $evidenceLines.Add("{0} => {1}" -f $lookup, $ruleMap[$lookup])
                        } else {
                            $evidenceLines.Add("{0} => (missing)" -f $lookup)
                        }
                    }
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("ASR rule not enforced: {0}, leaving exploit paths open." -f $set.Label) -Evidence ($evidenceLines -join "`n") -Subcategory 'Attack Surface Reduction'

                }
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'ASR policy data missing, leaving exploit paths open.' -Subcategory 'Attack Surface Reduction'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'ASR policy data missing, leaving exploit paths open.' -Subcategory 'Attack Surface Reduction'
    }

    $exploitArtifact = Get-AnalyzerArtifact -Context $Context -Name 'exploit-protection'
    if ($exploitArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $exploitArtifact)
        if ($payload -and $payload.Mitigations -and -not $payload.Mitigations.Error) {
            $mitigations = $payload.Mitigations
            $cfgEnabled = ConvertTo-NullableBool ($mitigations.CFG.Enable)
            $depEnabled = ConvertTo-NullableBool ($mitigations.DEP.Enable)
            $aslrEnabled = ConvertTo-NullableBool ($mitigations.ASLR.Enable)
            $evidence = [System.Collections.Generic.List[string]]::new()
            if ($mitigations.CFG.Enable -ne $null) { $evidence.Add("CFG.Enable: $($mitigations.CFG.Enable)") }
            if ($mitigations.DEP.Enable -ne $null) { $evidence.Add("DEP.Enable: $($mitigations.DEP.Enable)") }
            if ($mitigations.ASLR.Enable -ne $null) { $evidence.Add("ASLR.Enable: $($mitigations.ASLR.Enable)") }
            $evidenceText = $evidence.ToArray() -join "`n"
            if (($cfgEnabled -eq $true) -and ($depEnabled -eq $true) -and ($aslrEnabled -eq $true)) {
                Add-CategoryNormal -CategoryResult $result -Title 'Exploit protection mitigations enforced (CFG/DEP/ASLR)' -Evidence $evidenceText -Subcategory 'Exploit Protection'
            } else {
                $detailBuilder = [System.Text.StringBuilder]::new()
                if ($cfgEnabled -ne $true) {
                    if ($detailBuilder.Length -gt 0) { $null = $detailBuilder.Append('; ') }
                    $null = $detailBuilder.Append('CFG disabled')
                }
                if ($depEnabled -ne $true) {
                    if ($detailBuilder.Length -gt 0) { $null = $detailBuilder.Append('; ') }
                    $null = $detailBuilder.Append('DEP disabled')
                }
                if ($aslrEnabled -ne $true) {
                    if ($detailBuilder.Length -gt 0) { $null = $detailBuilder.Append('; ') }
                    $null = $detailBuilder.Append('ASLR disabled')
                }
                $detailText = if ($detailBuilder.Length -gt 0) { $detailBuilder.ToString() } else { 'Mitigation status unknown.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Exploit protection mitigations not fully enabled ({0}), reducing exploit resistance.' -f $detailText) -Evidence $evidenceText -Subcategory 'Exploit Protection'
            }
        } elseif ($payload -and $payload.Mitigations -and $payload.Mitigations.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Evidence $payload.Mitigations.Error -Subcategory 'Exploit Protection'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Subcategory 'Exploit Protection'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Subcategory 'Exploit Protection'
    }

    $wdacArtifact = Get-AnalyzerArtifact -Context $Context -Name 'wdac'
    if ($wdacArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wdacArtifact)
        $wdacEvidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($payload -and $payload.DeviceGuard -and -not $payload.DeviceGuard.Error) {
            $dgSection = $payload.DeviceGuard
            $wdacEvidenceLines.Add("SecurityServicesRunning: $($dgSection.SecurityServicesRunning)")
            $wdacEvidenceLines.Add("SecurityServicesConfigured: $($dgSection.SecurityServicesConfigured)")
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
                        $wdacEvidenceLines.Add(("{0}: {1}" -f $prop.Name, $prop.Value))
                        if ($prop.Name -match 'PolicyEnforcement' -and (ConvertTo-NullableInt $prop.Value) -ge 1) {
                            $wdacEnforced = $true
                        }
                    }
                }
            }
        }

        if ($wdacEnforced) {
            Add-CategoryNormal -CategoryResult $result -Title 'WDAC policy enforcement detected' -Evidence ($wdacEvidenceLines.ToArray() -join "`n") -Subcategory 'Windows Defender Application Control'
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'No WDAC policy enforcement detected, so unrestricted code execution remains possible.' -Evidence ($wdacEvidenceLines -join "`n") -Subcategory 'Windows Defender Application Control'
        }

        $smartAppEvidence = [System.Collections.Generic.List[string]]::new()
        $smartAppState = $null
        if ($payload -and $payload.SmartAppControl) {
            $entry = $payload.SmartAppControl
            if ($entry.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to query Smart App Control state, so app trust enforcement is unknown.' -Evidence $entry.Error -Subcategory 'Smart App Control'
            } elseif ($entry.Values) {
                foreach ($prop in $entry.Values.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $smartAppEvidence.Add(("{0}: {1}" -f $prop.Name, $prop.Value))
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

        $evidenceText = if ($smartAppEvidence.Count -gt 0) { $smartAppEvidence.ToArray() -join "`n" } else { '' }
        if ($smartAppState -eq 1) {
            Add-CategoryNormal -CategoryResult $result -Title 'Smart App Control enforced' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($smartAppState -eq 2) {
            $severity = if ($isWindows11) { 'low' } else { 'info' }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Smart App Control in evaluation mode, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($isWindows11) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Smart App Control is not enabled on Windows 11 device, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($smartAppState -ne $null) {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Smart App Control disabled, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory 'Smart App Control'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WDAC/Smart App Control diagnostics not collected, so app trust enforcement is unknown.' -Subcategory 'Smart App Control'
    }

    $lapsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'laps_localadmin'
    if (-not $lapsArtifact) {
        $lapsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'laps'
    }
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved LAPS artifact' -Data ([ordered]@{
        Found = [bool]$lapsArtifact
    })
    if ($lapsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $lapsArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating LAPS payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        $lapsPolicies = $null
        if ($payload -and $payload.LapsPolicies) {
            $lapsPolicies = $payload.LapsPolicies
        } elseif ($payload -and $payload.Policy) {
            $lapsPolicies = $payload.Policy
        }

        $lapsEnabled = $false
        $lapsEvidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($lapsPolicies) {
            foreach ($prop in $lapsPolicies.PSObject.Properties) {
                if ($prop.Name -match '^PS') { continue }
                $value = $prop.Value
                if ($null -eq $value) { continue }
                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                    foreach ($inner in $value) {
                        $lapsEvidenceLines.Add(("{0}: {1}" -f $prop.Name, $inner))
                    }
                } else {
                    $lapsEvidenceLines.Add(("{0}: {1}" -f $prop.Name, $value))
                }
                if ($prop.Name -match 'Enabled' -and (ConvertTo-NullableInt $value) -eq 1) { $lapsEnabled = $true }
                if ($prop.Name -match 'BackupDirectory' -and -not [string]::IsNullOrWhiteSpace($value.ToString())) { $lapsEnabled = $true }
            }
        }

        if ($lapsEnabled) {
            Add-CategoryNormal -CategoryResult $result -Title 'LAPS/PLAP policy detected' -Evidence ($lapsEvidenceLines.ToArray() -join "`n") -Subcategory 'Credential Management'
        } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'LAPS/PLAP not detected, allowing unmanaged or reused local admin passwords.' -Evidence ($lapsEvidenceLines -join "`n") -Subcategory 'Credential Management'
        }
    }

    $runAsPpl = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RunAsPPL')
    $runAsPplBoot = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RunAsPPLBoot')
    $credentialGuardRunning = ($securityServicesRunning -contains 1)
    $lsaEvidenceLines = [System.Collections.Generic.List[string]]::new()
    if ($credentialGuardRunning) { $lsaEvidenceLines.Add('SecurityServicesRunning includes 1 (Credential Guard).') }
    if ($runAsPpl -ne $null) { $lsaEvidenceLines.Add("RunAsPPL: $runAsPpl") }
    if ($runAsPplBoot -ne $null) { $lsaEvidenceLines.Add("RunAsPPLBoot: $runAsPplBoot") }
    $lsaEvidence = $lsaEvidenceLines.ToArray() -join "`n"
    Write-HeuristicDebug -Source 'Security' -Message 'Credential Guard evaluation summary' -Data ([ordered]@{
        CredentialGuardRunning = $credentialGuardRunning
        RunAsPpl             = $runAsPpl
        RunAsPplBoot         = $runAsPplBoot
    })
    if ($credentialGuardRunning -and $runAsPpl -eq 1) {
        Add-CategoryNormal -CategoryResult $result -Title 'Credential Guard with LSA protection enabled' -Evidence $lsaEvidence -Subcategory 'Credential Guard'
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Credential Guard or LSA protection is not enforced, leaving LSASS credentials vulnerable.' -Evidence $lsaEvidence -Subcategory 'Credential Guard'
    }

    $deviceGuardEvidenceLines = [System.Collections.Generic.List[string]]::new()
    if ($securityServicesConfigured.Count -gt 0) { $deviceGuardEvidenceLines.Add("Configured: $($securityServicesConfigured -join ',')") }
    if ($securityServicesRunning.Count -gt 0) { $deviceGuardEvidenceLines.Add("Running: $($securityServicesRunning -join ',')") }
    if ($availableSecurityProperties.Count -gt 0) { $deviceGuardEvidenceLines.Add("Available: $($availableSecurityProperties -join ',')") }
    if ($requiredSecurityProperties.Count -gt 0) { $deviceGuardEvidenceLines.Add("Required: $($requiredSecurityProperties -join ',')") }
    $hvciEvidence = $deviceGuardEvidenceLines.ToArray() -join "`n"
    $hvciRunning = ($securityServicesRunning -contains 2)
    $hvciAvailable = ($availableSecurityProperties -contains 2) -or ($requiredSecurityProperties -contains 2)
    if ($hvciRunning) {
        Add-CategoryNormal -CategoryResult $result -Title 'Memory integrity (HVCI) running' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    } elseif ($hvciAvailable) {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Memory integrity (HVCI) is available but not running, reducing kernel exploit defenses.' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Memory integrity (HVCI) not captured, so kernel exploit defenses are unknown.' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    }

    $uacArtifact = Get-AnalyzerArtifact -Context $Context -Name 'uac'
    if ($uacArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $uacArtifact)
        if ($payload -and $payload.Policy -and -not $payload.Policy.Error) {
            $policy = $payload.Policy
            $enableLua = ConvertTo-NullableInt $policy.EnableLUA
            $consentPrompt = ConvertTo-NullableInt $policy.ConsentPromptBehaviorAdmin
            $secureDesktop = ConvertTo-NullableInt $policy.PromptOnSecureDesktop
            $policyProperties = $policy.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
            $policyEvidence = [System.Collections.Generic.List[string]]::new()
            foreach ($property in $policyProperties) {
                $null = $policyEvidence.Add(("{0} = {1}" -f $property.Name, $property.Value))
            }

            $evidence = ($policyEvidence -join "`n")
            if ($enableLua -eq 1 -and ($secureDesktop -eq $null -or $secureDesktop -eq 1) -and ($consentPrompt -eq $null -or $consentPrompt -ge 2)) {
                Add-CategoryNormal -CategoryResult $result -Title 'UAC configured with secure prompts' -Evidence $evidence -Subcategory 'User Account Control'
            } else {
                $findings = [System.Collections.Generic.List[string]]::new()
                if ($enableLua -ne 1) { $findings.Add('EnableLUA=0') }
                if ($consentPrompt -ne $null -and $consentPrompt -lt 2) { $findings.Add("ConsentPrompt=$consentPrompt") }
                if ($secureDesktop -ne $null -and $secureDesktop -eq 0) { $findings.Add('PromptOnSecureDesktop=0') }
                $detail = if ($findings.Count -gt 0) { $findings.ToArray() -join '; ' } else { 'UAC configuration unclear.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('UAC configuration is insecure ({0}), reducing protection for administrative actions.' -f $detail) -Evidence $evidence -Subcategory 'User Account Control'
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
            $evidenceLines = [System.Collections.Generic.List[string]]::new()
            foreach ($policy in (ConvertTo-List $payload.Policies)) {
                if (-not $policy -or -not $policy.Values) { continue }
                foreach ($prop in $policy.Values.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $evidenceLines.Add(("{0} ({1}): {2}" -f $prop.Name, $policy.Path, $prop.Value))
                    switch -Regex ($prop.Name) {
                        'EnableScriptBlockLogging' { if ((ConvertTo-NullableInt $prop.Value) -eq 1) { $scriptBlockEnabled = $true } }
                        'EnableModuleLogging'     { if ((ConvertTo-NullableInt $prop.Value) -eq 1) { $moduleLoggingEnabled = $true } }
                        'EnableTranscripting'     { if ((ConvertTo-NullableInt $prop.Value) -eq 1) { $transcriptionEnabled = $true } }
                    }
                }
            }
            if ($scriptBlockEnabled -and $moduleLoggingEnabled) {
                Add-CategoryNormal -CategoryResult $result -Title 'PowerShell logging policies enforced' -Evidence ($evidenceLines.ToArray() -join "`n") -Subcategory 'PowerShell Logging'
            } else {
                $detailParts = [System.Collections.Generic.List[string]]::new()
                if (-not $scriptBlockEnabled) { $detailParts.Add('Script block logging disabled') }
                if (-not $moduleLoggingEnabled) { $detailParts.Add('Module logging disabled') }
                if (-not $transcriptionEnabled) { $detailParts.Add('Transcription not enabled') }
                $detail = if ($detailParts.Count -gt 0) { $detailParts.ToArray() -join '; ' } else { 'Logging state unknown.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('PowerShell logging is incomplete ({0}), leaving script activity untraceable. Enable required logging for auditing.' -f $detail) -Evidence ($evidenceLines.ToArray() -join "`n") -Subcategory 'PowerShell Logging'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'PowerShell logging is incomplete (Script block logging disabled; Module logging disabled; Transcription not enabled), leaving script activity untraceable. Enable required logging for auditing.' -Subcategory 'PowerShell Logging'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'PowerShell logging is incomplete (Script block logging disabled; Module logging disabled; Transcription not enabled), leaving script activity untraceable. Enable required logging for auditing.' -Subcategory 'PowerShell Logging'
    }

    $restrictSendingLsa = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RestrictSendingNTLMTraffic')
    $msvEntry = Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa\\\\MSV1_0$' -Name 'RestrictSendingNTLMTraffic'
    $restrictSendingMsv = ConvertTo-NullableInt $msvEntry
    $restrictReceivingMsv = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa\\\\MSV1_0$' -Name 'RestrictReceivingNTLMTraffic')
    $auditReceivingMsv = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa\\\\MSV1_0$' -Name 'AuditReceivingNTLMTraffic')
    $ntlmEvidenceLines = [System.Collections.Generic.List[string]]::new()
    if ($restrictSendingLsa -ne $null) { $ntlmEvidenceLines.Add("Lsa RestrictSendingNTLMTraffic: $restrictSendingLsa") }
    if ($restrictSendingMsv -ne $null) { $ntlmEvidenceLines.Add("MSV1_0 RestrictSendingNTLMTraffic: $restrictSendingMsv") }
    if ($restrictReceivingMsv -ne $null) { $ntlmEvidenceLines.Add("MSV1_0 RestrictReceivingNTLMTraffic: $restrictReceivingMsv") }
    if ($auditReceivingMsv -ne $null) { $ntlmEvidenceLines.Add("MSV1_0 AuditReceivingNTLMTraffic: $auditReceivingMsv") }
    $ntlmEvidence = $ntlmEvidenceLines.ToArray() -join "`n"
    $ntlmRestricted = ($restrictSendingLsa -ge 2) -or ($restrictSendingMsv -ge 2)
    $ntlmAudited = ($auditReceivingMsv -ge 2)
    if ($ntlmRestricted -and $ntlmAudited) {
        Add-CategoryNormal -CategoryResult $result -Title 'NTLM hardening policies enforced' -Evidence $ntlmEvidence -Subcategory 'NTLM Hardening'
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'NTLM hardening policies are not configured, allowing credential relay attacks. Enforce RestrictSending/Audit NTLM settings.' -Evidence $ntlmEvidence -Subcategory 'NTLM Hardening'
    }

    $autorunArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autorun'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved autorun artifact' -Data ([ordered]@{
        Found = [bool]$autorunArtifact
    })
    if ($autorunArtifact) {
        $autorunPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autorunArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating autorun payload' -Data ([ordered]@{
            HasPayload = [bool]$autorunPayload
        })

        if ($autorunPayload -and $autorunPayload.ExplorerPolicies) {
            $autorunEntries = ConvertTo-List $autorunPayload.ExplorerPolicies
            Write-HeuristicDebug -Source 'Security' -Message 'Analyzing autorun policy entries' -Data ([ordered]@{
                EntryCount = if ($autorunEntries) { $autorunEntries.Count } else { 0 }
            })

            $preferredPaths = @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            )

            $noDriveResult = Get-AutorunPolicyValue -Entries $autorunEntries -PreferredPaths $preferredPaths -Name 'NoDriveTypeAutoRun'
            $noAutoResult = Get-AutorunPolicyValue -Entries $autorunEntries -PreferredPaths $preferredPaths -Name 'NoAutoRun'
            $noDriveValue = if ($noDriveResult) { $noDriveResult.Value } else { $null }
            $noAutoValue = if ($noAutoResult) { $noAutoResult.Value } else { $null }
            $noDriveHardened = ($noDriveValue -eq 255)
            $noAutoHardened = ($noAutoValue -eq 1)

            $evidenceLines = [System.Collections.Generic.List[string]]::new()

            if ($noDriveResult) {
                if ($noDriveValue -ne $null) {
                    $evidenceLines.Add(("Effective NoDriveTypeAutoRun: 0x{0:X2} ({0}) from {1}" -f $noDriveValue, $noDriveResult.Path)) | Out-Null
                } elseif ($noDriveResult.RawValue) {
                    $evidenceLines.Add(("Effective NoDriveTypeAutoRun: value '{0}' from {1} could not be parsed" -f $noDriveResult.RawValue, $noDriveResult.Path)) | Out-Null
                } else {
                    $evidenceLines.Add('Effective NoDriveTypeAutoRun: value present but unreadable') | Out-Null
                }
            } else {
                $evidenceLines.Add('Effective NoDriveTypeAutoRun: not set (no applicable registry value found)') | Out-Null
            }

            if ($noAutoResult) {
                if ($noAutoValue -ne $null) {
                    $evidenceLines.Add(("Effective NoAutoRun: {0} from {1}" -f $noAutoValue, $noAutoResult.Path)) | Out-Null
                } elseif ($noAutoResult.RawValue) {
                    $evidenceLines.Add(("Effective NoAutoRun: value '{0}' from {1} could not be parsed" -f $noAutoResult.RawValue, $noAutoResult.Path)) | Out-Null
                } else {
                    $evidenceLines.Add('Effective NoAutoRun: value present but unreadable') | Out-Null
                }
            } else {
                $evidenceLines.Add('Effective NoAutoRun: not set (no applicable registry value found)') | Out-Null
            }

            foreach ($entry in (ConvertTo-List $autorunEntries)) {
                if (-not $entry) { continue }

                $lineParts = [System.Collections.Generic.List[string]]::new()
                if ($entry.Error) {
                    $lineParts.Add(("error: {0}" -f $entry.Error)) | Out-Null
                } elseif ($entry.PSObject.Properties['Exists'] -and -not $entry.Exists) {
                    $lineParts.Add('missing') | Out-Null
                } elseif (-not $entry.Values) {
                    $lineParts.Add('no values captured') | Out-Null
                } else {
                    foreach ($primary in @(
                        @{ Name = 'NoDriveTypeAutoRun'; Hex = $true },
                        @{ Name = 'NoAutoRun'; Hex = $false }
                    )) {
                        $property = $entry.Values.PSObject.Properties[$primary.Name]
                        if ($property) {
                            $converted = ConvertTo-NullablePolicyInt $property.Value
                            if ($primary.Hex -and $converted -ne $null) {
                                $lineParts.Add(("{0}=0x{1:X2} ({1})" -f $primary.Name, $converted)) | Out-Null
                            } elseif ($converted -ne $null) {
                                $lineParts.Add(("{0}={1}" -f $primary.Name, $converted)) | Out-Null
                            } else {
                                $lineParts.Add(("{0}={1}" -f $primary.Name, $property.Value)) | Out-Null
                            }
                        } else {
                            $lineParts.Add(("{0}=(not set)" -f $primary.Name)) | Out-Null
                        }
                    }

                    foreach ($extra in @('DisableAutoplay', 'DisableAutorun', 'Autorunsc', 'HonorAutorunSetting')) {
                        $extraProp = $entry.Values.PSObject.Properties[$extra]
                        if ($extraProp) {
                            $lineParts.Add(("{0}={1}" -f $extra, $extraProp.Value)) | Out-Null
                        }
                    }
                }

                $detail = if ($lineParts.Count -gt 0) { $lineParts -join '; ' } else { 'no relevant values' }
                $evidenceLines.Add(("Path {0}: {1}" -f $entry.Path, $detail)) | Out-Null
            }

            $evidenceText = $evidenceLines.ToArray() -join "`n"
            if ($noDriveHardened -and $noAutoHardened) {
                Add-CategoryNormal -CategoryResult $result -Title 'Autorun/Autoplay policies hardened (NoDriveTypeAutoRun=0xFF; NoAutoRun=1).' -Evidence $evidenceText -Subcategory 'Autorun Policies' -CheckId 'Security/AutorunPolicies'
            } else {
                $statusParts = [System.Collections.Generic.List[string]]::new()
                if (-not $noDriveHardened) {
                    if ($noDriveValue -eq $null) {
                        $statusParts.Add('NoDriveTypeAutoRun missing') | Out-Null
                    } else {
                        $statusParts.Add(("NoDriveTypeAutoRun=0x{0:X2}" -f ($noDriveValue -band 0xFFFFFFFF))) | Out-Null
                    }
                }
                if (-not $noAutoHardened) {
                    if ($noAutoValue -eq $null) {
                        $statusParts.Add('NoAutoRun missing') | Out-Null
                    } else {
                        $statusParts.Add(("NoAutoRun={0}" -f $noAutoValue)) | Out-Null
                    }
                }
                $detailText = if ($statusParts.Count -gt 0) { $statusParts -join '; ' } else { 'values not hardened' }
                $title = "Autorun/Autoplay policies not hardened ({0}), allowing removable media autorun." -f $detailText
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence $evidenceText -Subcategory 'Autorun Policies' -CheckId 'Security/AutorunPolicies'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Autorun policy artifact missing expected structure, so removable media autorun defenses are unknown.' -Subcategory 'Autorun Policies'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Autorun policy artifact not collected, so removable media autorun defenses are unknown.' -Subcategory 'Autorun Policies'
    }

    return $result
}
