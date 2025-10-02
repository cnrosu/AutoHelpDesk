function Invoke-SecurityBitLockerChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

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
                        Volume         = $volume
                        MountPoint     = $mount
                        ProtectorTypes = $distinctProtectorTypes
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
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'critical' -Title ("BitLocker is OFF for system volume(s): {0}, risking data exposure." -f $mountList) -Evidence $evidence -Subcategory 'BitLocker'
            } elseif ($osProtectedEvidence.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'BitLocker protection active for system volume(s).' -Evidence ($osProtectedEvidence.ToArray() -join "`n") -Subcategory 'BitLocker'
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
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ("System volume(s) {0} only use password-based BitLocker protectors, so attackers who obtain those secrets can unlock the device." -f $volumeList) -Evidence ($evidenceLines.ToArray() -join "`n") -Subcategory 'BitLocker'
            }

            if ($osTpmPinVolumes.Count -gt 0) {
                $evidence = ($osTpmPinVolumes | ForEach-Object {
                        $label = if ($_.MountPoint) { $_.MountPoint } else { 'Unknown volume' }
                        $types = if ($_.ProtectorTypes -and $_.ProtectorTypes.Count -gt 0) { $_.ProtectorTypes -join ', ' } else { 'None' }
                        '{0} -> Protectors: {1}' -f $label, $types
                    }) -join "`n"
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'System volume(s) configured with TPM+PIN BitLocker protectors, reducing pre-boot compromise risk.' -Evidence $evidence -Subcategory 'BitLocker'
            }

            if ($osTpmVolumes.Count -gt 0) {
                $evidence = ($osTpmVolumes | ForEach-Object {
                        $label = if ($_.MountPoint) { $_.MountPoint } else { 'Unknown volume' }
                        $types = if ($_.ProtectorTypes -and $_.ProtectorTypes.Count -gt 0) { $_.ProtectorTypes -join ', ' } else { 'None' }
                        '{0} -> Protectors: {1}' -f $label, $types
                    }) -join "`n"
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'System volume(s) protected with TPM-backed BitLocker keys, limiting exposure if the drive is removed.' -Evidence $evidence -Subcategory 'BitLocker'
            }

            if (-not $hasRecoveryProtector) {
                $volumeEvidence = ($volumes | ForEach-Object { Format-BitLockerVolume $_ }) -join "`n"
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'No BitLocker recovery password protector detected, risking data exposure if recovery is needed.' -Evidence $volumeEvidence -Subcategory 'BitLocker'
            }
        } elseif ($payload -and $payload.Volumes -and $payload.Volumes.Error) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'BitLocker query failed, so the encryption state and data exposure risk are unknown.' -Evidence $payload.Volumes.Error -Subcategory 'BitLocker'
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'BitLocker data missing expected structure, so the encryption state and data exposure risk are unknown.' -Subcategory 'BitLocker'
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'BitLocker artifact not collected, so the encryption state and data exposure risk are unknown.' -Subcategory 'BitLocker'
    }
}
