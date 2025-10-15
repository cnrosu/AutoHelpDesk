function Invoke-SecurityMeasuredBootChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

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
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'BitLocker PCR binding query failed, so boot integrity attestation cannot be confirmed.' -Evidence $volumeData.Error -Subcategory 'Measured Boot'
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
                        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'BitLocker PCR bindings captured for TPM-protected volumes.' -Evidence ($pcrEvidence.ToArray() -join "`n") -Subcategory 'Measured Boot'
                    } else {
                        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'BitLocker PCR binding data unavailable, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
                    }
                }
            }

            if (-not $pcrHandled) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'BitLocker PCR binding data unavailable, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
            }

            $attestationHandled = $false
            if ($measuredPayload.PSObject.Properties['Attestation']) {
                $attestationHandled = $true
                $attestation = $measuredPayload.Attestation
                if ($attestation -and $attestation.PSObject.Properties['Error'] -and $attestation.Error) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Measured boot attestation query failed (MDM required), so remote health attestations cannot be confirmed.' -Evidence $attestation.Error -Subcategory 'Measured Boot'
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

                        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Measured boot attestation events captured from TPM WMI log.' -Evidence ($evidence.ToArray() -join "`n") -Subcategory 'Measured Boot'
                    } else {
                        $noEventEvidence = 'No attestation events were returned by the collector.'
                        if ($attestation -and $attestation.PSObject.Properties['LogName'] -and $attestation.LogName) {
                            $noEventEvidence = 'Log: ' + [string]$attestation.LogName + ' returned 0 events.'
                        }

                        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Measured boot attestation events missing (MDM required), so remote health attestations cannot be confirmed.' -Evidence $noEventEvidence -Subcategory 'Measured Boot'
                    }
                }
            }

            if (-not $attestationHandled) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Measured boot attestation events missing (MDM required), so remote health attestations cannot be confirmed.' -Subcategory 'Measured Boot'
            }

            $secureBootHandled = $false
            if ($measuredPayload.PSObject.Properties['SecureBoot']) {
                $secureBootHandled = $true
                $secureBoot = $measuredPayload.SecureBoot
                if ($secureBoot -and $secureBoot.PSObject.Properties['Error'] -and $secureBoot.Error) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Evidence $secureBoot.Error -Subcategory 'Measured Boot'
                } else {
                    $enabled = $null
                    if ($secureBoot -and $secureBoot.PSObject.Properties['Enabled']) {
                        $enabled = ConvertTo-NullableBool $secureBoot.Enabled
                    }

                    if ($enabled -eq $true) {
                        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Secure Boot confirmed by firmware.' -Evidence 'Confirm-SecureBootUEFI returned True.' -Subcategory 'Measured Boot'
                    } elseif ($enabled -eq $false) {
                        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Secure Boot reported disabled, so firmware integrity checks are bypassed.' -Evidence 'Confirm-SecureBootUEFI returned False.' -Subcategory 'Measured Boot'
                    } else {
                        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Subcategory 'Measured Boot'
                    }
                }
            }

            if (-not $secureBootHandled) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Secure Boot confirmation unavailable, so firmware integrity checks cannot be verified.' -Subcategory 'Measured Boot'
            }
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Measured boot artifact missing expected structure, so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Measured boot artifact not collected (MDM required), so boot integrity attestation cannot be confirmed.' -Subcategory 'Measured Boot'
    }
}
