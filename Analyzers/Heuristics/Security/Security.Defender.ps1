function Invoke-SecurityDefenderChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

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
        $rtp = $null
        $modeLabel = 'Unknown'
        $modePassiveOrEdr = $false
        $otherAvKnown = $false
        $otherAvDetected = $false
        $otherAvNames = @()
        $securityCenterError = $null
        $prefDisableRealtime = $null
        $prefDisableIoav = $null

        if ($payload -and $payload.Status -and -not $payload.Status.Error) {
            $status = $payload.Status
            $rtp = ConvertTo-NullableBool $status.RealTimeProtectionEnabled

            $modeRaw = $null
            if ($status.PSObject.Properties['AMRunningMode'] -and $status.AMRunningMode) {
                $modeRaw = [string]$status.AMRunningMode
            }

            $modeNormalized = $null
            if ($modeRaw) {
                try {
                    $modeNormalized = $modeRaw.Trim()
                } catch {
                    $modeNormalized = $modeRaw
                    if ($modeNormalized) { $modeNormalized = $modeNormalized.Trim() }
                }

                if ($modeNormalized -and $modeNormalized.Equals('Passive', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $modeNormalized = 'Passive Mode'
                }
            }

            $modeIsPassive = $false
            $modeIsEdrBlock = $false
            if ($modeNormalized) {
                if ($modeNormalized.Equals('Passive Mode', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $modeIsPassive = $true
                    $modeNormalized = 'Passive Mode'
                } elseif ($modeNormalized.Equals('EDR Block Mode', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $modeIsEdrBlock = $true
                    $modeNormalized = 'EDR Block Mode'
                }
            }

            if ($modeNormalized) { $modeLabel = $modeNormalized }
            $modePassiveOrEdr = $modeIsPassive -or $modeIsEdrBlock

            $avArtifact = Get-AnalyzerArtifact -Context $Context -Name 'av-posture'
            if ($avArtifact) {
                $avPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $avArtifact)
                if ($avPayload -and $avPayload.PSObject.Properties['SecurityCenter']) {
                    $securityCenter = $avPayload.SecurityCenter
                    if ($securityCenter -and -not ($securityCenter.PSObject.Properties['Error'] -and $securityCenter.Error)) {
                        $otherAvKnown = $true
                        foreach ($product in (ConvertTo-List $securityCenter.Products)) {
                            if (-not $product) { continue }

                            $nameValue = $null
                            if ($product.PSObject.Properties['Name'] -and $product.Name) {
                                $nameValue = [string]$product.Name
                            } elseif ($product.PSObject.Properties['displayName'] -and $product.displayName) {
                                $nameValue = [string]$product.displayName
                            } elseif ($product.PSObject.Properties['DisplayName'] -and $product.DisplayName) {
                                $nameValue = [string]$product.DisplayName
                            }

                            if ([string]::IsNullOrWhiteSpace($nameValue)) { continue }
                            $trimmedName = $nameValue.Trim()
                            if (-not $trimmedName) { continue }
                            if ($trimmedName.Equals('Windows Defender', [System.StringComparison]::OrdinalIgnoreCase)) { continue }

                            $otherAvNames += $trimmedName
                        }
                    } elseif ($securityCenter -and $securityCenter.PSObject.Properties['Error'] -and $securityCenter.Error) {
                        $securityCenterError = [string]$securityCenter.Error
                    }
                }
            }

            if ($otherAvNames.Count -gt 0) {
                $otherAvDetected = $true
                $otherAvNames = $otherAvNames | Select-Object -Unique
            }

            $av = ConvertTo-NullableBool $status.AntivirusEnabled
            if ($av -eq $false) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'critical' -Title 'Defender antivirus engine disabled, creating antivirus protection gaps.' -Evidence 'Get-MpComputerStatus reports AntivirusEnabled = False.' -Subcategory 'Microsoft Defender'
            }
            $statusTamper = ConvertTo-NullableBool $status.TamperProtectionEnabled

            $definitions = @($status.AntivirusSignatureVersion, $status.AntispywareSignatureVersion) | Where-Object { $_ }
            if ($definitions.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title ('Defender signatures present ({0})' -f ($definitions -join ', ')) -Subcategory 'Microsoft Defender'
            }

            if ($payload.Threats -and $payload.Threats.Count -gt 0 -and -not ($payload.Threats[0] -is [string])) {
                $threatNames = $payload.Threats | Where-Object { $_.ThreatName } | Select-Object -First 5 -ExpandProperty ThreatName
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ('Recent threats detected: {0}' -f ($threatNames -join ', ')) -Evidence 'Get-MpThreat returned recent detections; confirm remediation.' -Subcategory 'Microsoft Defender'
            } else {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'No recent Defender detections' -Subcategory 'Microsoft Defender'
            }
        } elseif ($payload -and $payload.Status -and $payload.Status.Error) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Unable to query Defender status, leaving antivirus protection gaps unverified.' -Evidence $payload.Status.Error -Subcategory 'Microsoft Defender'
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Defender artifact missing expected structure, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender'
        }

        if ($payload -and $payload.PSObject.Properties['Preferences']) {
            $preferencesEntry = Resolve-SinglePayload -Payload $payload.Preferences
            if ($preferencesEntry -and $preferencesEntry.PSObject.Properties['Error'] -and $preferencesEntry.Error) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Unable to query Defender preferences, leaving antivirus protection gaps unverified.' -Evidence $preferencesEntry.Error -Subcategory 'Microsoft Defender'
            } elseif ($preferencesEntry) {
                $prefEvidence = 'DisableTamperProtection={0}; MAPSReporting={1}; SubmitSamplesConsent={2}; CloudBlockLevel={3}' -f `
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'DisableTamperProtection'), `
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'MAPSReporting'), `
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'SubmitSamplesConsent'), `
                    (Get-ObjectPropertyString -Object $preferencesEntry -PropertyName 'CloudBlockLevel')

                if ($preferencesEntry.PSObject.Properties['DisableRealtimeMonitoring']) {
                    $prefDisableRealtime = ConvertTo-NullableBool $preferencesEntry.DisableRealtimeMonitoring
                }

                if ($preferencesEntry.PSObject.Properties['DisableIOAVProtection']) {
                    $prefDisableIoav = ConvertTo-NullableBool $preferencesEntry.DisableIOAVProtection
                }

                $prefTamperDisabled = $null
                if ($preferencesEntry.PSObject.Properties['DisableTamperProtection']) {
                    $prefTamperDisabled = ConvertTo-NullableBool $preferencesEntry.DisableTamperProtection
                }

                $tamperProtectionOff = $false
                if ($prefTamperDisabled -eq $true -or $statusTamper -eq $false) {
                    $tamperProtectionOff = $true
                }

                if ($tamperProtectionOff) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Defender tamper protection disabled, creating antivirus protection gaps.' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderTamper'
                } elseif (($prefTamperDisabled -eq $false) -or ($statusTamper -eq $true)) {
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Defender tamper protection enabled' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderTamper'
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

                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity $cloudSeverity -Title 'Defender cloud-delivered protection disabled, creating antivirus protection gaps.' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderCloudProt'
                } elseif (($mapsEnabled -eq $true) -or ($cloudDisabled -eq $false)) {
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Defender cloud-delivered protection enabled' -Evidence $prefEvidence -Subcategory 'Microsoft Defender' -CheckId 'Security/DefenderCloudProt'
                }
            }
        }

        if ($rtp -eq $false) {
            $disableRealtimeLabel = if ($prefDisableRealtime -eq $true) { 'True' } elseif ($prefDisableRealtime -eq $false) { 'False' } else { 'Unknown' }
            $disableIoavLabel = if ($prefDisableIoav -eq $true) { 'True' } elseif ($prefDisableIoav -eq $false) { 'False' } else { 'Unknown' }

            $evidenceLines = [System.Collections.Generic.List[string]]::new()
            $evidenceLines.Add(("AMRunningMode={0}" -f $modeLabel)) | Out-Null
            $evidenceLines.Add('RealTimeProtectionEnabled=False') | Out-Null

            if ($otherAvKnown) {
                if ($otherAvDetected) {
                    $evidenceLines.Add(("Other AV detected: {0}" -f ($otherAvNames -join '; '))) | Out-Null
                } else {
                    $evidenceLines.Add('Other AV detected: (none)') | Out-Null
                }
            } elseif ($securityCenterError) {
                $evidenceLines.Add(("Other AV detected: Unknown ({0})" -f $securityCenterError)) | Out-Null
            } else {
                $evidenceLines.Add('Other AV detected: Unknown') | Out-Null
            }

            if ($prefDisableRealtime -ne $null) {
                $evidenceLines.Add(("DisableRealtimeMonitoring={0}" -f $disableRealtimeLabel)) | Out-Null
            }
            if ($prefDisableIoav -ne $null) {
                $evidenceLines.Add(("DisableIOAVProtection={0}" -f $disableIoavLabel)) | Out-Null
            }

            $policyDisabled = ($prefDisableRealtime -eq $true) -or ($prefDisableIoav -eq $true)
            $thirdPartyListText = if ($otherAvDetected) { $otherAvNames -join '; ' } else { 'third-party antivirus' }

            if ($policyDisabled) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Defender real-time protection disabled by policy.' -Evidence $evidenceLines.ToArray() -Explanation 'Policy settings disabled Defender real-time scanning, so technicians must re-enable those controls or confirm another antivirus is covering the device.' -Subcategory 'Microsoft Defender'
            } elseif ($modePassiveOrEdr -and $otherAvDetected) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Defender passive; third-party antivirus active.' -Evidence $evidenceLines.ToArray() -Explanation ('Another antivirus agent ({0}) is handling real-time protection while Defender stays passive.' -f $thirdPartyListText) -Subcategory 'Microsoft Defender'
            } elseif (-not $modePassiveOrEdr -and $otherAvKnown -and -not $otherAvDetected) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Defender real-time protection disabled, creating antivirus protection gaps.' -Evidence $evidenceLines.ToArray() -Explanation 'No antivirus engine is actively scanning because Defender real-time protection is off and no alternate AV is registered.' -Subcategory 'Microsoft Defender'
            } elseif (-not $otherAvKnown) {
                $title = 'Defender real-time protection disabled; third-party coverage unknown.'
                $explanation = 'Defender real-time scanning is off and no alternate antivirus could be confirmed, so technicians should verify another agent is protecting the device or restore Defender.'

                if ($securityCenterError) {
                    $title = 'Defender real-time protection disabled; antivirus inventory unavailable.'
                    $explanation = 'Defender real-time scanning is off and Windows Security Center inventory was unavailable, so technicians should verify another antivirus is protecting the device.'
                }

                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title $title -Evidence $evidenceLines.ToArray() -Explanation $explanation -Subcategory 'Microsoft Defender'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Defender artifact not collected, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender'
    }
}
