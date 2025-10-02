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
        if ($payload -and $payload.Status -and -not $payload.Status.Error) {
            $status = $payload.Status
            $rtp = ConvertTo-NullableBool $status.RealTimeProtectionEnabled
            if ($rtp -eq $false) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Defender real-time protection disabled, creating antivirus protection gaps.' -Evidence 'Get-MpComputerStatus reports RealTimeProtectionEnabled = False.' -Subcategory 'Microsoft Defender'
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
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Defender artifact missing expected structure, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender'
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
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Defender artifact not collected, leaving antivirus protection gaps unverified.' -Subcategory 'Microsoft Defender'
    }
}
