function Invoke-SecurityCredentialManagementChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult,
        [Parameter(Mandatory)]
        $EvaluationContext
    )

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

        $lapsEvidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($lapsPolicies) {
            $lapsDetection = $null
            if ($lapsPolicies.PSObject.Properties['WindowsLapsDetection']) {
                $lapsDetection = $lapsPolicies.WindowsLapsDetection
            }

            if ($lapsDetection) {
                $backupTarget = if ($lapsDetection.BackupTarget) { $lapsDetection.BackupTarget } else { 'Unknown' }
                $null = $lapsEvidenceLines.Add("Backup target (detector): $backupTarget")
                if ($lapsDetection.LastRotationUtc) {
                    $null = $lapsEvidenceLines.Add("Last rotation (UTC): $($lapsDetection.LastRotationUtc)")
                    if (-not $lapsDetection.RecentRotation) {
                        $null = $lapsEvidenceLines.Add('Rotation timestamp indicates password may be stale (>35 days).')
                    }
                } else {
                    $null = $lapsEvidenceLines.Add('Last rotation timestamp unavailable or zero.')
                }
                if ($lapsDetection.ManagedRid) {
                    $null = $lapsEvidenceLines.Add("Managed account RID: $($lapsDetection.ManagedRid)")
                }

                if ($lapsDetection.Signals) {
                    foreach ($signal in $lapsDetection.Signals) {
                        if ([string]::IsNullOrWhiteSpace($signal)) { continue }
                        $null = $lapsEvidenceLines.Add($signal)
                    }
                }

                $logEntries = @()
                if ($lapsPolicies.PSObject.Properties['WindowsLapsOperationalLog']) {
                    $logEntries = $lapsPolicies.WindowsLapsOperationalLog | Where-Object { -not $_.Error } | Select-Object -First 5
                }
                foreach ($entry in $logEntries) {
                    $message = if ($entry.Message) { $entry.Message } else { 'No message' }
                    $null = $lapsEvidenceLines.Add(("Log event {0} @ {1}: {2}" -f $entry.Id, $entry.TimeCreatedUtc, $message))
                }

                $legacyEnabled = $false
                if ($lapsPolicies.PSObject.Properties['LegacyAdmPwdPolicy'] -and $lapsPolicies.LegacyAdmPwdPolicy) {
                    foreach ($prop in ($lapsPolicies.LegacyAdmPwdPolicy.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $value = $prop.Value
                        if ($null -eq $value) { continue }
                        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                            foreach ($inner in $value) {
                                $null = $lapsEvidenceLines.Add(("Legacy.{0}: {1}" -f $prop.Name, $inner))
                            }
                        } else {
                            $null = $lapsEvidenceLines.Add(("Legacy.{0}: {1}" -f $prop.Name, $value))
                        }
                        if ($prop.Name -match 'Enabled' -and (ConvertTo-NullableInt $value) -eq 1) { $legacyEnabled = $true }
                    }
                }

                if ($lapsPolicies.PSObject.Properties['WindowsLapsPolicy'] -and $lapsPolicies.WindowsLapsPolicy) {
                    foreach ($prop in ($lapsPolicies.WindowsLapsPolicy.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $value = $prop.Value
                        if ($null -eq $value) { continue }
                        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                            foreach ($inner in $value) {
                                $null = $lapsEvidenceLines.Add(("Policy.{0}: {1}" -f $prop.Name, $inner))
                            }
                        } else {
                            $null = $lapsEvidenceLines.Add(("Policy.{0}: {1}" -f $prop.Name, $value))
                        }
                    }
                }

                if ($lapsPolicies.PSObject.Properties['WindowsLapsState'] -and $lapsPolicies.WindowsLapsState) {
                    foreach ($prop in ($lapsPolicies.WindowsLapsState.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $value = $prop.Value
                        if ($null -eq $value) { continue }
                        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                            foreach ($inner in $value) {
                                $null = $lapsEvidenceLines.Add(("State.{0}: {1}" -f $prop.Name, $inner))
                            }
                        } else {
                            $null = $lapsEvidenceLines.Add(("State.{0}: {1}" -f $prop.Name, $value))
                        }
                    }
                }

                $statusLabels = [System.Collections.Generic.List[string]]::new()
                $azureActive = [bool]$lapsDetection.AzureActive
                $adActive = [bool]$lapsDetection.ActiveDirectoryActive
                $anyActive = $azureActive -or $adActive

                if ($azureActive) { $statusLabels.Add('Entra (Azure AD)') }
                if ($adActive) { $statusLabels.Add('Active Directory') }
                if ($legacyEnabled) {
                    $statusLabels.Add('Legacy LAPS (AdmPwd)')
                    $anyActive = $true
                }

                if ($anyActive) {
                    $title = if ($statusLabels.Count -gt 0) {
                        'Windows LAPS active (' + ($statusLabels -join ' & ') + ')'
                    } else {
                        'Windows LAPS signals detected'
                    }
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title $title -Evidence ($lapsEvidenceLines.ToArray() -join "`n") -Subcategory 'Credential Management'
                } else {
                    $null = $lapsEvidenceLines.Add('Detector did not find recent Windows LAPS rotations or backup targets.')
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'LAPS/PLAP not detected, allowing unmanaged or reused local admin passwords.' -Evidence ($lapsEvidenceLines.ToArray() -join "`n") -Subcategory 'Credential Management'
                }
            } else {
                $legacyEnabled = $false
                foreach ($prop in ($lapsPolicies.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                    $value = $prop.Value
                    if ($null -eq $value) { continue }
                    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                        foreach ($inner in $value) {
                            $null = $lapsEvidenceLines.Add(("{0}: {1}" -f $prop.Name, $inner))
                        }
                    } else {
                        $null = $lapsEvidenceLines.Add(("{0}: {1}" -f $prop.Name, $value))
                    }
                    if ($prop.Name -match 'Enabled' -and (ConvertTo-NullableInt $value) -eq 1) { $legacyEnabled = $true }
                    if ($prop.Name -match 'BackupDirectory' -and -not [string]::IsNullOrWhiteSpace($value.ToString())) { $legacyEnabled = $true }
                }

                if ($legacyEnabled) {
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title 'LAPS/PLAP policy detected' -Evidence ($lapsEvidenceLines.ToArray() -join "`n") -Subcategory 'Credential Management'
                } else {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'LAPS/PLAP not detected, allowing unmanaged or reused local admin passwords.' -Evidence ($lapsEvidenceLines.ToArray() -join "`n") -Subcategory 'Credential Management'
                }
            }
        }
    }

    $lsaEntries = $EvaluationContext.LsaEntries
    $securityServicesRunning = $EvaluationContext.SecurityServicesRunning
    $securityServicesConfigured = $EvaluationContext.SecurityServicesConfigured
    $availableSecurityProperties = $EvaluationContext.AvailableSecurityProperties
    $requiredSecurityProperties = $EvaluationContext.RequiredSecurityProperties

    $runAsPpl = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RunAsPPL')
    $runAsPplBoot = ConvertTo-NullableInt (Get-RegistryValueFromEntries -Entries $lsaEntries -PathPattern 'Control\\\\Lsa$' -Name 'RunAsPPLBoot')
    $credentialGuardRunning = ($securityServicesRunning -contains 1)
    $lsaEvidenceLines = [System.Collections.Generic.List[string]]::new()
    $missingRunAsPpl = ($runAsPpl -eq $null)
    $missingRunAsPplBoot = ($runAsPplBoot -eq $null)

    if ($credentialGuardRunning) { $lsaEvidenceLines.Add('SecurityServicesRunning includes 1 (Credential Guard).') }
    if (-not $missingRunAsPpl) { $lsaEvidenceLines.Add("RunAsPPL: $runAsPpl") }
    if (-not $missingRunAsPplBoot) { $lsaEvidenceLines.Add("RunAsPPLBoot: $runAsPplBoot") }
    Write-HeuristicDebug -Source 'Security' -Message 'Credential Guard evaluation summary' -Data ([ordered]@{
        CredentialGuardRunning = $credentialGuardRunning
        RunAsPpl             = $runAsPpl
        RunAsPplBoot         = $runAsPplBoot
    })
    if ($credentialGuardRunning -and $runAsPpl -eq 1) {
        $lsaEvidence = $lsaEvidenceLines.ToArray() -join "`n"
        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Credential Guard with LSA protection enabled' -Evidence $lsaEvidence -Subcategory 'Credential Guard'
    } else {
        if ($missingRunAsPpl) { $lsaEvidenceLines.Add('RunAsPPL registry value missing or unreadable.') }
        if ($missingRunAsPplBoot) { $lsaEvidenceLines.Add('RunAsPPLBoot registry value missing or unreadable.') }
        $lsaEvidence = $lsaEvidenceLines.ToArray() -join "`n"
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'Credential Guard or LSA protection is not enforced, leaving LSASS credentials vulnerable.' -Evidence $lsaEvidence -Subcategory 'Credential Guard'
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
        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Memory integrity (HVCI) running' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    } elseif ($hvciAvailable) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Memory integrity (HVCI) is available but not running, reducing kernel exploit defenses.' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Memory integrity (HVCI) not captured, so kernel exploit defenses are unknown.' -Evidence $hvciEvidence -Subcategory 'Memory Integrity'
    }
}

function Invoke-SecurityPolicyChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult,
        [Parameter(Mandatory)]
        $EvaluationContext
    )

    $lsaEntries = $EvaluationContext.LsaEntries

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
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'UAC configured with secure prompts' -Evidence $evidence -Subcategory 'User Account Control'
            } else {
                $findings = [System.Collections.Generic.List[string]]::new()
                if ($enableLua -ne 1) { $findings.Add('EnableLUA=0') }
                if ($consentPrompt -ne $null -and $consentPrompt -lt 2) { $findings.Add("ConsentPrompt=$consentPrompt") }
                if ($secureDesktop -ne $null -and $secureDesktop -eq 0) { $findings.Add('PromptOnSecureDesktop=0') }
                $detail = if ($findings.Count -gt 0) { $findings.ToArray() -join '; ' } else { 'UAC configuration unclear.' }
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ('UAC configuration is insecure ({0}), reducing protection for administrative actions.' -f $detail) -Evidence $evidence -Subcategory 'User Account Control'
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
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'PowerShell logging policies enforced' -Evidence ($evidenceLines.ToArray() -join "`n") -Subcategory 'PowerShell Logging'
            } else {
                $detailParts = [System.Collections.Generic.List[string]]::new()
                if (-not $scriptBlockEnabled) { $detailParts.Add('Script block logging disabled') }
                if (-not $moduleLoggingEnabled) { $detailParts.Add('Module logging disabled') }
                if (-not $transcriptionEnabled) { $detailParts.Add('Transcription not enabled') }
                $detail = if ($detailParts.Count -gt 0) { $detailParts.ToArray() -join '; ' } else { 'Logging state unknown.' }
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title ('PowerShell logging is incomplete ({0}), leaving script activity untraceable. Enable required logging for auditing.' -f $detail) -Evidence ($evidenceLines.ToArray() -join "`n") -Subcategory 'PowerShell Logging'
            }
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'PowerShell logging is incomplete (Script block logging disabled; Module logging disabled; Transcription not enabled), leaving script activity untraceable. Enable required logging for auditing.' -Subcategory 'PowerShell Logging'
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'PowerShell logging is incomplete (Script block logging disabled; Module logging disabled; Transcription not enabled), leaving script activity untraceable. Enable required logging for auditing.' -Subcategory 'PowerShell Logging'
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
        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'NTLM hardening policies enforced' -Evidence $ntlmEvidence -Subcategory 'NTLM Hardening'
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'NTLM hardening policies are not configured, allowing credential relay attacks. Enforce RestrictSending/Audit NTLM settings.' -Evidence $ntlmEvidence -Subcategory 'NTLM Hardening'
    }
}
