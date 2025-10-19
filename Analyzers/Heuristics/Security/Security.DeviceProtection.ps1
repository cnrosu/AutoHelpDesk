function Invoke-SecurityTpmChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

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
                        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ("TPM spec version {0} reported, so modern key protection features that require TPM 2.0 are unavailable." -f $specVersionText) -Evidence ("Get-Tpm reported SpecVersion = {0}." -f $specVersionText) -Subcategory 'TPM'
                    }
                }
            }
            if ($present -eq $false) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'No TPM detected, so hardware-based key protection is unavailable.' -Evidence 'Get-Tpm reported TpmPresent = False.' -Subcategory 'TPM'
            } elseif ($ready -eq $false) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'TPM not initialized, so hardware-based key protection is unavailable.' -Evidence 'Get-Tpm reported TpmReady = False.' -Subcategory 'TPM'
            } elseif (-not $legacySpecVersion) {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'TPM present and ready' -Subcategory 'TPM'
            }
        } elseif ($payload -and $payload.Tpm -and $payload.Tpm.Error) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Unable to query TPM status, so hardware-based key protection availability is unknown.' -Evidence $payload.Tpm.Error -Subcategory 'TPM'
        }
    }
}

function Invoke-SecurityKernelDmaChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

    function ConvertTo-KernelDmaStatus {
        param([string]$Value)

        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

        switch -Regex ($Value.Trim()) {
            '^(?i)on$'          { return 'On' }
            '^(?i)off$'         { return 'Off' }
            '(?i)not\s*support' { return 'NotSupported' }
            default             { return $null }
        }
    }

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    $msinfoSystemSummary = $null
    $msinfoKernelDmaValue = $null
    if ($msinfoPayload) {
        $msinfoSystemSummary = Get-MsinfoSectionTable -Payload $msinfoPayload -Names @('system summary')
        if ($msinfoSystemSummary -and $msinfoSystemSummary.Rows) {
            foreach ($row in $msinfoSystemSummary.Rows) {
                if (-not $row) { continue }

                $itemName = Get-MsinfoRowValue -Row $row -Names @('Item', 'Name')
                if (-not $itemName) { continue }

                if ($itemName.Trim().Equals('Kernel DMA Protection', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $msinfoKernelDmaValue = Get-MsinfoRowValue -Row $row -Names @('Value')
                    break
                }
            }
        }
    }

    Write-HeuristicDebug -Source 'Security' -Message 'Evaluated msinfo32 system summary for Kernel DMA' -Data ([ordered]@{
        PayloadFound = [bool]$msinfoPayload
        SummaryFound = [bool]$msinfoSystemSummary
        KernelDmaValue = if ($msinfoKernelDmaValue) { $msinfoKernelDmaValue } else { $null }
    })
    $msinfoStatus = ConvertTo-KernelDmaStatus -Value $msinfoKernelDmaValue

    if ($msinfoStatus) {
        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        $evidenceLines.Add("KernelDmaProtection.Status: $msinfoStatus") | Out-Null
        $evidenceLines.Add('KernelDmaProtection.Source: msinfo32:SystemSummary') | Out-Null
        if ($msinfoKernelDmaValue) {
            $evidenceLines.Add("Msinfo.SystemSummary.KernelDmaProtection: $msinfoKernelDmaValue") | Out-Null
        }

        $dmaEvidence = ($evidenceLines.ToArray() | Where-Object { $_ }) -join "`n"

        switch ($msinfoStatus) {
            'On' {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Kernel DMA protection enforced' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
                return
            }
            'Off' {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Kernel DMA protection disabled, so DMA attacks via peripherals remain possible while locked.' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
                return
            }
            'NotSupported' {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Kernel DMA protection not supported on this OS, leaving locked devices exposed to DMA attacks from peripherals.' -Evidence $dmaEvidence -Subcategory 'Kernel DMA'
                return
            }
        }
    }

    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Kernel DMA protection unknown, leaving potential DMA attacks via peripherals unchecked.' -Subcategory 'Kernel DMA'
}

function Invoke-SecurityAttackSurfaceChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

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
                @{ Label = 'Block abuse of exploited vulnerable signed drivers'; Ids = @('56A863A9-875E-4185-98A7-B882C64B5CE5') },
                @{ Label = 'Block Adobe Reader from creating child processes'; Ids = @('7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C') },
                @{ Label = 'Block Office applications from creating executable content'; Ids = @('3B576869-A4EC-4529-8536-B80A7769E899') },
                @{ Label = 'Block Win32 API calls from Office'; Ids = @('92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B') },
                @{ Label = 'Block all Office applications from creating child processes.'; Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A') },
                @{ Label = 'Block executable content from email client and webmail'; Ids = @('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550') },
                @{ Label = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'; Ids = @('01443614-CD74-433A-B99E-2ECDC07BFC25') },
                @{ Label = 'Block JavaScript or VBScript from launching downloaded executable content'; Ids = @('D3E037E1-3EB8-44C8-A917-57927947596D') },
                @{ Label = 'Block execution of potentially obfuscated scripts'; Ids = @('5BEB7EFE-FD9A-4556-801D-275E5FFC04CC') },
                @{ Label = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe).'; Ids = @('9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2') },
                @{ Label = 'Block Office applications from injecting code into other processes'; Ids = @('75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84') },
                @{ Label = 'Block Office communication application from creating child processes'; Ids = @('26190899-1602-49E8-8B27-EB1D0A1CE869') }
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
                    Add-CategoryNormal -CategoryResult $CategoryResult -Title ("ASR blocking enforced: {0}" -f $set.Label) -Evidence $evidence -Subcategory 'Attack Surface Reduction'
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
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title ("ASR rule not enforced: {0}, leaving exploit paths open." -f $set.Label) -Evidence ($evidenceLines -join "`n") -Subcategory 'Attack Surface Reduction'
                }
            }
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'ASR policy data missing, leaving exploit paths open.' -Subcategory 'Attack Surface Reduction'
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'ASR policy data missing, leaving exploit paths open.' -Subcategory 'Attack Surface Reduction'
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
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Exploit protection mitigations enforced (CFG/DEP/ASLR)' -Evidence $evidenceText -Subcategory 'Exploit Protection'
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
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title ('Exploit protection mitigations not fully enabled ({0}), reducing exploit resistance.' -f $detailText) -Evidence $evidenceText -Subcategory 'Exploit Protection'
            }
        } elseif ($payload -and $payload.Mitigations -and $payload.Mitigations.Error) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Evidence $payload.Mitigations.Error -Subcategory 'Exploit Protection'
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Subcategory 'Exploit Protection'
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Subcategory 'Exploit Protection'
    }
}

function Invoke-SecurityWdacChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult,
        [Parameter(Mandatory)]
        $EvaluationContext
    )

    $wdacArtifact = Get-AnalyzerArtifact -Context $Context -Name 'wdac'
    if ($wdacArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $wdacArtifact)
        $wdacEvidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($payload -and $payload.DeviceGuard -and -not $payload.DeviceGuard.Error) {
            $dgSection = $payload.DeviceGuard
            $wdacEvidenceLines.Add("SecurityServicesRunning: $($dgSection.SecurityServicesRunning)")
            $wdacEvidenceLines.Add("SecurityServicesConfigured: $($dgSection.SecurityServicesConfigured)")
            if (($EvaluationContext.SecurityServicesRunning.Count -eq 0) -and $dgSection.SecurityServicesRunning) { $EvaluationContext.SecurityServicesRunning = ConvertTo-IntArray $dgSection.SecurityServicesRunning }
            if (($EvaluationContext.SecurityServicesConfigured.Count -eq 0) -and $dgSection.SecurityServicesConfigured) { $EvaluationContext.SecurityServicesConfigured = ConvertTo-IntArray $dgSection.SecurityServicesConfigured }
            if (($EvaluationContext.AvailableSecurityProperties.Count -eq 0) -and $dgSection.AvailableSecurityProperties) { $EvaluationContext.AvailableSecurityProperties = ConvertTo-IntArray $dgSection.AvailableSecurityProperties }
            if (($EvaluationContext.RequiredSecurityProperties.Count -eq 0) -and $dgSection.RequiredSecurityProperties) { $EvaluationContext.RequiredSecurityProperties = ConvertTo-IntArray $dgSection.RequiredSecurityProperties }
        }

        $wdacEnforced = $false
        if ($EvaluationContext.SecurityServicesRunning -contains 4 -or $EvaluationContext.SecurityServicesConfigured -contains 4) { $wdacEnforced = $true }

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
            Add-CategoryNormal -CategoryResult $CategoryResult -Title 'WDAC policy enforcement detected' -Evidence ($wdacEvidenceLines.ToArray() -join "`n") -Subcategory 'Windows Defender Application Control'
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'No WDAC policy enforcement detected, so unrestricted code execution remains possible.' -Evidence ($wdacEvidenceLines -join "`n") -Subcategory 'Windows Defender Application Control'
        }

        $smartAppEvidence = [System.Collections.Generic.List[string]]::new()
        $smartAppState = $null
        if ($payload -and $payload.SmartAppControl) {
            $entry = $payload.SmartAppControl
            if ($entry.Error) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Unable to query Smart App Control state, so app trust enforcement is unknown.' -Evidence $entry.Error -Subcategory 'Smart App Control'
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
            Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Smart App Control enforced' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($smartAppState -eq 2) {
            $severity = if ($EvaluationContext.IsWindows11) { 'low' } else { 'info' }
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title 'Smart App Control in evaluation mode, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($EvaluationContext.IsWindows11) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Smart App Control is not enabled on Windows 11 device, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory 'Smart App Control'
        } elseif ($smartAppState -ne $null) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Smart App Control disabled, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory 'Smart App Control'
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'WDAC/Smart App Control diagnostics not collected, so app trust enforcement is unknown.' -Subcategory 'Smart App Control'
    }
}
