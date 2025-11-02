# Structured remediation mapping:
# - Fix options become a list step with explicit choices.
# - Validation prompt becomes a text step leading into the code sample.
$script:WdacPolicyEnforcementRemediation = @'
[
  {
    "type": "list",
    "title": "Fix (pick one)",
    "items": [
      "Windows 11 SAC: Enable in Windows Security > App & browser control (Eval → On), or enforce WDAC via Intune for managed devices.",
      "Pilot WDAC with an allow-list policy in audit mode, then enforce after the burn-in period."
    ]
  },
  {
    "type": "text",
    "content": "Validate enforcement state with Device Guard signals."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -Class Win32_DeviceGuard"
  }
]
'@

$script:SacOffNoWdacRemediation = @'
[
  { "type": "text", "title": "What’s happening", "content": "Smart App Control (SAC) is Off on Windows 11, and no enterprise App Control policy is present. Unknown/unsigned apps won’t be proactively blocked." },
  { "type": "text", "title": "Turn on SAC", "content": "Open Windows Security → App & browser control → Smart App Control → On. If SAC was previously turned Off or the device was upgraded, a Reset/clean install may be required by design." },
  { "type": "code", "lang": "powershell", "content": "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy -Name VerifiedAndReputablePolicyState | Select-Object VerifiedAndReputablePolicyState" },
  { "type": "note", "content": "In managed environments, prefer App Control for Business (WDAC). If you adopt WDAC, SAC can remain Off." }
]
'@

$script:WdacAuditModeRemediation = @'
[
  { "type": "text", "title": "What’s happening", "content": "An App Control for Business (WDAC) policy is present in Audit mode (kernel). UMCI is Off. SAC is suppressed because WDAC governs app trust posture." },
  { "type": "text", "title": "Promote to enforce (admins)", "content": "Update the WDAC policy to Enforced (and enable UMCI if required). Redeploy the policy, then reboot the device to load it." },
  { "type": "code", "lang": "powershell", "content": "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -Class Win32_DeviceGuard | Select CodeIntegrityPolicyEnforcementStatus, UserModeCodeIntegrityPolicyEnforcementStatus" },
  { "type": "note", "content": "Values: 0=Off, 1=Enforce, 2=Audit. When Enforced, the SAC card will remain suppressed." }
]
'@

$script:SacEvaluationRemediation = @'
[
  { "type": "note", "content": "Smart App Control is evaluating recent installs. Windows may enable enforcement automatically if no compatibility issues are detected." }
]
'@

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
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title 'No TPM detected, so hardware-based key protection is unavailable.' -Evidence 'Get-Tpm reported TpmPresent = False.' -Subcategory 'TPM' -Remediation 'Enable TPM 2.0 in BIOS/UEFI; initialize in Windows Security > Device security > Security processor. (Not scriptable if firmware disabled.)'
            } elseif ($ready -eq $false) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'TPM not initialized, so hardware-based key protection is unavailable.' -Evidence 'Get-Tpm reported TpmReady = False.' -Subcategory 'TPM' -Remediation 'Enable TPM 2.0 in BIOS/UEFI; initialize in Windows Security > Device security > Security processor. (Not scriptable if firmware disabled.)'
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
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Kernel DMA protection disabled, so DMA attacks via peripherals remain possible while locked.' -Evidence $dmaEvidence -Subcategory 'Kernel DMA' -Remediation 'On modern hardware, enable in BIOS (IOMMU/VT-d). For older devices, mitigate with BitLocker and lock-screen DMA protections.'
                return
            }
            'NotSupported' {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Kernel DMA protection not supported on this OS, leaving locked devices exposed to DMA attacks from peripherals.' -Evidence $dmaEvidence -Subcategory 'Kernel DMA' -Remediation 'On modern hardware, enable in BIOS (IOMMU/VT-d). For older devices, mitigate with BitLocker and lock-screen DMA protections.'
                return
            }
        }
    }

    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Kernel DMA protection unknown, leaving potential DMA attacks via peripherals unchecked.' -Subcategory 'Kernel DMA' -Remediation 'On modern hardware, enable in BIOS (IOMMU/VT-d). For older devices, mitigate with BitLocker and lock-screen DMA protections.'
}

function Invoke-SecurityAttackSurfaceChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

    $asrMissingTitle = 'ASR policy data missing, so Attack Surface Reduction enforcement is unknown.'
    $asrMissingExplanation = 'Without ASR telemetry, technicians cannot confirm whether Attack Surface Reduction rules are blocking malicious Office behaviors.'
    # Structured remediation mapping for missing ASR data:
    # - Heading becomes a text step that highlights the gap.
    # - Fix directive remains a text step with console navigation guidance.
    # - Validation block stays a code step with the MpPreference command.
    $asrMissingRemediation = @'
[
  {
    "type": "text",
    "title": "Attack Surface Reduction (ASR) data missing / policy gap",
    "content": "Collectors lacked ASR policy output, so confirm baseline deployment."
  },
  {
    "type": "text",
    "title": "Fix",
    "content": "Intune > Endpoint security > Attack surface reduction: deploy your ASR baseline (Block Office child processes; Block Win32 API calls; etc.)."
  },
  {
    "type": "text",
    "title": "Validate",
    "content": "Confirm ASR rules and actions from Defender preferences."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions"
  }
]
'@

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
                @{ Label = 'Block abuse of exploited vulnerable signed drivers'; Ids = @('56A863A9-875E-4185-98A7-B882C64B5CE5'); Impact = 'attackers can load malicious kernel drivers even with stolen certificates' },
                @{ Label = 'Block Adobe Reader from creating child processes'; Ids = @('7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'); Impact = 'malicious PDFs can spawn helper processes to install payloads' },
                @{ Label = 'Block Office applications from creating executable content'; Ids = @('3B576869-A4EC-4529-8536-B80A7769E899'); Impact = 'Office macros can drop executable payloads to disk' },
                @{ Label = 'Block Win32 API calls from Office'; Ids = @('92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'); Impact = 'Office macros keep direct access to Windows APIs used for payload delivery' },
                @{ Label = 'Block all Office applications from creating child processes.'; Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A'); Impact = 'Office documents can launch external programs like cmd.exe or PowerShell' },
                @{ Label = 'Block executable content from email client and webmail'; Ids = @('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'); Impact = 'phishing attachments can run as soon as users open them' },
                @{ Label = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'; Ids = @('01443614-CD74-433A-B99E-2ECDC07BFC25'); Impact = 'new or rare executables can run without reputation checks' },
                @{ Label = 'Block JavaScript or VBScript from launching downloaded executable content'; Ids = @('D3E037E1-3EB8-44C8-A917-57927947596D'); Impact = 'downloaded scripts can hand off to executable payloads' },
                @{ Label = 'Block execution of potentially obfuscated scripts'; Ids = @('5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'); Impact = 'encoded or obfuscated scripts can run to evade inspection' },
                @{ Label = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe).'; Ids = @('9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'); Impact = 'credential dumping tools can read LSASS memory to steal passwords' },
                @{ Label = 'Block Office applications from injecting code into other processes'; Ids = @('75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'); Impact = 'Office can inject shellcode into trusted processes to hide malware' },
                @{ Label = 'Block Office communication application from creating child processes'; Ids = @('26190899-1602-49E8-8B27-EB1D0A1CE869'); Impact = 'Teams or Skype style clients can spawn payload processes from chat content' }
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
                    $evidenceLines = [System.Collections.Generic.List[string]]::new()
                    foreach ($id in $set.Ids) {
                        $lookup = $id.ToUpperInvariant()
                        if ($ruleMap.ContainsKey($lookup)) {
                            $evidenceLines.Add("{0} => {1}" -f $lookup, $ruleMap[$lookup])
                        } else {
                            $evidenceLines.Add("{0} => (missing)" -f $lookup)
                        }
                    }
                    $impactClause = $null
                    if ($set.ContainsKey('Impact') -and $set.Impact) {
                        $impactClause = [string]$set.Impact
                        $impactClause = $impactClause.Trim()
                        if ($impactClause.Length -gt 0) {
                            $firstChar = $impactClause.Substring(0,1).ToUpperInvariant()
                            $rest = if ($impactClause.Length -gt 1) { $impactClause.Substring(1) } else { '' }
                            $impactClause = "$firstChar$rest"
                            if (-not $impactClause.EndsWith('.')) { $impactClause = "$impactClause." }
                        } else {
                            $impactClause = $null
                        }
                    }

                    $titleLabel = [string]$set.Label
                    $titleLabel = $titleLabel.Trim()
                    if (-not $titleLabel.EndsWith('.')) { $titleLabel = "$titleLabel." }

                    $explanation = if ($impactClause) { "ASR rule not enforced, so $impactClause" } else { 'ASR rule not enforced.' }

                    $commandLines = [System.Collections.Generic.List[string]]::new()
                    foreach ($id in $set.Ids) {
                        $commandLines.Add("Add-MpPreference -AttackSurfaceReductionRules_Ids '{0}' -AttackSurfaceReductionRules_Actions Enabled" -f $id.ToUpperInvariant())
                    }
                    $remediationIntro = if ($impactClause) { $impactClause } else { 'Enable this rule in block mode to close the gap.' }
                    $remediationScript = $null
                    if ($commandLines.Count -gt 0) {
                        $remediationScript = $commandLines.ToArray() -join "`n"
                    }

                    $issueArguments = @{
                        CategoryResult = $CategoryResult
                        Severity        = 'high'
                        Title           = $titleLabel
                        Evidence        = ($evidenceLines -join "`n")
                        Subcategory     = 'Attack Surface Reduction'
                        Explanation     = $explanation
                        Remediation     = $remediationIntro
                    }
                    if ($remediationScript) { $issueArguments.RemediationScript = $remediationScript }

                    Add-CategoryIssue @issueArguments
                }
            }

            $impactRules = @(
                @{ Label = 'Block all Office applications from creating child processes'; Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A'); ImpactClause = 'legacy Office add-ins or macros that spawn cmd, PowerShell, or other tools may break.' },
                @{ Label = 'Block Office communication application from creating child processes'; Ids = @('26190899-1602-49E8-8B27-EB1D0A1CE869'); ImpactClause = 'Outlook, Teams, or Skype add-ins that launch helper processes may stop working.' },
                @{ Label = 'Block Office applications from injecting code into other processes'; Ids = @('75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'); ImpactClause = 'uncommon Office add-ins that rely on code injection may break.' },
                @{ Label = 'Block Office applications from creating executable content'; Ids = @('3B576869-A4EC-4529-8536-B80A7769E899'); ImpactClause = 'document-driven installers or templates that drop EXE or DLL files are blocked.' },
                @{ Label = 'Block Win32 API calls from Office macros'; Ids = @('92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'); ImpactClause = 'VBA macros that call low-level Win32 APIs or shellcode loaders stop running.' },
                @{ Label = 'Block execution of potentially obfuscated scripts'; Ids = @('5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'); ImpactClause = 'red-team tools or heavily packed admin scripts may be flagged.' },
                @{ Label = 'Block JavaScript or VBScript from launching downloaded executable content'; Ids = @('D3E037E1-3EB8-44C8-A917-57927947596D'); ImpactClause = 'legacy web installers that script a download-then-run chain are disrupted.' },
                @{ Label = 'Block executable files unless they meet prevalence, age, or trusted list criteria'; Ids = @('01443614-CD74-433A-B99E-2ECDC07BFC25'); ImpactClause = 'brand-new or rare in-house tools can be blocked until trusted or excluded.' },
                @{ Label = 'Block untrusted and unsigned processes that run from USB'; Ids = @('B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'); ImpactClause = 'unsigned tools from thumb drives cannot run, impacting field and bench workflows.' },
                @{ Label = 'Block process creations originating from PSExec and WMI commands'; Ids = @('D1E49AAC-8F56-4280-B9BA-993A6D77406C'); ImpactClause = 'remote admin tooling, scripted troubleshooting, and some software push methods can be blocked.' },
                @{ Label = 'Block persistence through WMI event subscription'; Ids = @('E6DB77E5-3DF2-4CF1-B95A-636979351E5B'); ImpactClause = 'niche IT or EDR workflows that use WMI events for automation may fail.' },
                @{ Label = 'Block use of copied or impersonated system tools'; Ids = @('C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB'); ImpactClause = 'portable admin kits bundling look-alike system binaries can be flagged.' },
                @{ Label = 'Block Adobe Reader from creating child processes'; Ids = @('7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'); ImpactClause = 'PDF add-ins or integrations that legitimately spawn helper processes could stop working.' },
                @{ Label = 'Block rebooting machine in Safe Mode'; Ids = @('33DDEDF1-C6E0-47CB-833E-DE6133960387'); ImpactClause = 'repair workflows that require Safe Mode are blocked.' }
            )

            foreach ($impactRule in $impactRules) {
                $impactEvidence = [System.Collections.Generic.List[string]]::new()
                $actionNames = [System.Collections.Generic.List[string]]::new()
                foreach ($id in $impactRule.Ids) {
                    $lookup = $id.ToUpperInvariant()
                    if (-not $ruleMap.ContainsKey($lookup)) { continue }

                    $action = $ruleMap[$lookup]
                    if ($action -eq 1) {
                        $actionNames.Add('Block') | Out-Null
                    } elseif ($action -eq 6) {
                        $actionNames.Add('Warn') | Out-Null
                    } else {
                        continue
                    }

                    $impactEvidence.Add("{0} => {1}" -f $lookup, $action) | Out-Null
                }

                if ($impactEvidence.Count -eq 0) { continue }

                $uniqueActionNames = $actionNames.ToArray() | Select-Object -Unique
                if (-not $uniqueActionNames) { continue }

                $actionText = ($uniqueActionNames -join '/')
                $title = "ASR rule '{0}' is set to {1}, so {2}" -f $impactRule.Label, $actionText, $impactRule.ImpactClause
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title $title -Evidence ($impactEvidence -join "`n") -Subcategory 'Attack Surface Reduction'
            }
        } else {
            $missingEvidence = 'ASR policy payload missing from collector output.'
            if ($payload -and $payload.Policy -and $payload.Policy.Error) {
                $missingEvidence = $payload.Policy.Error
            } elseif ($payload -and $payload.Policy) {
                $missingEvidence = 'ASR policy payload missing rule data.'
            }

            $missingIssue = @{
                CategoryResult = $CategoryResult
                Severity        = 'high'
                Title           = $asrMissingTitle
                Subcategory     = 'Attack Surface Reduction'
                Explanation     = $asrMissingExplanation
                Remediation     = $asrMissingRemediation
            }
            if ($missingEvidence) { $missingIssue.Evidence = $missingEvidence }

            Add-CategoryIssue @missingIssue
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title $asrMissingTitle -Subcategory 'Attack Surface Reduction' -Explanation $asrMissingExplanation -Remediation $asrMissingRemediation -Evidence 'ASR collector artifact missing from diagnostics.'
    }

    $exploitProtectionSteps = @(
        @{
            type    = 'text'
            title   = 'Stage the hardened policy'
            content = "Export the organization's approved Exploit Protection XML from a hardened reference endpoint and place it on the affected machine (for example, C:\Policies\ExploitProtection.xml)."
        }
        @{
            type    = 'code'
            title   = 'Apply enterprise policy'
            lang    = 'powershell'
            content = 'Set-ProcessMitigation -PolicyFilePath C:\Policies\ExploitProtection.xml'
        }
        @{
            type    = 'code'
            title   = 'Confirm system mitigations'
            lang    = 'powershell'
            content = 'Get-ProcessMitigation -System'
        }
    )
    $exploitProtectionRemediation = $exploitProtectionSteps | ConvertTo-Json -Depth 5

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
                if ($detailBuilder.Length -gt 0) {
                    $evidence.Add("Mitigation gaps: $detailText")
                } else {
                    $evidence.Add($detailText)
                }
                $evidenceText = $evidence.ToArray() -join "`n"
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Exploit protection mitigations not fully enabled, reducing exploit resistance.' -Evidence $evidenceText -Subcategory 'Exploit Protection' -Remediation $exploitProtectionRemediation
            }
        } elseif ($payload -and $payload.Mitigations -and $payload.Mitigations.Error) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Evidence $payload.Mitigations.Error -Subcategory 'Exploit Protection' -Remediation $exploitProtectionRemediation
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Subcategory 'Exploit Protection' -Remediation $exploitProtectionRemediation
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Exploit Protection not captured, so exploit resistance is unknown.' -Subcategory 'Exploit Protection' -Remediation $exploitProtectionRemediation
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
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'No WDAC policy enforcement detected, so unrestricted code execution remains possible.' -Evidence ($wdacEvidenceLines -join "`n") -Subcategory 'Windows Defender Application Control' -Remediation $script:WdacPolicyEnforcementRemediation
        }

        $sacSubcategory = 'Smart App Control (SAC) / WDAC'
        $appTrustPosture = $null
        if ($payload -and $payload.AppTrustPosture) {
            $appTrustPosture = $payload.AppTrustPosture
        }

        if ($appTrustPosture) {
            $postureEvidence = [System.Collections.Generic.List[string]]::new()
            if ($appTrustPosture.PSObject.Properties['OSVersion'] -and $appTrustPosture.OSVersion) { $postureEvidence.Add("OSVersion: $($appTrustPosture.OSVersion)") }
            if ($appTrustPosture.PSObject.Properties['SAC']) {
                $postureEvidence.Add("SAC.State: $($appTrustPosture.SAC)")
            }
            if ($appTrustPosture.PSObject.Properties['IsWin11']) {
                $postureEvidence.Add("IsWin11: $($appTrustPosture.IsWin11)")
            }
            $wdacPosture = $appTrustPosture.WDAC
            if ($wdacPosture) {
                if ($wdacPosture.PSObject.Properties['FilesPresent']) { $postureEvidence.Add("WDAC.FilesPresent: $([bool]$wdacPosture.FilesPresent)") }
                if ($wdacPosture.PSObject.Properties['SipolicyP7b']) { $postureEvidence.Add("WDAC.SIPolicyP7b: $([bool]$wdacPosture.SipolicyP7b)") }
                if ($wdacPosture.PSObject.Properties['CipCount']) { $postureEvidence.Add("WDAC.CipCount: $($wdacPosture.CipCount)") }
                if ($wdacPosture.PSObject.Properties['CiStatus']) { $postureEvidence.Add("WDAC.CIStatus: $($wdacPosture.CiStatus)") }
                if ($wdacPosture.PSObject.Properties['UmciStatus']) { $postureEvidence.Add("WDAC.UMCIStatus: $($wdacPosture.UmciStatus)") }
                if ($wdacPosture.PSObject.Properties['CipSamples']) {
                    $cipSamples = ConvertTo-List $wdacPosture.CipSamples
                    if ($cipSamples -and $cipSamples.Count -gt 0) {
                        $postureEvidence.Add("WDAC.CIPolicyFiles: $($cipSamples -join ', ')")
                    }
                }
            }
            if ($appTrustPosture.PSObject.Properties['Decision'] -and $appTrustPosture.Decision) { $postureEvidence.Add("Decision: $($appTrustPosture.Decision)") }
            if ($appTrustPosture.PSObject.Properties['Reason'] -and $appTrustPosture.Reason) { $postureEvidence.Add("Reason: $($appTrustPosture.Reason)") }

            $evidenceText = if ($postureEvidence.Count -gt 0) { $postureEvidence.ToArray() -join "`n" } else { '' }
            $decision = if ($appTrustPosture.PSObject.Properties['Decision']) { [string]$appTrustPosture.Decision } else { '' }
            $reason = if ($appTrustPosture.PSObject.Properties['Reason']) { [string]$appTrustPosture.Reason } else { '' }
            $remediationPayload = if ($appTrustPosture.PSObject.Properties['Remediation'] -and $appTrustPosture.Remediation) { [string]$appTrustPosture.Remediation } else { $null }

            if ($decision -eq 'NA' -or $decision -eq 'SUPPRESS') {
                # SAC not applicable or superseded by WDAC enforcement; no card needed.
            } elseif ($decision -eq 'OK') {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Smart App Control On, so untrusted apps are blocked.' -Evidence $evidenceText -Subcategory $sacSubcategory
            } elseif ($decision -eq 'MEDIUM') {
                $remediation = if ($remediationPayload) { $remediationPayload } else { $script:SacOffNoWdacRemediation }
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Smart App Control Off with no WDAC enforcement, so app trust is reduced.' -Evidence $evidenceText -Subcategory $sacSubcategory -Remediation $remediation
            } elseif ($decision -eq 'INFO') {
                $title = 'App control posture indeterminate, so review SAC/WDAC configuration.'
                $remediation = $remediationPayload
                if ($reason -eq 'WDAC present in Audit; UMCI Off/Audit.') {
                    $title = 'WDAC policy in Audit mode, so untrusted apps are not blocked yet.'
                    if (-not $remediation) { $remediation = $script:WdacAuditModeRemediation }
                } elseif ($reason -eq 'SAC in Evaluation; Windows may auto-enable.') {
                    $title = 'Smart App Control evaluating installs, so enforcement is pending.'
                    if (-not $remediation) { $remediation = $script:SacEvaluationRemediation }
                } elseif ($reason -eq 'WDAC artifacts found; enforcement status unavailable, so SAC guidance skipped.') {
                    $title = 'WDAC artifacts found but enforcement unknown, so SAC guidance deferred.'
                } elseif ($reason -eq 'WDAC artifacts found; enforcement status indeterminate.') {
                    $title = 'WDAC artifacts found but enforcement is indeterminate, so verify policy status.'
                }
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence $evidenceText -Subcategory $sacSubcategory -Remediation $remediation
            } else {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'App control posture indeterminate, so review SAC/WDAC configuration.' -Evidence $evidenceText -Subcategory $sacSubcategory -Remediation $remediationPayload
            }
        } else {
            $smartAppEvidence = [System.Collections.Generic.List[string]]::new()
            $smartAppState = $null
            if ($payload -and $payload.SmartAppControl) {
                $entry = $payload.SmartAppControl
                if ($entry.Error) {
                    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Unable to query Smart App Control state, so app trust enforcement is unknown.' -Evidence $entry.Error -Subcategory $sacSubcategory -Remediation $script:WdacPolicyEnforcementRemediation
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
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Smart App Control On, so untrusted apps are blocked.' -Evidence $evidenceText -Subcategory $sacSubcategory
            } elseif ($smartAppState -eq 2) {
                $remediation = $script:SacEvaluationRemediation
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Smart App Control evaluating installs, so enforcement is pending.' -Evidence $evidenceText -Subcategory $sacSubcategory -Remediation $remediation
            } elseif ($EvaluationContext.IsWindows11) {
                $remediation = $script:SacOffNoWdacRemediation
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Smart App Control Off with no WDAC enforcement, so app trust is reduced.' -Evidence $evidenceText -Subcategory $sacSubcategory -Remediation $remediation
            } elseif ($smartAppState -ne $null) {
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Smart App Control disabled, so app trust enforcement is reduced.' -Evidence $evidenceText -Subcategory $sacSubcategory -Remediation $script:WdacPolicyEnforcementRemediation
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'WDAC/Smart App Control diagnostics not collected, so app trust enforcement is unknown.' -Subcategory 'Smart App Control (SAC) / WDAC' -Remediation $script:WdacPolicyEnforcementRemediation
    }
}
