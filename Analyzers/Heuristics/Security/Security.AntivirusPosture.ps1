function ConvertTo-AvProductRecord {
    param($Product)

    if (-not $Product) { return $null }

    $name = $null
    if ($Product.PSObject.Properties['Name'] -and $Product.Name) {
        $name = [string]$Product.Name
    } elseif ($Product.PSObject.Properties['displayName'] -and $Product.displayName) {
        $name = [string]$Product.displayName
    } elseif ($Product.PSObject.Properties['DisplayName'] -and $Product.DisplayName) {
        $name = [string]$Product.DisplayName
    }

    $state = $null
    if ($Product.PSObject.Properties['ProductState']) {
        $state = ConvertTo-NullableInt $Product.ProductState
    } elseif ($Product.PSObject.Properties['productState']) {
        $state = ConvertTo-NullableInt $Product.productState
    }

    $path = $null
    if ($Product.PSObject.Properties['Path'] -and $Product.Path) {
        $path = [string]$Product.Path
    } elseif ($Product.PSObject.Properties['pathToSignedProductExe'] -and $Product.pathToSignedProductExe) {
        $path = [string]$Product.pathToSignedProductExe
    }

    return [pscustomobject]@{
        Name         = if ($name) { $name } else { $null }
        ProductState = $state
        Path         = if ($path) { $path } else { $null }
    }
}

function Test-AvProductActive {
    param($Product)

    if (-not $Product) { return $false }

    $state = $null
    if ($Product.PSObject.Properties['ProductState']) {
        $state = $Product.ProductState
    }

    if ($null -eq $state) { return $true }
    return ($state -ne 0)
}

function ConvertTo-AvBooleanString {
    param($Value)

    if ($Value -eq $true) { return 'True' }
    if ($Value -eq $false) { return 'False' }
    return 'Unknown'
}

function Normalize-DefenderModeLabel {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }

    if ($trimmed.Equals('Passive Mode', [System.StringComparison]::OrdinalIgnoreCase)) {
        return 'Passive Mode'
    }

    if ($trimmed.Equals('Passive', [System.StringComparison]::OrdinalIgnoreCase)) {
        return 'Passive Mode'
    }

    if ($trimmed.Equals('Active', [System.StringComparison]::OrdinalIgnoreCase)) {
        return 'Active'
    }

    return $trimmed
}

function Invoke-SecurityAntivirusPostureChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'av-posture'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved AV posture artifact' -Data ([ordered]@{
        Found = [bool]$artifact
    })

    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Endpoint AV: posture data not collected' -Explanation 'Without AV posture telemetry, technicians must verify antivirus coverage manually.' -Subcategory 'Antivirus'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    Write-HeuristicDebug -Source 'Security' -Message 'Evaluating AV posture payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Endpoint AV: posture payload missing' -Explanation 'Antivirus posture data was collected but not parsed, so coverage must be confirmed manually.' -Subcategory 'Antivirus'
        return
    }

    $securityCenter = $null
    if ($payload.PSObject.Properties['SecurityCenter']) {
        $securityCenter = $payload.SecurityCenter
    }

    $serviceSignalSteps = @(
        @{
            type    = 'text'
            title   = 'Restore Windows Security Center'
            content = 'Set the Security Center (wscsvc) service to Automatic and restart it so Defender posture data can be collected.'
        }
        @{
            type    = 'code'
            title   = 'Restart Security Center'
            lang    = 'powershell'
            content = @"
Set-Service wscsvc -StartupType Automatic
Restart-Service wscsvc
"@.Trim()
        }
        @{
            type    = 'text'
            content = 'If Security Center still fails, verify and repair WMI carefully before rerunning the collector.'
        }
        @{
            type    = 'code'
            title   = 'Verify WMI repository'
            lang    = 'powershell'
            content = 'winmgmt /verifyrepository'
        }
    )
    $serviceSignalRemediation = $serviceSignalSteps | ConvertTo-Json -Depth 5

    if (-not $securityCenter) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Endpoint AV: Security Center inventory missing' -Explanation 'Windows Security Center inventory was unavailable, so technicians cannot confirm which antivirus engine is active.' -Subcategory 'Antivirus' -Remediation $serviceSignalRemediation
        return
    }

    if ($securityCenter.PSObject.Properties['Error'] -and $securityCenter.Error) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Endpoint AV: Security Center query failed' -Evidence $securityCenter.Error -Explanation 'Windows Security Center inventory failed to load, so technicians cannot confirm which antivirus engine is active.' -Subcategory 'Antivirus' -Remediation $serviceSignalRemediation
        return
    }

    $defenderStatus = $null
    if ($payload.PSObject.Properties['Defender']) {
        $defenderStatus = $payload.Defender
    }

    if (-not $defenderStatus) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Endpoint AV: Defender status unavailable' -Explanation 'Microsoft Defender status data was unavailable, so technicians cannot determine whether Defender is active or passive.' -Subcategory 'Antivirus' -Remediation $serviceSignalRemediation
        return
    }

    if ($defenderStatus.PSObject.Properties['Error'] -and $defenderStatus.Error) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title 'Endpoint AV: Defender status query failed' -Evidence $defenderStatus.Error -Explanation 'Microsoft Defender status could not be read, so technicians cannot determine whether Defender is active or passive.' -Subcategory 'Antivirus' -Remediation $serviceSignalRemediation
        return
    }

    $collectedAtUtc = $null
    if ($payload.PSObject.Properties['CollectedAtUtc']) {
        $collectedAtUtc = $payload.CollectedAtUtc
    }

    $productsRaw = @()
    if ($securityCenter.PSObject.Properties['Products']) {
        $productsRaw = ConvertTo-List $securityCenter.Products
    }

    $products = @()
    foreach ($rawProduct in $productsRaw) {
        $record = ConvertTo-AvProductRecord $rawProduct
        if ($record) { $products += $record }
    }

    $productEvidenceEntries = @()
    foreach ($product in $products) {
        $name = if ($product.Name) { $product.Name } else { '(unnamed)' }
        $stateText = 'null'
        if ($product.PSObject.Properties['ProductState'] -and $null -ne $product.ProductState) {
            $stateText = [string]$product.ProductState
        }
        $productEvidenceEntries += ("{0} ({1})" -f $name, $stateText)
    }

    if (-not $productEvidenceEntries) {
        $productEvidenceEntries = @('(none)')
    }

    $thirdPartyProducts = @()
    foreach ($product in $products) {
        if (-not $product.Name) { continue }
        if ($product.Name.Trim().Equals('Windows Defender', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $thirdPartyProducts += $product
    }

    $thirdPartyActive = @()
    foreach ($product in $thirdPartyProducts) {
        if (Test-AvProductActive $product) { $thirdPartyActive += $product }
    }

    $thirdPartyActiveCount = $thirdPartyActive.Count

    $thirdPartyActiveNames = @()
    foreach ($product in $thirdPartyActive) {
        if ($product.Name) {
            $thirdPartyActiveNames += $product.Name
        } else {
            $thirdPartyActiveNames += '(unnamed product)'
        }
    }
    if ($thirdPartyActiveNames.Count -gt 0) {
        $thirdPartyActiveNames = $thirdPartyActiveNames | Select-Object -Unique
    } elseif ($thirdPartyActiveCount -gt 0) {
        $thirdPartyActiveNames = @('(unnamed product)')
    }

    $mode = $null
    if ($defenderStatus.PSObject.Properties['AMRunningMode']) {
        $mode = Normalize-DefenderModeLabel $defenderStatus.AMRunningMode
    }

    $realTime = $null
    if ($defenderStatus.PSObject.Properties['RealTimeProtectionEnabled']) {
        $realTime = ConvertTo-NullableBool $defenderStatus.RealTimeProtectionEnabled
    }

    $signaturesOutOfDate = $null
    if ($defenderStatus.PSObject.Properties['DefenderSignaturesOutOfDate']) {
        $signaturesOutOfDate = ConvertTo-NullableBool $defenderStatus.DefenderSignaturesOutOfDate
    }

    $lastSignatureUpdate = $null
    if ($defenderStatus.PSObject.Properties['AntivirusSignatureLastUpdatedUtc']) {
        $lastSignatureUpdate = $defenderStatus.AntivirusSignatureLastUpdatedUtc
    }

    $tamperProtected = $null
    if ($defenderStatus.PSObject.Properties['IsTamperProtected']) {
        $tamperProtected = ConvertTo-NullableBool $defenderStatus.IsTamperProtected
    }

    $defenderPassive = $null
    if ($mode) {
        $defenderPassive = $mode.Equals('Passive Mode', [System.StringComparison]::OrdinalIgnoreCase)
    }

    $defenderActiveFromMode = $null
    if ($mode) {
        $defenderActiveFromMode = -not $defenderPassive
    }

    $defenderActive = $null
    if ($null -ne $defenderActiveFromMode) {
        $defenderActive = $defenderActiveFromMode
    } elseif ($null -ne $realTime) {
        $defenderActive = $realTime
    }

    $signatureCurrent = $null
    if ($null -ne $signaturesOutOfDate) {
        $signatureCurrent = -not $signaturesOutOfDate
    }

    $conflict = $false
    $conflictReason = $null
    if ($thirdPartyActiveCount -ge 2) {
        $conflict = $true
        $conflictReason = 'MultipleThirdParty'
    } elseif ($thirdPartyActiveCount -ge 1 -and $defenderActiveFromMode -eq $true) {
        $conflict = $true
        $conflictReason = 'DefenderActiveWithThirdParty'
    }

    $gap = $false
    $gapReason = $null
    if ($thirdPartyActiveCount -eq 0) {
        if ($defenderPassive -eq $true) {
            $gap = $true
            $gapReason = 'DefenderPassive'
        } elseif ($realTime -eq $false) {
            $gap = $true
            $gapReason = 'RealtimeDisabled'
        }
    }

    $inventoryUncertain = $false
    if ($thirdPartyProducts.Count -gt 0 -and $thirdPartyActiveCount -eq 0 -and $defenderPassive -eq $true) {
        $inventoryUncertain = $true
    }

    $defenderActiveWithStaleSignatures = $false
    if (($defenderActiveFromMode -eq $true -or $defenderActive -eq $true) -and $signatureCurrent -eq $false) {
        $defenderActiveWithStaleSignatures = $true
    }

    $defenderPassiveWithStaleSignatures = $false
    if ($thirdPartyActiveCount -ge 1 -and $defenderPassive -eq $true -and $signatureCurrent -eq $false) {
        $defenderPassiveWithStaleSignatures = $true
    }

    $primaryNames = @()
    if ($thirdPartyActiveCount -gt 0) {
        $primaryNames = $thirdPartyActiveNames
    } elseif ($defenderActive -eq $true) {
        $primaryNames = @('Windows Defender')
    }

    if (-not $primaryNames -or $primaryNames.Count -eq 0) {
        if ($thirdPartyProducts.Count -gt 0) {
            $primaryNames = $thirdPartyProducts | ForEach-Object {
                if ($_.Name) { $_.Name } else { '(unnamed product)' }
            }
            if ($primaryNames.Count -gt 0) {
                $primaryNames = $primaryNames | Select-Object -Unique
            }
        }
    }

    $primaryLabel = if ($primaryNames -and $primaryNames.Count -gt 0) { ($primaryNames | Select-Object -Unique) -join ', ' } else { 'None detected' }
    $modeLabel = if ($mode) { $mode } else { 'Unknown' }
    $signatureLabel = if ($signatureCurrent -eq $true) { 'True' } elseif ($signatureCurrent -eq $false) { 'False' } else { 'Unknown' }
    $conflictLabel = if ($conflict) { if ($conflictReason -eq 'MultipleThirdParty') { [string]$thirdPartyActiveCount } else { '1' } } else { '0' }

    $evidenceLines = [System.Collections.Generic.List[string]]::new()
    $evidenceLines.Add(("Primary AV = {0}; Defender mode = {1}; Signatures current = {2}; Conflicts = {3}." -f $primaryLabel, $modeLabel, $signatureLabel, $conflictLabel)) | Out-Null
    $evidenceLines.Add(("SecurityCenter AVs: {0}" -f ($productEvidenceEntries -join '; '))) | Out-Null
    $defenderEvidenceParts = @(
        "AMRunningMode={0}" -f $modeLabel,
        "RealTimeProtectionEnabled={0}" -f (ConvertTo-AvBooleanString $realTime),
        "DefenderSignaturesOutOfDate={0}" -f (ConvertTo-AvBooleanString $signaturesOutOfDate)
    )
    if ($lastSignatureUpdate) {
        $defenderEvidenceParts += ("LastUpdated={0}" -f $lastSignatureUpdate)
    }
    $evidenceLines.Add(("Defender: {0}" -f ($defenderEvidenceParts -join '; '))) | Out-Null
    $evidenceLines.Add(("TamperProtection={0}" -f (ConvertTo-AvBooleanString $tamperProtected))) | Out-Null
    if ($collectedAtUtc) {
        $evidenceLines.Add(("CollectedAtUtc={0}" -f $collectedAtUtc)) | Out-Null
    }

    $explanation = $null
    $title = $null
    $severity = 'info'
    $remediation = $null

    if ($defenderActiveWithStaleSignatures) {
        $severity = 'high'
        $title = 'Endpoint AV: Defender active but signatures out of date'
        $explanation = 'With Microsoft Defender running primary but outdated signatures, malware can slip through until definitions update.'
    } elseif ($gap) {
        $severity = 'high'
        if ($gapReason -eq 'RealtimeDisabled') {
            $title = 'Endpoint AV: Defender real-time protection disabled and no third-party AV'
            $explanation = 'No antivirus engine is actively scanning the device, leaving it exposed until Defender real-time protection is restored or a third-party agent registers.'
            $remediationSteps = @(
                @{
                    type    = 'text'
                    title   = 'Re-enable Defender real-time protection'
                    content = 'Turn Microsoft Defender real-time protection back on so the device regains active scanning.'
                }
                @{
                    type    = 'code'
                    title   = 'Restore core Defender protections'
                    lang    = 'powershell'
                    content = @"
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples
"@.Trim()
                }
                @{
                    type    = 'text'
                    title   = 'Re-enable behavioral defenses'
                    content = 'Turn behavior monitoring, IOAV, and script scanning back on to close inspection gaps.'
                }
                @{
                    type    = 'code'
                    title   = 'Re-enable behavioral protections'
                    lang    = 'powershell'
                    content = 'Set-MpPreference -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false'
                }
                @{
                    type    = 'note'
                    content = 'Tamper Protection must be enabled from Intune or the Windows Security app; PowerShell cannot re-enable it when disabled.'
                }
                @{
                    type    = 'code'
                    title   = 'Validate Defender health'
                    lang    = 'powershell'
                    content = 'Get-MpComputerStatus | Select AMServiceEnabled, RealTimeProtectionEnabled, IsTamperProtected'
                }
            )
            $remediation = $remediationSteps | ConvertTo-Json -Depth 5
        } else {
            $title = 'Endpoint AV: No active AV detected (Defender passive; no third-party)'
            $explanation = 'No antivirus engine is actively scanning the device, leaving it exposed until Defender is activated or a third-party agent registers.'
            $remediationSteps = @(
                @{
                    type    = 'text'
                    title   = 'Choose the primary antivirus'
                    content = 'Decide whether a third-party antivirus will stay primary; if Defender must protect this device, leave passive mode and re-enable protections.'
                }
                @{
                    type    = 'code'
                    title   = 'Activate Defender protections'
                    lang    = 'powershell'
                    content = @"
Set-MpPreference -ForcePassiveMode 0
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples
Set-MpPreference -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false
"@.Trim()
                }
                @{
                    type    = 'note'
                    content = 'Tamper Protection must be enabled from Intune or the Windows Security app; PowerShell cannot re-enable it when disabled.'
                }
                @{
                    type    = 'code'
                    title   = 'Validate Defender health'
                    lang    = 'powershell'
                    content = 'Get-MpComputerStatus | Select AMServiceEnabled, RealTimeProtectionEnabled, IsTamperProtected'
                }
            )
            $remediation = $remediationSteps | ConvertTo-Json -Depth 5
        }
    } elseif ($defenderPassiveWithStaleSignatures) {
        $severity = 'medium'
        $title = 'Endpoint AV: Defender passive but signatures out of date'
        $explanation = 'Defender is passive with outdated signatures, so fallback scanning would miss malware until signatures update.'
    } elseif ($conflict) {
        $severity = 'medium'
        $conflictNamesText = if ($thirdPartyActiveNames -and $thirdPartyActiveNames.Count -gt 0) { $thirdPartyActiveNames -join ', ' } else { 'third-party AV' }
        if ($conflictReason -eq 'MultipleThirdParty') {
            $title = 'Endpoint AV: Multiple AV products registered ({0})' -f $conflictNamesText
            $explanation = 'Competing antivirus engines can fight for system hooks and leave threats unscanned, so align on a single primary AV per policy.'
        } else {
            $title = 'Endpoint AV: Defender active alongside third-party ({0})' -f $conflictNamesText
            $explanation = 'Running Defender active beside another antivirus causes duplicate scanning and conflicts until Defender is set to passive or the extra agent is removed.'
        }
    } elseif ($inventoryUncertain) {
        $severity = 'medium'
        $title = 'Endpoint AV: Defender passive with unverified third-party agent'
        $explanation = 'Defender is passive but Security Center lists third-party agents as inactive, so technicians should confirm a primary antivirus is still installed.'
    } elseif ($thirdPartyActiveCount -ge 1 -and $defenderPassive -eq $true -and $signatureCurrent -eq $true) {
        $severity = 'info'
        $title = 'Endpoint AV: Third-party active; Defender in Passive Mode'
        $explanation = 'Third-party antivirus is protecting the device while Defender stays passive with current signatures, so coverage is healthy.'
    } elseif ($thirdPartyActiveCount -ge 1 -and $defenderPassive -eq $true -and $signatureCurrent -eq $null) {
        $severity = 'medium'
        $title = 'Endpoint AV: Third-party active but Defender signature status unknown'
        $explanation = 'Defender is passive but its signature currency is unknown, so technicians should confirm fallback definitions are updating.'
    } elseif ($thirdPartyActiveCount -eq 0 -and $defenderActive -eq $true -and $signatureCurrent -eq $true) {
        $severity = 'info'
        $title = 'Endpoint AV: Defender active with current signatures'
        $explanation = 'Microsoft Defender is actively protecting the device with current signatures and no conflicting third-party engines.'
    } elseif ($thirdPartyActiveCount -eq 0 -and $defenderActive -eq $true -and $signatureCurrent -eq $null) {
        $severity = 'medium'
        $title = 'Endpoint AV: Defender active but signature status unknown'
        $explanation = 'Defender is active but signature freshness is unknown, so technicians should verify updates to avoid malware gaps.'
    } else {
        $severity = 'warning'
        $title = 'Endpoint AV: Antivirus posture could not be confirmed'
        $explanation = 'Antivirus telemetry was incomplete, so technicians should verify which engine is protecting the device.'
    }

    Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title $title -Evidence ($evidenceLines.ToArray()) -Explanation $explanation -Subcategory 'Antivirus' -Remediation $remediation
}
