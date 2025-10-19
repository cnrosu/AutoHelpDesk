function ConvertTo-UtcDateTime {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    return $null
}

function Format-StatusString {
    param($Value)

    if ($Value -eq $true) { return 'True' }
    if ($Value -eq $false) { return 'False' }
    return 'Unknown'
}

function Format-UtcTimestamp {
    param($Value)

    $date = ConvertTo-UtcDateTime $Value
    if ($date) { return $date.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Value -is [string] -and -not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
    return 'none'
}

function Join-ReadableList {
    param([string[]]$Items)

    if (-not $Items) { return '' }
    $filtered = @($Items | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($filtered.Count -eq 0) { return '' }
    if ($filtered.Count -eq 1) { return $filtered[0] }
    if ($filtered.Count -eq 2) { return "{0} and {1}" -f $filtered[0], $filtered[1] }

    $leading = $filtered[0..($filtered.Count - 2)]
    return "{0}, and {1}" -f ($leading -join ', '), $filtered[-1]
}

function Get-TpmSpecMaxVersion {
    param([string]$SpecText)

    if ([string]::IsNullOrWhiteSpace($SpecText)) { return $null }

    $matches = [regex]::Matches($SpecText, '\d+(?:\.\d+)?')
    if ($matches.Count -eq 0) { return $null }

    $max = $null
    foreach ($match in $matches) {
        if (-not $match.Success) { continue }
        $token = $match.Value
        if (-not $token) { continue }

        $parsed = 0.0
        if ([double]::TryParse($token, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            if ($null -eq $max -or $parsed -gt $max) {
                $max = $parsed
            }
        }
    }

    return $max
}

function Find-DhaPolicyFlag {
    param(
        $Object,
        [int]$Depth = 0
    )

    if ($Depth -gt 3) { return $null }
    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        foreach ($item in $Object) {
            $result = Find-DhaPolicyFlag -Object $item -Depth ($Depth + 1)
            if ($null -ne $result) { return $result }
        }
        return $null
    }

    if (-not ($Object -is [psobject])) { return $null }

    $candidateNames = @(
        'RequireDeviceHealthAttestation',
        'DeviceHealthAttestationRequired',
        'RequireDha',
        'RequireDHA',
        'MeasuredBootRequired',
        'HealthAttestationRequired',
        'RequireHealthAttestation'
    )

    foreach ($name in $candidateNames) {
        $property = $Object.PSObject.Properties[$name]
        if (-not $property) { continue }
        $value = $property.Value
        $converted = ConvertTo-NullableBool $value
        if ($null -ne $converted) { return $converted }
        if ($value -is [string]) {
            $text = $value.Trim()
            if ($text -match '(?i)^(required|true|yes)$') { return $true }
            if ($text -match '(?i)^(false|no|optional)$') { return $false }
        }
    }

    $nestedCandidates = @('Policy', 'Settings', 'Attestation', 'Requirements', 'Security')
    foreach ($nestedName in $nestedCandidates) {
        $nestedProperty = $Object.PSObject.Properties[$nestedName]
        if (-not $nestedProperty) { continue }
        $nestedResult = Find-DhaPolicyFlag -Object $nestedProperty.Value -Depth ($Depth + 1)
        if ($null -ne $nestedResult) { return $nestedResult }
    }

    return $null
}

function Get-DhaPolicyRequirement {
    param(
        $Context,
        $Payload
    )

    $sources = New-Object System.Collections.Generic.List[object]
    if ($Payload) { $null = $sources.Add($Payload) }

    if ($Context -and $Context.Artifacts) {
        foreach ($key in $Context.Artifacts.Keys) {
            if (-not $key) { continue }
            if ($key -notmatch 'policy') { continue }
            $artifactEntries = $Context.Artifacts[$key]
            foreach ($entry in (ConvertTo-List $artifactEntries)) {
                if (-not $entry) { continue }
                if ($entry.PSObject.Properties['Data'] -and $entry.Data) {
                    $null = $sources.Add($entry.Data)
                }
            }
        }
    }

    foreach ($source in $sources) {
        $flag = Find-DhaPolicyFlag -Object $source
        if ($null -ne $flag) { return $flag }
    }

    return $false
}

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

    if (-not $measuredBootArtifact) { return }

    $measuredPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $measuredBootArtifact)
    Write-HeuristicDebug -Source 'Security' -Message 'Evaluating measured boot payload' -Data ([ordered]@{
        HasPayload = [bool]$measuredPayload
    })

    if (-not $measuredPayload) { return }

    $join = if ($measuredPayload.PSObject.Properties['Join']) { $measuredPayload.Join } else { $null }
    $platform = if ($measuredPayload.PSObject.Properties['Platform']) { $measuredPayload.Platform } else { $null }
    $dha = if ($measuredPayload.PSObject.Properties['DHA']) { $measuredPayload.DHA } else { $null }
    $collectedAt = if ($measuredPayload.PSObject.Properties['CollectedAtUtc']) { ConvertTo-UtcDateTime $measuredPayload.CollectedAtUtc } else { $null }

    $mdmEnrolled = $null
    if ($join -and $join.PSObject.Properties['MDMEnrolled']) {
        $mdmEnrolled = ConvertTo-NullableBool $join.MDMEnrolled
    }

    $policyRequires = Get-DhaPolicyRequirement -Context $Context -Payload $measuredPayload
    $shouldEvaluate = ($mdmEnrolled -eq $true) -or ($policyRequires -eq $true)

    Write-HeuristicDebug -Source 'Security' -Message 'Measured boot evaluation context' -Data ([ordered]@{
        MdmEnrolled     = if ($null -ne $mdmEnrolled) { $mdmEnrolled } else { $null }
        PolicyRequires  = $policyRequires
        ShouldEvaluate  = $shouldEvaluate
    })

    $tpm = if ($platform -and $platform.PSObject.Properties['TPM']) { $platform.TPM } else { $null }
    $secureBoot = if ($platform -and $platform.PSObject.Properties['SecureBoot']) { ConvertTo-NullableBool $platform.SecureBoot } else { $null }
    $uefi = if ($platform -and $platform.PSObject.Properties['UEFI']) { ConvertTo-NullableBool $platform.UEFI } else { $null }
    $tpmPresent = if ($tpm -and $tpm.PSObject.Properties['Present']) { ConvertTo-NullableBool $tpm.Present } else { $null }
    $tpmReady = if ($tpm -and $tpm.PSObject.Properties['Ready']) { ConvertTo-NullableBool $tpm.Ready } else { $null }
    $tpmSpecText = if ($tpm -and $tpm.PSObject.Properties['Spec']) { [string]$tpm.Spec } else { $null }
    $tpmSpecVersion = Get-TpmSpecMaxVersion -SpecText $tpmSpecText
    $tpmSpecOk = if ($null -eq $tpmSpecVersion) { $null } else { $tpmSpecVersion -ge 2.0 }

    $dhaLogChannels = if ($dha -and $dha.PSObject.Properties['LogChannels']) { $dha.LogChannels } else { $null }
    $dhaChannelPresent = if ($dhaLogChannels -and $dhaLogChannels.PSObject.Properties['DHAOperationalPresent']) { ConvertTo-NullableBool $dhaLogChannels.DHAOperationalPresent } else { $null }
    $tpmWmiChannelPresent = if ($dhaLogChannels -and $dhaLogChannels.PSObject.Properties['TPMWMIOperationalPresent']) { ConvertTo-NullableBool $dhaLogChannels.TPMWMIOperationalPresent } else { $null }

    $lastSuccess = if ($dha -and $dha.PSObject.Properties['LastSuccessUtc']) { ConvertTo-UtcDateTime $dha.LastSuccessUtc } else { $null }
    $lastError = if ($dha -and $dha.PSObject.Properties['LastErrorUtc']) { ConvertTo-UtcDateTime $dha.LastErrorUtc } else { $null }

    $recentErrors = $null
    if ($dha -and $dha.PSObject.Properties['RecentErrors']) {
        $rawErrors = $dha.RecentErrors
        if ($rawErrors -is [int]) {
            $recentErrors = [int]$rawErrors
        } else {
            $parsedErrors = 0
            if ([int]::TryParse([string]$rawErrors, [ref]$parsedErrors)) {
                $recentErrors = $parsedErrors
            }
        }
    }
    if ($null -eq $recentErrors) { $recentErrors = 0 }

    $nowUtc = (Get-Date).ToUniversalTime()
    $successWindow = $nowUtc.AddDays(-7)
    $hasRecentSuccess = $false
    if ($lastSuccess) { $hasRecentSuccess = ($lastSuccess -ge $successWindow) }
    $hasRecentErrors = ($recentErrors -gt 0)

    $tpm2Status = $null
    if ($tpmPresent -eq $false -or $tpmReady -eq $false) {
        $tpm2Status = $false
    } elseif ($tpmPresent -eq $true -and $tpmReady -eq $true) {
        if ($tpmSpecOk -eq $false) { $tpm2Status = $false }
        elseif ($tpmSpecOk -eq $true) { $tpm2Status = $true }
    }

    $secureBootOk = ($secureBoot -eq $true)

    $platformIssues = New-Object System.Collections.Generic.List[string]
    if ($uefi -eq $false) { $null = $platformIssues.Add('the device is booting in legacy BIOS mode') }
    if ($secureBoot -eq $false) { $null = $platformIssues.Add('Secure Boot is disabled') }
    if ($tpmPresent -eq $false) { $null = $platformIssues.Add('no TPM is available') }
    if ($tpmReady -eq $false) { $null = $platformIssues.Add('the TPM is not ready') }
    if ($tpmSpecOk -eq $false) { $null = $platformIssues.Add('the TPM firmware is below version 2.0') }

    $summaryLine = "MDM={0}; SecureBoot={1}; TPM2={2}; DHA last success={3}; errors in window={4}." -f (
        Format-StatusString $mdmEnrolled,
        Format-StatusString $secureBoot,
        Format-StatusString $tpm2Status,
        Format-UtcTimestamp $lastSuccess,
        $recentErrors
    )

    $joinEvidence = $null
    if ($join) {
        $joinEvidence = "Join: AADJ={0}; HAADJ={1}; ADJoined={2}; MDMEnrolled={3}" -f (
            if ($join.PSObject.Properties['AADJ']) { Format-StatusString (ConvertTo-NullableBool $join.AADJ) } else { 'Unknown' },
            if ($join.PSObject.Properties['HAADJ']) { Format-StatusString (ConvertTo-NullableBool $join.HAADJ) } else { 'Unknown' },
            if ($join.PSObject.Properties['ADJoined']) { Format-StatusString (ConvertTo-NullableBool $join.ADJoined) } else { 'Unknown' },
            Format-StatusString $mdmEnrolled
        )
    }

    $platformEvidenceParts = @()
    $platformEvidenceParts += "UEFI={0}" -f (Format-StatusString $uefi)
    $platformEvidenceParts += "SecureBoot={0}" -f (Format-StatusString $secureBoot)
    $platformEvidenceParts += "TPMPresent={0}" -f (Format-StatusString $tpmPresent)
    $platformEvidenceParts += "TPMReady={0}" -f (Format-StatusString $tpmReady)
    if ($tpmSpecText) { $platformEvidenceParts += "TPMSpec=$tpmSpecText" }
    $platformEvidence = "Platform: {0}" -f ($platformEvidenceParts -join '; ')

    $dhaEvidenceParts = @()
    $dhaEvidenceParts += "DHAOperationalPresent={0}" -f (Format-StatusString $dhaChannelPresent)
    $dhaEvidenceParts += "TPMWMIOperationalPresent={0}" -f (Format-StatusString $tpmWmiChannelPresent)
    $dhaEvidenceParts += "LastSuccess={0}" -f (Format-UtcTimestamp $lastSuccess)
    $dhaEvidenceParts += "LastError={0}" -f (Format-UtcTimestamp $lastError)
    $dhaEvidenceParts += "RecentErrors={0}" -f $recentErrors
    $dhaEvidence = "DHA: {0}" -f ($dhaEvidenceParts -join '; ')

    $evidenceLines = New-Object System.Collections.Generic.List[string]
    $null = $evidenceLines.Add($summaryLine)
    if ($joinEvidence) { $null = $evidenceLines.Add($joinEvidence) }
    $null = $evidenceLines.Add($platformEvidence)
    $null = $evidenceLines.Add($dhaEvidence)
    if ($collectedAt) { $null = $evidenceLines.Add("CollectedAtUtc={0}" -f (Format-UtcTimestamp $collectedAt)) }
    if ($policyRequires -eq $true) { $null = $evidenceLines.Add('PolicyRequiresDHA=True') }

    $evidence = ($evidenceLines | Where-Object { $_ }) -join "`n"

    if (-not $shouldEvaluate) {
        $title = 'Security/Measured Boot: DHA not configured because the device is not enrolled in MDM, so remote attestation is not expected.'
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Measured Boot'
        return
    }

    if ($policyRequires -eq $true -and $mdmEnrolled -ne $true) {
        $title = 'Security/Measured Boot: Attestation required but device not MDM enrolled, so compliance cannot be verified.'
        $remediation = 'Enroll the device with the required MDM service or update policy expectations so health attestation can be evaluated.'
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Measured Boot' -Remediation $remediation
        return
    }

    if ($platformIssues.Count -gt 0) {
        $reasonText = Join-ReadableList $platformIssues.ToArray()
        $title = "Security/Measured Boot: Cannot attest because {0}, so remote health attestation cannot succeed." -f $reasonText
        $remediation = 'Enable Secure Boot in firmware, ensure TPM 2.0 hardware is present and initialized, and verify code integrity baselines before retrying attestation.'
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'high' -Title $title -Evidence $evidence -Subcategory 'Measured Boot' -Remediation $remediation
        return
    }

    if ($dhaChannelPresent -eq $true) {
        if (-not $hasRecentSuccess) {
            $title = 'Security/Measured Boot: No recent attestation result, so the device has not proven a healthy boot in the last 7 days.'
            $remediation = 'Confirm the device is enrolled in MDM, allow TLS 443 access to Microsoft attestation endpoints, trigger a device sync, and review the DHA Operational log for specific errors.'
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Measured Boot' -Remediation $remediation
            return
        }

        if ($hasRecentErrors) {
            $title = 'Security/Measured Boot: Health attestation errors detected, so recent attestation attempts did not complete.'
            $remediation = 'Review DeviceHealthAttestation/Operational errors, verify proxy or firewall access to DHA endpoints, and retry attestation from the MDM portal or Company Portal.'
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Measured Boot' -Remediation $remediation
            return
        }

        $title = 'Security/Measured Boot: DHA healthy because the device reported a successful health attestation within the last 7 days.'
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Measured Boot'
        return
    }

    if ($secureBootOk -and $tpm2Status -eq $true) {
        $title = 'Security/Measured Boot: DHA log channel missing even though the platform is ready, so enable logging if attestation diagnostics are needed.'
        $remediation = 'Enable the DeviceHealthAttestation/Operational channel if deeper troubleshooting is required, or confirm attestation status in your MDM portal.'
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Measured Boot' -Remediation $remediation
        return
    }

    $titleFallback = 'Security/Measured Boot: DHA state could not be confirmed because required log data is unavailable.'
    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $titleFallback -Evidence $evidence -Subcategory 'Measured Boot'
}
