$script:Windows11SupportCache = $null

function Get-Windows11SupportData {
    if ($script:Windows11SupportCache) {
        return $script:Windows11SupportCache
    }

    $supportMetadataRoot = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'OperatingSystem'
    $relativePath = Join-Path -Path $supportMetadataRoot -ChildPath '.\windows11_support.json'
    $resolvedPath = $null
    try {
        $resolvedPath = (Resolve-Path -LiteralPath $relativePath -ErrorAction Stop).ProviderPath
    } catch {
        Write-HeuristicDebug -Source 'System/OS' -Message 'Windows 11 support policy file not found' -Data ([ordered]@{
            RequestedPath = $relativePath
        })
        return $null
    }

    try {
        $rawJson = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
        $parsed = $rawJson | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-HeuristicDebug -Source 'System/OS' -Message 'Failed reading Windows 11 support policy file' -Data ([ordered]@{
            Path = $resolvedPath
            Error = $_.Exception.Message
        })
        return $null
    }

    if (-not $parsed) {
        return $null
    }

    $versionLookup = @{}
    foreach ($versionEntry in @($parsed.versions)) {
        if ($versionEntry.version) {
            $versionLookup[$versionEntry.version] = $versionEntry
        }
    }

    $ltcsLookup = @{}
    foreach ($ltEntry in @($parsed.LTSC)) {
        if ($ltEntry.edition) {
            $ltcsLookup[$ltEntry.edition.ToLowerInvariant()] = $ltEntry
        }
    }

    $tzInfo = $null
    if ($parsed.timezone) {
        $timeZoneId = [string]$parsed.timezone
        try {
            $tzInfo = [System.TimeZoneInfo]::FindSystemTimeZoneById($timeZoneId)
        } catch {
            $fallbackMap = @{
                'Australia/Sydney' = 'AUS Eastern Standard Time'
            }
            if ($fallbackMap.ContainsKey($timeZoneId)) {
                try {
                    $tzInfo = [System.TimeZoneInfo]::FindSystemTimeZoneById($fallbackMap[$timeZoneId])
                } catch {
                    Write-HeuristicDebug -Source 'System/OS' -Message 'Unable to resolve Windows 11 support timezone (fallback failed)' -Data ([ordered]@{
                        RequestedId = $timeZoneId
                        FallbackId = $fallbackMap[$timeZoneId]
                        Error = $_.Exception.Message
                    })
                }
            } else {
                Write-HeuristicDebug -Source 'System/OS' -Message 'Unable to resolve Windows 11 support timezone' -Data ([ordered]@{
                    RequestedId = $timeZoneId
                    Error = $_.Exception.Message
                })
            }
        }
    }

    $script:Windows11SupportCache = [ordered]@{
        Raw          = $parsed
        Versions     = $versionLookup
        LTSC         = $ltcsLookup
        TimeZoneInfo = $tzInfo
    }

    return $script:Windows11SupportCache
}

function Get-Windows11ReleaseLabel {
    param(
        [Parameter(Mandatory)]
        [string]$Caption,
        [string]$Version,
        [string]$Build,
        [string]$DisplayVersion
    )

    if ($DisplayVersion -and ($DisplayVersion -match '^(?<release>20\d{2}H[12])$')) {
        return $Matches['release'].ToUpperInvariant()
    }

    $captionMatch = [regex]::Match($Caption, '(?i)(?<release>20\d{2}H[12])')
    if ($captionMatch.Success) {
        return $captionMatch.Groups['release'].Value.ToUpperInvariant()
    }

    if ($Version -and ($Version -match '10\.0\.(?<build>\d{4,5})')) {
        $VersionBuild = [int]$Matches['build']
        if ($VersionBuild -ge 26100) { return '24H2' }
        if ($VersionBuild -ge 22631) { return '23H2' }
        if ($VersionBuild -ge 22621) { return '22H2' }
        if ($VersionBuild -ge 22000) { return '21H2' }
    }

    if ($Build -and ($Build -match '^(?<build>\d{4,5})')) {
        $buildNumber = [int]$Matches['build']
        if ($buildNumber -ge 26100) { return '24H2' }
        if ($buildNumber -ge 22631) { return '23H2' }
        if ($buildNumber -ge 22621) { return '22H2' }
        if ($buildNumber -ge 22000) { return '21H2' }
    }

    return $null
}

function Get-Windows11EditionDescriptor {
    param(
        [Parameter(Mandatory)]
        [string]$Caption,
        [string]$Edition = ''
    )

    $text = ($Caption, $Edition) | Where-Object { $_ } | ForEach-Object { $_.ToString().ToLowerInvariant() }
    $textBlob = [string]::Join(' ', $text)

    if ($textBlob -match 'ltsc') {
        return [ordered]@{
            Key   = 'LTSC'
            Label = $Caption
        }
    }

    if ($textBlob -match 'enterprise' -or $textBlob -match 'education') {
        return [ordered]@{
            Key   = 'Enterprise_Education'
            Label = 'Enterprise and Education'
        }
    }

    return [ordered]@{
        Key   = 'Home_Pro'
        Label = 'Home and Pro'
    }
}

function Get-Windows11SupportStatus {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$SupportData,
        [Parameter(Mandatory)]
        [string]$Caption,
        [string]$Version,
        [string]$Build,
        [string]$Edition,
        [string]$DisplayVersion
    )

    $releaseLabel = Get-Windows11ReleaseLabel -Caption $Caption -Version $Version -Build $Build -DisplayVersion $DisplayVersion
    $editionDescriptor = Get-Windows11EditionDescriptor -Caption $Caption -Edition $Edition

    $supportRecord = $null
    $supportType = 'end_of_servicing'
    if ($editionDescriptor.Key -eq 'LTSC') {
        $lookupKey = $Caption.ToLowerInvariant()
        if ($SupportData.LTSC.ContainsKey($lookupKey)) {
            $supportRecord = $SupportData.LTSC[$lookupKey]
        } else {
            foreach ($entry in $SupportData.LTSC.GetEnumerator()) {
                if ($lookupKey -like ("*{0}*" -f $entry.Key)) {
                    $supportRecord = $entry.Value
                    break
                }
            }
        }

        if ($supportRecord) {
            if ($supportRecord.extended_end) {
                $supportType = 'extended_end'
            } elseif ($supportRecord.mainstream_end) {
                $supportType = 'mainstream_end'
            }
        }
    } elseif ($releaseLabel -and $SupportData.Versions.ContainsKey($releaseLabel)) {
        $versionEntry = $SupportData.Versions[$releaseLabel]
        if ($versionEntry.editions -and $versionEntry.editions.PSObject.Properties[$editionDescriptor.Key]) {
            $supportRecord = $versionEntry.editions.$($editionDescriptor.Key)
        }
    }

    if (-not $supportRecord) {
        return $null
    }

    $dateString = $null
    if ($editionDescriptor.Key -eq 'LTSC') {
        if ($supportType -eq 'extended_end' -and $supportRecord.extended_end) {
            $dateString = [string]$supportRecord.extended_end
        } elseif ($supportRecord.mainstream_end) {
            $dateString = [string]$supportRecord.mainstream_end
        }
    } else {
        if ($supportRecord.end_of_servicing) {
            $dateString = [string]$supportRecord.end_of_servicing
        }
    }

    if (-not $dateString) {
        return $null
    }

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    try {
        $parsedDate = [DateTime]::ParseExact($dateString, 'yyyy-MM-dd', $culture, [System.Globalization.DateTimeStyles]::None)
    } catch {
        Write-HeuristicDebug -Source 'System/OS' -Message 'Unable to parse Windows 11 EOL date' -Data ([ordered]@{
            Caption = $Caption
            Release = $releaseLabel
            Edition = $editionDescriptor.Label
            Date    = $dateString
            Error   = $_.Exception.Message
        })
        return $null
    }

    $tzInfo = $SupportData.TimeZoneInfo
    $dateOffset = $null
    if ($tzInfo) {
        $offset = $tzInfo.GetUtcOffset($parsedDate)
        $dateOffset = [DateTimeOffset]::new([DateTime]::SpecifyKind($parsedDate, [DateTimeKind]::Unspecified), $offset)
    } else {
        $dateOffset = [DateTimeOffset]::new([DateTime]::SpecifyKind($parsedDate, [DateTimeKind]::Utc), [TimeSpan]::Zero)
    }

    $supportLabel = switch ($supportType) {
        'extended_end'   { 'Extended support' }
        'mainstream_end' { 'Mainstream support' }
        default          { 'End of servicing' }
    }

    [ordered]@{
        Release        = $releaseLabel
        EditionLabel   = $editionDescriptor.Label
        DateString     = $dateString
        DateOffset     = $dateOffset
        SupportLabel   = $supportLabel
        EditionKey     = $editionDescriptor.Key
    }
}

function Invoke-SystemOperatingSystemChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/OS' -Message 'Starting operating system checks'

    $msinfoIdentity = Get-MsinfoSystemIdentity -Context $Context
    Write-HeuristicDebug -Source 'System/OS' -Message 'Resolved msinfo system identity' -Data ([ordered]@{
        Found = [bool]$msinfoIdentity
    })
    if (-not $msinfoIdentity) {
        $artifactCandidates = @(
            [pscustomobject]@{ Name = 'msinfo32'; Label = 'msinfo32.json' },
            [pscustomobject]@{ Name = 'msinfo'; Label = 'msinfo.json' }
        )

        $candidateLabels = ($artifactCandidates | ForEach-Object { $_.Label }) -join ', '
        Write-HeuristicDebug -Source 'System/OS' -Message 'System identity unavailable; gathering msinfo artifact evidence' -Data ([ordered]@{
            Candidates = $candidateLabels
        })

        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($Context -and $Context.PSObject.Properties['InputFolder'] -and $Context.InputFolder) {
            $evidenceLines.Add(("Input folder: {0}" -f $Context.InputFolder)) | Out-Null
        }

        $candidateEvidence = [System.Collections.Generic.List[string]]::new()

        foreach ($candidate in $artifactCandidates) {
            $name = $candidate.Name
            $label = $candidate.Label

            Write-HeuristicDebug -Source 'System/OS' -Message 'Evaluating msinfo artifact candidate' -Data ([ordered]@{
                Candidate = $label
            })

            $artifactResult = $null
            try {
                $artifactResult = Get-AnalyzerArtifact -Context $Context -Name $name
            } catch {
                $errorMessage = $_.Exception.Message
                Write-HeuristicDebug -Source 'System/OS' -Message 'Msinfo artifact lookup failed' -Data ([ordered]@{
                    Candidate = $label
                    Error     = $errorMessage
                })
                $candidateEvidence.Add(("{0}: lookup error: {1}" -f $label, $errorMessage)) | Out-Null
                continue
            }

            $entries = @()
            if ($artifactResult) {
                if ($artifactResult -is [System.Collections.IEnumerable] -and -not ($artifactResult -is [string])) {
                    foreach ($entry in $artifactResult) {
                        if ($entry) { $entries += ,$entry }
                    }
                } else {
                    $entries += ,$artifactResult
                }
            }

            Write-HeuristicDebug -Source 'System/OS' -Message 'Resolved msinfo artifact candidate' -Data ([ordered]@{
                Candidate  = $label
                Found      = [bool]($entries.Count -gt 0)
                EntryCount = $entries.Count
            })

            if ($entries.Count -eq 0) {
                $candidateEvidence.Add(("{0}: not found" -f $label)) | Out-Null
                continue
            }

            $plural = if ($entries.Count -eq 1) { '' } else { 's' }
            $candidateEvidence.Add(("{0}: found {1} file{2}" -f $label, $entries.Count, $plural)) | Out-Null

            $entryIndex = 0
            foreach ($entry in $entries) {
                $entryIndex++
                if (-not $entry) { continue }

                $path = $null
                if ($entry.PSObject.Properties['Path'] -and $entry.Path) {
                    $path = [string]$entry.Path
                }

                $data = if ($entry.PSObject.Properties['Data']) { $entry.Data } else { $null }
                $parseError = $null
                if ($data -and $data.PSObject.Properties['Error'] -and $data.Error) {
                    $parseError = [string]$data.Error
                }

                $payload = $null
                $payloadError = $null
                if (-not $parseError) {
                    try {
                        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $entry)
                    } catch {
                        $payloadError = $_.Exception.Message
                    }
                }

                $sectionCount = $null
                $summaryPresent = $null
                $collectorErrors = @()
                if ($payload) {
                    if ($payload.PSObject.Properties['Diagnostics'] -and $payload.Diagnostics -and $payload.Diagnostics.PSObject.Properties['SectionCount']) {
                        $sectionCount = $payload.Diagnostics.SectionCount
                    } elseif ($payload.PSObject.Properties['Sections'] -and $payload.Sections) {
                        try { $sectionCount = $payload.Sections.Count } catch { $sectionCount = $null }
                    }

                    try {
                        $summaryTable = Get-MsinfoSectionTable -Payload $payload -Names @('System Summary', 'summary')
                        $summaryPresent = [bool]$summaryTable
                    } catch {
                        $summaryPresent = $false
                    }

                    if ($payload.PSObject.Properties['Errors'] -and $payload.Errors) {
                        $collectorErrors = @($payload.Errors | Where-Object { $_ })
                    }
                }

                $debugData = [ordered]@{
                    Candidate  = $label
                    EntryIndex = $entryIndex
                    Path       = if ($path) { $path } else { $null }
                    Parsed     = [bool]$data
                }
                if ($parseError) { $debugData['ParseError'] = $parseError }
                $debugData['HasPayload'] = [bool]$payload
                if ($payloadError) { $debugData['PayloadError'] = $payloadError }
                if ($null -ne $sectionCount) { $debugData['SectionCount'] = $sectionCount }
                if ($summaryPresent -ne $null) { $debugData['SystemSummaryPresent'] = $summaryPresent }
                if ($collectorErrors -and $collectorErrors.Count -gt 0) {
                    $debugData['CollectorErrors'] = ($collectorErrors -join ' | ')
                }

                Write-HeuristicDebug -Source 'System/OS' -Message 'Inspecting msinfo artifact entry' -Data $debugData

                $entryLabel = if ($entries.Count -gt 1) { "  - Entry $entryIndex" } else { '  - Entry' }
                if ($path) {
                    $candidateEvidence.Add(("{0} path: {1}" -f $entryLabel, $path)) | Out-Null
                } else {
                    $candidateEvidence.Add(("{0} path: (unknown)" -f $entryLabel)) | Out-Null
                }

                if ($parseError) {
                    $candidateEvidence.Add(("    Parse error: {0}" -f $parseError)) | Out-Null
                    continue
                }

                if (-not $payload) {
                    if ($payloadError) {
                        $candidateEvidence.Add(("    Payload error: {0}" -f $payloadError)) | Out-Null
                    } else {
                        $candidateEvidence.Add('    Payload: missing') | Out-Null
                    }
                    continue
                }

                if ($null -ne $sectionCount) {
                    $candidateEvidence.Add(("    Sections: {0}" -f $sectionCount)) | Out-Null
                } else {
                    $candidateEvidence.Add('    Sections: (unknown)') | Out-Null
                }

                if ($summaryPresent) {
                    $candidateEvidence.Add('    System summary section: present') | Out-Null
                } else {
                    $candidateEvidence.Add('    System summary section: missing') | Out-Null
                }

                if ($collectorErrors -and $collectorErrors.Count -gt 0) {
                    foreach ($error in $collectorErrors) {
                        $candidateEvidence.Add(("    Collector error: {0}" -f $error)) | Out-Null
                    }
                }
            }
        }

        if ($candidateEvidence.Count -gt 0) {
            if ($evidenceLines.Count -gt 0) { $evidenceLines.Add('') | Out-Null }
            $evidenceLines.Add('Msinfo artifact investigation:') | Out-Null
            foreach ($line in $candidateEvidence) { $evidenceLines.Add($line) | Out-Null }
        } else {
            $evidenceLines.Add('Msinfo artifact investigation: no artifact information available') | Out-Null
        }

        $evidence = $evidenceLines -join "`n"

        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'System summary missing from msinfo32.json, so OS checks were skipped.' -Evidence $evidence -Subcategory 'Collection'
        return
    }

    $msinfoSummary = $msinfoIdentity.Summary
    if (-not $msinfoSummary) {
        $msinfoSummary = Get-MsinfoSystemSummarySection -Context $Context
    }

    $msinfoSecurity = Get-MsinfoSecuritySummary -Context $Context

    $os = [pscustomobject]@{
        Caption        = $msinfoIdentity.OSName
        BuildNumber    = $msinfoIdentity.OSBuild
        Version        = if ($msinfoIdentity.OSVersion) { $msinfoIdentity.OSVersion } else { $msinfoIdentity.OSVersionRaw }
        DisplayVersion = $msinfoIdentity.DisplayVersion
        OSArchitecture = $msinfoIdentity.OSArchitecture
        Edition        = $null
    }

    $caption = if ($os.PSObject.Properties['Caption']) { [string]$os.Caption } else { $null }
    $build = if ($os.PSObject.Properties['BuildNumber']) { [string]$os.BuildNumber } else { $null }

    if ($caption) {
        $description = if ($build) { "{0} (build {1})" -f $caption, $build } else { [string]$caption }
        $captionLower = $caption.ToLowerInvariant()
        $versionLabel = $null
        $displayVersion = $null
        if ($os.PSObject.Properties['Version'] -and $os.Version) {
            $versionLabel = [string]$os.Version
        }
        if ($os.PSObject.Properties['DisplayVersion'] -and $os.DisplayVersion) {
            $displayVersion = [string]$os.DisplayVersion
        }

        if ($captionLower -match 'windows\s+11') {
            $supportData = Get-Windows11SupportData
            $supportStatus = $null
            if ($supportData) {
                $supportStatus = Get-Windows11SupportStatus -SupportData ([pscustomobject]$supportData) -Caption $caption -Version $versionLabel -Build $build -Edition ($os.Edition) -DisplayVersion $displayVersion
            }

            if ($supportStatus -and $supportStatus.DateOffset) {
                $nowOffset = [DateTimeOffset]::UtcNow
                if ($supportData.TimeZoneInfo) {
                    $nowOffset = [System.TimeZoneInfo]::ConvertTime($nowOffset, $supportData.TimeZoneInfo)
                }

                $eolOffset = $supportStatus.DateOffset
                $dateText = $eolOffset.ToString('yyyy-MM-dd')
                $supportAudience = if ($supportStatus.EditionKey -eq 'LTSC') {
                    $supportStatus.EditionLabel
                } elseif ($supportStatus.Release) {
                    "Windows 11 {0} {1}" -f $supportStatus.Release, $supportStatus.EditionLabel
                } else {
                    "Windows 11 {0}" -f $supportStatus.EditionLabel
                }

                $supportVerb = if ($nowOffset.Date -gt $eolOffset.Date) { 'ended' } else { 'ends' }
                $evidence = "Detected operating system: {0}. {1} support {2} on {3} ({4})." -f $description, $supportAudience, $supportVerb, $dateText, $supportStatus.SupportLabel

                $detailLines = @()
                if ($caption) { $detailLines += "Caption: $caption" }
                if ($build) { $detailLines += "Build: $build" }
                if ($os.Edition) { $detailLines += "Edition: $($os.Edition)" }
                if ($os.OSArchitecture) { $detailLines += "Architecture: $($os.OSArchitecture)" }
                if ($versionLabel) { $detailLines += "Version label: $versionLabel" }
                if ($supportStatus.Release) { $detailLines += "Release: $($supportStatus.Release)" }
                if ($supportAudience) { $detailLines += "Support audience: $supportAudience" }
                if ($supportStatus.SupportLabel) { $detailLines += "Support phase: $($supportStatus.SupportLabel)" }
                if ($supportStatus.DateString) { $detailLines += "Support end: $($supportStatus.DateString)" }
                if ($detailLines.Count -gt 0) {
                    $evidence = "{0}`n`nDetails:`n{1}" -f $evidence, ($detailLines -join "`n")
                }

                if ($nowOffset.Date -gt $eolOffset.Date) {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'Operating system unsupported, so Microsoft no longer ships fixes or security updates.' -Evidence $evidence -Area 'System/OS' -Subcategory 'Operating System'
                } else {
                    $title = "Operating system supported until {0}: {1}" -f $dateText, $description
                    Add-CategoryNormal -CategoryResult $Result -Title $title -Evidence $evidence -Subcategory 'Operating System'
                }
            } else {
                Write-HeuristicDebug -Source 'System/OS' -Message 'Windows 11 support metadata unavailable for caption' -Data ([ordered]@{
                    Caption = $caption
                    Version = $versionLabel
                    Build   = $build
                })
                Add-CategoryNormal -CategoryResult $Result -Title ("Operating system supported: {0}" -f $description) -Subcategory 'Operating System'
            }
        } else {
            $unsupportedMatch = [regex]::Match($captionLower, 'windows\s+(7|8(\.1)?|10)')
            if ($unsupportedMatch.Success) {
                $versionLabel = $unsupportedMatch.Groups[1].Value
                $evidence = "Detected operating system: {0}. Microsoft support for Windows {1} has ended; upgrade to Windows 11." -f $description, $versionLabel

                $detailLines = @()
                if ($caption) { $detailLines += "Caption: $caption" }
                if ($build) { $detailLines += "Build: $build" }
                if ($os.Edition) { $detailLines += "Edition: $($os.Edition)" }
                if ($os.OSArchitecture) { $detailLines += "Architecture: $($os.OSArchitecture)" }
                if ($versionLabel) { $detailLines += "Version label: Windows $versionLabel" }
                $detailLines += 'Support timeline: Ended (no further security updates)'
                if ($detailLines.Count -gt 0) {
                    $evidence = "{0}`n`nDetails:`n{1}" -f $evidence, ($detailLines -join "`n")
                }

                Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'Operating system unsupported, so Microsoft no longer ships fixes or security updates.' -Evidence $evidence -Area 'System/OS' -Subcategory 'Operating System'
            } else {
                Add-CategoryCheck -CategoryResult $Result -Name 'Operating system' -Status $description
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Operating system inventory not available' -Subcategory 'Operating System'
    }

    $memoryBytes = $null
    if ($msinfoIdentity.PSObject.Properties['TotalPhysicalMemoryBytes'] -and $msinfoIdentity.TotalPhysicalMemoryBytes) {
        $memoryBytes = [uint64]$msinfoIdentity.TotalPhysicalMemoryBytes
    } elseif ($msinfoIdentity.PSObject.Properties['TotalPhysicalMemory'] -and $msinfoIdentity.TotalPhysicalMemory) {
        $memoryBytes = ConvertTo-MsinfoByteCount -Value $msinfoIdentity.TotalPhysicalMemory
    }

    if ($memoryBytes) {
        $gb = [math]::Round($memoryBytes / 1GB, 2)
        Add-CategoryCheck -CategoryResult $Result -Name 'Physical memory (GB)' -Status ([string]$gb)
    }

    $biosMode = $null
    if ($msinfoIdentity.PSObject.Properties['BiosMode'] -and $msinfoIdentity.BiosMode) {
        $biosMode = [string]$msinfoIdentity.BiosMode
    } elseif ($msinfoSummary) {
        $biosMode = Get-MsinfoSystemSummaryValue -Summary $msinfoSummary -Names @('BIOS Mode')
    }

    $secureBootState = $null
    if ($msinfoSecurity -and $msinfoSecurity.PSObject.Properties['SecureBootState']) {
        $secureBootState = [string]$msinfoSecurity.SecureBootState
    } elseif ($msinfoSummary) {
        $secureBootState = Get-MsinfoSystemSummaryValue -Summary $msinfoSummary -Names @('Secure Boot State')
    }

    $secureBootEvidenceParts = [System.Collections.Generic.List[string]]::new()
    if ($biosMode) {
        $secureBootEvidenceParts.Add("BIOS Mode (msinfo32): $biosMode") | Out-Null
    }
    if ($secureBootState) {
        $secureBootEvidenceParts.Add("Secure Boot State (msinfo32): $secureBootState") | Out-Null
    }

    $secureBootEvidence = if ($secureBootEvidenceParts.Count -gt 0) {
        ($secureBootEvidenceParts | Where-Object { $_ }) -join "`n"
    } else {
        $null
    }

    if ($secureBootState) {
        if ($secureBootState -match '^(?i)on|enabled|active$') {
            Add-CategoryNormal -CategoryResult $Result -Title 'Secure Boot is enabled, so firmware integrity protections are enforced.' -Evidence $secureBootEvidence -Subcategory 'Firmware'
        } elseif ($secureBootState -match '^(?i)off|disabled$') {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot is disabled, so the device can boot untrusted firmware.' -Evidence $secureBootEvidence -Subcategory 'Firmware'
        } elseif ($secureBootState -match '^(?i)unsupported$') {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot is unsupported on this hardware, so firmware integrity protections cannot run.' -Evidence $secureBootEvidence -Subcategory 'Firmware'
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ("Secure Boot reported unexpected state '{0}', so firmware integrity protections may be unreliable." -f $secureBootState) -Evidence $secureBootEvidence -Subcategory 'Firmware'
        }
    } elseif ($biosMode -and ($biosMode -match '(?i)uefi')) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot state not reported despite UEFI firmware, so the device may boot without firmware integrity protections.' -Evidence $secureBootEvidence -Subcategory 'Firmware'
    }
}
