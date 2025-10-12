$script:Windows11SupportCache = $null

function Get-Windows11SupportData {
    if ($script:Windows11SupportCache) {
        return $script:Windows11SupportCache
    }

    $relativePath = Join-Path -Path $PSScriptRoot -ChildPath '..\OperatingSystem\windows11_support.json'
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

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    Write-HeuristicDebug -Source 'System/OS' -Message 'Resolved system artifact' -Data ([ordered]@{
        Found = [bool]$systemArtifact
    })
    if (-not $systemArtifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System inventory artifact missing' -Subcategory 'Collection'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
    Write-HeuristicDebug -Source 'System/OS' -Message 'Evaluating system payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if ($payload -and $payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
        $os = $payload.OperatingSystem
        $caption = $os.Caption
        $build = $os.BuildNumber
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

                    if ($nowOffset.Date -gt $eolOffset.Date) {
                        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'Operating system unsupported, so Microsoft no longer ships fixes or security updates.' -Evidence $evidence -Subcategory 'Operating System' -Data @{
                            Area = 'System/OS'
                            Kind = 'OsSupport'
                            OS   = @{
                                Caption       = $caption
                                Build         = $build
                                Edition       = $os.Edition
                                Architecture  = $os.OSArchitecture
                                VersionLabel  = $versionLabel
                                Release       = $supportStatus.Release
                                IsWin11       = $true
                                SupportPolicy = @{
                                    Audience = $supportAudience
                                    Phase    = $supportStatus.SupportLabel
                                    EndDate  = $supportStatus.DateString
                                }
                            }
                        }
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
                    Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'Operating system unsupported, so Microsoft no longer ships fixes or security updates.' -Evidence $evidence -Subcategory 'Operating System' -Data @{
                        Area = 'System/OS'
                        Kind = 'OsSupport'
                        OS = @{
                            Caption = $caption
                            Build   = $build
                            Edition = $os.Edition
                            Architecture = $os.OSArchitecture
                            VersionLabel = $versionLabel
                            IsWin11 = ($captionLower -match 'windows\s+11')
                        }
                    }
                } else {
                    Add-CategoryCheck -CategoryResult $Result -Name 'Operating system' -Status $description
                }
            }
        }
        if ($os.LastBootUpTime) {
            Add-CategoryCheck -CategoryResult $Result -Name 'Last boot time' -Status ([string]$os.LastBootUpTime)
        }
    } elseif ($payload -and $payload.OperatingSystem -and $payload.OperatingSystem.Error) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to read OS inventory' -Evidence ($payload.OperatingSystem.Error) -Subcategory 'Operating System'
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Operating system inventory not available' -Subcategory 'Operating System'
    }

    if ($payload -and $payload.ComputerSystem -and -not $payload.ComputerSystem.Error) {
        $cs = $payload.ComputerSystem
        if ($cs.TotalPhysicalMemory) {
            $gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            Add-CategoryCheck -CategoryResult $Result -Name 'Physical memory (GB)' -Status ([string]$gb)
        }
    } elseif ($payload -and $payload.ComputerSystem -and $payload.ComputerSystem.Error) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to query computer system details' -Evidence $payload.ComputerSystem.Error -Subcategory 'Hardware Inventory'
    }

    if ($payload -and $payload.SystemInfoText -and -not ($payload.SystemInfoText.Error)) {
        $systemInfo = $payload.SystemInfoText
        if ($systemInfo -is [System.Collections.IEnumerable] -and -not ($systemInfo -is [string])) {
            $systemInfo = ($systemInfo | ForEach-Object { [string]$_ }) -join "`n"
        }
        $systemInfoText = [string]$systemInfo
        if ($systemInfoText) {
            $systemInfoLines = $systemInfoText -split "\r?\n"
            $biosModeMatch = [regex]::Match($systemInfoText,'(?im)^\s*BIOS\s+Mode\s*:\s*(?<value>.+)$')
            $secureBootMatch = [regex]::Match($systemInfoText,'(?im)^\s*Secure\s+Boot\s+State\s*:\s*(?<value>.+)$')
            if ($secureBootMatch.Success) {
                $secureBootState = $secureBootMatch.Groups['value'].Value.Trim()
                $secureBootEvidenceLines = @($systemInfoLines | Where-Object { $_ -match '(?i)(Secure\s+Boot|BIOS\s+Mode)' } | Select-Object -First 5)
                if ($secureBootEvidenceLines.Count -eq 0) {
                    $secureBootEvidenceLines = @($systemInfoLines | Select-Object -First 10)
                }
                $secureBootEvidence = ($secureBootEvidenceLines | Where-Object { $_ }) -join "`n"

                if ($secureBootState -match '^(?i)on$') {
                    Add-CategoryNormal -CategoryResult $Result -Title 'Secure Boot is enabled, so firmware integrity protections are enforced.' -Evidence $secureBootEvidence -Subcategory 'Firmware'
                } elseif ($secureBootState -match '^(?i)off$') {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot is disabled, so the device can boot untrusted firmware.' -Evidence $secureBootEvidence -Subcategory 'Firmware'
                } elseif ($secureBootState -match '^(?i)unsupported$') {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot is unsupported on this hardware, so firmware integrity protections cannot run.' -Evidence $secureBootEvidence -Subcategory 'Firmware'
                } else {
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ("Secure Boot reported unexpected state '{0}', so firmware integrity protections may be unreliable." -f $secureBootState) -Evidence $secureBootEvidence -Subcategory 'Firmware'
                }
            }
            if ($biosModeMatch.Success) {
                $biosMode = $biosModeMatch.Groups['value'].Value.Trim()
                $uefi = ($biosMode -match '(?i)UEFI')
                if ($uefi -and -not $secureBootMatch.Success) {
                    $evidence = ($systemInfoLines | Where-Object { $_ -match '(?i)(BIOS\s+Mode|Secure\s+Boot)' } | Select-Object -First 5)
                    if ($evidence.Count -eq 0) { $evidence = ($systemInfoLines | Select-Object -First 10) }
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot state not reported despite UEFI firmware, so the device may boot without firmware integrity protections.' -Evidence (($evidence | Where-Object { $_ }) -join "`n") -Subcategory 'Firmware'
                }
            }
        }
    }
}
