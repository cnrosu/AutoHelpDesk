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
            if ($captionLower -match 'windows\s+11') {
                Add-CategoryNormal -CategoryResult $Result -Title ("Operating system supported: {0}" -f $description) -Subcategory 'Operating System'
            } else {
                $unsupportedMatch = [regex]::Match($captionLower, 'windows\s+(7|8(\.1)?|10)')
                if ($unsupportedMatch.Success) {
                    $versionLabel = $unsupportedMatch.Groups[1].Value
                    $evidence = "Detected operating system: {0}. Microsoft support for Windows {1} has ended; upgrade to Windows 11." -f $description, $versionLabel
                    Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title ("Windows {0} is unsupported, so the device no longer receives vital security updates." -f $versionLabel) -Evidence $evidence -Subcategory 'Operating System'
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
