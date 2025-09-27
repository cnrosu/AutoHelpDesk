function Invoke-SystemOperatingSystemChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if (-not $systemArtifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System inventory artifact missing' -Subcategory 'Collection'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
    if ($payload -and $payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
        $os = $payload.OperatingSystem
        $caption = $os.Caption
        $build = $os.BuildNumber
        if ($caption) {
            $description = if ($build) { "{0} (build {1})" -f $caption, $build } else { [string]$caption }
            $captionLower = $caption.ToLowerInvariant()
            if ($captionLower -match 'windows\s+11') {
                Add-CategoryNormal -CategoryResult $Result -Title ("Operating system supported: {0}" -f $description)
            } else {
                $unsupportedMatch = [regex]::Match($captionLower, 'windows\s+(7|8(\.1)?|10)')
                if ($unsupportedMatch.Success) {
                    $versionLabel = $unsupportedMatch.Groups[1].Value
                    $evidence = "Detected operating system: {0}. Microsoft support for Windows {1} has ended; upgrade to Windows 11." -f $description, $versionLabel
                    Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'Operating system unsupported' -Evidence $evidence -Subcategory 'Operating System'
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
            $biosModeMatch = [regex]::Match($systemInfoText,'(?im)^\s*BIOS\s+Mode\s*:\s*(?<value>.+)$')
            $secureBootMatch = [regex]::Match($systemInfoText,'(?im)^\s*Secure\s+Boot\s+State\s*:\s*(?<value>.+)$')
            if ($biosModeMatch.Success) {
                $biosMode = $biosModeMatch.Groups['value'].Value.Trim()
                $uefi = ($biosMode -match '(?i)UEFI')
                if ($uefi -and -not $secureBootMatch.Success) {
                    $evidence = ($systemInfoText -split "\r?\n" | Where-Object { $_ -match '(?i)(BIOS\s+Mode|Secure\s+Boot)' } | Select-Object -First 5)
                    if ($evidence.Count -eq 0) { $evidence = ($systemInfoText -split "\r?\n" | Select-Object -First 10) }
                    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Secure Boot state not reported despite UEFI firmware.' -Evidence (($evidence | Where-Object { $_ }) -join "`n") -Subcategory 'Firmware'
                }
            }
        }
    }
}
