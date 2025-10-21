function ConvertTo-UptimeDateTimeUtc {
    param($Value)

    if (-not $Value) { return $null }

    try {
        if ($Value -is [DateTimeOffset]) {
            return $Value.UtcDateTime
        }

        $candidate = $null
        if ($Value -is [DateTime]) {
            $candidate = $Value
        } elseif ($Value -is [string]) {
            $text = $Value.Trim()
            if (-not $text) { return $null }

            $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
            try {
                $offset = [DateTimeOffset]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
                return $offset.UtcDateTime
            } catch {
                $candidate = [DateTime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture)
            }
        } else {
            return $null
        }

        if (-not $candidate) { return $null }

        if ($candidate.Kind -eq [DateTimeKind]::Utc) { return $candidate }
        if ($candidate.Kind -eq [DateTimeKind]::Unspecified) {
            $candidate = [DateTime]::SpecifyKind($candidate, [DateTimeKind]::Local)
        }

        return $candidate.ToUniversalTime()
    } catch {
        return $null
    }
}

function ConvertTo-UptimeInt64 {
    param($Value)

    if ($null -eq $Value) { return $null }

    try {
        if ($Value -is [long] -or $Value -is [int]) {
            return [int64]$Value
        }
        if ($Value -is [double] -or $Value -is [decimal]) {
            return [int64][math]::Floor([double]$Value)
        }
        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        return [int64][math]::Floor([double]$text)
    } catch {
        return $null
    }
}

function ConvertTo-UptimeNullableBool {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }

    if ($Value -is [int] -or $Value -is [long]) {
        return ([int64]$Value -ne 0)
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    if ($text -match '^(?i)(true|yes|enabled|on)$') { return $true }
    if ($text -match '^(?i)(false|no|disabled|off)$') { return $false }

    try {
        $number = [int64]$text
        return ($number -ne 0)
    } catch {
        return $null
    }
}

function Format-UptimeBoolean {
    param($Value)

    if ($null -eq $Value) { return 'Unknown' }
    if ($Value) {
        return 'True'
    }

    return 'False'
}

function ConvertTo-UptimeHumanizedTime {
    param([int64]$Seconds)

    if ($Seconds -lt 0) { $Seconds = 0 }
    $span = [TimeSpan]::FromSeconds($Seconds)

    $parts = New-Object System.Collections.Generic.List[string]
    if ($span.Days -gt 0) {
        $label = if ($span.Days -eq 1) { 'day' } else { 'days' }
        $parts.Add(("{0} {1}" -f $span.Days, $label)) | Out-Null
    }
    if ($span.Hours -gt 0) {
        $label = if ($span.Hours -eq 1) { 'hour' } else { 'hours' }
        $parts.Add(("{0} {1}" -f $span.Hours, $label)) | Out-Null
    }
    if ($span.Minutes -gt 0 -and $parts.Count -lt 3) {
        $label = if ($span.Minutes -eq 1) { 'minute' } else { 'minutes' }
        $parts.Add(("{0} {1}" -f $span.Minutes, $label)) | Out-Null
    }
    if ($parts.Count -eq 0) {
        $label = if ($span.Seconds -eq 1) { 'second' } else { 'seconds' }
        return "{0} {1}" -f $span.Seconds, $label
    }

    return ($parts | Select-Object -First 3) -join ', '
}

function Get-UptimeSummaryFromPayload {
    param($Uptime)

    if (-not $Uptime) { return $null }
    if ($Uptime.PSObject.Properties['Error'] -and $Uptime.Error) {
        return [pscustomobject]@{
            HasError = $true
            Error    = [string]$Uptime.Error
            Source   = if ($Uptime.PSObject.Properties['Source']) { [string]$Uptime.Source } else { 'UptimeCollector' }
        }
    }

    $lastBootRaw = $null
    if ($Uptime.PSObject.Properties['LastBootUpTime']) { $lastBootRaw = $Uptime.LastBootUpTime }
    $effectiveSinceRaw = $null
    if ($Uptime.PSObject.Properties['EffectiveSince']) { $effectiveSinceRaw = $Uptime.EffectiveSince }

    return [pscustomobject]@{
        HasError               = $false
        LastBootUtc            = ConvertTo-UptimeDateTimeUtc -Value $lastBootRaw
        LastBootRaw            = $lastBootRaw
        KernelUptimeSeconds    = ConvertTo-UptimeInt64 -Value $(if ($Uptime.PSObject.Properties['KernelUptimeSeconds']) { $Uptime.KernelUptimeSeconds } else { $null })
        EffectiveSinceUtc      = ConvertTo-UptimeDateTimeUtc -Value $effectiveSinceRaw
        EffectiveSinceRaw      = $effectiveSinceRaw
        EffectiveUptimeSeconds = ConvertTo-UptimeInt64 -Value $(if ($Uptime.PSObject.Properties['EffectiveUptimeSeconds']) { $Uptime.EffectiveUptimeSeconds } else { $null })
        FastStartupConfigured  = ConvertTo-UptimeNullableBool -Value $(if ($Uptime.PSObject.Properties['FastStartupConfigured']) { $Uptime.FastStartupConfigured } else { $null })
        HibernateEnabled       = ConvertTo-UptimeNullableBool -Value $(if ($Uptime.PSObject.Properties['HibernateEnabled']) { $Uptime.HibernateEnabled } else { $null })
        HiberfilePresent       = ConvertTo-UptimeNullableBool -Value $(if ($Uptime.PSObject.Properties['HiberfilePresent']) { $Uptime.HiberfilePresent } else { $null })
        FastStartupEffective   = ConvertTo-UptimeNullableBool -Value $(if ($Uptime.PSObject.Properties['FastStartupEffective']) { $Uptime.FastStartupEffective } else { $null })
    }
}

function Get-CaseInsensitivePropertyValue {
    param(
        $Object,
        [string]$Name
    )

    if (-not $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ($null -eq $key) { continue }
            $text = [string]$key
            if ($text.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Object[$key]
            }
        }
        return $null
    }

    foreach ($prop in $Object.PSObject.Properties) {
        if (-not $prop -or -not $prop.Name) { continue }
        if ($prop.Name.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $prop.Value
        }
    }

    return $null
}

function Get-UptimeConfigPayload {
    param($Context)

    $configNames = @('config', 'configuration', 'settings', 'analyzer-config', 'ahd-config')
    foreach ($name in $configNames) {
        $artifact = Get-AnalyzerArtifact -Context $Context -Name $name
        if (-not $artifact) { continue }

        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
        if ($payload) { return $payload }
    }

    return $null
}

function Get-UptimeConfigValue {
    param(
        $Config,
        [string[]]$Path
    )

    if (-not $Config -or -not $Path -or $Path.Count -eq 0) { return $null }

    $current = $Config
    foreach ($segment in $Path) {
        if (-not $current) { return $null }
        $current = Get-CaseInsensitivePropertyValue -Object $current -Name $segment
        if ($null -eq $current) { return $null }
    }

    return $current
}

function ConvertTo-UptimeThresholdArray {
    param(
        $Value,
        [bool]$IsServer
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $numbers = New-Object System.Collections.Generic.List[double]
        foreach ($entry in $Value) {
            if ($null -eq $entry) { continue }
            try {
                $number = [double]$entry
                if ($number -lt 0) { continue }
                $numbers.Add($number) | Out-Null
            } catch {
                continue
            }
        }

        if ($numbers.Count -gt 0) {
            return @($numbers.ToArray())
        }
    }

    if ($Value -is [System.Collections.IDictionary] -or $Value.PSObject) {
        $key = if ($IsServer) { 'Server' } else { 'Workstation' }
        $child = Get-CaseInsensitivePropertyValue -Object $Value -Name $key
        if ($null -ne $child) {
            return ConvertTo-UptimeThresholdArray -Value $child -IsServer:$IsServer
        }
    }

    return $null
}

function Resolve-UptimeThresholds {
    param(
        $Context,
        [bool]$IsServer
    )

    $defaults = if ($IsServer) { @(7, 14, 30, 60) } else { @(3, 7, 14, 21) }

    $config = Get-UptimeConfigPayload -Context $Context
    $override = $null
    if ($config) {
        $paths = @(
            @('Heuristics', 'System', 'Uptime', 'LongUptimeDays'),
            @('Heuristics', 'System', 'LongUptimeDays'),
            @('Heuristics', 'System', 'LongUptime'),
            @('Heuristics', 'LongUptimeDays'),
            @('Heuristics', 'LongUptime'),
            @('LongUptimeDays')
        )

        foreach ($path in $paths) {
            $candidate = Get-UptimeConfigValue -Config $config -Path $path
            if ($null -eq $candidate) { continue }
            $override = ConvertTo-UptimeThresholdArray -Value $candidate -IsServer:$IsServer
            if ($override) { break }
        }
    }

    $selected = if ($override) { $override } else { $defaults }
    return @($selected | Sort-Object)
}

function Invoke-SystemUptimeFastStartup {
    param(
        $Result,
        $Summary
    )

    $fastStartupEffective = $Summary.FastStartupEffective
    $fastStartupConfigured = $Summary.FastStartupConfigured
    $hibernateEnabled = $Summary.HibernateEnabled
    $hiberfilePresent = $Summary.HiberfilePresent

    if ($null -eq $fastStartupEffective -and $null -eq $fastStartupConfigured -and $null -eq $hibernateEnabled -and $null -eq $hiberfilePresent) {
        Write-HeuristicDebug -Source 'System/Uptime' -Message 'Fast Startup signals unavailable; skipping fast startup heuristic.'
        return
    }

    $evidenceLines = New-Object System.Collections.Generic.List[string]
    $evidenceLines.Add("FastStartupEffective: $(Format-UptimeBoolean $fastStartupEffective)") | Out-Null
    $evidenceLines.Add("FastStartupConfigured: $(Format-UptimeBoolean $fastStartupConfigured)") | Out-Null
    $evidenceLines.Add("HibernateEnabled: $(Format-UptimeBoolean $hibernateEnabled)") | Out-Null
    $evidenceLines.Add("HiberfilePresent: $(Format-UptimeBoolean $hiberfilePresent)") | Out-Null

    if ($fastStartupConfigured -eq $true -and $fastStartupEffective -ne $true -and ($hibernateEnabled -ne $true) -and ($hiberfilePresent -ne $true)) {
        $evidenceLines.Add('Fast Startup is configured but hibernation support is unavailable, so the feature is inert.') | Out-Null
    }

    if ($fastStartupEffective -ne $true) {
        $evidenceLines.Insert(0, 'Fast Startup signals indicate shutdown is already performing a cold boot.') | Out-Null
    }

    $evidenceArray = $evidenceLines.ToArray()

    if ($fastStartupEffective -eq $true) {
        $title = 'Fast Startup is enabled: Shutdown does not cold boot'
        $explanation = 'Kernel state persists across shutdown, inflating uptime and delaying fixes that require a true restart.'
        $signals = [ordered]@{
            FastStartupEffective = $fastStartupEffective
            FastStartupConfigured = $fastStartupConfigured
            HibernateEnabled = $hibernateEnabled
            HiberfilePresent = $hiberfilePresent
        }

        $data = [ordered]@{
            BusinessImpact = 'Kernel state persists across shutdown, inflating uptime and delaying fixes that require a true restart.'
            Signals        = $signals
        }

        $data['Recommendations'] = @(
            'Disable Fast Startup so Shutdown performs a cold boot.',
            'Schedule a weekly Restart policy to refresh kernel state.',
            'Communicate to users: use Restart after driver/Windows updates.'
        )

        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title $title -Explanation $explanation -Evidence $evidenceArray -Subcategory 'Fast Startup' -Data $data
    } else {
        $title = 'Fast Startup is inactive, so shutdown performs a cold boot.'
        Add-CategoryNormal -CategoryResult $Result -Title $title -Evidence $evidenceArray -Subcategory 'Fast Startup'
    }
}

function Invoke-SystemLongUptime {
    param(
        $Context,
        $Result,
        $Summary
    )

    $nowUtc = (Get-Date).ToUniversalTime()
    $effectiveSeconds = $Summary.EffectiveUptimeSeconds
    $usedKernelFallback = $false

    if ($null -eq $effectiveSeconds -and $null -ne $Summary.KernelUptimeSeconds) {
        $effectiveSeconds = $Summary.KernelUptimeSeconds
        $usedKernelFallback = $true
    }

    if ($null -eq $effectiveSeconds) {
        Write-HeuristicDebug -Source 'System/Uptime' -Message 'Effective uptime seconds unavailable; skipping long-uptime heuristic.'
        return
    }

    if ($effectiveSeconds -lt 0) { $effectiveSeconds = 0 }

    $effectiveSinceUtc = $Summary.EffectiveSinceUtc
    if (-not $effectiveSinceUtc -and $Summary.LastBootUtc) {
        $effectiveSinceUtc = $Summary.LastBootUtc
    }

    $effectiveSinceIso = if ($Summary.EffectiveSinceRaw) { [string]$Summary.EffectiveSinceRaw } elseif ($effectiveSinceUtc) { $effectiveSinceUtc.ToString('o') } else { $null }

    $days = [double]$effectiveSeconds / 86400

    $identity = Get-MsinfoSystemIdentity -Context $Context
    $isServer = $false
    if ($identity -and $identity.PSObject.Properties['OSName'] -and $identity.OSName) {
        $isServer = ($identity.OSName -match '(?i)windows\s+server')
    }

    $thresholds = Resolve-UptimeThresholds -Context $Context -IsServer:$isServer
    $sortedThresholds = @($thresholds | Sort-Object)

    $lowThreshold = if ($sortedThresholds.Count -ge 1) { [double]$sortedThresholds[0] } else { $null }
    $mediumThreshold = if ($sortedThresholds.Count -ge 2) { [double]$sortedThresholds[1] } else { $null }
    $highThreshold = if ($sortedThresholds.Count -ge 3) { [double]$sortedThresholds[2] } else { $null }
    $criticalThreshold = if ($sortedThresholds.Count -ge 4) { [double]$sortedThresholds[3] } else { $null }

    $severity = 'info'
    $thresholdReached = $null

    if ($criticalThreshold -ne $null -and $days -ge $criticalThreshold) {
        $severity = 'critical'
        $thresholdReached = $criticalThreshold
    } elseif ($highThreshold -ne $null -and $days -ge $highThreshold) {
        $severity = 'high'
        $thresholdReached = $highThreshold
    } elseif ($mediumThreshold -ne $null -and $days -ge $mediumThreshold) {
        $severity = 'medium'
        $thresholdReached = $mediumThreshold
    } elseif ($lowThreshold -ne $null -and $days -ge $lowThreshold) {
        $severity = 'low'
        $thresholdReached = $lowThreshold
    }

    $clockSkew = $false
    if ($effectiveSinceUtc -and $effectiveSinceUtc -gt $nowUtc) {
        $clockSkew = $true
        $severity = 'info'
    }

    $humanUptime = ConvertTo-UptimeHumanizedTime -Seconds $effectiveSeconds

    $evidenceLines = New-Object System.Collections.Generic.List[string]
    $evidenceLines.Add("EffectiveSince (UTC): {0}" -f $(if ($effectiveSinceIso) { $effectiveSinceIso } else { 'Unknown' })) | Out-Null
    $evidenceLines.Add("EffectiveUptime: {0}" -f $(if ($humanUptime) { $humanUptime } else { 'Unknown' })) | Out-Null
    $evidenceLines.Add("EffectiveUptimeSeconds: {0}" -f $(if ($effectiveSeconds -ne $null) { $effectiveSeconds } else { 'Unknown' })) | Out-Null

    if ($usedKernelFallback) {
        $evidenceLines.Add('Effective uptime seconds missing; using kernel uptime seconds as a fallback.') | Out-Null
    }

    if ($clockSkew) {
        $evidenceLines.Add('EffectiveSince is later than the current time; system clock appears invalid.') | Out-Null
    }

    if ($null -ne $Summary.FastStartupEffective) {
        $evidenceLines.Add("FastStartupEffective: $(Format-UptimeBoolean $Summary.FastStartupEffective)") | Out-Null
    }

    $data = [ordered]@{
        EffectiveSinceUtc        = $effectiveSinceIso
        EffectiveUptimeSeconds   = $effectiveSeconds
        UsedKernelUptimeFallback = $usedKernelFallback
        ThresholdsDays           = $sortedThresholds
        FastStartupEffective     = $Summary.FastStartupEffective
        ClockSkewDetected        = $clockSkew
    }

    if ($thresholdReached -ne $null) {
        $data['TriggeredThresholdDays'] = $thresholdReached
    }

    $businessImpact = $null
    $recommendations = $null
    $explanation = $null

    switch ($severity) {
        'critical' {
            $businessImpact = 'Extended uptime keeps security patches and driver fixes from applying until a restart completes.'
            $recommendations = @(
                'Plan an immediate reboot to clear stale kernel state.',
                'Verify critical updates and services recover after the restart.',
                'Notify stakeholders about the downtime required to reboot.'
            )
            $explanation = "This device has been running for $humanUptime without a full reboot, so updates remain pending until it restarts."
        }
        'high' {
            $businessImpact = 'Long uptime increases the risk of instability and leaves updates pending until a restart occurs.'
            $recommendations = @(
                'Schedule a reboot in the current maintenance window.',
                'Confirm Windows Update and driver installs complete after restarting.',
                'Communicate the restart requirement to affected users.'
            )
            $explanation = "This device has been running for $humanUptime, so a restart is required to refresh kernel state."
        }
        'medium' {
            $businessImpact = 'Long-running sessions can accumulate memory leaks and stale drivers, so a restart is strongly recommended.'
            $recommendations = @(
                'Plan a restart during the next maintenance window.',
                'Check for pending updates that require a reboot.',
                'Monitor for instability until the restart is completed.'
            )
            $explanation = "This device has been running for $humanUptime, so schedule a restart soon to prevent stability issues."
        }
        'low' {
            $businessImpact = 'Uptime is trending long and may contribute to instability if issues appear.'
            $recommendations = @(
                'Restart the device if users report issues or as part of routine maintenance.',
                'Verify updates apply during the next restart window.'
            )
            $explanation = "This device has been running for $humanUptime; restart if you notice instability or pending updates."
        }
        Default {
            if ($clockSkew) {
                $businessImpact = 'System time appears incorrect, so uptime reporting cannot be trusted for troubleshooting.'
                $recommendations = @(
                    'Correct the system clock or synchronize time with a reliable source.',
                    'Re-run diagnostics after fixing the system time.'
                )
                $explanation = 'Effective uptime appears invalid because the reported restart time is in the future.'
            }
        }
    }

    if ($severity -eq 'info' -and -not $clockSkew) {
        Write-HeuristicDebug -Source 'System/Uptime' -Message 'Effective uptime within healthy range; recording normal if appropriate.'
        if ($effectiveSeconds -lt 86400) {
            Add-CategoryNormal -CategoryResult $Result -Title 'Recent reboot detected' -Evidence ("Effective uptime: {0}" -f $humanUptime) -Subcategory 'Uptime'
        }
        return
    }

    if ($clockSkew) {
        $severity = 'info'
    }

    $data['BusinessImpact'] = $businessImpact
    if ($recommendations) { $data['Recommendations'] = $recommendations }

    Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'Restart is required in all high/critical instances, medium is restart is strongly recommended, low is restart if you are experiencing issues' -Explanation $explanation -Evidence ($evidenceLines.ToArray()) -Subcategory 'Uptime' -Data $data
}

function Invoke-SystemUptimeChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Uptime' -Message 'Starting uptime checks'

    $uptimeArtifact = Get-AnalyzerArtifact -Context $Context -Name 'uptime'
    Write-HeuristicDebug -Source 'System/Uptime' -Message 'Resolved uptime artifact' -Data ([ordered]@{
        Found = [bool]$uptimeArtifact
    })
    if (-not $uptimeArtifact) { return }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $uptimeArtifact)
    Write-HeuristicDebug -Source 'System/Uptime' -Message 'Evaluating uptime payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload -or -not $payload.Uptime) { return }

    $summary = Get-UptimeSummaryFromPayload -Uptime $payload.Uptime
    if (-not $summary) { return }

    if ($summary.HasError) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to read uptime data, so reboot posture is unknown.' -Evidence $summary.Error -Subcategory 'Uptime' -Explanation 'Uptime diagnostics failed, so technicians must recollect data to confirm reboot history.'
        return
    }

    $effectiveSeconds = $summary.EffectiveUptimeSeconds
    if ($null -eq $effectiveSeconds -and $null -ne $summary.KernelUptimeSeconds) {
        $effectiveSeconds = $summary.KernelUptimeSeconds
    }

    if ($null -ne $effectiveSeconds) {
        $effectiveDays = [math]::Round(([double]$effectiveSeconds / 86400), 2)
        Add-CategoryCheck -CategoryResult $Result -Name 'Effective uptime (days)' -Status ([string]$effectiveDays)
    }

    if ($null -ne $summary.KernelUptimeSeconds) {
        $kernelDays = [math]::Round(([double]$summary.KernelUptimeSeconds / 86400), 2)
        Add-CategoryCheck -CategoryResult $Result -Name 'Kernel uptime (days)' -Status ([string]$kernelDays)
    }

    Invoke-SystemUptimeFastStartup -Result $Result -Summary $summary
    Invoke-SystemLongUptime -Context $Context -Result $Result -Summary $summary
}
