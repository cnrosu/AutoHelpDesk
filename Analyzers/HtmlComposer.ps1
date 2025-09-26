<#!
.SYNOPSIS
    Renders analyzer findings into an HTML report styled like the legacy AutoL1 output.
#>

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

function Resolve-CategoryGroup {
    param([string]$Name)

    if (-not $Name) { return 'General' }
    $trimmed = $Name.Trim()
    switch -regex ($trimmed) {
        '^(?i)services'          { return 'Services' }
        '^(?i)office'            { return 'Office' }
        '^(?i)network'           { return 'Network' }
        '^(?i)system'            { return 'System' }
        '^(?i)storage|hardware'  { return 'Hardware' }
        '^(?i)security'          { return 'Security' }
        '^(?i)active\s*directory' { return 'Active Directory' }
        '^(?i)printing'          { return 'Printing' }
        '^(?i)events'            { return 'Events' }
        default                  { return $trimmed }
    }
}

function Add-SubcategoryCandidate {
    param(
        [System.Collections.Generic.List[string]]$List,
        $Value,
        [string]$BaseCategory,
        [string]$OriginalCategory
    )

    if ($null -eq $Value) { return }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            Add-SubcategoryCandidate -List $List -Value $item -BaseCategory $BaseCategory -OriginalCategory $OriginalCategory
        }
        return
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return }

    $candidate = $text.Trim()
    if (-not $candidate) { return }

    $originalBase = $OriginalCategory
    if ($OriginalCategory -and $OriginalCategory.Contains('/')) {
        $parts = $OriginalCategory.Split('/', 2)
        if ($parts.Length -gt 0) { $originalBase = $parts[0].Trim() }
    }

    if ($candidate.Contains('/')) {
        $split = $candidate.Split('/', 2)
        $first = $split[0].Trim()
        $rest = if ($split.Length -gt 1) { $split[1].Trim() } else { '' }

        if ($rest -and (
                ($BaseCategory -and $first.Equals($BaseCategory, [System.StringComparison]::OrdinalIgnoreCase)) -or
                ($originalBase -and $first.Equals($originalBase, [System.StringComparison]::OrdinalIgnoreCase))
            )) {
            $candidate = $rest
        }
    }

    if ($candidate -and -not $candidate.Equals($BaseCategory, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not $List.Contains($candidate)) {
            $List.Add($candidate) | Out-Null
        }
    }
}

function Get-IssueAreaLabel {
    param(
        $Category,
        $Entry
    )

    $categoryName = if ($Category -and $Category.PSObject.Properties['Name']) { [string]$Category.Name } else { '' }
    $baseCategory = Resolve-CategoryGroup -Name $categoryName

    $subcategories = New-Object System.Collections.Generic.List[string]

    if ($Entry -and $Entry.PSObject.Properties['Subcategory']) {
        Add-SubcategoryCandidate -List $subcategories -Value $Entry.Subcategory -BaseCategory $baseCategory -OriginalCategory $categoryName
    }

    if ($Entry -and $Entry.PSObject.Properties['Area']) {
        Add-SubcategoryCandidate -List $subcategories -Value $Entry.Area -BaseCategory $baseCategory -OriginalCategory $categoryName
    }

    if ($categoryName -and $categoryName.Contains('/')) {
        $tail = $categoryName.Split('/', 2)[1].Trim()
        Add-SubcategoryCandidate -List $subcategories -Value $tail -BaseCategory $baseCategory -OriginalCategory $categoryName
    }

    if ($subcategories.Count -gt 0) {
        return ("{0}/{1}" -f $baseCategory, $subcategories[0])
    }

    return $baseCategory
}

function Format-AnalyzerEvidence {
    param($Value)

    if ($null -eq $Value) { return '' }

    if ($Value -is [string]) { return $Value }
    if ($Value -is [ValueType]) { return $Value.ToString() }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            $items += Format-AnalyzerEvidence -Value $item
        }
        return ($items -join [Environment]::NewLine)
    }

    try {
        return ($Value | ConvertTo-Json -Depth 6)
    } catch {
        return [string]$Value
    }
}

function Convert-ToIssueCard {
    param(
        $Category,
        $Issue
    )

    $severity = ConvertTo-NormalizedSeverity $Issue.Severity
    $detail = Format-AnalyzerEvidence -Value $Issue.Evidence
    $hasNewLines = $detail -match "\r|\n"

    return [pscustomobject]@{
        Severity    = $severity
        CssClass    = if ($severity) { $severity } else { 'info' }
        BadgeText   = if ($Issue.Severity) { ([string]$Issue.Severity).ToUpperInvariant() } else { 'ISSUE' }
        Area        = Get-IssueAreaLabel -Category $Category -Entry $Issue
        Message     = $Issue.Title
        Explanation = if ($hasNewLines) { $null } else { $detail }
        Evidence    = if ($hasNewLines) { $detail } else { $null }
    }
}

function Convert-ToGoodCard {
    param(
        $Category,
        $Normal
    )

    $detail = Format-AnalyzerEvidence -Value $Normal.Evidence

    return [pscustomobject]@{
        CssClass  = 'good'
        BadgeText = 'GOOD'
        Area      = Get-IssueAreaLabel -Category $Category -Entry $Normal
        Message   = $Normal.Title
        Evidence  = $detail
    }
}

function Get-CollectorDisplayName {
    param(
        [string]$ScriptPath,
        [string]$Fallback
    )

    if ($ScriptPath) {
        try {
            $name = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
        } catch {
            $name = $null
        }

        if ($name) {
            if ($name.StartsWith('Collect-', [System.StringComparison]::OrdinalIgnoreCase)) {
                $trimmed = $name.Substring('Collect-'.Length)
                if ($trimmed) { return $trimmed }
            }

            return $name
        }

        return $ScriptPath
    }

    if ($Fallback) { return $Fallback }

    return 'Unknown'
}

function Get-CollectorOutputCandidates {
    param($Output)

    $values = New-Object System.Collections.Generic.List[string]

    if ($null -eq $Output) { return $values }

    if ($Output -is [System.Collections.IEnumerable] -and -not ($Output -is [string])) {
        foreach ($item in $Output) {
            foreach ($value in Get-CollectorOutputCandidates -Output $item) {
                if ($value) { $values.Add($value) | Out-Null }
            }
        }

        return $values
    }

    $text = [string]$Output
    if ([string]::IsNullOrWhiteSpace($text)) { return $values }

    $trimmed = $text.Trim()
    if (-not $trimmed) { return $values }

    $values.Add($trimmed) | Out-Null
    return $values
}

function Get-FailedCollectorReports {
    param($Context)

    $failures = New-Object System.Collections.Generic.List[pscustomobject]

    if (-not $Context) { return $failures }

    $summaryArtifact = Get-AnalyzerArtifact -Context $Context -Name 'collection-summary'
    if ($summaryArtifact -and $summaryArtifact.Data -and $summaryArtifact.Data.PSObject.Properties['Results']) {
        $results = $summaryArtifact.Data.Results
        if (-not ($results -is [System.Collections.IEnumerable] -and -not ($results -is [string]))) {
            $results = @($results)
        }

        foreach ($result in $results) {
            if (-not $result) { continue }

            $scriptPath = if ($result.PSObject.Properties['Script']) { [string]$result.Script } else { $null }
            $output = if ($result.PSObject.Properties['Output']) { $result.Output } else { $null }
            $candidates = Get-CollectorOutputCandidates -Output $output
            $displayName = $null
            foreach ($candidate in $candidates) {
                if (-not $candidate) { continue }
                try {
                    $name = [System.IO.Path]::GetFileName($candidate)
                } catch {
                    $name = $null
                }
                if ($name) { $displayName = $name; break }
            }
            if (-not $displayName -and $candidates.Count -gt 0) { $displayName = $candidates[0] }
            if (-not $displayName) { $displayName = Get-CollectorDisplayName -ScriptPath $scriptPath -Fallback $null }

            $status = if ($result.PSObject.Properties['Success']) { [bool]$result.Success } else { $null }
            if ($status -eq $false) {
                $detail = if ($result.PSObject.Properties['Error'] -and $result.Error) { [string]$result.Error } else { 'Collector reported failure.' }
                $failures.Add([pscustomobject]@{
                        Key     = if ($displayName) { $displayName } else { 'Collector' }
                        Status  = 'Execution failed'
                        Details = $detail
                        Path    = $scriptPath
                    }) | Out-Null
                continue
            }

            if ($status -eq $true) {
                if ($null -eq $output -or ([string]::IsNullOrWhiteSpace([string]$output))) {
                    $failures.Add([pscustomobject]@{
                            Key     = if ($displayName) { $displayName } else { 'Collector' }
                            Status  = 'No output'
                            Details = 'Collector did not return a path or payload reference.'
                            Path    = $scriptPath
                        }) | Out-Null
                    continue
                }

                $resolvedAny = $false
                $missing = New-Object System.Collections.Generic.List[string]

                foreach ($candidate in $candidates) {
                    if (-not $candidate) { continue }

                    try {
                        if (Test-Path -LiteralPath $candidate) {
                            $resolvedAny = $true
                            continue
                        }
                    } catch {
                    }

                    $missing.Add($candidate) | Out-Null
                }

                if (-not $resolvedAny -and $missing.Count -gt 0) {
                    $detailText = "Expected file not found: {0}" -f ($missing -join ', ')
                    $failures.Add([pscustomobject]@{
                            Key     = if ($displayName) { $displayName } else { 'Collector' }
                            Status  = 'Output missing'
                            Details = $detailText
                            Path    = $scriptPath
                        }) | Out-Null
                }
            }
        }
    }

    if ($Context.Artifacts) {
        foreach ($key in $Context.Artifacts.Keys) {
            if (-not $Context.Artifacts[$key]) { continue }

            $entries = $Context.Artifacts[$key]
            if (-not ($entries -is [System.Collections.IEnumerable] -and -not ($entries -is [string]))) {
                $entries = @($entries)
            }

            foreach ($entry in $entries) {
                if (-not $entry) { continue }
                $path = if ($entry.PSObject.Properties['Path']) { [string]$entry.Path } else { $null }
                $data = if ($entry.PSObject.Properties['Data']) { $entry.Data } else { $null }

                if ($data -and $data.PSObject.Properties['Error'] -and $data.Error) {
                    $failures.Add([pscustomobject]@{
                            Key     = if ($path) { [System.IO.Path]::GetFileName($path) } else { $key }
                            Status  = 'Parse error'
                            Details = [string]$data.Error
                            Path    = $path
                        }) | Out-Null
                    continue
                }

                if ($data -and $data.PSObject.Properties['Payload']) {
                    $payload = $data.Payload
                    $isEmpty = $false

                    if ($null -eq $payload) {
                        $isEmpty = $true
                    } elseif ($payload -is [string]) {
                        if ([string]::IsNullOrWhiteSpace($payload)) { $isEmpty = $true }
                    } elseif ($payload -is [System.Collections.IEnumerable] -and -not ($payload -is [string])) {
                        $enumerated = @()
                        foreach ($item in $payload) { $enumerated += $item }
                        if ($enumerated.Count -eq 0) { $isEmpty = $true }
                    }

                    if ($isEmpty) {
                        $failures.Add([pscustomobject]@{
                                Key     = if ($path) { [System.IO.Path]::GetFileName($path) } else { $key }
                                Status  = 'Empty output'
                                Details = 'Captured file contained no payload.'
                                Path    = $path
                            }) | Out-Null
                    }
                }
            }
        }
    }

    return $failures
}

function Build-SummaryCardHtml {
    param(
        [pscustomobject]$Summary,
        [System.Collections.Generic.List[pscustomobject]]$Issues
    )

    $generatedAt = if ($Summary.GeneratedAt) { [datetime]$Summary.GeneratedAt } else { Get-Date }
    $generatedAtHtml = Encode-Html ($generatedAt.ToString("dddd, MMMM d, yyyy 'at' h:mm tt"))

    $counts = @{}
    foreach ($key in @('critical','high','medium','low','warning','info')) { $counts[$key] = 0 }
    foreach ($issue in $Issues) {
        $key = if ($issue.Severity) { $issue.Severity } else { 'info' }
        if (-not $counts.ContainsKey($key)) { $counts[$key] = 0 }
        $counts[$key]++
    }

    $weights = @{ critical = 10; high = 6; medium = 3; warning = 2; low = 1; info = 0 }
    $penalty = 0
    foreach ($issue in $Issues) {
        $sev = if ($issue.Severity) { $issue.Severity } else { 'info' }
        if ($weights.ContainsKey($sev)) { $penalty += $weights[$sev] }
    }
    $score = [Math]::Max(0, 100 - [Math]::Min($penalty, 80))

    $deviceName = if ($Summary.DeviceName) { $Summary.DeviceName } else { 'Unknown' }
    $deviceState = if ($Summary.DeviceState) { $Summary.DeviceState } else { 'Unknown' }

    $osParts = @()
    if ($Summary.OperatingSystem) { $osParts += $Summary.OperatingSystem }
    if ($Summary.OSVersion) { $osParts += $Summary.OSVersion }
    if ($Summary.OSBuild) { $osParts += "Build $($Summary.OSBuild)" }    $osText = if ($osParts.Count -gt 0) { ($osParts -join ' | ') } else { 'Unknown' }

    $serverText = if ($Summary.IsWindowsServer -eq $true) { 'Yes' } elseif ($Summary.IsWindowsServer -eq $false) { 'No' } else { 'Unknown' }

    $ipv4Text = if ($Summary.IPv4Addresses -and $Summary.IPv4Addresses.Count -gt 0) { ($Summary.IPv4Addresses -join ', ') } else { 'Unknown' }
    $gatewayText = if ($Summary.Gateways -and $Summary.Gateways.Count -gt 0) { ($Summary.Gateways -join ', ') } else { 'Unknown' }
    $dnsText = if ($Summary.DnsServers -and $Summary.DnsServers.Count -gt 0) { ($Summary.DnsServers -join ', ') } else { 'Unknown' }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<h1>Device Health Report</h1>')
    $null = $sb.AppendLine("<h2 class='report-subtitle'>Generated $generatedAtHtml</h2>")
    $null = $sb.AppendLine("<div class='report-card'>")
    $null = $sb.AppendLine("  <div class='report-badge-group'>")
    $null = $sb.AppendLine("    <span class='report-badge report-badge--score'><span class='report-badge__label'>SCORE</span><span class='report-badge__value'>$score</span><span class='report-badge__suffix'>/100</span></span>")
    foreach ($badge in @(
            @{ Key = 'critical'; Label = 'CRITICAL'; Class = 'critical' },
            @{ Key = 'high';     Label = 'HIGH';     Class = 'bad' },
            @{ Key = 'medium';   Label = 'MEDIUM';   Class = 'medium' },
            @{ Key = 'low';      Label = 'LOW';      Class = 'ok' },
            @{ Key = 'warning';  Label = 'WARNING';  Class = 'warning' },
            @{ Key = 'info';     Label = 'INFO';     Class = 'info' }
        )) {
        $count = if ($counts.ContainsKey($badge.Key)) { $counts[$badge.Key] } else { 0 }
        $labelHtml = Encode-Html $badge.Label
        $null = $sb.AppendLine("    <span class='report-badge report-badge--$($badge.Class)'><span class='report-badge__label'>$labelHtml</span><span class='report-badge__value'>$count</span></span>")
    }
    $null = $sb.AppendLine('  </div>')

    $null = $sb.AppendLine("  <table class='report-table report-table--key-value' cellspacing='0' cellpadding='0'>")
    $null = $sb.AppendLine("    <tr><td>Device Name</td><td>$(Encode-Html $deviceName)</td></tr>")
    $null = $sb.AppendLine("    <tr><td>Device State</td><td>$(Encode-Html $deviceState)</td></tr>")
    $null = $sb.AppendLine("    <tr><td>System</td><td>$(Encode-Html $osText)</td></tr>")
    $null = $sb.AppendLine("    <tr><td>Windows Server</td><td>$(Encode-Html $serverText)</td></tr>")
    $null = $sb.AppendLine("    <tr><td>IPv4</td><td>$(Encode-Html $ipv4Text)</td></tr>")
    $null = $sb.AppendLine("    <tr><td>Gateway</td><td>$(Encode-Html $gatewayText)</td></tr>")
    $null = $sb.AppendLine("    <tr><td>DNS</td><td>$(Encode-Html $dnsText)</td></tr>")
    $null = $sb.AppendLine('  </table>')
    $null = $sb.AppendLine("  <small class='report-note'>Score is heuristic. Triage Critical/High items first.</small>")
    $null = $sb.AppendLine('</div>')

    return $sb.ToString()
}

function Build-GoodSection {
    param(
        [System.Collections.Generic.List[pscustomobject]]$Normals
    )

    if ($Normals.Count -eq 0) {
        return "<div class='report-card'><i>No specific positives recorded.</i></div>"
    }

    $categoryOrder = @('Services','Office','Network','System','Hardware','Security','Active Directory','Printing','Events')
    $categorized = [ordered]@{}
    foreach ($category in $categoryOrder) {
        $categorized[$category] = New-Object System.Collections.Generic.List[string]
    }

    foreach ($entry in $Normals) {
        $category = Resolve-CategoryGroup -Name $entry.Area
        if (-not $categorized.ContainsKey($category)) {
            $categorized[$category] = New-Object System.Collections.Generic.List[string]
        }
        $categorized[$category].Add((New-GoodCardHtml -Entry $entry))
    }

    $orderedCategories = New-Object System.Collections.Generic.List[string]
    foreach ($category in $categoryOrder) {
        $null = $orderedCategories.Add($category)
    }
    foreach ($category in $categorized.Keys) {
        if (-not $orderedCategories.Contains($category)) {
            $null = $orderedCategories.Add($category)
        }
    }

    $firstNonEmpty = $null
    foreach ($category in $orderedCategories) {
        if ($categorized.ContainsKey($category) -and $categorized[$category].Count -gt 0) {
            $firstNonEmpty = $category
            break
        }
    }
    if (-not $firstNonEmpty) {
        return "<div class='report-card'><i>No positives captured in any category.</i></div>"
    }

    $tabName = 'good-tabs'
    $tabsBuilder = [System.Text.StringBuilder]::new()
    $null = $tabsBuilder.Append("<div class='report-tabs'><div class='report-tabs__list'>")
    $index = 0
    foreach ($category in $orderedCategories) {
        if (-not $categorized.ContainsKey($category)) { continue }
        $cards = $categorized[$category]
        $count = $cards.Count
        if ($count -eq 0) { continue }
        $slug = [regex]::Replace($category.ToLowerInvariant(), '[^a-z0-9]+', '-')
        $slug = [regex]::Replace($slug, '^-+|-+$', '')
        if (-not $slug) { $slug = "cat$index" }
        $tabId = "$tabName-$slug"
        $checkedAttr = if ($category -eq $firstNonEmpty) { " checked='checked'" } else { '' }
        $labelText = Encode-Html "$category ($count)"
        $panelContent = if ($count -gt 0) { ($cards -join '') } else { "<div class='report-card'><i>No positives captured in this category.</i></div>" }

        $null = $tabsBuilder.Append("<input type='radio' name='$tabName' id='$tabId' class='report-tabs__radio'$checkedAttr>")
        $null = $tabsBuilder.Append("<label class='report-tabs__label' for='$tabId'>$labelText</label>")
        $null = $tabsBuilder.Append("<div class='report-tabs__panel'>$panelContent</div>")
        $index++
    }

    $null = $tabsBuilder.Append("</div></div>")
    return $tabsBuilder.ToString()
}

function Build-IssueSection {
    param(
        [System.Collections.Generic.List[pscustomobject]]$Issues
    )

    if ($Issues.Count -eq 0) {
        return "<div class='report-card report-card--good'><span class='report-badge report-badge--good'>GOOD</span> No obvious issues detected from the provided outputs.</div>"
    }

    $severityDefinitions = @(
        @{ Key = 'critical'; Label = 'Critical'; BadgeClass = 'critical' },
        @{ Key = 'high';     Label = 'High';     BadgeClass = 'high' },
        @{ Key = 'medium';   Label = 'Medium';   BadgeClass = 'medium' },
        @{ Key = 'low';      Label = 'Low';      BadgeClass = 'low' },
        @{ Key = 'warning';  Label = 'Warning';  BadgeClass = 'warning' },
        @{ Key = 'info';     Label = 'Info';     BadgeClass = 'info' }
    )

    $severityOrder = @{ critical = 0; high = 1; medium = 2; low = 3; warning = 4; info = 5 }
    $sorted = $Issues | Sort-Object -Stable -Property @(
        @{ Expression = { if ($severityOrder.ContainsKey($_.Severity)) { $severityOrder[$_.Severity] } else { [int]::MaxValue } } },
        @{ Expression = { $_.Area } },
        @{ Expression = { $_.Message } }
    )

    $grouped = [ordered]@{}
    foreach ($definition in $severityDefinitions) {
        $grouped[$definition.Key] = New-Object System.Collections.Generic.List[string]
    }
    $other = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $sorted) {
        $card = New-IssueCardHtml -Entry $entry
        $key = if ($entry.Severity) { $entry.Severity } else { 'info' }
        if ($grouped.ContainsKey($key)) {
            $grouped[$key].Add($card)
        } else {
            $other.Add($card)
        }
    }

    $activeDefinitions = @()
    foreach ($definition in $severityDefinitions) {
        if ($grouped[$definition.Key].Count -gt 0) { $activeDefinitions += ,$definition }
    }
    if ($other.Count -gt 0) {
        $grouped['other'] = $other
        $activeDefinitions += ,@{ Key = 'other'; Label = 'Other'; BadgeClass = 'info' }
    }

    if ($activeDefinitions.Count -eq 0) {
        return ($sorted | ForEach-Object { New-IssueCardHtml -Entry $_ }) -join ''
    }

    $tabName = 'issue-tabs'
    $tabsBuilder = [System.Text.StringBuilder]::new()
    $null = $tabsBuilder.Append("<div class='report-tabs'><div class='report-tabs__list'>")
    $firstDefinition = $activeDefinitions[0]
    $firstKey = if ($firstDefinition.Key) { [string]$firstDefinition.Key } else { '' }
    $index = 0

    foreach ($definition in $activeDefinitions) {
        $keyValue = if ($definition.Key) { [string]$definition.Key } else { "severity$index" }
        if (-not $grouped.ContainsKey($keyValue)) { continue }
        $cards = $grouped[$keyValue]
        $count = $cards.Count
        $slug = [regex]::Replace($keyValue.ToLowerInvariant(), '[^a-z0-9]+', '-')
        $slug = [regex]::Replace($slug, '^-+|-+$', '')
        if (-not $slug) { $slug = "severity$index" }

        $tabId = "$tabName-$slug"
        $checkedAttr = if ($keyValue.ToLowerInvariant() -eq $firstKey.ToLowerInvariant()) { " checked='checked'" } else { '' }

        $labelText = if ($definition.Label) { [string]$definition.Label } else { $keyValue }
        $badgeLabel = Encode-Html ($labelText.ToUpperInvariant())
        $countLabel = Encode-Html "($count)"
        $labelInner = "<span class='report-badge report-badge--$($definition.BadgeClass) report-tabs__label-badge'>$badgeLabel</span><span class='report-tabs__label-count'>$countLabel</span>"
        $panelContent = if ($count -gt 0) { ($cards -join '') } else { "<div class='report-card'><i>No issues captured for this severity.</i></div>" }

        $null = $tabsBuilder.Append("<input type='radio' name='$tabName' id='$tabId' class='report-tabs__radio'$checkedAttr>")
        $null = $tabsBuilder.Append("<label class='report-tabs__label' for='$tabId'>$labelInner</label>")
        $null = $tabsBuilder.Append("<div class='report-tabs__panel'>$panelContent</div>")
        $index++
    }

    $null = $tabsBuilder.Append("</div></div>")
    return $tabsBuilder.ToString()
}

function Get-TruncatedText {
    param(
        [string]$Text,
        [int]$MaxLines,
        [int]$MaxChars
    )

    if ($null -eq $Text) {
        return [pscustomobject]@{ Text = ''; WasTruncated = $false }
    }

    $normalized = $Text -replace "`r`n", "`n"
    $normalized = $normalized -replace "`r", "`n"
    $wasTruncated = $false

    if ($MaxLines -gt 0) {
        $lines = $normalized -split "`n"
        if ($lines.Length -gt $MaxLines) {
            $normalized = ($lines[0..($MaxLines - 1)] -join [Environment]::NewLine)
            $wasTruncated = $true
        }
    }

    if ($MaxChars -gt 0 -and $normalized.Length -gt $MaxChars) {
        $normalized = $normalized.Substring(0, $MaxChars)
        $wasTruncated = $true
    }

    if ($wasTruncated) {
        $normalized = $normalized.TrimEnd() + [Environment]::NewLine + '... (truncated)'
    }

    return [pscustomobject]@{
        Text         = $normalized
        WasTruncated = $wasTruncated
    }
}

function ConvertTo-RawCard {
    param(
        [string]$Key,
        $Entry,
        [int]$MaxLines,
        [int]$MaxChars
    )

    $path = $null
    $data = $null

    if ($Entry -and $Entry.PSObject.Properties['Path']) {
        $path = [string]$Entry.Path
    }

    if ($Entry -and $Entry.PSObject.Properties['Data']) {
        $data = $Entry.Data
    }

    $collectedAt = $null
    if ($data -and $data.PSObject.Properties['CollectedAt']) {
        $collectedAt = [string]$data.CollectedAt
        if ($collectedAt) {
            try {
                $parsed = [datetime]$collectedAt
                $collectedAt = $parsed.ToUniversalTime().ToString('u')
            } catch {
                $collectedAt = [string]$collectedAt
            }
        }
    }

    $payload = $null
    if ($data -and $data.PSObject.Properties['Payload']) {
        $payload = $data.Payload
    } elseif ($data) {
        $payload = $data
    } elseif ($Entry -and $Entry.PSObject.Properties['Payload']) {
        $payload = $Entry.Payload
    }

    $evidence = Format-AnalyzerEvidence -Value $payload
    if (-not $evidence) {
        if ($data -and $data.PSObject.Properties['Error'] -and $data.Error) {
            $evidence = "Error: $($data.Error)"
        } else {
            $evidence = '(no payload data)'
        }
    }

    $trimmedResult = Get-TruncatedText -Text ([string]$evidence).TrimEnd() -MaxLines $MaxLines -MaxChars $MaxChars
    $metaParts = @()
    if ($collectedAt) { $metaParts += "Collected: $collectedAt" }
    if ($path) { $metaParts += "File: $path" }

    $metaHtml = ''
    if ($metaParts.Count -gt 0) {
        $metaHtml = "<div><small class='report-note'>$(Encode-Html ($metaParts -join ' • '))</small></div>"
    }

    return "<div class='report-card'><b>$(Encode-Html $Key)</b>$metaHtml<pre class='report-pre'>$(Encode-Html $($trimmedResult.Text))</pre></div>"
}

function Build-DebugSection {
    param($Context)

    if (-not $Context -or -not $Context.Artifacts) {
        return "<div class='report-card'><i>No debug metadata available.</i></div>"
    }

    $lines = @()
    foreach ($key in ($Context.Artifacts.Keys | Sort-Object)) {
        $entries = $Context.Artifacts[$key]
        if (-not $entries) {
            $lines += "${key}: (no entries)"
            continue
        }

        if ($entries -is [System.Collections.IEnumerable] -and -not ($entries -is [string])) {
            $count = $entries.Count
            $firstPath = $entries[0].Path
            $lines += "${key}: $count file(s); first = $firstPath"
        } else {
            $lines += "${key}: $($entries.Path)"
        }
    }

    if ($lines.Count -eq 0) {
        return "<div class='report-card'><i>No debug metadata available.</i></div>"
    }

    return "<div class='report-card'><b>Artifacts discovered</b><pre class='report-pre'>$(Encode-Html ($lines -join [Environment]::NewLine))</pre></div>"
}

function Build-RawSection {
    param(
        $Context,
        [int]$MaxArtifacts = 10,
        [int]$MaxLines = 40,
        [int]$MaxChars = 2000
    )

    if (-not $Context -or -not $Context.Artifacts -or $Context.Artifacts.Count -eq 0) {
        return "<div class='report-card'><i>No raw payloads available.</i></div>"
    }

    $items = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($key in ($Context.Artifacts.Keys | Sort-Object)) {
        $entries = $Context.Artifacts[$key]
        if (-not $entries) { continue }

        if ($entries -is [System.Collections.IEnumerable] -and -not ($entries -is [string])) {
            foreach ($entry in $entries) {
                if ($entry) {
                    $items.Add([pscustomobject]@{ Key = $key; Entry = $entry }) | Out-Null
                }
            }
        } else {
            $items.Add([pscustomobject]@{ Key = $key; Entry = $entries }) | Out-Null
        }
    }

    if ($items.Count -eq 0) {
        return "<div class='report-card'><i>No raw payloads available.</i></div>"
    }

    $cards = New-Object System.Collections.Generic.List[string]
    $cards.Add("<div class='report-card'><i>Showing up to $MaxArtifacts artifact(s); each excerpt is limited to $MaxLines lines or $MaxChars characters.</i></div>") | Out-Null

    $processed = 0
    foreach ($item in $items) {
        if ($processed -ge $MaxArtifacts) { break }
        $card = ConvertTo-RawCard -Key $item.Key -Entry $item.Entry -MaxLines $MaxLines -MaxChars $MaxChars
        if ($card) {
            $cards.Add($card) | Out-Null
            $processed++
        }
    }

    if ($processed -eq 0) {
        return "<div class='report-card'><i>No raw payload excerpts available.</i></div>"
    }

    if ($items.Count -gt $processed) {
        $remaining = $items.Count - $processed
        $cards.Add("<div class='report-card'><i>$remaining additional artifact(s) available in the collector output folder.</i></div>") | Out-Null
    }

    return ($cards -join '')
}

function New-AnalyzerHtml {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.IEnumerable[object]]$Categories,

        [Parameter()]
        [pscustomobject]$Summary,

        [Parameter()]
        $Context
    )

    $issues = New-Object System.Collections.Generic.List[pscustomobject]
    $normals = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($category in $Categories) {
        if (-not $category) { continue }
        foreach ($issue in $category.Issues) { $issues.Add((Convert-ToIssueCard -Category $category -Issue $issue)) | Out-Null }
        foreach ($normal in $category.Normals) { $normals.Add((Convert-ToGoodCard -Category $category -Normal $normal)) | Out-Null }
    }

    if (-not $Summary) {
        $Summary = [pscustomobject]@{ GeneratedAt = Get-Date }
    }

    $head = '<!doctype html><html><head><meta charset="utf-8"><title>Device Health Report</title><link rel="stylesheet" href="styles/device-health-report.css"></head><body class="page report-page">'
    $summaryHtml = Build-SummaryCardHtml -Summary $Summary -Issues $issues
    $goodHtml = New-ReportSection -Title "What Looks Good ($($normals.Count))" -ContentHtml (Build-GoodSection -Normals $normals) -Open
    $issuesHtml = New-ReportSection -Title "Detected Issues ($($issues.Count))" -ContentHtml (Build-IssueSection -Issues $issues) -Open
    $failedReports = Get-FailedCollectorReports -Context $Context
    $failedTitle = "Failed Reports ({0})" -f $failedReports.Count
    if ($failedReports.Count -eq 0) {
        $failedContent = "<div class='report-card'><i>All expected inputs produced output.</i></div>"
    } else {
        $failedContentBuilder = [System.Text.StringBuilder]::new()
        $null = $failedContentBuilder.Append("<div class='report-card'><table class='report-table report-table--list' cellspacing='0' cellpadding='0'><tr><th>Key</th><th>Status</th><th>Details</th></tr>")
        foreach ($entry in $failedReports) {
            $detailParts = @()
            if ($entry.Path) { $detailParts += "File: $($entry.Path)" }
            if ($entry.Details) { $detailParts += $entry.Details }
            $detailHtml = if ($detailParts.Count -gt 0) { ($detailParts | ForEach-Object { Encode-Html $_ }) -join '<br>' } else { Encode-Html '' }
            $null = $failedContentBuilder.Append("<tr><td>$(Encode-Html $($entry.Key))</td><td>$(Encode-Html $($entry.Status))</td><td>$detailHtml</td></tr>")
        }
        $null = $failedContentBuilder.Append("</table></div>")
        $failedContent = $failedContentBuilder.ToString()
    }
    $failedHtml = New-ReportSection -Title $failedTitle -ContentHtml $failedContent -Open
    $rawHtml = New-ReportSection -Title 'Raw (key excerpts)' -ContentHtml (Build-RawSection -Context $Context)
    $debugHtml = "<details><summary>Debug</summary>$(Build-DebugSection -Context $Context)</details>"
    $tail = '</body></html>'

    return ($head + $summaryHtml + $goodHtml + $issuesHtml + $failedHtml + $rawHtml + $debugHtml + $tail)
}
