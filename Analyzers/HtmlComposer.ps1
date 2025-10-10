<#!
.SYNOPSIS
    Renders analyzer findings into an HTML report styled like the legacy AutoL1 output.
#>

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

function Write-HtmlDebug {
    param(
        [Parameter(Mandatory)]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data
    )

    $formatted = "HTML [{0}] {1}" -f $Stage, $Message

    if ($PSBoundParameters.ContainsKey('Data') -and $Data) {
        $detailEntries = $Data.GetEnumerator() | Sort-Object Name
        $details = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $detailEntries) {
            if ($entry -is [System.Collections.DictionaryEntry]) {
                $null = $details.Add(("{0}={1}" -f $entry.Key, $entry.Value))
            } elseif ($entry.PSObject.Properties['Name']) {
                $null = $details.Add(("{0}={1}" -f $entry.Name, $entry.Value))
            }
        }

        if ($details.Count -gt 0) {
            $formatted = "{0} :: {1}" -f $formatted, ($details -join '; ')
        }
    }

    Write-Verbose $formatted
}

function Get-SourceLogData {
    param($Source)

    $data = @{}
    if (-not $Source) { return $data }

    if ($Source.PSObject.Properties['Script'] -and $Source.Script) { $data['SourceScript'] = [string]$Source.Script }
    if ($Source.PSObject.Properties['Function'] -and $Source.Function) { $data['SourceFunction'] = [string]$Source.Function }
    if ($Source.PSObject.Properties['Command'] -and $Source.Command) { $data['SourceCommand'] = [string]$Source.Command }
    if ($Source.PSObject.Properties['Line'] -and ($null -ne $Source.Line)) { $data['SourceLine'] = [string]$Source.Line }

    return $data
}

function Resolve-CategoryGroup {
    param([string]$Name)

    if (-not $Name) { return 'General' }
    $trimmed = $Name.Trim()
    switch -regex ($trimmed) {
        '^(?i)services'          { return 'Services' }
        '^(?i)office'            { return 'Office' }
        '^(?i)network'           { return 'Network' }
        '^(?i)dhcp'              { return 'Network' }
        '^(?i)system'            { return 'System' }
        '^(?i)storage|hardware'  { return 'Hardware' }
        '^(?i)security'          { return 'Security' }
        '^(?i)active\s*directory' { return 'Active Directory' }
        '^(?i)printing'          { return 'Printing' }
        '^(?i)events'            { return 'Events' }
        default                  { return $trimmed }
    }
}

function Get-BaseCategoryFromArea {
    param([string]$Area)

    if ([string]::IsNullOrWhiteSpace($Area)) { return 'General' }

    $trimmed = $Area.Trim()
    $candidate = $trimmed
    if ($trimmed.Contains('/')) {
        $candidate = $trimmed.Split('/', 2)[0].Trim()
        if (-not $candidate) { $candidate = $trimmed }
    }

    $resolved = Resolve-CategoryGroup -Name $candidate
    if ([string]::IsNullOrWhiteSpace($resolved)) { return 'General' }

    return $resolved
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
    [CmdletBinding()]
    param(
        $Value,
        [int]$MaxDepth = 4,
        [int]$Depth = 0
    )

    if ($null -eq $Value) { return '' }
    if ($Depth -ge $MaxDepth) { return ($Value -as [string]) }

    switch ($Value) {
        { $_ -is [string] }    { return $_ }
        { $_ -is [ValueType] } { return $_.ToString() }
        { $_ -is [System.Collections.IDictionary] } {
            $parts = New-Object System.Collections.Generic.List[string]
            foreach ($k in $_.Keys) {
                $v = $_[$k]
                $parts.Add(('{0}={1}' -f [string]$k, (Format-AnalyzerEvidence -Value $v -MaxDepth $MaxDepth -Depth ($Depth+1))))
            }
            return ($parts -join [Environment]::NewLine)
        }
        { $_ -is [System.Collections.IEnumerable] -and -not ($_ -is [string]) } {
            $parts = New-Object System.Collections.Generic.List[string]
            foreach ($item in $_) {
                $parts.Add((Format-AnalyzerEvidence -Value $item -MaxDepth $MaxDepth -Depth ($Depth+1)))
            }
            return ($parts -join [Environment]::NewLine)
        }
        default {
            try {
                return ($Value | ConvertTo-Json -Depth 2)
            } catch {
                return [string]$Value
            }
        }
    }
}

function Get-IssueCardContent {
    param($Issue)

    $evidence = $null
    $remediation = $null
    $remediationScript = $null

    if ($Issue -and $Issue.PSObject.Properties['Evidence']) {
        $evidence = $Issue.Evidence
    }

    if ($Issue -and $Issue.PSObject.Properties['Remediation']) {
        $candidate = [string]$Issue.Remediation
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $remediation = $candidate.Trim()
        }
    }

    if ($Issue -and $Issue.PSObject.Properties['RemediationScript']) {
        $candidateScript = [string]$Issue.RemediationScript
        if (-not [string]::IsNullOrWhiteSpace($candidateScript)) {
            $remediationScript = $candidateScript
        }
    }

    if ($evidence -is [System.Collections.IDictionary]) {
        $normalized = [System.Collections.Specialized.OrderedDictionary]::new()
        foreach ($key in $evidence.Keys) {
            $value = $evidence[$key]
            if (-not $remediation -and $key -match '^(?i)remediation(text)?$') {
                $remediation = [string]$value
                continue
            }
            if (-not $remediationScript -and $key -match '^(?i)(remediationscript|remediationcode|powershell(script)?|script)$') {
                $remediationScript = [string]$value
                continue
            }

            $normalized[$key] = $value
        }

        $evidence = $normalized
    } elseif ($evidence -and -not ($evidence -is [string]) -and -not ($evidence -is [ValueType]) -and $evidence.PSObject -and
        $evidence.PSObject.Properties.Count -gt 0) {
        $normalized = [System.Collections.Specialized.OrderedDictionary]::new()
        foreach ($property in $evidence.PSObject.Properties) {
            if (-not $property) { continue }
            $name = $property.Name
            $value = $property.Value
            if (-not $remediation -and $name -match '^(?i)remediation(text)?$') {
                $remediation = [string]$value
                continue
            }
            if (-not $remediationScript -and $name -match '^(?i)(remediationscript|remediationcode|powershell(script)?|script)$') {
                $remediationScript = [string]$value
                continue
            }

            $normalized[$name] = $value
        }

        $evidence = $normalized
    }

    [pscustomobject]@{
        Evidence          = $evidence
        Remediation       = $remediation
        RemediationScript = $remediationScript
    }
}

function Convert-ToIssueCard {
    param(
        $Category,
        $Issue
    )

    if (-not $Issue) {
        Write-HtmlDebug -Stage 'Composer.IssueCard' -Message 'Issue conversion skipped because entry was null.' -Data @{ Category = if ($Category -and $Category.PSObject.Properties['Name']) { [string]$Category.Name } else { '(unknown)' } }
        return $null
    }

    $issueTitle = if ($Issue.PSObject.Properties['Title']) { [string]$Issue.Title } else { '(no title)' }
    $issueSeverity = if ($Issue.PSObject.Properties['Severity']) { [string]$Issue.Severity } else { '(none)' }
    $issueSource = if ($Issue.PSObject.Properties['Source']) { $Issue.Source } else { $null }
    $issueSourceData = Get-SourceLogData -Source $issueSource
    $convertData = @{ Title = $issueTitle; Severity = $issueSeverity }
    foreach ($key in $issueSourceData.Keys) {
        $convertData[$key] = $issueSourceData[$key]
    }
    Write-HtmlDebug -Stage 'Composer.IssueCard' -Message 'Converting issue entry to card.' -Data $convertData

    $content = Get-IssueCardContent -Issue $Issue
    $severity = ConvertTo-NormalizedSeverity $Issue.Severity
    $detail = Format-AnalyzerEvidence -Value $content.Evidence
    if ($null -ne $detail) { $detail = [string]$detail } else { $detail = '' }
    $hasEvidence = -not [string]::IsNullOrWhiteSpace($detail)

    $explanation = $null
    if ($Issue -and $Issue.PSObject.Properties['Explanation']) {
        $explanationCandidate = [string]$Issue.Explanation
        if (-not [string]::IsNullOrWhiteSpace($explanationCandidate)) {
            $explanation = $explanationCandidate.Trim()
        }
    }

    $card = [pscustomobject]@{
        Severity    = $severity
        CssClass    = if ($severity) { $severity } else { 'info' }
        BadgeText   = if ($Issue.Severity) { ([string]$Issue.Severity).ToUpperInvariant() } else { 'ISSUE' }
        Area        = Get-IssueAreaLabel -Category $Category -Entry $Issue
        Message     = $Issue.Title
        Explanation = $explanation
        Evidence    = if ($hasEvidence) { $detail } else { $null }
        Remediation = $content.Remediation
        RemediationScript = $content.RemediationScript
        Source     = $issueSource
    }

    $generatedData = @{ Title = $card.Message; Severity = $card.Severity; HasEvidence = [bool]$card.Evidence; HasRemediation = [bool]$card.Remediation; HasRemediationScript = [bool]$card.RemediationScript }
    foreach ($key in $issueSourceData.Keys) {
        $generatedData[$key] = $issueSourceData[$key]
    }
    Write-HtmlDebug -Stage 'Composer.IssueCard' -Message 'Issue card generated.' -Data $generatedData
    return $card
}

function Convert-ToGoodCard {
    param(
        $Category,
        $Normal
    )

    if (-not $Normal) {
        Write-HtmlDebug -Stage 'Composer.GoodCard' -Message 'Positive finding conversion skipped because entry was null.' -Data @{ Category = if ($Category -and $Category.PSObject.Properties['Name']) { [string]$Category.Name } else { '(unknown)' } }
        return $null
    }

    $normalTitle = if ($Normal.PSObject.Properties['Title']) { [string]$Normal.Title } else { '(no title)' }
    $normalSource = if ($Normal.PSObject.Properties['Source']) { $Normal.Source } else { $null }
    $normalSourceData = Get-SourceLogData -Source $normalSource
    $goodConvertData = @{ Title = $normalTitle }
    foreach ($key in $normalSourceData.Keys) {
        $goodConvertData[$key] = $normalSourceData[$key]
    }
    Write-HtmlDebug -Stage 'Composer.GoodCard' -Message 'Converting positive finding entry to card.' -Data $goodConvertData

    $detail = Format-AnalyzerEvidence -Value $Normal.Evidence

    $card = [pscustomobject]@{
        CssClass  = 'good'
        BadgeText = 'GOOD'
        Area      = Get-IssueAreaLabel -Category $Category -Entry $Normal
        Message   = $Normal.Title
        Evidence  = $detail
        Source    = $normalSource
    }

    $goodGeneratedData = @{ Title = $card.Message; HasEvidence = [bool]$card.Evidence }
    foreach ($key in $normalSourceData.Keys) {
        $goodGeneratedData[$key] = $normalSourceData[$key]
    }
    Write-HtmlDebug -Stage 'Composer.GoodCard' -Message 'Positive finding card generated.' -Data $goodGeneratedData
    return $card
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

    if (-not $Context) {
        Write-HtmlDebug -Stage 'FailedReports' -Message 'No analyzer context supplied; skipping collector evaluation.'
        return $failures
    }

    $summaryArtifact = Get-AnalyzerArtifact -Context $Context -Name 'collection-summary'
    if (-not $summaryArtifact) {
        Write-HtmlDebug -Stage 'FailedReports' -Message 'Collection summary artifact unavailable; assuming no failures.'
    }

    if ($summaryArtifact -and $summaryArtifact.Data -and $summaryArtifact.Data.PSObject.Properties['Results']) {
        $results = $summaryArtifact.Data.Results
        if (-not ($results -is [System.Collections.IEnumerable] -and -not ($results -is [string]))) {
            $results = @($results)
        }

        Write-HtmlDebug -Stage 'FailedReports' -Message 'Evaluating collector results.' -Data @{ Count = $results.Count }

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
                Write-HtmlDebug -Stage 'FailedReports' -Message 'Collector execution failed.' -Data @{ Collector = $displayName; Path = $scriptPath }
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
                    Write-HtmlDebug -Stage 'FailedReports' -Message 'Collector succeeded but returned no output.' -Data @{ Collector = $displayName; Path = $scriptPath }
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
                    Write-HtmlDebug -Stage 'FailedReports' -Message 'Collector output references missing files.' -Data @{ Collector = $displayName; Missing = ($missing -join ', ') }
                }
            }
        }
    } else {
        Write-HtmlDebug -Stage 'FailedReports' -Message 'Collection summary missing result entries.'
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
                    Write-HtmlDebug -Stage 'FailedReports' -Message 'Artifact parsing failed.' -Data @{ Key = $key; Path = $path }
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
                        $enumerated = [System.Collections.Generic.List[object]]::new()
                        foreach ($item in $payload) { $enumerated.Add($item) }
                        if ($enumerated.Count -eq 0) { $isEmpty = $true }
                    }

                    if ($isEmpty) {
                        $failures.Add([pscustomobject]@{
                                Key     = if ($path) { [System.IO.Path]::GetFileName($path) } else { $key }
                                Status  = 'Empty output'
                                Details = 'Captured file contained no payload.'
                                Path    = $path
                            }) | Out-Null
                        Write-HtmlDebug -Stage 'FailedReports' -Message 'Artifact payload empty.' -Data @{ Key = $key; Path = $path }
                    }
                }
            }
        }
    }

    Write-HtmlDebug -Stage 'FailedReports' -Message 'Collector evaluation complete.' -Data @{ Failures = $failures.Count }
    return $failures
}


function Build-SummaryCardHtml {
    param(
        [pscustomobject]$Summary,
        [System.Collections.Generic.List[pscustomobject]]$Issues,
        [System.Collections.Generic.List[pscustomobject]]$Normals
    )

    if (-not $Summary) { $Summary = [pscustomobject]@{} }
    if (-not $Issues) { $Issues = @() }
    if (-not $Normals) { $Normals = @() }

    $generatedAt = if ($Summary.GeneratedAt) { [datetime]$Summary.GeneratedAt } else { Get-Date }
    $generatedAtHtml = Encode-Html ($generatedAt.ToString("dddd, MMMM d, yyyy 'at' h:mm tt"))

    $severityKeys = @('critical','high','medium','warning','low','info')
    $counts = @{}
    foreach ($key in $severityKeys) { $counts[$key] = 0 }
    foreach ($issue in $Issues) {
        $key = if ($issue.Severity) { $issue.Severity } else { 'info' }
        if (-not $counts.ContainsKey($key)) { $counts[$key] = 0 }
        $counts[$key]++
    }

    $goodCount = if ($Normals) { [int]$Normals.Count } else { 0 }
    $badCount = if ($Issues) { [int]$Issues.Count } else { 0 }
    $totalCount = $goodCount + $badCount
    if ($totalCount -le 0) {
        $overallRatio = 1.0
        $fractionDisplay = '0/0'
    } else {
        $overallRatio = [Math]::Max(0.0, [Math]::Min(([double]$goodCount / [double]$totalCount), 1.0))
        $fractionDisplay = ("{0}/{1}" -f $goodCount, $totalCount)
    }

    $severityOrder = @{ critical = 0; high = 1; medium = 2; warning = 3; low = 4; info = 5; good = 6 }
    $overallWorst = 'good'
    foreach ($severity in $severityKeys) {
        if ($counts.ContainsKey($severity) -and $counts[$severity] -gt 0) {
            $overallWorst = $severity
            break
        }
    }

    $severityDisplay = @{
        critical = 'Critical'
        high     = 'High'
        medium   = 'Medium'
        warning  = 'Warning'
        low      = 'Low'
        info     = 'Info'
        good     = 'All clear'
    }

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    $deviceName = if ($Summary.DeviceName) { $Summary.DeviceName } else { 'Unknown' }
    $deviceState = if ($Summary.DeviceState) { $Summary.DeviceState } else { 'Unknown' }
    $mdmEnrollment = if ($Summary.MdmEnrollment) { $Summary.MdmEnrollment } else { 'Unknown' }

    $osParts = [System.Collections.Generic.List[string]]::new()
    if ($Summary.OperatingSystem) { $osParts.Add($Summary.OperatingSystem) }
    if ($Summary.OSVersion) { $osParts.Add($Summary.OSVersion) }
    if ($Summary.OSBuild) { $osParts.Add("Build $($Summary.OSBuild)") }
    $osArray = $osParts.ToArray()
    $osText = if ($osArray.Length -gt 0) { ($osArray -join ' | ') } else { 'Unknown' }


    $ipv4Text = if ($Summary.IPv4Addresses -and $Summary.IPv4Addresses.Count -gt 0) { ($Summary.IPv4Addresses -join ', ') } else { 'Unknown' }
    $gatewayText = if ($Summary.Gateways -and $Summary.Gateways.Count -gt 0) { ($Summary.Gateways -join ', ') } else { 'Unknown' }
    $dnsText = if ($Summary.DnsServers -and $Summary.DnsServers.Count -gt 0) { ($Summary.DnsServers -join ', ') } else { 'Unknown' }

    $overallPercent = [Math]::Round(100.0 * $overallRatio, 1)
    $overallCircumference = 2.0 * [Math]::PI * 54.0
    $overallDashArray = [string]::Format($invariant, '{0:0.##}', $overallCircumference)
    $overallDashOffset = [string]::Format($invariant, '{0:0.##}', $overallCircumference * (1.0 - ($overallRatio)))
    $overallClass = if ($overallWorst) { "score-ring score-ring--overall score-ring--$overallWorst" } else { 'score-ring score-ring--overall score-ring--info' }

    $overallLabelParts = New-Object System.Collections.Generic.List[string]
    if ($totalCount -le 0) {
        $null = $overallLabelParts.Add('No good or bad findings were recorded')
    } else {
        $null = $overallLabelParts.Add(("Good findings {0}; bad findings {1}" -f $goodCount, $badCount))
        $null = $overallLabelParts.Add(("Good fraction {0}%" -f $overallPercent))
    }
    if ($overallWorst -and $overallWorst -ne 'good') {
        $display = if ($severityDisplay.ContainsKey($overallWorst)) { $severityDisplay[$overallWorst] } else { $overallWorst }
        $null = $overallLabelParts.Add(("Worst severity {0}" -f $display))
    } else {
        $null = $overallLabelParts.Add('No active issues detected')
    }
    $overallAriaHtml = Encode-Html ($overallLabelParts -join '. ')

    $overallRingBuilder = [System.Text.StringBuilder]::new()
    $overallLabelHtml = Encode-Html 'Overall'
    $overallScoreHtml = Encode-Html ([string]$fractionDisplay)
    $null = $overallRingBuilder.AppendLine("<div class='$overallClass' role='img' aria-label='$overallAriaHtml'>")
    $null = $overallRingBuilder.AppendLine("  <svg class='score-ring__svg' viewBox='0 0 120 120'>")
    $null = $overallRingBuilder.AppendLine("    <circle class='score-ring__background' cx='60' cy='60' r='54'></circle>")
    $null = $overallRingBuilder.AppendLine("    <circle class='score-ring__value' cx='60' cy='60' r='54' stroke-dasharray='$overallDashArray' stroke-dashoffset='$overallDashOffset'></circle>")
    $null = $overallRingBuilder.AppendLine('  </svg>')
    $null = $overallRingBuilder.AppendLine("  <div class='score-ring__content'><span class='score-ring__label'>$overallLabelHtml</span><span class='score-ring__number'>$overallScoreHtml</span></div>")
    $null = $overallRingBuilder.AppendLine('</div>')
    $overallRingHtml = $overallRingBuilder.ToString().TrimEnd()

    $appendIndented = {
        param(
            [System.Text.StringBuilder]$Builder,
            [string]$Text,
            [string]$Indent
        )

        if (-not $Builder -or [string]::IsNullOrEmpty($Text)) { return }
        foreach ($line in [regex]::Split($Text, '\\r?\\n')) {
            if ($line.Length -eq 0) {
                [void]$Builder.AppendLine('')
            } else {
                [void]$Builder.AppendLine("$Indent$line")
            }
        }
    }

    $summarySectionId = 'section-overview'
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("<div class='report-summary'>")
    $null = $sb.AppendLine("  <div class='report-summary__heading'>")
    $null = $sb.AppendLine('    <h1>Device Health Report</h1>')
    $null = $sb.AppendLine("    <h2 class='report-subtitle'>Generated $generatedAtHtml</h2>")
    $null = $sb.AppendLine('  </div>')
    $null = $sb.AppendLine("  <div class='report-card report-card--overview'>")
    $null = $sb.AppendLine("    <div class='score-section'>")
    $null = $sb.AppendLine("      <div class='score-section__primary'>")
    & $appendIndented $sb $overallRingHtml '        '
    $null = $sb.AppendLine("        <div class='report-badge-group'>")
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
        $null = $sb.AppendLine("          <span class='report-badge report-badge--$($badge.Class)'><span class='report-badge__label'>$labelHtml</span><span class='report-badge__value'>$count</span></span>")
    }
    $null = $sb.AppendLine('        </div>')
    $null = $sb.AppendLine('      </div>')
    $null = $sb.AppendLine('    </div>')
    $null = $sb.AppendLine("    <table class='report-table report-table--overview' cellspacing='0' cellpadding='0'>")
    $null = $sb.AppendLine('      <colgroup>')
    $null = $sb.AppendLine("        <col class='report-table__col--overview-primary'>")
    $null = $sb.AppendLine("        <col class='report-table__col--overview-secondary'>")
    $null = $sb.AppendLine('      </colgroup>')
    $null = $sb.AppendLine('      <tbody>')
    $null = $sb.AppendLine('        <tr>')
    $null = $sb.AppendLine("          <td>")
    $null = $sb.AppendLine("            <h3 class='report-overview__group-title'>Device</h3>")
    $null = $sb.AppendLine("            <table class='report-table report-table--key-value' cellspacing='0' cellpadding='0'>")
    $null = $sb.AppendLine("              <tr><td>Device Name</td><td>$(Encode-Html $deviceName)</td></tr>")
    $null = $sb.AppendLine("              <tr><td>Device State</td><td>$(Encode-Html $deviceState)</td></tr>")
    $null = $sb.AppendLine("              <tr><td>MAM/MDM Enrollment</td><td>$(Encode-Html $mdmEnrollment)</td></tr>")
    $null = $sb.AppendLine("              <tr><td>System</td><td>$(Encode-Html $osText)</td></tr>")
    $null = $sb.AppendLine('            </table>')
    $null = $sb.AppendLine('          </td>')
    $null = $sb.AppendLine('          <td>')
    $null = $sb.AppendLine("            <h3 class='report-overview__group-title'>Network</h3>")
    $null = $sb.AppendLine("            <table class='report-table report-table--key-value' cellspacing='0' cellpadding='0'>")
    $null = $sb.AppendLine("              <tr><td>IPv4</td><td>$(Encode-Html $ipv4Text)</td></tr>")
    $null = $sb.AppendLine("              <tr><td>Gateway</td><td>$(Encode-Html $gatewayText)</td></tr>")
    $null = $sb.AppendLine("              <tr><td>DNS</td><td>$(Encode-Html $dnsText)</td></tr>")
    $null = $sb.AppendLine('            </table>')
    $null = $sb.AppendLine('          </td>')
    $null = $sb.AppendLine('        </tr>')
    $null = $sb.AppendLine('      </tbody>')
    $null = $sb.AppendLine('    </table>')
    $null = $sb.AppendLine('  </div>')
    $null = $sb.AppendLine('</div>')

    return $sb.ToString()
}

function Build-ReportNavigation {
    param(
        [System.Collections.IEnumerable]$Sections
    )

    if (-not $Sections) { return '' }

    $processed = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($section in $Sections) {
        if (-not $section) { continue }

        $id = $null
        $label = $null
        $count = $null
        $description = $null
        $contentHtml = $null
        $panelHeading = $null
        $panelDescription = $null
        $hasExplicitPanelHeading = $false
        $hasExplicitPanelDescription = $false

        if ($section -is [System.Collections.IDictionary]) {
            if ($section.Contains('Id')) { $id = [string]$section['Id'] }
            if ($section.Contains('Label')) { $label = [string]$section['Label'] }
            if ($section.Contains('Count')) { $count = $section['Count'] }
            if ($section.Contains('Description')) { $description = [string]$section['Description'] }
            if ($section.Contains('ContentHtml')) { $contentHtml = [string]$section['ContentHtml'] }
            if ($section.Contains('PanelHeading')) { $hasExplicitPanelHeading = $true; $panelHeading = [string]$section['PanelHeading'] }
            if ($section.Contains('PanelDescription')) { $hasExplicitPanelDescription = $true; $panelDescription = [string]$section['PanelDescription'] }
        } else {
            if ($section.PSObject.Properties['Id']) { $id = [string]$section.Id }
            if ($section.PSObject.Properties['Label']) { $label = [string]$section.Label }
            if ($section.PSObject.Properties['Count']) { $count = $section.Count }
            if ($section.PSObject.Properties['Description']) { $description = [string]$section.Description }
            if ($section.PSObject.Properties['ContentHtml']) { $contentHtml = [string]$section.ContentHtml }
            if ($section.PSObject.Properties['PanelHeading']) { $hasExplicitPanelHeading = $true; $panelHeading = [string]$section.PanelHeading }
            if ($section.PSObject.Properties['PanelDescription']) { $hasExplicitPanelDescription = $true; $panelDescription = [string]$section.PanelDescription }
        }

        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $safeId = [regex]::Replace($id.ToLowerInvariant(), '[^a-z0-9\-_]+', '-')
        $safeId = [regex]::Replace($safeId, '^-+|-+$', '')
        if (-not $safeId) { $safeId = [regex]::Replace($id, '\s+', '-') }
        if (-not $safeId) { continue }

        $labelText = if ($label) { $label } else { $id }
        $labelHtml = Encode-Html $labelText
        $countText = $null
        if ($null -ne $count -and $count -ne '') { $countText = [string]$count }
        $contentValue = if ($null -ne $contentHtml) { $contentHtml } else { '' }
        $panelHeadingValue = if ($null -ne $panelHeading) { $panelHeading } else { $null }
        $panelDescriptionValue = if ($null -ne $panelDescription) { $panelDescription } else { $null }

        $processed.Add([pscustomobject]@{
                Id               = $safeId
                Label            = $labelText
                LabelHtml        = $labelHtml
                Count            = $countText
                Description      = $description
                ContentHtml      = $contentValue
                PanelHeading     = $panelHeadingValue
                PanelDescription = $panelDescriptionValue
                HasExplicitPanelHeading = $hasExplicitPanelHeading
                HasExplicitPanelDescription = $hasExplicitPanelDescription
            })
    }

    if ($processed.Count -eq 0) { return '' }

    $tabsetId = 'report-tabs-' + ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    $builder = [System.Text.StringBuilder]::new()
    $null = $builder.Append("<div class='report-tabs-container' data-report-tabs='$tabsetId'>")
    $null = $builder.Append("<nav class='report-nav' role='tablist' aria-label='Report sections'><ul class='report-nav__list'>")

    $panelMarkup = New-Object System.Collections.Generic.List[string]

    for ($index = 0; $index -lt $processed.Count; $index++) {
        $entry = $processed[$index]
        $isActive = ($index -eq 0)
        $tabId = '{0}-tab-{1}' -f $tabsetId, ($index + 1)
        $ariaSelected = if ($isActive) { 'true' } else { 'false' }
        $buttonClasses = 'report-nav__link report-nav__link--tab'
        if ($isActive) { $buttonClasses += ' is-active' }

        $countFragment = ''
        if ($entry.Count) {
            $countValue = Encode-Html $entry.Count
            $countFragment = "<span class='report-nav__count'>$countValue</span>"
        }

        $descriptionFragment = ''
        if (-not [string]::IsNullOrWhiteSpace($entry.Description)) {
            $descriptionFragment = "<span class='report-nav__description'>$(Encode-Html $entry.Description)</span>"
        }

        $null = $builder.Append("<li class='report-nav__item'>")
        $null = $builder.Append("<button type='button' class='$buttonClasses' role='tab' id='$tabId' aria-controls='$($entry.Id)' aria-selected='$ariaSelected'>")
        $null = $builder.Append("<span class='report-nav__label'>$($entry.LabelHtml)</span>")
        if ($countFragment) { $null = $builder.Append($countFragment) }
        if ($descriptionFragment) { $null = $builder.Append($descriptionFragment) }
        $null = $builder.Append('</button></li>')

        $panelClasses = 'report-tabpanel'
        if ($isActive) { $panelClasses += ' is-active' }
        $hiddenAttr = if ($isActive) { '' } else { " hidden='hidden'" }
        $tabIndexValue = if ($isActive) { '0' } else { '-1' }

        $panelHeadingText = $entry.PanelHeading
        if ((-not $entry.HasExplicitPanelHeading) -and [string]::IsNullOrWhiteSpace($panelHeadingText)) {
            if (-not [string]::IsNullOrWhiteSpace($entry.Label)) {
                if ($entry.Count) {
                    $panelHeadingText = '{0} ({1})' -f $entry.Label, $entry.Count
                } else {
                    $panelHeadingText = $entry.Label
                }
            } else {
                $panelHeadingText = $entry.Id
            }
        }

        $panelHeadingFragment = ''
        if (-not [string]::IsNullOrWhiteSpace($panelHeadingText)) {
            $panelHeadingHtml = Encode-Html $panelHeadingText
            $panelHeadingFragment = "<header class='report-tabpanel__header'><h2 class='report-tabpanel__title'>$panelHeadingHtml</h2></header>"
        }

        $panelDescriptionFragment = ''
        $panelDescriptionText = if (-not [string]::IsNullOrWhiteSpace($entry.PanelDescription)) { $entry.PanelDescription } elseif ((-not $entry.HasExplicitPanelDescription) -and (-not [string]::IsNullOrWhiteSpace($entry.Description))) { $entry.Description } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($panelDescriptionText)) {
            $panelDescriptionFragment = "<p class='report-tabpanel__description'>$(Encode-Html $panelDescriptionText)</p>"
        }

        $panelBodyBuilder = [System.Text.StringBuilder]::new()
        $null = $panelBodyBuilder.Append("<section class='$panelClasses' id='$($entry.Id)' role='tabpanel' aria-labelledby='$tabId'$hiddenAttr tabindex='$tabIndexValue'>")
        if ($panelHeadingFragment -or $panelDescriptionFragment) {
            $null = $panelBodyBuilder.Append("<div class='report-tabpanel__intro'>$panelHeadingFragment$panelDescriptionFragment</div>")
        }
        $null = $panelBodyBuilder.Append("<div class='report-tabpanel__body'>$($entry.ContentHtml)</div></section>")

        $panelMarkup.Add($panelBodyBuilder.ToString()) | Out-Null
    }

    $null = $builder.Append('</ul></nav>')
    $null = $builder.Append("<div class='report-tabpanels'>")
    foreach ($panel in $panelMarkup) {
        $null = $builder.Append($panel)
    }
    $null = $builder.Append('</div></div>')

    return $builder.ToString()
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

    foreach ($entry in ($Normals | Sort-Object -Property @(
                @{ Expression = { $_.Area } },
                @{ Expression = { $_.Message } }
            ))) {
        $category = Get-BaseCategoryFromArea -Area $entry.Area
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

    $severityOrder = @{ critical = 0; high = 1; medium = 2; low = 3; warning = 4; info = 5 }
    $sorted = $Issues | Sort-Object -Stable -Property @(
        @{ Expression = { if ($severityOrder.ContainsKey($_.Severity)) { $severityOrder[$_.Severity] } else { [int]::MaxValue } } },
        @{ Expression = { $_.Area } },
        @{ Expression = { $_.Message } }
    )

    $categoryOrder = @('Services','Office','Network','System','Hardware','Security','Active Directory','Printing','Events','General')
    $categorized = [ordered]@{}
    foreach ($category in $categoryOrder) {
        $categorized[$category] = New-Object System.Collections.Generic.List[string]
    }

    foreach ($entry in $sorted) {
        $category = Get-BaseCategoryFromArea -Area $entry.Area
        if (-not $categorized.ContainsKey($category)) {
            $categorized[$category] = New-Object System.Collections.Generic.List[string]
        }

        $categorized[$category].Add((New-IssueCardHtml -Entry $entry))
    }

    $orderedCategories = New-Object System.Collections.Generic.List[string]
    foreach ($category in $categoryOrder) { $null = $orderedCategories.Add($category) }
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
        $issueCards = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $sorted) {
            $null = $issueCards.Add((New-IssueCardHtml -Entry $entry))
        }

        return ($issueCards -join '')
    }

    $tabName = 'issue-tabs'
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
        $panelContent = if ($count -gt 0) { ($cards -join '') } else { "<div class='report-card'><i>No issues captured for this category.</i></div>" }

        $null = $tabsBuilder.Append("<input type='radio' name='$tabName' id='$tabId' class='report-tabs__radio'$checkedAttr>")
        $null = $tabsBuilder.Append("<label class='report-tabs__label' for='$tabId'>$labelText</label>")
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
    $metaBuilder = [System.Text.StringBuilder]::new()
    if ($collectedAt) { $null = $metaBuilder.Append("Collected: $collectedAt") }
    if ($path) {
        if ($metaBuilder.Length -gt 0) { $null = $metaBuilder.Append(' • ') }
        $null = $metaBuilder.Append("File: $path")
    }

    $metaHtml = ''
    if ($metaBuilder.Length -gt 0) {
        $metaHtml = "<div><small class='report-note'>$(Encode-Html ($metaBuilder.ToString()))</small></div>"
    }

    return "<div class='report-card'><b>$(Encode-Html $Key)</b>$metaHtml<pre class='report-pre'>$(Encode-Html $($trimmedResult.Text))</pre></div>"
}

function Build-DebugSection {
    param($Context)

    if (-not $Context -or -not $Context.Artifacts) {
        return "<div class='report-card'><i>No debug metadata available.</i></div>"
    }

    $builder = [System.Text.StringBuilder]::new()
    foreach ($key in ($Context.Artifacts.Keys | Sort-Object)) {
        $entries = $Context.Artifacts[$key]
        if (-not $entries) {
            $null = $builder.AppendLine("${key}: (no entries)")
            continue
        }

        if ($entries -is [System.Collections.IEnumerable] -and -not ($entries -is [string])) {
            $count = $entries.Count
            $firstPath = $entries[0].Path
            $null = $builder.AppendLine("${key}: $count file(s); first = $firstPath")
        } else {
            $null = $builder.AppendLine("${key}: $($entries.Path)")
        }
    }

    if ($builder.Length -eq 0) {
        return "<div class='report-card'><i>No debug metadata available.</i></div>"
    }

    $linesText = $builder.ToString().TrimEnd(@([char]13, [char]10))
    return "<div class='report-card'><b>Artifacts discovered</b><pre class='report-pre'>$(Encode-Html ($linesText))</pre></div>"
}

function Build-RawSection {
    param(
        $Context,
        [int]$MaxArtifacts = 10,
        [int]$MaxLines = 40,
        [int]$MaxChars = 2000
    )

    $artifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    Write-HtmlDebug -Stage 'RawSection' -Message 'Starting raw artifact rendering.' -Data @{ Artifacts = $artifactCount; MaxArtifacts = $MaxArtifacts }

    if (-not $Context -or -not $Context.Artifacts -or $Context.Artifacts.Count -eq 0) {
        Write-HtmlDebug -Stage 'RawSection' -Message 'No artifacts available; returning placeholder.'
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
        Write-HtmlDebug -Stage 'RawSection' -Message 'Artifacts resolved but none produced renderable entries.'
        return "<div class='report-card'><i>No raw payloads available.</i></div>"
    }

    $cardsBuilder = [System.Text.StringBuilder]::new()
    $null = $cardsBuilder.Append("<div class='report-card'><i>Showing up to $MaxArtifacts artifact(s); each excerpt is limited to $MaxLines lines or $MaxChars characters.</i></div>")

    $processed = 0
    foreach ($item in $items) {
        if ($processed -ge $MaxArtifacts) { break }
        $card = ConvertTo-RawCard -Key $item.Key -Entry $item.Entry -MaxLines $MaxLines -MaxChars $MaxChars
        if ($card) {
            $null = $cardsBuilder.Append($card)
            $processed++
        }
    }

    if ($processed -eq 0) {
        Write-HtmlDebug -Stage 'RawSection' -Message 'Artifacts located but all entries were filtered out.' -Data @{ Candidates = $items.Count }
        return "<div class='report-card'><i>No raw payload excerpts available.</i></div>"
    }

    if ($items.Count -gt $processed) {
        $remaining = $items.Count - $processed
        $null = $cardsBuilder.Append("<div class='report-card'><i>$remaining additional artifact(s) available in the collector output folder.</i></div>")
    }

    Write-HtmlDebug -Stage 'RawSection' -Message 'Raw artifact section built.' -Data @{ Rendered = $processed; Remaining = [Math]::Max($items.Count - $processed, 0) }
    return $cardsBuilder.ToString()
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

    $categoryCount = if ($Categories) { ($Categories | Measure-Object).Count } else { 0 }
    Write-HtmlDebug -Stage 'Composer' -Message 'Beginning HTML composition.' -Data @{ Categories = $categoryCount; HasSummary = [bool]$Summary; HasContext = [bool]$Context }

    $issues = New-Object System.Collections.Generic.List[pscustomobject]
    $normals = New-Object System.Collections.Generic.List[pscustomobject]

    $categoryIndex = 0
    foreach ($category in $Categories) {
        $categoryIndex++

        if (-not $category) {
            Write-HtmlDebug -Stage 'Composer.Categories' -Message 'Encountered null category entry during flattening.' -Data @{ Index = $categoryIndex }
            continue
        }

        $categoryName = if ($category.PSObject.Properties['Name']) { [string]$category.Name } else { '(unnamed)' }
        $issueSet = if ($category.PSObject.Properties['Issues']) { $category.Issues } else { $null }
        $normalSet = if ($category.PSObject.Properties['Normals']) { $category.Normals } else { $null }

        $issueCandidates = if ($issueSet -is [System.Collections.IEnumerable] -and -not ($issueSet -is [string])) { $issueSet } elseif ($issueSet) { @($issueSet) } else { @() }
        $normalCandidates = if ($normalSet -is [System.Collections.IEnumerable] -and -not ($normalSet -is [string])) { $normalSet } elseif ($normalSet) { @($normalSet) } else { @() }

        $categorySource = if ($category.PSObject.Properties['Source']) { $category.Source } else { $null }
        $categorySourceData = Get-SourceLogData -Source $categorySource
        $categoryData = @{ Index = $categoryIndex; Name = $categoryName; Issues = ($issueCandidates | Measure-Object).Count; Normals = ($normalCandidates | Measure-Object).Count }
        foreach ($key in $categorySourceData.Keys) {
            $categoryData[$key] = $categorySourceData[$key]
        }
        Write-HtmlDebug -Stage 'Composer.Categories' -Message 'Processing category.' -Data $categoryData

        $issueIndex = 0
        foreach ($issue in $issueCandidates) {
            $issueIndex++
            if (-not $issue) {
                Write-HtmlDebug -Stage 'Composer.Categories' -Message 'Skipping null issue entry.' -Data @{ Category = $categoryName; CategoryIndex = $categoryIndex; IssueIndex = $issueIndex }
                continue
            }

            $card = Convert-ToIssueCard -Category $category -Issue $issue
            if ($card) {
                $issues.Add($card) | Out-Null
            } else {
                $issueSource = if ($issue.PSObject.Properties['Source']) { $issue.Source } else { $null }
                $issueSourceData = Get-SourceLogData -Source $issueSource
                $issueNoCardData = @{ Category = $categoryName; CategoryIndex = $categoryIndex; IssueIndex = $issueIndex }
                foreach ($key in $issueSourceData.Keys) {
                    $issueNoCardData[$key] = $issueSourceData[$key]
                }
                Write-HtmlDebug -Stage 'Composer.Categories' -Message 'Issue conversion returned no card.' -Data $issueNoCardData
            }
        }

        $normalIndex = 0
        foreach ($normal in $normalCandidates) {
            $normalIndex++
            if (-not $normal) {
                Write-HtmlDebug -Stage 'Composer.Categories' -Message 'Skipping null positive entry.' -Data @{ Category = $categoryName; CategoryIndex = $categoryIndex; NormalIndex = $normalIndex }
                continue
            }

            $card = Convert-ToGoodCard -Category $category -Normal $normal
            if ($card) {
                $normals.Add($card) | Out-Null
            } else {
                $normalSource = if ($normal.PSObject.Properties['Source']) { $normal.Source } else { $null }
                $normalSourceData = Get-SourceLogData -Source $normalSource
                $normalNoCardData = @{ Category = $categoryName; CategoryIndex = $categoryIndex; NormalIndex = $normalIndex }
                foreach ($key in $normalSourceData.Keys) {
                    $normalNoCardData[$key] = $normalSourceData[$key]
                }
                Write-HtmlDebug -Stage 'Composer.Categories' -Message 'Positive finding conversion returned no card.' -Data $normalNoCardData
            }
        }
    }

    Write-HtmlDebug -Stage 'Composer' -Message 'Category flattening complete.' -Data @{ Issues = $issues.Count; Normals = $normals.Count }

    $servicesIssueCount = ($issues | Where-Object { $_ -and $_.PSObject.Properties['Area'] -and ($_.Area -like 'Services*') }).Count
    $servicesNormalCount = ($normals | Where-Object { $_ -and $_.PSObject.Properties['Area'] -and ($_.Area -like 'Services*') }).Count
    Write-HtmlDebug -Stage 'Composer.Services' -Message ('Composer: Rendering Services section: rows={0}' -f ($servicesIssueCount + $servicesNormalCount)) -Data ([ordered]@{
        Issues  = $servicesIssueCount
        Normals = $servicesNormalCount
    })

    if (-not $Summary) {
        $Summary = [pscustomobject]@{ GeneratedAt = Get-Date }
        Write-HtmlDebug -Stage 'Composer' -Message 'No summary provided; synthesized default summary.'
    }

    $summaryContent = Build-SummaryCardHtml -Summary $Summary -Issues $issues -Normals $normals
    $goodSectionId = 'section-good'
    $issuesSectionId = 'section-issues'
    $failedSectionId = 'section-failed'
    $rawSectionId = 'section-raw'

    $head = '<!doctype html><html><head><meta charset="utf-8"><title>Device Health Report</title><link rel="stylesheet" href="styles/device-health-report.css"></head><body class="page report-page"><main class="report-main">'
    $goodContent = Build-GoodSection -Normals $normals
    $issuesContent = Build-IssueSection -Issues $issues
    $failedReports = Get-FailedCollectorReports -Context $Context
    $failedTitle = "Failed Reports ({0})" -f $failedReports.Count
    Write-HtmlDebug -Stage 'Composer' -Message 'Failed collector section prepared.' -Data @{ Count = $failedReports.Count }
    if ($failedReports.Count -eq 0) {
        $failedContent = "<div class='report-card'><i>All expected inputs produced output.</i></div>"
    } else {
        $failedContentBuilder = [System.Text.StringBuilder]::new()
        $null = $failedContentBuilder.Append("<div class='report-card'><table class='report-table report-table--list' cellspacing='0' cellpadding='0'><tr><th>Key</th><th>Status</th><th>Details</th></tr>")
        foreach ($entry in $failedReports) {
            $detailBuilder = [System.Text.StringBuilder]::new()
            if ($entry.Path) {
                $null = $detailBuilder.Append((Encode-Html "File: $($entry.Path)"))
            }
            if ($entry.Details) {
                if ($detailBuilder.Length -gt 0) { $null = $detailBuilder.Append('<br>') }
                $null = $detailBuilder.Append((Encode-Html $entry.Details))
            }
            $detailHtml = if ($detailBuilder.Length -gt 0) { $detailBuilder.ToString() } else { Encode-Html '' }
            $null = $failedContentBuilder.Append("<tr><td>$(Encode-Html $($entry.Key))</td><td>$(Encode-Html $($entry.Status))</td><td>$detailHtml</td></tr>")
        }
        $null = $failedContentBuilder.Append("</table></div>")
        $failedContent = $failedContentBuilder.ToString()
    }
    $rawContent = Build-RawSection -Context $Context
    $rawCount = if ($Context -and $Context.Artifacts) { ($Context.Artifacts.Keys | Measure-Object).Count } else { 0 }
    $goodCount = $normals.Count
    $issueCount = $issues.Count
    $failedCount = $failedReports.Count
    $navSections = @(
        @{ Id = 'section-overview'; Label = 'Overview'; Description = 'Score & device summary'; ContentHtml = $summaryContent; PanelHeading = ''; PanelDescription = '' },
        @{ Id = $goodSectionId; Label = 'What Looks Good'; Count = $goodCount; ContentHtml = $goodContent; PanelHeading = "What Looks Good ($goodCount)" },
        @{ Id = $issuesSectionId; Label = 'Detected Issues'; Count = $issueCount; ContentHtml = $issuesContent; PanelHeading = "Detected Issues ($issueCount)" },
        @{ Id = $failedSectionId; Label = 'Failed Reports'; Count = $failedCount; ContentHtml = $failedContent; PanelHeading = $failedTitle },
        @{ Id = $rawSectionId; Label = 'Raw excerpts'; Count = $rawCount; ContentHtml = $rawContent; PanelHeading = "Raw excerpts ($rawCount)" }
    )
    $navHtml = Build-ReportNavigation -Sections $navSections
    $debugHtml = "<details><summary>Debug</summary>$(Build-DebugSection -Context $Context)</details>"
    $tabsScript = @'
<script>
(function () {
  'use strict';

  function toArray(value) {
    return Array.prototype.slice.call(value || []);
  }

  function focusTab(tab) {
    if (!tab || typeof tab.focus !== 'function') {
      return;
    }

    try {
      tab.focus({ preventScroll: true });
    } catch (err) {
      try {
        tab.focus();
      } catch (focusErr) {
        // Ignore focus errors in older browsers.
      }
    }
  }

  function setActiveTab(tabset, tabs, tab, updateHash) {
    tabs.forEach(function (candidate) {
      var isSelected = candidate === tab;
      candidate.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      candidate.classList.toggle('is-active', isSelected);

      var targetId = candidate.getAttribute('aria-controls');
      if (!targetId) {
        return;
      }

      var panel = document.getElementById(targetId);
      if (!panel) {
        return;
      }

      if (isSelected) {
        panel.classList.add('is-active');
        panel.removeAttribute('hidden');
        panel.setAttribute('tabindex', '0');
      } else {
        panel.classList.remove('is-active');
        panel.setAttribute('hidden', 'hidden');
        panel.setAttribute('tabindex', '-1');
      }
    });

    if (tab && updateHash !== false) {
      var activeId = tab.getAttribute('aria-controls');
      if (activeId) {
        try {
          if (window.history && window.history.replaceState) {
            window.history.replaceState(null, '', '#' + activeId);
          } else {
            window.location.hash = activeId;
          }
        } catch (err) {
          window.location.hash = activeId;
        }
      }
    }
  }

  function handleKey(event, tabs, currentTab, tabset) {
    var key = event.key || event.keyCode;
    var currentIndex = -1;
    if (tabs && typeof tabs.indexOf === 'function') {
      currentIndex = tabs.indexOf(currentTab);
    }

    if (currentIndex < 0) {
      for (var idx = 0; idx < tabs.length; idx += 1) {
        if (tabs[idx] === currentTab) {
          currentIndex = idx;
          break;
        }
      }
    }

    if (currentIndex < 0) {
      currentIndex = 0;
    }

    var targetIndex = null;
    if (key === 'ArrowRight' || key === 'ArrowDown' || key === 39 || key === 40) {
      targetIndex = (currentIndex + 1) % tabs.length;
    } else if (key === 'ArrowLeft' || key === 'ArrowUp' || key === 37 || key === 38) {
      targetIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else if (key === 'Home' || key === 36) {
      targetIndex = 0;
    } else if (key === 'End' || key === 35) {
      targetIndex = tabs.length - 1;
    }

    if (targetIndex !== null) {
      event.preventDefault();
      var nextTab = tabs[targetIndex];
      if (nextTab) {
        setActiveTab(tabset, tabs, nextTab, true);
        focusTab(nextTab);
      }
    }
  }

  function initReportTabs(tabset) {
    var tabs = toArray(tabset.querySelectorAll('[role="tab"]'));
    if (!tabs.length) {
      return;
    }

    tabs.forEach(function (tab, index) {
      if (!tab.id) {
        tab.id = tabset.getAttribute('data-report-tabs') + '-tab-' + (index + 1);
      }
    });

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function (event) {
        event.preventDefault();
        if (tab.getAttribute('aria-selected') === 'true') {
          return;
        }
        setActiveTab(tabset, tabs, tab, true);
      });

      tab.addEventListener('keydown', function (event) {
        handleKey(event, tabs, tab, tabset);
      });
    });

    var initialTab = null;
    var hash = window.location.hash ? window.location.hash.substring(1) : '';
    if (hash) {
      for (var i = 0; i < tabs.length; i += 1) {
        if (tabs[i].getAttribute('aria-controls') === hash) {
          initialTab = tabs[i];
          break;
        }
      }
    }

    if (!initialTab) {
      for (var j = 0; j < tabs.length; j += 1) {
        if (tabs[j].getAttribute('aria-selected') === 'true') {
          initialTab = tabs[j];
          break;
        }
      }
    }

    if (!initialTab) {
      initialTab = tabs[0];
    }

    setActiveTab(tabset, tabs, initialTab, false);

    window.addEventListener('hashchange', function () {
      var updatedHash = window.location.hash ? window.location.hash.substring(1) : '';
      if (!updatedHash) {
        return;
      }

      for (var i = 0; i < tabs.length; i += 1) {
        if (tabs[i].getAttribute('aria-controls') === updatedHash) {
          setActiveTab(tabset, tabs, tabs[i], false);
          focusTab(tabs[i]);
          break;
        }
      }
    });
  }

  function copyToClipboard(text) {
    if (!text) {
      return Promise.reject(new Error('No text to copy'));
    }

    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      return navigator.clipboard.writeText(text);
    }

    return new Promise(function (resolve, reject) {
      var textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      textarea.style.pointerEvents = 'none';
      document.body.appendChild(textarea);

      try {
        if (typeof textarea.focus === 'function') {
          try {
            textarea.focus({ preventScroll: true });
          } catch (focusErr) {
            textarea.focus();
          }
        }
      } catch (err) {
        // Ignore focus errors.
      }

      textarea.select();

      try {
        var successful = document.execCommand('copy');
        document.body.removeChild(textarea);
        if (successful) {
          resolve();
        } else {
          reject(new Error('Copy command failed'));
        }
      } catch (err) {
        document.body.removeChild(textarea);
        reject(err);
      }
    });
  }

  function setCopyButtonState(button, state) {
    if (!button) {
      return;
    }

    var original = button.getAttribute('data-copy-label');
    if (!original) {
      original = button.textContent || button.innerText || '';
      button.setAttribute('data-copy-label', original);
    }

    var successText = button.getAttribute('data-copy-success') || 'Copied!';
    var failureText = button.getAttribute('data-copy-failure') || 'Copy failed';

    var targetText = original;
    button.classList.remove('is-success');
    button.classList.remove('is-error');

    if (state === 'success') {
      targetText = successText;
      button.classList.add('is-success');
    } else if (state === 'failure') {
      targetText = failureText;
      button.classList.add('is-error');
    }

    if (typeof button.textContent === 'string') {
      button.textContent = targetText;
    } else {
      button.innerText = targetText;
    }

    if (state === 'success' || state === 'failure') {
      if (button._copyResetId) {
        window.clearTimeout(button._copyResetId);
      }

      button._copyResetId = window.setTimeout(function () {
        var resetText = button.getAttribute('data-copy-label') || original;
        if (typeof button.textContent === 'string') {
          button.textContent = resetText;
        } else {
          button.innerText = resetText;
        }
        button.classList.remove('is-success');
        button.classList.remove('is-error');
      }, 2000);
    }
  }

  function bindCopyButton(button) {
    if (!button) {
      return;
    }

    button.setAttribute('aria-live', 'polite');
    button.setAttribute('aria-atomic', 'true');

    button.addEventListener('click', function () {
      var targetSelector = button.getAttribute('data-copy-target');
      if (!targetSelector) {
        setCopyButtonState(button, 'failure');
        return;
      }

      var target = document.querySelector(targetSelector);
      if (!target) {
        setCopyButtonState(button, 'failure');
        return;
      }

      var text = '';
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
        text = target.value;
      } else {
        text = target.textContent || target.innerText || '';
      }

      if (!text) {
        setCopyButtonState(button, 'failure');
        return;
      }

      copyToClipboard(text).then(function () {
        setCopyButtonState(button, 'success');
      }).catch(function () {
        setCopyButtonState(button, 'failure');
      });
    });
  }

  function initCopyButtons(root) {
    var buttons = toArray((root || document).querySelectorAll('[data-copy-target]'));
    buttons.forEach(function (button) {
      bindCopyButton(button);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var tabsets = toArray(document.querySelectorAll('[data-report-tabs]'));
    tabsets.forEach(function (tabset) {
      initReportTabs(tabset);
    });

    initCopyButtons(document);
  });
})();
</script>
'@
    $tail = "</main>$tabsScript</body></html>"

    $htmlBuilder = [System.Text.StringBuilder]::new()
    foreach ($segment in @($head, $navHtml, $debugHtml, $tail)) {
        if ($segment) { $null = $htmlBuilder.Append($segment) }
    }

    $html = $htmlBuilder.ToString()
    Write-HtmlDebug -Stage 'Composer' -Message 'HTML composition complete.' -Data @{ Length = $html.Length }
    return $html
}
