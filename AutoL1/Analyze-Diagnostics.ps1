<#
Analyze-Diagnostics.ps1
- Loads analyzer modules from the local Modules directory
- Runs each module's Collect-<Area>Data and Analyze-<Area> functions
- Renders a consolidated HTML report summarising issues, healthy findings, and checks
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$InputFolder
)

$ErrorActionPreference = 'Stop'

function Encode-Html([string]$s){
  if ($null -eq $s) { return '' }
  return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'","&#39;")
}

function Normalize-Severity {
  param([string]$Severity)

  if ([string]::IsNullOrWhiteSpace($Severity)) { return 'info' }

  try {
    $value = $Severity.ToLowerInvariant()
  } catch {
    $value = [string]$Severity
    if ($value) { $value = $value.ToLowerInvariant() }
  }

  switch ($value) {
    'critical' { return 'critical' }
    'high'     { return 'high' }
    'medium'   { return 'medium' }
    'low'      { return 'low' }
    'info'     { return 'info' }
    'good'     { return 'good' }
    default    { return 'info' }
  }
}

function Get-SeverityRank {
  param([string]$Severity)

  switch (Normalize-Severity $Severity) {
    'critical' { return 0 }
    'high'     { return 1 }
    'medium'   { return 2 }
    'low'      { return 3 }
    'info'     { return 4 }
    'good'     { return 5 }
    default    { return 4 }
  }
}

function Get-PrimaryArea {
  param([string]$Area)

  if ([string]::IsNullOrWhiteSpace($Area)) { return 'General' }

  $prefix = ($Area -split '/')[0]
  if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = $Area }

  $trimmed = $prefix.Trim()

  switch -Regex ($trimmed) {
    '^(?i)system'            { return 'System' }
    '^(?i)(hardware|storage)'{ return 'Hardware' }
    '^(?i)(network|dns)'     { return 'Network' }
    '^(?i)(security|defender|firewall)' { return 'Security' }
    '^(?i)services?'         { return 'Services' }
    '^(?i)(office|outlook)'  { return 'Office' }
    '^(?i)(active\s*directory|^ad$|^gpo$|kerberos|secure channel)' { return 'Active Directory' }
    '^(?i)printing|^printer' { return 'Printing' }
    default                  { return 'General' }
  }
}

function Get-NormalCategory {
  param([string]$Area)
  return Get-PrimaryArea $Area
}

function New-ReportSection {
  param(
    [string]$Title,
    [string]$ContentHtml,
    [switch]$Open
  )

  $openAttr = if ($Open.IsPresent) { ' open' } else { '' }
  $titleValue = if ($null -ne $Title) { $Title } else { '' }
  $titleHtml = Encode-Html $titleValue
  $bodyHtml = if ($null -ne $ContentHtml) { $ContentHtml } else { '' }
  return "<details class='report-section'$openAttr><summary>$titleHtml</summary><div class='report-section__content'>$bodyHtml</div></details>"
}

function New-IssueCardHtml {
  param(
    [pscustomobject]$Entry
  )

  $cardClass = if ($Entry.CssClass) { $Entry.CssClass } else { 'ok' }
  $badgeText = if ($Entry.BadgeText) { $Entry.BadgeText } elseif ($Entry.Severity) { $Entry.Severity.ToUpperInvariant() } else { 'ISSUE' }
  $badgeHtml = Encode-Html $badgeText
  $areaHtml = Encode-Html $Entry.Area
  $messageValue = if ($null -ne $Entry.Message) { $Entry.Message } else { '' }
  $messageHtml = Encode-Html $messageValue
  $hasMessage = -not [string]::IsNullOrWhiteSpace($messageValue)
  $summaryText = if ($hasMessage) { "<strong>$areaHtml</strong>: $messageHtml" } else { "<strong>$areaHtml</strong>" }

  $cardHtml = "<details class='report-card report-card--{0}'><summary><span class='report-badge report-badge--{0}'>{1}</span><span class='report-card__summary-text'>{2}</span></summary>" -f $cardClass, $badgeHtml, $summaryText

  $bodyParts = @()

  if (-not [string]::IsNullOrWhiteSpace($Entry.Explanation)) {
    $explanationHtml = Encode-Html $Entry.Explanation
    $bodyParts += "<p class='report-card__explanation'>{0}</p>" -f $explanationHtml
  }

  if (-not [string]::IsNullOrWhiteSpace($Entry.Evidence)) {
    $evidenceHtml = Encode-Html $Entry.Evidence
    $bodyParts += "<pre class='report-pre'>{0}</pre>" -f $evidenceHtml
  }

  if ($bodyParts.Count -gt 0) {
    $cardHtml += "<div class='report-card__body'>{0}</div>" -f ($bodyParts -join '')
  }

  $cardHtml += "</details>"
  return $cardHtml
}

function New-GoodCardHtml {
  param(
    [pscustomobject]$Entry
  )

  $cardClass = if ($Entry.CssClass) { $Entry.CssClass } else { 'good' }
  $badgeText = if ($Entry.BadgeText) { $Entry.BadgeText } else { 'GOOD' }
  $badgeHtml = Encode-Html $badgeText
  $areaHtml = Encode-Html $Entry.Area
  $messageValue = if ($null -ne $Entry.Message) { $Entry.Message } else { '' }
  $messageHtml = Encode-Html $messageValue
  $hasMessage = -not [string]::IsNullOrWhiteSpace($messageValue)
  $summaryText = if ($hasMessage) { "<strong>$areaHtml</strong>: $messageHtml" } else { "<strong>$areaHtml</strong>" }

  $cardHtml = "<details class='report-card report-card--{0}'><summary><span class='report-badge report-badge--{0}'>{1}</span><span class='report-card__summary-text'>{2}</span></summary>" -f $cardClass, $badgeHtml, $summaryText

  if (-not [string]::IsNullOrWhiteSpace($Entry.Evidence)) {
    $evidenceHtml = Encode-Html $Entry.Evidence
    $cardHtml += "<div class='report-card__body'><pre class='report-pre'>{0}</pre></div>" -f $evidenceHtml
  }

  $cardHtml += "</details>"
  return $cardHtml
}

function New-BadgeHtml {
  param(
    [string]$CssClass,
    [string]$Label,
    [string]$Value,
    [string]$Suffix
  )

  $labelHtml = Encode-Html $Label
  $valueHtml = Encode-Html $Value
  $suffixHtml = if ($Suffix) { "<span class='report-badge__suffix'>{0}</span>" -f (Encode-Html $Suffix) } else { '' }
  return "<div class='report-badge report-badge--$CssClass'><span class='report-badge__label'>$labelHtml</span><span class='report-badge__value'>$valueHtml</span>$suffixHtml</div>"
}

function Build-SummaryBadges {
  param(
    [hashtable]$SeverityCounts,
    [int]$IssueCount,
    [int]$GoodCount,
    [int]$ModuleCount,
    [Nullable[int]]$OverallScore
  )

  $badges = New-Object System.Collections.Generic.List[string]

  if ($null -ne $OverallScore) {
    $badges.Add( (New-BadgeHtml -CssClass 'score' -Label 'Overall Score' -Value ([string]$OverallScore) -Suffix '%') )
  }

  $badges.Add( (New-BadgeHtml -CssClass 'critical' -Label 'Critical' -Value ([string]$SeverityCounts['critical']) ) )
  $badges.Add( (New-BadgeHtml -CssClass 'bad'      -Label 'High'      -Value ([string]$SeverityCounts['high']) ) )
  $badges.Add( (New-BadgeHtml -CssClass 'warning'  -Label 'Medium'    -Value ([string]$SeverityCounts['medium']) ) )
  $badges.Add( (New-BadgeHtml -CssClass 'ok'       -Label 'Low'       -Value ([string]$SeverityCounts['low']) ) )
  $badges.Add( (New-BadgeHtml -CssClass 'good'     -Label 'Info'      -Value ([string]$SeverityCounts['info']) ) )
  $badges.Add( (New-BadgeHtml -CssClass 'bad'      -Label 'Total Issues' -Value ([string]$IssueCount) ) )
  $badges.Add( (New-BadgeHtml -CssClass 'good'     -Label 'Healthy Cards' -Value ([string]$GoodCount) ) )
  $badges.Add( (New-BadgeHtml -CssClass 'ok'       -Label 'Modules'   -Value ([string]$ModuleCount) ) )

  return "<div class='report-badge-group'>{0}</div>" -f ($badges -join '')
}

function Build-AreaSummaryTable {
  param([System.Collections.IEnumerable]$Summaries)

  $list = @()
  foreach ($entry in $Summaries) { $list += $entry }
  if ($list.Count -eq 0) {
    return "<div class='report-card'><i>No analyzer output was returned.</i></div>"
  }

  $rows = New-Object System.Collections.Generic.List[string]
  foreach ($entry in $list) {
    $areaHtml = Encode-Html $entry.Area
    $issuesHtml = Encode-Html ([string]$entry.IssueCount)
    $goodHtml = Encode-Html ([string]$entry.GoodCount)
    $scoreHtml = if ($null -ne $entry.Score) { Encode-Html ("{0}" -f $entry.Score) + '%' } else { '—' }
    $rows.Add("<tr><td>$areaHtml</td><td>$issuesHtml</td><td>$goodHtml</td><td>$scoreHtml</td></tr>")
  }

  return "<table class='report-table'><thead><tr><th>Area</th><th>Issues</th><th>Healthy</th><th>Score</th></tr></thead><tbody>{0}</tbody></table>" -f ($rows -join '')
}

function Get-StatusBadgeClass {
  param([string]$Status)

  switch ($Status.ToLowerInvariant()) {
    'pass' { return 'good' }
    'fail' { return 'bad' }
    'warn' { return 'warning' }
    default { return 'ok' }
  }
}

function Build-ChecksTable {
  param([System.Collections.IEnumerable]$Checks)

  $list = @()
  foreach ($check in $Checks) { if ($check) { $list += $check } }

  if ($list.Count -eq 0) {
    return "<div class='report-card'><i>No check records were produced by the analyzers.</i></div>"
  }

  $rows = New-Object System.Collections.Generic.List[string]
  foreach ($check in $list) {
    $areaText = if ($check.Area) { [string]$check.Area } else { 'General' }
    $areaHtml = Encode-Html $areaText
    $nameHtml = Encode-Html ([string]$check.Name)
    $statusValue = if ($check.Status) { [string]$check.Status } else { 'info' }
    $statusClass = Get-StatusBadgeClass $statusValue
    $statusHtml = "<span class='report-badge report-badge--$statusClass'><span class='report-badge__label'>Status</span><span class='report-badge__value'>{0}</span></span>" -f (Encode-Html ($statusValue.ToUpperInvariant()))
    $weightValue = if ($null -ne $check.Weight) { [double]$check.Weight } else { 1.0 }
    $weightHtml = Encode-Html ([string]([math]::Round($weightValue,2)))
    $evidenceHtml = if ($check.Evidence) { Encode-Html ([string]$check.Evidence) } else { '' }
    $rows.Add("<tr><td>$areaHtml</td><td>$nameHtml</td><td>$statusHtml</td><td>$weightHtml</td><td>$evidenceHtml</td></tr>")
  }

  return "<table class='report-table'><thead><tr><th>Area</th><th>Check</th><th>Status</th><th>Weight</th><th>Evidence</th></tr></thead><tbody>{0}</tbody></table>" -f ($rows -join '')
}

function Build-FailureCards {
  param([System.Collections.IEnumerable]$Failures)

  $list = @()
  foreach ($failure in $Failures) { if ($failure) { $list += $failure } }
  if ($list.Count -eq 0) { return '' }

  $cards = New-Object System.Collections.Generic.List[string]
  foreach ($failure in $list) {
    $area = if ($failure.Area) { $failure.Area } else { 'Module' }
    $stage = if ($failure.Stage) { $failure.Stage } else { 'Unknown' }
    $message = if ($failure.Message) { $failure.Message } else { 'Module execution failed.' }
    $details = if ($failure.Details) { $failure.Details } else { $message }

    $summary = "{0} ({1})" -f $area, $stage
    $summaryHtml = Encode-Html $summary
    $messageHtml = Encode-Html $message
    $detailHtml = if ($details) { "<pre class='report-pre'>{0}</pre>" -f (Encode-Html ([string]$details)) } else { '' }

    $cards.Add("<details class='report-card report-card--critical'><summary><span class='report-badge report-badge--critical'>FAIL</span><span class='report-card__summary-text'>$summaryHtml</span></summary><div class='report-card__body'><p class='report-card__explanation'>$messageHtml</p>$detailHtml</div></details>")
  }

  return $cards -join ''
}

function Compute-AreaSummaries {
  param(
    [System.Collections.Generic.List[psobject]]$Issues,
    [System.Collections.Generic.List[psobject]]$Normals,
    [System.Collections.Generic.List[psobject]]$Checks
  )

  $map = [ordered]@{}

  function Ensure-Area([string]$Name){
    if (-not $map.Contains($Name)) {
      $map[$Name] = [ordered]@{
        Area        = $Name
        IssueCount  = 0
        GoodCount   = 0
        PassWeight  = 0.0
        WarnWeight  = 0.0
        FailWeight  = 0.0
        InfoWeight  = 0.0
        TotalWeight = 0.0
        Score       = $null
      }
    }
  }

  foreach ($card in $Issues) {
    $primary = Get-PrimaryArea $card.Area
    Ensure-Area $primary
    $map[$primary].IssueCount++
  }

  foreach ($card in $Normals) {
    $primary = Get-PrimaryArea $card.Area
    Ensure-Area $primary
    $map[$primary].GoodCount++
  }

  foreach ($check in $Checks) {
    $primary = Get-PrimaryArea $check.Area
    Ensure-Area $primary
    $weight = if ($null -ne $check.Weight) { [double]$check.Weight } else { 1.0 }
    $status = if ($check.Status) { $check.Status.ToLowerInvariant() } else { 'info' }

    switch ($status) {
      'pass' { $map[$primary].PassWeight += $weight }
      'fail' { $map[$primary].FailWeight += $weight }
      'warn' { $map[$primary].WarnWeight += $weight }
      default { $map[$primary].InfoWeight += $weight }
    }

    $map[$primary].TotalWeight += $weight
  }

  foreach ($entry in $map.Values) {
    if ($entry.TotalWeight -gt 0) {
      $scoreValue = ($entry.PassWeight + (0.5 * $entry.WarnWeight) + (0.25 * $entry.InfoWeight)) / $entry.TotalWeight
      $entry.Score = [math]::Round($scoreValue * 100)
    }
  }

  return $map.Values
}

function Compute-OverallScore {
  param([System.Collections.IEnumerable]$Summaries)

  $totalWeight = 0.0
  $scoreNumerator = 0.0

  foreach ($entry in $Summaries) {
    if ($entry.TotalWeight -gt 0) {
      $totalWeight += $entry.TotalWeight
      $scoreNumerator += ($entry.PassWeight + (0.5 * $entry.WarnWeight) + (0.25 * $entry.InfoWeight))
    }
  }

  if ($totalWeight -le 0) { return $null }
  return [math]::Round(($scoreNumerator / $totalWeight) * 100)
}

function Build-IssuesContent {
  param([System.Collections.Generic.List[psobject]]$Issues)

  if ($Issues.Count -eq 0) {
    return "<div class='report-card report-card--good'><span class='report-badge report-badge--good'>GOOD</span> No obvious issues detected from the analyzer modules.</div>"
  }

  $severityDefinitions = @(
    @{ Key = 'critical'; Label = 'Critical' },
    @{ Key = 'high';     Label = 'High' },
    @{ Key = 'medium';   Label = 'Medium' },
    @{ Key = 'low';      Label = 'Low' },
    @{ Key = 'info';     Label = 'Info' }
  )

  $groups = @{}
  foreach ($def in $severityDefinitions) {
    $groups[$def.Key] = New-Object System.Collections.Generic.List[pscustomobject]
  }

  foreach ($card in $Issues) {
    $sev = Normalize-Severity $card.Severity
    if (-not $groups.ContainsKey($sev)) { $groups[$sev] = New-Object System.Collections.Generic.List[pscustomobject] }
    $groups[$sev].Add($card)
  }

  $parts = New-Object System.Collections.Generic.List[string]
  foreach ($def in $severityDefinitions) {
    $cards = $groups[$def.Key]
    if (-not $cards -or $cards.Count -eq 0) { continue }
    $heading = Encode-Html ("{0} ({1})" -f $def.Label, $cards.Count)
    $parts.Add("<h3>$heading</h3>")
    $cardHtml = $cards | Sort-Object -Property @{ Expression = { Get-SeverityRank $_.Severity } }, @{ Expression = { $_.Area } }, @{ Expression = { $_.Message } } | ForEach-Object { New-IssueCardHtml -Entry $_ }
    $parts.Add(($cardHtml -join ''))
  }

  return $parts -join ''
}

function Build-GoodContent {
  param([System.Collections.Generic.List[psobject]]$Normals)

  if ($Normals.Count -eq 0) {
    return "<div class='report-card'><i>No specific positives were recorded.</i></div>"
  }

  $groups = $Normals | Group-Object { Get-NormalCategory $_.Area } | Sort-Object Name

  $parts = New-Object System.Collections.Generic.List[string]
  foreach ($group in $groups) {
    $heading = Encode-Html ("{0} ({1})" -f $group.Name, $group.Count)
    $parts.Add("<h3>$heading</h3>")
    $cards = $group.Group | ForEach-Object { New-GoodCardHtml -Entry $_ }
    $parts.Add(($cards -join ''))
  }

  return $parts -join ''
}

function Copy-Styles {
  param([string]$DestinationFolder)

  $repoRoot = Split-Path $PSScriptRoot -Parent
  $cssSources = @(
    Join-Path $repoRoot 'styles/base.css',
    Join-Path $repoRoot 'styles/layout.css',
    Join-Path $PSScriptRoot 'styles/device-health-report.css'
  )

  foreach ($source in $cssSources) {
    if (-not (Test-Path $source)) {
      throw "Required stylesheet not found: $source"
    }
  }

  $cssOutputDir = Join-Path $DestinationFolder 'styles'
  if (-not (Test-Path $cssOutputDir)) {
    New-Item -ItemType Directory -Path $cssOutputDir | Out-Null
  }

  $cssOutputPath = Join-Path $cssOutputDir 'device-health-report.css'
  $cssContent = $cssSources | ForEach-Object { Get-Content -Raw -Path $_ }
  Set-Content -Path $cssOutputPath -Value ($cssContent -join "`n`n") -Encoding UTF8

  return 'styles/device-health-report.css'
}

if (-not (Test-Path $InputFolder)) {
  throw "Input folder '$InputFolder' was not found."
}

$resolvedInput = (Resolve-Path -Path $InputFolder).Path

$moduleDirectory = Join-Path $PSScriptRoot 'Modules'
if (-not (Test-Path $moduleDirectory)) {
  throw "Modules directory not found at $moduleDirectory"
}

$moduleSpecs = @(
  @{ Area = 'System';           Module = 'System.psm1';           Collect = 'Collect-SystemData';           Analyze = 'Analyze-System' },
  @{ Area = 'Hardware';         Module = 'Hardware.psm1';         Collect = 'Collect-HardwareData';         Analyze = 'Analyze-Hardware' },
  @{ Area = 'Network';          Module = 'Network.psm1';          Collect = 'Collect-NetworkData';          Analyze = 'Analyze-Network' },
  @{ Area = 'Security';         Module = 'Security.psm1';         Collect = 'Collect-SecurityData';         Analyze = 'Analyze-Security' },
  @{ Area = 'Services';         Module = 'Services.psm1';         Collect = 'Collect-ServicesData';         Analyze = 'Analyze-Services' },
  @{ Area = 'Office';           Module = 'Office.psm1';           Collect = 'Collect-OfficeData';           Analyze = 'Analyze-Office' },
  @{ Area = 'Active Directory'; Module = 'ActiveDirectory.psm1'; Collect = 'Collect-ActiveDirectoryData'; Analyze = 'Analyze-ActiveDirectory' },
  @{ Area = 'Printing';         Module = 'Printing.psm1';         Collect = 'Collect-PrintingData';         Analyze = 'Analyze-Printing' }
)

$issues   = New-Object System.Collections.Generic.List[psobject]
$normals  = New-Object System.Collections.Generic.List[psobject]
$checks   = New-Object System.Collections.Generic.List[psobject]
$failures = New-Object System.Collections.Generic.List[pscustomobject]

$context = @{
  InputFolder = $resolvedInput
  GeneratedAt = Get-Date
}

foreach ($spec in $moduleSpecs) {
  $modulePath = Join-Path $moduleDirectory $spec.Module
  if (-not (Test-Path $modulePath)) {
    $failures.Add([pscustomobject]@{
      Area    = $spec.Area
      Stage   = 'Import'
      Message = "Module file not found: $modulePath"
      Details = $modulePath
    })
    continue
  }

  try {
    Import-Module -Name $modulePath -Force -ErrorAction Stop | Out-Null
  } catch {
    $failures.Add([pscustomobject]@{
      Area    = $spec.Area
      Stage   = 'Import'
      Message = $_.Exception.Message
      Details = $_.ToString()
    })
    continue
  }

  $data = $null
  try {
    $data = & $spec.Collect -InputFolder $resolvedInput
  } catch {
    $failures.Add([pscustomobject]@{
      Area    = $spec.Area
      Stage   = 'Collect'
      Message = $_.Exception.Message
      Details = $_.ToString()
    })
    continue
  }

  if ($null -eq $data) { $data = [pscustomobject]@{} }

  $analysis = $null
  try {
    $analysis = & $spec.Analyze -Context $context -Data $data
  } catch {
    $failures.Add([pscustomobject]@{
      Area    = $spec.Area
      Stage   = 'Analyze'
      Message = $_.Exception.Message
      Details = $_.ToString()
    })
    continue
  }

  if ($null -eq $analysis) { continue }

  if ($analysis.Cards) {
    foreach ($card in $analysis.Cards) {
      if (-not $card) { continue }
      $normalizedSeverity = Normalize-Severity $card.Severity
      if ($normalizedSeverity -eq 'good') {
        $normals.Add($card)
      } else {
        $issues.Add($card)
      }
    }
  }

  if ($analysis.Checks) {
    foreach ($check in $analysis.Checks) {
      if ($check) { $checks.Add($check) }
    }
  }
}

$areaSummaries = Compute-AreaSummaries -Issues $issues -Normals $normals -Checks $checks
$overallScore = Compute-OverallScore -Summaries $areaSummaries

$severityCounts = @{
  critical = 0
  high     = 0
  medium   = 0
  low      = 0
  info     = 0
}
foreach ($card in $issues) {
  $sev = Normalize-Severity $card.Severity
  if (-not $severityCounts.ContainsKey($sev)) { $severityCounts[$sev] = 0 }
  $severityCounts[$sev] = $severityCounts[$sev] + 1
}

$badgesHtml = Build-SummaryBadges -SeverityCounts $severityCounts -IssueCount $issues.Count -GoodCount $normals.Count -ModuleCount $moduleSpecs.Count -OverallScore $overallScore
$areaSummaryHtml = Build-AreaSummaryTable -Summaries $areaSummaries

$summaryContent = $badgesHtml + $areaSummaryHtml
$summarySection = New-ReportSection -Title 'Summary' -ContentHtml $summaryContent -Open

$issuesContent = Build-IssuesContent -Issues $issues
$issuesSection = New-ReportSection -Title ("Detected Issues ({0})" -f $issues.Count) -ContentHtml $issuesContent -Open

$goodContent = Build-GoodContent -Normals $normals
$goodSection = New-ReportSection -Title ("What Looks Good ({0})" -f $normals.Count) -ContentHtml $goodContent

$checksContent = Build-ChecksTable -Checks $checks
$checksSection = New-ReportSection -Title ("Checks ({0})" -f $checks.Count) -ContentHtml $checksContent

$failSection = $null
if ($failures.Count -gt 0) {
  $failureContent = Build-FailureCards -Failures $failures
  $failSection = New-ReportSection -Title ("Module Failures ({0})" -f $failures.Count) -ContentHtml $failureContent -Open
}

$cssRelativePath = Copy-Styles -DestinationFolder $resolvedInput

$reportName = "DeviceHealth_Report_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
$reportPath = Join-Path $resolvedInput $reportName

$generatedAt = Get-Date
$folderHtml = Encode-Html $resolvedInput
$generatedHtml = Encode-Html ($generatedAt.ToString('u'))

$head = "<!doctype html><html><head><meta charset='utf-8'><title>Device Health Report</title><link rel='stylesheet' href='$cssRelativePath'></head><body class='page report-page'>"
$intro = "<h1>Device health report</h1><p class='report-intro'>Generated $generatedHtml for <code>$folderHtml</code></p>"

$sections = @($summarySection, $issuesSection, $goodSection, $checksSection)
if ($failSection) { $sections += $failSection }

$body = $head + $intro + ($sections -join '') + "</body></html>"
$body | Out-File -FilePath $reportPath -Encoding UTF8

$reportPath
