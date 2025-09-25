# Common helper functions shared across analyzer scripts
$script:SeverityOrder = @('info','warning','low','medium','high','critical')

function Normalize-Severity {
  param($Severity)

  if ($null -eq $Severity) { return '' }

  try {
    $text = [string]$Severity
  } catch {
    $text = [string]$Severity
  }

  if (-not $text) { return '' }

  $trimmed = $text.Trim()
  if (-not $trimmed) { return '' }

  try {
    return $trimmed.ToLowerInvariant()
  } catch {
    return $trimmed.ToLowerInvariant()
  }
}

function Get-SeverityIndex {
  param([string]$Severity)

  if (-not $Severity) { return -1 }

  $normalized = Normalize-Severity $Severity
  if (-not $normalized) { return -1 }

  return $script:SeverityOrder.IndexOf($normalized)
}

function Get-MaxSeverity {
  param([string]$First,[string]$Second)

  if (-not $First) { return $Second }
  if (-not $Second) { return $First }

  $firstIndex = Get-SeverityIndex $First
  $secondIndex = Get-SeverityIndex $Second

  if ($firstIndex -ge $secondIndex) { return $First }
  return $Second
}

function Promote-Severity {
  param(
    [string]$Severity,
    [int]$Steps = 1
  )

  if (-not $Severity) { return $Severity }

  $currentIndex = Get-SeverityIndex $Severity
  if ($currentIndex -lt 0) { return $Severity }

  $target = [math]::Min($script:SeverityOrder.Count - 1, $currentIndex + [math]::Max(0,$Steps))
  return $script:SeverityOrder[$target]
}

function ConvertTo-NullableBool {
  param($Value)

  if ($Value -is [bool]) { return [bool]$Value }
  if ($null -eq $Value) { return $null }

  $stringValue = [string]$Value
  if (-not $stringValue) { return $null }

  $trimmed = $stringValue.Trim()
  if (-not $trimmed) { return $null }

  try {
    $lower = $trimmed.ToLowerInvariant()
  } catch {
    $lower = $trimmed
    if ($lower) { $lower = $lower.ToLowerInvariant() }
  }

  switch ($lower) {
    'true' { return $true }
    'false' { return $false }
    't' { return $true }
    'f' { return $false }
    'yes' { return $true }
    'no' { return $false }
    'y' { return $true }
    'n' { return $false }
    'enabled' { return $true }
    'disabled' { return $false }
    'on' { return $true }
    'off' { return $false }
    default {
      if ($lower -match '^[01]$') { return ($lower -eq '1') }
      return $null
    }
  }
}

function ConvertTo-NullableInt {
  param($Value)

  if ($Value -is [int]) { return [int]$Value }
  if ($null -eq $Value) { return $null }

  $stringValue = [string]$Value
  if (-not $stringValue) { return $null }

  $trimmed = $stringValue.Trim()
  if (-not $trimmed) { return $null }

  $parsed = 0
  if ([int]::TryParse($trimmed, [ref]$parsed)) {
    return $parsed
  }

  return $null
}

function ConvertFrom-JsonSafe {
  param([string]$Text)

  if (-not $Text) { return $null }

  try {
    return $Text | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return $null
  }
}

function ConvertTo-IntArray {
  param($Value)

  if ($null -eq $Value) { return @() }

  if ($Value -is [string]) {
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return @() }
    $clean = ($trimmed -replace '^\{','') -replace '\}$',''
    $parts = [regex]::Split($clean,'[\s,]+') | Where-Object { $_ }
    $result = @()
    foreach ($part in $parts) {
      $parsed = 0
      if ([int]::TryParse($part, [ref]$parsed)) {
        $result += $parsed
      }
    }
    return $result
  }

  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    $result = @()
    foreach ($item in $Value) {
      if ($null -eq $item) { continue }
      $parsed = 0
      if ([int]::TryParse([string]$item, [ref]$parsed)) {
        $result += $parsed
      }
    }
    return $result
  }

  $single = 0
  if ([int]::TryParse([string]$Value, [ref]$single)) {
    return @($single)
  }

  return @()
}

function Get-TopLines {
  param(
    [string]$Text,
    [int]$Count = 12
  )

  if (-not $Text) { return '' }

  $lines = [regex]::Split($Text,'\r?\n')
  return ($lines | Select-Object -First $Count) -join "`n"
}

function Parse-KeyValueBlock {
  param([string]$Text)

  $map = @{}
  if (-not $Text) { return $map }

  $lines = [regex]::Split($Text,'\r?\n')
  $currentKey = $null
  foreach ($line in $lines) {
    if ($null -eq $line) { continue }
    $match = [regex]::Match($line,'^\s*([^:]+?)\s*:\s*(.*)$')
    if ($match.Success) {
      $key = $match.Groups[1].Value.Trim()
      $value = $match.Groups[2].Value.Trim()
      if ($key) {
        $map[$key] = $value
        $currentKey = $key
      }
      continue
    }

    if ($currentKey -and $line.Trim()) {
      $existing = $map[$currentKey]
      if ($existing) {
        $map[$currentKey] = $existing + "`n" + $line.Trim()
      } else {
        $map[$currentKey] = $line.Trim()
      }
    }
  }

  return $map
}

function Convert-DiskBlock {
  param([string]$BlockText)

  if (-not $BlockText) { return $null }

  $props = Parse-KeyValueBlock $BlockText
  if (-not $props -or $props.Count -eq 0) { return $null }

  $operRaw = if ($props.ContainsKey('OperationalStatus')) { $props['OperationalStatus'] } else { '' }
  $healthRaw = if ($props.ContainsKey('HealthStatus')) { $props['HealthStatus'] } else { '' }

  $operStatuses = @()
  if ($operRaw) {
    $operStatuses = ($operRaw -split '\r?\n|,') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }

  $healthStatuses = @()
  if ($healthRaw) {
    $healthStatuses = ($healthRaw -split '\r?\n|,') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }

  return [pscustomobject]@{
    Number            = if ($props.ContainsKey('Number')) { $props['Number'] } else { '' }
    FriendlyName      = if ($props.ContainsKey('FriendlyName')) { $props['FriendlyName'] } else { '' }
    OperationalStatus = $operStatuses
    HealthStatus      = $healthStatuses
    IsBoot            = if ($props.ContainsKey('IsBoot')) { ConvertTo-NullableBool $props['IsBoot'] } else { $null }
    IsSystem          = if ($props.ContainsKey('IsSystem')) { ConvertTo-NullableBool $props['IsSystem'] } else { $null }
    IsOffline         = if ($props.ContainsKey('IsOffline')) { ConvertTo-NullableBool $props['IsOffline'] } else { $null }
    IsReadOnly        = if ($props.ContainsKey('IsReadOnly')) { ConvertTo-NullableBool $props['IsReadOnly'] } else { $null }
    Raw               = $BlockText
  }
}

function Parse-DiskList {
  param([string]$Text)

  $results = @()
  if (-not $Text) { return $results }

  $lines = [regex]::Split($Text,'\r?\n')
  $current = @()

  foreach ($line in $lines) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      if ($current.Count -gt 0) {
        $blockText = ($current -join "`n").Trim()
        $current = @()
        if ($blockText) {
          $parsed = Convert-DiskBlock $blockText
          if ($parsed) { $results += $parsed }
        }
      }
      continue
    }

    $current += $line
  }

  if ($current.Count -gt 0) {
    $blockText = ($current -join "`n").Trim()
    if ($blockText) {
      $parsed = Convert-DiskBlock $blockText
      if ($parsed) { $results += $parsed }
    }
  }

  return ,$results
}

function Normalize-ServiceStatus {
  param([string]$Status)

  if (-not $Status) { return 'unknown' }
  $trimmed = $Status.Trim()
  if (-not $trimmed) { return 'unknown' }

  $lower = $trimmed.ToLowerInvariant()
  switch ($lower) {
    'running' { return 'running' }
    'stopped' { return 'stopped' }
    'paused' { return 'other' }
    'pause pending' { return 'other' }
    'continue pending' { return 'other' }
    'start pending' { return 'other' }
    'stop pending' { return 'other' }
    default { return 'other' }
  }
}

function Normalize-ServiceStartType {
  param([string]$StartType)

  if (-not $StartType) { return 'unknown' }
  $trimmed = $StartType.Trim()
  if (-not $trimmed) { return 'unknown' }

  $lower = $trimmed.ToLowerInvariant()
  if ($lower -like 'automatic*') {
    if ($trimmed -match '(?i)delayed') { return 'automatic-delayed' }
    return 'automatic'
  }
  if ($lower -like 'manual*') { return 'manual' }
  if ($lower -like 'disabled*') { return 'disabled' }
  return 'other'
}

function Parse-ServiceSnapshot {
  param([string]$Text)

  $map = @{}
  if (-not $Text) { return $map }

  $lines = [regex]::Split($Text,'\r?\n')
  foreach ($line in $lines) {
    if (-not $line) { continue }
    $trimmed = $line.Trim()
    if (-not $trimmed) { continue }
    if ($trimmed -match '^(?i)Name\s+Status\s+StartType') { continue }
    if ($trimmed -match '^(?i)-{2,}\s') { continue }

    $parts = $line -split "`t"
    if ($parts.Count -lt 3) { continue }

    $name = $parts[0].Trim()
    if (-not $name) { continue }

    $status = $parts[1].Trim()
    $startType = $parts[2].Trim()
    $displayName = if ($parts.Count -ge 4) { $parts[3].Trim() } else { '' }

    $map[$name] = [pscustomobject]@{
      Name        = $name
      Status      = $status
      StartType   = $startType
      DisplayName = $displayName
      RawLine     = $line.Trim()
    }
  }

  return $map
}

function Encode-Html([string]$s){
  if ($null -eq $s) { return "" }
  try {
    return [System.Web.HttpUtility]::HtmlEncode($s)
  } catch {
    try { return [System.Net.WebUtility]::HtmlEncode([string]$s) } catch { return [string]$s }
  }
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

  $cardClass = if ($Entry.CssClass) { $Entry.CssClass } else { 'info' }
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

function Get-HealthScores {
  param(
    [hashtable]$Checks
  )
  $scores = @{
    Categories = @{}
    Overall = @{ Achieved = 0.0; Max = 0.0; Percent = $null }
  }
  if (-not $Checks) { return $scores }

  $sevScore = @{ critical=0.0; high=0.25; medium=0.5; warning=0.6; low=0.75; info=1.0 }
  foreach($entry in $Checks.GetEnumerator()){
    $c = $entry.Value
    if (-not $c.Attempted) { continue }
    if ($c.NA) { continue }
    $cat = if ($c.Category) { $c.Category } else { 'General' }
    if (-not $scores.Categories.ContainsKey($cat)) {
      $scores.Categories[$cat] = @{ Achieved = 0.0; Max = 0.0; Percent = $null }
    }
    $w = [double]$c.Weight
    $scores.Categories[$cat].Max += $w
    $scores.Overall.Max += $w

    $sev = if ($c.WorstSeverity) { $c.WorstSeverity } else { 'info' }
    $val = $sevScore[$sev]
    if ($null -eq $val) { $val = 1.0 }
    $scores.Categories[$cat].Achieved += ($w * $val)
    $scores.Overall.Achieved += ($w * $val)
  }

  foreach($cat in $scores.Categories.Keys){
    $ach = $scores.Categories[$cat].Achieved
    $mx  = $scores.Categories[$cat].Max
    $scores.Categories[$cat].Percent = if ($mx -eq 0) { $null } else { [math]::Round(100.0 * $ach / $mx, 1) }
  }
  $scores.Overall.Percent = if ($scores.Overall.Max -eq 0) { $null } else { [math]::Round(100.0 * $scores.Overall.Achieved / $scores.Overall.Max, 1) }
  return $scores
}

function Get-CategoryFromArea {
  param([string]$a)

  if (-not $a) { return 'General' }
  $p = $a.Split('/')[0]
  switch -regex ($p) {
    '^OS|^System|^Startup|^Backup|^Firmware|^BitLocker' { 'System'; break }
    '^Storage|^SMART|^Disks|^Volumes|^Hardware' { 'Hardware'; break }
    '^Network|^DNS|^Proxy' { 'Network'; break }
    '^Security|^Firewall|^RDP|^SMB|^Browser|^OfficeHardening' { 'Security'; break }
    '^Services' { 'Services'; break }
    '^Office|^Outlook' { 'Office'; break }
    '^AD|^GPO|^Kerberos|^SecureChannel' { 'Active Directory'; break }
    '^Printing|^Spooler' { 'Printing'; break }
    default { 'General' }
  }
}
