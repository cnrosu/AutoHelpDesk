# Common helper functions shared across analyzer scripts

# Ensure ordered dictionaries support ContainsKey like hashtables for compatibility.
if (-not ([System.Collections.Specialized.OrderedDictionary].GetMethods() | Where-Object { $_.Name -eq 'ContainsKey' })) {
  try {
    Update-TypeData -TypeName System.Collections.Specialized.OrderedDictionary -MemberType ScriptMethod -MemberName ContainsKey -Value {
      param($Key)
      return $this.Contains($Key)
    } -ErrorAction Stop
  } catch {
    # If type data registration fails, continue without interrupting import.
  }
}

$script:SeverityOrder = @('info','warning','low','medium','high','critical')

$script:RegexSplitWhitespaceComma = [System.Text.RegularExpressions.Regex]::new(
  '[\s,]+',
  [System.Text.RegularExpressions.RegexOptions]::Compiled
)
$script:RegexNewLine = [System.Text.RegularExpressions.Regex]::new(
  '\r?\n',
  [System.Text.RegularExpressions.RegexOptions]::Compiled
)
$script:RegexKeyValueLine = [System.Text.RegularExpressions.Regex]::new(
  '^\s*([^:]+?)\s*:\s*(.*)$',
  [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# DHCP analyzers expect Write-DhcpDebug and related helpers. Prefer the central
# analyzer logger when available but gracefully fall back to verbose output so
# the helpers remain useful when executed standalone.
function Write-DhcpDebug {
  [CmdletBinding()]
  param(
    # Main debug message. If omitted but -Data is supplied, the data will be logged.
    [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    $Message,

    # Tag the area for your common logger
    [string] $Area = 'Network/DHCP',

    # Optional structured object to include alongside the message
    [Alias('Object')]
    [object] $Data,

    # When falling back (no Write-AnalyzerDebug), emit Data as JSON instead of table text
    [switch] $AsJson
  )

  begin {
    $heuristicCmd = Get-Command Write-HeuristicDebug -ErrorAction SilentlyContinue
    $analyzerCmd = Get-Command Write-AnalyzerDebug -ErrorAction SilentlyContinue
    $supportsData = $false
    if ($analyzerCmd) {
      try { $supportsData = $analyzerCmd.Parameters.ContainsKey('Data') } catch { $supportsData = $false }
    }
  }

  process {
    $msg = if ($PSBoundParameters.ContainsKey('Message') -and $null -ne $Message) {
      [string]$Message
    } elseif ($PSBoundParameters.ContainsKey('Data') -and $null -ne $Data) {
      # If no explicit message, derive a compact one from Data
      try { ($Data | ConvertTo-Json -Depth 3 -Compress) } catch { ($Data | Out-String).Trim() }
    } else {
      ''
    }

    if ($heuristicCmd) {
      $arguments = @{ Source = $Area; Message = $msg }
      if ($PSBoundParameters.ContainsKey('Data') -and $null -ne $Data) { $arguments.Data = $Data }
      & $heuristicCmd @arguments
      return
    }

    if ($analyzerCmd) {
      # Prefer centralized analyzer logger
      $splat = @{ Area = $Area; Message = $msg }
      if ($supportsData -and $PSBoundParameters.ContainsKey('Data')) { $splat.Data = $Data }
      & $analyzerCmd @splat
      return
    }

    # Fallback: Write-Verbose lines
    if ($msg) { Write-Verbose ("[{0}] {1}" -f $Area, $msg) }
    if ($PSBoundParameters.ContainsKey('Data') -and $null -ne $Data) {
      try {
        if ($AsJson) {
          Write-Verbose ("[{0}] DATA: {1}" -f $Area, ($Data | ConvertTo-Json -Depth 3 -Compress))
        } else {
          Write-Verbose ("[{0}] DATA:`n{1}" -f $Area, (($Data | Out-String).Trim()))
        }
      } catch {
        Write-Verbose ("[{0}] DATA: {1}" -f $Area, ($Data.ToString()))
      }
    }
  }
}

function Get-DhcpCollectorPayload {
  param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Parameter(Mandatory)]
    [string]$FileName
  )

  $path = Join-Path -Path $InputFolder -ChildPath $FileName
  if (-not (Test-Path -Path $path)) { return $null }

  try {
    $text = Get-Content -Path $path -Raw -ErrorAction Stop
    $json = $text | ConvertFrom-Json -ErrorAction Stop
    return $json.Payload
  } catch {
    return [pscustomobject]@{ Error = $_.Exception.Message; File = $path }
  }
}

function ConvertFrom-Iso8601 {
  param([string]$Text)

  if (-not $Text) { return $null }

  $trimmed = $Text.Trim()
  if (-not $trimmed) { return $null }

  $result = [datetime]::MinValue
  if ([datetime]::TryParse($trimmed, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$result)) {
    return $result
  }

  try {
    return [datetime]::Parse($trimmed)
  } catch {
    return $null
  }
}

function Ensure-Array {
  param($Value)

  if ($null -eq $Value) { return @() }
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    $out = @()
    foreach ($item in $Value) { if ($null -ne $item) { $out += $item } }
    return $out
  }
  return @($Value)
}

function Get-AdapterIdentity {
  param($Adapter)

  if ($null -eq $Adapter) { return 'Unknown adapter' }

  $partsBuilder = [System.Text.StringBuilder]::new()
  $appendPart = {
    param([string]$value)
    if (-not [string]::IsNullOrWhiteSpace($value)) {
      if ($partsBuilder.Length -gt 0) { [void]$partsBuilder.Append(' | ') }
      [void]$partsBuilder.Append($value)
    }
  }

  if ($Adapter.Description) { & $appendPart ([string]$Adapter.Description) }
  elseif ($Adapter.Caption) { & $appendPart ([string]$Adapter.Caption) }

  $indexValue = $null
  if ($Adapter.PSObject.Properties['InterfaceIndex'] -and $null -ne $Adapter.InterfaceIndex) {
    $indexValue = $Adapter.InterfaceIndex
  } elseif ($Adapter.PSObject.Properties['Index'] -and $null -ne $Adapter.Index) {
    $indexValue = $Adapter.Index
  }
  if ($null -ne $indexValue) {
    & $appendPart ("Index $indexValue")
  }

  if ($Adapter.MACAddress) { & $appendPart ("MAC $($Adapter.MACAddress)") }

  if ($partsBuilder.Length -eq 0) { return 'Unknown adapter' }
  return $partsBuilder.ToString()
}

function Get-AdapterIpv4Addresses {
  param($Adapter)

  $addresses = @()
  $raw = $null
  if ($Adapter.PSObject.Properties['IPAddress']) { $raw = $Adapter.IPAddress }
  if (-not $raw) { return @() }

  foreach ($value in (Ensure-Array $raw)) {
    if ($value -match '^\s*$') { continue }
    $candidate = $value.Trim()
    if ($candidate -match '^\d+\.\d+\.\d+\.\d+$') {
      $addresses += $candidate
    }
  }

  return $addresses
}

function Test-IsPrivateIPv4 {
  param([string]$Address)

  if (-not $Address) { return $false }

  if ($Address -match '^10\.') { return $true }
  if ($Address -match '^192\.168\.') { return $true }
  if ($Address -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
  return $false
}

function Test-IsApipaIPv4 {
  param([string]$Address)

  if (-not $Address) { return $false }
  return $Address -match '^169\.254\.'
}

function Format-StringList {
  param($Values)

  $array = Ensure-Array $Values
  $clean = $array | Where-Object { $_ -and $_.Trim() }
  if (-not $clean) { return '' }

  $trimmedValues = [System.Collections.Generic.List[string]]::new()
  foreach ($value in $clean) {
    $null = $trimmedValues.Add($value.Trim())
  }

  return ($trimmedValues -join ', ')
}

function New-DhcpFinding {
  param(
    [string]$Check,
    [string]$Severity,
    [string]$Message,
    [hashtable]$Evidence
  )

  return [pscustomobject]@{
    Category    = 'Network'
    Subcategory = 'DHCP'
    Check       = $Check
    Severity    = $Severity
    Message     = $Message
    Evidence    = $Evidence
  }
}

function ConvertTo-NormalizedSeverity {
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

  $normalized = ConvertTo-NormalizedSeverity $Severity
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

function ConvertTo-EscalatedSeverity {
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

function ConvertTo-NullableDouble {
  param($Value)

  if ($Value -is [double]) { return [double]$Value }
  if ($Value -is [single]) { return [double]$Value }
  if ($null -eq $Value) { return $null }

  $stringValue = [string]$Value
  if (-not $stringValue) { return $null }

  $trimmed = $stringValue.Trim()
  if (-not $trimmed) { return $null }

  $parsed = 0.0
  if ([double]::TryParse($trimmed, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
    return $parsed
  }

  $normalized = ($trimmed -replace '(?i)[^0-9eE\+\-\.,]', '')
  if ([string]::IsNullOrWhiteSpace($normalized)) { return $null }
  $normalized = $normalized -replace ',', '.'

  if ([double]::TryParse($normalized, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
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
    $parts = $script:RegexSplitWhitespaceComma.Split($clean) | Where-Object { $_ }
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

  $lines = $script:RegexNewLine.Split($Text)
  return ($lines | Select-Object -First $Count) -join "`n"
}

function Parse-KeyValueBlock {
  param([string]$Text)

  $map = @{}
  if (-not $Text) { return $map }

  $lines = $script:RegexNewLine.Split($Text)
  $currentKey = $null
  foreach ($line in $lines) {
    if ($null -eq $line) { continue }
    $match = $script:RegexKeyValueLine.Match($line)
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

  $lines = $script:RegexNewLine.Split($Text)
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

  $lines = $script:RegexNewLine.Split($Text)
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
    [switch]$Open,
    [string]$Id
  )

  $openAttr = if ($Open.IsPresent) { ' open' } else { '' }
  $titleValue = if ($null -ne $Title) { $Title } else { '' }
  $titleHtml = Encode-Html $titleValue
  $bodyHtml = if ($null -ne $ContentHtml) { $ContentHtml } else { '' }

  $idAttr = ''
  if ($PSBoundParameters.ContainsKey('Id') -and -not [string]::IsNullOrWhiteSpace($Id)) {
    $trimmedId = $Id.Trim()
    if ($trimmedId) {
      $safeId = [regex]::Replace($trimmedId.ToLowerInvariant(), '[^a-z0-9\-_]+', '-')
      $safeId = [regex]::Replace($safeId, '^-+|-+$', '')
      if (-not $safeId) {
        $safeId = [regex]::Replace($trimmedId, '\\s+', '-')
      }

      if ($safeId) {
        $idAttr = " id='$safeId'"
      }
    }
  }

  return "<details$idAttr class='report-section'$openAttr><summary>$titleHtml</summary><div class='report-section__content'>$bodyHtml</div></details>"
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

  $bodyBuilder = [System.Text.StringBuilder]::new()

  if (-not [string]::IsNullOrWhiteSpace($Entry.Explanation)) {
    $explanationHtml = Encode-Html $Entry.Explanation
    [void]$bodyBuilder.Append("<p class='report-card__explanation'>$explanationHtml</p>")
  }

  if (-not [string]::IsNullOrWhiteSpace($Entry.Evidence)) {
    $evidenceHtml = Encode-Html $Entry.Evidence
    [void]$bodyBuilder.Append("<details class='report-evidence'><summary class='report-evidence__summary'>Evidence</summary><div class='report-evidence__body'><pre class='report-pre'>$evidenceHtml</pre></div></details>")
  }

  $hasRemediation = -not [string]::IsNullOrWhiteSpace($Entry.Remediation)
  $hasRemediationScript = -not [string]::IsNullOrWhiteSpace($Entry.RemediationScript)
  if ($hasRemediation -or $hasRemediationScript) {
    $remediationBuilder = [System.Text.StringBuilder]::new()
    [void]$remediationBuilder.Append("<details class='report-remediation'><summary class='report-remediation__summary'>Remediation</summary><div class='report-remediation__body'>")

    if ($hasRemediation) {
      $remediationHtml = Encode-Html $Entry.Remediation
      $remediationHtml = [regex]::Replace($remediationHtml, '\\r?\\n', '<br>')
      [void]$remediationBuilder.Append("<p class='report-remediation__text'>$remediationHtml</p>")
    }

    if ($hasRemediationScript) {
      $codeId = 'remediation-' + ([guid]::NewGuid().ToString('N'))
      $codeHtml = Encode-Html $Entry.RemediationScript
      $buttonLabel = Encode-Html 'Copy PowerShell'
      $successLabel = Encode-Html 'Copied!'
      $failureLabel = Encode-Html 'Copy failed'
      [void]$remediationBuilder.Append("<div class='report-remediation__code'><button type='button' class='report-copy-button' data-copy-target='#$codeId' data-copy-success='$successLabel' data-copy-failure='$failureLabel'>$buttonLabel</button><pre class='report-pre'><code id='$codeId' class='language-powershell'>$codeHtml</code></pre></div>")
    }

    [void]$remediationBuilder.Append('</div></details>')
    [void]$bodyBuilder.Append($remediationBuilder.ToString())
  }

  $badgeFragment = "<span class='report-badge report-badge--$cardClass'>$badgeHtml</span>"
  $summaryFragment = "<span class='report-card__summary-text'>$summaryText</span>"

  if ($bodyBuilder.Length -eq 0) {
    return "<div class='report-card report-card--$cardClass report-card--static'>$badgeFragment$summaryFragment</div>"
  }

  $cardBuilder = [System.Text.StringBuilder]::new()
  [void]$cardBuilder.Append("<details class='report-card report-card--$cardClass'><summary>$badgeFragment$summaryFragment</summary>")

  if ($bodyBuilder.Length -gt 0) {
    [void]$cardBuilder.Append("<div class='report-card__body'>")
    [void]$cardBuilder.Append($bodyBuilder.ToString())
    [void]$cardBuilder.Append("</div>")
  }

  [void]$cardBuilder.Append("</details>")
  return $cardBuilder.ToString()
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

  if ([string]::IsNullOrWhiteSpace($Entry.Evidence)) {
    return "<div class='report-card report-card--$cardClass report-card--static'><span class='report-badge report-badge--$cardClass'>$badgeHtml</span><span class='report-card__summary-text'>$summaryText</span></div>"
  }

  $cardBuilder = [System.Text.StringBuilder]::new()
  [void]$cardBuilder.Append("<details class='report-card report-card--$cardClass'><summary><span class='report-badge report-badge--$cardClass'>$badgeHtml</span><span class='report-card__summary-text'>$summaryText</span></summary>")

  $evidenceHtml = Encode-Html $Entry.Evidence
  [void]$cardBuilder.Append("<div class='report-card__body'><details class='report-evidence'><summary class='report-evidence__summary'>Evidence</summary><div class='report-evidence__body'><pre class='report-pre'>$evidenceHtml</pre></div></details></div>")

  [void]$cardBuilder.Append("</details>")
  return $cardBuilder.ToString()
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
