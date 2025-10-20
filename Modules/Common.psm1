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

# Some collectors return a single error string instead of an array. Several analyzer helpers
# call .ToArray() on evidence collections, so add a lightweight shim that wraps strings in a
# single-element array to keep those helpers resilient without special casing every call site.
$stringHasToArray = $false
try {
  $stringTypeData = Get-TypeData -TypeName System.String -ErrorAction Stop
  if ($stringTypeData -and $stringTypeData.PSObject.Properties['Members']) {
    $existingToArray = $stringTypeData.Members['ToArray']
    if ($existingToArray) { $stringHasToArray = $true }
  }
} catch {
  $stringHasToArray = $false
}

if (-not $stringHasToArray) {
  try {
    Update-TypeData -TypeName System.String -MemberType ScriptMethod -MemberName ToArray -Value {
      return ,([string]$this)
    } -ErrorAction Stop
  } catch {
    # Ignore registration failures so module import proceeds normally.
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

function Get-DeviceDisplayName {
  <#
    .SYNOPSIS
      Returns a clean, human-readable device name from common PnP/WMI/CIM objects.

    .DESCRIPTION
      Chooses the best-available property in priority order and trims noise.
      Works with objects from Win32_PnPEntity, Get-PnpDevice, MSFT_NetAdapter, etc.

    .PARAMETER InputObject
      The device object. Supports pipeline.

    .PARAMETER Fallback
      Text to use if no meaningful name can be derived (default: 'Unknown device').

    .EXAMPLE
      Get-PnpDevice | Get-DeviceDisplayName
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [psobject]$InputObject,
    [string]$Fallback = 'Unknown device'
  )

  process {
    $candidates = @(
      'FriendlyName', 'Name', 'ProductName', 'DeviceName',
      'Description', 'Caption', 'DisplayName'
    )

    $value = $null
    foreach ($prop in $candidates) {
      if ($InputObject.PSObject.Properties[$prop] -and
          ($InputObject.$prop -is [string]) -and
          ($InputObject.$prop.Trim()).Length -gt 0) {
        $value = $InputObject.$prop.Trim()
        break
      }
    }

    if (-not $value) {
      foreach ($prop in @('InstanceId','PNPDeviceID','DeviceID','HardwareID')) {
        if ($InputObject.PSObject.Properties[$prop] -and
            ($InputObject.$prop -is [string]) -and
            ($InputObject.$prop.Trim()).Length -gt 0) {
          $value = $InputObject.$prop.Trim()
          break
        }
      }
    }

    if ($value) {
      $value = ($value -replace '\s+', ' ').Trim()
      $value = $value -replace '\s*\(TM\)|\(R\)|\(C\)', ''
      $value = $value.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($value)) { $Fallback } else { $value }
  }
}

function Join-PathSafe {
  param(
    [Parameter(Mandatory=$true)]
    [AllowNull()]
    [AllowEmptyCollection()]
    $Path,
    [Parameter(Mandatory=$true)]
    [string]$ChildPath
  )
  $base = @($Path | Where-Object { $_ })
  if ($base.Count -eq 0) { return $null }
  return Join-Path -Path $base[0] -ChildPath $ChildPath
}

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

    [Alias('FileName')]
    [string[]]$FileNames
  )

  if (-not $InputFolder) { return $null }

  $candidates = New-Object System.Collections.Generic.List[string]
  [void]$candidates.Add('dhcp-base.json')
  if ($FileNames) {
    foreach ($name in $FileNames) {
      if ([string]::IsNullOrWhiteSpace($name)) { continue }
      [void]$candidates.Add($name)
    }
  }

  $visited = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($candidate in $candidates) {
    if (-not $visited.Add($candidate)) { continue }

    $path = Join-Path -Path $InputFolder -ChildPath $candidate
    if (-not (Test-Path -LiteralPath $path)) { continue }

    try {
      $text = Get-Content -Path $path -Raw -ErrorAction Stop
      $json = $text | ConvertFrom-Json -ErrorAction Stop
      return $json.Payload
    } catch {
      return [pscustomobject]@{ Error = $_.Exception.Message; File = $path }
    }
  }

  return $null
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
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Value) {
      if ($null -ne $item) {
        $null = $items.Add($item)
      }
    }
    return $items.ToArray()
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

function Encode-Html([string]$s){
  if ($null -eq $s) { return "" }
  try {
    return [System.Web.HttpUtility]::HtmlEncode($s)
  } catch {
    try { return [System.Net.WebUtility]::HtmlEncode([string]$s) } catch { return [string]$s }
  }
}

function Test-IsSafeRemediationLink {
  param([string]$Uri)

  if ([string]::IsNullOrWhiteSpace($Uri)) { return $false }

  $candidate = $Uri.Trim()
  if (-not $candidate) { return $false }

  $allowedSchemes = @('http', 'https', 'ms-settings', 'control')
  $parsed = $null
  if ([System.Uri]::TryCreate($candidate, [System.UriKind]::Absolute, [ref]$parsed)) {
    $scheme = $parsed.Scheme
    if ($scheme) {
      $normalizedScheme = $scheme.ToLowerInvariant()
      return $allowedSchemes -contains $normalizedScheme
    }
  }

  return $false
}

function Resolve-RemediationTemplateText {
  param(
    [string]$Value,
    [hashtable]$Context
  )

  if ([string]::IsNullOrEmpty($Value)) { return '' }

  $replacement = {
    param($match)
    $key = $match.Groups[1].Value
    if (-not $key) { return '' }
    if (-not $Context) { return '' }
    if (-not ($Context.ContainsKey($key))) { return '' }

    $raw = $Context[$key]
    if ($null -eq $raw) { return '' }
    return [string]$raw
  }

  $pattern = '\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}'
  return [regex]::Replace([string]$Value, $pattern, $replacement)
}

function Test-RemediationStepCondition {
  param(
    $Condition,
    [hashtable]$Context
  )

  if ($null -eq $Condition) { return $true }

  if ($Condition -is [bool]) { return [bool]$Condition }
  if ($Condition -is [int] -or $Condition -is [double]) { return [bool]$Condition }

  if ($Condition -is [string]) {
    $expr = $Condition.Trim()
    if (-not $expr) { return $false }
    if ($expr.IndexOf([char]';') -ge 0 -or $expr.IndexOf([char]'`n') -ge 0 -or $expr.IndexOf([char]'`r') -ge 0) {
      return $false
    }
    if ($expr -match '[^0-9A-Za-z_\.\-!&|=<>\(\)\s\'\"]') { return $false }

    $normalized = $expr
    $normalized = $normalized -replace '!=', ' -ne '
    $normalized = $normalized -replace '==', ' -eq '
    $normalized = $normalized -replace '&&', ' -and '
    $normalized = $normalized -replace '\|\|', ' -or '
    $normalized = [regex]::Replace($normalized, '(?<![<>=!])!', ' -not ')

    $contextTable = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Context) {
      foreach ($key in $Context.Keys) {
        $contextTable[$key] = $Context[$key]
      }
    }

    $builder = [System.Text.StringBuilder]::new()
    $token = [System.Text.StringBuilder]::new()
    $inSingle = $false
    $inDouble = $false
    $flushToken = {
      if ($token.Length -eq 0) { return }
      $word = $token.ToString()
      $token.Clear()
      if (-not $word) { return }

      $lower = $word.ToLowerInvariant()
      switch ($lower) {
        '-and' { [void]$builder.Append(' -and '); return }
        '-or'  { [void]$builder.Append(' -or '); return }
        '-not' { [void]$builder.Append(' -not '); return }
        'and'  { [void]$builder.Append(' -and '); return }
        'or'   { [void]$builder.Append(' -or '); return }
        'not'  { [void]$builder.Append(' -not '); return }
        'true' { [void]$builder.Append('$true'); return }
        'false' { [void]$builder.Append('$false'); return }
        'eq'   { [void]$builder.Append(' -eq '); return }
        'ne'   { [void]$builder.Append(' -ne '); return }
        'gt'   { [void]$builder.Append(' -gt '); return }
        'ge'   { [void]$builder.Append(' -ge '); return }
        'lt'   { [void]$builder.Append(' -lt '); return }
        'le'   { [void]$builder.Append(' -le '); return }
      }

      $numeric = $null
      if ([double]::TryParse($word, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$numeric)) {
        [void]$builder.Append($numeric.ToString([System.Globalization.CultureInfo]::InvariantCulture))
        return
      }

      if ($contextTable.ContainsKey($word)) {
        $escaped = $word.Replace("'", "''")
        [void]$builder.Append("(`$ctx['$escaped'])")
      } else {
        [void]$builder.Append('$null')
      }
    }

    for ($i = 0; $i -lt $normalized.Length; $i++) {
      $ch = $normalized[$i]
      if ($ch -eq '\'') {
        & $flushToken
        $inSingle = -not $inSingle
        [void]$builder.Append($ch)
        continue
      }
      if ($ch -eq '"') {
        & $flushToken
        $inDouble = -not $inDouble
        [void]$builder.Append($ch)
        continue
      }

      if (-not $inSingle -and -not $inDouble) {
        if ([char]::IsLetterOrDigit($ch) -or $ch -eq '_' -or $ch -eq '.' -or $ch -eq '-') {
          [void]$token.Append($ch)
          continue
        }

        & $flushToken
        [void]$builder.Append($ch)
        continue
      }

      [void]$builder.Append($ch)
    }

    & $flushToken
    $psExpression = $builder.ToString()
    if ([string]::IsNullOrWhiteSpace($psExpression)) { return $false }

    try {
      $script = [scriptblock]::Create($psExpression)
      $ctx = $contextTable
      $result = $script.InvokeWithContext($null, @{ ctx = $ctx }, $null)
      return [bool]$result
    } catch {
      return $false
    }
  }

  return [bool]$Condition
}

function ConvertTo-StructuredRemediationHtml {
  param(
    [System.Collections.IEnumerable]$Steps,
    [hashtable]$Context
  )

  if (-not $Steps) { return '' }

  $contextTable = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
  if ($Context) {
    foreach ($key in $Context.Keys) {
      $contextTable[$key] = $Context[$key]
    }
  }

  $codeFunction = $null
  try {
    $codeFunction = Get-Command -Name New-CodeBlockHtml -CommandType Function -ErrorAction Stop
  } catch {
    $codeFunction = $null
  }

  $builder = [System.Text.StringBuilder]::new()
  $index = 0
  foreach ($rawStep in $Steps) {
    $index++
    if (-not $rawStep) { continue }

    $step = $rawStep
    if (-not ($step -is [psobject])) { $step = [pscustomobject]$rawStep }

    if ($step.PSObject.Properties['if']) {
      if (-not (Test-RemediationStepCondition -Condition $step.if -Context $contextTable)) { continue }
    }

    $type = 'text'
    if ($step.PSObject.Properties['type'] -and $step.type) {
      try {
        $type = [string]$step.type
      } catch {
        $type = 'text'
      }
    }

    if ([string]::IsNullOrWhiteSpace($type)) { $type = 'text' }
    try { $type = $type.ToLowerInvariant() } catch { $type = 'text' }

    $title = $null
    if ($step.PSObject.Properties['title']) {
      $title = Resolve-RemediationTemplateText -Value $step.title -Context $contextTable
    }

    $content = $null
    if ($step.PSObject.Properties['content']) {
      $content = Resolve-RemediationTemplateText -Value $step.content -Context $contextTable
    }

    $classList = @('rem-step')
    if ($type) { $classList += "rem-step--$type" }
    $classAttr = ($classList -join ' ')
    [void]$builder.Append("<div class='$classAttr'>")

    if (-not [string]::IsNullOrWhiteSpace($title)) {
      $encodedTitle = Encode-Html $title
      [void]$builder.Append("<h4>$encodedTitle</h4>")
    }

    switch ($type) {
      'code' {
        if ([string]::IsNullOrWhiteSpace($content)) { break }

        $language = 'powershell'
        if ($step.PSObject.Properties['lang']) {
          $langCandidate = Resolve-RemediationTemplateText -Value $step.lang -Context $contextTable
          if (-not [string]::IsNullOrWhiteSpace($langCandidate)) { $language = $langCandidate }
        }

        $codeBlockHtml = $null
        if ($codeFunction) {
          try {
            $codeBlockHtml = New-CodeBlockHtml -Language $language -Code $content
          } catch {
            $codeBlockHtml = $null
          }
        }

        if ([string]::IsNullOrWhiteSpace($codeBlockHtml)) {
          $codeId = 'remediation-' + ([guid]::NewGuid().ToString('N'))
          $encodedCode = Encode-Html $content
          $langKey = if ($language) { $language.ToString().ToLowerInvariant() } else { 'powershell' }
          $langClass = [regex]::Replace($langKey, "[^a-z0-9\-]+", '')
          if ([string]::IsNullOrWhiteSpace($langClass)) { $langClass = 'code' }
          $preClasses = if ($langClass -eq 'powershell') { " class='line-numbers'" } else { '' }
          $copyLabel = Encode-Html 'Copy'
          $successLabel = Encode-Html 'Copied!'
          $failureLabel = Encode-Html 'Copy failed'
          $badge = if ($language) { $language } else { 'Code' }
          $badgeLabel = Encode-Html $badge
          $toolbar = "<div class='code-toolbar' role='toolbar' aria-label='Code toolbar'><div class='code-toolbar__meta'><span class='lang-badge'>$badgeLabel</span></div><div class='code-actions'><button class='btn' type='button' data-copy='#$codeId' data-copy-target='#$codeId' data-copy-success='$successLabel' data-copy-failure='$failureLabel'>$copyLabel</button></div></div>"
          [void]$builder.Append("<div class='code-card'>$toolbar<pre$preClasses><code class='language-$langClass' id='$codeId'>$encodedCode</code></pre></div>")
        } else {
          [void]$builder.Append($codeBlockHtml)
        }
      }
      'note' {
        if (-not [string]::IsNullOrWhiteSpace($content)) {
          $encoded = Encode-Html $content
          $encoded = [regex]::Replace($encoded, '\\r?\\n', '<br>')
          [void]$builder.Append("<p class='rem-note'>$encoded</p>")
        }
      }
      default {
        if (-not [string]::IsNullOrWhiteSpace($content)) {
          $encoded = Encode-Html $content
          $encoded = [regex]::Replace($encoded, '\\r?\\n', '<br>')
          [void]$builder.Append("<p class='rem-text report-remediation__text'>$encoded</p>")
        }
      }
    }

    [void]$builder.Append('</div>')
  }

  return $builder.ToString()
}

function ConvertTo-LegacyRemediationHtml {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

  $builder = [System.Text.StringBuilder]::new()
  $cursor = 0
  $pattern = '\\[([^\\]]+)\\]\\(([^)]+)\\)'
  foreach ($match in [regex]::Matches($Text, $pattern)) {
    if (-not $match) { continue }

    if ($match.Index -gt $cursor) {
      $segment = $Text.Substring($cursor, $match.Index - $cursor)
      [void]$builder.Append((Encode-Html $segment))
    }

    $linkText = $match.Groups[1].Value
    $linkTarget = $match.Groups[2].Value
    if (Test-IsSafeRemediationLink -Uri $linkTarget) {
      $encodedTarget = Encode-Html $linkTarget.Trim()
      $encodedText = Encode-Html $linkText
      [void]$builder.Append("<a class='report-link' href='$encodedTarget'>$encodedText</a>")
    } else {
      [void]$builder.Append((Encode-Html $match.Value))
    }

    $cursor = $match.Index + $match.Length
  }

  if ($cursor -lt $Text.Length) {
    $remaining = $Text.Substring($cursor)
    [void]$builder.Append((Encode-Html $remaining))
  }

  $result = $builder.ToString()
  if (-not [string]::IsNullOrEmpty($result)) {
    $result = [regex]::Replace($result, '\\r?\\n', '<br>')
  }

  if ([string]::IsNullOrWhiteSpace($result)) { return '' }
  return "<p class='report-remediation__text'>$result</p>"
}

function ConvertTo-RemediationHtml {
  param(
    [string]$Text,
    [hashtable]$Context
  )

  if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

  $trimmed = $Text.Trim()
  if ($trimmed.StartsWith('[')) {
    try {
      $parsed = $trimmed | ConvertFrom-Json -Depth 10
      if ($parsed -is [System.Collections.IEnumerable]) {
        $structured = ConvertTo-StructuredRemediationHtml -Steps $parsed -Context $Context
        if (-not [string]::IsNullOrWhiteSpace($structured)) { return $structured }
      }
    } catch {
      # Ignore JSON parsing failures and fall back to legacy behaviour.
    }
  }

  return ConvertTo-LegacyRemediationHtml -Text $Text
}

function New-IssueCardHtml {
  param(
    [pscustomobject]$Entry
  )

  $normalizedSeverity = ConvertTo-NormalizedSeverity $Entry.Severity
  $cardClass = if ($Entry.CssClass) { $Entry.CssClass } else { 'info' }
  $badgeText = if ($Entry.BadgeText) { $Entry.BadgeText } elseif ($Entry.Severity) { $Entry.Severity.ToUpperInvariant() } else { 'ISSUE' }
  $badgeHtml = Encode-Html $badgeText
  $areaHtml = Encode-Html $Entry.Area
  $resolvedTitle = $null
  $troubleshootingHtml = $null
  $messageValue = if ($null -ne $Entry.Message) { $Entry.Message } else { '' }

  $remediationContext = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
  $addContextValue = {
    param($name, $value)
    if (-not $name) { return }
    if ($remediationContext.ContainsKey($name)) { return }
    $remediationContext[$name] = $value
  }
  $addContextSource = {
    param($source)
    if (-not $source) { return }
    if ($source -is [System.Collections.IDictionary]) {
      foreach ($key in $source.Keys) {
        if (-not $remediationContext.ContainsKey($key)) {
          $remediationContext[$key] = $source[$key]
        }
      }
      return
    }
    $props = @()
    try { $props = $source | Get-Member -MemberType NoteProperty,AliasProperty -ErrorAction Stop } catch { $props = @() }
    foreach ($prop in $props) {
      $name = $prop.Name
      if (-not $remediationContext.ContainsKey($name)) {
        try { $remediationContext[$name] = $source.$name } catch { }
      }
    }
  }

  foreach ($propName in @('Area', 'Severity', 'Title', 'Message', 'RenderTitle', 'CheckId')) {
    if ($Entry.PSObject.Properties[$propName]) {
      try { & $addContextValue $propName $Entry.$propName } catch { }
    }
  }

  if ($Entry.PSObject.Properties['Data']) { & $addContextSource $Entry.Data }
  if ($Entry.PSObject.Properties['Payload']) { & $addContextSource $Entry.Payload }
  if ($Entry.PSObject.Properties['Meta']) { & $addContextSource $Entry.Meta }
  if ($Entry.PSObject.Properties['Context']) { & $addContextSource $Entry.Context }
  if ($Entry.PSObject.Properties['RemediationContext']) { & $addContextSource $Entry.RemediationContext }

  $tshootCommand = $null
  try { $tshootCommand = Get-Command -Name Get-TroubleshootingForCard -ErrorAction Stop } catch { $tshootCommand = $null }
  if ($tshootCommand) {
    $titleForLookup = if ($Entry.PSObject.Properties['Title'] -and $Entry.Title) { $Entry.Title } else { $messageValue }
    $areaForLookup = if ($Entry.Area) { $Entry.Area } else { '' }
    $checkIdForLookup = if ($Entry.PSObject.Properties['CheckId']) { $Entry.CheckId } else { $null }

    try {
      $tsCardOriginal = Get-TroubleshootingForCard -CheckId $checkIdForLookup -Area $areaForLookup -Title $titleForLookup
    } catch {
      $tsCardOriginal = $null
    }

    if ($tsCardOriginal) {
      $tsCard = $tsCardOriginal
      try {
        $tsCard = $tsCardOriginal | ConvertTo-Json -Depth 10 | ConvertFrom-Json
      } catch {
        try { $tsCard = $tsCardOriginal | Select-Object * } catch { $tsCard = $tsCardOriginal }
      }

      $bind = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
      foreach ($key in $remediationContext.Keys) {
        $bind[$key] = $remediationContext[$key]
      }
      $addSource = {
        param($source)
        if (-not $source) { return }
        if ($source -is [System.Collections.IDictionary]) {
          foreach ($key in $source.Keys) {
            if (-not $bind.ContainsKey($key)) { $bind[$key] = $source[$key] }
          }
          return
        }
        $props = @()
        try { $props = $source | Get-Member -MemberType *Property -ErrorAction Stop } catch { $props = @() }
        foreach ($prop in $props) {
          $name = $prop.Name
          if (-not $bind.ContainsKey($name)) {
            try { $bind[$name] = $source.$name } catch { }
          }
        }
      }

      if ($Entry.PSObject.Properties['Data']) { & $addSource $Entry.Data }
      if ($Entry.PSObject.Properties['Payload']) { & $addSource $Entry.Payload }
      if ($Entry.PSObject.Properties['Meta']) { & $addSource $Entry.Meta }

      $templateCommand = Get-Command -Name Resolve-Template -ErrorAction SilentlyContinue
      $templateSafeCommand = Get-Command -Name Resolve-TemplateSafe -ErrorAction SilentlyContinue
      $titleFallback = if (-not [string]::IsNullOrWhiteSpace($messageValue)) { $messageValue } else { $titleForLookup }
      if ($tsCard.title_template) {
        if ($templateSafeCommand) {
          $candidate = Resolve-TemplateSafe -Template $tsCard.title_template -Data $bind -Fallback $titleFallback
          if (-not [string]::IsNullOrWhiteSpace($candidate)) { $resolvedTitle = $candidate }
        } elseif ($templateCommand) {
          try {
            $candidate = Resolve-Template -Template $tsCard.title_template -Data $bind
          } catch {
            $candidate = $null
          }
          if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = $titleFallback }
          if (-not [string]::IsNullOrWhiteSpace($candidate)) { $resolvedTitle = $candidate }
        }
      }

      if ($templateCommand) {
        if ($tsCard.troubleshooting) {
          if ($tsCard.troubleshooting.overview) {
            $tsCard.troubleshooting.overview = Resolve-Template -Template $tsCard.troubleshooting.overview -Data $bind
          }
          if ($tsCard.troubleshooting.scenarios) {
            foreach ($sc in $tsCard.troubleshooting.scenarios) {
              if (-not $sc) { continue }
              if ($sc.title) { $sc.title = Resolve-Template -Template $sc.title -Data $bind }
              if ($sc.steps) { $sc.steps = @($sc.steps | ForEach-Object { Resolve-Template -Template $_ -Data $bind }) }
              if ($sc.validation) { $sc.validation = @($sc.validation | ForEach-Object { Resolve-Template -Template $_ -Data $bind }) }
              if ($sc.roll_back) { $sc.roll_back = @($sc.roll_back | ForEach-Object { Resolve-Template -Template $_ -Data $bind }) }
              if ($sc.scripts) {
                foreach ($scriptEntry in $sc.scripts) {
                  if ($scriptEntry.name) { $scriptEntry.name = Resolve-Template -Template $scriptEntry.name -Data $bind }
                  if ($scriptEntry.code) { $scriptEntry.code = Resolve-Template -Template $scriptEntry.code -Data $bind }
                }
              }
            }
          }
        }
      }

      $tsHtmlCommand = Get-Command -Name New-TroubleshootingHtml -ErrorAction SilentlyContinue
      if ($tsHtmlCommand -and $tsCard.troubleshooting) {
        try { $troubleshootingHtml = New-TroubleshootingHtml -Card $tsCard } catch { $troubleshootingHtml = $null }
      }
      foreach ($key in $bind.Keys) {
        if (-not $remediationContext.ContainsKey($key)) {
          $remediationContext[$key] = $bind[$key]
        }
      }
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($resolvedTitle)) {
    $Entry.RenderTitle = $resolvedTitle
    $messageValue = $resolvedTitle
  } elseif ($Entry.PSObject.Properties['RenderTitle'] -and -not [string]::IsNullOrWhiteSpace($Entry.RenderTitle)) {
    $messageValue = $Entry.RenderTitle
  }
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

  if (-not [string]::IsNullOrWhiteSpace($troubleshootingHtml)) {
    [void]$bodyBuilder.Append($troubleshootingHtml)
  }

  $hasRemediation = -not [string]::IsNullOrWhiteSpace($Entry.Remediation)
  $hasRemediationScript = -not [string]::IsNullOrWhiteSpace($Entry.RemediationScript)
  if ($hasRemediation -or $hasRemediationScript) {
    $remediationBuilder = [System.Text.StringBuilder]::new()
    [void]$remediationBuilder.Append("<details class='report-remediation'><summary class='report-remediation__summary'>Remediation</summary><div class='report-remediation__body'>")

    if ($hasRemediation) {
      $remediationHtml = ConvertTo-RemediationHtml -Text $Entry.Remediation -Context $remediationContext
      if (-not [string]::IsNullOrWhiteSpace($remediationHtml)) {
        [void]$remediationBuilder.Append($remediationHtml)
      }
    }

    if ($hasRemediationScript) {
      $scriptContent = [string]$Entry.RemediationScript
      $codeBlockHtml = $null
      try {
        $codeFunction = Get-Command -Name New-CodeBlockHtml -CommandType Function -ErrorAction SilentlyContinue
      } catch {
        $codeFunction = $null
      }

      if ($codeFunction) {
        try {
          $codeBlockHtml = New-CodeBlockHtml -Language 'powershell' -Code $scriptContent -Caption 'Remediation script'
        } catch {
          $codeBlockHtml = $null
        }
      }

      if ([string]::IsNullOrWhiteSpace($codeBlockHtml)) {
        $codeId = 'remediation-' + ([guid]::NewGuid().ToString('N'))
        $codeHtml = Encode-Html $scriptContent
        $buttonLabel = Encode-Html 'Copy PowerShell'
        $successLabel = Encode-Html 'Copied!'
        $failureLabel = Encode-Html 'Copy failed'
        $fallback = "<div class='report-remediation__code'><button type='button' class='report-copy-button' data-copy-target='#$codeId' data-copy-success='$successLabel' data-copy-failure='$failureLabel'>$buttonLabel</button><pre class='report-pre'><code id='$codeId' class='language-powershell'>$codeHtml</code></pre></div>"
        [void]$remediationBuilder.Append($fallback)
      } else {
        [void]$remediationBuilder.Append("<div class='report-remediation__code'>$codeBlockHtml</div>")
      }
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
  [void]$cardBuilder.Append("<div class='report-card__body'><details class='report-evidence' open><summary class='report-evidence__summary'>Evidence</summary><div class='report-evidence__body'><pre class='report-pre'>$evidenceHtml</pre></div></details></div>")

  [void]$cardBuilder.Append("</details>")
  return $cardBuilder.ToString()
}

