# Common helpers (dot-sourced). Extracted unchanged from Analyze-Diagnostics.ps1.

function Read-Text($path) {
  if (Test-Path $path) { return (Get-Content $path -Raw -ErrorAction SilentlyContinue) } else { return "" }
}

$allTxt = Get-ChildItem -Path $InputFolder -Recurse -File -Include *.txt,*.log,*.csv,*.tsv 2>$null

function Find-ByContent([string[]]$nameHints, [string[]]$needles) {
  if ($nameHints) {
    $byName = $allTxt | Where-Object {
      $n = $_.Name.ToLower()
      $nameHints | Where-Object { $n -like "*$($_.ToLower())*" }
    } | Select-Object -First 1
    if ($byName) { return $byName.FullName }
  }
  foreach ($f in $allTxt) {
    $head = Get-Content $f.FullName -TotalCount 80 -ErrorAction SilentlyContinue | Out-String
    foreach ($n in $needles) { if ($head -match $n) { return $f.FullName } }
  }
  return $null
}

function Convert-SizeToGB {
  param(
    [double]$Value,
    [string]$Unit
  )
  if (-not $Unit) { return $Value }
  switch ($Unit.ToUpper()) {
    'TB' { return $Value * 1024 }
    'MB' { return $Value / 1024 }
    default { return $Value }
  }
}

function ConvertTo-NullableBool {
  param($Value)

  if ($Value -is [bool]) { return [bool]$Value }
  if ($null -eq $Value) { return $null }

  $stringValue = [string]$Value
  if (-not $stringValue) { return $null }

  $trimmed = $stringValue.Trim()
  if (-not $trimmed) { return $null }

  if ($trimmed -match '^(?i)(true|yes|y|1)$') { return $true }
  if ($trimmed -match '^(?i)(false|no|n|0)$') { return $false }
  return $null
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

function Test-IsMicrosoftPublisher {
  param(
    [string[]]$Values
  )

  if (-not $Values) { return $false }

  foreach ($value in $Values) {
    if (-not $value) { continue }
    $text = ''
    try {
      $text = $value.ToLowerInvariant()
    } catch {
      $text = ([string]$value).ToLowerInvariant()
    }

    if ($text -match 'microsoft' -or $text -match 'windows defender' -or $text -match 'windows component' -or $text -match 'sysinternals') {
      return $true
    }
  }

  return $false
}

function Parse-AutorunsEntries {
  param([string]$Text)

  $result = New-Object psobject -Property @{
    Entries     = New-Object System.Collections.Generic.List[pscustomobject]
    HeaderFound = $false
  }

  if ([string]::IsNullOrWhiteSpace($Text)) { return $result }

  $lines = [regex]::Split($Text,'\r?\n')
  if (-not $lines -or $lines.Count -eq 0) { return $result }

  $headerIndex = -1
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $candidate = $lines[$i]
    if (-not $candidate) { continue }
    if ($candidate -match '(?i)\bentry\b' -and ($candidate -match '(?i)\bpublisher\b' -or $candidate -match '(?i)\bcompany\b')) {
      $headerIndex = $i
      break
    }
  }

  if ($headerIndex -lt 0) { return $result }

  $result.HeaderFound = $true
  $headerLine = $lines[$headerIndex]
  $delimiter = $null
  if ($headerLine -match "`t") {
    $delimiter = "`t"
  } elseif ($headerLine -match ';') {
    $delimiter = ';'
  } elseif ($headerLine -match ',') {
    $delimiter = ','
  }

  $rows = @()
  if ($delimiter) {
    $dataLines = @()
    for ($j = $headerIndex; $j -lt $lines.Count; $j++) {
      $line = $lines[$j]
      if ($line -match '^\s*$') { continue }
      $dataLines += $line.TrimEnd()
    }
    $dataBlock = ($dataLines -join "`n").Trim()
    if ($dataBlock) {
      try {
        $rows = $dataBlock | ConvertFrom-Csv -Delimiter $delimiter
      } catch {
        $rows = @()
      }
    }
  } else {
    for ($j = $headerIndex + 1; $j -lt $lines.Count; $j++) {
      $line = $lines[$j]
      if (-not $line) { continue }
      $trimmed = $line.Trim()
      if (-not $trimmed) { continue }
      $parts = [regex]::Split($trimmed,'\s{2,}')
      if ($parts.Length -lt 2) { continue }
      $obj = [ordered]@{ Entry = $parts[0] }
      if ($parts.Length -gt 1) { $obj['Description'] = $parts[1] }
      if ($parts.Length -gt 2) { $obj['Publisher']   = $parts[2] }
      if ($parts.Length -gt 3) { $obj['Image Path']  = $parts[3] }
      if ($parts.Length -gt 4) { $obj['Entry Location'] = $parts[4] }
      $rows += New-Object psobject -Property $obj
    }
  }

  foreach ($row in $rows) {
    if (-not $row) { continue }
    $entryName = ''
    if ($row.PSObject.Properties['Entry']) { $entryName = [string]$row.Entry }
    if (-not $entryName) { continue }
    $entryName = $entryName.Trim()
    if (-not $entryName) { continue }
    if ($entryName -match '^(?i)entry$') { continue }

    $description = ''
    foreach ($propName in @('Description','Product')) {
      if ($row.PSObject.Properties[$propName]) {
        $value = [string]$row.$propName
        if ($value) {
          $valueTrimmed = $value.Trim()
          if ($valueTrimmed) { $description = $valueTrimmed; break }
        }
      }
    }

    $publisherFields = New-Object System.Collections.Generic.List[string]
    foreach ($propName in @('Publisher','Company','Signer','Verified','Signed By','Signer Company')) {
      if ($row.PSObject.Properties[$propName]) {
        $value = [string]$row.$propName
        if ($value) {
          $valueTrimmed = $value.Trim()
          if ($valueTrimmed) { [void]$publisherFields.Add($valueTrimmed) }
        }
      }
    }

    $imagePath = ''
    foreach ($propName in @('ImagePath','Image Path','Path','Command','Image','Binary','Launch','Location')) {
      if ($row.PSObject.Properties[$propName]) {
        $value = [string]$row.$propName
        if ($value) {
          $valueTrimmed = $value.Trim()
          if ($valueTrimmed) { $imagePath = $valueTrimmed; break }
        }
      }
    }

    $entryLocation = ''
    foreach ($propName in @('Entry Location','Location','Launch String','Registry Location','Source','EntryLocation')) {
      if ($row.PSObject.Properties[$propName]) {
        $value = [string]$row.$propName
        if ($value) {
          $valueTrimmed = $value.Trim()
          if ($valueTrimmed) { $entryLocation = $valueTrimmed; break }
        }
      }
    }

    $category = ''
    foreach ($propName in @('Category','Section')) {
      if ($row.PSObject.Properties[$propName]) {
        $value = [string]$row.$propName
        if ($value) {
          $valueTrimmed = $value.Trim()
          if ($valueTrimmed) { $category = $valueTrimmed; break }
        }
      }
    }

    $profile = ''
    if ($row.PSObject.Properties['Profile']) {
      $profileValue = [string]$row.Profile
      if ($profileValue) { $profile = $profileValue.Trim() }
    }

    $enabled = $true
    foreach ($propName in @('Enabled','Active','Disabled')) {
      if (-not $row.PSObject.Properties[$propName]) { continue }
      $value = [string]$row.$propName
      if (-not $value) { continue }
      $lower = $value.Trim().ToLowerInvariant()
      switch ($propName) {
        'Enabled' {
          if ($lower -match '^(no|false|disabled|0)$') { $enabled = $false }
          elseif ($lower -match '^(yes|true|enabled|1)$') { $enabled = $true }
        }
        'Active' {
          if ($lower -match '^(no|false|0)$') { $enabled = $false }
          elseif ($lower -match '^(yes|true|1)$') { $enabled = $true }
        }
        'Disabled' {
          if ($lower -match '^(yes|true|1)$' -or $lower -match 'disabled') { $enabled = $false }
        }
      }
    }

    $publisherSummary = ($publisherFields | Where-Object { $_ }) -join '; '
    $isMicrosoft = Test-IsMicrosoftPublisher $publisherFields.ToArray()
    if (-not $isMicrosoft -and $row.PSObject.Properties['Verified']) {
      $verifiedValue = [string]$row.Verified
      if ($verifiedValue) {
        $isMicrosoft = Test-IsMicrosoftPublisher @($verifiedValue)
      }
    }
    if (-not $isMicrosoft -and $imagePath) {
      $pathLower = $imagePath.ToLowerInvariant()
      if ($pathLower -match '\\microsoft\\') { $isMicrosoft = $true }
    }

    $result.Entries.Add([pscustomobject]@{
      Entry           = $entryName
      Description     = $description
      Publisher       = $publisherSummary
      PublisherFields = $publisherFields.ToArray()
      ImagePath       = $imagePath
      Location        = $entryLocation
      Category        = $category
      Profile         = $profile
      Enabled         = $enabled
      IsMicrosoft     = $isMicrosoft
    })
  }

  return $result
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

function Test-IsEnabledValue {
  param($Value)

  if ($null -eq $Value) { return $false }

  try {
    $text = [string]$Value
  } catch {
    $text = [string]$Value
  }

  if (-not $text) { return $false }
  $trimmed = $text.Trim()
  if (-not $trimmed) { return $false }

  try {
    $lower = $trimmed.ToLowerInvariant()
  } catch {
    $lower = $trimmed
    if ($lower) { $lower = $lower.ToLowerInvariant() }
  }

  if ($lower -match '^(on|true|enabled|1)$') { return $true }
  if ($lower -match 'yes') { return $true }
  return $false
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

function Get-DictionaryValue {
  param(
    [System.Collections.IDictionary]$Dictionary,
    [string]$Key
  )

  if (-not $Dictionary -or -not $Key) { return $null }

  try {
    if ($Dictionary -is [System.Collections.Specialized.OrderedDictionary]) {
      if ($Dictionary.Contains($Key)) { return $Dictionary[$Key] }
    } elseif ($Dictionary -is [hashtable]) {
      if ($Dictionary.ContainsKey($Key)) { return $Dictionary[$Key] }
    } else {
      if ($Dictionary.ContainsKey($Key)) { return $Dictionary[$Key] }
    }
  } catch {
    try {
      if ($Dictionary.Contains($Key)) { return $Dictionary[$Key] }
    } catch {}
  }

  return $null
}

function ConvertTo-StringArray {
  param($Value)

  $list = @()
  if ($null -eq $Value) { return $list }

  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    foreach ($item in $Value) {
      if ($null -eq $item) { continue }
      $text = [string]$item
      if (-not [string]::IsNullOrWhiteSpace($text)) {
        $list += $text.Trim()
      }
    }
  } else {
    $text = [string]$Value
    if (-not [string]::IsNullOrWhiteSpace($text)) {
      $list += $text.Trim()
    }
  }

  return $list | Where-Object { $_ } | Select-Object -Unique
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

function Get-WinHttpProxyInfo {
  param([string]$Text)

  if (-not $Text) { return $null }

  $hasProxy = $null

  $proxyMatch = [regex]::Match($Text,'(?im)^\s*Proxy Server\(s\)\s*:\s*(?<value>.+)$')
  if ($proxyMatch.Success) {
    $value = $proxyMatch.Groups['value'].Value.Trim()
    if ($value -and $value -notmatch '^(?i)(\(none\)|none|not set|n/?a|<not set>)$') {
      if ($value -notmatch '^(?i)direct access') { $hasProxy = $true }
    } elseif ($hasProxy -eq $null) {
      $hasProxy = $false
    }
  }

  $autoMatches = [regex]::Matches($Text,'(?im)^\s*Auto(?:matic)?(?:\s+Config(?:uration)?(?:\s+Script|\s+URL)?)?\s*:\s*(?<value>.+)$')
  foreach ($match in $autoMatches) {
    $value = $match.Groups['value'].Value.Trim()
    if ($value -and $value -notmatch '^(?i)(\(none\)|none|not set|n/?a|<not set>)$') {
      $hasProxy = $true
    }
  }

  if ($Text -match '(?i)Direct access\s*\(no proxy server\)') {
    if ($hasProxy -ne $true) { $hasProxy = $false }
  }

  return [pscustomobject]@{
    HasProxy = $hasProxy
    Raw      = $Text
  }
}

function Parse-BitLockerStatus {
  param([string]$Text)

  $entries = New-Object System.Collections.Generic.List[pscustomobject]
  if (-not $Text) { return $entries }

  $blocks = [regex]::Split($Text, '\r?\n\s*\r?\n')
  foreach ($block in $blocks) {
    if (-not $block) { continue }
    $trimmed = $block.Trim()
    if (-not $trimmed) { continue }

    $mountMatch = [regex]::Match($trimmed,'(?im)^\s*Mount\s*Point\s*:\s*(.+)$')
    if (-not $mountMatch.Success) {
      $mountMatch = [regex]::Match($trimmed,'(?im)^\s*MountPoint\s*:\s*(.+)$')
    }
    if (-not $mountMatch.Success) { continue }

    $volumeTypeMatch = [regex]::Match($trimmed,'(?im)^\s*Volume\s*Type\s*:\s*(.+)$')
    $protectionMatch = [regex]::Match($trimmed,'(?im)^\s*Protection\s*Status\s*:\s*(.+)$')
    $volumeStatusMatch = [regex]::Match($trimmed,'(?im)^\s*Volume\s*Status\s*:\s*(.+)$')
    $encryptionMatch = [regex]::Match($trimmed,'(?im)^\s*Encryption\s*Percentage\s*:\s*(.+)$')

    $mountPoint = $mountMatch.Groups[1].Value.Trim()
    $volumeType = if ($volumeTypeMatch.Success) { $volumeTypeMatch.Groups[1].Value.Trim() } else { '' }
    $protectionText = if ($protectionMatch.Success) { $protectionMatch.Groups[1].Value.Trim() } else { '' }
    $volumeStatus = if ($volumeStatusMatch.Success) { $volumeStatusMatch.Groups[1].Value.Trim() } else { '' }

    $protectionEnabled = $null
    if ($protectionText) {
      $protectionEnabled = Get-BoolFromString -Value $protectionText
    }

    $encryptionPercent = $null
    if ($encryptionMatch.Success) {
      $encText = $encryptionMatch.Groups[1].Value.Trim()
      if ($encText) {
        $normalized = ($encText -replace '[^0-9\.,]', '')
        if ($normalized) {
          $normalized = $normalized -replace ',', '.'
          $parsedValue = 0.0
          if ([double]::TryParse($normalized, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsedValue)) {
            $encryptionPercent = $parsedValue
          }
        }
      }
    }

    $entries.Add([pscustomobject]@{
      MountPoint          = $mountPoint
      VolumeType          = $volumeType
      ProtectionStatus    = $protectionText
      ProtectionEnabled   = $protectionEnabled
      VolumeStatus        = $volumeStatus
      EncryptionPercentage = $encryptionPercent
      RawBlock            = $trimmed
    })
  }

  return $entries
}

$script:ResolveDnsAvailable = $null
function Resolve-Safe {
  param(
    [string]$Name,
    [string]$Type = 'A',
    [string]$Server = $null
  )

  if (-not $Name) { return @() }

  if ($null -eq $script:ResolveDnsAvailable) {
    $script:ResolveDnsAvailable = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
  }

  if (-not $script:ResolveDnsAvailable) { return $null }

  try {
    if ($Server) {
      return Resolve-DnsName -Name $Name -Type $Type -Server $Server -ErrorAction Stop
    } else {
      return Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop
    }
  } catch {
    return @()
  }
}

function Test-IsRFC1918 {
  param([string]$Address)

  if (-not $Address) { return $false }

  $addressTrimmed = $Address.Trim()
  $parsed = $null
  if (-not [System.Net.IPAddress]::TryParse($addressTrimmed, [ref]$parsed)) {
    return $false
  }

  if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    $bytes = $parsed.GetAddressBytes()
    $first = $bytes[0]
    $second = $bytes[1]

    if ($first -eq 10) { return $true }
    if ($first -eq 192 -and $second -eq 168) { return $true }
    if ($first -eq 172 -and $second -ge 16 -and $second -le 31) { return $true }
    if ($first -eq 127) { return $true }
    if ($first -eq 100 -and $second -ge 64 -and $second -le 127) { return $true }

    return $false
  }

  if ($parsed.Equals([System.Net.IPAddress]::IPv6Loopback)) { return $true }
  if ($parsed.IsIPv6LinkLocal -or $parsed.IsIPv6SiteLocal) { return $true }

  $ipv6Bytes = $parsed.GetAddressBytes()
  if (($ipv6Bytes[0] -band 0xfe) -eq 0xfc) { return $true }

  return $false
}

function Test-ServerAuthoritative {
  param(
    [string]$Server,
    [string]$Zone
  )

  if (-not $Server -or -not $Zone) { return $null }

  $soa = Resolve-Safe -Name $Zone -Type SOA -Server $Server
  if ($null -eq $soa) { return $null }
  return ($soa.Count -gt 0)
}

function Test-ServerKnowsAD {
  param(
    [string]$Server,
    [string]$Forest
  )

  if (-not $Server -or -not $Forest) { return $null }

  $srv = Resolve-Safe -Name ("_ldap._tcp.dc._msdcs.$Forest") -Type SRV -Server $Server
  if ($null -eq $srv) { return $null }
  return ($srv.Count -gt 0)
}

function Get-FreeSpaceRule {
  param(
    [string]$DriveLetter,
    [double]$SizeGB,
    [string]$VolumeLine
  )

  $rule = [pscustomobject]@{
    WarnPercent  = 0.20
    WarnAbsolute = 25
    CritPercent  = 0.10
    CritAbsolute = 10
    Description  = 'standard workstation rule'
  }

  if ($DriveLetter -eq 'C') {
    $rule.Description = 'system drive rule'
  } elseif ($VolumeLine -match '(?i)\b(data|archive)\b') {
    $rule.WarnPercent  = 0.15
    $rule.WarnAbsolute = 15
    $rule.CritPercent  = 0.08
    $rule.CritAbsolute = 8
    $rule.Description  = 'relaxed data/archive rule'
  }

  $warnFloor = [math]::Max($SizeGB * $rule.WarnPercent, $rule.WarnAbsolute)
  $critFloor = [math]::Max($SizeGB * $rule.CritPercent, $rule.CritAbsolute)

  if ($SizeGB -le 0) {
    $warnFloor = $rule.WarnAbsolute
    $critFloor = $rule.CritAbsolute
  }

  return [pscustomobject]@{
    WarnFloorGB = $warnFloor
    CritFloorGB = $critFloor
    Description = $rule.Description
  }
}

# map logical keys → discovered files
$files = [ordered]@{
  ipconfig       = Find-ByContent @('ipconfig_all')              @('Windows IP Configuration')
  route          = Find-ByContent @('route_print')               @('Active Routes:','IPv4 Route Table')
  netstat        = Find-ByContent @('netstat_ano','netstat')     @('Proto\s+Local Address\s+Foreign Address')
  arp            = Find-ByContent @('arp_table','arp')           @('Interface:\s')
  nslookup       = Find-ByContent @('nslookup_google','nslookup')@('Server:\s','Address:\s')
  tracert        = Find-ByContent @('tracert_google','tracert')  @('Tracing route to','over a maximum of')
  ping           = Find-ByContent @('ping_google','ping')        @('Pinging .* with','Packets: Sent =')
  testnet_outlook443 = Find-ByContent @('TestNetConnection_Outlook443') @('Test-NetConnection','TcpTestSucceeded')
  outlook_ost    = Find-ByContent @('Outlook_OST')               @('FullName\s*:.*\.ost','No OST files found','Outlook OST root')
  outlook_autodiscover = Find-ByContent @('Autodiscover_DNS')    @('### Domain','autodiscover')
  outlook_scp    = Find-ByContent @('Outlook_SCP')               @('Autodiscover','serviceBindingInformation','SCP lookup')
  office_security = Find-ByContent @('Office_SecurityPolicies')  @('BlockContentExecutionFromInternet','VBAWarnings','ProtectedView')

  systeminfo     = Find-ByContent @('systeminfo')                @('OS Name:\s','OS Version:\s','System Boot Time')
  os_cim         = Find-ByContent @('OS_CIM','OperatingSystem')  @('Win32_OperatingSystem','Caption\s*:')
  computerinfo   = Find-ByContent @('ComputerInfo')              @('CsName\s*:','WindowsBuildLabEx\s*:')
  power_settings = Find-ByContent @('Power_Settings','PowerSettings','PowerCfg') @('HiberbootEnabled','Fast Startup','powercfg /a')

  nic_configs    = Find-ByContent @('NetworkAdapterConfigs')     @('Win32_NetworkAdapterConfiguration')
  netip          = Find-ByContent @('NetIPAddresses','NetIP')    @('IPAddress','InterfaceIndex')
  netadapters    = Find-ByContent @('NetAdapters')               @('Name\s*:.*Status','LinkSpeed|Speed')
  winhttp_proxy  = Find-ByContent @('WinHttpProxy','winhttp_proxy') @('Current WinHTTP proxy settings','Direct access \(no proxy server\)')

  diskdrives     = Find-ByContent @('Disk_Drives')               @('Model\s+Serial|Model\s+SerialNumber','Status')
  volumes        = Find-ByContent @('Volumes')                   @('DriveLetter|FileSystem|HealthStatus')
  disks          = Find-ByContent @('Disks')                     @('Number\s*:','OperationalStatus')

  hotfixes       = Find-ByContent @('Hotfixes')                  @('HotFixID','InstalledOn')
  programs       = Find-ByContent @('Programs_Reg')              @('DisplayName\s+DisplayVersion')
  programs32     = Find-ByContent @('Programs_Reg_32')           @('DisplayName\s+DisplayVersion')

  autoruns       = Find-ByContent @('Autoruns','Autorunsc','StartupPrograms','StartupItems') @('Entry,Description,Publisher','Autoruns', 'Entry Location')

  services       = Find-ByContent @('Services')                  @('Status\s+Name|SERVICE_NAME')
  processes      = Find-ByContent @('Processes','tasklist')      @('Image Name\s+PID|====')
  drivers        = Find-ByContent @('Drivers','driverquery')     @('Driver Name|Display Name')

  event_system   = Find-ByContent @('Event_System')              @('(?im)^\s*Log Name\s*[:=]\s*System','(?im)^\s*Provider(?: Name)?\s*[:=]','(?im)^Event\[','(?i)TimeCreated','(?i)EventID')
  event_app      = Find-ByContent @('Event_Application')         @('(?im)^\s*Log Name\s*[:=]\s*Application','(?im)^\s*Provider(?: Name)?\s*[:=]','(?im)^Event\[','(?i)TimeCreated','(?i)EventID')

  firewall       = Find-ByContent @('Firewall')                  @('Windows Firewall with Advanced Security|Profile Settings')
  firewall_rules = Find-ByContent @('FirewallRules')             @('Rule Name:|DisplayName\s*:')
  security_tpm   = Find-ByContent @('Security_TPM')              @('TpmPresent','TpmReady')
  security_deviceguard = Find-ByContent @('Security_DeviceGuard') @('SecurityServicesRunning','DeviceGuard')
  security_computersystem = Find-ByContent @('Security_ComputerSystem') @('PCSystemType','SystemSkuNumber')
  security_systemenclosure = Find-ByContent @('Security_SystemEnclosure') @('ChassisTypes')
  security_kerneldma = Find-ByContent @('Security_KernelDMA')    @('Kernel DMA Protection')
  security_rdp   = Find-ByContent @('Security_RDP')              @('fDenyTSConnections','RdpTcp')
  security_smb   = Find-ByContent @('Security_SMB')              @('EnableSMB1Protocol')
  security_lsa   = Find-ByContent @('Security_LSA')              @('RunAsPPL','LmCompatibilityLevel')
  security_ntlm  = Find-ByContent @('Security_NTLM')             @('RestrictSendingNTLMTraffic')
  security_smartscreen = Find-ByContent @('Security_SmartScreen') @('SmartScreenEnabled')
  security_asr   = Find-ByContent @('Security_ASR')              @('AttackSurfaceReduction','Rules')
  security_exploit = Find-ByContent @('Security_ExploitProtection') @('Get-ProcessMitigation','ASLR')
  security_wdac  = Find-ByContent @('Security_WDAC')             @('SmartAppControl','CodeIntegrity')
  security_localadmins = Find-ByContent @('Security_LocalAdmins') @('Administrators','Member :')
  security_laps  = Find-ByContent @('Security_LAPS')             @('AdmPwd','WindowsLAPS')
  security_pslogging = Find-ByContent @('Security_PowerShellLogging') @('ScriptBlockLogging','ModuleLogging')
  security_uac   = Find-ByContent @('Security_UAC')              @('EnableLUA')
  security_ldap  = Find-ByContent @('Security_LDAP')             @('LDAPClientIntegrity','LDAPServerIntegrity')

  defender       = Find-ByContent @('DefenderStatus')            @('Get-MpComputerStatus|AMProductVersion')
  bitlocker      = Find-ByContent @('BitLockerStatus','BitLocker') @('(?im)^\s*Mount\s*Point\s*:','Get-BitLockerVolume')
  shares         = Find-ByContent @('NetShares')                 @('Share name|Resource')
  tasks          = Find-ByContent @('ScheduledTasks','tasks')    @('(?im)^Folder:\s','(?im)^TaskName:\s','(?im)^HostName:\s')
  whoami         = Find-ByContent @('Whoami')                    @('USER INFORMATION|GROUP INFORMATION')
  dsreg          = Find-ByContent @('dsregcmd_status','dsregcmd','dsreg_status','dsreg') @('AzureAdJoined','Device State','TenantName','dsregcmd')
  uptime         = Find-ByContent @('Uptime')                    @('\d{4}-\d{2}-\d{2}')
  topcpu         = Find-ByContent @('TopCPU')                    @('ProcessName|CPU')
  memory         = Find-ByContent @('Memory')                    @('TotalVisibleMemoryMB|FreePhysicalMemoryMB')
}

# dump discovery map when verbose
Write-Verbose "Discovered files map:"
foreach($key in $files.Keys){
  $resolved = if($files[$key]){ (Resolve-Path $files[$key] -ErrorAction SilentlyContinue).Path } else { "(not found)" }
  Write-Verbose ("  {0} = {1}" -f $key, $resolved)
}

# read contents
$raw = @{}
foreach($k in $files.Keys){ $raw[$k] = if($files[$k]){ Read-Text $files[$k] } else { "" } }

Write-Verbose "Loaded raw text for keys:"
foreach($key in $raw.Keys){
  if ($raw[$key]) {
    $snippet = $raw[$key].Substring(0,[Math]::Min(80,$raw[$key].Length)).Replace("`r"," ").Replace("`n"," ")
    Write-Verbose ("  {0}: {1}" -f $key, $snippet)
  }
}

# issues list
$issues = New-Object System.Collections.Generic.List[pscustomobject]
function Get-IssueExplanation {
  param(
    [string]$Area,
    [string]$Message,
    [string]$Severity
  )

  $areaLower = if ($Area) { $Area.ToLowerInvariant() } else { '' }
  $messageLower = if ($Message) { $Message.ToLowerInvariant() } else { '' }
  $mainArea = if ($areaLower -and $areaLower.Contains('/')) { ($areaLower -split '/')[0] } else { $areaLower }

  if ($messageLower -match 'secure boot' -or $areaLower -match 'secure boot') {
    return "Secure Boot being disabled means your PC can start up using untrusted, tampered code, making it easier for deep, hard-to-remove malware to infect the machine before Windows and your antivirus even load."
  }

  if ($areaLower -match 'system/firmware') {
    return "Running in legacy BIOS mode blocks modern protections like Secure Boot and measured boot. Switching the device to UEFI unlocks those defenses and improves manageability."
  }

  if ($areaLower -match 'system/fast startup') {
    return "Fast Startup keeps parts of Windows in hibernation, so the machine never truly power-cycles. That can hide driver issues and stop updates from applying cleanly until you disable it for troubleshooting."
  }

  if ($areaLower -match 'system/startup') {
    return "Many auto-starting programs keep Windows busy right after sign-in. Trimming unnecessary autoruns speeds boot time and reduces the risk of unwanted software launching silently."
  }

  if ($areaLower -match 'system/bitlocker') {
    return "BitLocker not being healthy means the drive is sitting unencrypted. A lost or stolen device could be read without a password, so turning BitLocker back on protects the data."
  }

  if ($areaLower -match 'system/uptime') {
    return "Very long uptime tells us the PC has not restarted to finish updates or clear memory. A reboot usually resolves lingering glitches and completes patch installations."
  }

  if ($areaLower -match 'dns/internal') {
    return "DNS not configured correctly means the Domain Controller cannot be reached. Therefore you may experience login issues and group policies failing to apply."
  }

  if ($areaLower -match 'active directory/dc discovery') {
    return "When a device cannot discover a domain controller it cannot authenticate or refresh policies. Restoring DC discovery is critical to get logons, password changes, and script processing working again."
  }

  if ($areaLower -match 'active directory/ad dns') {
    return "Active Directory DNS records are how clients find domain controllers. Fixing DNS ensures the machine can reach the right DCs for sign-in, Kerberos, and policy updates."
  }

  if ($areaLower -match 'active directory/time') {
    return "Kerberos requires the workstation clock to be in sync with the domain. Time or Kerberos errors block authentication, so correcting clock drift keeps tickets issuing correctly."
  }

  if ($areaLower -match 'active directory/secure channel') {
    return "A broken secure channel means the computer account trust is gone. Until it is reset the machine cannot talk to domain controllers for logons or policy."
  }

  if ($areaLower -match 'active directory/sysvol') {
    return "SYSVOL and NETLOGON shares host logon scripts and Group Policy templates. Errors reaching them stop policies from applying and can break scripted logons."
  }

  if ($areaLower -match 'active directory/gpo') {
    return "Group Policy processing failures mean security baselines and configuration changes are not taking effect. Fixing GPO errors keeps the device aligned with enterprise policy."
  }

  if ($areaLower -match 'dns/order') {
    return "Public DNS servers listed ahead of the internal ones make the computer ask the wrong place first. That slows logons and can stop it finding domain controllers or internal apps." 
  }

  if ($mainArea -eq 'dns') {
    return "When DNS breaks the PC cannot translate server or website names into IP addresses. Apps that rely on name lookups will hang or fail until DNS is fixed." 
  }

  if ($mainArea -eq 'network') {
    return "Network connectivity issues block the device from reaching the internet or company resources. Users will see web pages, VPN, or shared drives stop responding until the link is repaired." 
  }

  if ($mainArea -eq 'firewall') {
    return "A disabled or misconfigured firewall leaves the machine wide open to unsolicited network traffic. Attackers and worms can reach the device far more easily without that shield." 
  }

  if ($mainArea -eq 'security') {
    return "Microsoft Defender problems mean the built-in antivirus is not updating or guarding the system correctly. Without current protection the device is vulnerable to malware and phishing payloads." 
  }

  if ($mainArea -eq 'services') {
    return "Critical Windows services being stopped or broken keeps dependent features from working. Users can notice failures with logons, printing, updates, or other roles tied to that service." 
  }

  if ($mainArea -eq 'events') {
    return "Heavy error and warning activity in the event logs points to underlying problems that need attention. Ignoring them can lead to crashes, data loss, or service outages." 
  }

  if ($areaLower -match 'storage/smart') {
    return "SMART warnings mean the drive itself is reporting hardware trouble. Disks in this state often fail soon, so backing up and replacing them prevents sudden data loss." 
  }

  if ($areaLower -match 'storage/free space') {
    return "Running low on disk space makes Windows sluggish and can stop updates or temporary files from saving. Cleaning up space keeps applications responsive and prevents crashes." 
  }

  if ($areaLower -match 'storage/disks') {
    return "Disk health or configuration problems slow the machine and risk file corruption. Fixing the underlying disk issue keeps storage reliable." 
  }

  if ($areaLower -match 'storage/volumes') {
    return "Volume-related warnings mean Windows is struggling with partitions or mount points. Left alone the drive can stop mounting or data can disappear unexpectedly." 
  }

  if ($areaLower -match 'office/macros') {
    return "Allowing Office macros to run freely gives malicious documents an easy way to install malware. Tightening macro policies stops harmful scripts from launching automatically." 
  }

  if ($areaLower -match 'office/protected view') {
    return "Turning off Protected View makes Office open email or internet files directly. That removes the safety sandbox and lets risky attachments run with full access." 
  }

  if ($areaLower -match 'outlook/connectivity') {
    return "Outlook connectivity failures mean the client cannot reach Exchange or Microsoft 365 to send and receive mail. Messages may pile up in the Outbox until the connection is restored." 
  }

  if ($areaLower -match 'outlook/autodiscover') {
    return "Autodiscover issues stop Outlook from automatically locating mailbox settings. New profiles may not configure and users can see repeated password prompts." 
  }

  if ($areaLower -match 'outlook/ost') {
    return "Oversized or unhealthy OST cache files slow Outlook down and risk mailbox data going out of sync. Trimming or rebuilding the cache brings Outlook performance back." 
  }

  if ($areaLower -match 'outlook/scp') {
    return "Broken Autodiscover SCP records keep domain-joined PCs from finding the right Exchange endpoints. Outlook may connect to the wrong place or fail to sign in on the internal network." 
  }

  $severityWord = if ($Severity) { $Severity.ToLowerInvariant() } else { 'issue' }
  return "This $severityWord points to something outside the normal health baseline. Reviewing the evidence and correcting it will help keep the device stable and secure." 
}

function Add-Issue(
    [string]$Severity,
    [string]$Area,
    [string]$Message,
    [string]$Evidence = "",
    [string]$CheckId = $null,
    [double]$Weight = 1.0,
    [switch]$NA
){
    if (-not $script:issues) {
        $script:issues = New-Object System.Collections.Generic.List[pscustomobject]
    }
    if (-not $script:Checks) {
        $script:Checks = @{}
    }

    # normalize
    $sevKey = if ($null -ne $Severity) { $Severity.Trim().ToLowerInvariant() } else { "" }
    switch -regex ($sevKey){
        '^(crit(ical)?)$' { $sevKey = 'critical' }
        '^(hi(gh)?)$'     { $sevKey = 'high' }
        '^(med(iu[mn])?)$'{ $sevKey = 'medium' }
        '^(lo(w)?)$'      { $sevKey = 'low' }
        '^(info|informational|information)$' { $sevKey = 'info' }
        default { if ([string]::IsNullOrWhiteSpace($sevKey)) { $sevKey = 'info' } }
    }
    $area = if ($null -ne $Area -and $Area.Trim().Length -gt 0) { $Area.Trim() } else { 'General' }
    $msg  = if ($null -ne $Message -and $Message.Trim().Length -gt 0) { $Message.Trim() } else { 'Issue detected' }
    if ([string]::IsNullOrEmpty($Evidence)) { $Evidence = 'No additional details captured.' }
    $evShort = if ($Evidence.Length -gt 1500) { $Evidence.Substring(0,1500) } else { $Evidence }

    $badgeText = 'ISSUE'
    $cssClass  = 'ok'
    switch ($sevKey) {
        'critical' { $badgeText = 'CRITICAL'; $cssClass = 'critical' }
        'high'     { $badgeText = 'BAD';       $cssClass = 'bad' }
        'medium'   { $badgeText = 'WARNING';   $cssClass = 'warning' }
        'low'      { $badgeText = 'OK';        $cssClass = 'ok' }
        'info'     { $badgeText = 'GOOD';      $cssClass = 'good' }
        default    { $badgeText = $sevKey.ToUpperInvariant(); $cssClass = 'ok' }
    }

    # Add to cards
    $script:issues.Add([pscustomobject]@{
        Severity  = $sevKey
        Area      = $area
        Message   = $msg
        Evidence  = $evShort
        CssClass  = $cssClass
        BadgeText = $badgeText
    })

    # Update check registry (worst severity wins)
    if ($CheckId) {
        # map Area prefix to Category (top-level)

function Get-CategoryFromArea([string]$a){
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
        $cat = Get-CategoryFromArea $area

        if (-not $script:Checks.ContainsKey($CheckId)) {
            $script:Checks[$CheckId] = @{
                CheckId       = $CheckId
                Category      = $cat
                Weight        = $Weight
                Attempted     = $true
                NA            = [bool]$NA
                Outcome       = 'Issue'
                WorstSeverity = $sevKey
                FirstMessage  = $msg
            }
        } else {
            $c = $script:Checks[$CheckId]
            $c['Attempted'] = $true
            if ($NA) { $c['NA'] = $true }
            $c['Outcome'] = 'Issue'
            # severity order: critical > high > medium > low > info
            $rank = @{ critical=5; high=4; medium=3; low=2; info=1 }
            $prev = $c['WorstSeverity']; if (-not $prev) { $prev = 'info' }
            if ($rank[$sevKey] -ge $rank[$prev]) { $c['WorstSeverity'] = $sevKey }
            $script:Checks[$CheckId] = $c
        }
    }
}


# healthy findings
$normals = New-Object System.Collections.Generic.List[pscustomobject]

function Add-Normal(
    [string]$Area,
    [string]$Message,
    [string]$Evidence = "",
    [string]$CheckId = $null,
    [double]$Weight = 1.0,
    [switch]$NA
){
    if (-not $script:normals) {
        $script:normals = New-Object System.Collections.Generic.List[pscustomobject]
    }
    if (-not $script:Checks) {
        $script:Checks = @{}
    }

    $area = if ($null -ne $Area -and $Area.Trim().Length -gt 0) { $Area.Trim() } else { 'General' }
    $msg  = if ($null -ne $Message -and $Message.Trim().Length -gt 0) { $Message.Trim() } else { 'OK' }
    if ([string]::IsNullOrEmpty($Evidence)) { $Evidence = '—' }
    $evShort = if ($Evidence.Length -gt 1500) { $Evidence.Substring(0,1500) } else { $Evidence }

    $script:normals.Add([pscustomobject]@{
        Severity  = 'good'
        Area      = $area
        Message   = $msg
        Evidence  = $evShort
        CssClass  = 'good'
        BadgeText = 'GOOD'
    })

    if ($CheckId) {

function Add-EventStats($txt,$name){
  if (-not $txt) { return }
  $err = ([regex]::Matches($txt,'\bError\b','IgnoreCase')).Count
  $warn= ([regex]::Matches($txt,'\bWarning\b','IgnoreCase')).Count
  if ($err -ge 5){
    $highlights = Get-EventHighlights -Text $txt -TargetLevels @('Error') -Max 3
    $evidenceParts = @()
    if ($highlights.Snippets.Count -gt 0) { $evidenceParts += $highlights.Snippets }
    $extraErrors = [Math]::Max(0, $highlights.Matched - $highlights.Snippets.Count)
    if ($extraErrors -gt 0) {
      $evidenceParts += "(+{0} additional error events in sample)" -f $extraErrors
    }
    if ($evidenceParts.Count -eq 0) {
      $evidenceParts += "Sample contained $err entries with 'Error'."
    }
    $evidenceText = $evidenceParts -join "`n`n"
    Add-Issue "info" "Events" "$name log shows many errors ($err in recent sample)." $evidenceText
  }
  elseif ($warn -ge 10){
    $highlights = Get-EventHighlights -Text $txt -TargetLevels @('Warning') -Max 3
    $evidenceParts = @()
    if ($highlights.Snippets.Count -gt 0) { $evidenceParts += $highlights.Snippets }
    $extraWarnings = [Math]::Max(0, $highlights.Matched - $highlights.Snippets.Count)
    if ($extraWarnings -gt 0) {
      $evidenceParts += "(+{0} additional warning events in sample)" -f $extraWarnings
    }
    if ($evidenceParts.Count -eq 0) {
      $evidenceParts += "Sample contained $warn entries with 'Warning'."
    }
    $evidenceText = $evidenceParts -join "`n`n"
    Add-Issue "low" "Events" "$name log shows many warnings ($warn in recent sample)." $evidenceText
  }
}
Add-EventStats $raw['event_system'] "System"
Add-EventStats $raw['event_app'] "Application"

function Get-EventCounts($txt){
  if (-not $txt){ return @{E=0;W=0} }
  return @{
    E = ([regex]::Matches($txt,'\bError\b','IgnoreCase')).Count
    W = ([regex]::Matches($txt,'\bWarning\b','IgnoreCase')).Count
  }
}
$sysEW = Get-EventCounts $raw['event_system']
$appEW = Get-EventCounts $raw['event_app']
if ($sysEW.E -lt 5 -and $appEW.E -lt 5){
  Add-Normal "Events" "Low recent error counts in System/Application" ("System: E=$($sysEW.E) W=$($sysEW.W) ; Application: E=$($appEW.E) W=$($appEW.W)")
}

$eventLogLabels = @{
  event_system = 'System'
  event_app    = 'Application'
}
foreach($eventKey in $eventLogLabels.Keys){
  $text = $raw[$eventKey]
  if (-not $text){ continue }
  if ($text -match '(?im)^Event\['){ continue }
  if ($text -match '(?im)^\s*Log Name\s*[:=]'){ continue }
  if ($text -match '(?im)^\s*Provider(?: Name)?\s*[:=]'){ continue }
  if ($text -match '(?i)TimeCreated'){ continue }
  if ($text -match '(?i)EventID'){ continue }
  $lines = [regex]::Split($text,'\r?\n')
  $snippet = ($lines | Where-Object { $_ -and $_.Trim() } | Select-Object -First 6)
  if (-not $snippet -or $snippet.Count -eq 0){
    $snippet = $lines | Select-Object -First 6
  }
  $evidence = if ($snippet) { ($snippet -join "`n").Trim() } else { '' }
  $label = $eventLogLabels[$eventKey]
  Add-Normal ("Events/$label") "Collected (unparsed format)" $evidence
}

if ($raw['tasks']){
  $scheduleInfo = [regex]::Match($raw['tasks'],'(?im)^Schedule:\s*Scheduling data is not available in this format\.?')
  if ($scheduleInfo.Success){
    Add-Normal "System/Scheduled Tasks" "Contains on-demand/unscheduled entries" $scheduleInfo.Value
  }
}

# netstat summary
if ($raw['netstat']){
  $lstn = ([regex]::Matches($raw['netstat'],'\sLISTENING\s+\d+$','Multiline')).Count
  if ($lstn -le 150){
    Add-Normal "Network/Netstat" "Reasonable number of listening sockets" ("LISTENING count: " + $lstn)
  }
}

# hotfix presence
if ($raw['hotfixes']){
  $hfCount = ([regex]::Matches($raw['hotfixes'],'^KB\d+','Multiline')).Count
  if ($hfCount -gt 0){
    Add-Normal "System/Patching" "Hotfixes present" ("Counted KB lines: " + $hfCount)
  }
}

# disk SMART status
if ($raw['diskdrives']){
  $smartText = $raw['diskdrives']
  $failurePattern = '(?i)\b(Pred\s*Fail|Fail(?:ed|ing)?|Bad|Caution)\b'
  if ($smartText -match $failurePattern) {
    $failureMatches = [regex]::Matches($smartText, $failurePattern)
    $keywords = $failureMatches | ForEach-Object { $_.Value.Trim() } | Where-Object { $_ } | Sort-Object -Unique
    $keywordSummary = if ($keywords) { $keywords -join ', ' } else { $null }
    $evidenceLines = ([regex]::Split($smartText,'\r?\n') | Where-Object { $_ -match $failurePattern } | Select-Object -First 12)
    if (-not $evidenceLines -or $evidenceLines.Count -eq 0) {
      $evidenceLines = ([regex]::Split($smartText,'\r?\n') | Select-Object -First 12)
    }
    $evidenceText = $evidenceLines -join "`n"
    $message = if ($keywordSummary) {
      "SMART status reports failure indicators ({0})." -f $keywordSummary
    } else {
      'SMART status reports failure indicators.'
    }
    Add-Issue "critical" "Storage/SMART" $message $evidenceText
  }
  elseif ($smartText -notmatch '(?i)Unknown') {
    Add-Normal "Storage/SMART" "SMART status shows no failure indicators" (([regex]::Split($smartText,'\r?\n') | Select-Object -First 12) -join "`n")
  }
}

# disk operational status and health
if ($raw['disks']) {
  $diskEntries = Parse-DiskList $raw['disks']
  $diskProblems = @()

  foreach ($disk in $diskEntries) {
    if (-not $disk) { continue }

    $reasons = @()
    $severity = $null

    if ($disk.IsOffline -eq $true) {
      $reasons += 'Marked Offline'
      $severity = Get-MaxSeverity $severity 'high'
    }

    if ($disk.IsReadOnly -eq $true) {
      $reasons += 'Marked ReadOnly'
      $severity = Get-MaxSeverity $severity 'medium'
    }

    if ($disk.OperationalStatus -and $disk.OperationalStatus.Count -gt 0) {
      $nonOk = $disk.OperationalStatus | Where-Object { $_ -and $_ -notmatch '^(?i)(ok|online)$' }
      if ($nonOk.Count -gt 0) {
        $reasons += ("OperationalStatus {0}" -f ($nonOk -join ', '))
        if ($nonOk | Where-Object { $_ -match '(?i)(failed|offline|not\s+ready|no\s+access|io\s+error|lost|no\s+contact|unavailable)' }) {
          $severity = Get-MaxSeverity $severity 'high'
        } elseif ($nonOk | Where-Object { $_ -match '(?i)(degraded|stressed|unknown|no\s+media|not\s+initialized|error)' }) {
          $severity = Get-MaxSeverity $severity 'medium'
        } else {
          $severity = Get-MaxSeverity $severity 'medium'
        }
      }
    }

    if ($disk.HealthStatus -and $disk.HealthStatus.Count -gt 0) {
      $nonHealthy = $disk.HealthStatus | Where-Object { $_ -and $_ -notmatch '^(?i)healthy$' }
      if ($nonHealthy.Count -gt 0) {
        $reasons += ("HealthStatus {0}" -f ($nonHealthy -join ', '))
        if ($nonHealthy | Where-Object { $_ -match '(?i)(unhealthy|failed)' }) {
          $severity = Get-MaxSeverity $severity 'high'
        } else {
          $severity = Get-MaxSeverity $severity 'medium'
        }
      }
    }

    if ($reasons.Count -eq 0) { continue }

    if ($disk.IsBoot -eq $true -or $disk.IsSystem -eq $true) {
      if ($severity) {
        $severity = Promote-Severity $severity 1
      } else {
        $severity = 'high'
      }
      $reasons = @('Boot/System disk') + $reasons
    }

    if (-not $severity) { $severity = 'medium' }

    $labelParts = @()
    if ($disk.Number -ne $null -and $disk.Number -ne '') { $labelParts += ("Disk {0}" -f $disk.Number) }
    if ($disk.FriendlyName) { $labelParts += $disk.FriendlyName }
    $label = if ($labelParts.Count -gt 0) { $labelParts -join ' - ' } else { 'Disk' }

    $diskProblems += [pscustomobject]@{
      Severity = $severity
      Message  = ("{0} reports {1}" -f $label, ($reasons -join '; '))
      Evidence = $disk.Raw
    }
  }

  if ($diskProblems.Count -gt 0) {
    $aggregateSeverity = $null
    $messages = @()
    $evidenceBlocks = @()
    foreach ($problem in $diskProblems) {
      $aggregateSeverity = Get-MaxSeverity $aggregateSeverity $problem.Severity
      $messages += $problem.Message
      $evidenceBlocks += $problem.Evidence
    }

    if (-not $aggregateSeverity) { $aggregateSeverity = 'medium' }
    $evidenceText = ($evidenceBlocks | Where-Object { $_ } | Select-Object -Unique) -join "`n`n"
    $messageText = "Disk health problems detected: {0}" -f ($messages -join '; ')
    Add-Issue $aggregateSeverity "Storage/Disks" $messageText $evidenceText
  }
  elseif ($diskEntries.Count -gt 0) {
    $sampleDisk = $diskEntries | Select-Object -First 1
    Add-Normal "Storage/Disks" "All discovered disks report Online/Healthy status" ($sampleDisk.Raw)
  }
}

# volume health status
if ($raw['volumes']) {
  $volumeLines = [regex]::Split($raw['volumes'],'\r?\n')
  $volumeProblems = @()

  foreach ($line in $volumeLines) {
    if (-not $line) { continue }
    if ($line -match '^(?i)\s*(DriveLetter|FileSystem|----)') { continue }

    $trimmed = $line.Trim()
    if (-not $trimmed) { continue }

    $reasons = @()
    $severity = $null

    $healthMatch = [regex]::Match($line,'(?i)\b(Healthy|Warning|Unhealthy|Unknown|Failed|Degraded)\b')
    if ($healthMatch.Success) {
      $healthValue = $healthMatch.Groups[1].Value
      if ($healthValue -notmatch '^(?i)Healthy$') {
        $reasons += ("HealthStatus {0}" -f $healthValue)
        if ($healthValue -match '(?i)(Unhealthy|Failed)') {
          $severity = Get-MaxSeverity $severity 'high'
        } elseif ($healthValue -match '(?i)(Warning|Degraded)') {
          $severity = Get-MaxSeverity $severity 'medium'
        } else {
          $severity = Get-MaxSeverity $severity 'medium'
        }
      }
    }

    if ($line -match '(?i)\bRAW\b') {
      $reasons += 'File system RAW'
      $severity = Get-MaxSeverity $severity 'high'
    }

    if ($reasons.Count -eq 0) { continue }

    $driveLetter = $null
    if ($line -match '^\s*([A-Z]):') {
      $driveLetter = $matches[1].Value
    } elseif ($line -match '^\s*([A-Z])\b') {
      $driveLetter = $matches[1].Value
    }

    $columns = @()
    try {
      $columns = [regex]::Split($trimmed,'\s{2,}') | Where-Object { $_ }
    } catch {
      $columns = @()
    }

    $label = $null
    if ($columns.Count -ge 2) {
      $label = $columns[1].Trim()
    } elseif ($columns.Count -ge 1) {
      $label = $columns[0].Trim()
    }

    if ($driveLetter -and $driveLetter.Length -gt 0 -and $driveLetter.ToUpperInvariant() -eq 'C') {
      $severity = if ($severity) { Promote-Severity $severity 1 } else { 'medium' }
    }

    if (-not $severity) { $severity = 'medium' }

    $displayParts = @()
    if ($driveLetter) { $displayParts += ("Volume {0}" -f $driveLetter) }
    if ($label -and ($driveLetter -ne $label)) { $displayParts += $label }
    $displayName = if ($displayParts.Count -gt 0) { $displayParts -join ' - ' } else { 'Volume' }

    $volumeProblems += [pscustomobject]@{
      Severity = $severity
      Message  = ("{0} reports {1}" -f $displayName, ($reasons -join '; '))
      Evidence = $trimmed
    }
  }

  if ($volumeProblems.Count -gt 0) {
    $aggregateSeverity = $null
    $messages = @()
    $evidenceLines = @()
    foreach ($problem in $volumeProblems) {
      $aggregateSeverity = Get-MaxSeverity $aggregateSeverity $problem.Severity
      $messages += $problem.Message
      $evidenceLines += $problem.Evidence
    }

    if (-not $aggregateSeverity) { $aggregateSeverity = 'medium' }
    $messageText = "Volume health warnings: {0}" -f ($messages -join '; ')
    $evidenceText = ($evidenceLines | Where-Object { $_ } | Select-Object -Unique) -join "`n"
    Add-Issue $aggregateSeverity "Storage/Volumes" $messageText $evidenceText
  }
}

# volume free space
if ($raw['volumes']){
  $healthy = @()
  $warns = @()
  $criticals = @()
  foreach($line in ([regex]::Split($raw['volumes'],'\r?\n'))){
    $match = [regex]::Match($line,'^\s*([A-Z]):.*?(\d+(?:\.\d+)?)\s*(TB|GB|MB).*?(\d+(?:\.\d+)?)\s*(TB|GB|MB)')
    if ($match.Success){
      $dl = $match.Groups[1].Value
      $sz = [double]$match.Groups[2].Value
      $szUnit = $match.Groups[3].Value
      $fr = [double]$match.Groups[4].Value
      $frUnit = $match.Groups[5].Value
      $szGB = Convert-SizeToGB -Value $sz -Unit $szUnit
      $frGB = Convert-SizeToGB -Value $fr -Unit $frUnit
      if ($szGB -gt 0){
        $pctFree = [math]::Round(($frGB/$szGB)*100,0)
      } else {
        $pctFree = 0
      }

      $thresholds = Get-FreeSpaceRule -DriveLetter $dl -SizeGB $szGB -VolumeLine $line
      $warnFloorGB = $thresholds.WarnFloorGB
      $critFloorGB = $thresholds.CritFloorGB
      $freeRounded = [math]::Round($frGB,1)
      $sizeRounded = [math]::Round($szGB,1)
      $warnRounded = [math]::Round($warnFloorGB,1)
      $critRounded = [math]::Round($critFloorGB,1)
      $summary = "{0}: {1} GB free ({2}% of {3} GB)" -f $dl, $freeRounded, $pctFree, $sizeRounded

      if ($frGB -lt $critFloorGB){
        $criticals += ("{0}; below critical floor {1} GB (warn floor {2} GB, {3})." -f $summary, $critRounded, $warnRounded, $thresholds.Description)
      }
      elseif ($frGB -lt $warnFloorGB){
        $warns += ("{0}; below warning floor {1} GB (critical floor {2} GB, {3})." -f $summary, $warnRounded, $critRounded, $thresholds.Description)
      }
      elseif ($szGB -gt 0){
        $healthy += ("{0}; meets free space targets (warn {1} GB / crit {2} GB, {3})." -f $summary, $warnRounded, $critRounded, $thresholds.Description)
      }
    }
  }
  if ($criticals.Count -gt 0){
    Add-Issue "critical" "Storage/Free Space" "Free space critically low" ($criticals -join "; ")
  }
  if ($warns.Count -gt 0){
    Add-Issue "high" "Storage/Free Space" "Free space warning" ($warns -join "; ")
  }
  if ($healthy.Count -gt 0){
    Add-Normal "Storage/Free Space" "Volumes meet free space targets" ($healthy -join "; ")
  }
}

# ---------- scoring ----------
$weights = @{ critical=10; high=6; medium=3; low=1; info=0 }
$penalty = 0
foreach($i in $issues){ $penalty += ($weights[$i.Severity]) }
$score = [Math]::Max(0, 100 - [Math]::Min($penalty,80))

# ---------- HTML ----------

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

$reportName = "DeviceHealth_Report_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$reportPath = Join-Path $InputFolder $reportName

# CSS assets
$repoRoot = Split-Path $PSScriptRoot -Parent
$cssSources = @(
  Join-Path $repoRoot 'styles/base.css'
  Join-Path $repoRoot 'styles/layout.css'
  Join-Path $PSScriptRoot 'styles/device-health-report.css'
)

foreach ($source in $cssSources) {
  if (-not (Test-Path $source)) {
    throw "Required stylesheet not found: $source"
  }
}

$cssOutputDir = Join-Path $InputFolder 'styles'
if (-not (Test-Path $cssOutputDir)) {
  New-Item -ItemType Directory -Path $cssOutputDir | Out-Null
}

$cssOutputPath = Join-Path $cssOutputDir 'device-health-report.css'
$cssContent = $cssSources | ForEach-Object { Get-Content -Raw -Path $_ }
Set-Content -Path $cssOutputPath -Value ($cssContent -join "`n`n") -Encoding UTF8

$head = '<!doctype html><html><head><meta charset="utf-8"><title>Device Health Report</title><link rel="stylesheet" href="styles/device-health-report.css"></head><body class="page report-page">'

# Expanding here-string for summary (variables expand); closing "@ at column 1
$serverDisplayValue = if ($summary.IsServer -eq $true) {
  'Yes'
} elseif ($summary.IsServer -eq $false -and ($summary.OS -or $summary.OS_Version)) {
  'No'
} else {
  'Unknown'
}
$serverDisplayHtml = Encode-Html $serverDisplayValue

$criticalCount = @($issues | Where-Object { $_.Severity -eq 'critical' }).Count
$highCount = @($issues | Where-Object { $_.Severity -eq 'high' }).Count
$mediumCount = @($issues | Where-Object { $_.Severity -eq 'medium' }).Count
$lowCount = @($issues | Where-Object { $_.Severity -eq 'low' }).Count
$infoCount = @($issues | Where-Object { $_.Severity -eq 'info' }).Count

$deviceNameValue = if ($summary.DeviceName) { $summary.DeviceName } else { 'Unknown' }
$deviceNameHtml = Encode-Html $deviceNameValue

$domainNameValue = if ($summary.Domain) { $summary.Domain.Trim() } else { '' }
$domainNameUpper = if ($domainNameValue) { $domainNameValue.ToUpperInvariant() } else { '' }
$formatJoinStatus = {
  param($value)
  if ($value -eq $true) { 'Yes' }
  elseif ($value -eq $false) { 'No' }
  else { 'Unknown' }
}

$deviceStateDefinitions = @(
  @{ Name = 'Microsoft Entra joined'; AzureAdJoined = $true; EnterpriseJoined = $false; DomainJoined = $false },
  @{ Name = 'Microsoft Entra hybrid joined'; AzureAdJoined = $true; EnterpriseJoined = $false; DomainJoined = $true },
  @{ Name = 'Domain joined'; AzureAdJoined = $false; EnterpriseJoined = $false; DomainJoined = $true },
  @{ Name = 'On-premises DRS joined'; AzureAdJoined = $false; EnterpriseJoined = $true; DomainJoined = $true },
  @{ Name = 'Not domain joined'; AzureAdJoined = $false; EnterpriseJoined = $false; DomainJoined = $false }
)

$deviceStateLabel = $null
foreach ($definition in $deviceStateDefinitions) {
  $matches = $true
  foreach ($key in @('AzureAdJoined','EnterpriseJoined','DomainJoined')) {
    $expected = $definition[$key]
    if ($expected -ne $null) {
      $actual = $summary[$key]
      if ($actual -eq $null) {
        if ($expected -ne $false) {
          $matches = $false
          break
        }
      } elseif ($actual -ne $expected) {
        $matches = $false
        break
      }
    }
  }
  if ($matches) {
    $deviceStateLabel = $definition.Name
    break
  }
}

$deviceStateDetails = @()
if ($deviceStateLabel) {
  $deviceStateDetails += $deviceStateLabel
} else {
  $aadStatus = & $formatJoinStatus $summary.AzureAdJoined
  $entStatus = & $formatJoinStatus $summary.EnterpriseJoined
  $domainStatus = & $formatJoinStatus $summary.DomainJoined
  $deviceStateDetails += "State unknown (Azure AD joined: $aadStatus, Enterprise joined: $entStatus, Domain joined: $domainStatus)"
}

if ($domainNameValue) {
  if ($summary.DomainJoined -eq $true) {
    $deviceStateDetails += "Domain: $domainNameValue"
  } elseif ($domainNameUpper -eq 'WORKGROUP') {
    $deviceStateDetails += 'Domain: WORKGROUP (not domain joined)'
  } else {
    $deviceStateDetails += "Domain (reported): $domainNameValue"
  }
} else {
  $deviceStateDetails += 'Domain: Unknown'
}

if ($summary.LogonServer -and ($summary.DomainJoined -eq $true -or ($domainNameUpper -and $domainNameUpper -ne 'WORKGROUP'))) {
  $deviceStateDetails += "Logon Server: $($summary.LogonServer)"
}

if ($summary.DomainRole) { $deviceStateDetails += "Role: $($summary.DomainRole)" }
if ($summary.AzureAdTenantName) { $deviceStateDetails += "Tenant: $($summary.AzureAdTenantName)" }
if ($summary.AzureAdTenantDomain) { $deviceStateDetails += "Tenant Domain: $($summary.AzureAdTenantDomain)" }
if ($summary.AzureAdTenantId) { $deviceStateDetails += "Tenant ID: $($summary.AzureAdTenantId)" }
if ($summary.AzureAdDeviceId) { $deviceStateDetails += "Device ID: $($summary.AzureAdDeviceId)" }
if ($summary.WorkplaceJoined -eq $true) { $deviceStateDetails += 'Workplace join: Yes' }

$deviceStateHtml = if ($deviceStateDetails.Count -gt 0) { ($deviceStateDetails | ForEach-Object { Encode-Html $_ }) -join '<br>' } else { Encode-Html 'Unknown' }

$osHtml = "$(Encode-Html ($summary.OS)) | $(Encode-Html ($summary.OS_Version))"
$ipv4Html = Encode-Html ($summary.IPv4)
$gatewayHtml = Encode-Html ($summary.Gateway)
$dnsHtml = Encode-Html ($summary.DNS)
$sumTable = @"
<h1>Device Health Report</h1>
<div class='report-card'>
  <div class='report-badge-group'>
    <span class='report-badge report-badge--score'><span class='report-badge__label'>SCORE</span><span class='report-badge__value'>$score</span><span class='report-badge__suffix'>/100</span></span>
    <span class='report-badge report-badge--critical'><span class='report-badge__label'>CRITICAL</span><span class='report-badge__value'>$criticalCount</span></span>
    <span class='report-badge report-badge--bad'><span class='report-badge__label'>HIGH</span><span class='report-badge__value'>$highCount</span></span>
    <span class='report-badge report-badge--warning'><span class='report-badge__label'>MEDIUM</span><span class='report-badge__value'>$mediumCount</span></span>
    <span class='report-badge report-badge--ok'><span class='report-badge__label'>LOW</span><span class='report-badge__value'>$lowCount</span></span>
    <span class='report-badge report-badge--good'><span class='report-badge__label'>INFO</span><span class='report-badge__value'>$infoCount</span></span>
  </div>
  <table class='report-table report-table--key-value' cellspacing='0' cellpadding='0'>
    <tr><td>Device Name</td><td>$deviceNameHtml</td></tr>
    <tr><td>Device State</td><td>$deviceStateHtml</td></tr>
    <tr><td>System</td><td>$osHtml</td></tr>
    <tr><td>Windows Server</td><td>$serverDisplayHtml</td></tr>
    <tr><td>IPv4</td><td>$ipv4Html</td></tr>
    <tr><td>Gateway</td><td>$gatewayHtml</td></tr>
    <tr><td>DNS</td><td>$dnsHtml</td></tr>
  </table>
  <small class='report-note'>Score is heuristic. Triage Critical/High items first.</small>
</div>
"@

# Failed report summary
$failedReports = New-Object System.Collections.Generic.List[pscustomobject]
foreach($key in $files.Keys){
  $filePath = $files[$key]
  $rawContent = if ($raw.ContainsKey($key)) { $raw[$key] } else { '' }
  $resolvedPath = if ($filePath) { (Resolve-Path $filePath -ErrorAction SilentlyContinue).Path } else { $null }

  if (-not $filePath){
    $failedReports.Add([pscustomobject]@{
      Key = $key
      Status = 'Missing'
      Details = 'File not discovered in collection output.'
      Path = $null
    })
    continue
  }

  $trimmed = if ($rawContent) { $rawContent.Trim() } else { '' }
  if (-not $trimmed){
    $failedReports.Add([pscustomobject]@{
      Key = $key
      Status = 'Empty'
      Details = 'Captured file contained no output.'
      Path = $resolvedPath
    })
    continue
  }

  $errorLine = ([regex]::Split($rawContent,'\r?\n') | Where-Object { $_ -match '(?i)ERROR running|not present|missing or failed|is not recognized|The system cannot find' } | Select-Object -First 1)
  if ($errorLine){
    $failedReports.Add([pscustomobject]@{
      Key = $key
      Status = 'Command error'
      Details = $errorLine.Trim()
      Path = $resolvedPath
    })
  }
}

$failedTitle = "Failed Reports ({0})" -f $failedReports.Count
if ($failedReports.Count -eq 0){
  $failedContent = "<div class='report-card'><i>All expected inputs produced output.</i></div>"
} else {
  $failedContent = "<div class='report-card'><table class='report-table report-table--list' cellspacing='0' cellpadding='0'><tr><th>Key</th><th>Status</th><th>Details</th></tr>"
  foreach($entry in $failedReports){
    $detailParts = @()
    if ($entry.Path){ $detailParts += "File: $($entry.Path)" }
    if ($entry.Details){ $detailParts += $entry.Details }
    $detailHtml = if ($detailParts.Count -gt 0) { ($detailParts | ForEach-Object { Encode-Html $_ }) -join '<br>' } else { Encode-Html '' }
    $failedContent += "<tr><td>$(Encode-Html $($entry.Key))</td><td>$(Encode-Html $($entry.Status))</td><td>$detailHtml</td></tr>"
  }
  $failedContent += "</table></div>"
}
$failedHtml = New-ReportSection -Title $failedTitle -ContentHtml $failedContent -Open

function Get-NormalCategory {
  param(
    [string]$Area
  )

  if ([string]::IsNullOrWhiteSpace($Area)) {
    return 'Hardware'
  }

  $prefix = ($Area -split '/')[0]
  if ([string]::IsNullOrWhiteSpace($prefix)) {
    $prefix = $Area
  }

  $trimmed = $prefix.Trim()

  switch -Regex ($trimmed) {
    '^(?i)services$'        { return 'Services' }
    '^(?i)(outlook|office)$' { return 'Office' }
    '^(?i)(network|dns)$'    { return 'Network' }
    '^(?i)security$'         { return 'Security' }
    '^(?i)system$'           { return 'System' }
    '^(?i)scheduled tasks$'  { return 'System' }
    '^(?i)storage$'          { return 'Hardware' }
    default { return 'Hardware' }
  }
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

# Issues
$goodTitle = "What Looks Good ({0})" -f $normals.Count
if ($normals.Count -eq 0){
  $goodContent = '<div class="report-card"><i>No specific positives recorded.</i></div>'
} else {
  $categoryOrder = @('Services','Office','Network','System','Hardware','Security')
  $categorized = [ordered]@{}

  foreach ($category in $categoryOrder) {
    $categorized[$category] = New-Object System.Collections.Generic.List[string]
  }

  foreach ($entry in $normals){
    $category = Get-NormalCategory -Area $entry.Area
    if (-not $categorized.ContainsKey($category)) {
      $categorized[$category] = New-Object System.Collections.Generic.List[string]
    }
    $categorized[$category].Add((New-GoodCardHtml -Entry $entry))
  }

  $firstNonEmpty = $null
  foreach ($category in $categoryOrder) {
    if ($categorized.ContainsKey($category) -and $categorized[$category].Count -gt 0) {
      $firstNonEmpty = $category
      break
    }
  }
  if (-not $firstNonEmpty) { $firstNonEmpty = $categoryOrder[0] }

  $tabName = 'good-tabs'
  $goodTabs = "<div class='report-tabs'><div class='report-tabs__list'>"
  $index = 0

  foreach ($category in $categoryOrder) {
    if (-not $categorized.ContainsKey($category)) { continue }

    $cardsList = $categorized[$category]
    $count = $cardsList.Count
    $slug = [regex]::Replace($category.ToLowerInvariant(), '[^a-z0-9]+', '-')
    $slug = [regex]::Replace($slug, '^-+|-+$', '')
    if (-not $slug) { $slug = "cat$index" }

    $tabId = "{0}-{1}" -f $tabName, $slug
    $checkedAttr = if ($category -eq $firstNonEmpty) { " checked='checked'" } else { '' }
    $labelText = "{0} ({1})" -f $category, $count
    $labelHtml = Encode-Html $labelText
    $panelContent = if ($count -gt 0) { ($cardsList -join '') } else { "<div class='report-card'><i>No positives captured in this category.</i></div>" }

    $goodTabs += "<input type='radio' name='{0}' id='{1}' class='report-tabs__radio'{2}>" -f $tabName, $tabId, $checkedAttr
    $goodTabs += "<label class='report-tabs__label' for='{0}'>{1}</label>" -f $tabId, $labelHtml
    $goodTabs += "<div class='report-tabs__panel'>$panelContent</div>"
    $index++
  }

  $goodTabs += "</div></div>"
  $goodContent = $goodTabs
}
$goodHtml = New-ReportSection -Title $goodTitle -ContentHtml $goodContent -Open

$issuesTitle = "Detected Issues ({0})" -f $issues.Count
if ($issues.Count -eq 0){
  $issuesContent = "<div class='report-card report-card--good'><span class='report-badge report-badge--good'>GOOD</span> No obvious issues detected from the provided outputs.</div>"
} else {
  $severitySortOrder = @{
    'critical' = 0
    'high'     = 1
    'medium'   = 2
    'low'      = 3
    'info'     = 4
  }

  $sortedIssues = $issues | Sort-Object -Stable -Property @(
    @{ Expression = { if ($severitySortOrder.ContainsKey($_.Severity)) { $severitySortOrder[$_.Severity] } else { [int]::MaxValue } } }
    @{ Expression = { if ($_.Area) { $_.Area.ToLowerInvariant() } else { '' } } }
    @{ Expression = { if ($_.Message) { $_.Message.ToLowerInvariant() } else { '' } } }
  )

  $severityDefinitions = @(
    @{ Key = 'critical'; Label = 'Critical'; BadgeClass = 'critical' },
    @{ Key = 'high';     Label = 'High';     BadgeClass = 'bad' },
    @{ Key = 'medium';   Label = 'Medium';   BadgeClass = 'warning' },
    @{ Key = 'low';      Label = 'Low';      BadgeClass = 'ok' },
    @{ Key = 'info';     Label = 'Info';     BadgeClass = 'good' }
  )

  $groupedIssues = [ordered]@{}
  foreach ($definition in $severityDefinitions) {
    $groupedIssues[$definition.Key] = New-Object System.Collections.Generic.List[string]
  }
  $otherIssues = New-Object System.Collections.Generic.List[string]

  foreach ($entry in $sortedIssues) {
    $cardHtml = New-IssueCardHtml -Entry $entry
    $severityKey = if ($entry.Severity) { $entry.Severity.ToLowerInvariant() } else { '' }
    if ($severityKey -and $groupedIssues.ContainsKey($severityKey)) {
      $groupedIssues[$severityKey].Add($cardHtml)
    } else {
      $otherIssues.Add($cardHtml)
    }
  }

  $activeDefinitions = @()
  foreach ($definition in $severityDefinitions) {
    if ($groupedIssues[$definition.Key].Count -gt 0) {
      $activeDefinitions += ,$definition
    }
  }
  if ($otherIssues.Count -gt 0) {
    $groupedIssues['other'] = $otherIssues
    $activeDefinitions += ,@{ Key = 'other'; Label = 'Other'; BadgeClass = 'ok' }
  }

  if ($activeDefinitions.Count -eq 0) {
    $issuesContent = ($sortedIssues | ForEach-Object { New-IssueCardHtml -Entry $_ }) -join ''
  } else {
    $tabName = 'issue-tabs'
    $issuesTabs = "<div class='report-tabs'><div class='report-tabs__list'>"
    $firstDefinition = $activeDefinitions[0]
    $firstKey = if ($firstDefinition.Key) { [string]$firstDefinition.Key } else { '' }
    $index = 0

    foreach ($definition in $activeDefinitions) {
      $keyValue = if ($definition.Key) { [string]$definition.Key } else { "severity$index" }
      if (-not $groupedIssues.ContainsKey($keyValue)) { continue }
      $cardsList = $groupedIssues[$keyValue]
      $count = $cardsList.Count
      $slug = [regex]::Replace($keyValue.ToLowerInvariant(), '[^a-z0-9]+', '-')
      $slug = [regex]::Replace($slug, '^-+|-+$', '')
      if (-not $slug) { $slug = "severity$index" }

      $tabId = "{0}-{1}" -f $tabName, $slug
      $checkedAttr = if ($keyValue.ToLowerInvariant() -eq $firstKey.ToLowerInvariant()) { " checked='checked'" } else { '' }

      $labelText = if ($definition.Label) { [string]$definition.Label } else { $keyValue }
      $badgeLabel = Encode-Html ($labelText.ToUpperInvariant())
      $countLabel = Encode-Html ("({0})" -f $count)
      $labelInner = "<span class='report-badge report-badge--{0} report-tabs__label-badge'>{1}</span><span class='report-tabs__label-count'>{2}</span>" -f $definition.BadgeClass, $badgeLabel, $countLabel
      $panelContent = if ($count -gt 0) { ($cardsList -join '') } else { "<div class='report-card'><i>No issues captured for this severity.</i></div>" }

      $issuesTabs += "<input type='radio' name='{0}' id='{1}' class='report-tabs__radio'{2}>" -f $tabName, $tabId, $checkedAttr
      $issuesTabs += "<label class='report-tabs__label' for='{0}'>{1}</label>" -f $tabId, $labelInner
      $issuesTabs += "<div class='report-tabs__panel'>$panelContent</div>"
      $index++
    }

    $issuesTabs += "</div></div>"
    $issuesContent = $issuesTabs
  }
}
$issuesHtml = New-ReportSection -Title $issuesTitle -ContentHtml $issuesContent -Open

# Raw extracts (key files)
$rawSections = ''
foreach($key in @('ipconfig','route','nslookup','ping','os_cim','computerinfo','firewall','defender','bitlocker')){
  if ($files[$key]) {
    $fileName = [IO.Path]::GetFileName($files[$key])
    $content = Read-Text $files[$key]
    $fileNameHtml = Encode-Html $fileName
    $contentHtml = Encode-Html $content
    $rawSections += "<details class='report-subsection'><summary>$fileNameHtml</summary><div class='report-subsection__body'><div class='report-card'><pre class='report-pre'>$contentHtml</pre></div></div></details>"
  }
}
if (-not $rawSections){
  $rawSections = "<div class='report-card'><i>No raw excerpts available.</i></div>"
}
$rawHtml = New-ReportSection -Title 'Raw (key excerpts)' -ContentHtml $rawSections

$filesDump = ($files.Keys | ForEach-Object {
    $resolved = if($files[$_]){ (Resolve-Path $files[$_] -ErrorAction SilentlyContinue).Path } else { "(not found)" }
    "{0} = {1}" -f $_, $resolved
  }) -join [Environment]::NewLine
$rawDump = ($raw.Keys | Where-Object { $raw[$_] } | ForEach-Object {
    $snippet = $raw[$_].Substring(0,[Math]::Min(120,$raw[$_].Length)).Replace("`r"," ").Replace("`n"," ")
    "{0}: {1}" -f $_, $snippet
  }) -join [Environment]::NewLine
if (-not $filesDump){ $filesDump = "(no files discovered)" }
if (-not $rawDump){ $rawDump = "(no raw entries populated)" }

$dnsDebugHtmlSection = ''
if ($summary.ContainsKey('DnsDebug') -and $summary.DnsDebug) {
  $dnsDebugData = $summary.DnsDebug
  $dnsDebugLines = @()

  if ($dnsDebugData -is [System.Collections.IDictionary]) {
    foreach ($key in $dnsDebugData.Keys) {
      $value = $dnsDebugData[$key]
      if ($null -eq $value) {
        $valueText = 'Unknown'
      } elseif ($value -is [string]) {
        $valueText = $value
      } elseif ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        $items = @()
        foreach ($item in $value) {
          if ($null -eq $item) {
            $items += 'Unknown'
          } else {
            $itemText = [string]$item
            if ([string]::IsNullOrWhiteSpace($itemText)) { $items += '(empty)' } else { $items += $itemText }
          }
        }
        if ($items.Count -eq 0) {
          $valueText = '(none)'
        } else {
          $valueText = $items -join ', '
        }
      } else {
        $valueText = [string]$value
      }

      if ([string]::IsNullOrWhiteSpace($valueText)) { $valueText = '(empty)' }
      $dnsDebugLines += ("{0}: {1}" -f $key, $valueText)
    }
  } else {
    $dnsDebugLines += [string]$dnsDebugData
  }

  if ($dnsDebugLines.Count -gt 0) {
    $dnsDebugText = $dnsDebugLines -join "`n"
    $dnsDebugHtmlSection = "<div class='report-card'><b>DNS heuristic data</b><pre class='report-pre'>$(Encode-Html $dnsDebugText)</pre></div>"
  }
}

$filesCardHtml = "<div class='report-card'><b>Files map</b><pre class='report-pre'>$(Encode-Html $filesDump)</pre></div>"
$rawCardHtml = "<div class='report-card'><b>Raw samples</b><pre class='report-pre'>$(Encode-Html $rawDump)</pre></div>"
$debugCards = @($filesCardHtml)
if ($dnsDebugHtmlSection) { $debugCards += $dnsDebugHtmlSection }
$debugCards += $rawCardHtml
$debugBodyHtml = ($debugCards -join '')
$debugHtml = "<details><summary>Debug</summary>$debugBodyHtml</details>"

$tail = "</body></html>"

# Write and return path
$reportName = "DeviceHealth_Report_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$reportPath = Join-Path $InputFolder $reportName
($head + $sumTable + $goodHtml + $issuesHtml + $failedHtml + $rawHtml + $debugHtml + $tail) | Out-File -FilePath $reportPath -Encoding UTF8
$reportPath
