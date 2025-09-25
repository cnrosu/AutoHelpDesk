<#
Analyze-Diagnostics.ps1  (fixed)
- Robust file detection (by name or content)
- Bracket indexing for hashtables ($raw['key'])
- Issues are [pscustomobject]
- CSS via literal here-string; summary via expanding here-string
USAGE:
  .\Analyze-Diagnostics.ps1 -InputFolder "C:\Path\To\DiagReports\20250924_181518"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$InputFolder
)

$ErrorActionPreference = 'SilentlyContinue'

$commonModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules/Common.psm1'
Import-Module $commonModulePath -Force

# DNS heuristics configuration (override in-line as needed)
[string[]]$AnycastDnsAllow = @()

# ---------- helpers ----------
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
      $rawValue = [string]$row.$propName
      if (-not $rawValue) { continue }
      $trimmedValue = $rawValue.Trim()
      if (-not $trimmedValue) { continue }

      switch ($propName) {
        'Enabled' {
          if ($trimmedValue -match '(?i)disabled') { $enabled = $false; continue }
          $boolValue = To-BoolOrNull $trimmedValue
          if ($null -ne $boolValue) { $enabled = $boolValue }
        }
        'Active' {
          $boolValue = To-BoolOrNull $trimmedValue
          if ($null -ne $boolValue) { $enabled = $boolValue }
        }
        'Disabled' {
          if ($trimmedValue -match '(?i)disabled') { $enabled = $false; continue }
          $boolValue = To-BoolOrNull $trimmedValue
          if ($null -ne $boolValue) { $enabled = -not $boolValue }
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
      $protectionEnabled = To-BoolOrNull -Value $protectionText
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
        'low'      { $badgeText = 'LOW';       $cssClass = 'ok' }
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
        $cat = Get-CategoryFromArea $area

        if (-not $script:Checks.ContainsKey($CheckId)) {
            $script:Checks[$CheckId] = @{
                CheckId       = $CheckId
                Category      = $cat
                Weight        = $Weight
                Attempted     = $true
                NA            = [bool]$NA
                Outcome       = 'Good'
                WorstSeverity = 'info'
                FirstMessage  = $msg
            }
        } else {
            $c = $script:Checks[$CheckId]
            $c['Attempted'] = $true
            if ($NA) { $c['NA'] = $true }
            # Do not downgrade if earlier marked as Issue
            if ($c['Outcome'] -ne 'Issue') {
                $c['Outcome'] = 'Good'
                $c['WorstSeverity'] = 'info'
            }
            $script:Checks[$CheckId] = $c
        }
    }
}


$securityHeuristics = New-Object System.Collections.Generic.List[pscustomobject]
$securityHealthOrder = @('good','info','warning','bad','critical')

function Normalize-SecurityHealth {
  param([string]$Value)

  if (-not $Value) { return 'info' }

  try {
    $lower = $Value.ToLowerInvariant()
  } catch {
    $lower = [string]$Value
    if ($lower) { $lower = $lower.ToLowerInvariant() }
  }

  switch ($lower) {
    'good' { return 'good' }
    'ok' { return 'good' }
    'pass' { return 'good' }
    'info' { return 'info' }
    'low' { return 'info' }
    'warning' { return 'warning' }
    'medium' { return 'warning' }
    'bad' { return 'bad' }
    'high' { return 'bad' }
    'critical' { return 'critical' }
    'fail' { return 'bad' }
    default { return 'info' }
  }
}

function Get-SecurityHealthIndex {
  param([string]$Value)

  $normalized = Normalize-SecurityHealth $Value
  return $securityHealthOrder.IndexOf($normalized)
}

function Get-WorstSecurityHealth {
  param([string]$First,[string]$Second)

  if (-not $First) { return (Normalize-SecurityHealth $Second) }
  if (-not $Second) { return (Normalize-SecurityHealth $First) }

  $firstIndex = Get-SecurityHealthIndex $First
  $secondIndex = Get-SecurityHealthIndex $Second

  if ($firstIndex -ge $secondIndex) { return (Normalize-SecurityHealth $First) }
  return (Normalize-SecurityHealth $Second)
}

function Add-SecurityHeuristic {
  param(
    [string]$Name,
    [string]$Status,
    [string]$Health = 'info',
    [string]$Details = '',
    [string]$Evidence = '',
    [string]$Area = 'Security',
    [switch]$SkipIssue,
    [switch]$SkipNormal
  )

  $controlName = if ($Name) { $Name } else { 'Control' }
  $statusText = if ($null -ne $Status) { $Status } else { '' }
  $normalizedHealth = Normalize-SecurityHealth $Health
  $detailText = if ($null -ne $Details) { $Details } else { '' }
  $evidenceTrimmed = ''
  if ($Evidence) {
    $evidenceTrimmed = $Evidence.Substring(0,[Math]::Min(1200,$Evidence.Length))
  }

  $combinedEvidenceParts = @()
  if (-not [string]::IsNullOrWhiteSpace($detailText)) { $combinedEvidenceParts += $detailText }
  if (-not [string]::IsNullOrWhiteSpace($evidenceTrimmed)) { $combinedEvidenceParts += $evidenceTrimmed }
  $combinedEvidence = if ($combinedEvidenceParts.Count -gt 0) { $combinedEvidenceParts -join "`n" } else { '' }
  $areaLabel = if (-not [string]::IsNullOrWhiteSpace($Area)) { $Area } else { 'Security' }
  $messageText = if ($statusText) { "{0}: {1}" -f $controlName, $statusText } else { $controlName }

  switch ($normalizedHealth) {
    'good' {
      if (-not $SkipNormal) {
        Add-Normal $areaLabel $messageText $combinedEvidence 'GOOD'
      }
    }
    'info' {
      if (-not $SkipNormal) {
        Add-Normal $areaLabel $messageText $combinedEvidence 'INFO'
      }
    }
    'warning' {
      if (-not $SkipIssue) {
        Add-Issue 'medium' $areaLabel $messageText $combinedEvidence
      }
    }
    'bad' {
      if (-not $SkipIssue) {
        Add-Issue 'high' $areaLabel $messageText $combinedEvidence
      }
    }
    'critical' {
      if (-not $SkipIssue) {
        Add-Issue 'critical' $areaLabel $messageText $combinedEvidence
      }
    }
    default {
      if (-not $SkipIssue) {
        Add-Issue 'info' $areaLabel $messageText $combinedEvidence
      }
    }
  }

  $securityHeuristics.Add([pscustomobject]@{
    Name     = $controlName
    Status   = $statusText
    Health   = $normalizedHealth
    Details  = $detailText
    Evidence = $evidenceTrimmed
  })
}

function Get-UptimeClassification {
  param(
    [double]$Days,
    [bool]$IsServer
  )

  $profileName = if ($IsServer) { 'Server' } else { 'Workstation' }
  $ranges = if ($IsServer) {
    @(
      @{ Label = 'Good';     Min = 0;   Max = 30; Severity = $null;        Css = 'uptime-good';     RangeText = '≤ 30 days' },
      @{ Label = 'Warning';  Min = 31;  Max = 60; Severity = 'medium';     Css = 'uptime-warning'; RangeText = '31–60 days' },
      @{ Label = 'Bad';      Min = 61;  Max = 90; Severity = 'high';       Css = 'uptime-bad';     RangeText = '61–90 days' },
      @{ Label = 'Critical'; Min = 91;  Max = $null; Severity = 'critical'; Css = 'uptime-critical'; RangeText = '> 90 days' }
    )
  } else {
    @(
      @{ Label = 'Good';     Min = 0;   Max = 14; Severity = $null;        Css = 'uptime-good';     RangeText = '≤ 14 days' },
      @{ Label = 'Warning';  Min = 15;  Max = 30; Severity = 'medium';     Css = 'uptime-warning'; RangeText = '15–30 days' },
      @{ Label = 'Bad';      Min = 31;  Max = 60; Severity = 'high';       Css = 'uptime-bad';     RangeText = '31–60 days' },
      @{ Label = 'Critical'; Min = 61;  Max = $null; Severity = 'critical'; Css = 'uptime-critical'; RangeText = '> 60 days' }
    )
  }

  foreach ($range in $ranges) {
    $min = if ($null -ne $range.Min) { [double]$range.Min } else { 0 }
    $max = if ($null -ne $range.Max) { [double]$range.Max } else { $null }
    if (($Days -ge $min) -and ($null -eq $max -or $Days -le $max)) {
      return [pscustomobject]@{
        Label       = $range.Label
        Severity    = $range.Severity
        CssClass    = $range.Css
        ProfileName = $profileName
        RangeText   = $range.RangeText
        MinDays     = $min
        MaxDays     = $max
      }
    }
  }

  return $null
}

# ---------- parsers ----------
$summary = @{}
$summary.Folder = (Resolve-Path $InputFolder).Path

# OS/build/boot
if ($raw['systeminfo']){
  $mOS  = [regex]::Match($raw['systeminfo'],'OS Name:\s*(.+)')
  $mVer = [regex]::Match($raw['systeminfo'],'OS Version:\s*(.+)')
  $mBt  = [regex]::Match($raw['systeminfo'],'System Boot Time:\s*(.+)')
  if ($mOS.Success){  $summary.OS = $mOS.Groups[1].Value.Trim() }
  if ($mVer.Success){ $summary.OS_Version = $mVer.Groups[1].Value.Trim() }
  if ($mBt.Success){  $summary.LastBoot = $mBt.Groups[1].Value.Trim() }
}
if (-not $summary.OS -and $raw['os_cim']){
  $m = [regex]::Match($raw['os_cim'],'Caption\s*:\s*(.+)'); if ($m.Success){ $summary.OS = $m.Groups[1].Value.Trim() }
}
if (-not $summary.OS_Version -and $raw['computerinfo']){
  $m = [regex]::Match($raw['computerinfo'],'WindowsBuildLabEx\s*:\s*(.+)'); if ($m.Success){ $summary.OS_Version = $m.Groups[1].Value.Trim() }
}
if (-not $summary.LastBoot -and $raw['os_cim']){
  $m = [regex]::Match($raw['os_cim'],'LastBootUpTime\s*:\s*(.+)'); if ($m.Success){ $summary.LastBoot = $m.Groups[1].Value.Trim() }
}

if (-not $summary.DeviceName -and $raw['computerinfo']){
  $m = [regex]::Match($raw['computerinfo'],'CsName\s*:\s*(.+)'); if ($m.Success){ $summary.DeviceName = $m.Groups[1].Value.Trim() }
}
if (-not $summary.DeviceName -and $raw['systeminfo']){
  $m = [regex]::Match($raw['systeminfo'],'(?im)^\s*Host Name\s*:\s*(.+)$'); if ($m.Success){ $summary.DeviceName = $m.Groups[1].Value.Trim() }
}
if ($raw['systeminfo']){
  if (-not $summary.Domain -or -not $summary.Domain.Trim()){
    $m = [regex]::Match($raw['systeminfo'],'(?im)^\s*Domain\s*:\s*(.+)$'); if ($m.Success){ $summary.Domain = $m.Groups[1].Value.Trim() }
  }
  if (-not $summary.DomainRole){
    $m = [regex]::Match($raw['systeminfo'],'(?im)^\s*Domain Role\s*:\s*(.+)$'); if ($m.Success){ $summary.DomainRole = $m.Groups[1].Value.Trim() }
  }
  if (-not $summary.LogonServer){
    $m = [regex]::Match($raw['systeminfo'],'(?im)^\s*Logon Server\s*:\s*(.+)$'); if ($m.Success){ $summary.LogonServer = $m.Groups[1].Value.Trim() }
  }
}

$computerInfoText = $raw['computerinfo']
$firmwareEvidenceLines = @()
$secureBootEvidenceLines = @()
if ($computerInfoText) {
  $biosFirmwareMatch = [regex]::Match($computerInfoText,'(?im)^\s*BiosFirmwareType\s*:\s*(.+)$')
  if ($biosFirmwareMatch.Success) {
    $summary.BiosFirmwareType = $biosFirmwareMatch.Groups[1].Value.Trim()
    $firmwareEvidenceLines += $biosFirmwareMatch.Value.Trim()
  }

  $biosModeMatch = [regex]::Match($computerInfoText,'(?im)^\s*BiosMode\s*:\s*(.+)$')
  if ($biosModeMatch.Success) {
    $summary.BiosMode = $biosModeMatch.Groups[1].Value.Trim()
    $firmwareEvidenceLines += $biosModeMatch.Value.Trim()
  }

  $secureBootMatch = [regex]::Match($computerInfoText,'(?im)^\s*BiosSecureBootState\s*:\s*(.+)$')
  if ($secureBootMatch.Success) {
    $summary.BiosSecureBootState = $secureBootMatch.Groups[1].Value.Trim()
    $secureBootEvidenceLines += $secureBootMatch.Value.Trim()
  }
}

$uefiIndicator = $null
if ($summary.BiosFirmwareType) {
  $uefiIndicator = $summary.BiosFirmwareType
} elseif ($summary.BiosMode) {
  $uefiIndicator = $summary.BiosMode
}

$uefiStatus = $null
if ($uefiIndicator) {
  $indicatorNormalized = ($uefiIndicator -replace '\s+', '').ToLowerInvariant()
  if ($indicatorNormalized -match 'uefi') {
    $uefiStatus = $true
  } elseif ($indicatorNormalized -match 'bios' -or $indicatorNormalized -match 'legacy') {
    $uefiStatus = $false
  }
}
if ($uefiStatus -ne $null) { $summary.UefiFirmware = $uefiStatus }

$firmwareEvidenceText = $null
if ($firmwareEvidenceLines.Count -gt 0) {
  $firmwareEvidenceText = $firmwareEvidenceLines -join "`n"
} elseif ($computerInfoText) {
  $firmwareEvidenceText = (([regex]::Split($computerInfoText,'\r?\n') | Where-Object { $_ -match '(?i)Bios' } | Select-Object -First 6)) -join "`n"
}

if ($uefiStatus -eq $true) {
  Add-Normal "System/Firmware" "UEFI firmware mode detected" $firmwareEvidenceText
} elseif ($uefiStatus -eq $false) {
  Add-Issue "medium" "System/Firmware" "Legacy BIOS firmware mode detected—enable UEFI to support modern security protections." $firmwareEvidenceText
} elseif ($computerInfoText) {
  Add-Issue "low" "System/Firmware" "Unable to determine firmware mode from Get-ComputerInfo output." $firmwareEvidenceText
}

$secureBootState = $summary.BiosSecureBootState
$secureBootEvidenceText = $null
if ($secureBootState) {
  if ($uefiIndicator) {
    $secureBootEvidenceLines += ("Firmware indicator: {0}" -f $uefiIndicator)
  }
  $secureBootEvidenceText = $secureBootEvidenceLines -join "`n"
  $secureBootValue = To-BoolOrNull -Value $secureBootState
  if ($secureBootValue -eq $true) {
    Add-Normal "System/Secure Boot" "Secure Boot enabled" $secureBootEvidenceText
    $summary.SecureBootEnabled = $true
  } elseif ($secureBootValue -eq $false) {
    # CIS Windows benchmarks and Microsoft security baselines require Secure Boot to
    # remain enabled to protect boot integrity, so treat a disabled state as a high
    # severity finding.
    Add-Issue "high" "System/Secure Boot" "Secure Boot is disabled." $secureBootEvidenceText
    $summary.SecureBootEnabled = $false
  } elseif ($secureBootState -match '(?i)unsupported|not supported') {
    Add-Issue "high" "System/Secure Boot" "Secure Boot unsupported on this hardware." $secureBootEvidenceText
  } else {
    Add-Issue "high" "System/Secure Boot" ("Secure Boot state reported as '{0}'." -f $secureBootState) $secureBootEvidenceText
  }
} elseif ($computerInfoText -and $uefiStatus -eq $true) {
  $secureBootEvidenceText = $firmwareEvidenceText
  Add-Issue "high" "System/Secure Boot" "Secure Boot state not reported despite UEFI firmware." $secureBootEvidenceText
}

$fastStartupState = $null
$fastStartupEvidenceLines = @()
if ($raw['power_settings']) {
  $powerSettingsText = $raw['power_settings']
  $hiberMatch = [regex]::Match($powerSettingsText,'(?im)^\s*HiberbootEnabled\s*[:=]\s*(.+)$')
  if ($hiberMatch.Success) {
    $hiberValueText = $hiberMatch.Groups[1].Value.Trim()
    if ($hiberValueText) { $fastStartupEvidenceLines += $hiberMatch.Value.Trim() }
    $fastStartupState = To-BoolOrNull -Value $hiberValueText
    if ($fastStartupState -eq $null) {
      $numericMatch = [regex]::Match($hiberValueText,'0x[0-9a-fA-F]+|\d+')
      if ($numericMatch.Success) {
        $numericText = $numericMatch.Value
        try {
          if ($numericText -match '^0x') {
            $fastStartupState = ([Convert]::ToInt32($numericText.Substring(2),16) -ne 0)
          } else {
            $fastStartupState = ([int]$numericText -ne 0)
          }
        } catch {
          $fastStartupState = $null
        }
      }
    }
  } elseif ($powerSettingsText -match '(?i)value not present') {
    $fastStartupEvidenceLines += 'HiberbootEnabled value not present.'
  }

  $fastStartupLines = [regex]::Matches($powerSettingsText,'(?im)^.*Fast Startup.*$')
  foreach ($lineMatch in $fastStartupLines) {
    $lineValue = $lineMatch.Value.Trim()
    if ($lineValue) { $fastStartupEvidenceLines += $lineValue }
  }
}

if ($fastStartupState -ne $null) {
  $summary.FastStartupEnabled = $fastStartupState
}

if ($fastStartupState -eq $true) {
  $fastStartupEvidence = $fastStartupEvidenceLines -join "`n"
  if (-not $fastStartupEvidence) { $fastStartupEvidence = 'HiberbootEnabled value indicates Fast Startup enabled.' }
  Add-Issue "low" "System/Fast Startup" "Fast Startup (Fast Boot) is enabled. Disable Fast Startup for consistent shutdown and troubleshooting." $fastStartupEvidence
} elseif ($fastStartupState -eq $false) {
  $fastStartupEvidence = $fastStartupEvidenceLines -join "`n"
  if ($fastStartupEvidence) {
    Add-Normal "System/Fast Startup" "Fast Startup disabled" $fastStartupEvidence
  }
} elseif ($raw['power_settings']) {
  $fastStartupEvidence = $fastStartupEvidenceLines -join "`n"
  if ($fastStartupEvidence) {
    Add-Issue "low" "System/Fast Startup" "Unable to determine Fast Startup (Fast Boot) state from available data." $fastStartupEvidence
  }
}

$autorunsText = $raw['autoruns']
if (-not [string]::IsNullOrWhiteSpace($autorunsText)) {
  $autorunsParse = Parse-AutorunsEntries $autorunsText
  $autorunEntries = $autorunsParse.Entries
  if (-not $autorunsParse.HeaderFound) {
    $autorunsEvidence = Get-TopLines $autorunsText 20
    Add-Issue 'low' 'System/Startup Programs' 'Autoruns output detected but format not recognized for automated analysis. Review manually for startup bloat.' $autorunsEvidence
  } else {
    $enabledEntries = @($autorunEntries | Where-Object { $_.Enabled -ne $false })
    $totalAutoruns = $enabledEntries.Count
    $nonMicrosoftEntries = @($enabledEntries | Where-Object { $_.IsMicrosoft -ne $true })
    $nonMicrosoftCount = $nonMicrosoftEntries.Count
    $summary.AutorunsTotal = $totalAutoruns
    $summary.AutorunsNonMicrosoft = $nonMicrosoftCount

    if ($totalAutoruns -eq 0) {
      Add-Normal 'System/Startup Programs' 'Autoruns captured: no enabled startup entries detected.' '' 'INFO'
    } else {
      $evidenceParts = New-Object System.Collections.Generic.List[string]
      [void]$evidenceParts.Add("Total autorun entries evaluated: $totalAutoruns")
      [void]$evidenceParts.Add("Non-Microsoft autorun entries: $nonMicrosoftCount")
      $topEntries = @($nonMicrosoftEntries | Select-Object -First 8)
      foreach ($entry in $topEntries) {
        $linePieces = @()
        $linePieces += $entry.Entry
        if ($entry.Description) { $linePieces += $entry.Description }
        if ($entry.Publisher) { $linePieces += ("Publisher: {0}" -f $entry.Publisher) }
        else { $linePieces += 'Publisher: (unknown)' }
        if ($entry.Location) { $linePieces += ("Location: {0}" -f $entry.Location) }
        elseif ($entry.ImagePath) { $linePieces += ("Path: {0}" -f $entry.ImagePath) }
        $lineText = ($linePieces -join ' | ')
        if ($lineText) { [void]$evidenceParts.Add($lineText) }
      }
      $remaining = $nonMicrosoftCount - $topEntries.Count
      if ($remaining -gt 0) {
        [void]$evidenceParts.Add("(+{0} additional non-Microsoft autorun entries)" -f $remaining)
      }
      $autorunsEvidence = $evidenceParts -join "`n"

      if ($nonMicrosoftCount -gt 10) {
        $message = "Startup autoruns bloat: {0} non-Microsoft entries detected. Review and trim startup apps to reduce login delay." -f $nonMicrosoftCount
        Add-Issue 'medium' 'System/Startup Programs' $message $autorunsEvidence
      } elseif ($nonMicrosoftCount -gt 5) {
        $message = "Startup autoruns trending high: {0} non-Microsoft entries detected. Consider pruning unnecessary startup items." -f $nonMicrosoftCount
        Add-Issue 'low' 'System/Startup Programs' $message $autorunsEvidence
      } else {
        Add-Normal 'System/Startup Programs' ("Startup autoruns manageable ({0} non-Microsoft entries out of {1})." -f $nonMicrosoftCount, $totalAutoruns) '' 'INFO'
      }
    }
  }
} elseif ($files['autoruns']) {
  Add-Issue 'low' 'System/Startup Programs' 'Autoruns file present but empty.' ''
}

if ($raw['dsreg']){
  $dsregMap = @{}
  foreach($line in [regex]::Split($raw['dsreg'],'\r?\n')){
    $match = [regex]::Match($line,'^\s*([^:]+?)\s*:\s*(.+)$')
    if ($match.Success){
      $key = $match.Groups[1].Value.Trim()
      $value = $match.Groups[2].Value.Trim()
      if ($key){ $dsregMap[$key] = $value }
    }
  }

  if ($dsregMap.ContainsKey('AzureAdJoined')){
    $aad = To-BoolOrNull $dsregMap['AzureAdJoined']
    if ($null -ne $aad){ $summary.AzureAdJoined = $aad }
  }
  if ($dsregMap.ContainsKey('WorkplaceJoined')){
    $wp = To-BoolOrNull $dsregMap['WorkplaceJoined']
    if ($null -ne $wp){ $summary.WorkplaceJoined = $wp }
  }
  if ($dsregMap.ContainsKey('EnterpriseJoined')){
    $ent = To-BoolOrNull $dsregMap['EnterpriseJoined']
    if ($null -ne $ent){ $summary.EnterpriseJoined = $ent }
  }
  if ($dsregMap.ContainsKey('DomainJoined')){
    $dj = To-BoolOrNull $dsregMap['DomainJoined']
    if ($null -ne $dj){ $summary.DomainJoined = $dj }
  }
  foreach($deviceKey in @('Device Name','DeviceName')){
    if (-not $summary.DeviceName -and $dsregMap.ContainsKey($deviceKey)){
      $summary.DeviceName = $dsregMap[$deviceKey]
      break
    }
  }
  if (-not $summary.Domain -and $dsregMap.ContainsKey('DomainName')){
    $summary.Domain = $dsregMap['DomainName']
  }
  if ($dsregMap.ContainsKey('TenantName')){ $summary.AzureAdTenantName = $dsregMap['TenantName'] }
  if ($dsregMap.ContainsKey('TenantId')){ $summary.AzureAdTenantId = $dsregMap['TenantId'] }
  if ($dsregMap.ContainsKey('IdpDomain')){ $summary.AzureAdTenantDomain = $dsregMap['IdpDomain'] }
  foreach($deviceIdKey in @('AzureAdDeviceId','DeviceId')){
    if ($dsregMap.ContainsKey($deviceIdKey)){
      $summary.AzureAdDeviceId = $dsregMap[$deviceIdKey]
      break
    }
  }
}

if ($summary.Domain -and $summary.DomainJoined -eq $null){
  $domainTrimmed = $summary.Domain.Trim()
  if ($domainTrimmed -and $domainTrimmed.ToUpperInvariant() -eq 'WORKGROUP'){
    $summary.DomainJoined = $false
  }
}

$summary.IsServer = $null
if ($summary.OS -and $summary.OS -match 'server'){
  $summary.IsServer = $true
} elseif ($summary.OS_Version -and $summary.OS_Version -match 'server'){
  $summary.IsServer = $true
} elseif ($summary.OS -or $summary.OS_Version) {
  $summary.IsServer = $false
}

if ($summary.LastBoot){
  $bootDt = $null
  if ($summary.LastBoot -match '^\d{14}\.\d{6}[-+]\d{3}$'){
    try { $bootDt = [System.Management.ManagementDateTimeConverter]::ToDateTime($summary.LastBoot) } catch {}
  }
  if (-not $bootDt){
    $parsedBoot = $null
    foreach ($culture in @([System.Globalization.CultureInfo]::CurrentCulture, [System.Globalization.CultureInfo]::InvariantCulture)) {
      try {
        $parsedBoot = [datetime]::Parse($summary.LastBoot, $culture)
        break
      } catch {
        $parsedBoot = $null
      }
    }
    if ($parsedBoot) {
      $now = Get-Date
      if ($parsedBoot -le $now.AddMinutes(1)) {
        $bootDt = $parsedBoot
      }
    }
  }
    if ($bootDt){
      $uptimeDays = (New-TimeSpan -Start $bootDt -End (Get-Date)).TotalDays
      $classification = Get-UptimeClassification -Days $uptimeDays -IsServer:($summary.IsServer -eq $true)
      if ($classification){
        $summary.UptimeDays = $uptimeDays
        $summary.UptimeStatus = $classification
        $roundedDays = [math]::Round($uptimeDays,1)
        $rangeText = $classification.RangeText
        $profileName = $classification.ProfileName
        $rangeSuffix = if ($rangeText) { " ({0})" -f $rangeText } else { "" }
        if ($classification.Label -eq 'Good'){
          $message = "{0} uptime {1} days within {2} range{3}." -f $profileName, $roundedDays, $classification.Label, $rangeSuffix
          Add-Normal "System/Uptime" $message $summary.LastBoot
        } elseif ($classification.Severity) {
          $message = "{0} uptime {1} days in {2} range{3}." -f $profileName, $roundedDays, $classification.Label, $rangeSuffix
          Add-Issue $classification.Severity "System/Uptime" $message $summary.LastBoot
        }
      }
    } else {
    Add-Normal "System/Uptime" "Last boot captured" $summary.LastBoot
  }
}

$outlookConnectivityResult = $null
$outlookOstDomains = @()

# ipconfig
if ($raw['ipconfig']){
  $ipv4s = [regex]::Matches($raw['ipconfig'],'IPv4 Address[^\d]*([\d\.]+)') | ForEach-Object { $_.Groups[1].Value }
  if (-not $ipv4s){ $ipv4s = [regex]::Matches($raw['ipconfig'],'IP(v4)? Address[^\d]*([\d\.]+)') | ForEach-Object { $_.Groups[2].Value } }
  $gws   = [regex]::Matches($raw['ipconfig'],'Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)') | ForEach-Object { $_.Groups[1].Value }
  $dns   = [regex]::Matches($raw['ipconfig'],'DNS Servers[^\d]*(\d+\.\d+\.\d+\.\d+)') | ForEach-Object { $_.Groups[1].Value }

  $uniqueIPv4 = @()
  foreach ($ip in $ipv4s) {
    if (-not $ip) { continue }
    if ($uniqueIPv4 -notcontains $ip) { $uniqueIPv4 += $ip }
  }
  $uniqueGws = @()
  foreach ($gw in $gws) {
    if (-not $gw) { continue }
    if ($uniqueGws -notcontains $gw) { $uniqueGws += $gw }
  }
  $dnsServers = @()
  foreach ($server in $dns) {
    if (-not $server) { continue }
    if ($dnsServers -notcontains $server) { $dnsServers += $server }
  }

  $summary.IPv4    = $uniqueIPv4 -join ", "
  $summary.Gateway = $uniqueGws  -join ", "
  $summary.DNS     = $dnsServers -join ", "

  if (-not $uniqueIPv4){ Add-Issue "critical" "Network" "No IPv4 address detected (driver/DHCP/link)." $raw['ipconfig'] }
  if ($uniqueIPv4 | Where-Object { $_ -like "169.254.*" }){ Add-Issue "critical" "Network" "APIPA address 169.254.x.x → DHCP/link issue." ($uniqueIPv4 -join ", ") }
  if (-not $uniqueGws){ Add-Issue "high" "Network" "No default gateway — internet likely broken." "" }

  if ($uniqueIPv4 -and -not ($uniqueIPv4 | Where-Object { $_ -like "169.254.*" })) {
    Add-Normal "Network/IP" "IPv4 address acquired" ("IPv4: " + ($uniqueIPv4 -join ", "))
  }
  if ($uniqueGws) {
    Add-Normal "Network/Routing" "Default gateway present" ("GW: " + ($uniqueGws -join ", "))
  }

  $dnsContextHandled = $false
  if ($dnsServers -and $dnsServers.Count -gt 0) {
    $domainJoined = $null
    $domainName = $null
    $forestName = $null

    try {
      $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
      if ($null -ne $cs.PartOfDomain) { $domainJoined = [bool]$cs.PartOfDomain }
      if ($cs.Domain) { $domainName = $cs.Domain.Trim() }
    } catch {}

    if ($env:USERDNSDOMAIN) { $forestName = $env:USERDNSDOMAIN.Trim() }

    if (-not $domainName -and $raw['systeminfo']) {
      $domainMatch = [regex]::Match($raw['systeminfo'],'(?im)^\s*Domain\s*:\s*(.+)$')
      if ($domainMatch.Success) { $domainName = $domainMatch.Groups[1].Value.Trim() }
    }

    if (-not $forestName -and $raw['systeminfo']) {
      $suffixMatch = [regex]::Match($raw['systeminfo'],'(?im)^\s*Primary Dns Suffix\s*:\s*(.+)$')
      if ($suffixMatch.Success) { $forestName = $suffixMatch.Groups[1].Value.Trim() }
    }

    if (-not $forestName -and $domainName) { $forestName = $domainName }
    if ($domainName) { $summary.Domain = $domainName }

    $domainUpper = if ($domainName) { $domainName.Trim().ToUpperInvariant() } else { $null }
    if ($domainUpper -eq 'WORKGROUP') { $domainJoined = $false }

    if ($null -eq $domainJoined) {
      if ($domainUpper -and $domainUpper -ne 'WORKGROUP') {
        $domainJoined = $true
      } else {
        $domainJoined = $false
      }
    }

    if ($domainJoined -eq $true) { $summary.DomainJoined = $true }
    elseif ($domainJoined -eq $false) { $summary.DomainJoined = $false }

    $dnsDebugData = [ordered]@{
      PartOfDomain           = $domainJoined
      DomainName             = $domainName
      ForestName             = $forestName
      ConfiguredDns          = $dnsServers
      AdCapableDns           = @()
      DcHosts                = @()
      DcIPs                  = @()
      DcCount                = 0
      DnsTestsAvailable      = $null
      DnsTestsAttempted      = $null
      DcQueryName            = $null
      PublicDns              = @()
      SecureChannelOK        = $null
      AnycastOverrideMatched = $false
    }

    if ($domainJoined -eq $false) {
      Add-Normal "DNS/Internal" "GOOD DNS/Internal: Workgroup device, policy N/A."
      Add-Normal "Network/DNS" "Workgroup/standalone: DNS servers configured" ("DNS: " + ($dnsServers -join ", "))
      $summary.DnsDebug = $dnsDebugData
      $dnsContextHandled = $true
    } elseif ($domainJoined -eq $true) {
      Add-Normal "Network/DNS" "Domain-joined: DNS servers captured" ("DNS: " + ($dnsServers -join ", "))
      $dnsContextHandled = $true

      $forestForQuery = if ($forestName) { $forestName } else { $domainName }
      $dcHosts = @()
      $dcIPs = @()
      $dnsTestsAvailable = $true
      $dnsTestsAttempted = $false

      if ($forestForQuery) {
        $dcSrvName = "_ldap._tcp.dc._msdcs.$forestForQuery"
        $srvRecords = Resolve-Safe -Name $dcSrvName -Type SRV
        if ($null -eq $srvRecords) {
          $dnsTestsAvailable = $false
          $srvRecords = @()
        } else {
          $dnsTestsAttempted = $true
          if ($srvRecords.Count -gt 0) {
            $dcHosts = $srvRecords | Select-Object -ExpandProperty NameTarget -Unique
          }
        }
      }

      foreach ($host in $dcHosts) {
        $aRecords = Resolve-Safe -Name $host -Type A
        if ($null -eq $aRecords) {
          $dnsTestsAvailable = $false
          $aRecords = @()
        } else {
          $dnsTestsAttempted = $true
          if ($aRecords.Count -gt 0) {
            $dcIPs += ($aRecords | Select-Object -ExpandProperty IPAddress)
          }
        }
      }
      $dcIPs = $dcIPs | Where-Object { $_ } | Select-Object -Unique
      $dcCount = $dcIPs.Count
      $dnsDebugData.DcHosts = $dcHosts
      $dnsDebugData.DcIPs = $dcIPs
      $dnsDebugData.DcCount = $dcCount
      $dnsDebugData.DnsTestsAvailable = $dnsTestsAvailable
      $dnsDebugData.DnsTestsAttempted = $dnsTestsAttempted
      $dnsDebugData.DcQueryName = if ($forestForQuery) { "_ldap._tcp.dc._msdcs.$forestForQuery" } else { $null }

      $dnsEval = @()
      foreach ($server in $dnsServers) {
        $auth = $null
        $srv = $null
        if ($domainName -and $domainUpper -ne 'WORKGROUP') {
          $auth = Test-ServerAuthoritative -Server $server -Zone $domainName
          if ($null -eq $auth) {
            $dnsTestsAvailable = $false
          } else {
            $dnsTestsAttempted = $true
          }
        }
        if ($forestForQuery) {
          $srv = Test-ServerKnowsAD -Server $server -Forest $forestForQuery
          if ($null -eq $srv) {
            $dnsTestsAvailable = $false
          } else {
            $dnsTestsAttempted = $true
          }
        }
        $isPrivate = Test-IsRFC1918 $server
        $dnsEval += [pscustomobject]@{
          Server          = $server
          IsRFC1918       = $isPrivate
          IsPublic        = -not $isPrivate
          IsDCIP          = $dcIPs -contains $server
          AuthoritativeAD = $auth
          ResolvesADSRV   = $srv
        }
      }

      $configuredCount = if ($dnsServers) { $dnsServers.Count } else { 0 }
      $adCapableInOrder = @()
      foreach ($server in $dnsServers) {
        $entry = $dnsEval | Where-Object { $_.Server -eq $server } | Select-Object -First 1
        if ($entry -and ($entry.IsDCIP -or $entry.AuthoritativeAD -eq $true -or $entry.ResolvesADSRV -eq $true)) {
          if ($adCapableInOrder -notcontains $server) { $adCapableInOrder += $server }
        }
      }
      $dnsDebugData.AdCapableDns = $adCapableInOrder

      $dnsEvalTable = if ($dnsEval -and $dnsEval.Count -gt 0) { $dnsEval | Format-Table -AutoSize | Out-String } else { '' }

      $normalizedAllow = @()
      if ($AnycastDnsAllow) {
        $normalizedAllow = $AnycastDnsAllow | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique
      }
      $anycastOverrideMatch = $false
      $primaryServer = $dnsServers | Select-Object -First 1
      if ($configuredCount -eq 1 -and $primaryServer) {
        if ($normalizedAllow -and ($normalizedAllow -contains $primaryServer)) {
          $anycastOverrideMatch = $true
        }
      }
      $dnsDebugData.AnycastOverrideMatched = $anycastOverrideMatch

      $secureOK = $null
      try { $secureOK = Test-ComputerSecureChannel -Verbose:$false -ErrorAction Stop } catch { $secureOK = $null }
      $dnsDebugData.SecureChannelOK = $secureOK

      $canEvaluateDns = $dnsTestsAvailable -and ($dnsTestsAttempted -or $dcIPs.Count -gt 0)

      $dnsEvidenceLines = @()
      if ($configuredCount -gt 0) { $dnsEvidenceLines += ("Configured DNS: " + ($dnsServers -join ", ")) }
      if ($adCapableInOrder.Count -gt 0) {
        $dnsEvidenceLines += ("AD-capable DNS: " + ($adCapableInOrder -join ", "))
      } else {
        $dnsEvidenceLines += "AD-capable DNS: (none)"
      }
      if ($dcIPs.Count -gt 0) {
        $dnsEvidenceLines += ("Discovered DC IPs: " + ($dcIPs -join ", "))
      } else {
        $dnsEvidenceLines += "Discovered DC IPs: (none)"
      }
      $dnsEvidenceLines += ("DC count: " + $dcCount)
      if ($normalizedAllow -and $normalizedAllow.Count -gt 0) {
        $dnsEvidenceLines += ("Anycast allowlist: " + ($normalizedAllow -join ", "))
      }
      $dnsEvidenceLines += ("Anycast override matched: " + ([string]$anycastOverrideMatch))
      $dnsEvidenceLines += ("Secure channel healthy: " + (if ($null -eq $secureOK) { 'Unknown' } else { [string]$secureOK }))
      if ($dcCount -ge 2 -and $adCapableInOrder.Count -lt 2) {
        $dnsEvidenceLines += ("Note: {0} DC IPs discovered; only {1} AD-capable resolver(s) configured." -f $dcCount, $adCapableInOrder.Count)
      }
      if ($dnsEvalTable) {
        $dnsEvidenceLines += ''
        $dnsEvidenceLines += $dnsEvalTable.TrimEnd()
      }
      $dnsEvidence = $dnsEvidenceLines -join "`n"

      if ($anycastOverrideMatch) {
        Add-Normal "DNS/Internal" ("GOOD DNS/Internal: Single Anycast/VIP resolver approved by policy: {0}." -f $primaryServer) $dnsEvidence
      } elseif ($canEvaluateDns) {
        if ($adCapableInOrder.Count -ge 2) {
          Add-Normal "DNS/Internal" ("GOOD DNS/Internal: Two or more AD-capable DNS servers detected: {0}." -f ($adCapableInOrder -join ", ")) $dnsEvidence
        } elseif ($adCapableInOrder.Count -eq 1) {
          $singleCapable = $adCapableInOrder[0]
          $severity = if ($secureOK -eq $false) { 'medium' } else { 'high' }
          Add-Issue $severity "DNS/Internal" ("DNS/Internal: Only one AD-capable DNS server configured (no failover) — {0}." -f $singleCapable) $dnsEvidence
        } else {
          if ($secureOK -eq $false) {
            Add-Issue 'medium' "DNS/Internal" "DNS/Internal: Domain-joined but AD-capable DNS not present; device likely off-network/VPN down." $dnsEvidence
          } else {
            Add-Issue 'high' "DNS/Internal" "DNS/Internal: No AD-capable DNS resolvers configured; AD lookups will fail." $dnsEvidence
          }
        }
      }

      $publicServers = $dnsEval | Where-Object { $_.IsPublic }
      $pubList = @()
      if ($publicServers) {
        $pubList = $publicServers | Select-Object -ExpandProperty Server -Unique
      }
      $dnsDebugData.PublicDns = $pubList
      if (-not $anycastOverrideMatch -and $pubList.Count -gt 0) {
        Add-Issue "medium" "DNS/Internal" "Domain-joined: public DNS servers detected ($($pubList -join ', '))." $dnsEvalTable
      }

      if (-not $anycastOverrideMatch -and $primaryServer) {
        $primaryEval = $dnsEval | Where-Object { $_.Server -eq $primaryServer } | Select-Object -First 1
        $adCapableLater = $adCapableInOrder | Where-Object { $_ -ne $primaryServer } | Select-Object -First 1
        if ($primaryEval -and $primaryEval.IsPublic -and $adCapableLater) {
          Add-Issue "low" "DNS/Order" ("DNS/Order: Primary DNS is public; move internal AD-capable DNS to the top: Primary={0}; Internal={1}." -f $primaryServer, $adCapableLater) ("Primary: $primaryServer`nInternal: $adCapableLater`nAll: " + ($dnsServers -join ", "))
        }
      }

      $summary.DnsDebug = $dnsDebugData
      $summary.DnsDebugEvidence = $dnsEvidence
    }
  }

  if (-not $dnsContextHandled -and $dnsServers -and $dnsServers.Count -gt 0) {
    Add-Normal "Network/DNS" "DNS servers configured" ("DNS: " + ($dnsServers -join ", "))
  }
}

# route
if ($raw['route']){
  $hasDefault = [regex]::IsMatch($raw['route'],'\s0\.0\.0\.0\s+0\.0\.0\.0\s+\d+\.\d+\.\d+\.\d+')
  if (-not $hasDefault) {
    Add-Issue "high" "Network" "Routing table lacks a default route (0.0.0.0/0)." $raw['route']
  }
  if ($hasDefault) {
    $routeLines = ([regex]::Split($raw['route'],'\r?\n') | Where-Object { $_ -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0' } | Select-Object -First 2)
    if ($routeLines){
      Add-Normal "Network/Routing" "Default route 0.0.0.0/0 present" ($routeLines -join "`n")
    }
  }
}

$osCimMap = $null
if ($raw['os_cim']) {
  $osCimMap = Parse-KeyValueBlock $raw['os_cim']
}

$osVersionMajor = $null
if ($osCimMap -and $osCimMap.ContainsKey('Version')) {
  $versionText = $osCimMap['Version']
  if ($versionText) {
    $firstPart = ($versionText -split '\.')[0]
    $parsedMajor = 0
    if ([int]::TryParse($firstPart, [ref]$parsedMajor)) {
      $osVersionMajor = $parsedMajor
    }
  }
}
if (-not $osVersionMajor -and $summary.OS_Version) {
  $firstPart = ($summary.OS_Version -split '\.')[0]
  $parsedMajor = 0
  if ([int]::TryParse($firstPart, [ref]$parsedMajor)) {
    $osVersionMajor = $parsedMajor
  }
}
if ($osVersionMajor) { $summary.OSVersionMajor = $osVersionMajor }

$computerSystemJson = ConvertFrom-JsonSafe $raw['security_computersystem']
$systemSkuNumber = $null
$pcSystemType = $null
$pcSystemTypeEx = $null
$partOfDomainFromCs = $null
if ($computerSystemJson) {
  if ($computerSystemJson.PSObject.Properties['SystemSkuNumber']) {
    $systemSkuNumber = [string]$computerSystemJson.SystemSkuNumber
  }
  if ($computerSystemJson.PSObject.Properties['PCSystemType']) {
    $pcSystemType = ConvertTo-NullableInt $computerSystemJson.PCSystemType
  }
  if ($computerSystemJson.PSObject.Properties['PCSystemTypeEx']) {
    $pcSystemTypeEx = ConvertTo-NullableInt $computerSystemJson.PCSystemTypeEx
  }
  if ($computerSystemJson.PSObject.Properties['PartOfDomain']) {
    $partOfDomainFromCs = $computerSystemJson.PartOfDomain
  }
  if ($computerSystemJson.PSObject.Properties['Domain']) {
    if (-not $summary.Domain) { $summary.Domain = [string]$computerSystemJson.Domain }
  }
}
if ($systemSkuNumber) { $summary.SystemSkuNumber = $systemSkuNumber }

if ($summary.DomainJoined -eq $null -and $null -ne $partOfDomainFromCs) {
  try {
    $summary.DomainJoined = [bool]$partOfDomainFromCs
  } catch {}
}

$enclosureJson = ConvertFrom-JsonSafe $raw['security_systemenclosure']
$chassisTypes = @()
if ($enclosureJson) {
  if ($enclosureJson -is [System.Collections.IEnumerable] -and -not ($enclosureJson -is [string])) {
    foreach ($entry in $enclosureJson) {
      if (-not $entry) { continue }
      if ($entry.PSObject.Properties['ChassisTypes']) {
        $chassisTypes += (ConvertTo-IntArray $entry.ChassisTypes)
      }
    }
  } elseif ($enclosureJson.PSObject.Properties['ChassisTypes']) {
    $chassisTypes = ConvertTo-IntArray $enclosureJson.ChassisTypes
  }
}
if ($chassisTypes) {
  $chassisTypes = $chassisTypes | Where-Object { $_ -ne $null } | Sort-Object -Unique
}

$mobileChassisValues = @(8,9,10,11,12,14,18,21,30,31,32,33,34)
$mobilePcSystemTypes = @(2,8,9,10,11)
$isLaptop = $false
foreach ($ct in $chassisTypes) {
  if ($mobileChassisValues -contains $ct) { $isLaptop = $true; break }
}
if (-not $isLaptop -and $pcSystemType -ne $null -and ($mobilePcSystemTypes -contains $pcSystemType)) {
  $isLaptop = $true
}
if (-not $isLaptop -and $pcSystemTypeEx -ne $null -and ($mobilePcSystemTypes -contains $pcSystemTypeEx)) {
  $isLaptop = $true
}
if (-not $isLaptop -and $computerSystemJson) {
  $family = $null
  if ($computerSystemJson.PSObject.Properties['SystemFamily']) { $family = [string]$computerSystemJson.SystemFamily }
  if (-not $family -and $computerSystemJson.PSObject.Properties['Model']) { $family = [string]$computerSystemJson.Model }
  if ($family) {
    try {
      $familyLower = $family.ToLowerInvariant()
      if ($familyLower -match '(?i)laptop|notebook|mobile|portable|ultrabook') { $isLaptop = $true }
    } catch {}
  }
}
$summary.IsLaptop = $isLaptop

$isWorkstationProfile = ($summary.IsServer -ne $true)
$isModernClient = $false
if ($isWorkstationProfile -and $osVersionMajor -ge 10) {
  $isModernClient = $true
}
$summary.IsModernClient = $isModernClient

# nslookup / ping / tracert
if ($raw['nslookup'] -and ($raw['nslookup'] -match "Request timed out|Non-existent domain")){
  Add-Issue "medium" "DNS" "nslookup shows timeouts or NXDOMAIN." $raw['nslookup']
}
if ($raw['nslookup'] -and $raw['nslookup'] -match "Server:\s*(.+)") {
  Add-Normal "DNS" "DNS resolver responds" (([regex]::Split($raw['nslookup'],'\r?\n') | Select-Object -First 6) -join "`n")
}
if ($raw['ping'] -and ($raw['ping'] -match "Received\s*=\s*0")){
  Add-Issue "high" "Network" "Ping to 8.8.8.8 failed (0 received)." $raw['ping']
}
if ($raw['ping']){
  $pingMatch = [regex]::Match($raw['ping'],'Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)')
  if ($pingMatch.Success) {
    $sent = [int]$pingMatch.Groups[1].Value
    $rcv = [int]$pingMatch.Groups[2].Value
    $lost = [int]$pingMatch.Groups[3].Value
    if ($sent -gt 0 -and $lost -eq 0) {
      $avgMatch = [regex]::Match($raw['ping'],"Average\s*=\s*(\d+)\w*")
      $avg = $avgMatch.Groups[1].Value
      $avgLabel = if ($avg) { " (avg $avg ms)" } else { "" }
      $pingTail = ([regex]::Split($raw['ping'],'\r?\n') | Select-Object -Last 6) -join "`n"
      Add-Normal "Network/ICMP" ("Ping OK" + $avgLabel) $pingTail
    }
  }
}
if ($raw['tracert'] -and ($raw['tracert'] -match "over a maximum of" -and $raw['tracert'] -notmatch "Trace complete")){
  Add-Issue "low" "Network" "Traceroute didn’t complete within hop limit (may be normal if ICMP filtered)." $raw['tracert']
}

# outlook connectivity (HTTPS to EXO)
if ($raw['testnet_outlook443']){
  if ($raw['testnet_outlook443'] -match 'Test-NetConnection cmdlet not available'){
    Add-Issue "info" "Outlook/Connectivity" "Test-NetConnection cmdlet not available to verify outlook.office365.com:443." $raw['testnet_outlook443']
  } else {
    $tcpMatch = [regex]::Match($raw['testnet_outlook443'],'TcpTestSucceeded\s*:\s*(True|False)','IgnoreCase')
    $rttMatch = [regex]::Match($raw['testnet_outlook443'],'PingReplyDetails \(RTT\)\s*:\s*(\d+)\s*ms','IgnoreCase')
    $remoteMatch = [regex]::Match($raw['testnet_outlook443'],'RemoteAddress\s*:\s*([^\r\n]+)','IgnoreCase')
    $evidenceLines = @([regex]::Split($raw['testnet_outlook443'],'\r?\n') | Select-Object -First 12)
    $evidenceText = $evidenceLines -join "`n"
    if ($tcpMatch.Success -and $tcpMatch.Groups[1].Value -ieq 'True'){
      $outlookConnectivityResult = $true
      $rttText = if ($rttMatch.Success) { " (RTT {0} ms)" -f $rttMatch.Groups[1].Value.Trim() } else { "" }
      $remoteSuffix = if ($remoteMatch.Success) { " (remote {0})" -f $remoteMatch.Groups[1].Value.Trim() } else { "" }
      Add-Normal "Outlook/Connectivity" ("HTTPS connectivity to outlook.office365.com succeeded{0}{1}." -f $rttText, $remoteSuffix) $evidenceText
    } elseif ($tcpMatch.Success -and $tcpMatch.Groups[1].Value -ieq 'False'){
      $outlookConnectivityResult = $false
      $remoteSuffix = if ($remoteMatch.Success) { " (remote {0})" -f $remoteMatch.Groups[1].Value.Trim() } else { "" }
      Add-Issue "high" "Outlook/Connectivity" ("HTTPS connectivity to outlook.office365.com failed{0}." -f $remoteSuffix) $evidenceText
    } else {
      Add-Issue "info" "Outlook/Connectivity" "Unable to determine Test-NetConnection result for outlook.office365.com." $evidenceText
    }
  }
}

# outlook OST cache sizing (workstations)
if (($summary.IsServer -ne $true) -and $raw['outlook_ost']){
  $ostMatches = [regex]::Matches($raw['outlook_ost'],'(?ms)FullName\s*:\s*(?<full>[^\r\n]+).*?Length\s*:\s*(?<length>\d+)(?:.*?LastWriteTime\s*:\s*(?<lwt>[^\r\n]+))?')
  if ($ostMatches.Count -gt 0){
    $ostEntries = @()
    foreach($m in $ostMatches){
      $fullName = $m.Groups['full'].Value.Trim()
      if (-not $fullName){ continue }
      $lengthBytes = [double]$m.Groups['length'].Value
      $lastWrite = if ($m.Groups['lwt'].Success) { $m.Groups['lwt'].Value.Trim() } else { $null }
      $fileName = [System.IO.Path]::GetFileName($fullName)
      $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fullName)
      $domainPart = $null
      if ($baseName -match '@(?<domain>[^@]+)$'){
        $domainPart = $matches['domain'].ToLowerInvariant()
      }
      if ($domainPart){ $outlookOstDomains += $domainPart }
      $sizeGB = if ($lengthBytes -gt 0) { $lengthBytes / 1GB } else { 0 }
      $ostEntries += [pscustomobject]@{
        FullName       = $fullName
        FileName       = $fileName
        SizeGB         = $sizeGB
        LastWriteTime  = $lastWrite
      }
    }
    if ($ostEntries.Count -gt 0){
      $outlookOstDomains = @($outlookOstDomains | Where-Object { $_ } | Sort-Object -Unique)
      $ostEntries = $ostEntries | Sort-Object SizeGB -Descending
      $criticalEntries = @()
      $badEntries = @()
      $warnEntries = @()
      $healthyEntries = @()
      foreach($entry in $ostEntries){
        $sizeText = ('{0:N2}' -f $entry.SizeGB)
        $lastWriteLabel = if ($entry.LastWriteTime) { " (LastWrite {0})" -f $entry.LastWriteTime } else { "" }
        $line = "{0} - {1} GB{2}" -f $entry.FullName, $sizeText, $lastWriteLabel
        if ($entry.SizeGB -gt 25){
          $criticalEntries += $line
        } elseif ($entry.SizeGB -gt 15){
          $badEntries += $line
        } elseif ($entry.SizeGB -gt 5){
          $warnEntries += $line
        } else {
          $healthyEntries += $line
        }
      }
      if ($criticalEntries.Count -gt 0){
        Add-Issue "critical" "Outlook/OST" "OST cache HIGH tier (>25 GB) detected." ($criticalEntries -join "`n")
      }
      if ($badEntries.Count -gt 0){
        Add-Issue "high" "Outlook/OST" "OST cache BAD tier (15–25 GB) detected." ($badEntries -join "`n")
      }
      if ($warnEntries.Count -gt 0){
        Add-Issue "medium" "Outlook/OST" "OST cache WARN tier (5–15 GB) detected." ($warnEntries -join "`n")
      }
      if ($criticalEntries.Count -eq 0 -and $badEntries.Count -eq 0 -and $warnEntries.Count -eq 0 -and $healthyEntries.Count -gt 0){
        $largestEntry = $ostEntries | Select-Object -First 1
        $largestText = ('{0:N2}' -f $largestEntry.SizeGB)
        $count = $ostEntries.Count
        $plural = if ($count -eq 1) { '' } else { 's' }
        $sampleCount = [Math]::Min($healthyEntries.Count,5)
        $healthyEvidence = @($healthyEntries | Select-Object -First $sampleCount) -join "`n"
        Add-Normal "Outlook/OST" ("OST cache sizes within guidance (max {0} GB across {1} file{2})." -f $largestText, $count, $plural) $healthyEvidence
      }
    }
  }
}

# autodiscover DNS CNAME validation
if ($raw['outlook_autodiscover']){
  $autoText = $raw['outlook_autodiscover']
  if ($autoText -match 'Resolve-DnsName cmdlet not available'){
    Add-Issue "info" "Outlook/Autodiscover" "Resolve-DnsName cmdlet not available to check autodiscover CNAME." $autoText
  } elseif ($autoText -match 'No domain candidates identified'){
    Add-Issue "info" "Outlook/Autodiscover" "No domain candidates identified for autodiscover lookup." $autoText
  } else {
    $lines = [regex]::Split($autoText,'\r?\n')
    $blocks = @()
    $currentDomain = $null
    $currentLines = @()
    foreach($line in $lines){
      $domainMatch = [regex]::Match($line,'^###\s*Domain:\s*(.+)$')
      if ($domainMatch.Success){
        if ($currentDomain){
          $blockText = ($currentLines -join "`n").Trim()
          $blocks += [pscustomobject]@{ Domain = $currentDomain; Text = $blockText }
        }
        $currentDomain = $domainMatch.Groups[1].Value.Trim()
        $currentLines = @()
      } else {
        $currentLines += $line
      }
    }
    if ($currentDomain){
      $blockText = ($currentLines -join "`n").Trim()
      $blocks += [pscustomobject]@{ Domain = $currentDomain; Text = $blockText }
    }

    if ($blocks.Count -gt 0){
      $autoResults = @()
      foreach($block in $blocks){
        $domainValue = $block.Domain
        if (-not $domainValue){ continue }
        $text = if ($block.Text) { $block.Text.Trim() } else { '' }
        $status = 'Unknown'
        if ($text -match '(?i)Resolve-DnsName failed'){
          $status = 'Failed'
        } elseif ($text -match '(?i)No CNAME records returned'){
          $status = 'Empty'
        }
        $target = $null
        $cnameMatch = [regex]::Match($text,'(?im)^\s*autodiscover\.[^\s]+\s+CNAME\s+(?<target>[^\s]+)\s*$')
        if ($cnameMatch.Success){
          $target = $cnameMatch.Groups['target'].Value.Trim()
        }
        if (-not $target){
          $nameHostMatch = [regex]::Match($text,'(?im)^\s*NameHost\s*:\s*(?<target>[^\s]+)')
          if ($nameHostMatch.Success){
            $target = $nameHostMatch.Groups['target'].Value.Trim()
          }
        }
        if ($target){
          $target = $target.TrimEnd('.')
          $targetLower = $target.ToLowerInvariant()
          if ($targetLower -eq 'autodiscover.outlook.com'){
            $status = 'Outlook'
          } else {
            $status = 'Other'
          }
        }
        $autoResults += [pscustomobject]@{
          Domain   = $domainValue
          Status   = $status
          Target   = if ($target) { $target } else { $null }
          Evidence = $text
        }
      }

      if ($autoResults.Count -gt 0){
        $likelyExo = $false
        if ($summary.AzureAdTenantId -or $summary.AzureAdTenantDomain){
          $likelyExo = $true
        } elseif ($summary.DomainJoined -eq $false){
          $likelyExo = $true
        } elseif ($autoResults | Where-Object { $_.Status -eq 'Outlook' }){
          $likelyExo = $true
        } elseif ($outlookConnectivityResult -eq $true -and $summary.DomainJoined -ne $true){
          $likelyExo = $true
        }

        if (-not $likelyExo -and $outlookOstDomains -and $outlookOstDomains.Count -gt 0){
          $publicOstDomains = @($outlookOstDomains | Where-Object { $_ -match '\.' -and $_ -notmatch '\.(local|lan|corp|internal)$' })
          if ($publicOstDomains.Count -gt 0){
            $likelyExo = $true
          }
        }

        foreach($result in $autoResults){
          $domainValue = $result.Domain
          if (-not $domainValue){ continue }
          $domainTrimmed = $domainValue.Trim()
          if (-not $domainTrimmed){ continue }
          $domainLower = $domainTrimmed.ToLowerInvariant()
          $isInternalDomain = ($domainLower -notmatch '\.') -or ($domainLower -match '\.(local|lan|corp|internal)$')
          $evidenceLines = if ($result.Evidence) { @($result.Evidence -split '\r?\n' | Select-Object -First 12) } else { @() }
          $evidenceText = if ($evidenceLines -and $evidenceLines.Count -gt 0) { $evidenceLines -join "`n" } else { $autoText }

          switch ($result.Status) {
            'Outlook' {
              Add-Normal "Outlook/Autodiscover" ("autodiscover.{0} CNAME → autodiscover.outlook.com" -f $domainTrimmed) $evidenceText
            }
            'Other' {
              $targetDisplay = if ($result.Target) { $result.Target } else { 'unknown target' }
              if ($likelyExo -and -not $isInternalDomain){
                Add-Issue "medium" "Outlook/Autodiscover" ("autodiscover.{0} CNAME points to {1} (expected autodiscover.outlook.com)." -f $domainTrimmed, $targetDisplay) $evidenceText
              } elseif (-not $isInternalDomain){
                Add-Issue "info" "Outlook/Autodiscover" ("autodiscover.{0} CNAME points to {1}. Verify Exchange Online onboarding." -f $domainTrimmed, $targetDisplay) $evidenceText
              }
            }
            'Failed' {
              if ($likelyExo -and -not $isInternalDomain){
                Add-Issue "medium" "Outlook/Autodiscover" ("Autodiscover lookup failed for {0}." -f $domainTrimmed) $evidenceText
              } elseif (-not $isInternalDomain){
                Add-Issue "info" "Outlook/Autodiscover" ("Autodiscover lookup failed for {0}." -f $domainTrimmed) $evidenceText
              }
            }
            'Empty' {
              if ($likelyExo -and -not $isInternalDomain){
                Add-Issue "medium" "Outlook/Autodiscover" ("No CNAME records returned for autodiscover.{0}." -f $domainTrimmed) $evidenceText
              } elseif (-not $isInternalDomain){
                Add-Issue "info" "Outlook/Autodiscover" ("No CNAME records returned for autodiscover.{0}." -f $domainTrimmed) $evidenceText
              }
            }
          }
        }
      }
    }
  }
}

# autodiscover SCP discovery
if ($raw['outlook_scp']){
  $scpText = $raw['outlook_scp']
  $scpLines = @([regex]::Split($scpText,'\r?\n'))
  $scpEvidenceLines = @($scpLines | Select-Object -First 25)
  $scpEvidence = $scpEvidenceLines -join "`n"

  $partMatch = $scpLines | Where-Object { $_ -match '^(?i)PartOfDomain\s*:\s*(.+)$' } | Select-Object -First 1
  $partValue = $null
  if ($partMatch) {
    $partRaw = ([regex]::Match($partMatch,'^(?i)PartOfDomain\s*:\s*(.+)$')).Groups[1].Value.Trim()
    $partBool = To-BoolOrNull $partRaw
    if ($null -ne $partBool) {
      $partValue = $partBool
    }
  }
  if ($null -ne $partValue) {
    $summary.DomainJoined = $partValue
  }

  $statusMatch = $scpLines | Where-Object { $_ -match '^(?i)Status\s*:\s*(.+)$' } | Select-Object -Last 1
  $statusValue = $null
  if ($statusMatch) {
    $statusValue = ([regex]::Match($statusMatch,'^(?i)Status\s*:\s*(.+)$')).Groups[1].Value.Trim()
  }
  $errorMatch = $scpLines | Where-Object { $_ -match '^(?i)Error\s*:\s*(.+)$' } | Select-Object -First 1

  $bindingMatches = [regex]::Matches($scpText,'(?im)^ServiceBindingInformation\s*:\s*(.+)$')
  $bindingValues = @()
  foreach ($match in $bindingMatches) {
    $value = $match.Groups[1].Value.Trim()
    if (-not $value) { continue }
    $splitValues = $value -split '\s*;\s*'
    foreach ($entry in $splitValues) {
      $entryTrim = $entry.Trim()
      if ($entryTrim) {
        $bindingValues += $entryTrim
        break
      }
    }
  }
  $bindingUrl = if ($bindingValues.Count -gt 0) { $bindingValues[0] } else { $null }

  $domainJoined = if ($null -ne $partValue) {
    $partValue
  } elseif ($summary.DomainJoined -ne $null) {
    $summary.DomainJoined
  } else {
    $null
  }

  $statusLower = if ($statusValue) { $statusValue.ToLowerInvariant() } else { '' }
  $queryFailed = $false
  if ($statusLower -like 'queryfailed*') {
    $queryFailed = $true
  } elseif ($errorMatch) {
    $queryFailed = $true
  }

  if ($domainJoined -eq $false) {
    Add-Normal "Outlook/SCP" "GOOD Outlook/SCP: Not domain-joined; SCP not applicable." $scpEvidence
  } elseif ($domainJoined -eq $true) {
    if ($queryFailed) {
      Add-Issue "medium" "Outlook/SCP" "Outlook/SCP: Domain-joined; SCP query failed (AD unreachable or permissions)." $scpEvidence
    } elseif ($bindingUrl) {
      Add-Normal "Outlook/SCP" ("GOOD Outlook/SCP: Autodiscover SCP published: {0}" -f $bindingUrl) $scpEvidence
    } else {
      Add-Issue "low" "Outlook/SCP" "Outlook/SCP: Domain-joined but no Autodiscover SCP found (OK if EXO-only)." $scpEvidence
    }
  } else {
    if ($queryFailed) {
      Add-Issue "medium" "Outlook/SCP" "Outlook/SCP: SCP query failed (domain join status unknown)." $scpEvidence
    } elseif ($bindingUrl) {
      Add-Normal "Outlook/SCP" ("GOOD Outlook/SCP: Autodiscover SCP published: {0}" -f $bindingUrl) $scpEvidence
    }
  }
}

# office macro / protected view policies
$macroSecurityStatus = New-Object System.Collections.Generic.List[pscustomobject]
function Format-MacroContextEvidence {
  param(
    [pscustomobject]$Context
  )

  $lines = @()
  $contextLabel = if ($Context.Context) { $Context.Context } else { '(unknown)' }
  $lines += ("Context: {0}" -f $contextLabel)

  if ($Context.EvidenceLines -and $Context.EvidenceLines.Count -gt 0) {
    $lines += $Context.EvidenceLines
  } else {
    $blockDisplay = if ($Context.BlockRaw) { $Context.BlockRaw } else { 'NotConfigured' }
    $warningsDisplay = if ($Context.WarningsRaw) { $Context.WarningsRaw } else { 'NotConfigured' }
    $pvInternetDisplay = if ($Context.PvInternetRaw) { $Context.PvInternetRaw } else { 'NotConfigured' }
    $pvUnsafeDisplay = if ($Context.PvUnsafeRaw) { $Context.PvUnsafeRaw } else { 'NotConfigured' }
    $lines += ("BlockContentExecutionFromInternet : {0}" -f $blockDisplay)
    $lines += ("VBAWarnings : {0}" -f $warningsDisplay)
    $lines += ("ProtectedView.DisableInternetFilesInPV : {0}" -f $pvInternetDisplay)
    $lines += ("ProtectedView.DisableUnsafeLocationsInPV : {0}" -f $pvUnsafeDisplay)
  }

  return ($lines -join "`n")
}

if ($raw['office_security']) {
  $macroLines = [regex]::Split($raw['office_security'],'\r?\n')
  $macroContexts = New-Object System.Collections.Generic.List[pscustomobject]
  $currentContext = $null

  foreach ($line in $macroLines) {
    $contextMatch = [regex]::Match($line,'^\s*Context\s*:\s*(.+)$')
    if ($contextMatch.Success) {
      $contextText = $contextMatch.Groups[1].Value.Trim()
      $parts = $contextText -split '\\'
      $hiveName = $null
      $appName = $null
      if ($parts.Count -ge 1) { $hiveName = $parts[0].Trim() }
      if ($parts.Count -ge 2) { $appName = $parts[1].Trim() }
      $appKey = $null
      if ($appName) { $appKey = $appName.ToLowerInvariant() }

      $currentContext = [pscustomobject]@{
        Context        = $contextText
        Hive           = $hiveName
        App            = $appName
        AppKey         = $appKey
        BlockRaw       = 'NotConfigured'
        WarningsRaw    = 'NotConfigured'
        PvInternetRaw  = 'NotConfigured'
        PvUnsafeRaw    = 'NotConfigured'
        EvidenceLines  = New-Object System.Collections.Generic.List[string]
      }
      $macroContexts.Add($currentContext)
      continue
    }

    if (-not $currentContext) { continue }
    $trimmedLine = $line.Trim()
    if (-not $trimmedLine) { continue }

    $currentContext.EvidenceLines.Add($trimmedLine)

    $blockMatch = [regex]::Match($trimmedLine,'^BlockContentExecutionFromInternet\s*:\s*(.+)$','IgnoreCase')
    if ($blockMatch.Success) { $currentContext.BlockRaw = $blockMatch.Groups[1].Value.Trim() }

    $warningMatch = [regex]::Match($trimmedLine,'^VBAWarnings\s*:\s*(.+)$','IgnoreCase')
    if ($warningMatch.Success) { $currentContext.WarningsRaw = $warningMatch.Groups[1].Value.Trim() }

    $pvInternetMatch = [regex]::Match($trimmedLine,'^ProtectedView\.DisableInternetFilesInPV\s*:\s*(.+)$','IgnoreCase')
    if ($pvInternetMatch.Success) { $currentContext.PvInternetRaw = $pvInternetMatch.Groups[1].Value.Trim() }

    $pvUnsafeMatch = [regex]::Match($trimmedLine,'^ProtectedView\.DisableUnsafeLocationsInPV\s*:\s*(.+)$','IgnoreCase')
    if ($pvUnsafeMatch.Success) { $currentContext.PvUnsafeRaw = $pvUnsafeMatch.Groups[1].Value.Trim() }
  }

  foreach ($context in $macroContexts) {
    $context.BlockValue = ConvertTo-NullableInt $context.BlockRaw
    $context.WarningsValue = ConvertTo-NullableInt $context.WarningsRaw
    $context.PvInternetValue = ConvertTo-NullableInt $context.PvInternetRaw
    $context.PvUnsafeValue = ConvertTo-NullableInt $context.PvUnsafeRaw
  }

  $macroApps = @(
    @{ Name = 'Excel'; Key = 'excel' },
    @{ Name = 'Word'; Key = 'word' },
    @{ Name = 'PowerPoint'; Key = 'powerpoint' }
  )

  foreach ($appInfo in $macroApps) {
    $appContexts = @($macroContexts | Where-Object { $_.AppKey -eq $appInfo.Key })
    if ($appContexts.Count -eq 0) { continue }

    $hasIssue = $false

    $blockCompliant = @($appContexts | Where-Object { $_.BlockValue -eq 1 })
    $blockFullyEnforced = ($appContexts.Count -gt 0 -and $blockCompliant.Count -eq $appContexts.Count)
    if ($blockCompliant.Count -eq 0) {
      $blockEvidence = ($appContexts | ForEach-Object { Format-MacroContextEvidence $_ }) -join "`n`n"
      Add-Issue "high" "Office/Macros" ("{0} macro MOTW blocking disabled or not configured. Fix: Enforce via GPO/MDM." -f $appInfo.Name) $blockEvidence
      $hasIssue = $true
    }

    $laxContexts = @($appContexts | Where-Object {
        $val = $_.WarningsValue
        if ($null -ne $val) {
          $val -lt 3
        } else {
          $raw = $_.WarningsRaw
          if ([string]::IsNullOrWhiteSpace($raw)) {
            $true
          } else {
            $raw -match '(?i)notconfigured'
          }
        }
      })
    if ($laxContexts.Count -gt 0) {
      $warnValues = ($laxContexts | ForEach-Object { if ($_.WarningsRaw) { $_.WarningsRaw } else { 'NotConfigured' } } | Sort-Object -Unique) -join ', '
      if (-not $warnValues) { $warnValues = 'NotConfigured' }
      $warnEvidence = ($laxContexts | ForEach-Object { Format-MacroContextEvidence $_ }) -join "`n`n"
      Add-Issue "medium" "Office/Macros" ("{0} macro notification policy allows macros ({1}). Fix: Enforce via GPO/MDM." -f $appInfo.Name, $warnValues) $warnEvidence
      $hasIssue = $true
    }

    $pvDisabledContexts = @($appContexts | Where-Object { ($_.PvInternetValue -eq 1) -or ($_.PvUnsafeValue -eq 1) })
    if ($pvDisabledContexts.Count -gt 0) {
      $pvReasons = @()
      foreach ($ctx in $pvDisabledContexts) {
        if ($ctx.PvInternetValue -eq 1) { $pvReasons += 'internet files' }
        if ($ctx.PvUnsafeValue -eq 1) { $pvReasons += 'unsafe locations' }
      }
      $pvReasonText = ($pvReasons | Sort-Object -Unique) -join ', '
      if (-not $pvReasonText) { $pvReasonText = 'Protected View' }
      $pvEvidence = ($pvDisabledContexts | ForEach-Object { Format-MacroContextEvidence $_ }) -join "`n`n"
      Add-Issue "medium" "Office/Protected View" ("Protected View disabled for {0} ({1}). Fix: Enforce via GPO/MDM." -f $appInfo.Name, $pvReasonText) $pvEvidence
      $hasIssue = $true
    }

    $strictContexts = @($appContexts | Where-Object {
        $val = $_.WarningsValue
        if ($null -eq $val) {
          $false
        } else {
          $val -ge 3
        }
      })
    $warningsStrict = ($appContexts.Count -gt 0 -and $strictContexts.Count -eq $appContexts.Count)
    $protectedViewGood = ($pvDisabledContexts.Count -eq 0)
    $macroEvidenceContext = if ($blockCompliant.Count -gt 0) { $blockCompliant[0] } elseif ($appContexts.Count -gt 0) { $appContexts[0] } else { $null }
    $macroEvidenceText = if ($macroEvidenceContext) { Format-MacroContextEvidence $macroEvidenceContext } else { '' }
    $macroSecurityStatus.Add([pscustomobject]@{
      App               = $appInfo.Name
      BlockEnforced     = $blockFullyEnforced
      BlockEvidence     = if ($blockFullyEnforced -and $macroEvidenceContext) { $macroEvidenceText } else { '' }
      AnyBlockContexts  = ($blockCompliant.Count -gt 0)
      WarningsStrict    = $warningsStrict
      ProtectedViewGood = $protectedViewGood
      Evidence          = $macroEvidenceText
    })

    if (-not $hasIssue) {
      $positiveParts = @()
      if ($blockCompliant.Count -gt 0) { $positiveParts += 'MOTW macro blocking enforced' }
      $strictWarnings = @($appContexts | Where-Object {
          $val = $_.WarningsValue
          if ($null -eq $val) {
            $false
          } else {
            $val -ge 3
          }
        })
      if ($strictWarnings.Count -gt 0) { $positiveParts += 'strict macro notification policy' }
      if ($pvDisabledContexts.Count -eq 0) { $positiveParts += 'Protected View active for internet/unsafe files' }

      if ($positiveParts.Count -gt 0) {
        $evidenceContext = if ($blockCompliant.Count -gt 0) { $blockCompliant[0] } else { $appContexts[0] }
        $positiveEvidence = Format-MacroContextEvidence $evidenceContext
        $messageDetails = $positiveParts -join '; '
        Add-Normal "Office/Macros" ("{0} macro protections verified ({1})." -f $appInfo.Name, $messageDetails) $positiveEvidence
      }
    }
  }
}

# defender
if ($raw['defender']){
  $rt = [regex]::Match($raw['defender'],'RealTimeProtectionEnabled\s*:\s*(True|False)','IgnoreCase')
  if ($rt.Success -and $rt.Groups[1].Value -ieq "False"){ Add-Issue "high" "Security" "Defender real-time protection is OFF." $raw['defender'] }

  $signaturePatterns = @(
    @{ Label = 'Antivirus';    Regex = 'AntivirusSignatureAge\s*:\s*(\d+)'; },
    @{ Label = 'Antispyware'; Regex = 'AntispywareSignatureAge\s*:\s*(\d+)'; },
    @{ Label = 'NIS';         Regex = 'NISSignatureAge\s*:\s*(\d+)'; }
  )
  $signatureAges = @()
  $signatureEvidence = @()
  foreach($pattern in $signaturePatterns){
    $match = [regex]::Match($raw['defender'],$pattern.Regex,'IgnoreCase')
    if ($match.Success){
      $signatureAges += [int]$match.Groups[1].Value
      $signatureEvidence += $match.Value.Trim()
    }
  }
  if ($signatureAges.Count -gt 0){
    $maxSigAge = ($signatureAges | Measure-Object -Maximum).Maximum
    $maxSigAgeInt = [int]$maxSigAge
    $sigEvidenceText = if ($signatureEvidence.Count -gt 0) { $signatureEvidence -join "`n" } else { "" }

    if ($maxSigAge -le 3){
      Add-Normal "Security/Defender" ("Signature age GOOD ({0} days; daily updates confirmed)." -f $maxSigAgeInt) $sigEvidenceText
    } elseif ($maxSigAge -le 7){
      Add-Normal "Security/Defender" ("Signature age OK ({0} days; monitor that daily updates continue)." -f $maxSigAgeInt) $sigEvidenceText
    } elseif ($maxSigAge -le 14){
      Add-Issue "medium" "Security" ("Defender signatures WARNING tier ({0} days old). Signatures should update daily—even on isolated networks." -f $maxSigAgeInt) $sigEvidenceText
    } elseif ($maxSigAge -le 30){
      Add-Issue "high" "Security" ("Defender signatures BAD tier ({0} days old). Trigger an update promptly." -f $maxSigAgeInt) $sigEvidenceText
    } else {
      Add-Issue "critical" "Security" ("Defender signatures CRITICAL tier ({0} days old). Update signatures immediately." -f $maxSigAgeInt) $sigEvidenceText
    }
  }

  $rtOK = $rt.Success -and $rt.Groups[1].Value -ieq "True"
  if ($rtOK) {
    Add-Normal "Security/Defender" "Real-time protection ON" (([regex]::Split($raw['defender'],'\r?\n') | Select-Object -First 12) -join "`n")
  }

  $engineVersionMatch = [regex]::Match($raw['defender'],'AMEngineVersion\s*:\s*([^\r\n]+)','IgnoreCase')
  $platformVersionMatch = [regex]::Match($raw['defender'],'AMProductVersion\s*:\s*([^\r\n]+)','IgnoreCase')

  $engineOutMatches = [regex]::Matches($raw['defender'],'(?im)^(?<name>[^\r\n]*Engine[^\r\n]*OutOfDate)\s*:\s*(?<value>[^\r\n]+)$')
  $engineEvidence = @()
  if ($engineVersionMatch.Success){ $engineEvidence += $engineVersionMatch.Value.Trim() }
  $engineStatusTrue = $false
  $engineStatusFalse = $false
  foreach($m in $engineOutMatches){
    $engineEvidence += $m.Value.Trim()
    $boolVal = To-BoolOrNull $m.Groups['value'].Value
    if ($null -eq $boolVal){ continue }
    if ($boolVal){ $engineStatusTrue = $true } else { $engineStatusFalse = $true }
  }
  $engineVersionValue = if ($engineVersionMatch.Success) { $engineVersionMatch.Groups[1].Value.Trim() } else { $null }
  $engineVersionMissing = $false
  if ($engineVersionValue -and ($engineVersionValue -match '^(?:0+(?:\.0+)*)$' -or $engineVersionValue -match '(?i)not\s*available|unknown')){
    $engineVersionMissing = $true
  }
  if ($engineStatusTrue -or $engineVersionMissing){
    $engineEvidenceText = if ($engineEvidence.Count -gt 0) { $engineEvidence -join "`n" } else { $raw['defender'] }
    Add-Issue "high" "Security" "Defender engine updates appear missing/out of date." $engineEvidenceText
  } elseif ($engineStatusFalse -and -not $engineStatusTrue -and $engineEvidence.Count -gt 0){
    Add-Normal "Security/Defender" "Defender engine reports up to date" ($engineEvidence -join "`n")
  }

  $platformOutMatches = [regex]::Matches($raw['defender'],'(?im)^(?<name>[^\r\n]*Platform[^\r\n]*OutOfDate)\s*:\s*(?<value>[^\r\n]+)$')
  $platformEvidence = @()
  if ($platformVersionMatch.Success){ $platformEvidence += $platformVersionMatch.Value.Trim() }
  $platformStatusTrue = $false
  $platformStatusFalse = $false
  foreach($m in $platformOutMatches){
    $platformEvidence += $m.Value.Trim()
    $boolVal = To-BoolOrNull $m.Groups['value'].Value
    if ($null -eq $boolVal){ continue }
    if ($boolVal){ $platformStatusTrue = $true } else { $platformStatusFalse = $true }
  }
  $platformVersionValue = if ($platformVersionMatch.Success) { $platformVersionMatch.Groups[1].Value.Trim() } else { $null }
  $platformVersionMissing = $false
  if ($platformVersionValue -and ($platformVersionValue -match '^(?:0+(?:\.0+)*)$' -or $platformVersionValue -match '(?i)not\s*available|unknown')){
    $platformVersionMissing = $true
  }
  if ($platformStatusTrue -or $platformVersionMissing){
    $platformEvidenceText = if ($platformEvidence.Count -gt 0) { $platformEvidence -join "`n" } else { $raw['defender'] }
    Add-Issue "high" "Security" "Defender platform updates appear missing/out of date." $platformEvidenceText
  } elseif ($platformStatusFalse -and -not $platformStatusTrue -and $platformEvidence.Count -gt 0){
    Add-Normal "Security/Defender" "Defender platform reports up to date" ($platformEvidence -join "`n")
  }
} else {
  Add-Issue "info" "Security" "Defender status not captured (3rd-party AV or cmdlet unavailable)." ""
}

$securityFirewallSummary = $null
# firewall profiles
if ($raw['firewall']){
  $profiles = @{}
  $blocks = ($raw['firewall'] -split "Profile Settings:")
  foreach($b in $blocks){
    if (-not $b -or -not $b.Trim()) { continue }
    $nameMatch = [regex]::Match($b,'^(.*?)[\r\n]')
    $pname = if($nameMatch.Success){ $nameMatch.Groups[1].Value.Trim() } else { "Profile" }
    $isOn = ($b -match 'State\s*ON')
    if ($pname) { $profiles[$pname] = $isOn }
    if (-not $isOn -and $b -match 'State\s*OFF'){
      Add-Issue "medium" "Firewall" "$pname profile is OFF." $b
    }
  }
  if ($profiles.Count -gt 0){
    $profileStates = $profiles.GetEnumerator() | ForEach-Object { "{0}: {1}" -f $_.Key, ($(if ($_.Value) {"ON"} else {"OFF"})) }
    $profileSummary = $profileStates -join "; "
    if (-not ($profiles.Values -contains $false)){
      Add-Normal "Security/Firewall" "All firewall profiles ON" $profileSummary
    }
    $securityFirewallSummary = [pscustomobject]@{
      Profiles = $profiles
      AllOn    = -not ($profiles.Values -contains $false)
      Summary  = $profileSummary
    }
  }
}

# BitLocker status
if ($raw['bitlocker']) {
  $bitlockerText = $raw['bitlocker']
  if ($bitlockerText -match '(?i)Get-BitLockerVolume cmdlet not available') {
    Add-Issue "low" "Security/BitLocker" "BitLocker cmdlets unavailable on this system (likely unsupported edition)." (($bitlockerText -split "\r?\n") | Select-Object -First 8) -join "`n"
  } elseif ($bitlockerText -match '(?i)Get-BitLockerVolume failed') {
    Add-Issue "low" "Security/BitLocker" "Failed to query BitLocker status." (($bitlockerText -split "\r?\n") | Select-Object -First 12) -join "`n"
  } else {
    $bitlockerEntries = Parse-BitLockerStatus $bitlockerText
    if ($bitlockerEntries.Count -gt 0) {
      $FormatBitLockerEntry = {
        param($entry)
        $details = @()
        if ($entry.MountPoint) { $details += "Mount: $($entry.MountPoint)" }
        if ($entry.VolumeType) { $details += "Type: $($entry.VolumeType)" }
        if ($entry.ProtectionStatus) { $details += "Protection: $($entry.ProtectionStatus)" }
        if ($entry.VolumeStatus) { $details += "Status: $($entry.VolumeStatus)" }
        if ($null -ne $entry.EncryptionPercentage) { $details += "Encryption: $([math]::Round($entry.EncryptionPercentage,1))%" }
        if ($details.Count -eq 0) { return $entry.RawBlock }
        return $details -join '; '
      }

      $osVolumes = New-Object System.Collections.Generic.List[pscustomobject]
      foreach ($entry in $bitlockerEntries) {
        $typeNorm = if ($entry.VolumeType) { ($entry.VolumeType -replace '\s+', '').ToLowerInvariant() } else { '' }
        $mountNorm = if ($entry.MountPoint) { $entry.MountPoint.Trim().ToUpperInvariant() } else { '' }
        $isOs = $false
        if ($typeNorm -match 'operatingsystem' -or $typeNorm -eq 'system' -or $typeNorm -eq 'osvolume') { $isOs = $true }
        elseif ($mountNorm -match '^C:$') { $isOs = $true }
        if ($isOs) { $osVolumes.Add($entry) }
      }

      if ($osVolumes.Count -gt 0) {
        $osArray = @($osVolumes.ToArray())
        $unprotected = @($osArray | Where-Object { $_.ProtectionEnabled -ne $true })
        $partial = @($osArray | Where-Object { $_.ProtectionEnabled -eq $true -and $null -ne $_.EncryptionPercentage -and $_.EncryptionPercentage -lt 99 })
        $unknown = @($osArray | Where-Object { $null -eq $_.ProtectionEnabled -and $_.ProtectionStatus })

        if ($unprotected.Count -gt 0) {
          $mountList = ($unprotected | ForEach-Object { $_.MountPoint } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
          if (-not $mountList) { $mountList = 'Unknown volume' }
          $evidence = ($unprotected | ForEach-Object { & $FormatBitLockerEntry $_ }) -join "`n"
          Add-Issue "critical" "Security/BitLocker" ("BitLocker is OFF for system volume(s): {0}." -f ($mountList)) $evidence
          $summary.BitLockerSystemProtected = $false
        } elseif ($partial.Count -gt 0) {
          $mountList = ($partial | ForEach-Object { $_.MountPoint } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
          if (-not $mountList) { $mountList = 'Unknown volume' }
          $evidence = ($partial | ForEach-Object { & $FormatBitLockerEntry $_ }) -join "`n"
          # Industry guidance such as CIS Controls and Microsoft security baselines
          # call for full BitLocker protection on OS drives; incomplete encryption
          # leaves data at risk and should surface as a high severity issue.
          Add-Issue "high" "Security/BitLocker" ("BitLocker encryption incomplete on system volume(s): {0}." -f ($mountList)) $evidence
          $summary.BitLockerSystemProtected = $false
        } elseif ($unknown.Count -gt 0) {
          $mountList = ($unknown | ForEach-Object { $_.MountPoint } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
          if (-not $mountList) { $mountList = 'Unknown volume' }
          $evidence = ($unknown | ForEach-Object { & $FormatBitLockerEntry $_ }) -join "`n"
          Add-Issue "low" "Security/BitLocker" ("BitLocker protection state unclear for system volume(s): {0}." -f ($mountList)) $evidence
        } else {
          $evidence = ($osArray | ForEach-Object { & $FormatBitLockerEntry $_ }) -join "`n"
          Add-Normal "Security/BitLocker" "BitLocker protection active for system volume(s)." $evidence
          $summary.BitLockerSystemProtected = $true
        }
      } else {
        $protectedVolumes = @($bitlockerEntries | Where-Object { $_.ProtectionEnabled -eq $true })
        if ($protectedVolumes.Count -gt 0) {
          $evidence = ($protectedVolumes | ForEach-Object { & $FormatBitLockerEntry $_ }) -join "`n"
          Add-Normal "Security/BitLocker" "BitLocker enabled on captured volume(s)." $evidence
        } else {
          $evidence = ($bitlockerEntries | ForEach-Object { & $FormatBitLockerEntry $_ }) -join "`n"
          # Devices without any BitLocker-protected volumes fail baseline controls for
          # data-at-rest protection, so escalate this to a high severity gap.
          Add-Issue "high" "Security/BitLocker" "No BitLocker-protected volumes detected." $evidence
          $summary.BitLockerSystemProtected = $false
        }
      }
    } else {
      Add-Issue "low" "Security/BitLocker" "BitLocker output captured but no volumes parsed." (($bitlockerText -split "\r?\n") | Select-Object -First 12) -join "`n"
    }
  }
} elseif ($files['bitlocker']) {
  Add-Issue "low" "Security/BitLocker" "BitLocker status file present but empty." ""
}

# security heuristics evaluation
$isLaptopProfile = ($summary.IsLaptop -eq $true)
$isModernClientProfile = ($summary.IsModernClient -eq $true)
$isDomainJoinedProfile = ($summary.DomainJoined -eq $true)
$deviceGuardData = ConvertFrom-JsonSafe $raw['security_deviceguard']
$securityServicesRunning = @()
$securityServicesConfigured = @()
$availableSecurityProperties = @()
$requiredSecurityProperties = @()
if ($deviceGuardData) {
  if ($deviceGuardData.PSObject.Properties['SecurityServicesRunning']) {
    $securityServicesRunning = ConvertTo-IntArray $deviceGuardData.SecurityServicesRunning
  }
  if ($deviceGuardData.PSObject.Properties['SecurityServicesConfigured']) {
    $securityServicesConfigured = ConvertTo-IntArray $deviceGuardData.SecurityServicesConfigured
  }
  if ($deviceGuardData.PSObject.Properties['AvailableSecurityProperties']) {
    $availableSecurityProperties = ConvertTo-IntArray $deviceGuardData.AvailableSecurityProperties
  }
  if ($deviceGuardData.PSObject.Properties['RequiredSecurityProperties']) {
    $requiredSecurityProperties = ConvertTo-IntArray $deviceGuardData.RequiredSecurityProperties
  }
}

$lsaMap = Parse-KeyValueBlock $raw['security_lsa']
$ntlmMap = Parse-KeyValueBlock $raw['security_ntlm']
$smartScreenMap = Parse-KeyValueBlock $raw['security_smartscreen']
$uacMap = Parse-KeyValueBlock $raw['security_uac']
$ldapMap = Parse-KeyValueBlock $raw['security_ldap']

# 1. TPM present and ready
$tpmText = $raw['security_tpm']
if ($tpmText) {
  $tpmMap = Parse-KeyValueBlock $tpmText
  $tpmPresent = To-BoolOrNull $tpmMap['TpmPresent']
  $tpmReady = To-BoolOrNull $tpmMap['TpmReady']
  $specVersion = if ($tpmMap.ContainsKey('SpecVersion')) { $tpmMap['SpecVersion'] } else { '' }
  $tpmEvidence = Get-TopLines $tpmText 12
  if ($tpmPresent -eq $true -and $tpmReady -eq $true) {
    $details = if ($specVersion) { "SpecVersion: $specVersion" } else { 'TPM ready' }
    Add-SecurityHeuristic 'TPM' 'Present and ready' 'good' $details $tpmEvidence
  } elseif ($tpmPresent -eq $true) {
    $details = 'TPM detected but not ready.'
    if ($specVersion) { $details = "$details SpecVersion: $specVersion" }
    Add-SecurityHeuristic 'TPM' 'Present but not ready' 'warning' $details $tpmEvidence -SkipIssue
    Add-Issue 'medium' 'Security/TPM' 'TPM detected but not ready. Initialize TPM to meet security baselines.' $tpmEvidence
  } else {
    $details = if ($specVersion) { "SpecVersion (reported): $specVersion" } else { 'No TPM detected.' }
    $health = if ($isModernClientProfile) { 'bad' } else { 'warning' }
    $issueSeverity = 'high'
    Add-SecurityHeuristic 'TPM' 'Not detected' $health $details $tpmEvidence -SkipIssue
    Add-Issue $issueSeverity 'Security/TPM' 'No TPM detected. Modern Windows devices require TPM 2.0 for security assurances.' $tpmEvidence
  }
} else {
  Add-SecurityHeuristic 'TPM' 'Not captured' 'warning' 'Get-Tpm output missing.' ''
}

# 2. Memory integrity (HVCI)
$dgEvidenceLines = @()
if ($securityServicesConfigured.Count -gt 0) { $dgEvidenceLines += "Configured: $($securityServicesConfigured -join ',')" }
if ($securityServicesRunning.Count -gt 0) { $dgEvidenceLines += "Running: $($securityServicesRunning -join ',')" }
if ($availableSecurityProperties.Count -gt 0) { $dgEvidenceLines += "Available: $($availableSecurityProperties -join ',')" }
if ($requiredSecurityProperties.Count -gt 0) { $dgEvidenceLines += "Required: $($requiredSecurityProperties -join ',')" }
$dgEvidence = $dgEvidenceLines -join "`n"
$hvciRunning = ($securityServicesRunning -contains 2)
$hvciAvailable = ($availableSecurityProperties -contains 2) -or ($requiredSecurityProperties -contains 2)
if ($hvciRunning) {
  Add-SecurityHeuristic 'Memory integrity (HVCI)' 'Enabled' 'good' 'Hypervisor-protected Code Integrity running (service 2).' $dgEvidence
} elseif ($hvciAvailable) {
  Add-SecurityHeuristic 'Memory integrity (HVCI)' 'Disabled' 'warning' 'HVCI supported but not running.' $dgEvidence -SkipIssue
  Add-Issue 'medium' 'Security/HVCI' 'Memory integrity (HVCI) is available but not running. Enable virtualization-based protection.' $dgEvidence
} elseif ($deviceGuardData) {
  Add-SecurityHeuristic 'Memory integrity (HVCI)' 'Not supported' 'info' 'Device Guard reports HVCI not available.' $dgEvidence
} else {
  Add-SecurityHeuristic 'Memory integrity (HVCI)' 'Not captured' 'warning' 'Device Guard status unavailable.' ''
  Add-Issue 'medium' 'Security/HVCI' 'Memory integrity (HVCI) not captured. Collect Device Guard diagnostics.' ''
}

# 3. Credential Guard / LSA isolation
$credentialGuardRunning = ($securityServicesRunning -contains 1)
$runAsPpl = ConvertTo-NullableInt $lsaMap['RunAsPPL']
$runAsPplBoot = ConvertTo-NullableInt $lsaMap['RunAsPPLBoot']
$lsaEvidenceLines = @()
if ($credentialGuardRunning) { $lsaEvidenceLines += 'SecurityServicesRunning includes 1 (Credential Guard).' }
if ($runAsPpl -ne $null) { $lsaEvidenceLines += "RunAsPPL: $runAsPpl" }
if ($runAsPplBoot -ne $null) { $lsaEvidenceLines += "RunAsPPLBoot: $runAsPplBoot" }
$lsaEvidence = $lsaEvidenceLines -join "`n"
if ($credentialGuardRunning -and $runAsPpl -eq 1) {
  Add-SecurityHeuristic 'Credential Guard (LSA isolation)' 'Enabled' 'good' 'Credential Guard running with LSA protection.' $lsaEvidence
} else {
  Add-SecurityHeuristic 'Credential Guard (LSA isolation)' 'Disabled' 'warning' 'Credential Guard or LSA RunAsPPL not enforced.' $lsaEvidence -SkipIssue
  Add-Issue 'high' 'Security/Credential Guard' 'Credential Guard or LSA protection is not enforced. Enable RunAsPPL and Credential Guard.' $lsaEvidence
}

# 4. Kernel DMA protection
$dmaText = $raw['security_kerneldma']
if ($dmaText) {
  $dmaMatch = [regex]::Match($dmaText,'(?im)^\s*Kernel DMA Protection\s*:\s*(.+)$')
  $dmaStatus = if ($dmaMatch.Success) { $dmaMatch.Groups[1].Value.Trim() } else { '' }
  $dmaEvidence = Get-TopLines $dmaText 20
  if ($dmaStatus) {
    $lower = $dmaStatus.ToLowerInvariant()
    $dmaDisabled = ($lower -match 'not available' -or $lower -match 'off' -or $lower -match 'disabled' -or $lower -match 'unsupported')
    if ($dmaDisabled -and $isLaptopProfile) {
      Add-SecurityHeuristic 'Kernel DMA protection' $dmaStatus 'warning' 'Kernel DMA protection not enabled on mobile device.' $dmaEvidence -SkipIssue
      Add-Issue 'medium' 'Security/Kernel DMA' 'Kernel DMA protection is disabled or unsupported on this mobile device.' $dmaEvidence
    } else {
      $health = if ($dmaDisabled) { 'info' } else { 'good' }
      Add-SecurityHeuristic 'Kernel DMA protection' $dmaStatus $health '' $dmaEvidence
    }
  } else {
    Add-SecurityHeuristic 'Kernel DMA protection' 'Status unknown' 'warning' 'msinfo32 output did not include Kernel DMA line.' $dmaEvidence
    Add-Issue 'medium' 'Security/Kernel DMA' 'Kernel DMA protection unknown. Confirm DMA protection capabilities.' $dmaEvidence
  }
} else {
  Add-SecurityHeuristic 'Kernel DMA protection' 'Not captured' 'warning' 'msinfo32 output missing.' ''
}

# 5. Windows Firewall
if ($securityFirewallSummary) {
  if ($securityFirewallSummary.AllOn) {
    Add-SecurityHeuristic 'Windows Firewall' 'All profiles ON' 'good' '' $securityFirewallSummary.Summary
  } else {
    Add-SecurityHeuristic 'Windows Firewall' 'Profile(s) OFF' 'warning' 'One or more firewall profiles disabled.' $securityFirewallSummary.Summary
  }
} else {
  Add-SecurityHeuristic 'Windows Firewall' 'Not captured' 'warning' 'Firewall status output missing.' ''
  Add-Issue 'high' 'Security/Firewall' 'Windows Firewall not captured. Collect firewall profile configuration.' ''
}

# 6. RDP exposure
$rdpMap = Parse-KeyValueBlock $raw['security_rdp']
$denyConnections = ConvertTo-NullableInt $rdpMap['fDenyTSConnections']
$userAuthValue = ConvertTo-NullableInt $rdpMap['UserAuthentication']
$rdpEnabled = ($denyConnections -eq 0)
$nlaEnabled = ($userAuthValue -eq 1)
$rdpEvidence = Get-TopLines $raw['security_rdp'] 18
if ($rdpMap.Count -eq 0 -and -not $raw['security_rdp']) {
  Add-SecurityHeuristic 'Remote Desktop' 'Not captured' 'warning' 'Terminal Server registry data unavailable.' ''
} elseif ($rdpEnabled) {
  if (-not $nlaEnabled) {
    Add-SecurityHeuristic 'Remote Desktop' 'Enabled without NLA' 'bad' 'NLA (UserAuthentication) not enforced.' $rdpEvidence -SkipIssue
    Add-Issue 'high' 'Security/RDP' 'Remote Desktop is enabled without Network Level Authentication. Enforce NLA or disable RDP.' $rdpEvidence
  } else {
    $health = if ($isLaptopProfile) { 'warning' } else { 'info' }
    if ($isLaptopProfile) {
      Add-Issue 'medium' 'Security/RDP' 'Remote Desktop is enabled on a mobile device. Validate exposure and access controls.' $rdpEvidence
    }
    Add-SecurityHeuristic 'Remote Desktop' 'Enabled with NLA' $health 'RDP enabled; NLA enforced.' $rdpEvidence -SkipIssue:$isLaptopProfile
  }
} else {
  Add-SecurityHeuristic 'Remote Desktop' 'Disabled' 'good' '' $rdpEvidence
}

# 7. SMB & legacy protocols
$smbMap = Parse-KeyValueBlock $raw['security_smb']
$enableSmb1 = To-BoolOrNull $smbMap['EnableSMB1Protocol']
$smbEvidence = Get-TopLines $raw['security_smb'] 20
if ($enableSmb1 -eq $true) {
  Add-SecurityHeuristic 'SMB1 protocol' 'Enabled' 'bad' 'SMB1 protocol enabled on server configuration.' $smbEvidence -SkipIssue
  Add-Issue 'high' 'Security/SMB' 'SMB1 protocol is enabled. Disable SMB1 to mitigate legacy protocol risks.' $smbEvidence
} elseif ($enableSmb1 -eq $false) {
  Add-SecurityHeuristic 'SMB1 protocol' 'Disabled' 'good' '' $smbEvidence
} else {
  Add-SecurityHeuristic 'SMB1 protocol' 'Status unknown' 'warning' '' $smbEvidence
}

$restrictSendingLsa = ConvertTo-NullableInt $lsaMap['RestrictSendingNTLMTraffic']
$restrictSendingMsv = ConvertTo-NullableInt $ntlmMap['RestrictSendingNTLMTraffic']
$restrictReceivingMsv = ConvertTo-NullableInt $ntlmMap['RestrictReceivingNTLMTraffic']
$auditReceivingMsv = ConvertTo-NullableInt $ntlmMap['AuditReceivingNTLMTraffic']
$ntlmEvidenceLines = @()
if ($restrictSendingLsa -ne $null) { $ntlmEvidenceLines += "Lsa RestrictSendingNTLMTraffic: $restrictSendingLsa" }
if ($restrictSendingMsv -ne $null) { $ntlmEvidenceLines += "MSV1_0 RestrictSendingNTLMTraffic: $restrictSendingMsv" }
if ($restrictReceivingMsv -ne $null) { $ntlmEvidenceLines += "MSV1_0 RestrictReceivingNTLMTraffic: $restrictReceivingMsv" }
if ($auditReceivingMsv -ne $null) { $ntlmEvidenceLines += "MSV1_0 AuditReceivingNTLMTraffic: $auditReceivingMsv" }
$ntlmEvidence = $ntlmEvidenceLines -join "`n"
$ntlmRestricted = $false
if (($restrictSendingLsa -ne $null -and $restrictSendingLsa -ge 1) -or ($restrictSendingMsv -ne $null -and $restrictSendingMsv -ge 1)) {
  $ntlmRestricted = $true
}
if ($auditReceivingMsv -ne $null -and $auditReceivingMsv -ge 1) { $ntlmRestricted = $true }
if ($ntlmRestricted) {
  Add-SecurityHeuristic 'NTLM restrictions' 'Policies enforced' 'good' '' $ntlmEvidence
} else {
  Add-SecurityHeuristic 'NTLM restrictions' 'Not enforced' 'warning' 'NTLM traffic not audited or restricted.' $ntlmEvidence -SkipIssue
  Add-Issue 'medium' 'Security/NTLM' 'NTLM hardening policies are not configured. Enforce RestrictSending/Audit NTLM settings.' $ntlmEvidence
}

# 8. SmartScreen
if ($smartScreenMap.Count -gt 0) {
  $smartScreenDisabled = $false
  $explorerValue = $smartScreenMap['Explorer.SmartScreenEnabled']
  if ($explorerValue -and $explorerValue.ToString().Trim().ToLowerInvariant() -match 'off|0|disable') { $smartScreenDisabled = $true }
  $policyValue = $smartScreenMap['Policy.System.EnableSmartScreen']
  if ($policyValue -ne $null -and (ConvertTo-NullableInt $policyValue) -eq 0) { $smartScreenDisabled = $true }
  $smartScreenSummary = ($smartScreenMap.GetEnumerator() | ForEach-Object { "{0} = {1}" -f $_.Key, $_.Value }) -join "`n"
  if ($smartScreenDisabled) {
    Add-SecurityHeuristic 'SmartScreen' 'Disabled' 'warning' 'SmartScreen policy not enforced.' $smartScreenSummary -SkipIssue
    Add-Issue 'medium' 'Security/SmartScreen' 'SmartScreen is disabled. Enable SmartScreen for app and URL protection.' $smartScreenSummary
  } else {
    Add-SecurityHeuristic 'SmartScreen' 'Enabled/Not disabled' 'good' '' $smartScreenSummary
  }
} else {
  Add-SecurityHeuristic 'SmartScreen' 'Not captured' 'warning' 'SmartScreen registry values unavailable.' ''
}

# 9. Attack Surface Reduction rules
$asrData = ConvertFrom-JsonSafe $raw['security_asr']
$asrRules = @{}
if ($asrData -and $asrData.PSObject.Properties['Rules']) {
  foreach ($rule in $asrData.Rules) {
    if (-not $rule) { continue }
    $id = [string]$rule.Id
    if (-not $id) { continue }
    $idUpper = $id.ToUpperInvariant()
    $actionValue = $null
    if ($rule.PSObject.Properties['Action']) { $actionValue = ConvertTo-NullableInt $rule.Action }
    $asrRules[$idUpper] = $actionValue
  }
}
$requiredAsrSets = @(
  @{ Label = 'Block Office macros from Internet'; Ids = @('3B576869-A4EC-4529-8536-B80A7769E899') },
  @{ Label = 'Block Win32 API calls from Office'; Ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A') },
  @{ Label = 'Block executable content from email/WebDAV'; Ids = @('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550','D3E037E1-3EB8-44C8-A917-57927947596D') },
  @{ Label = 'Block credential stealing from LSASS'; Ids = @('9E6C4E1F-7D60-472F-B5E9-2D3BEEB1BF0E') }
)
foreach ($set in $requiredAsrSets) {
  $label = $set.Label
  $ids = $set.Ids
  $missing = @()
  $nonBlocking = @()
  foreach ($id in $ids) {
    $lookup = $id.ToUpperInvariant()
    if (-not $asrRules.ContainsKey($lookup)) {
      $missing += $lookup
      continue
    }
    $action = $asrRules[$lookup]
    if ($action -ne 1) {
      $nonBlocking += "{0} => {1}" -f $lookup, $action
    }
  }
  if ($missing.Count -eq 0 -and $nonBlocking.Count -eq 0 -and $ids.Count -gt 0) {
    $evidence = ($ids | ForEach-Object { "{0} => 1" -f $_ }) -join "`n"
    Add-SecurityHeuristic ("ASR: {0}" -f $label) 'Block' 'good' '' $evidence
  } else {
    $detailsParts = @()
    if ($missing.Count -gt 0) { $detailsParts += ("Missing rule(s): {0}" -f ($missing -join ', ')) }
    if ($nonBlocking.Count -gt 0) { $detailsParts += ("Non-blocking: {0}" -f ($nonBlocking -join '; ')) }
    $detailText = if ($detailsParts.Count -gt 0) { $detailsParts -join '; ' } else { 'Rule not enforced.' }
    $evidenceLines = @()
    foreach ($id in $ids) {
      $lookup = $id.ToUpperInvariant()
      if ($asrRules.ContainsKey($lookup)) {
        $evidenceLines += "{0} => {1}" -f $lookup, $asrRules[$lookup]
      } else {
        $evidenceLines += "{0} => (missing)" -f $lookup
      }
    }
    $evidence = $evidenceLines -join "`n"
    Add-SecurityHeuristic ("ASR: {0}" -f $label) 'Not blocking' 'warning' $detailText $evidence -SkipIssue
    Add-Issue 'high' 'Security/ASR' ("ASR rule not enforced: {0}. Configure to Block (1)." -f $label) $evidence
  }
}

# 10. Exploit protection mitigations
$exploitData = ConvertFrom-JsonSafe $raw['security_exploit']
$cfgEnabled = $false
$depEnabled = $false
$aslrEnabled = $false
$exploitEvidenceLines = @()
if ($exploitData) {
  if ($exploitData.PSObject.Properties['CFG']) {
    $cfgValue = $exploitData.CFG.Enable
    $cfgEnabled = (To-BoolOrNull $cfgValue) -eq $true
    $exploitEvidenceLines += "CFG.Enable: $cfgValue"
  }
  if ($exploitData.PSObject.Properties['DEP']) {
    $depValue = $exploitData.DEP.Enable
    $depEnabled = (To-BoolOrNull $depValue) -eq $true
    $exploitEvidenceLines += "DEP.Enable: $depValue"
  }
  if ($exploitData.PSObject.Properties['ASLR']) {
    $aslrValue = $exploitData.ASLR.Enable
    $aslrEnabled = (To-BoolOrNull $aslrValue) -eq $true
    $exploitEvidenceLines += "ASLR.Enable: $aslrValue"
  }
}
$exploitEvidence = $exploitEvidenceLines -join "`n"
if ($cfgEnabled -and $depEnabled -and $aslrEnabled) {
  Add-SecurityHeuristic 'Exploit protection (system)' 'CFG/DEP/ASLR enforced' 'good' '' $exploitEvidence
} elseif ($exploitData) {
  $details = @()
  if (-not $cfgEnabled) { $details += 'CFG disabled' }
  if (-not $depEnabled) { $details += 'DEP disabled' }
  if (-not $aslrEnabled) { $details += 'ASLR disabled' }
  $detailText = if ($details.Count -gt 0) { $details -join '; ' } else { 'Mitigation status unknown.' }
  Add-SecurityHeuristic 'Exploit protection (system)' 'Relaxed' 'warning' $detailText $exploitEvidence -SkipIssue
  Add-Issue 'medium' 'Security/ExploitProtection' ('Exploit protection mitigations not fully enabled ({0}).' -f $detailText) $exploitEvidence
} else {
  Add-SecurityHeuristic 'Exploit protection (system)' 'Not captured' 'warning' 'Get-ProcessMitigation output unavailable.' ''
  Add-Issue 'medium' 'Security/ExploitProtection' 'Exploit Protection not captured. Collect Get-ProcessMitigation output.' ''
}

# 11. WDAC / Smart App Control
$wdacData = ConvertFrom-JsonSafe $raw['security_wdac']
$wdacEvidenceLines = @()
$wdacEnforced = $false
if ($securityServicesConfigured -contains 4 -or $securityServicesRunning -contains 4) {
  $wdacEnforced = $true
  $wdacEvidenceLines += 'DeviceGuard SecurityServices include 4 (Code Integrity).'
}
if ($wdacData -and $wdacData.PSObject.Properties['DeviceGuard']) {
  $dgSection = $wdacData.DeviceGuard
  if ($dgSection.PSObject.Properties['CodeIntegrityPolicyEnforcementStatus']) {
    $ciStatus = ConvertTo-NullableInt $dgSection.CodeIntegrityPolicyEnforcementStatus
    $wdacEvidenceLines += "CodeIntegrityPolicyEnforcementStatus: $ciStatus"
    if ($ciStatus -ge 1) { $wdacEnforced = $true }
  }
}
if ($wdacEnforced) {
  Add-SecurityHeuristic 'WDAC' 'Policy enforced' 'good' '' ($wdacEvidenceLines -join "`n")
} else {
  Add-SecurityHeuristic 'WDAC' 'No policy detected' 'warning' 'No WDAC enforcement detected.' ($wdacEvidenceLines -join "`n") -SkipIssue:($isModernClientProfile)
  if ($isModernClientProfile) {
    Add-Issue 'medium' 'Security/WDAC' 'No WDAC policy enforcement detected. Evaluate Application Control requirements.' ($wdacEvidenceLines -join "`n")
  }
}

$smartAppEvidence = ''
$smartAppState = $null
if ($wdacData -and $wdacData.PSObject.Properties['Registry']) {
  $registrySection = $wdacData.Registry
  foreach ($prop in $registrySection.PSObject.Properties) {
    if ($prop.Name -match 'SmartAppControl') {
      $smartAppEntry = $prop.Value
      if ($smartAppEntry -and $smartAppEntry.PSObject.Properties['Enabled']) {
        $smartAppState = ConvertTo-NullableInt $smartAppEntry.Enabled
      }
      $smartAppEvidence = ($smartAppEntry.PSObject.Properties | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Value }) -join "`n"
    }
  }
}
$isWindows11 = $false
if ($summary.OS -and $summary.OS -match 'Windows\s*11') { $isWindows11 = $true }
if (-not $smartAppEvidence) { $smartAppEvidence = $smartScreenMap['Policy.System.EnableSmartScreen'] }
if ($isWindows11 -and $smartAppState -ne 1) {
  Add-SecurityHeuristic 'Smart App Control' 'Off' 'warning' 'Smart App Control not in enforced mode.' $smartAppEvidence -SkipIssue:($isWindows11)
  Add-Issue 'medium' 'Security/SmartAppControl' 'Smart App Control is not enabled on Windows 11 device.' $smartAppEvidence
} elseif ($smartAppState -eq 1) {
  Add-SecurityHeuristic 'Smart App Control' 'On' 'good' '' $smartAppEvidence
} else {
  Add-SecurityHeuristic 'Smart App Control' 'Not configured' 'info' '' $smartAppEvidence
}

# 12. Local Administrators & LAPS
$localAdminsText = $raw['security_localadmins']
$localAdminMembers = @()
if ($localAdminsText) {
  $matches = [regex]::Matches($localAdminsText,'(?im)^\s*Member\s*:\s*(.+)$')
  foreach ($m in $matches) {
    $memberName = $m.Groups[1].Value.Trim()
    if ($memberName) { $localAdminMembers += $memberName }
  }
}
$localAdminEvidence = if ($localAdminMembers.Count -gt 0) { $localAdminMembers -join "`n" } else { Get-TopLines $localAdminsText 20 }
$whoamiText = $raw['whoami']
$isCurrentUserAdmin = $false
if ($whoamiText) {
  $adminLine = ([regex]::Split($whoamiText,'\r?\n') | Where-Object { $_ -match '(?i)builtin\\\\administrators' } | Select-Object -First 1)
  if ($adminLine -and $adminLine -match '(?i)enabled') { $isCurrentUserAdmin = $true }
}
if ($isCurrentUserAdmin) {
  Add-SecurityHeuristic 'Local admin rights' 'Current user in Administrators' 'bad' '' ($localAdminEvidence) -SkipIssue
  Add-Issue 'high' 'Security/LocalAdmin' 'The current user is a member of the local Administrators group. Use least privilege accounts.' $localAdminEvidence
} else {
  $memberSummary = if ($localAdminMembers.Count -gt 0) { "Members: $($localAdminMembers -join ', ')" } else { 'Group membership not captured.' }
  Add-SecurityHeuristic 'Local admin rights' 'Least privilege verified' 'good' $memberSummary ($localAdminEvidence)
}

$lapsData = ConvertFrom-JsonSafe $raw['security_laps']
$lapsEnabled = $false
$lapsEvidenceLines = @()
if ($lapsData) {
  if ($lapsData.PSObject.Properties['Legacy']) {
    $legacy = $lapsData.Legacy
    if ($legacy -and $legacy.PSObject.Properties['AdmPwdEnabled']) {
      $legacyEnabled = ConvertTo-NullableInt $legacy.AdmPwdEnabled
      $lapsEvidenceLines += "Legacy AdmPwdEnabled: $legacyEnabled"
      if ($legacyEnabled -eq 1) { $lapsEnabled = $true }
    }
  }
  if ($lapsData.PSObject.Properties['WindowsLAPS']) {
    $modern = $lapsData.WindowsLAPS
    foreach ($prop in $modern.PSObject.Properties) {
      $lapsEvidenceLines += "WindowsLAPS {0}: {1}" -f $prop.Name, $prop.Value
      if ($prop.Name -eq 'BackupDirectory' -and $prop.Value -ne $null) { $lapsEnabled = $true }
      if ($prop.Name -match 'Enabled' -and (ConvertTo-NullableInt $prop.Value) -eq 1) { $lapsEnabled = $true }
    }
  }
  if ($lapsData.PSObject.Properties['Status']) { $lapsEvidenceLines += $lapsData.Status }
}
$lapsEvidence = $lapsEvidenceLines -join "`n"
if ($lapsEnabled) {
  Add-SecurityHeuristic 'LAPS/PLAP' 'Policy detected' 'good' '' $lapsEvidence
} else {
  Add-SecurityHeuristic 'LAPS/PLAP' 'Not detected' 'warning' 'No LAPS policy detected.' $lapsEvidence
  Add-Issue 'high' 'Security/LAPS' 'LAPS/PLAP not detected. Enforce password management policy.' $lapsEvidence
}

# 13. UAC
$enableLua = ConvertTo-NullableInt $uacMap['EnableLUA']
$consentPrompt = ConvertTo-NullableInt $uacMap['ConsentPromptBehaviorAdmin']
$secureDesktop = ConvertTo-NullableInt $uacMap['PromptOnSecureDesktop']
$uacEvidence = ($uacMap.GetEnumerator() | ForEach-Object { "{0} = {1}" -f $_.Key, $_.Value }) -join "`n"
if ($enableLua -eq 1 -and ($secureDesktop -eq $null -or $secureDesktop -eq 1) -and ($consentPrompt -eq $null -or $consentPrompt -ge 2)) {
  Add-SecurityHeuristic 'UAC' 'Secure' 'good' '' $uacEvidence
} else {
  $uacFindings = @()
  if ($enableLua -ne 1) { $uacFindings += 'EnableLUA=0' }
  if ($consentPrompt -ne $null -and $consentPrompt -lt 2) { $uacFindings += "ConsentPrompt=$consentPrompt" }
  if ($secureDesktop -ne $null -and $secureDesktop -eq 0) { $uacFindings += 'PromptOnSecureDesktop=0' }
  $detail = if ($uacFindings.Count -gt 0) { $uacFindings -join '; ' } else { 'UAC configuration unclear.' }
  Add-SecurityHeuristic 'UAC' 'Weakened' 'warning' $detail $uacEvidence -SkipIssue
  Add-Issue 'high' 'Security/UAC' ('UAC configuration is insecure ({0}). Enforce secure UAC prompts.' -f $detail) $uacEvidence
}

# 14. PowerShell logging & AMSI
$psLoggingData = ConvertFrom-JsonSafe $raw['security_pslogging']
$scriptBlockEnabled = $false
$moduleLoggingEnabled = $false
$transcriptionEnabled = $false
$psLoggingEvidenceLines = @()
if ($psLoggingData -and -not $psLoggingData.PSObject.Properties['Status']) {
  foreach ($prop in $psLoggingData.PSObject.Properties) {
    $entry = $psLoggingData.$($prop.Name)
    if (-not $entry) { continue }
    if ($prop.Name -match 'ScriptBlockLogging') {
      if ($entry.PSObject.Properties['EnableScriptBlockLogging']) {
        $scriptBlockEnabled = ((ConvertTo-NullableInt $entry.EnableScriptBlockLogging) -eq 1)
        $psLoggingEvidenceLines += "EnableScriptBlockLogging: $($entry.EnableScriptBlockLogging)"
      }
    }
    if ($prop.Name -match 'ModuleLogging') {
      if ($entry.PSObject.Properties['EnableModuleLogging']) {
        $moduleLoggingEnabled = ((ConvertTo-NullableInt $entry.EnableModuleLogging) -eq 1)
        $psLoggingEvidenceLines += "EnableModuleLogging: $($entry.EnableModuleLogging)"
      }
    }
    if ($prop.Name -match 'Transcription') {
      if ($entry.PSObject.Properties['EnableTranscripting']) {
        $transcriptionEnabled = ((ConvertTo-NullableInt $entry.EnableTranscripting) -eq 1)
        $psLoggingEvidenceLines += "EnableTranscripting: $($entry.EnableTranscripting)"
      }
    }
  }
}
if ($psLoggingEvidenceLines.Count -eq 0 -and $psLoggingData -and $psLoggingData.PSObject.Properties['Status']) {
  $psLoggingEvidenceLines += $psLoggingData.Status
}
$psLoggingEvidence = $psLoggingEvidenceLines -join "`n"
if ($scriptBlockEnabled -and $moduleLoggingEnabled) {
  Add-SecurityHeuristic 'PowerShell logging' 'Script block & module logging enabled' 'good' '' $psLoggingEvidence
} else {
  $detailParts = @()
  if (-not $scriptBlockEnabled) { $detailParts += 'Script block logging disabled' }
  if (-not $moduleLoggingEnabled) { $detailParts += 'Module logging disabled' }
  if (-not $transcriptionEnabled) { $detailParts += 'Transcription not enabled' }
  $detail = if ($detailParts.Count -gt 0) { $detailParts -join '; ' } else { 'Logging state unknown.' }
  Add-SecurityHeuristic 'PowerShell logging' 'Insufficient logging' 'warning' $detail $psLoggingEvidence -SkipIssue
  Add-Issue 'medium' 'Security/PowerShellLogging' ('PowerShell logging is incomplete ({0}). Enable required logging for auditing.' -f $detail) $psLoggingEvidence
}

# 15. NTLM / LDAP hardening
$ldapClientIntegrity = ConvertTo-NullableInt $ldapMap['LDAPClientIntegrity']
$ldapChannelBinding = ConvertTo-NullableInt $ldapMap['LdapEnforceChannelBinding']
$ldapServerIntegrity = ConvertTo-NullableInt $ldapMap['LDAPServerIntegrity']
$ldapEvidence = ($ldapMap.GetEnumerator() | ForEach-Object { "{0} = {1}" -f $_.Key, $_.Value }) -join "`n"
$ldapSigningOk = ($ldapClientIntegrity -ge 1) -or ($ldapServerIntegrity -ge 1)
$channelBindingOk = ($ldapChannelBinding -ge 1)
if ($isDomainJoinedProfile) {
  if ($ldapSigningOk -and $channelBindingOk -and $ntlmRestricted) {
    Add-SecurityHeuristic 'LDAP/NTLM hardening' 'Policies enforced' 'good' '' $ldapEvidence
  } else {
    $hardeningDetails = @()
    if (-not $ldapSigningOk) { $hardeningDetails += 'LDAP signing not required' }
    if (-not $channelBindingOk) { $hardeningDetails += 'LDAP channel binding not enforced' }
    if (-not $ntlmRestricted) { $hardeningDetails += 'NTLM restrictions absent' }
    $detailText = if ($hardeningDetails.Count -gt 0) { $hardeningDetails -join '; ' } else { 'Hardening gaps detected.' }
    Add-SecurityHeuristic 'LDAP/NTLM hardening' 'Gaps detected' 'bad' $detailText ($ldapEvidence + "`n" + $ntlmEvidence) -SkipIssue
    Add-Issue 'high' 'Security/LDAPNTLM' ('LDAP/NTLM hardening not enforced ({0}). Configure signing, channel binding, and NTLM controls.' -f $detailText) ($ldapEvidence + "`n" + $ntlmEvidence)
  }
} else {
  Add-SecurityHeuristic 'LDAP/NTLM hardening' 'Not domain joined' 'info' '' $ldapEvidence
}

# 16. DHCP server ranges
$dhcpServers = @()
if ($raw['ipconfig']) {
  foreach ($line in [regex]::Split($raw['ipconfig'],'\r?\n')) {
    $match = [regex]::Match($line,'(?i)DHCP Server\s*[^:]*:\s*([0-9\.]+)')
    if ($match.Success) {
      $address = $match.Groups[1].Value.Trim()
      if ($address) { $dhcpServers += $address }
    }
  }
}
$publicDhcp = @()
foreach ($server in $dhcpServers) {
  if (-not (Test-IsRFC1918 $server)) { $publicDhcp += $server }
}
if ($publicDhcp.Count -gt 0) {
  $evidence = 'DHCP Servers: ' + ($dhcpServers -join ', ')
  Add-SecurityHeuristic 'DHCP servers' ('Public DHCP detected: ' + ($publicDhcp -join ', ')) 'bad' '' $evidence -SkipIssue
  Add-Issue 'high' 'Security/DHCP' ('Non-private DHCP servers detected: {0}. Investigate rogue DHCP sources.' -f ($publicDhcp -join ', ')) $evidence
} elseif ($dhcpServers.Count -gt 0) {
  $evidence = 'DHCP Servers: ' + ($dhcpServers -join ', ')
  Add-SecurityHeuristic 'DHCP servers' ('Private DHCP: ' + ($dhcpServers -join ', ')) 'good' '' $evidence
} else {
  Add-SecurityHeuristic 'DHCP servers' 'No DHCP servers detected' 'info' '' ''
}

# 17-19. Office macro protections
if ($macroSecurityStatus.Count -gt 0) {
  $allBlock = ($macroSecurityStatus | Where-Object { $_.BlockEnforced })
  $allStrict = ($macroSecurityStatus | Where-Object { $_.WarningsStrict })
  $allPvGood = ($macroSecurityStatus | Where-Object { $_.ProtectedViewGood })
  $blockOk = ($allBlock.Count -eq $macroSecurityStatus.Count)
  $warnOk = ($allStrict.Count -eq $macroSecurityStatus.Count)
  $pvOk = ($allPvGood.Count -eq $macroSecurityStatus.Count)
  $blockEvidence = ($macroSecurityStatus | ForEach-Object { "{0}: Block={1}" -f $_.App, $_.BlockEnforced }) -join "`n"
  $warnEvidence = ($macroSecurityStatus | ForEach-Object { "{0}: WarningsStrict={1}" -f $_.App, $_.WarningsStrict }) -join "`n"
  $pvEvidence = ($macroSecurityStatus | ForEach-Object { "{0}: ProtectedViewGood={1}" -f $_.App, $_.ProtectedViewGood }) -join "`n"
  Add-SecurityHeuristic 'Office MOTW macro blocking' (if ($blockOk) { 'Enforced' } else { 'Gaps detected' }) (if ($blockOk) { 'good' } else { 'warning' }) '' $blockEvidence -Area 'Security/Office'
  Add-SecurityHeuristic 'Office macro notifications' (if ($warnOk) { 'Strict' } else { 'Allows macros' }) (if ($warnOk) { 'good' } else { 'warning' }) '' $warnEvidence -Area 'Security/Office'
  Add-SecurityHeuristic 'Office Protected View' (if ($pvOk) { 'Active' } else { 'Disabled contexts' }) (if ($pvOk) { 'good' } else { 'warning' }) '' $pvEvidence -Area 'Security/Office'
} else {
  Add-SecurityHeuristic 'Office MOTW macro blocking' 'No data' 'warning' '' '' -Area 'Security/Office'
  Add-Issue 'medium' 'Security/Office' 'Office MOTW macro blocking - no data. Confirm macro policies.' ''
  Add-SecurityHeuristic 'Office macro notifications' 'No data' 'warning' '' '' -Area 'Security/Office'
  Add-Issue 'low' 'Security/Office' 'Office macro notifications - no data. Collect policy details.' ''
  Add-SecurityHeuristic 'Office Protected View' 'No data' 'warning' '' '' -Area 'Security/Office'
  Add-Issue 'low' 'Security/Office' 'Office Protected View - no data. Verify Protected View policies.' ''
}

# 20. BitLocker recovery key escrow
$bitlockerText = $raw['bitlocker']
if ($bitlockerText) {
  $recoveryMatch = [regex]::Matches($bitlockerText,'(?im)^\s*Key\s*Protector\s*Type\s*:\s*RecoveryPassword')
  $recoveryCount = $recoveryMatch.Count
  $bitlockerEvidence = Get-TopLines $bitlockerText 40
  if ($recoveryCount -gt 0) {
    Add-SecurityHeuristic 'BitLocker recovery key' ('Recovery passwords present (' + $recoveryCount + ')') 'good' '' $bitlockerEvidence
  } else {
    Add-SecurityHeuristic 'BitLocker recovery key' 'Recovery password not detected' 'warning' 'Ensure recovery keys are escrowed to AD/Azure AD.' $bitlockerEvidence -SkipIssue
    Add-Issue 'high' 'Security/BitLocker' 'No BitLocker recovery password protector detected. Ensure recovery keys are escrowed.' $bitlockerEvidence
  }
} else {
  Add-SecurityHeuristic 'BitLocker recovery key' 'Not captured' 'warning' 'BitLocker output missing.' ''
}

# crucial services snapshot
$serviceDefinitions = @(
  [pscustomobject]@{ Name='WSearch';            Display='Windows Search (WSearch)';                         Note='Outlook search depends on this.' },
  [pscustomobject]@{ Name='Dnscache';          Display='DNS Client (Dnscache)';                             Note='DNS resolution/cache for all apps.' },
  [pscustomobject]@{ Name='NlaSvc';            Display='Network Location Awareness (NlaSvc)';               Note='network profile changes; VPN/proxy awareness.' },
  [pscustomobject]@{ Name='LanmanWorkstation'; Display='Workstation (LanmanWorkstation)';                   Note='SMB client for shares/printers.' },
  [pscustomobject]@{ Name='RpcSs';             Display='Remote Procedure Call (RPC) (RpcSs)';               Note='core RPC runtime (do not disable).' },
  [pscustomobject]@{ Name='RpcEptMapper';      Display='RPC Endpoint Mapper (RpcEptMapper)';                Note='RPC endpoint directory.' },
  [pscustomobject]@{ Name='WinHttpAutoProxySvc'; Display='WinHTTP Auto Proxy (WinHttpAutoProxySvc)';        Note='WPAD/PAC for system services.' },
  [pscustomobject]@{ Name='BITS';              Display='Background Intelligent Transfer Service (BITS)';    Note='background transfers for updates/AV/Office.' },
  [pscustomobject]@{ Name='ClickToRunSvc';     Display='Office Click-to-Run (ClickToRunSvc)';               Note='Office updates and repair.' }
)
$serviceSnapshot = Parse-ServiceSnapshot $raw['services']
$servicesTextAvailable = -not [string]::IsNullOrWhiteSpace($raw['services'])
$winHttpProxyInfo = Get-WinHttpProxyInfo $raw['winhttp_proxy']
$systemHasProxy = if ($winHttpProxyInfo) { $winHttpProxyInfo.HasProxy } else { $null }
$serviceEvaluations = New-Object System.Collections.Generic.List[pscustomobject]
$isWorkstationProfile = ($summary.IsServer -ne $true)

foreach ($svc in $serviceDefinitions) {
  $isHealthy = $false
  $issueSeverity = $null
  $issueMessage = $null
  $tag = 'info'
  $statusDisplay = 'Not captured'
  $startDisplay = 'Unknown'
  $evidenceParts = @()
  $record = $null
  $normalizedStatus = 'unknown'
  $normalizedStart = 'unknown'
  $startDisplayForTable = 'Unknown'
  $noteParts = @()
  if (-not [string]::IsNullOrWhiteSpace($svc.Note)) {
    $noteParts += $svc.Note
  }

  if ($servicesTextAvailable) {
    if ($serviceSnapshot.ContainsKey($svc.Name)) {
      $record = $serviceSnapshot[$svc.Name]
      if ($record.RawLine) { $evidenceParts += $record.RawLine }
    }

    if ($record) {
      $statusDisplay = if ($record.Status) { $record.Status } else { 'Unknown' }
      $rawStartType = if ($record.StartType) { $record.StartType } else { '' }
      $startDisplay = if ($rawStartType) { $rawStartType } else { 'Unknown' }
      $startDisplayForTable = $startDisplay
      $normalizedStatus = Normalize-ServiceStatus $record.Status
      $normalizedStart = Normalize-ServiceStartType $rawStartType
    } else {
      $statusDisplay = 'Not found'
      $startDisplayForTable = 'Unknown'
    }

    $isAutomatic = ($normalizedStart -eq 'automatic' -or $normalizedStart -eq 'automatic-delayed')
    $isManual = ($normalizedStart -eq 'manual')
    $isDisabled = ($normalizedStart -eq 'disabled')

    switch ($svc.Name) {
      'WSearch' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          if ($isAutomatic) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'Windows Search stopped — Outlook search depends on this.'
          } elseif ($isDisabled) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'Windows Search disabled — Outlook search depends on this.'
          } elseif ($isManual) {
            if ($isWorkstationProfile) {
              $tag = 'warning'
              $issueSeverity = 'medium'
              $issueMessage = 'Windows Search stopped (Manual start) — Outlook search depends on this.'
            } else {
              $tag = 'info'
            }
          }
        }
      }
      'Dnscache' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          $tag = 'critical'
          $issueSeverity = 'critical'
          if ($record) {
            if ($isDisabled) {
              $issueMessage = 'Dnscache disabled — DNS lookups will fail/intermittent.'
            } elseif ($normalizedStatus -eq 'stopped') {
              $issueMessage = 'Dnscache stopped — DNS lookups will fail/intermittent.'
            } else {
              $issueMessage = 'Dnscache not running — DNS lookups will fail/intermittent.'
            }
          } else {
            $issueMessage = 'Dnscache service missing — DNS lookups will fail/intermittent.'
          }
        }
      }
      'NlaSvc' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          if ($isAutomatic) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'NlaSvc stopped — network profile changes; VPN/proxy awareness impacted.'
          } elseif ($isDisabled) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'NlaSvc disabled — network profile changes; VPN/proxy awareness impacted.'
          } elseif ($isManual) {
            if ($isWorkstationProfile) {
              $tag = 'warning'
              $issueSeverity = 'medium'
              $issueMessage = 'NlaSvc stopped (Manual start) — network profile changes; VPN/proxy awareness impacted.'
            } else {
              $tag = 'info'
            }
          }
        }
      }
      'LanmanWorkstation' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          $tag = 'bad'
          $issueSeverity = 'high'
          if ($isDisabled) {
            $issueMessage = 'LanmanWorkstation disabled — SMB shares/mapped drives broken.'
          } else {
            $issueMessage = 'LanmanWorkstation stopped — SMB shares/mapped drives broken.'
          }
        }
      }
      'RpcSs' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          $tag = 'critical'
          $issueSeverity = 'critical'
          if ($record) {
            $issueMessage = 'RpcSs not running — system unstable.'
          } else {
            $issueMessage = 'RpcSs service missing — system unstable.'
          }
        }
      }
      'RpcEptMapper' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          $tag = 'critical'
          $issueSeverity = 'critical'
          if ($record) {
            $issueMessage = 'RpcEptMapper not running — RPC endpoint directory unavailable.'
          } else {
            $issueMessage = 'RpcEptMapper service missing — RPC endpoint directory unavailable.'
          }
        }
      }
      'WinHttpAutoProxySvc' {
        if ($isManual -and $startDisplay) {
          if ($startDisplay -notmatch '(?i)trigger') {
            $startDisplayForTable = "$startDisplay (Trigger Start)"
          } else {
            $startDisplayForTable = $startDisplay
          }
        } else {
          $startDisplayForTable = $startDisplay
        }

        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          if ($isManual) {
            if ($systemHasProxy -eq $false) {
              $tag = 'good'
              $isHealthy = $true
              $noteParts += 'No system proxy detected; manual trigger start is expected.'
            } elseif ($systemHasProxy -eq $true) {
              $tag = 'warning'
              $issueSeverity = 'medium'
              $issueMessage = 'WinHTTP Auto Proxy stopped (proxy configured) — WPAD/PAC for system services will fail.'
            } else {
              $tag = 'info'
            }
          } elseif ($isAutomatic) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'WinHTTP Auto Proxy stopped — WPAD/PAC for system services unavailable.'
          } elseif ($isDisabled) {
            if ($systemHasProxy -eq $true) {
              $tag = 'bad'
              $issueSeverity = 'high'
              $issueMessage = 'WinHTTP Auto Proxy disabled (proxy configured) — WPAD/PAC for system services will fail.'
            } else {
              $tag = 'info'
            }
          }
        }

        if ($systemHasProxy -and $winHttpProxyInfo -and $winHttpProxyInfo.Raw) {
          $evidenceParts += $winHttpProxyInfo.Raw
        } elseif ($systemHasProxy -eq $false -and $winHttpProxyInfo -and $winHttpProxyInfo.Raw -and $tag -eq 'good') {
          $evidenceParts += $winHttpProxyInfo.Raw
        }
      }
      'BITS' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          if ($isAutomatic) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'BITS stopped — background transfers for updates/AV/Office.'
          } elseif ($isDisabled) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'BITS disabled — background transfers for updates/AV/Office.'
          } elseif ($isManual) {
            if ($isWorkstationProfile) {
              $tag = 'warning'
              $issueSeverity = 'medium'
              $issueMessage = 'BITS stopped (Manual start) — background transfers for updates/AV/Office.'
            } else {
              $tag = 'info'
            }
          }
        }
      }
      'ClickToRunSvc' {
        if ($normalizedStatus -eq 'running') {
          $tag = 'good'
          $isHealthy = $true
        } else {
          if ($isAutomatic) {
            $tag = 'bad'
            $issueSeverity = 'high'
            $issueMessage = 'ClickToRunSvc stopped — Office updates and repair blocked.'
          } elseif ($isManual) {
            if ($isWorkstationProfile) {
              $tag = 'warning'
              $issueSeverity = 'medium'
              $issueMessage = 'ClickToRunSvc stopped (Manual start) — Office updates and repair blocked.'
            } else {
              $tag = 'info'
            }
          } elseif ($isDisabled) {
            $tag = 'info'
          }
        }
      }
    }
  }

  if ($svc.Name -eq 'WinHttpAutoProxySvc' -and $tag -eq 'good' -and $normalizedStatus -ne 'running' -and $statusDisplay -and $statusDisplay -notmatch '(?i)trigger') {
    $statusDisplay = "$statusDisplay (Trigger Start)"
  }

  $combinedNotes = if ($noteParts.Count -gt 0) { ($noteParts -join ' ') } else { '' }
  $noteForOutput = if (-not [string]::IsNullOrWhiteSpace($combinedNotes)) { $combinedNotes } else { 'None recorded.' }

  $statusValue = if (-not [string]::IsNullOrWhiteSpace($statusDisplay)) { $statusDisplay } else { 'Unknown' }
  $startValue = if (-not [string]::IsNullOrWhiteSpace($startDisplayForTable)) { $startDisplayForTable } else { 'Unknown' }
  $detailLines = New-Object System.Collections.Generic.List[string]
  [void]$detailLines.Add("Status: $statusValue")
  [void]$detailLines.Add("Start Type: $startValue")
  [void]$detailLines.Add("Notes: $noteForOutput")

  if ($evidenceParts.Count -gt 0) {
    [void]$detailLines.Add('')
    foreach ($part in $evidenceParts) {
      if (-not [string]::IsNullOrWhiteSpace($part)) {
        [void]$detailLines.Add($part)
      }
    }
  }

  $serviceDetailsBlock = $detailLines -join "`n"

  if ($isHealthy) {
    Add-Normal 'Services' $svc.Display $serviceDetailsBlock
  } elseif ($issueSeverity -and $issueMessage) {
    Add-Issue $issueSeverity 'Services' $issueMessage $serviceDetailsBlock
  }

  $serviceEvaluations.Add([pscustomobject]@{
    Name        = $svc.Name
    Display     = $svc.Display
    Status      = $statusDisplay
    StartType   = $startDisplayForTable
    Tag         = $tag
    Note        = $noteForOutput
  })
}

if ($servicesTextAvailable -and $serviceSnapshot.Count -gt 0) {
  $legacyCritical = @('Dhcp','WlanSvc','LanmanServer','WinDefend')
  $legacyRunning = @()
  foreach ($legacyName in $legacyCritical) {
    if (-not $serviceSnapshot.ContainsKey($legacyName)) { continue }
    $legacyRecord = $serviceSnapshot[$legacyName]
    $legacyStatus = Normalize-ServiceStatus $legacyRecord.Status
    if ($legacyStatus -eq 'stopped') {
      Add-Issue 'high' 'Services' "Core service stopped: $legacyName" $legacyRecord.RawLine
    } elseif ($legacyStatus -eq 'running') {
      $legacyRunning += $legacyName
    }
  }
  if ($legacyRunning.Count -gt 0) {
    Add-Normal 'Services' ("Core services running: " + ($legacyRunning -join ', ')) ''
  }
}

# events quick counters
function Parse-EventLogBlocks {
  param([string]$Text)

  $events = New-Object System.Collections.Generic.List[pscustomobject]
  if ([string]::IsNullOrWhiteSpace($Text)) { return $events }

  $pattern = '(?ms)^Event\[\d+\]:.*?(?=^Event\[\d+\]:|\z)'
  $matches = [regex]::Matches($Text, $pattern)
  foreach ($match in $matches) {
    if (-not $match) { continue }
    $block = $match.Value
    if ([string]::IsNullOrWhiteSpace($block)) { continue }

    $trimmed = $block.Trim()
    if (-not $trimmed) { continue }

    $provider = ''
    $providerMatch = [regex]::Match($trimmed,'(?im)^\s*(Provider Name|Provider|Source)\s*[:=]\s*(?<value>[^\r\n]+)')
    if ($providerMatch.Success) { $provider = $providerMatch.Groups['value'].Value.Trim() }

    $eventId = $null
    $eventIdMatch = [regex]::Match($trimmed,'(?im)^\s*(Event ID|EventID)\s*[:=]\s*(?<value>\d+)')
    if ($eventIdMatch.Success) {
      $idValue = $eventIdMatch.Groups['value'].Value.Trim()
      $parsedId = 0
      if ([int]::TryParse($idValue, [ref]$parsedId)) { $eventId = $parsedId }
    }

    $level = ''
    $levelMatch = [regex]::Match($trimmed,'(?im)^\s*Level\s*[:=]\s*(?<value>[^\r\n]+)')
    if ($levelMatch.Success) { $level = $levelMatch.Groups['value'].Value.Trim() }

    $index = $null
    $indexMatch = [regex]::Match($trimmed,'(?im)^Event\[(?<index>\d+)\]')
    if ($indexMatch.Success) {
      $parsedIndex = 0
      if ([int]::TryParse($indexMatch.Groups['index'].Value, [ref]$parsedIndex)) { $index = $parsedIndex }
    }

    $lines = [regex]::Split($trimmed,'\r?\n')
    $snippetLines = $lines | Where-Object { $_ -and $_.Trim() } | Select-Object -First 8
    if (-not $snippetLines -or $snippetLines.Count -eq 0) {
      $snippetLines = $lines | Select-Object -First 8
    }
    $snippet = ''
    if ($snippetLines) {
      $snippet = ($snippetLines -join "`n").Trim()
    }

    $events.Add([pscustomobject]@{
      Index    = $index
      Provider = $provider
      EventId  = $eventId
      Level    = $level
      Raw      = $trimmed
      Snippet  = $snippet
    })
  }

  return $events
}

function Select-EventMatches {
  param(
    [System.Collections.Generic.List[pscustomobject]]$Events,
    [string[]]$ProviderPatterns = @(),
    [int[]]$EventIds = @(),
    [string[]]$MessagePatterns = @(),
    [string[]]$LevelFilter = @('Error','Warning')
  )

  $matches = New-Object System.Collections.Generic.List[pscustomobject]
  if (-not $Events) { return $matches }

  foreach ($evt in $Events) {
    if (-not $evt) { continue }

    $include = $true

    if ($ProviderPatterns -and $ProviderPatterns.Count -gt 0) {
      $include = $false
      $providerText = if ($evt.Provider) { [string]$evt.Provider } else { '' }
      foreach ($pattern in $ProviderPatterns) {
        if (-not $pattern) { continue }
        if ($providerText -match $pattern) { $include = $true; break }
      }
      if (-not $include) { continue }
    }

    if ($EventIds -and $EventIds.Count -gt 0) {
      if ($null -eq $evt.EventId) { continue }
      if (-not ($EventIds -contains $evt.EventId)) { continue }
    }

    if ($LevelFilter -and $LevelFilter.Count -gt 0) {
      $levelText = if ($evt.Level) { [string]$evt.Level } else { '' }
      $levelMatch = $false
      foreach ($levelPattern in $LevelFilter) {
        if (-not $levelPattern) { continue }
        $regexLevel = '(?i)' + [regex]::Escape($levelPattern)
        if ($levelText -match $regexLevel) { $levelMatch = $true; break }
      }
      if (-not $levelMatch) {
        $rawForLevel = if ($evt.Raw) { [string]$evt.Raw } else { '' }
        foreach ($levelPattern in $LevelFilter) {
          if (-not $levelPattern) { continue }
          if ($rawForLevel -match ('(?i)\b' + [regex]::Escape($levelPattern) + '\b')) { $levelMatch = $true; break }
        }
      }
      if (-not $levelMatch) { continue }
    }

    if ($MessagePatterns -and $MessagePatterns.Count -gt 0) {
      $rawText = if ($evt.Raw) { [string]$evt.Raw } else { '' }
      $messageMatch = $false
      foreach ($pattern in $MessagePatterns) {
        if (-not $pattern) { continue }
        if ($rawText -match $pattern) { $messageMatch = $true; break }
      }
      if (-not $messageMatch) { continue }
    }

    $matches.Add($evt)
  }

  return $matches
}

function Get-EventEvidenceText {
  param(
    [System.Collections.Generic.List[pscustomobject]]$Events,
    [int]$Max = 2
  )

  if (-not $Events -or $Events.Count -eq 0) { return '' }

  $take = [Math]::Min($Max, $Events.Count)
  $parts = New-Object System.Collections.Generic.List[string]

  for ($i = 0; $i -lt $take; $i++) {
    $evt = $Events[$i]
    if (-not $evt) { continue }

    $headerParts = @()
    if ($evt.Provider) { $headerParts += $evt.Provider }
    if ($evt.EventId -ne $null) { $headerParts += ("ID {0}" -f $evt.EventId) }
    if ($evt.Level) { $headerParts += $evt.Level }
    $header = if ($headerParts.Count -gt 0) { "[{0}]" -f ($headerParts -join ' • ') } else { '' }

    $snippet = if ($evt.Snippet) { [string]$evt.Snippet } else { [string]$evt.Raw }
    if (-not [string]::IsNullOrWhiteSpace($snippet)) { $snippet = $snippet.Trim() }

    if ($header) {
      $parts.Add("$header`n$snippet")
    } else {
      $parts.Add($snippet)
    }
  }

  if ($Events.Count -gt $take) {
    $remaining = $Events.Count - $take
    $parts.Add("(+{0} additional related event(s) in sample)" -f $remaining)
  }

  return ($parts -join "`n`n")
}

function Get-EventHighlights {
  param(
    [string]$Text,
    [string[]]$TargetLevels = @('Error'),
    [int]$Max = 3
  )

  $snippets = New-Object System.Collections.Generic.List[string]
  $matched = 0
  if ([string]::IsNullOrWhiteSpace($Text)) {
    return [pscustomobject]@{ Snippets = $snippets; Matched = 0 }
  }

  $levels = @($TargetLevels | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  $eventPattern = '(?ms)^Event\[\d+\]:.*?(?=^Event\[\d+\]:|\z)'
  $matches = [regex]::Matches($Text, $eventPattern)

  foreach ($match in $matches) {
    $block = $match.Value
    if (-not $block) { continue }

    $levelMatch = [regex]::Match($block,'(?im)^\s*Level\s*[:=]\s*(?<level>[^\r\n]+)')
    $levelValue = if ($levelMatch.Success) { $levelMatch.Groups['level'].Value.Trim() } else { '' }

    $include = $true
    if ($levels.Count -gt 0) {
      $include = $false
      foreach ($level in $levels) {
        if ($levelValue -and $levelValue -match ('(?i)\b' + [regex]::Escape($level) + '\b')) { $include = $true; break }
      }
      if (-not $include) {
        foreach ($level in $levels) {
          if ($block -match ('(?i)\b' + [regex]::Escape($level) + '\b')) { $include = $true; break }
        }
      }
    }

    if (-not $include) { continue }

    $matched++
    if ($snippets.Count -ge $Max) { continue }

    $lines = [regex]::Split($block,'\r?\n')
    $selected = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      $selected.Add($line.Trim())
      if ($selected.Count -ge 8) { break }
    }
    if ($selected.Count -gt 0) {
      $snippets.Add(($selected -join "`n"))
    }
  }

  if ($matched -eq 0 -and $levels.Count -gt 0) {
    $keywordPattern = '(?i)\b(' + (($levels | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b'
    $lines = [regex]::Split($Text,'\r?\n')
    foreach ($line in $lines) {
      if (-not $line) { continue }
      if ($line -notmatch $keywordPattern) { continue }
      $matched++
      if ($snippets.Count -lt $Max) {
        $snippets.Add($line.Trim())
      }
    }
  }

  if ($matched -eq 0) { $matched = $snippets.Count }

  return [pscustomobject]@{
    Snippets = $snippets
    Matched  = $matched
  }
}

$systemEventBlocks = Parse-EventLogBlocks $raw['event_system']
$applicationEventBlocks = Parse-EventLogBlocks $raw['event_app']
$allEventBlocks = New-Object System.Collections.Generic.List[pscustomobject]
if ($systemEventBlocks) {
  foreach ($evt in $systemEventBlocks) { if ($evt) { $allEventBlocks.Add($evt) } }
}
if ($applicationEventBlocks) {
  foreach ($evt in $applicationEventBlocks) { if ($evt) { $allEventBlocks.Add($evt) } }
}

# Active Directory heuristics (client-side)
$domainIsJoined = ($summary.DomainJoined -eq $true)
if ($domainIsJoined) {
  $dnsDebug = $null
  if ($summary.ContainsKey('DnsDebug')) { $dnsDebug = $summary.DnsDebug }
  $dnsEvidence = ''
  if ($summary.ContainsKey('DnsDebugEvidence')) { $dnsEvidence = [string]$summary.DnsDebugEvidence }

  $dcCountValue = 0
  $dcIPsList = @()
  $dcHostsList = @()
  $adCapableList = @()
  $configuredDnsList = @()
  $publicDnsList = @()
  $dnsTestsAvailableBool = $null
  $dnsTestsAttemptedBool = $null
  $secureChannelState = $null
  $anycastOverride = $null
  $dcQueryName = ''

  if ($dnsDebug -is [System.Collections.IDictionary]) {
    $dcCountRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'DcCount'
    if ($dcCountRaw -is [int]) {
      $dcCountValue = [int]$dcCountRaw
    } elseif ($dcCountRaw -ne $null) {
      $parsedDcCount = 0
      if ([int]::TryParse(([string]$dcCountRaw).Trim(), [ref]$parsedDcCount)) { $dcCountValue = $parsedDcCount }
    }

    $dcIPsList = ConvertTo-StringArray (Get-DictionaryValue -Dictionary $dnsDebug -Key 'DcIPs')
    $dcHostsList = ConvertTo-StringArray (Get-DictionaryValue -Dictionary $dnsDebug -Key 'DcHosts')
    $adCapableList = ConvertTo-StringArray (Get-DictionaryValue -Dictionary $dnsDebug -Key 'AdCapableDns')
    $configuredDnsList = ConvertTo-StringArray (Get-DictionaryValue -Dictionary $dnsDebug -Key 'ConfiguredDns')
    $publicDnsList = ConvertTo-StringArray (Get-DictionaryValue -Dictionary $dnsDebug -Key 'PublicDns')

    $dnsTestsAvailableRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'DnsTestsAvailable'
    if ($dnsTestsAvailableRaw -is [bool]) {
      $dnsTestsAvailableBool = $dnsTestsAvailableRaw
    } elseif ($dnsTestsAvailableRaw -ne $null) {
      $dnsTestsAvailableBool = To-BoolOrNull ([string]$dnsTestsAvailableRaw)
    }

    $dnsTestsAttemptedRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'DnsTestsAttempted'
    if ($dnsTestsAttemptedRaw -is [bool]) {
      $dnsTestsAttemptedBool = $dnsTestsAttemptedRaw
    } elseif ($dnsTestsAttemptedRaw -ne $null) {
      $dnsTestsAttemptedBool = To-BoolOrNull ([string]$dnsTestsAttemptedRaw)
    }

    $secureChannelRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'SecureChannelOK'
    if ($secureChannelRaw -is [bool]) {
      $secureChannelState = $secureChannelRaw
    } elseif ($secureChannelRaw -ne $null) {
      $secureChannelState = To-BoolOrNull ([string]$secureChannelRaw)
    }

    $anycastRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'AnycastOverrideMatched'
    if ($anycastRaw -is [bool]) {
      $anycastOverride = $anycastRaw
    } elseif ($anycastRaw -ne $null) {
      $anycastOverride = To-BoolOrNull ([string]$anycastRaw)
    }

    $dcQueryNameValue = Get-DictionaryValue -Dictionary $dnsDebug -Key 'DcQueryName'
    if ($dcQueryNameValue) { $dcQueryName = [string]$dcQueryNameValue }
  }

  $canEvaluateDcDiscovery = $true
  if ($dnsTestsAvailableBool -eq $false) { $canEvaluateDcDiscovery = $false }
  if ($dnsTestsAttemptedBool -eq $false -and $dcCountValue -eq 0 -and $dcIPsList.Count -eq 0) { $canEvaluateDcDiscovery = $false }

  if ($canEvaluateDcDiscovery -and $dcCountValue -le 0 -and $dcIPsList.Count -eq 0) {
    $dcEvidenceParts = New-Object System.Collections.Generic.List[string]
    if ($dcQueryName) { $dcEvidenceParts.Add("SRV query attempted: $dcQueryName") }
    if ($configuredDnsList.Count -gt 0) { $dcEvidenceParts.Add("Configured DNS: " + ($configuredDnsList -join ', ')) }
    if ($dnsEvidence) { $dcEvidenceParts.Add($dnsEvidence) }
    if ($dcEvidenceParts.Count -eq 0) { $dcEvidenceParts.Add('No domain controllers discovered via DNS SRV query.') }
    $dcEvidenceText = ($dcEvidenceParts -join "`n`n")
    Add-Issue 'critical' 'Active Directory/DC Discovery' 'No domain controllers discovered via DNS SRV records. Domain logons and policy refresh will fail.' $dcEvidenceText
  }

  if ($adCapableList.Count -eq 0) {
    $dnsText = if ($dnsEvidence) { $dnsEvidence } else { "Configured DNS: " + ($configuredDnsList -join ', ') }
    Add-Issue 'critical' 'Active Directory/AD DNS' 'No AD-capable DNS resolvers detected; client cannot locate domain controllers.' $dnsText
  } elseif ($adCapableList.Count -eq 1 -and -not ($anycastOverride -eq $true)) {
    $singleDns = $adCapableList[0]
    $dnsText = if ($dnsEvidence) { $dnsEvidence } else { "AD-capable DNS: $singleDns" }
    Add-Issue 'high' 'Active Directory/AD DNS' ("Only one AD-capable DNS resolver configured ({0}); there is no failover for domain lookups." -f $singleDns) $dnsText
  }

  if ($publicDnsList.Count -gt 0 -and -not ($anycastOverride -eq $true) -and $adCapableList.Count -gt 0) {
    $dnsText = if ($dnsEvidence) { $dnsEvidence } else { "Public DNS detected: " + ($publicDnsList -join ', ') }
    Add-Issue 'medium' 'Active Directory/AD DNS' ("Public DNS servers configured on a domain-joined client: {0}. These can block DC discovery." -f ($publicDnsList -join ', ')) $dnsText
  }

  if ($secureChannelState -eq $false) {
    $secureEvidenceParts = New-Object System.Collections.Generic.List[string]
    $secureEvidenceParts.Add('Test-ComputerSecureChannel returned False.')
    if ($dnsEvidence) { $secureEvidenceParts.Add($dnsEvidence) }
    $secureEvidence = ($secureEvidenceParts -join "`n`n")
    Add-Issue 'critical' 'Active Directory/Secure Channel' 'Machine secure channel to the domain is broken. Reset the computer account or rejoin the domain.' $secureEvidence
  }

  $timeEventIds = @(29,30,31,32,34,35,36,47,50,134,138)
  $timeEvents = Select-EventMatches -Events $systemEventBlocks -ProviderPatterns @('(?i)Time-Service','(?i)W32Time') -EventIds $timeEventIds
  if ($timeEvents.Count -eq 0) {
    $timeEvents = Select-EventMatches -Events $systemEventBlocks -ProviderPatterns @('(?i)Time-Service','(?i)W32Time') -MessagePatterns @('(?i)clock skew','(?i)time difference','(?i)time service','(?i)synchronization attempt','(?i)Not synchronize')
  }

  $kerberosEventIds = @(4,5,6,7,9,11,14,16,18)
  $kerberosEvents = Select-EventMatches -Events $allEventBlocks -ProviderPatterns @('(?i)Kerberos','(?i)KDC') -EventIds $kerberosEventIds
  if ($kerberosEvents.Count -eq 0) {
    $kerberosEvents = Select-EventMatches -Events $allEventBlocks -ProviderPatterns @('(?i)Kerberos','(?i)KDC') -MessagePatterns @('(?i)Kerberos','(?i)KRB_','(?i)clock skew','(?i)pre-authentication','(?i)PAC verification','(?i)0xC000018B','(?i)0xC000006A')
  }

  $timeKerbEvidenceParts = New-Object System.Collections.Generic.List[string]
  if ($timeEvents.Count -gt 0) {
    $timeKerbEvidenceParts.Add("Time synchronization errors:`n" + (Get-EventEvidenceText $timeEvents 2))
  }
  if ($kerberosEvents.Count -gt 0) {
    $timeKerbEvidenceParts.Add("Kerberos authentication errors:`n" + (Get-EventEvidenceText $kerberosEvents 2))
  }
  if ($timeKerbEvidenceParts.Count -gt 0) {
    $timeKerbEvidence = ($timeKerbEvidenceParts -join "`n`n")
    Add-Issue 'high' 'Active Directory/Time & Kerberos' 'Time synchronization or Kerberos authentication errors detected. Verify clock alignment and domain controller reachability.' $timeKerbEvidence
  }

  $netlogonEvents = Select-EventMatches -Events $systemEventBlocks -ProviderPatterns @('(?i)Netlogon') -EventIds @(5719,5722,5805,3210)
  if ($netlogonEvents.Count -eq 0) {
    $netlogonEvents = Select-EventMatches -Events $systemEventBlocks -ProviderPatterns @('(?i)Netlogon') -MessagePatterns @('(?i)logon server','(?i)NETLOGON','(?i)trust relationship','(?i)secure channel')
  }
  $sysvolPathEvents = Select-EventMatches -Events $systemEventBlocks -ProviderPatterns @('(?i)GroupPolicy','(?i)Microsoft-Windows-GroupPolicy') -MessagePatterns @('(?i)\\[^\r\n]+\\SYSVOL','(?i)\\[^\r\n]+\\NETLOGON','(?i)The network path was not found','(?i)The system cannot find the path specified')

  $combinedSysvol = New-Object System.Collections.Generic.List[pscustomobject]
  foreach ($evt in $netlogonEvents) { if ($evt) { $combinedSysvol.Add($evt) } }
  foreach ($evt in $sysvolPathEvents) { if ($evt) { $combinedSysvol.Add($evt) } }

  if ($combinedSysvol.Count -gt 0) {
    $uniqueSysvol = New-Object System.Collections.Generic.List[pscustomobject]
    $sysvolSeen = @{}
    foreach ($evt in $combinedSysvol) {
      if (-not $evt) { continue }
      $rawKey = if ($evt.Raw) { [string]$evt.Raw } else { [string]$evt.Snippet }
      if (-not $rawKey) { $rawKey = [guid]::NewGuid().ToString() }
      if (-not $sysvolSeen.ContainsKey($rawKey)) {
        $sysvolSeen[$rawKey] = $true
        $uniqueSysvol.Add($evt)
      }
    }
    if ($uniqueSysvol.Count -gt 0) {
      $sysvolEvidence = Get-EventEvidenceText $uniqueSysvol 2
      Add-Issue 'high' 'Active Directory/SYSVOL/NETLOGON' 'Errors accessing SYSVOL or NETLOGON shares detected. Client cannot read required domain scripts or policies.' $sysvolEvidence
    }
  }

  $gpoEvents = Select-EventMatches -Events $systemEventBlocks -ProviderPatterns @('(?i)GroupPolicy','(?i)Microsoft-Windows-GroupPolicy') -EventIds @(1058,1030,1129,7016,7017)
  if ($gpoEvents.Count -eq 0) {
    $gpoEvents = Select-EventMatches -Events $systemEventBlocks -ProviderPatterns @('(?i)GroupPolicy','(?i)Microsoft-Windows-GroupPolicy') -MessagePatterns @('(?i)Group Policy.*failed','(?i)processing of Group Policy','(?i)Failed to connect to a Windows domain controller','(?i)The policy processing failed','(?i)Could not apply policy')
  }
  if ($gpoEvents.Count -gt 0) {
    $filteredGpo = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($evt in $gpoEvents) {
      if (-not $evt) { continue }
      $rawText = if ($evt.Raw) { [string]$evt.Raw } else { '' }
      if ($rawText -match '(?i)\bSYSVOL\b' -or $rawText -match '(?i)\bNETLOGON\b') { continue }
      $filteredGpo.Add($evt)
    }
    if ($filteredGpo.Count -eq 0) { $filteredGpo = $gpoEvents }
    if ($filteredGpo.Count -gt 0) {
      $gpoEvidence = Get-EventEvidenceText $filteredGpo 2
      Add-Issue 'high' 'Active Directory/GPO Processing' 'Group Policy processing errors detected in recent logs.' $gpoEvidence
    }
  }
}

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
    Add-Issue "medium" "Events" "$name log shows many errors ($err in recent sample)." $evidenceText
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
