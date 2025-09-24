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

# ---------- helpers ----------
function Read-Text($path) {
  if (Test-Path $path) { return (Get-Content $path -Raw -ErrorAction SilentlyContinue) } else { return "" }
}

$allTxt = Get-ChildItem -Path $InputFolder -Recurse -File -Include *.txt 2>$null

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

  systeminfo     = Find-ByContent @('systeminfo')                @('OS Name:\s','OS Version:\s','System Boot Time')
  os_cim         = Find-ByContent @('OS_CIM','OperatingSystem')  @('Win32_OperatingSystem','Caption\s*:')
  computerinfo   = Find-ByContent @('ComputerInfo')              @('CsName\s*:','WindowsBuildLabEx\s*:')

  nic_configs    = Find-ByContent @('NetworkAdapterConfigs')     @('Win32_NetworkAdapterConfiguration')
  netip          = Find-ByContent @('NetIPAddresses','NetIP')    @('IPAddress','InterfaceIndex')
  netadapters    = Find-ByContent @('NetAdapters')               @('Name\s*:.*Status','LinkSpeed|Speed')
  winhttp_proxy  = Find-ByContent @('WinHTTP_Proxy','winhttp_proxy') @('WinHTTP proxy settings','Direct access','Proxy Server')

  diskdrives     = Find-ByContent @('Disk_Drives')               @('Model\s+Serial|Model\s+SerialNumber','Status')
  volumes        = Find-ByContent @('Volumes')                   @('DriveLetter|FileSystem|HealthStatus')
  disks          = Find-ByContent @('Disks')                     @('Number\s*:','OperationalStatus')

  hotfixes       = Find-ByContent @('Hotfixes')                  @('HotFixID','InstalledOn')
  programs       = Find-ByContent @('Programs_Reg')              @('DisplayName\s+DisplayVersion')
  programs32     = Find-ByContent @('Programs_Reg_32')           @('DisplayName\s+DisplayVersion')

  services       = Find-ByContent @('Services')                  @('Status\s+Name|SERVICE_NAME')
  core_services  = Find-ByContent @('Core_Services','CoreServices') @('Name,DisplayName,Status,StartType')
  processes      = Find-ByContent @('Processes','tasklist')      @('Image Name\s+PID|====')
  drivers        = Find-ByContent @('Drivers','driverquery')     @('Driver Name|Display Name')

  event_system   = Find-ByContent @('Event_System')              @('(?im)^\s*Log Name\s*[:=]\s*System','(?im)^\s*Provider(?: Name)?\s*[:=]','(?im)^Event\[','(?i)TimeCreated','(?i)EventID')
  event_app      = Find-ByContent @('Event_Application')         @('(?im)^\s*Log Name\s*[:=]\s*Application','(?im)^\s*Provider(?: Name)?\s*[:=]','(?im)^Event\[','(?i)TimeCreated','(?i)EventID')

  firewall       = Find-ByContent @('Firewall')                  @('Windows Firewall with Advanced Security|Profile Settings')
  firewall_rules = Find-ByContent @('FirewallRules')             @('Rule Name:|DisplayName\s*:')

  defender       = Find-ByContent @('DefenderStatus')            @('Get-MpComputerStatus|AMProductVersion')
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
function Add-Issue([string]$sev,[string]$area,[string]$msg,[string]$evidence=""){
  $logMsg = if ($null -eq $msg) { "" } else { $msg }
  $sevKey = if ($sev) { $sev.ToLowerInvariant() } else { "" }
  $badgeText = 'ISSUE'
  $cssClass = 'ok'

  switch ($sevKey) {
    'critical' { $badgeText = 'CRITICAL'; $cssClass = 'critical' }
    'high'     { $badgeText = 'BAD';       $cssClass = 'bad' }
    'medium'   { $badgeText = 'WARNING';   $cssClass = 'warning' }
    'low'      { $badgeText = 'OK';        $cssClass = 'ok' }
    'info'     { $badgeText = 'GOOD';      $cssClass = 'good' }
    default    {
      if ($sev) {
        $badgeText = $sev.ToUpperInvariant()
      }
    }
  }

  $logSeverity = if ($sev) { $sev.ToUpperInvariant() } else { $badgeText }
  Write-Verbose ("Issue added => {0}: {1} - {2}" -f $logSeverity, $area, $logMsg)
  $issues.Add([pscustomobject]@{
    Severity  = $sev
    Area      = $area
    Message   = $msg
    Evidence  = if($evidence){ $evidence.Substring(0,[Math]::Min(1500,$evidence.Length)) } else { "" }
    CssClass  = $cssClass
    BadgeText = $badgeText
  })
}

# healthy findings
$normals = New-Object System.Collections.Generic.List[pscustomobject]
function Add-Normal([string]$area,[string]$msg,[string]$evidence="",[string]$badgeText="GOOD"){
  $normalizedBadge = if ($badgeText) { $badgeText.ToUpperInvariant() } else { 'GOOD' }
  $normals.Add([pscustomobject]@{
    Area     = $area
    Message  = $msg
    Evidence = if($evidence){ $evidence.Substring(0,[Math]::Min(800,$evidence.Length)) } else { "" }
    CssClass  = 'good'
    BadgeText = $normalizedBadge
  })
}

function Get-BoolFromString {
  param(
    [string]$Value
  )

  if ($null -eq $Value) { return $null }
  $trimmed = $Value.Trim()
  if (-not $trimmed) { return $null }

  $lower = $trimmed.ToLowerInvariant()
  switch ($lower) {
    'true' { return $true }
    'false' { return $false }
    'yes' { return $true }
    'no' { return $false }
    'enabled' { return $true }
    'disabled' { return $false }
    'on' { return $true }
    'off' { return $false }
    default {
      if ($lower -match '^[01]$') {
        return ($lower -eq '1')
      }
      return $null
    }
  }
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

function Normalize-ServiceStatus {
  param([string]$Status)

  if ($null -eq $Status) { return 'Unknown' }
  $trimmed = $Status.Trim()
  if (-not $trimmed) { return 'Unknown' }

  $lower = $trimmed.ToLowerInvariant()
  switch ($lower) {
    'running' { return 'Running' }
    'stopped' { return 'Stopped' }
    'paused'  { return 'Paused' }
    'notfound' { return 'NotFound' }
    'not found' { return 'NotFound' }
    default { return $trimmed }
  }
}

function Normalize-ServiceStartType {
  param([string]$StartType)

  if ($null -eq $StartType) { return 'Unknown' }
  $trimmed = $StartType.Trim()
  if (-not $trimmed) { return 'Unknown' }

  $lower = $trimmed.ToLowerInvariant()
  if ($lower -eq 'notfound' -or $lower -eq 'not found') { return 'NotFound' }
  if ($trimmed -match '(?i)automatic' -and $trimmed -match '(?i)delay') { return 'Automatic (Delayed)' }
  if ($trimmed -match '(?i)automatic') { return 'Automatic' }
  if ($trimmed -match '(?i)manual') { return 'Manual' }
  if ($trimmed -match '(?i)demand') { return 'Manual' }
  if ($trimmed -match '(?i)disabled') { return 'Disabled' }
  if ($trimmed -match '(?i)boot') { return 'Boot' }
  if ($trimmed -match '(?i)system') { return 'System' }
  return $trimmed
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
    $aad = Get-BoolFromString $dsregMap['AzureAdJoined']
    if ($null -ne $aad){ $summary.AzureAdJoined = $aad }
  }
  if ($dsregMap.ContainsKey('WorkplaceJoined')){
    $wp = Get-BoolFromString $dsregMap['WorkplaceJoined']
    if ($null -ne $wp){ $summary.WorkplaceJoined = $wp }
  }
  if ($dsregMap.ContainsKey('EnterpriseJoined')){
    $ent = Get-BoolFromString $dsregMap['EnterpriseJoined']
    if ($null -ne $ent){ $summary.EnterpriseJoined = $ent }
  }
  if ($dsregMap.ContainsKey('DomainJoined')){
    $dj = Get-BoolFromString $dsregMap['DomainJoined']
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
          Add-Normal "OS/Uptime" $message $summary.LastBoot
        } elseif ($classification.Severity) {
          $message = "{0} uptime {1} days in {2} range{3}." -f $profileName, $roundedDays, $classification.Label, $rangeSuffix
          Add-Issue $classification.Severity "OS/Uptime" $message $summary.LastBoot
        }
      }
    } else {
    Add-Normal "OS/Uptime" "Last boot captured" $summary.LastBoot
  }
}

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

    if ($domainJoined -eq $false) {
      Add-Normal "Network/DNS" "Workgroup/standalone: DNS servers configured" ("DNS: " + ($dnsServers -join ", "))
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

      $goodServers = $dnsEval | Where-Object { $_.IsDCIP -or $_.AuthoritativeAD -eq $true -or $_.ResolvesADSRV -eq $true }
      if ($goodServers) {
        $goodList = $goodServers | Select-Object -ExpandProperty Server -Unique
        Add-Normal "DNS/Internal" "Domain-joined: AD-capable DNS present" ($goodList -join ", ")
      }

      $dnsEvalTable = if ($dnsEval -and $dnsEval.Count -gt 0) { $dnsEval | Format-Table -AutoSize | Out-String } else { '' }

      $publicServers = $dnsEval | Where-Object { $_.IsPublic }
      if ($publicServers) {
        $pubList = $publicServers | Select-Object -ExpandProperty Server -Unique
        Add-Issue "medium" "DNS/Internal" "Domain-joined: public DNS servers detected ($($pubList -join ', '))." $dnsEvalTable
      }

      $primaryServer = $dnsServers | Select-Object -First 1
      if ($primaryServer) {
        $primaryEval = $dnsEval | Where-Object { $_.Server -eq $primaryServer }
        if ($primaryEval -and $primaryEval.IsPublic) {
          Add-Issue "low" "DNS/Order" "Primary DNS is public; move internal server to the top." ("Primary: $primaryServer`nAll: " + ($dnsServers -join ", "))
        }
      }

      $needCritical = $false
      if ($dnsTestsAvailable -and $dnsTestsAttempted) {
        if (-not $goodServers -or $goodServers.Count -eq 0) {
          $needCritical = $true
        }
      }

      if ($needCritical) {
        $secureOK = $null
        try { $secureOK = Test-ComputerSecureChannel -Verbose:$false -ErrorAction Stop } catch { $secureOK = $null }
        if ($secureOK -eq $false) {
          Add-Issue "medium" "DNS/Internal" "Domain-joined but DNS not internal/AD-capable (device likely off-network/VPN down)." $dnsEvalTable
        } else {
          Add-Issue "critical" "DNS/Internal" "Domain-joined: DNS servers cannot resolve AD SRV records or are public." $dnsEvalTable
        }
      }
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
    $boolVal = Get-BoolFromString $m.Groups['value'].Value
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
    $boolVal = Get-BoolFromString $m.Groups['value'].Value
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
  if ($profiles.Count -gt 0 -and -not ($profiles.Values -contains $false)){
    $profileSummary = ($profiles.GetEnumerator() | ForEach-Object { "{0}: {1}" -f $_.Key, ($(if ($_.Value) {"ON"} else {"OFF"})) }) -join "; "
    Add-Normal "Security/Firewall" "All firewall profiles ON" $profileSummary
  }
}

# services (quick)
if ($raw['services']){
  $crit = @("Dhcp","Dnscache","WlanSvc","LanmanWorkstation","LanmanServer","WinDefend")
  $running = @()
  foreach($svc in $crit){
    if ($raw['services'] -match "^\s*$svc\s+Stopped" ){ Add-Issue "high" "Services" "Core service stopped: $svc" "" }
    elseif ($raw['services'] -match "^\s*$svc\s+Running") { $running += $svc }
  }
  if ($running.Count -gt 0) { Add-Normal "Services" ("Core services running: " + ($running -join ", ")) "" }
}

# services report (detailed)
$servicesReport = [ordered]@{
  Rows           = New-Object System.Collections.Generic.List[pscustomobject]
  SeverityCounts = @{ good = 0; warning = 0; bad = 0; critical = 0; info = 0 }
  DataAvailable  = $false
  Missing        = $false
  ParseError     = $false
}
$coreServicesMap = @{}
$servicesRaw = $raw['core_services']
if ($servicesRaw) {
  $csvLines = [regex]::Split($servicesRaw,'\r?\n') | Where-Object { $_ -and ($_ -notmatch '^=====') }
  $csvText = ($csvLines -join "`n").Trim()
  if ($csvText) {
    try {
      $parsedCore = $csvText | ConvertFrom-Csv
      foreach ($entry in $parsedCore) {
        if (-not $entry) { continue }
        $nameKey = $null
        if ($entry.PSObject.Properties['Name']) { $nameKey = $entry.Name }
        if (-not $nameKey) { continue }
        $trimmedName = $nameKey.Trim()
        if (-not $trimmedName) { continue }
        $coreServicesMap[$trimmedName] = $entry
      }
      if ($coreServicesMap.Count -gt 0) { $servicesReport.DataAvailable = $true }
    } catch {
      $servicesReport.ParseError = $true
    }
  } else {
    $servicesReport.ParseError = $true
  }
} else {
  $servicesReport.Missing = $true
}
if (-not $servicesReport.DataAvailable -and -not $servicesReport.Missing) {
  $servicesReport.ParseError = $true
}
if ($servicesReport.Missing -or $servicesReport.ParseError) {
  Add-Issue 'low' 'Services' 'Core services snapshot not collected' ''
}

$winHttpProxyConfigured = $false
$winHttpProxyEvidence = @()
if ($raw['winhttp_proxy']) {
  $proxyLines = [regex]::Split($raw['winhttp_proxy'],'\r?\n')
  $hasDirect = $proxyLines | Where-Object { $_ -match '(?i)Direct access' }
  if (-not $hasDirect) {
    foreach ($line in $proxyLines) {
      if (-not $line -or -not $line.Trim()) { continue }
      if ($line -match '(?i)Proxy\s+Server') {
        $parts = $line -split '[:=]',2
        if ($parts.Count -ge 2) {
          $value = $parts[1].Trim()
          if ($value -and $value -notmatch '(?i)\b(none|n/a|not set)\b') {
            $winHttpProxyConfigured = $true
            $winHttpProxyEvidence += $line.Trim()
          }
        }
      }
      if ($line -match '(?i)AutoConfig\s+URL') {
        $parts = $line -split '[:=]',2
        if ($parts.Count -ge 2) {
          $value = $parts[1].Trim()
          if ($value -and $value -notmatch '(?i)\b(none|n/a|not set)\b') {
            $winHttpProxyConfigured = $true
            $winHttpProxyEvidence += $line.Trim()
          }
        }
      }
    }
    $winHttpProxyEvidence = $winHttpProxyEvidence | Where-Object { $_ } | Select-Object -Unique
  }
}

$serviceDefinitions = @(
  [pscustomobject]@{ Name='WSearch';             DisplayName='Windows Search';                          Importance='High';     Notes='Outlook search depends on this.' },
  [pscustomobject]@{ Name='Dnscache';            DisplayName='DNS Client';                              Importance='High';     Notes='DNS resolution/cache for all apps.' },
  [pscustomobject]@{ Name='NlaSvc';              DisplayName='Network Location Awareness';             Importance='High';     Notes='network profile changes; VPN/proxy awareness.' },
  [pscustomobject]@{ Name='LanmanWorkstation';   DisplayName='Workstation';                            Importance='High';     Notes='SMB client for shares/printers.' },
  [pscustomobject]@{ Name='RpcSs';               DisplayName='Remote Procedure Call (RPC)';            Importance='Critical'; Notes='core RPC runtime (do not disable).' },
  [pscustomobject]@{ Name='RpcEptMapper';        DisplayName='RPC Endpoint Mapper';                    Importance='Critical'; Notes='RPC endpoint directory.' },
  [pscustomobject]@{ Name='WinHttpAutoProxySvc'; DisplayName='WinHTTP Web Proxy Auto-Discovery';       Importance='Medium';   Notes='WPAD/PAC for system services.' },
  [pscustomobject]@{ Name='BITS';                DisplayName='Background Intelligent Transfer Service';Importance='High';     Notes='background transfers for updates/AV/Office.' },
  [pscustomobject]@{ Name='ClickToRunSvc';       DisplayName='Microsoft Office Click-to-Run Service';  Importance='Medium';   Notes='Office updates and repair.' }
)

$autoBadServices = @('WSearch','Dnscache','NlaSvc','BITS','ClickToRunSvc','LanmanWorkstation')
$manualWarningServices = @('WSearch','BITS','ClickToRunSvc','NlaSvc')
$isWorkstation = ($summary.IsServer -ne $true)

if ($servicesReport.DataAvailable) {
foreach ($definition in $serviceDefinitions) {
  $name = $definition.Name
  $displayName = $definition.DisplayName
  $record = $null
  if ($coreServicesMap.ContainsKey($name)) { $record = $coreServicesMap[$name] }
  if ($record -and $record.PSObject.Properties['DisplayName'] -and $record.DisplayName) {
    $displayName = $record.DisplayName
  }

  if ($record) {
    $rawStatus = if ($record.PSObject.Properties['Status']) { $record.Status } else { $null }
    $rawStartType = if ($record.PSObject.Properties['StartType']) { $record.StartType } else { $null }
    $statusNormalized = Normalize-ServiceStatus $rawStatus
    $startTypeNormalized = Normalize-ServiceStartType $rawStartType
    if (-not $startTypeNormalized -or $startTypeNormalized -eq 'Unknown') {
      if ($record.PSObject.Properties['StartMode']) {
        $startTypeNormalized = Normalize-ServiceStartType $record.StartMode
      }
    }
  } else {
    $statusNormalized = 'NotFound'
    $startTypeNormalized = 'NotFound'
  }

  $statusDisplay = if ($statusNormalized) { $statusNormalized } else { 'Unknown' }
  $displayStartType = if ($startTypeNormalized -and $startTypeNormalized -ne 'NotFound') { $startTypeNormalized } elseif ($statusNormalized -eq 'NotFound') { '—' } else { 'Unknown' }

  $tag = 'info'
  $issueSeverity = $null
  $issueMessage = $null
  $issueEvidence = $null
  $goodMessage = $null

  $isRunning = ($statusNormalized -eq 'Running')
  $isStopped = ($statusNormalized -eq 'Stopped')
  $isPaused = ($statusNormalized -eq 'Paused')
  if ($isPaused) { $isStopped = $true }
  $isNotFound = ($statusNormalized -eq 'NotFound')
  $startTypeAuto = ($startTypeNormalized -match '^Automatic')
  $startTypeManual = ($startTypeNormalized -match '^Manual')
  $startTypeDisabled = ($startTypeNormalized -match '^Disabled')

  $handled = $false

  if ($isRunning) {
    $tag = 'good'
    $goodMessage = "Service: $name running ($displayStartType)"
    $handled = $true
  } elseif ($isNotFound) {
    $tag = 'info'
    $statusDisplay = 'NotFound'
    $displayStartType = '—'
    $serviceLabel = if ($displayName) { $displayName } else { $name }
    $issueSeverity = 'low'
    $issueMessage = "$serviceLabel service not found (may not be installed on this SKU)."
    $handled = $true
  } elseif ($name -eq 'WinHttpAutoProxySvc') {
    if ($winHttpProxyConfigured) {
      $tag = 'warning'
      $issueSeverity = 'medium'
      $issueMessage = 'WinHttpAutoProxySvc stopped — system proxy/PAC configured; automatic proxy discovery will fail.'
      if ($winHttpProxyEvidence -and $winHttpProxyEvidence.Count -gt 0) {
        $issueEvidence = ($winHttpProxyEvidence -join "`n")
      }
    } else {
      $tag = 'good'
      $statusDisplay = 'Trigger Start (OK)'
      if (-not $displayStartType -or $displayStartType -eq 'Unknown' -or $displayStartType -eq 'Manual') {
        $displayStartType = 'Manual (Trigger Start)'
      }
      $goodMessage = "Service: $name running ($displayStartType)"
    }
    $handled = $true
  } elseif ($name -eq 'RpcSs' -and -not $isRunning) {
    $tag = 'critical'
    $issueSeverity = 'critical'
    $issueMessage = 'RpcSs not running — system unstable.'
    $handled = $true
  } elseif ($name -eq 'RpcEptMapper' -and -not $isRunning) {
    $tag = 'critical'
    $issueSeverity = 'critical'
    $issueMessage = 'RpcEptMapper not running — RPC endpoint directory unavailable.'
    $handled = $true
  } elseif ($name -eq 'Dnscache' -and -not $isRunning) {
    $tag = 'critical'
    $issueSeverity = 'critical'
    $issueMessage = 'Dnscache stopped — DNS lookups will fail/intermittent.'
    $handled = $true
  }

  if (-not $handled -and $startTypeDisabled -and ($autoBadServices -contains $name)) {
    $tag = 'bad'
    $issueSeverity = 'high'
    $issueMessage = switch ($name) {
      'WSearch'          { 'WSearch disabled — Windows/Desktop search unavailable.' }
      'NlaSvc'           { 'NlaSvc disabled — network profile detection broken.' }
      'BITS'             { 'BITS disabled — background transfers for updates/AV/Office halted.' }
      'ClickToRunSvc'    { 'ClickToRunSvc disabled — Office updates and repair blocked.' }
      'LanmanWorkstation'{ 'LanmanWorkstation disabled — SMB shares/mapped drives broken.' }
      'Dnscache'         { 'Dnscache disabled — DNS lookups will fail/intermittent.' }
      default            { "$name disabled — service required." }
    }
    $handled = $true
  }

  if (-not $handled -and $isStopped -and $startTypeAuto -and ($autoBadServices -contains $name)) {
    if ($name -eq 'Dnscache') {
      $tag = 'critical'
      $issueSeverity = 'critical'
      $issueMessage = 'Dnscache stopped — DNS lookups will fail/intermittent.'
    } else {
      $tag = 'bad'
      $issueSeverity = 'high'
      $issueMessage = switch ($name) {
        'WSearch'          { 'WSearch stopped — Windows/Desktop search unavailable.' }
        'NlaSvc'           { 'NlaSvc stopped — network profile detection broken.' }
        'BITS'             { 'BITS stopped — background transfers for updates/AV/Office halted.' }
        'ClickToRunSvc'    { 'ClickToRunSvc stopped — Office updates and repair blocked.' }
        'LanmanWorkstation'{ 'LanmanWorkstation stopped — SMB shares/mapped drives broken.' }
        default            { "$name stopped — service required." }
      }
    }
    $handled = $true
  }

  if (-not $handled -and $isStopped -and $startTypeManual -and $isWorkstation -and ($manualWarningServices -contains $name)) {
    $tag = 'warning'
    $issueSeverity = 'medium'
    $issueMessage = switch ($name) {
      'WSearch'       { 'WSearch stopped (manual) — desktop search will not run until started.' }
      'NlaSvc'        { 'NlaSvc stopped (manual) — network profile awareness reduced.' }
      'BITS'          { 'BITS stopped (manual) — background transfers won’t run automatically.' }
      'ClickToRunSvc' { 'ClickToRunSvc stopped (manual) — Office updates may not run.' }
      default         { "$name stopped (manual) — start if required." }
    }
    $handled = $true
  }

  if (-not $handled -and -not $isRunning) {
    $tag = 'info'
    $statusLabel = if ($statusDisplay) { $statusDisplay } else { 'Unknown' }
    $issueSeverity = $null
    $issueMessage = $null
  }

  $servicesReport.SeverityCounts[$tag]++

  $servicesReport.Rows.Add([pscustomobject]@{
    Name        = $name
    DisplayName = $displayName
    Status      = $statusDisplay
    StartType   = $displayStartType
    Importance  = $definition.Importance
    Notes       = $definition.Notes
    Tag         = $tag
  })

  if ($tag -eq 'good' -and $goodMessage) {
    Add-Normal 'Services' $goodMessage
  } elseif ($issueMessage) {
    $sev = switch ($tag) {
      'critical' { 'critical' }
      'bad'      { 'high' }
      'warning'  { 'medium' }
      default    { 'low' }
    }
    if ($tag -eq 'info' -and -not $sev) { $sev = 'low' }
    Add-Issue $sev 'Services' $issueMessage $issueEvidence
  }
}
}


# events quick counters
function Add-EventStats($txt,$name){
  if (-not $txt) { return }
  $err = ([regex]::Matches($txt,'\bError\b','IgnoreCase')).Count
  $warn= ([regex]::Matches($txt,'\bWarning\b','IgnoreCase')).Count
  if ($err -ge 5){ Add-Issue "medium" "Events" "$name log shows many errors ($err in recent sample)." "" }
  elseif ($warn -ge 10){ Add-Issue "low" "Events" "$name log shows many warnings ($warn in recent sample)." "" }
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
    Add-Normal "Scheduled Tasks" "Contains on-demand/unscheduled entries" $scheduleInfo.Value
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
    Add-Normal "OS/Patching" "Hotfixes present" ("Counted KB lines: " + $hfCount)
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

$uptimeSummaryHtml = ''
if ($summary.UptimeStatus) {
  $badgeClass = $summary.UptimeStatus.CssClass
  $badgeLabelHtml = Encode-Html ($summary.UptimeStatus.Label.ToUpper())
  $daysRounded = if ($null -ne $summary.UptimeDays) { [math]::Round($summary.UptimeDays,1) } else { $null }
  $daysHtml = if ($null -ne $daysRounded) { Encode-Html ("{0:N1}" -f $daysRounded) } else { Encode-Html '0.0' }
  $profileHtml = Encode-Html $summary.UptimeStatus.ProfileName
  $rangeHtml = Encode-Html $summary.UptimeStatus.RangeText
  $uptimeSummaryHtml = "<span class='report-badge report-badge--{0}'>{1}</span> {2} days ({3} thresholds: {4})" -f $badgeClass, $badgeLabelHtml, $daysHtml, $profileHtml, $rangeHtml
  if ($summary.IsServer -eq $null) {
    $uptimeSummaryHtml += " <small class='report-note'>{0}</small>" -f (Encode-Html 'Server detection unavailable; workstation thresholds applied.')
  }
} elseif ($summary.LastBoot) {
  $uptimeSummaryHtml = "<small class='report-note'>{0}</small>" -f (Encode-Html 'Last boot captured; uptime could not be determined.')
} else {
  $uptimeSummaryHtml = "<small class='report-note'>{0}</small>" -f (Encode-Html 'Uptime data not captured.')
}

$criticalCount = @($issues | Where-Object { $_.Severity -eq 'critical' }).Count
$highCount = @($issues | Where-Object { $_.Severity -eq 'high' }).Count
$mediumCount = @($issues | Where-Object { $_.Severity -eq 'medium' }).Count
$lowCount = @($issues | Where-Object { $_.Severity -eq 'low' }).Count
$infoCount = @($issues | Where-Object { $_.Severity -eq 'info' }).Count

$deviceNameValue = if ($summary.DeviceName) { $summary.DeviceName } else { 'Unknown' }
$deviceNameHtml = Encode-Html $deviceNameValue

$domainNameValue = if ($summary.Domain) { $summary.Domain.Trim() } else { '' }
$domainNameUpper = if ($domainNameValue) { $domainNameValue.ToUpperInvariant() } else { '' }
$adDetails = @()
if ($summary.DomainJoined -eq $true) {
  if ($domainNameValue -and $domainNameUpper -ne 'WORKGROUP') {
    $adDetails += "Joined to $domainNameValue"
  } else {
    $adDetails += 'Domain joined'
    if ($domainNameValue) { $adDetails += "Reported domain: $domainNameValue" }
  }
} elseif ($summary.DomainJoined -eq $false) {
  if ($domainNameUpper -eq 'WORKGROUP') {
    $adDetails += 'Workgroup / not domain joined'
  } elseif ($domainNameValue) {
    $adDetails += "Not domain joined (reported: $domainNameValue)"
  } else {
    $adDetails += 'Not domain joined'
  }
} else {
  if ($domainNameValue) {
    if ($domainNameUpper -eq 'WORKGROUP') {
      $adDetails += 'Workgroup / not domain joined'
    } else {
      $adDetails += "Join status unknown (reported: $domainNameValue)"
    }
  } else {
    $adDetails += 'Join status unknown'
  }
}
if ($summary.DomainRole) { $adDetails += "Role: $($summary.DomainRole)" }
if ($summary.LogonServer) { $adDetails += "Logon Server: $($summary.LogonServer)" }
$adSummaryHtml = if ($adDetails.Count -gt 0) { ($adDetails | ForEach-Object { Encode-Html $_ }) -join '<br>' } else { Encode-Html 'Unknown' }

$hybridNote = if ($summary.DomainJoined -eq $true -and $summary.AzureAdJoined -eq $true) { 'Hybrid joined (AD + Azure AD)' } else { $null }
$azureDetails = @()
if ($summary.AzureAdJoined -eq $true) {
  $azureDetails += 'Azure AD join: Yes'
} elseif ($summary.AzureAdJoined -eq $false) {
  $azureDetails += 'Azure AD join: No'
} else {
  $azureDetails += 'Azure AD join: Unknown'
}
if ($hybridNote) { $azureDetails += $hybridNote }
if ($summary.AzureAdTenantName) { $azureDetails += "Tenant: $($summary.AzureAdTenantName)" }
if ($summary.AzureAdTenantDomain) { $azureDetails += "Tenant Domain: $($summary.AzureAdTenantDomain)" }
if ($summary.AzureAdTenantId) { $azureDetails += "Tenant ID: $($summary.AzureAdTenantId)" }
if ($summary.AzureAdDeviceId) { $azureDetails += "Device ID: $($summary.AzureAdDeviceId)" }
if ($summary.EnterpriseJoined -eq $true) { $azureDetails += 'Enterprise join: Yes' }
elseif ($summary.EnterpriseJoined -eq $false) { $azureDetails += 'Enterprise join: No' }
if ($summary.WorkplaceJoined -eq $true) { $azureDetails += 'Workplace join: Yes' }
elseif ($summary.WorkplaceJoined -eq $false) { $azureDetails += 'Workplace join: No' }
$azureSummaryHtml = if ($azureDetails.Count -gt 0) { ($azureDetails | ForEach-Object { Encode-Html $_ }) -join '<br>' } else { Encode-Html 'Unknown' }

$folderHtml = Encode-Html $summary.Folder
$osHtml = "$(Encode-Html ($summary.OS)) | $(Encode-Html ($summary.OS_Version))"
$ipv4Html = Encode-Html ($summary.IPv4)
$gatewayHtml = Encode-Html ($summary.Gateway)
$dnsHtml = Encode-Html ($summary.DNS)
$lastBootHtml = Encode-Html ($summary.LastBoot)

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
    <tr><td>Active Directory</td><td>$adSummaryHtml</td></tr>
    <tr><td>Azure AD / Entra</td><td>$azureSummaryHtml</td></tr>
    <tr><td>Folder</td><td>$folderHtml</td></tr>
    <tr><td>OS</td><td>$osHtml</td></tr>
    <tr><td>Windows Server</td><td>$serverDisplayHtml</td></tr>
    <tr><td>Uptime</td><td>$uptimeSummaryHtml</td></tr>
    <tr><td>IPv4</td><td>$ipv4Html</td></tr>
    <tr><td>Gateway</td><td>$gatewayHtml</td></tr>
    <tr><td>DNS</td><td>$dnsHtml</td></tr>
    <tr><td>Last Boot</td><td>$lastBootHtml</td></tr>
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

# Issues
$goodTitle = "What Looks Good ({0})" -f $normals.Count
if ($normals.Count -eq 0){
  $goodContent = '<div class="report-card"><i>No specific positives recorded.</i></div>'
} else {
  $goodCards = ''
  foreach($g in $normals){
    $cardClass = if ($g.CssClass) { $g.CssClass } else { 'good' }
    $badgeText = if ($g.BadgeText) { $g.BadgeText } else { 'GOOD' }
    $badgeHtml = Encode-Html $badgeText
    $areaHtml = Encode-Html $($g.Area)
    $messageHtml = Encode-Html $($g.Message)
    $goodCards += "<div class='report-card report-card--{0}'><span class='report-badge report-badge--{0}'>{1}</span> <b>{2}</b>: {3}" -f $cardClass, $badgeHtml, $areaHtml, $messageHtml
    if ($g.Evidence){ $goodCards += "<pre class='report-pre'>$(Encode-Html $($g.Evidence))</pre>" }
    $goodCards += "</div>"
  }
  $goodContent = $goodCards
}
$goodHtml = New-ReportSection -Title $goodTitle -ContentHtml $goodContent -Open

$issuesTitle = "Detected Issues ({0})" -f $issues.Count
if ($issues.Count -eq 0){
  $issuesContent = "<div class='report-card report-card--good'><span class='report-badge report-badge--good'>GOOD</span> No obvious issues detected from the provided outputs.</div>"
} else {
  $issuesCards = ''
  foreach($i in $issues){
    $cardClass = if ($i.CssClass) { $i.CssClass } else { 'ok' }
    $badgeText = if ($i.BadgeText) { $i.BadgeText } elseif ($i.Severity) { $i.Severity.ToUpperInvariant() } else { 'ISSUE' }
    $badgeHtml = Encode-Html $badgeText
    $areaHtml = Encode-Html $($i.Area)
    $messageHtml = Encode-Html $($i.Message)
    $issuesCards += "<div class='report-card report-card--{0}'><div class='report-badge report-badge--{0}'>{1}</div> <b>{2}</b>: {3}" -f $cardClass, $badgeHtml, $areaHtml, $messageHtml
    if ($i.Evidence){ $issuesCards += "<pre class='report-pre'>$(Encode-Html $i.Evidence)</pre>" }
    $issuesCards += "</div>"
  }
  $issuesContent = $issuesCards
}
$issuesHtml = New-ReportSection -Title $issuesTitle -ContentHtml $issuesContent -Open

# Services section
$servicesTitleCount = if ($servicesReport.DataAvailable) { $servicesReport.Rows.Count } else { 0 }
$servicesTitle = "Services Report ({0})" -f $servicesTitleCount
$servicesSummaryHtml = ''
if ($servicesReport.DataAvailable) {
  $criticalServices = $servicesReport.SeverityCounts['critical']
  $badServices = $servicesReport.SeverityCounts['bad']
  $warningServices = $servicesReport.SeverityCounts['warning']
  $goodServices = $servicesReport.SeverityCounts['good']
  $infoServices = $servicesReport.SeverityCounts['info']
  $needsSummary = ($criticalServices + $badServices + $warningServices) -gt 0
  if ($needsSummary) {
    $summaryParts = @()
    if ($criticalServices -gt 0) { $summaryParts += "Critical $criticalServices" }
    if ($badServices -gt 0) { $summaryParts += "High $badServices" }
    if ($warningServices -gt 0) { $summaryParts += "Medium $warningServices" }
    $summaryParts += "Good $goodServices"
    if ($infoServices -gt 0) { $summaryParts += "Info $infoServices" }
    $servicesSummaryHtml = "<div class='services-report__summary'>{0}</div>" -f (($summaryParts | ForEach-Object { Encode-Html $_ }) -join ' · ')
  }
}

$servicesRowsHtml = ''
if ($servicesReport.DataAvailable -and $servicesReport.Rows.Count -gt 0) {
  foreach ($row in $servicesReport.Rows) {
    $nameHtml = Encode-Html $row.Name
    $displayHtml = Encode-Html $row.DisplayName
    $startTypeDisplay = if ($row.StartType) { $row.StartType } else { '—' }
    $startTypeHtml = Encode-Html $startTypeDisplay
    $importanceHtml = Encode-Html $row.Importance
    $notesHtml = Encode-Html $row.Notes
    $statusText = if ($row.Status) { $row.Status } else { 'Unknown' }
    $statusHtml = Encode-Html $statusText
    $tagName = if ($row.Tag) { $row.Tag } else { 'info' }
    $statusBadge = "<span class='services-report__tag services-report__tag--{0} {0}'>{1}</span>" -f (Encode-Html $tagName), $statusHtml
    $servicesRowsHtml += "<tr><td>$nameHtml</td><td>$displayHtml</td><td>$statusBadge</td><td>$startTypeHtml</td><td>$importanceHtml</td><td>$notesHtml</td></tr>"
  }
} else {
  $servicesRowsHtml = "<tr><td colspan='6' class='services-report__nodata'>(No data)</td></tr>"
}
$servicesTableHtml = "<table class='report-table services-report__table' cellspacing='0' cellpadding='0'><thead><tr><th>Service</th><th>Display name</th><th>Status</th><th>Start type</th><th>Importance</th><th>Notes</th></tr></thead><tbody>$servicesRowsHtml</tbody></table>"
$servicesContent = "<div class='services-report'>$servicesSummaryHtml<div class='report-card services-report__card'>$servicesTableHtml</div></div>"
$servicesHtml = New-ReportSection -Title $servicesTitle -ContentHtml $servicesContent -Open

# Raw extracts (key files)
$rawSections = ''
foreach($key in @('ipconfig','route','nslookup','ping','os_cim','computerinfo','firewall','defender')){
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
$debugHtml = "<details><summary>Debug</summary><div class='report-card'><b>Files map</b><pre class='report-pre'>$(Encode-Html $filesDump)</pre></div><div class='report-card'><b>Raw samples</b><pre class='report-pre'>$(Encode-Html $rawDump)</pre></div></details>"

$tail = "</body></html>"

# Write and return path
$reportName = "DeviceHealth_Report_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$reportPath = Join-Path $InputFolder $reportName
($head + $sumTable + $goodHtml + $issuesHtml + $servicesHtml + $failedHtml + $rawHtml + $debugHtml + $tail) | Out-File -FilePath $reportPath -Encoding UTF8
$reportPath
