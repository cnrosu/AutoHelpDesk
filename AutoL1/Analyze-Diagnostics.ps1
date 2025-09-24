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

  diskdrives     = Find-ByContent @('Disk_Drives')               @('Model\s+Serial|Model\s+SerialNumber','Status')
  volumes        = Find-ByContent @('Volumes')                   @('DriveLetter|FileSystem|HealthStatus')
  disks          = Find-ByContent @('Disks')                     @('Number\s*:','OperationalStatus')

  hotfixes       = Find-ByContent @('Hotfixes')                  @('HotFixID','InstalledOn')
  programs       = Find-ByContent @('Programs_Reg')              @('DisplayName\s+DisplayVersion')
  programs32     = Find-ByContent @('Programs_Reg_32')           @('DisplayName\s+DisplayVersion')

  services       = Find-ByContent @('Services')                  @('Status\s+Name|SERVICE_NAME')
  processes      = Find-ByContent @('Processes','tasklist')      @('Image Name\s+PID|====')
  drivers        = Find-ByContent @('Drivers','driverquery')     @('Driver Name|Display Name')

  event_system   = Find-ByContent @('Event_System')              @('Log Name:\s*System|Provider Name=')
  event_app      = Find-ByContent @('Event_Application')         @('Log Name:\s*Application|Provider Name=')

  firewall       = Find-ByContent @('Firewall')                  @('Windows Firewall with Advanced Security|Profile Settings')
  firewall_rules = Find-ByContent @('FirewallRules')             @('Rule Name:|DisplayName\s*:')

  defender       = Find-ByContent @('DefenderStatus')            @('Get-MpComputerStatus|AMProductVersion')
  shares         = Find-ByContent @('NetShares')                 @('Share name|Resource')
  tasks          = Find-ByContent @('ScheduledTasks','tasks')    @('Folder:\s|TaskName')
  whoami         = Find-ByContent @('Whoami')                    @('USER INFORMATION|GROUP INFORMATION')
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
  Write-Verbose ("Issue added => {0}: {1} - {2}" -f $sev.ToUpper(), $area, $logMsg)
  $issues.Add([pscustomobject]@{
    Severity = $sev
    Area     = $area
    Message  = $msg
    Evidence = if($evidence){ $evidence.Substring(0,[Math]::Min(1500,$evidence.Length)) } else { "" }
  })
}

# healthy findings
$normals = New-Object System.Collections.Generic.List[pscustomobject]
function Add-Normal([string]$area,[string]$msg,[string]$evidence=""){
  $normals.Add([pscustomobject]@{
    Area     = $area
    Message  = $msg
    Evidence = if($evidence){ $evidence.Substring(0,[Math]::Min(800,$evidence.Length)) } else { "" }
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
    if ([datetime]::TryParse($summary.LastBoot, [ref]$parsedBoot)) { $bootDt = $parsedBoot }
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
  $sigAge = [regex]::Match($raw['defender'],'AntispywareSignatureAge\s*:\s*(\d+)','IgnoreCase')
  if ($rt.Success -and $rt.Groups[1].Value -ieq "False"){ Add-Issue "high" "Security" "Defender real-time protection is OFF." $raw['defender'] }
  if ($sigAge.Success -and [int]$sigAge.Groups[1].Value -gt 7){ Add-Issue "medium" "Security" "Defender signatures appear old (>7 days)." $sigAge.Value }

  $rtOK = $rt.Success -and $rt.Groups[1].Value -ieq "True"
  if ($rtOK) {
    Add-Normal "Security/Defender" "Real-time protection ON" (([regex]::Split($raw['defender'],'\r?\n') | Select-Object -First 12) -join "`n")
  }
  if ($sigAge.Success -and [int]$sigAge.Groups[1].Value -le 7) {
    Add-Normal "Security/Defender" "Signatures are recent (≤7 days)" $sigAge.Value
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
if ($raw['diskdrives'] -and -not ($raw['diskdrives'] -match 'Pred Fail|Bad|Unknown')) {
  Add-Normal "Storage/SMART" "SMART status shows no failure indicators" (([regex]::Split($raw['diskdrives'],'\r?\n') | Select-Object -First 12) -join "`n")
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

$reportName = "AutoL1_Report_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$reportPath = Join-Path $InputFolder $reportName

# CSS: literal here-string (no expansion); closing '@ on column 1
$css = @'
<style>
body{font-family:Segoe UI,Arial;margin:16px}
h1,h2{color:#0b63a6}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;border:1px solid #ccc;margin-right:6px}
.critical{background:#ffebee;border-color:#d32f2f}
.high{background:#fff3e0;border-color:#ef6c00}
.medium{background:#fffde7;border-color:#f9a825}
.low{background:#e8f5e9;border-color:#43a047}
.info{background:#e3f2fd;border-color:#1e88e5}
.uptime-good{background:#e8f5e9;border-color:#43a047;color:#1b5e20}
.uptime-warning{background:#fff8e1;border-color:#fbc02d;color:#8c6d1f}
.uptime-bad{background:#ffebee;border-color:#ef5350;color:#b71c1c}
.uptime-critical{background:#ffebee;border-color:#c62828;color:#8e0000}
.ok{background:#f1f8e9;border-color:#66bb6a;color:#2e7d32}
.card{border:1px solid #ddd;border-radius:8px;padding:12px;margin-bottom:12px}
pre{background:#f6f6f6;border-left:4px solid #ddd;padding:8px;overflow:auto;max-height:280px}
table.kv td{padding:6px 10px;border:1px solid #ddd}
small.note{color:#666}
table.list td, table.list th{padding:6px 10px;border:1px solid #ddd}
</style>
'@

$head = '<!doctype html><html><head><meta charset="utf-8"><title>Auto L1 Device Report</title>' + $css + '</head><body>'

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
  $uptimeSummaryHtml = "<span class='badge {0}'>{1}</span> {2} days ({3} thresholds: {4})" -f $badgeClass, $badgeLabelHtml, $daysHtml, $profileHtml, $rangeHtml
  if ($summary.IsServer -eq $null) {
    $uptimeSummaryHtml += " <small class='note'>{0}</small>" -f (Encode-Html 'Server detection unavailable; workstation thresholds applied.')
  }
} elseif ($summary.LastBoot) {
  $uptimeSummaryHtml = "<small class='note'>{0}</small>" -f (Encode-Html 'Last boot captured; uptime could not be determined.')
} else {
  $uptimeSummaryHtml = "<small class='note'>{0}</small>" -f (Encode-Html 'Uptime data not captured.')
}

$sumTable = @"
<h1>Auto L1 Device Report</h1>
<div class='card'>
  <div>
    <span class='badge'>Score: <b>$score/100</b></span>
    <span class='badge'>Critical: $(@($issues | Where-Object {$_.Severity -eq 'critical'}).Count)</span>
    <span class='badge'>High: $(@($issues | Where-Object {$_.Severity -eq 'high'}).Count)</span>
    <span class='badge'>Medium: $(@($issues | Where-Object {$_.Severity -eq 'medium'}).Count)</span>
    <span class='badge'>Low: $(@($issues | Where-Object {$_.Severity -eq 'low'}).Count)</span>
    <span class='badge'>Info: $(@($issues | Where-Object {$_.Severity -eq 'info'}).Count)</span>
  </div>
  <table class='kv' cellspacing='0' cellpadding='0' style='margin-top:10px'>
    <tr><td>Folder</td><td>$(Encode-Html $summary.Folder)</td></tr>
    <tr><td>OS</td><td>$(Encode-Html ($summary.OS)) | $(Encode-Html ($summary.OS_Version))</td></tr>
    <tr><td>Windows Server</td><td>$serverDisplayHtml</td></tr>
    <tr><td>Uptime</td><td>$uptimeSummaryHtml</td></tr>
    <tr><td>IPv4</td><td>$(Encode-Html ($summary.IPv4))</td></tr>
    <tr><td>Gateway</td><td>$(Encode-Html ($summary.Gateway))</td></tr>
    <tr><td>DNS</td><td>$(Encode-Html ($summary.DNS))</td></tr>
    <tr><td>Last Boot</td><td>$(Encode-Html ($summary.LastBoot))</td></tr>
  </table>
  <small class='note'>Score is heuristic. Triage Critical/High items first.</small>
</div>
"@

# Found files table
$foundRows = foreach($k in $files.Keys){
  [pscustomobject]@{ Key=$k; File= if($files[$k]){ (Resolve-Path $files[$k]).Path } else { "(not found)" } }
}
$foundHtml = "<h2>Found Files</h2><div class='card'><table class='list' cellspacing='0' cellpadding='0'><tr><th>Key</th><th>File</th></tr>"
foreach($r in $foundRows){ $foundHtml += "<tr><td>$(Encode-Html $($r.Key))</td><td>$(Encode-Html $($r.File))</td></tr>" }
$foundHtml += "</table></div>"

# Issues
$goodHtml = "<h2>What Looks Good</h2>"
if ($normals.Count -eq 0){
  $goodHtml += '<div class="card"><i>No specific positives recorded.</i></div>'
} else {
  foreach($g in $normals){
    $goodHtml += "<div class='card'><span class='badge ok'>OK</span> <b>$(Encode-Html $($g.Area))</b>: $(Encode-Html $($g.Message))"
    if ($g.Evidence){ $goodHtml += "<pre>$(Encode-Html $($g.Evidence))</pre>" }
    $goodHtml += "</div>"
  }
}

$issuesHtml = "<h2>Detected Issues</h2>"
if ($issues.Count -eq 0){
  $issuesHtml += '<div class="card">No obvious issues detected from the provided outputs.</div>'
} else {
  foreach($i in $issues){
    $issuesHtml += "<div class='card'><div class='badge $($i.Severity)'>$($i.Severity.ToUpper())</div> <b>$(Encode-Html $($i.Area))</b>: $(Encode-Html $($i.Message))"
    if ($i.Evidence){ $issuesHtml += "<pre>$(Encode-Html $i.Evidence)</pre>" }
    $issuesHtml += "</div>"
  }
}

# Raw extracts (key files)
$rawHtml = "<h2>Raw (key excerpts)</h2>"
foreach($key in @('ipconfig','route','nslookup','ping','os_cim','computerinfo','firewall','defender')){
  if ($files[$key]) {
    $content = Read-Text $files[$key]
    $rawHtml += "<div class='card'><b>$(Encode-Html ([IO.Path]::GetFileName($files[$key])))</b><pre>$(Encode-Html $content)</pre></div>"
  }
}

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
$debugHtml = "<details><summary>Debug</summary><div class='card'><b>Files map</b><pre>$(Encode-Html $filesDump)</pre></div><div class='card'><b>Raw samples</b><pre>$(Encode-Html $rawDump)</pre></div></details>"

$tail = "</body></html>"

# Write and return path
$reportName = "AutoL1_Report_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$reportPath = Join-Path $InputFolder $reportName
($head + $sumTable + $foundHtml + $goodHtml + $issuesHtml + $rawHtml + $debugHtml + $tail) | Out-File -FilePath $reportPath -Encoding UTF8
$reportPath
