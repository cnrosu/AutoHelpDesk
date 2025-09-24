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

# read contents
$raw = @{}
foreach($k in $files.Keys){ $raw[$k] = if($files[$k]){ Read-Text $files[$k] } else { "" } }

# issues list
$issues = New-Object System.Collections.Generic.List[pscustomobject]
function Add-Issue([string]$sev,[string]$area,[string]$msg,[string]$evidence=""){
  $issues.Add([pscustomobject]@{
    Severity = $sev
    Area     = $area
    Message  = $msg
    Evidence = if($evidence){ $evidence.Substring(0,[Math]::Min(1500,$evidence.Length)) } else { "" }
  })
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

# ipconfig
if ($raw['ipconfig']){
  $ipv4s = [regex]::Matches($raw['ipconfig'],'IPv4 Address[^\d]*([\d\.]+)') | ForEach-Object { $_.Groups[1].Value }
  if (-not $ipv4s){ $ipv4s = [regex]::Matches($raw['ipconfig'],'IP(v4)? Address[^\d]*([\d\.]+)') | ForEach-Object { $_.Groups[2].Value } }
  $gws   = [regex]::Matches($raw['ipconfig'],'Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)') | ForEach-Object { $_.Groups[1].Value }
  $dns   = [regex]::Matches($raw['ipconfig'],'DNS Servers[^\d]*(\d+\.\d+\.\d+\.\d+)') | ForEach-Object { $_.Groups[1].Value }

  $summary.IPv4    = ($ipv4s | Select-Object -Unique) -join ", "
  $summary.Gateway = ($gws   | Select-Object -Unique) -join ", "
  $summary.DNS     = ($dns   | Select-Object -Unique) -join ", "

  if (-not $ipv4s){ Add-Issue "critical" "Network" "No IPv4 address detected (driver/DHCP/link)." $raw['ipconfig'] }
  if ($ipv4s | Where-Object { $_ -like "169.254.*" }){ Add-Issue "critical" "Network" "APIPA address 169.254.x.x → DHCP/link issue." ($ipv4s -join ", ") }
  if (-not $gws){ Add-Issue "high" "Network" "No default gateway — internet likely broken." "" }

  $public = @("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112")
  if ($dns | Where-Object { $public -contains $_ }) {
    Add-Issue "medium" "DNS" "Public DNS in use — fine at home; breaks AD in corp environments." ($dns -join ", ")
  }
}

# route
if ($raw['route']){
  if (-not ([regex]::IsMatch($raw['route'],'\s0\.0\.0\.0\s+0\.0\.0\.0\s+\d+\.\d+\.\d+\.\d+'))) {
    Add-Issue "high" "Network" "Routing table lacks a default route (0.0.0.0/0)." $raw['route']
  }
}

# nslookup / ping / tracert
if ($raw['nslookup'] -and ($raw['nslookup'] -match "Request timed out|Non-existent domain")){
  Add-Issue "medium" "DNS" "nslookup shows timeouts or NXDOMAIN." $raw['nslookup']
}
if ($raw['ping'] -and ($raw['ping'] -match "Received\s*=\s*0")){
  Add-Issue "high" "Network" "Ping to 8.8.8.8 failed (0 received)." $raw['ping']
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
} else {
  Add-Issue "info" "Security" "Defender status not captured (3rd-party AV or cmdlet unavailable)." ""
}

# firewall profiles
if ($raw['firewall']){
  $blocks = ($raw['firewall'] -split "Profile Settings:")
  foreach($b in $blocks){
    if ($b -match 'State\s*OFF'){ 
      $nameMatch = [regex]::Match($b,'^(.*?)[\r\n]') 
      $name = if($nameMatch.Success){ $nameMatch.Groups[1].Value.Trim() } else { "Profile" }
      Add-Issue "medium" "Firewall" "$name profile is OFF." $b
    }
  }
}

# services (quick)
if ($raw['services']){
  $crit = @("Dhcp","Dnscache","WlanSvc","LanmanWorkstation","LanmanServer","WinDefend")
  foreach($svc in $crit){
    if ($raw['services'] -match "^\s*$svc\s+Stopped" ){ Add-Issue "high" "Services" "Core service stopped: $svc" "" }
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

# ---------- scoring ----------
$weights = @{ critical=10; high=6; medium=3; low=1; info=0 }
$penalty = 0
foreach($i in $issues){ $penalty += ($weights[$i.Severity]) }
$score = [Math]::Max(0, 100 - [Math]::Min($penalty,80))

# ---------- HTML ----------
function H([string]$s){ return [System.Web.HttpUtility]::HtmlEncode($s) }

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
.card{border:1px solid #ddd;border-radius:8px;padding:12px;margin-bottom:12px}
pre{background:#f6f6f6;border-left:4px solid #ddd;padding:8px;overflow:auto;max-height:280px}
table.kv td{padding:6px 10px;border:1px solid #ddd}
small.note{color:#666}
table.list td, table.list th{padding:6px 10px;border:1px solid #ddd}
</style>
'@

$head = '<!doctype html><html><head><meta charset="utf-8"><title>Auto L1 Device Report</title>' + $css + '</head><body>'

# Expanding here-string for summary (variables expand); closing "@ at column 1
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
    <tr><td>Folder</td><td>$(H $summary.Folder)</td></tr>
    <tr><td>OS</td><td>$(H ($summary.OS)) | $(H ($summary.OS_Version))</td></tr>
    <tr><td>IPv4</td><td>$(H ($summary.IPv4))</td></tr>
    <tr><td>Gateway</td><td>$(H ($summary.Gateway))</td></tr>
    <tr><td>DNS</td><td>$(H ($summary.DNS))</td></tr>
    <tr><td>Last Boot</td><td>$(H ($summary.LastBoot))</td></tr>
  </table>
  <small class='note'>Score is heuristic. Triage Critical/High items first.</small>
</div>
"@

# Found files table
$foundRows = foreach($k in $files.Keys){
  [pscustomobject]@{ Key=$k; File= if($files[$k]){ (Resolve-Path $files[$k]).Path } else { "(not found)" } }
}
$foundHtml = "<h2>Found Files</h2><div class='card'><table class='list' cellspacing='0' cellpadding='0'><tr><th>Key</th><th>File</th></tr>"
foreach($r in $foundRows){ $foundHtml += "<tr><td>$(H $($r.Key))</td><td>$(H $($r.File))</td></tr>" }
$foundHtml += "</table></div>"

# Issues
$issuesHtml = "<h2>Detected Issues</h2>"
if ($issues.Count -eq 0){
  $issuesHtml += '<div class="card">No obvious issues detected from the provided outputs.</div>'
} else {
  foreach($i in $issues){
    $issuesHtml += "<div class='card'><div class='badge $($i.Severity)'>$($i.Severity.ToUpper())</div> <b>$(H $($i.Area))</b>: $(H $($i.Message))"
    if ($i.Evidence){ $issuesHtml += "<pre>$([System.Web.HttpUtility]::HtmlEncode($i.Evidence))</pre>" }
    $issuesHtml += "</div>"
  }
}

# Raw extracts (key files)
$rawHtml = "<h2>Raw (key excerpts)</h2>"
foreach($key in @('ipconfig','route','nslookup','ping','os_cim','computerinfo','firewall','defender')){
  if ($files[$key]) {
    $content = Read-Text $files[$key]
    $rawHtml += "<div class='card'><b>$(H ([IO.Path]::GetFileName($files[$key])))</b><pre>$([System.Web.HttpUtility]::HtmlEncode($content))</pre></div>"
  }
}

$tail = "</body></html>"

# Write and return path
$reportName = "AutoL1_Report_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$reportPath = Join-Path $InputFolder $reportName
($head + $sumTable + $foundHtml + $issuesHtml + $rawHtml + $tail) | Out-File -FilePath $reportPath -Encoding UTF8
$reportPath
