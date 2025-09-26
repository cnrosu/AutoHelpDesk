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

. "$PSScriptRoot/Modules/Common.ps1"  # dot-source shared helpers (no functional change)

$ErrorActionPreference = 'SilentlyContinue'

# severity ordering helpers
$script:SeverityOrder = @('low','medium','high','critical')

function Get-SeverityIndex {
  param([string]$Severity)

  if (-not $Severity) { return -1 }

  try {
    $normalized = $Severity.ToLowerInvariant()
  } catch {
    $normalized = [string]$Severity
    if ($normalized) {
      $normalized = $normalized.ToLowerInvariant()
    }
  }

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

# DNS heuristics configuration (override in-line as needed)
[string[]]$AnycastDnsAllow = @()

# ---------- helpers ----------
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

function Get-HealthScores {
    param(
        [hashtable]$Checks
    )
    $scores = @{
        Categories = @{}
        Overall = @{ Achieved = 0.0; Max = 0.0; Percent = $null }
    }
    if (-not $Checks) { return $scores }

    $sevScore = @{ critical=0.0; high=0.25; medium=0.5; low=0.75; info=1.0 }
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
  $secureBootValue = Get-BoolFromString -Value $secureBootState
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
    $fastStartupState = Get-BoolFromString -Value $hiberValueText
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
    $partBool = Get-BoolFromString $partRaw
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
  $tpmPresent = Get-BoolFromString $tpmMap['TpmPresent']
  $tpmReady = Get-BoolFromString $tpmMap['TpmReady']
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
$enableSmb1 = Get-BoolFromString $smbMap['EnableSMB1Protocol']
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
    $cfgEnabled = Test-IsEnabledValue $cfgValue
    $exploitEvidenceLines += "CFG.Enable: $cfgValue"
  }
  if ($exploitData.PSObject.Properties['DEP']) {
    $depValue = $exploitData.DEP.Enable
    $depEnabled = Test-IsEnabledValue $depValue
    $exploitEvidenceLines += "DEP.Enable: $depValue"
  }
  if ($exploitData.PSObject.Properties['ASLR']) {
    $aslrValue = $exploitData.ASLR.Enable
    $aslrEnabled = Test-IsEnabledValue $aslrValue
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
      $dnsTestsAvailableBool = Get-BoolFromString ([string]$dnsTestsAvailableRaw)
    }

    $dnsTestsAttemptedRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'DnsTestsAttempted'
    if ($dnsTestsAttemptedRaw -is [bool]) {
      $dnsTestsAttemptedBool = $dnsTestsAttemptedRaw
    } elseif ($dnsTestsAttemptedRaw -ne $null) {
      $dnsTestsAttemptedBool = Get-BoolFromString ([string]$dnsTestsAttemptedRaw)
    }

    $secureChannelRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'SecureChannelOK'
    if ($secureChannelRaw -is [bool]) {
      $secureChannelState = $secureChannelRaw
    } elseif ($secureChannelRaw -ne $null) {
      $secureChannelState = Get-BoolFromString ([string]$secureChannelRaw)
    }

    $anycastRaw = Get-DictionaryValue -Dictionary $dnsDebug -Key 'AnycastOverrideMatched'
    if ($anycastRaw -is [bool]) {
      $anycastOverride = $anycastRaw
    } elseif ($anycastRaw -ne $null) {
      $anycastOverride = Get-BoolFromString ([string]$anycastRaw)
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
