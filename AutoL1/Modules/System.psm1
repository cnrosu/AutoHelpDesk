# System.psm1
# Responsibilities:
# - Collect-SystemData: read saved files from a diagnostics folder or run live probes
# - Analyze-System: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'System'

function Collect-SystemData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: systeminfo.txt, msinfo32.nfo (exported to txt), uptime, OS build
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*systeminfo.*\.txt$' {{ $result['SystemInfo'] = Read-Text $f.FullName; break }}
        '.*uptime.*\.txt$' {{ $result['Uptime'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*systeminfo.*\.txt$' {{ $result['SystemInfo'] = Read-Text $f.FullName; break }}
        '.*uptime.*\.txt$' {{ $result['Uptime'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-System {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-SystemData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
# very simple uptime heuristic
$uptime = $Data.Uptime
if ($null -ne $uptime -and $uptime -match '(\d+)\s*day') {
  $days = [int]$Matches[1]
  if ($days -gt 14) {
    $cards.Add( New-IssueCard -Area $AreaName -Severity 'medium' -Message "Uptime is $days days (consider rebooting)" -Evidence ($uptime.Trim()) )
    $checks.Add( New-Check -Area $AreaName -Name 'Uptime < 14 days' -Status 'fail' -Weight 1 -Evidence ($uptime.Trim()) )
  } else {
    $cards.Add( New-GoodCard -Area $AreaName -Message "Healthy uptime ($days days)" )
    $checks.Add( New-Check -Area $AreaName -Name 'Uptime < 14 days' -Status 'pass' -Weight 1 -Evidence ($uptime.Trim()) )
  }
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'System: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-SystemData, Analyze-System
