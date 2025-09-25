# System.psm1
# Responsibilities:
# - Collect-SystemData: read saved files from a diagnostics folder or run live probes
# - Analyze-System: return [cards, checks] for rendering + scoring

$commonModulePath = Join-Path $PSScriptRoot 'Common.psm1'
if (-not (Get-Command -Name New-IssueCard -ErrorAction SilentlyContinue)) {
  if (Test-Path -LiteralPath $commonModulePath) {
    Import-Module -Name $commonModulePath -Scope Local -ErrorAction SilentlyContinue | Out-Null
  }
}

$AreaName = 'System'

function Collect-SystemData {
  [CmdletBinding(DefaultParameterSetName='FromFolder')]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )

  $result = [ordered]@{}

  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    return [pscustomobject]$result
  }

  if (-not (Test-Path -LiteralPath $InputFolder)) {
    return [pscustomobject]$result
  }

  $files = Get-AllTextFiles -Root $InputFolder
  foreach ($f in $files) {
    $name = $f.Name.ToLowerInvariant()
    switch -Regex ($name) {
      'systeminfo' {
        if (-not $result.Contains('SystemInfo')) {
          $result['SystemInfo'] = Read-Text $f.FullName
        }
        continue
      }
      'uptime' {
        if (-not $result.Contains('Uptime')) {
          $result['Uptime'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
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
  if ($null -ne $uptime) {
    $uptimeText = $uptime.Trim()
    if ($uptimeText -match '(\d+)\s*day') {
      $days = [int]$Matches[1]
      if ($days -gt 14) {
        $cards.Add( (New-IssueCard -Area $AreaName -Severity 'medium' -Message ("Uptime is {0} days (consider rebooting)" -f $days) -Evidence $uptimeText) )
        $checks.Add( (New-Check -Area $AreaName -Name 'Uptime < 14 days' -Status 'fail' -Weight 1 -Evidence $uptimeText) )
      } else {
        $cards.Add( (New-GoodCard -Area $AreaName -Message ("Healthy uptime ({0} days)" -f $days) -Evidence $uptimeText) )
        $checks.Add( (New-Check -Area $AreaName -Name 'Uptime < 14 days' -Status 'pass' -Weight 1 -Evidence $uptimeText) )
      }
    }
  }

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( (New-GoodCard -Area $AreaName -Message 'System: No issues detected by baseline heuristics.') )
    $checks.Add( (New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1) )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-SystemData, Analyze-System
