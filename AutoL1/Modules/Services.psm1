# Services.psm1
# Responsibilities:
# - Collect-ServicesData: read saved files from a diagnostics folder or run live probes
# - Analyze-Services: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Services'

function Collect-ServicesData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: services.txt snapshot (name, status, start type), startup impact
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*services.*snapshot.*\.txt$' {{ $result['Services'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*services.*snapshot.*\.txt$' {{ $result['Services'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-Services {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-ServicesData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
if ($Data.Services -and $Data.Services -match 'Windows Update\s+Disabled') {
  $cards.Add( New-IssueCard -Area $AreaName -Severity 'medium' -Message 'Windows Update service is disabled' )
  $checks.Add( New-Check -Area $AreaName -Name 'WUSvc running' -Status 'fail' -Weight 1.0 )
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'Services: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-ServicesData, Analyze-Services
