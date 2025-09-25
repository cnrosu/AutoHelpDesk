# Services.psm1
# Responsibilities:
# - Collect-ServicesData: read saved files from a diagnostics folder or run live probes
# - Analyze-Services: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Services'

function Collect-ServicesData {
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
      'services' {
        if (-not $result.Contains('Services')) {
          $result['Services'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
}

function Analyze-Services {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,
    [Parameter(Mandatory)][psobject]$Data
  )

  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  if ($Data.Services -and $Data.Services -match 'Windows Update\s+Disabled') {
    $cards.Add( New-IssueCard -Area $AreaName -Severity 'medium' -Message 'Windows Update service is disabled' -Evidence ($Data.Services.Trim()) )
    $checks.Add( New-Check -Area $AreaName -Name 'WUSvc running' -Status 'fail' -Weight 1.0 -Evidence ($Data.Services.Trim()) )
  }

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
