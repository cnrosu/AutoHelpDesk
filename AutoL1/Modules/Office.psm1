# Office.psm1
# Responsibilities:
# - Collect-OfficeData: read saved files from a diagnostics folder or run live probes
# - Analyze-Office: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Office'

function Collect-OfficeData {
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
      'office.*licen' {
        if (-not $result.Contains('OfficeLicense')) {
          $result['OfficeLicense'] = Read-Text $f.FullName
        }
        continue
      }
      'outlook.*connectivity' {
        if (-not $result.Contains('Outlook')) {
          $result['Outlook'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
}

function Analyze-Office {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,
    [Parameter(Mandatory)][psobject]$Data
  )

  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  if ($Data.OfficeLicense -and $Data.OfficeLicense -match 'Licensed\s*:\s*No') {
    $cards.Add( New-IssueCard -Area $AreaName -Severity 'high' -Message 'Office is not licensed' -Evidence ($Data.OfficeLicense.Trim()) )
    $checks.Add( New-Check -Area $AreaName -Name 'Office licensed' -Status 'fail' -Weight 1.3 -Evidence ($Data.OfficeLicense.Trim()) )
  }

  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'Office: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-OfficeData, Analyze-Office
