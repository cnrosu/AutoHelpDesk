# Office.psm1
# Responsibilities:
# - Collect-OfficeData: read saved files from a diagnostics folder or run live probes
# - Analyze-Office: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Office'

function Collect-OfficeData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: Office/Outlook logs, licensing status, build channel
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*office.*licen.*\.txt$' {{ $result['OfficeLicense'] = Read-Text $f.FullName; break }}
        '.*outlook.*connectivity.*\.txt$' {{ $result['Outlook'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*office.*licen.*\.txt$' {{ $result['OfficeLicense'] = Read-Text $f.FullName; break }}
        '.*outlook.*connectivity.*\.txt$' {{ $result['Outlook'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-Office {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-OfficeData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
if ($Data.OfficeLicense -and $Data.OfficeLicense -match 'Licensed:\s*No') {
  $cards.Add( New-IssueCard -Area $AreaName -Severity 'high' -Message 'Office is not licensed' )
  $checks.Add( New-Check -Area $AreaName -Name 'Office licensed' -Status 'fail' -Weight 1.3 )
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
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
