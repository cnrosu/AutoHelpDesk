# Printing.psm1
# Responsibilities:
# - Collect-PrintingData: read saved files from a diagnostics folder or run live probes
# - Analyze-Printing: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Printing'

function Collect-PrintingData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: Get-Printer, spooler status, stuck queues
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*printers?.*\.txt$' {{ $result['Printers'] = Read-Text $f.FullName; break }}
        '.*spooler.*status.*\.txt$' {{ $result['Spooler'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*printers?.*\.txt$' {{ $result['Printers'] = Read-Text $f.FullName; break }}
        '.*spooler.*status.*\.txt$' {{ $result['Spooler'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-Printing {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-PrintingData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
if ($Data.Spooler -and $Data.Spooler -match 'Stopped') {
  $cards.Add( New-IssueCard -Area $AreaName -Severity 'medium' -Message 'Print Spooler service is stopped' )
  $checks.Add( New-Check -Area $AreaName -Name 'Spooler running' -Status 'fail' -Weight 1.0 )
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'Printing: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-PrintingData, Analyze-Printing
