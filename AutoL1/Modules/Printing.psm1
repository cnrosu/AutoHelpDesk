# Printing.psm1
# Responsibilities:
# - Collect-PrintingData: read saved files from a diagnostics folder or run live probes
# - Analyze-Printing: return [cards, checks] for rendering + scoring

$commonModulePath = Join-Path $PSScriptRoot 'Common.psm1'
if (-not (Get-Command -Name New-IssueCard -ErrorAction SilentlyContinue)) {
  if (Test-Path -LiteralPath $commonModulePath) {
    Import-Module -Name $commonModulePath -Scope Local -ErrorAction SilentlyContinue | Out-Null
  }
}

$AreaName = 'Printing'

function Collect-PrintingData {
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
      'printer' {
        if (-not $result.Contains('Printers')) {
          $result['Printers'] = Read-Text $f.FullName
        }
        continue
      }
      'spooler' {
        if (-not $result.Contains('Spooler')) {
          $result['Spooler'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
}

function Analyze-Printing {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,
    [Parameter(Mandatory)][psobject]$Data
  )

  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  if ($Data.Spooler -and $Data.Spooler -match 'Stopped') {
    $cards.Add( (New-IssueCard -Area $AreaName -Severity 'medium' -Message 'Print Spooler service is stopped' -Evidence ($Data.Spooler.Trim())) )
    $checks.Add( (New-Check -Area $AreaName -Name 'Spooler running' -Status 'fail' -Weight 1.0 -Evidence ($Data.Spooler.Trim())) )
  }

  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( (New-GoodCard -Area $AreaName -Message 'Printing: No issues detected by baseline heuristics.') )
    $checks.Add( (New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1) )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-PrintingData, Analyze-Printing
