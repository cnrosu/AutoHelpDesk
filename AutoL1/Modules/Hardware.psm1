# Hardware.psm1
# Responsibilities:
# - Collect-HardwareData: read saved files from a diagnostics folder or run live probes
# - Analyze-Hardware: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Hardware'

function Collect-HardwareData {
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
      'dxdiag' {
        if (-not $result.Contains('DxDiag')) {
          $result['DxDiag'] = Read-Text $f.FullName
        }
        continue
      }
      'disk' {
        if (-not $result.Contains('DiskList')) {
          $result['DiskList'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
}

function Analyze-Hardware {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,
    [Parameter(Mandatory)][psobject]$Data
  )

  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  $diskList = $Data.DiskList
  if ($diskList) {
    if ($diskList -match 'Status\s*:\s*([A-Za-z]+)') {
      $status = $Matches[1]
      if ($status -notin @('OK','Healthy','Good')) {
        $cards.Add( New-IssueCard -Area $AreaName -Severity 'high' -Message ("Disk SMART status indicates: {0}" -f $status) -Evidence ($diskList.Trim()) )
        $checks.Add( New-Check -Area $AreaName -Name 'Disk health' -Status 'fail' -Weight 1.5 -Evidence ($diskList.Trim()) )
      } else {
        $cards.Add( New-GoodCard -Area $AreaName -Message 'Disk health appears OK' -Evidence ($diskList.Trim()) )
        $checks.Add( New-Check -Area $AreaName -Name 'Disk health' -Status 'pass' -Weight 1.0 -Evidence ($diskList.Trim()) )
      }
    }
  }

  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'Hardware: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-HardwareData, Analyze-Hardware
