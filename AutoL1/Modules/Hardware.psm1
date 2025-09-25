# Hardware.psm1
# Responsibilities:
# - Collect-HardwareData: read saved files from a diagnostics folder or run live probes
# - Analyze-Hardware: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Hardware'

function Collect-HardwareData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: dxdiag.txt, wmic/cim disk lists, memory, CPU
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*dxdiag.*\.txt$' {{ $result['DxDiag'] = Read-Text $f.FullName; break }}
        '.*disk.*list.*\.txt$' {{ $result['DiskList'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*dxdiag.*\.txt$' {{ $result['DxDiag'] = Read-Text $f.FullName; break }}
        '.*disk.*list.*\.txt$' {{ $result['DiskList'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-Hardware {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-HardwareData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
if ($Data.DiskList -and $Data.DiskList -match 'Status\s*:\s*(\w+)') {
  $status = $Matches[1]
  if ($status -notin @('OK','Healthy','Good')) {
    $cards.Add( New-IssueCard -Area $AreaName -Severity 'high' -Message "Disk SMART status indicates: $status" )
    $checks.Add( New-Check -Area $AreaName -Name 'Disk health' -Status 'fail' -Weight 1.5 )
  } else {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'Disk health appears OK' )
    $checks.Add( New-Check -Area $AreaName -Name 'Disk health' -Status 'pass' -Weight 1.0 )
  }
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
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
