# Security.psm1
# Responsibilities:
# - Collect-SecurityData: read saved files from a diagnostics folder or run live probes
# - Analyze-Security: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Security'

function Collect-SecurityData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: Defender summary, BitLocker status, Secure Boot, SmartScreen
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*bitlocker.*status.*\.txt$' {{ $result['BitLocker'] = Read-Text $f.FullName; break }}
        '.*defender.*summary.*\.txt$' {{ $result['Defender'] = Read-Text $f.FullName; break }}
        '.*secure.*boot.*\.txt$' {{ $result['SecureBoot'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*bitlocker.*status.*\.txt$' {{ $result['BitLocker'] = Read-Text $f.FullName; break }}
        '.*defender.*summary.*\.txt$' {{ $result['Defender'] = Read-Text $f.FullName; break }}
        '.*secure.*boot.*\.txt$' {{ $result['SecureBoot'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-Security {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-SecurityData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
if ($Data.BitLocker -and $Data.BitLocker -match 'Protection Status\s*:\s*Protection Off') {
  $cards.Add( New-IssueCard -Area $AreaName -Severity 'critical' -Message 'BitLocker is OFF' )
  $checks.Add( New-Check -Area $AreaName -Name 'BitLocker enabled' -Status 'fail' -Weight 2.0 )
}
if ($Data.SecureBoot -and $Data.SecureBoot -match 'Enabled\s*:\s*False') {
  $cards.Add( New-IssueCard -Area $AreaName -Severity 'high' -Message 'Secure Boot is disabled' )
  $checks.Add( New-Check -Area $AreaName -Name 'Secure Boot enabled' -Status 'warn' -Weight 1.2 )
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'Security: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-SecurityData, Analyze-Security
