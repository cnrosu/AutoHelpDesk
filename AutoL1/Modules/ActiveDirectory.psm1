# ActiveDirectory.psm1
# Responsibilities:
# - Collect-ActiveDirectoryData: read saved files from a diagnostics folder or run live probes
# - Analyze-ActiveDirectory: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'ActiveDirectory'

function Collect-ActiveDirectoryData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: nltest /dsgetdc, whoami /upn, Test-ComputerSecureChannel, time sync
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*nltest.*dsgetdc.*\.txt$' {{ $result['DsGetDc'] = Read-Text $f.FullName; break }}
        '.*securechannel.*\.txt$' {{ $result['SecureChannel'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*nltest.*dsgetdc.*\.txt$' {{ $result['DsGetDc'] = Read-Text $f.FullName; break }}
        '.*securechannel.*\.txt$' {{ $result['SecureChannel'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-ActiveDirectory {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-ActiveDirectoryData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
if ($Data.SecureChannel -and $Data.SecureChannel -match 'False') {
  $cards.Add( New-IssueCard -Area $AreaName -Severity 'high' -Message 'Computer secure channel to domain is broken' )
  $checks.Add( New-Check -Area $AreaName -Name 'Secure channel healthy' -Status 'fail' -Weight 1.5 )
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'ActiveDirectory: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-ActiveDirectoryData, Analyze-ActiveDirectory
