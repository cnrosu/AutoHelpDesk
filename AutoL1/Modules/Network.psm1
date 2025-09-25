# Network.psm1
# Responsibilities:
# - Collect-NetworkData: read saved files from a diagnostics folder or run live probes
# - Analyze-Network: return [cards, checks] for rendering + scoring

using module ./Common.psm1

$AreaName = 'Network'

function Collect-NetworkData {
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='FromFolder', Mandatory)][string]$InputFolder,
    [Parameter(ParameterSetName='Live')][switch]$Live
  )
  # Hints: ipconfig.txt, route print, netsh wlan show interfaces, DNS test logs
  if ($PSCmdlet.ParameterSetName -eq 'Live') {
    '.*ipconfig.*\.txt$' {{ $result['IpConfig'] = Read-Text $f.FullName; break }}
        '.*route.*print.*\.txt$' {{ $result['RoutePrint'] = Read-Text $f.FullName; break }}
        '.*dns.*diag.*\.txt$' {{ $result['DnsDiag'] = Read-Text $f.FullName; break }}
  } else {
    $result = [ordered]@{}
    $files = Get-AllTextFiles -Root $InputFolder
    foreach ($f in $files) {
      $name = $f.Name.ToLowerInvariant()
      switch -Regex ($name) {
        '.*ipconfig.*\.txt$' {{ $result['IpConfig'] = Read-Text $f.FullName; break }}
        '.*route.*print.*\.txt$' {{ $result['RoutePrint'] = Read-Text $f.FullName; break }}
        '.*dns.*diag.*\.txt$' {{ $result['DnsDiag'] = Read-Text $f.FullName; break }}
        default { }
      }
    }
    return [pscustomobject]$result
  }
}

function Analyze-Network {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,  # shared context if needed across modules
    [Parameter(Mandatory)][psobject]$Data       # output of Collect-NetworkData
  )
  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  
if ($Data.IpConfig -and $Data.IpConfig -match 'Autoconfiguration IPv4 Address\s*:\s*169\.254\.') {
  $cards.Add( New-IssueCard -Area $AreaName -Severity 'high' -Message 'Link-local address detected (likely DHCP failure)' )
  $checks.Add( New-Check -Area $AreaName -Name 'Has valid DHCP lease' -Status 'fail' -Weight 1.2 )
} elseif ($Data.IpConfig) {
  $cards.Add( New-GoodCard -Area $AreaName -Message 'IP configuration present' )
  $checks.Add( New-Check -Area $AreaName -Name 'Has valid DHCP lease' -Status 'pass' -Weight 0.8 )
}
   

  # Example baseline: if we produced nothing, surface a neutral check so scoring doesn't divide by zero
  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( New-GoodCard -Area $AreaName -Message 'Network: No issues detected by baseline heuristics.' )
    $checks.Add( New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1 )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-NetworkData, Analyze-Network
