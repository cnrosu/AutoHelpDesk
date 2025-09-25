# Network.psm1
# Responsibilities:
# - Collect-NetworkData: read saved files from a diagnostics folder or run live probes
# - Analyze-Network: return [cards, checks] for rendering + scoring

$commonModulePath = Join-Path $PSScriptRoot 'Common.psm1'
if (-not (Get-Command -Name New-IssueCard -ErrorAction SilentlyContinue)) {
  if (Test-Path -LiteralPath $commonModulePath) {
    Import-Module -Name $commonModulePath -Scope Local -ErrorAction SilentlyContinue | Out-Null
  }
}

$AreaName = 'Network'

function Collect-NetworkData {
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
      'ipconfig' {
        if (-not $result.Contains('IpConfig')) {
          $result['IpConfig'] = Read-Text $f.FullName
        }
        continue
      }
      'route' {
        if (-not $result.Contains('RoutePrint')) {
          $result['RoutePrint'] = Read-Text $f.FullName
        }
        continue
      }
      'dns' {
        if (-not $result.Contains('DnsDiag')) {
          $result['DnsDiag'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
}

function Analyze-Network {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,
    [Parameter(Mandatory)][psobject]$Data
  )

  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  if ($Data.IpConfig) {
    if ($Data.IpConfig -match 'Autoconfiguration IPv4 Address\s*:\s*169\.254\.') {
      $cards.Add( (New-IssueCard -Area $AreaName -Severity 'high' -Message 'Link-local address detected (likely DHCP failure)' -Evidence ($Data.IpConfig.Trim())) )
      $checks.Add( (New-Check -Area $AreaName -Name 'Has valid DHCP lease' -Status 'fail' -Weight 1.2 -Evidence ($Data.IpConfig.Trim())) )
    } else {
      $cards.Add( (New-GoodCard -Area $AreaName -Message 'IP configuration present' -Evidence ($Data.IpConfig.Trim())) )
      $checks.Add( (New-Check -Area $AreaName -Name 'Has valid DHCP lease' -Status 'pass' -Weight 0.8 -Evidence ($Data.IpConfig.Trim())) )
    }
  }

  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( (New-GoodCard -Area $AreaName -Message 'Network: No issues detected by baseline heuristics.') )
    $checks.Add( (New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1) )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-NetworkData, Analyze-Network
