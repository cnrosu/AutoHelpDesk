# Security.psm1
# Responsibilities:
# - Collect-SecurityData: read saved files from a diagnostics folder or run live probes
# - Analyze-Security: return [cards, checks] for rendering + scoring

$commonModulePath = Join-Path $PSScriptRoot 'Common.psm1'
if (-not (Get-Command -Name New-IssueCard -ErrorAction SilentlyContinue)) {
  if (Test-Path -LiteralPath $commonModulePath) {
    Import-Module -Name $commonModulePath -Scope Local -ErrorAction SilentlyContinue | Out-Null
  }
}

$AreaName = 'Security'

function Collect-SecurityData {
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
      'bitlocker' {
        if (-not $result.Contains('BitLocker')) {
          $result['BitLocker'] = Read-Text $f.FullName
        }
        continue
      }
      'defender' {
        if (-not $result.Contains('Defender')) {
          $result['Defender'] = Read-Text $f.FullName
        }
        continue
      }
      'secure.*boot' {
        if (-not $result.Contains('SecureBoot')) {
          $result['SecureBoot'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
}

function Analyze-Security {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,
    [Parameter(Mandatory)][psobject]$Data
  )

  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  if ($Data.BitLocker -and $Data.BitLocker -match 'Protection Status\s*:\s*Protection Off') {
    $cards.Add( (New-IssueCard -Area $AreaName -Severity 'critical' -Message 'BitLocker is OFF' -Evidence ($Data.BitLocker.Trim())) )
    $checks.Add( (New-Check -Area $AreaName -Name 'BitLocker enabled' -Status 'fail' -Weight 2.0 -Evidence ($Data.BitLocker.Trim())) )
  }

  if ($Data.SecureBoot -and $Data.SecureBoot -match 'Enabled\s*:\s*False') {
    $cards.Add( (New-IssueCard -Area $AreaName -Severity 'high' -Message 'Secure Boot is disabled' -Evidence ($Data.SecureBoot.Trim())) )
    $checks.Add( (New-Check -Area $AreaName -Name 'Secure Boot enabled' -Status 'warn' -Weight 1.2 -Evidence ($Data.SecureBoot.Trim())) )
  }

  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( (New-GoodCard -Area $AreaName -Message 'Security: No issues detected by baseline heuristics.') )
    $checks.Add( (New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1) )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-SecurityData, Analyze-Security
