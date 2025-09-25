# ActiveDirectory.psm1
# Responsibilities:
# - Collect-ActiveDirectoryData: read saved files from a diagnostics folder or run live probes
# - Analyze-ActiveDirectory: return [cards, checks] for rendering + scoring

$commonModulePath = Join-Path $PSScriptRoot 'Common.psm1'
if (-not (Get-Command -Name New-IssueCard -ErrorAction SilentlyContinue)) {
  if (Test-Path -LiteralPath $commonModulePath) {
    Import-Module -Name $commonModulePath -Scope Local -ErrorAction SilentlyContinue | Out-Null
  }
}

$AreaName = 'ActiveDirectory'

function Collect-ActiveDirectoryData {
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
      'nltest.*dsgetdc' {
        if (-not $result.Contains('DsGetDc')) {
          $result['DsGetDc'] = Read-Text $f.FullName
        }
        continue
      }
      'securechannel' {
        if (-not $result.Contains('SecureChannel')) {
          $result['SecureChannel'] = Read-Text $f.FullName
        }
        continue
      }
    }
  }

  return [pscustomobject]$result
}

function Analyze-ActiveDirectory {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Context,
    [Parameter(Mandatory)][psobject]$Data
  )

  $cards  = New-Object System.Collections.Generic.List[object]
  $checks = New-Object System.Collections.Generic.List[object]

  if ($Data.SecureChannel -and $Data.SecureChannel -match 'False') {
    $cards.Add( (New-IssueCard -Area $AreaName -Severity 'high' -Message 'Computer secure channel to domain is broken' -Evidence ($Data.SecureChannel.Trim())) )
    $checks.Add( (New-Check -Area $AreaName -Name 'Secure channel healthy' -Status 'fail' -Weight 1.5 -Evidence ($Data.SecureChannel.Trim())) )
  }

  if ($cards.Count -eq 0 -and $checks.Count -eq 0) {
    $cards.Add( (New-GoodCard -Area $AreaName -Message 'ActiveDirectory: No issues detected by baseline heuristics.') )
    $checks.Add( (New-Check -Area $AreaName -Name 'Baseline' -Status 'info' -Weight 0.1) )
  }

  [pscustomobject]@{
    Area   = $AreaName
    Cards  = $cards
    Checks = $checks
  }
}

Export-ModuleMember -Function Collect-ActiveDirectoryData, Analyze-ActiveDirectory
