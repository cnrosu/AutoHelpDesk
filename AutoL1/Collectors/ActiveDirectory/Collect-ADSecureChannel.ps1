. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADSecureChannelCollection {
  param(
    [pscustomobject]$Context
  )

  $ctx = if ($PSBoundParameters.ContainsKey('Context') -and $Context) { $Context } else { Get-ADCollectorContext }

  Write-Output ("Timestamp : {0:o}" -f (Get-Date))
  $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
  Write-Output ("PartOfDomain : {0}" -f $partText)
  if ($ctx.PartOfDomain -ne $true) {
    Write-Output "Status : Skipped (NotDomainJoined)"
    return
  }

  try {
    $scResult = Test-ComputerSecureChannel -ErrorAction Stop
    Write-Output ("SecureChannelResult : {0}" -f $scResult)
  } catch {
    Write-Output "SecureChannelResult : Error"
    Write-Output ("SecureChannelError : {0}" -f $_)
  }

  $queryTarget = $null
  if ($ctx.DomainDnsName) {
    $queryTarget = $ctx.DomainDnsName
  } elseif ($ctx.Domain) {
    $queryTarget = $ctx.Domain
  } elseif ($ctx.DomainCandidates -and $ctx.DomainCandidates.Count -gt 0) {
    $queryTarget = $ctx.DomainCandidates[0]
  }

  Write-Output ("SecureChannelQueryTarget : {0}" -f (if ($queryTarget) { $queryTarget } else { '(unknown)' }))
  if ($queryTarget) {
    try {
      $nlOutput = nltest /sc_query:$queryTarget 2>&1
      $nlExit = $LASTEXITCODE
    } catch {
      $nlOutput = @("nltest /sc_query failed: {0}" -f $_)
      $nlExit = -1
    }
  } else {
    $nlOutput = @("nltest /sc_query skipped: domain unknown")
    $nlExit = -1
  }

  Write-Output ("SecureChannelNltestExitCode : {0}" -f $nlExit)
  Write-Output "## nltest /sc_query"
  if ($nlOutput) { $nlOutput | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
}
