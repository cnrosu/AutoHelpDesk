. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADTimeCollection {
  param(
    [pscustomobject]$Context
  )

  $ctx = if ($PSBoundParameters.ContainsKey('Context') -and $Context) { $Context } else { Get-ADCollectorContext }

  Write-Output ("Timestamp : {0:o}" -f (Get-Date))
  $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
  Write-Output ("PartOfDomain : {0}" -f $partText)

  try {
    $status = w32tm /query /status 2>&1
    $statusExit = $LASTEXITCODE
  } catch {
    $status = @("w32tm /query /status failed: {0}" -f $_)
    $statusExit = -1
  }
  Write-Output "## w32tm /query /status"
  if ($status) { $status | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
  Write-Output ("StatusExitCode : {0}" -f $statusExit)
  if ($status) {
    $statusText = ($status -join "`n")
    $offsetMatch = [regex]::Match($statusText,'(?im)^(?:Phase Offset|Offset)\s*:\s*([+-]?[0-9\.]+)s')
    if ($offsetMatch.Success) { Write-Output ("PhaseOffsetSeconds : {0}" -f $offsetMatch.Groups[1].Value.Trim()) }
    $sourceMatch = [regex]::Match($statusText,'(?im)^\s*Source\s*:\s*(.+)$')
    if ($sourceMatch.Success) { Write-Output ("TimeSource : {0}" -f $sourceMatch.Groups[1].Value.Trim()) }
    $lastSyncMatch = [regex]::Match($statusText,'(?im)^\s*Last Successful Sync Time\s*:\s*(.+)$')
    if ($lastSyncMatch.Success) { Write-Output ("LastSuccessfulSync : {0}" -f $lastSyncMatch.Groups[1].Value.Trim()) }
  }
  Write-Output ""
  try {
    $peers = w32tm /query /peers 2>&1
    $peersExit = $LASTEXITCODE
  } catch {
    $peers = @("w32tm /query /peers failed: {0}" -f $_)
    $peersExit = -1
  }
  Write-Output "## w32tm /query /peers"
  if ($peers) { $peers | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
  Write-Output ("PeersExitCode : {0}" -f $peersExit)
}
