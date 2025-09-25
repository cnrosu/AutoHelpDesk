. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADGpoCollection {
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

  Write-Output "## gpresult /r /scope computer"
  try {
    $gpComputer = gpresult /r /scope computer 2>&1
    $gpComputerExit = $LASTEXITCODE
  } catch {
    $gpComputer = @("gpresult /r /scope computer failed: {0}" -f $_)
    $gpComputerExit = -1
  }
  if ($gpComputer) { $gpComputer | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
  Write-Output ("GPResultComputerExitCode : {0}" -f $gpComputerExit)
  Write-Output ""

  Write-Output "## gpresult /r /scope user"
  try {
    $gpUser = gpresult /r /scope user 2>&1
    $gpUserExit = $LASTEXITCODE
  } catch {
    $gpUser = @("gpresult /r /scope user failed: {0}" -f $_)
    $gpUserExit = -1
  }
  if ($gpUser) { $gpUser | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
  Write-Output ("GPResultUserExitCode : {0}" -f $gpUserExit)
  Write-Output ""

  $startTime = (Get-Date).AddHours(-72)
  try {
    $gpoEvents = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=@(1058,1030); StartTime=$startTime } -ErrorAction Stop
    $count = if ($gpoEvents) { $gpoEvents.Count } else { 0 }
    Write-Output ("GPOEventCount : {0}" -f $count)
    if ($gpoEvents) {
      $sorted = $gpoEvents | Sort-Object TimeCreated -Descending | Select-Object -First 25
      foreach ($ev in $sorted) {
        $msg = ($ev.Message -replace "[\r\n]+", ' ').Trim()
        Write-Output ("GPOEvent : Id={0}; Time={1:o}; Provider={2}; Message={3}" -f $ev.Id, $ev.TimeCreated, $ev.ProviderName, $msg)
      }
    }
  } catch {
    Write-Output ("GPOEventError : {0}" -f $_)
  }
}
