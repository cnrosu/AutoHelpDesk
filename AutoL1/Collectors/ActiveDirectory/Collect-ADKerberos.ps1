. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADKerberosCollection {
  param(
    [pscustomobject]$Context
  )

  $ctx = if ($PSBoundParameters.ContainsKey('Context') -and $Context) { $Context } else { Get-ADCollectorContext }

  Write-Output ("Timestamp : {0:o}" -f (Get-Date))
  $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
  Write-Output ("PartOfDomain : {0}" -f $partText)
  Write-Output "## klist"
  try {
    $klistOutput = klist 2>&1
    if ($klistOutput) { $klistOutput | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
  } catch {
    Write-Output ("klist failed: {0}" -f $_)
  }
  Write-Output ""
  $startTime = (Get-Date).AddHours(-72)
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(4768,4771,4776); StartTime=$startTime } -ErrorAction Stop
    $count = if ($events) { $events.Count } else { 0 }
    Write-Output ("KerberosEventCount : {0}" -f $count)
    if ($events) {
      $sorted = $events | Sort-Object TimeCreated -Descending | Select-Object -First 25
      foreach ($ev in $sorted) {
        $msg = ($ev.Message -replace "[\r\n]+", ' ').Trim()
        Write-Output ("KerberosEvent : Id={0}; Time={1:o}; Provider={2}; Message={3}" -f $ev.Id, $ev.TimeCreated, $ev.ProviderName, $msg)
      }
    }
  } catch {
    Write-Output ("KerberosEventError : {0}" -f $_)
  }
}
