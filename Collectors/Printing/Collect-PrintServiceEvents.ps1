[CmdletBinding()]
param(
  [int]$Days = 7,
  [int]$MaxEventsPerLog = 200
)

$logs = @('Microsoft-Windows-PrintService/Admin','Microsoft-Windows-PrintService/Operational')
$start = (Get-Date).AddDays(-[math]::Abs($Days))
foreach ($log in $logs) {
  Write-Output ("### Log: {0}" -f $log)
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -ErrorAction Stop |
      Sort-Object TimeCreated |
      Select-Object -Last $MaxEventsPerLog
  } catch {
    Write-Output ("LogError : {0}" -f $_)
    Write-Output ""
    continue
  }

  if (-not $events -or $events.Count -eq 0) {
    Write-Output "LogStatus : NoEventsInRange"
    Write-Output ""
    continue
  }

  foreach ($event in $events) {
    $timeCreated = $null
    if ($event.TimeCreated) {
      try { $timeCreated = $event.TimeCreated.ToUniversalTime() } catch { $timeCreated = $event.TimeCreated }
    }
    $levelName = $event.LevelDisplayName
    if (-not $levelName) {
      switch ($event.Level) {
        1 { $levelName = 'Critical' }
        2 { $levelName = 'Error' }
        3 { $levelName = 'Warning' }
        4 { $levelName = 'Information' }
        5 { $levelName = 'Verbose' }
      }
    }
    $message = ''
    try {
      if ($event.Message) { $message = ($event.Message -replace '\r?\n',' ').Trim() }
    } catch {}
    Write-Output ("EventID : {0}" -f $event.Id)
    if ($timeCreated) { Write-Output ("TimeCreated : {0:o}" -f $timeCreated) }
    if ($event.PSObject.Properties['Level']) { Write-Output ("Level : {0}" -f $event.Level) }
    if ($levelName) { Write-Output ("LevelDisplayName : {0}" -f $levelName) }
    if ($event.PSObject.Properties['ProviderName']) { Write-Output ("ProviderName : {0}" -f $event.ProviderName) }
    if ($event.PSObject.Properties['TaskDisplayName'] -and $event.TaskDisplayName) { Write-Output ("Task : {0}" -f $event.TaskDisplayName) }
    Write-Output ("Message : {0}" -f $message)
    Write-Output ""
  }
}
