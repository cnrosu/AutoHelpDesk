[CmdletBinding()]
param(
  [int]$EventLookbackHours = 48
)

function Get-RegistryValue {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )

  try {
    return Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
  } catch {
    return $null
  }
}

function Get-WindowsSearchSnapshot {
  param(
    [int]$EventLookbackHours = 48
  )

  # 1) Service state
  $svc = $null
  try {
    $svc = Get-Service -Name 'WSearch' -ErrorAction Stop
  } catch {
    $svc = $null
  }

  # 2) Core registry (machine)
  $wsKey = 'HKLM:\SOFTWARE\Microsoft\Windows Search'
  $datastoreDir = Get-RegistryValue -Path "$wsKey\Datastore" -Name 'Directory'
  $setupCompleted = Get-RegistryValue -Path $wsKey -Name 'SetupCompletedSuccessfully'
  $perUserCatalog = Get-RegistryValue -Path $wsKey -Name 'EnablePerUserCatalog'
  $indexerStatus   = Get-RegistryValue -Path $wsKey -Name 'IndexerStatus'
  $pauseReason     = Get-RegistryValue -Path $wsKey -Name 'PauseReason'

  # 3) Policy (if any)
  $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
  $preventIndexingOutlook = Get-RegistryValue -Path $polKey -Name 'PreventIndexingOutlook'
  $disableBackoff         = Get-RegistryValue -Path $polKey -Name 'DisableBackoff'
  $preventIndexingUserFolders = Get-RegistryValue -Path $polKey -Name 'PreventIndexingUserFolders'

  # 4) Index location + size
  $indexPath = if ($datastoreDir) { $datastoreDir } else { "$env:ProgramData\Microsoft\Search\Data" }
  $indexExists = Test-Path $indexPath
  $catalogSizeBytes = 0
  if ($indexExists) {
    try {
      $catalogSizeBytes = (Get-ChildItem -Path $indexPath -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    } catch {
      $catalogSizeBytes = $null
    }
  }

  # 5) Disk free on index volume
  $indexDrive = $null
  try {
    $indexDrive = (Get-Item $indexPath).PSDrive.Root
  } catch {
    $indexDrive = $null
  }

  $driveInfo = $null
  if ($indexDrive) {
    $driveLetter = $indexDrive.TrimEnd('\\').TrimEnd(':')
    try {
      $driveInfo = Get-PSDrive -Name $driveLetter -ErrorAction Stop
    } catch {
      $driveInfo = $null
    }
  }

  $freePct = $null
  if ($driveInfo -and $driveInfo.Used -ge 0) {
    $freePct = [math]::Round(100 * ($driveInfo.Free / ($driveInfo.Free + $driveInfo.Used)), 1)
  }

  # 6) Battery/throttling context (laptops)
  $batterySaver = $false
  try {
    $batterySaver = (Get-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BatterySaver' -Name 'BatterySaver') -eq 1
  } catch {
    $batterySaver = $false
  }

  # 7) Event log snapshot (errors/warnings)
  $logName = 'Microsoft-Windows-Search/Operational'
  $since   = (Get-Date).AddHours(-$EventLookbackHours)
  $events = @()
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName=$logName; StartTime=$since } -ErrorAction Stop |
              Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
  } catch {
    $events = @()
  }

  $errCount = ($events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
  $warnCount= ($events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count

  # 8) Suggested indexed scope (best-effort heuristics)
  $commonUserPaths = @(
    "$env:SystemDrive\Users\*\Documents",
    "$env:SystemDrive\Users\*\Desktop",
    "$env:SystemDrive\Users\*\Pictures"
  )
  $presentUserDocs = $commonUserPaths |
    ForEach-Object { Resolve-Path $_ -ErrorAction SilentlyContinue } |
    Select-Object -ExpandProperty ProviderPath -ErrorAction SilentlyContinue

  # 9) Optional: perf counters (not present on all builds)
  $perf = [ordered]@{}
  $counterPaths = @(
    '\\Search Indexer(*)\\Items in index',
    '\\Search Gatherer(*)\\URLs to be crawled',
    '\\Search Gatherer(*)\\Crawl rate'
  )
  try {
    $c = Get-Counter -Counter $counterPaths -ErrorAction Stop
    foreach ($set in $c.CounterSamples) {
      $perf[$set.Path] = [int]$set.CookedValue
    }
  } catch {
    # Perf counters unavailable or access denied; ignore.
  }

  return [pscustomobject]@{
    Source                       = 'WindowsSearch'
    CollectedAt                  = (Get-Date).ToString('s')
    Service                      = if ($svc) { [pscustomobject]@{ Status=$svc.Status.ToString(); StartType=$svc.StartType.ToString() } } else { $null }
    SetupCompletedSuccessfully   = $setupCompleted
    EnablePerUserCatalog         = $perUserCatalog
    IndexerStatus                = $indexerStatus
    PauseReason                  = $pauseReason
    Policy                       = [pscustomobject]@{
                                    PreventIndexingOutlook      = $preventIndexingOutlook
                                    DisableBackoff              = $disableBackoff
                                    PreventIndexingUserFolders  = $preventIndexingUserFolders
                                  }
    Index                        = [pscustomobject]@{
                                    PathExists   = $indexExists
                                    Path         = $indexPath
                                    SizeBytes    = $catalogSizeBytes
                                    DriveFreePct = $freePct
                                  }
    BatterySaver                 = $batterySaver
    Events                       = [pscustomobject]@{
                                    LookbackHours = $EventLookbackHours
                                    ErrorCount    = $errCount
                                    WarningCount  = $warnCount
                                  }
    PerfCounters                 = $perf
    UserDocumentPathsPresent     = @($presentUserDocs)
    Notes                        = 'Scopes approximated via policy; detailed scope enumeration omitted for compatibility.'
  }
}

if ($MyInvocation.InvocationName -ne '.') {
  return Get-WindowsSearchSnapshot -EventLookbackHours $EventLookbackHours
}
