[CmdletBinding()]
param()

function Convert-QueueStatusFlags {
  param($Value)

  if ($null -eq $Value) { return '' }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  try {
    Add-Type -AssemblyName ReachFramework -ErrorAction SilentlyContinue
    $enumType = [System.Printing.PrintQueueStatus]
  } catch {
    return [string]$Value
  }

  $labels = @()
  foreach ($flag in [Enum]::GetValues($enumType)) {
    $flagValue = [int]$flag
    if ($flagValue -eq 0) { continue }
    if (($intValue -band $flagValue) -ne 0) {
      $labels += $flag.ToString()
    }
  }

  if ($labels.Count -eq 0) { return 'None' }
  return ($labels -join ', ')
}

function Get-PrinterStatusLabel {
  param($Value)

  if ($null -eq $Value) { return '' }

  $map = @{
    1  = 'Other'
    2  = 'Unknown'
    3  = 'Idle'
    4  = 'Printing'
    5  = 'WarmingUp'
    6  = 'Stopped'
    7  = 'Offline'
    8  = 'Paused'
    9  = 'Error'
    10 = 'Busy'
    11 = 'NotAvailable'
    12 = 'Waiting'
    13 = 'Processing'
    14 = 'Initialization'
    15 = 'PowerSave'
    16 = 'PendingDeletion'
    17 = 'IOActive'
    18 = 'ManualFeed'
  }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  if ($map.ContainsKey($intValue)) { return $map[$intValue] }
  return [string]$intValue
}

function Get-PrinterErrorLabel {
  param($Value)

  if ($null -eq $Value) { return '' }

  $map = @{
    0  = 'Unknown'
    1  = 'Other'
    2  = 'NoError'
    3  = 'LowPaper'
    4  = 'NoPaper'
    5  = 'LowToner'
    6  = 'NoToner'
    7  = 'DoorOpen'
    8  = 'Jammed'
    9  = 'Offline'
    10 = 'ServiceRequested'
    11 = 'OutputBinFull'
    12 = 'NotAvailable'
    13 = 'NoInputTray'
    14 = 'NoFormFeed'
    15 = 'Paused'
    16 = 'ManualFeed'
  }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  if ($map.ContainsKey($intValue)) { return $map[$intValue] }
  return [string]$intValue
}

function Get-PortProtocolLabel {
  param($Value)

  if ($null -eq $Value) { return '' }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  switch ($intValue) {
    1 { return 'RAW' }
    2 { return 'LPR' }
    default { return [string]$intValue }
  }
}

function Get-PrinterPortRole {
  param(
    [string]$PortName,
    [string]$PortMonitor,
    [string]$PrinterHostAddress,
    [string]$DeviceUrl
  )

  $host = ''
  $role = 'Local'

  $monitor = if ($PortMonitor) { $PortMonitor.Trim() } else { '' }
  $monitorLower = if ($monitor) { $monitor.ToLowerInvariant() } else { '' }
  $deviceUrl = if ($DeviceUrl) { $DeviceUrl.Trim() } else { '' }

  if ($monitorLower -match 'wsd') {
    $role = 'WSD'
    if ($deviceUrl -match '://([^/]+)') { $host = $matches[1] }
  } elseif ($monitorLower -match 'standard tcp/ip') {
    $role = 'DirectIP'
    if ($PrinterHostAddress) {
      $host = $PrinterHostAddress
    } elseif ($deviceUrl -match '://([^/]+)') {
      $host = $matches[1]
    } elseif ($PortName -match '^IP_(.+)$') {
      $host = $matches[1]
    }
  } elseif ($monitorLower -match 'http' -or $monitorLower -match 'ipp') {
    $role = 'IPP'
    if ($deviceUrl -match '://([^/]+)') {
      $host = $matches[1]
    } elseif ($PrinterHostAddress) {
      $host = $PrinterHostAddress
    }
  } elseif ($monitorLower -match 'local') {
    if ($PortName -match '^\\\\([^\\]+)\\') {
      $role = 'ServerQueue'
      $host = $matches[1]
    } else {
      $role = 'Local'
    }
  } elseif ($deviceUrl -match '^(ipp|http|https)://([^/]+)') {
    $role = 'IPP'
    $host = $matches[2]
  }

  if (-not $host -and $PortName -match '^\\\\([^\\]+)\\') {
    $role = 'ServerQueue'
    $host = $matches[1]
  }

  if (-not $host -and $PortName -match '^IP_(.+)$') {
    if ($role -eq 'Local') { $role = 'DirectIP' }
    $host = $matches[1]
  }

  if (-not $host -and $PrinterHostAddress) { $host = $PrinterHostAddress }

  if ($host) {
    $host = $host.Trim().TrimStart('[').TrimEnd(']')
  }

  if (-not $role) { $role = 'Unknown' }

  return [pscustomobject]@{
    Host = $host
    Role = $role
  }
}

function Test-TcpPort {
  param(
    [Parameter(Mandatory)] [string]$Host,
    [Parameter(Mandatory)] [int]$Port,
    [int]$TimeoutMs = 3000
  )

  $result = [pscustomobject]@{
    Host      = $Host
    Port      = $Port
    Success   = $false
    LatencyMs = $null
    Error     = ''
  }

  if (-not $Host) {
    $result.Error = 'HostNotProvided'
    return $result
  }

  $client = $null
  $waitHandle = $null
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $async = $client.BeginConnect($Host, $Port, $null, $null)
    $waitHandle = $async.AsyncWaitHandle
    if (-not $waitHandle.WaitOne($TimeoutMs)) {
      $stopwatch.Stop()
      $result.Error = 'Timeout'
      return $result
    }

    $client.EndConnect($async)
    $stopwatch.Stop()
    $result.Success = $true
    $result.LatencyMs = [int][math]::Round($stopwatch.Elapsed.TotalMilliseconds)
  } catch {
    $message = $_.Exception.Message
    if ($message) {
      $result.Error = ($message -replace '\r?\n', ' ').Trim()
    } else {
      $result.Error = 'ConnectionFailed'
    }
  } finally {
    if ($waitHandle) {
      try { $waitHandle.Close() } catch {}
    }
    if ($client) {
      try { $client.Close() } catch {}
    }
  }

  return $result
}

Write-Output "### Spooler"
$spoolerInfo = $null
try {
  $spoolerInfo = Get-CimInstance Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop
} catch {
  try { $spoolerInfo = Get-WmiObject Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop } catch {}
}
if ($spoolerInfo) {
  Write-Output ("State : {0}" -f $spoolerInfo.State)
  Write-Output ("Status : {0}" -f $spoolerInfo.Status)
  if ($spoolerInfo.PSObject.Properties['Started']) { Write-Output ("Started : {0}" -f ([bool]$spoolerInfo.Started)) }
  if ($spoolerInfo.PSObject.Properties['StartMode']) { Write-Output ("StartMode : {0}" -f $spoolerInfo.StartMode) }
  if ($spoolerInfo.PSObject.Properties['DelayedAutoStart']) { Write-Output ("DelayedAutoStart : {0}" -f ([bool]$spoolerInfo.DelayedAutoStart)) }
  if ($spoolerInfo.PSObject.Properties['StartName']) { Write-Output ("StartName : {0}" -f $spoolerInfo.StartName) }
} else {
  Write-Output "State : (not found)"
}
Write-Output ""

$printersCim = @()
try {
  $printersCim = Get-CimInstance Win32_Printer -ErrorAction Stop
} catch {
  try { $printersCim = Get-WmiObject Win32_Printer -ErrorAction Stop } catch {}
}

$printersMap = @{}
foreach ($printer in $printersCim) {
  if (-not $printer) { continue }
  $name = [string]$printer.Name
  if (-not $name) { continue }
  $entry = [ordered]@{
    Name                        = $name
    Default                     = $printer.Default
    Shared                      = $printer.Shared
    Network                     = $printer.Network
    Local                       = $printer.Local
    Hidden                      = $printer.Hidden
    WorkOffline                 = $printer.WorkOffline
    PortName                    = $printer.PortName
    DriverName                  = $printer.DriverName
    Comment                     = $printer.Comment
    Location                    = $printer.Location
    Attributes                  = $printer.Attributes
    PrinterStatusRaw            = $printer.PrinterStatus
    PrinterStatus               = Get-PrinterStatusLabel $printer.PrinterStatus
    ExtendedPrinterStatusRaw    = $printer.ExtendedPrinterStatus
    ExtendedPrinterStatus       = Get-PrinterStatusLabel $printer.ExtendedPrinterStatus
    DetectedErrorState          = $printer.DetectedErrorState
    DetectedError               = Get-PrinterErrorLabel $printer.DetectedErrorState
    ExtendedDetectedErrorState  = $printer.ExtendedDetectedErrorState
    Availability                = $printer.Availability
    PrintProcessor              = $printer.PrintProcessor
    JobCountSinceLastReset      = $printer.JobCountSinceLastReset
  }
  if ($printer.PSObject.Properties['Published']) { $entry['Published'] = $printer.Published }
  $printersMap[$name] = $entry
}

$pmPrinters = @()
$getPrinterCmd = Get-Command Get-Printer -ErrorAction SilentlyContinue
if ($getPrinterCmd) {
  try { $pmPrinters = Get-Printer -ErrorAction Stop } catch {}
}
foreach ($pm in $pmPrinters) {
  if (-not $pm) { continue }
  $name = [string]$pm.Name
  if (-not $name) { continue }
  if (-not $printersMap.ContainsKey($name)) {
    $printersMap[$name] = [ordered]@{ Name = $name }
  }
  $entry = $printersMap[$name]
  if ($pm.PSObject.Properties['Default']) { $entry['Default'] = $pm.Default }
  if ($pm.PSObject.Properties['Shared']) { $entry['Shared'] = $pm.Shared }
  if ($pm.PSObject.Properties['WorkOffline']) { $entry['WorkOffline'] = $pm.WorkOffline }
  if ($pm.PSObject.Properties['QueueStatus']) {
    $entry['QueueStatusRaw'] = $pm.QueueStatus
    $entry['QueueStatus'] = Convert-QueueStatusFlags $pm.QueueStatus
  }
  if ($pm.PSObject.Properties['JobCount']) { $entry['JobCount'] = $pm.JobCount }
  if ($pm.PSObject.Properties['Type']) { $entry['Type'] = $pm.Type }
  if ($pm.PSObject.Properties['Comment'] -and -not $entry['Comment']) { $entry['Comment'] = $pm.Comment }
  if ($pm.PSObject.Properties['Published']) { $entry['Published'] = $pm.Published }
}

Write-Output "### Printers"
if ($printersMap.Count -eq 0) {
  Write-Output "Status : NoneFound"
  Write-Output ""
} else {
  foreach ($printerName in ($printersMap.Keys | Sort-Object)) {
    $entry = $printersMap[$printerName]
    Write-Output ("#### Printer: {0}" -f $printerName)
    foreach ($key in @('Default','Shared','Network','Local','Hidden','WorkOffline','Published','PortName','DriverName','Type','JobCount','JobCountSinceLastReset','QueueStatusRaw','QueueStatus','PrinterStatusRaw','PrinterStatus','ExtendedPrinterStatusRaw','ExtendedPrinterStatus','DetectedErrorState','DetectedError','ExtendedDetectedErrorState','Availability','PrintProcessor','Attributes','Comment','Location')) {
      if ($entry.ContainsKey($key)) {
        $value = $entry[$key]
        if ($null -eq $value) { $value = '' }
        elseif ($value -is [array]) { $value = ($value -join ', ') }
        Write-Output ("{0} : {1}" -f $key, $value)
      }
    }
    Write-Output ""
  }
}

Write-Output "### Ports"
$portRecords = @()
$printerPorts = @()
$getPrinterPortCmd = Get-Command Get-PrinterPort -ErrorAction SilentlyContinue
if ($getPrinterPortCmd) {
  try { $printerPorts = Get-PrinterPort -ErrorAction Stop } catch {}
}
if (-not $printerPorts -or $printerPorts.Count -eq 0) {
  try { $printerPorts = Get-CimInstance Win32_PrinterPort -ErrorAction Stop } catch {}
}
foreach ($port in $printerPorts) {
  if (-not $port) { continue }
  $portName = [string]$port.Name
  if (-not $portName) { continue }
  $record = [ordered]@{ Name = $portName }
  foreach ($prop in @('PortMonitor','PrinterHostAddress','DeviceURL','PortNumber','Protocol','SNMPEnabled','SNMPCommunity')) {
    if ($port.PSObject.Properties[$prop]) {
      $value = $port.$prop
      if ($prop -eq 'Protocol') {
        $record[$prop] = $value
        $record['ProtocolLabel'] = Get-PortProtocolLabel $value
      } else {
        $record[$prop] = $value
      }
    }
  }
  $roleInfo = Get-PrinterPortRole -PortName $portName -PortMonitor ($record['PortMonitor']) -PrinterHostAddress ($record['PrinterHostAddress']) -DeviceUrl ($record['DeviceURL'])
  if ($roleInfo.Host) { $record['Host'] = $roleInfo.Host }
  if ($roleInfo.Role) { $record['Role'] = $roleInfo.Role }
  $portRecords += $record
}
if ($portRecords.Count -eq 0) {
  Write-Output "Status : NoPortsFound"
  Write-Output ""
} else {
  foreach ($record in ($portRecords | Sort-Object Name)) {
    Write-Output ("#### Port: {0}" -f $record['Name'])
    foreach ($key in @('PortMonitor','PrinterHostAddress','DeviceURL','PortNumber','Protocol','ProtocolLabel','SNMPEnabled','SNMPCommunity','Host','Role')) {
      if ($record.ContainsKey($key)) {
        $value = $record[$key]
        if ($null -eq $value) { $value = '' }
        elseif ($value -is [bool]) { $value = [bool]$value }
        Write-Output ("{0} : {1}" -f $key, $value)
      }
    }
    Write-Output ""
  }
}

Write-Output "### Drivers"
$drivers = @()
$driverCmd = Get-Command Get-PrinterDriver -ErrorAction SilentlyContinue
if ($driverCmd) {
  try { $drivers = Get-PrinterDriver -ErrorAction Stop } catch {}
}
if (-not $drivers -or $drivers.Count -eq 0) {
  try { $drivers = Get-CimInstance Win32_PrinterDriver -ErrorAction Stop } catch {}
}
if (-not $drivers -or $drivers.Count -eq 0) {
  Write-Output "Status : NoDriversFound"
  Write-Output ""
} else {
  foreach ($driver in ($drivers | Sort-Object Name)) {
    if (-not $driver) { continue }
    $name = [string]$driver.Name
    if (-not $name) { continue }
    Write-Output ("#### Driver: {0}" -f $name)
    $typeValue = $null
    if ($driver.PSObject.Properties['Type']) { $typeValue = $driver.Type }
    foreach ($key in @('Manufacturer','Type','IsPackaged','MajorVersion','MinorVersion','DriverVersion','InfPath')) {
      if ($driver.PSObject.Properties[$key]) {
        $value = $driver.$key
        if ($value -is [bool]) { $value = [bool]$value }
        Write-Output ("{0} : {1}" -f $key, $value)
      }
    }
    if ($null -ne $typeValue) {
      $intType = $null
      if ($typeValue -is [int]) { $intType = [int]$typeValue }
      elseif ([int]::TryParse([string]$typeValue, [ref]$intType)) { $intType = [int]$intType }
      if ($null -ne $intType) {
        switch ($intType) {
          3 { Write-Output "TypeLabel : Type3" }
          4 { Write-Output "TypeLabel : Type4" }
          default { Write-Output ("TypeLabel : {0}" -f $intType) }
        }
      }
    }
    Write-Output ""
  }
}

Write-Output "### Configurations"
$configCmd = Get-Command Get-PrintConfiguration -ErrorAction SilentlyContinue
if ($configCmd -and $printersMap.Count -gt 0) {
  foreach ($printerName in ($printersMap.Keys | Sort-Object)) {
    try { $config = Get-PrintConfiguration -PrinterName $printerName -ErrorAction Stop } catch { $config = $null }
    if (-not $config) { continue }
    Write-Output ("#### Printer: {0}" -f $printerName)
    foreach ($key in @('DuplexingMode','Collate','ColorMode','PaperSize','NUp','Quality','Orientation')) {
      if ($config.PSObject.Properties[$key]) {
        $value = $config.$key
        if ($value -is [bool]) { $value = [bool]$value }
        Write-Output ("{0} : {1}" -f $key, $value)
      }
    }
    Write-Output ""
  }
} else {
  Write-Output "Status : ConfigurationDataUnavailable"
  Write-Output ""
}

Write-Output "### Jobs"
$jobs = @()
$getPrintJobCmd = Get-Command Get-PrintJob -ErrorAction SilentlyContinue
if ($getPrintJobCmd) {
  try { $jobs = Get-PrintJob -ErrorAction Stop } catch {}
}
if (-not $jobs -or $jobs.Count -eq 0) {
  try { $jobs = Get-CimInstance Win32_PrintJob -ErrorAction Stop } catch {}
}
if (-not $jobs -or $jobs.Count -eq 0) {
  Write-Output "Status : NoJobs"
  Write-Output ""
} else {
  $now = Get-Date
  foreach ($job in $jobs) {
    if (-not $job) { continue }
    $printerName = $null
    if ($job.PSObject.Properties['PrinterName']) {
      $printerName = [string]$job.PrinterName
    } elseif ($job.PSObject.Properties['Name']) {
      $nameValue = [string]$job.Name
      if ($nameValue -match '^([^,]+),') { $printerName = $matches[1] }
    }
    if (-not $printerName) { $printerName = '(unknown)' }
    Write-Output ("#### Job: {0}" -f $printerName)
    if ($job.PSObject.Properties['Id']) { Write-Output ("JobId : {0}" -f $job.Id) }
    elseif ($job.PSObject.Properties['JobId']) { Write-Output ("JobId : {0}" -f $job.JobId) }
    if ($job.PSObject.Properties['DocumentName']) { Write-Output ("Document : {0}" -f $job.DocumentName) }
    elseif ($job.PSObject.Properties['Document']) { Write-Output ("Document : {0}" -f $job.Document) }
    if ($job.PSObject.Properties['UserName']) { Write-Output ("UserName : {0}" -f $job.UserName) }
    if ($job.PSObject.Properties['Size']) { Write-Output ("SizeBytes : {0}" -f $job.Size) }
    elseif ($job.PSObject.Properties['TotalBytes']) { Write-Output ("SizeBytes : {0}" -f $job.TotalBytes) }
    if ($job.PSObject.Properties['TotalPages']) { Write-Output ("TotalPages : {0}" -f $job.TotalPages) }
    if ($job.PSObject.Properties['JobStatus']) { Write-Output ("JobStatus : {0}" -f $job.JobStatus) }
    if ($job.PSObject.Properties['Status']) { Write-Output ("Status : {0}" -f $job.Status) }
    $submitted = $null
    if ($job.PSObject.Properties['SubmittedTime']) {
      $submitted = $job.SubmittedTime
    } elseif ($job.PSObject.Properties['TimeSubmitted']) {
      $submittedRaw = $job.TimeSubmitted
      if ($submittedRaw -is [datetime]) {
        $submitted = $submittedRaw
      } elseif ($submittedRaw -is [string] -and $submittedRaw) {
        try { $submitted = [System.Management.ManagementDateTimeConverter]::ToDateTime($submittedRaw) } catch { $submitted = $null }
      }
    }
    if ($submitted -is [datetime]) {
      try { $submittedUtc = $submitted.ToUniversalTime() } catch { $submittedUtc = $submitted }
      Write-Output ("SubmittedTime : {0:o}" -f $submittedUtc)
      $ageMinutes = [int][math]::Max(0, [math]::Ceiling(($now - $submitted).TotalMinutes))
      Write-Output ("ElapsedMinutes : {0}" -f $ageMinutes)
    }
    Write-Output ""
  }
}

Write-Output "### Policies"
$policySpecs = @(
  @{ Name = 'RestrictDriverInstallationToAdministrators'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers' },
  @{ Name = 'PackagePointAndPrintOnly'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
  @{ Name = 'PackagePointAndPrintServerList'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
  @{ Name = 'NoWarningNoElevationOnInstall'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
  @{ Name = 'NoWarningNoElevationOnUpdate'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
  @{ Name = 'UpdatePromptSettings'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
  @{ Name = 'InForest'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
  @{ Name = 'TrustedServers'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' }
)
$policyCaptured = $false
foreach ($spec in $policySpecs) {
  $path = $spec.Path
  $name = $spec.Name
  if (-not (Test-Path $path)) { continue }
  try { $props = Get-ItemProperty -Path $path -ErrorAction Stop } catch { continue }
  if (-not $props) { continue }
  $prop = $props.PSObject.Properties[$name]
  if (-not $prop) { continue }
  $value = $prop.Value
  if ($null -eq $value) { continue }
  if ($value -is [array]) {
    $valueString = ($value | ForEach-Object { ($_ | Out-String).Trim() } | Where-Object { $_ }) -join ', '
  } else {
    $valueString = [string]$value
  }
  if ([string]::IsNullOrWhiteSpace($valueString)) { continue }
  Write-Output ("Policy.{0} : {1}" -f $name, $valueString.Trim())
  $policyCaptured = $true
}
if (-not $policyCaptured) { Write-Output "PolicyStatus : NoneCaptured" }
Write-Output ""

Write-Output "### NetworkTests"
$portLookup = @{}
foreach ($record in $portRecords) {
  $portLookup[$record['Name']] = $record
}
$hostRecords = @{}
foreach ($entry in $printersMap.Values) {
  if (-not $entry.ContainsKey('PortName')) { continue }
  $portName = $entry['PortName']
  if (-not $portName) { continue }
  if (-not $portLookup.ContainsKey($portName)) { continue }
  $portInfo = $portLookup[$portName]
  $host = if ($portInfo.ContainsKey('Host')) { $portInfo['Host'] } else { '' }
  if (-not $host) { continue }
  $role = if ($portInfo.ContainsKey('Role')) { $portInfo['Role'] } else { 'Local' }
  $hostKey = $host.ToLowerInvariant()
  if (-not $hostRecords.ContainsKey($hostKey)) {
    $hostRecords[$hostKey] = @{ Host = $host; Roles = @(); Printers = @(); Ports = @() }
  }
  $record = $hostRecords[$hostKey]
  if ($role -and ($record.Roles -notcontains $role)) { $record.Roles += $role }
  if ($record.Printers -notcontains $entry['Name']) { $record.Printers += $entry['Name'] }
  if ($record.Ports -notcontains $portName) { $record.Ports += $portName }
}
$testPlans = @()
$planKeys = @{}
foreach ($record in $hostRecords.Values) {
  $roles = $record.Roles | Sort-Object -Unique
  foreach ($role in $roles) {
    if ($role -eq 'ServerQueue') {
      $portsToTest = @(135, 445)
    } elseif ($role -eq 'DirectIP' -or $role -eq 'IPP') {
      $portsToTest = @(9100, 631)
    } else {
      continue
    }
    foreach ($port in $portsToTest) {
      $key = "{0}|{1}|{2}" -f $record.Host.ToLowerInvariant(), $role, $port
      if ($planKeys.ContainsKey($key)) { continue }
      $planKeys[$key] = $true
      $testPlans += [pscustomobject]@{
        Host        = $record.Host
        Role        = $role
        Port        = $port
        Printers    = $record.Printers
        SourcePorts = $record.Ports
      }
    }
  }
}
if ($testPlans.Count -eq 0) {
  Write-Output "Targets : (none)"
} else {
  foreach ($plan in ($testPlans | Sort-Object Host, Role, Port)) {
    $result = Test-TcpPort -Host $plan.Host -Port $plan.Port
    Write-Output ("#### Target: {0}" -f $plan.Host)
    Write-Output ("Role : {0}" -f $plan.Role)
    Write-Output ("Port : {0}" -f $plan.Port)
    Write-Output ("Printers : {0}" -f (($plan.Printers | Sort-Object) -join ', '))
    Write-Output ("SourcePorts : {0}" -f (($plan.SourcePorts | Sort-Object) -join ', '))
    Write-Output ("Success : {0}" -f $result.Success)
    if ($null -ne $result.LatencyMs) { Write-Output ("LatencyMs : {0}" -f $result.LatencyMs) }
    if ($result.Error) { Write-Output ("Error : {0}" -f $result.Error) } else { Write-Output "Error : " }
    Write-Output ""
  }
}
