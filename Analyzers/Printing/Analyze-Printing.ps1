function Invoke-PrintingAnalysis {
  param(
    $Summary,
    $PrintingStatus,
    $PrintingEventRecords
  )

  if (-not $PrintingStatus) { return }

  $portIndex = @{}
  if ($PrintingStatus.Ports) {
    foreach ($port in $PrintingStatus.Ports) {
      if (-not $port -or -not $port.Name) { continue }
      $key = $port.Name.ToLowerInvariant()
      $portIndex[$key] = $port
    }
  }

  $printersByPort = @{}
  if ($PrintingStatus.Printers) {
    foreach ($printer in $PrintingStatus.Printers) {
      if (-not $printer -or -not $printer.PortName) { continue }
      $portKey = $printer.PortName.ToLowerInvariant()
      if (-not $printersByPort.ContainsKey($portKey)) { $printersByPort[$portKey] = @() }
      $printersByPort[$portKey] += $printer.Name
    }
  }

  if ($PrintingStatus.Spooler) {
    $spooler = $PrintingStatus.Spooler
    $spoolerEvidence = @()
    if ($spooler.State) { $spoolerEvidence += "State: $($spooler.State)" }
    if ($spooler.Status) { $spoolerEvidence += "Status: $($spooler.Status)" }
    if ($null -ne $spooler.Started) { $spoolerEvidence += "Started: $($spooler.Started)" }
    if ($spooler.StartMode) { $spoolerEvidence += "StartMode: $($spooler.StartMode)" }
    if ($null -ne $spooler.DelayedAutoStart) { $spoolerEvidence += "DelayedAutoStart: $($spooler.DelayedAutoStart)" }
    if ($spooler.StartName) { $spoolerEvidence += "StartName: $($spooler.StartName)" }
    $spoolerEvidenceText = $spoolerEvidence -join "`n"

    $spoolerRunning = ($spooler.Started -eq $true)
    if (-not $spoolerRunning -and $spooler.State) {
      if ($spooler.State -match '(?i)running') { $spoolerRunning = $true }
    }

    $spoolerStartNormalized = $null
    if ($spooler.StartMode) { $spoolerStartNormalized = Normalize-ServiceStartType $spooler.StartMode }

    if (-not $spoolerRunning) {
      Add-Issue 'high' 'Printing/Spooler' 'Print Spooler service is not running.' $spoolerEvidenceText
    } elseif ($spoolerStartNormalized -in @('automatic','automatic-delayed')) {
      Add-Normal 'Printing/Spooler' 'GOOD Printing/Spooler Running (Automatic)' $spoolerEvidenceText
    }

    if ($spoolerStartNormalized -eq 'disabled') {
      Add-Issue 'high' 'Printing/Spooler' 'Print Spooler service startup type is Disabled.' $spoolerEvidenceText
    }
  }

  $offlineInfo = @{}
  $offlineDetails = @()
  if ($PrintingStatus.Printers) {
    foreach ($printer in $PrintingStatus.Printers) {
      if (-not $printer.Name) { continue }
      $reasons = @()
      if ($printer.WorkOffline -eq $true) { $reasons += 'WorkOffline=True' }
      if ($printer.QueueStatus -and $printer.QueueStatus -match '(?i)offline') { $reasons += "QueueStatus=$($printer.QueueStatus)" }
      elseif ($printer.QueueStatusRaw -eq 1) { $reasons += 'QueueStatus=Offline' }
      if ($printer.PrinterStatus -and $printer.PrinterStatus -match '(?i)offline') { $reasons += "PrinterStatus=$($printer.PrinterStatus)" }
      elseif ($printer.PrinterStatusRaw -eq 7) { $reasons += 'PrinterStatus=Offline' }
      if ($printer.ExtendedPrinterStatus -and $printer.ExtendedPrinterStatus -match '(?i)offline') { $reasons += "ExtendedStatus=$($printer.ExtendedPrinterStatus)" }
      elseif ($printer.ExtendedPrinterStatusRaw -eq 7) { $reasons += 'ExtendedStatus=Offline' }
      if ($printer.DetectedError -and $printer.DetectedError -match '(?i)offline') { $reasons += "DetectedError=$($printer.DetectedError)" }
      elseif ($printer.DetectedErrorState -eq 9) { $reasons += 'DetectedError=Offline' }
      if ($printer.Availability -eq 7) { $reasons += 'Availability=7' }

      if ($reasons.Count -gt 0) {
        $offlineInfo[$printer.Name] = $reasons
        $offlineDetails += ("{0} ({1})" -f $printer.Name, ($reasons -join '; '))
      }
    }
  }

  if ($offlineDetails.Count -gt 0) {
    $queueSeverity = if ($offlineDetails.Count -gt 1) { 'high' } else { 'medium' }
    $offlineEvidence = @()
    foreach ($kv in $offlineInfo.GetEnumerator()) {
      $offlineEvidence += ("{0}: {1}" -f $kv.Key, ($kv.Value -join ', '))
    }
    $offlineEvidence = $offlineEvidence | Sort-Object
    $offlineEvidenceText = $offlineEvidence -join "`n"
    Add-Issue $queueSeverity 'Printing/Queues' ("Printer queue offline: {0}." -f ($offlineDetails -join '; ')) $offlineEvidenceText
  }

  $defaultPrinters = @($PrintingStatus.Printers | Where-Object { $_.Default -eq $true })
  if ($defaultPrinters.Count -eq 0) {
    Add-Issue 'low' 'Printing/Default' 'Default printer not configured.' ''
  } else {
    foreach ($dp in $defaultPrinters) {
      $reason = @()
      if ($dp.WorkOffline -eq $true) { $reason += 'WorkOffline' }
      if ($dp.QueueStatus -and $dp.QueueStatus -match '(?i)offline') { $reason += 'QueueStatus' }
      if ($dp.PrinterStatus -and $dp.PrinterStatus -match '(?i)offline') { $reason += 'PrinterStatus' }
      if ($dp.DetectedError -and $dp.DetectedError -match '(?i)offline') { $reason += 'DetectedError' }
      if ($dp.Availability -eq 7) { $reason += 'Availability=7' }
      if ($reason.Count -gt 0) {
        $reasonText = $reason -join ', '
        Add-Issue 'low' 'Printing/Default' ("Default printer {0} offline ({1})." -f $dp.Name, $reasonText) $reasonText
      }
    }
  }

  $stuckJobs = @()
  $jobsByPrinter = @{}
  if ($PrintingStatus.Jobs) {
    foreach ($job in $PrintingStatus.Jobs) {
      if (-not $job.PrinterName) { continue }
      if (-not $jobsByPrinter.ContainsKey($job.PrinterName)) { $jobsByPrinter[$job.PrinterName] = @() }
      $jobsByPrinter[$job.PrinterName] += $job
    }

    foreach ($job in $PrintingStatus.Jobs) {
      $ageMinutes = $job.ElapsedMinutes
      if ($ageMinutes -eq $null) { continue }
      if ($ageMinutes -lt 15) { continue }
      $statusInfo = @()
      if ($job.JobStatus) { $statusInfo += "JobStatus=$($job.JobStatus)" }
      if ($job.Status) { $statusInfo += "Status=$($job.Status)" }
      $statusLabel = if ($statusInfo.Count -gt 0) { $statusInfo -join ', ' } else { 'NoStatus' }
      $stuckJobs += [pscustomobject]@{
        Printer   = $job.PrinterName
        JobId     = $job.JobId
        Document  = $job.Document
        Age       = $ageMinutes
        Status    = $statusLabel
        UserName  = $job.UserName
      }
    }
  }

  if ($stuckJobs.Count -gt 0) {
    $overHour = @($stuckJobs | Where-Object { $_.Age -ge 60 })
    $multipleQueues = @($jobsByPrinter.Keys | Where-Object { ($jobsByPrinter[$_] | Where-Object { $_.ElapsedMinutes -ge 60 }).Count -gt 0 })
    $severity = if ($overHour.Count -gt 1 -or $multipleQueues.Count -gt 1) { 'high' } else { 'medium' }
    if ($severity -eq 'high' -and $overHour.Count -gt 0) {
      $evidence = $overHour | Sort-Object Age -Descending | Select-Object -First 5 | ForEach-Object {
        "{0} | Job {1} | {2} min | {3}" -f $_.Printer, $_.JobId, $_.Age, $_.Status
      }
      Add-Issue 'high' 'Printing/Jobs' 'Multiple print jobs older than 60 minutes detected.' ($evidence -join "`n")
    } else {
      $evidence = $stuckJobs | Sort-Object Age -Descending | Select-Object -First 5 | ForEach-Object {
        "{0} | Job {1} | {2} min | {3}" -f $_.Printer, $_.JobId, $_.Age, $_.Status
      }
      Add-Issue 'medium' 'Printing/Jobs' 'Print jobs have been queued longer than 15 minutes.' ($evidence -join "`n")
    }
  }

  $wsdPrinters = @()
  $snmpPublic = @()
  $connectivityPlans = @{}
  $portsTested = @()
  if ($PrintingStatus.Ports) {
    foreach ($port in $PrintingStatus.Ports) {
      if (-not $port.Name) { continue }
      $role = if ($port.Role) { $port.Role } else { '' }
      $host = if ($port.Host) { $port.Host } else { '' }
      $printers = if ($printersByPort.ContainsKey($port.Name.ToLowerInvariant())) { $printersByPort[$port.Name.ToLowerInvariant()] } else { @() }

      if ($role -eq 'WSD') {
        foreach ($printerName in $printers) {
          $wsdPrinters += "$printerName on $($port.Name)"
        }
      }

      if ($port.SNMPEnabled -eq $true -and $port.SNMPCommunity -and $port.SNMPCommunity -match '^(?i)public$') {
        $snmpPrinters = if ($printers.Count -gt 0) { $printers -join ', ' } else { '(no printers mapped)' }
        $snmpPublic += "{0} ({1})" -f $port.Name, $snmpPrinters
      }

      if ($host) {
        $portKey = "{0}|{1}|{2}" -f $host.ToLowerInvariant(), $role, $port.Name
        if (-not $portsTested.ContainsKey($portKey)) {
          $portsTested[$portKey] = [pscustomobject]@{
            Host     = $host
            Role     = $role
            PortName = $port.Name
            Printers = $printers
          }
        }
      }
    }
  }

  if ($wsdPrinters.Count -gt 0) {
    Add-Issue 'low' 'Printing/Ports' 'Printers using WSD ports detected—prefer TCP/IP/IPP ports.' ($wsdPrinters -join "`n")
  }

  if ($snmpPublic.Count -gt 0) {
    Add-Issue 'low' 'Printing/Ports' 'SNMP community set to "public" on printer ports.' ($snmpPublic -join "`n")
  }

  if ($PrintingStatus.Tests) {
    $serverFailures = @()
    $directFailures = @()
    $hostsTested = @()
    foreach ($test in $PrintingStatus.Tests) {
      if (-not $test.Target) { continue }
      $hostsTested += $test.Target
      $role = if ($test.Role) { $test.Role } else { '' }
      $success = ($test.Success -eq $true)
      if ($success) { continue }
      $error = if ($test.Error) { $test.Error } else { 'UnknownError' }
      $label = "{0}:{1} ({2})" -f $test.Target, $test.Port, $error
      if ($role -eq 'ServerQueue') {
        $serverFailures += $label
      } else {
        $directFailures += $label
      }
    }

    if ($serverFailures.Count -gt 0) {
      Add-Issue 'high' 'Printing/Connectivity' ("Print server connectivity failures: {0}." -f ($serverFailures -join '; ')) ($serverFailures -join "`n")
    }
    if ($directFailures.Count -gt 0) {
      $severity = if ($directFailures.Count -gt 1) { 'high' } else { 'medium' }
      Add-Issue $severity 'Printing/Connectivity' ("Direct printer connectivity failures: {0}." -f ($directFailures -join '; ')) ($directFailures -join "`n")
    }
    if ($hostsTested.Count -gt 0 -and $serverFailures.Count -eq 0 -and $directFailures.Count -eq 0) {
      $hostsSummary = ($hostsTested | Sort-Object -Unique) -join ', '
      Add-Normal 'Printing/Connectivity' 'GOOD Printing/Network Reachable (ports)' ("Hosts tested: {0}" -f $hostsSummary)
    }
  }

  $driverIndex = @{}
  if ($PrintingStatus.Drivers) {
    foreach ($driver in $PrintingStatus.Drivers) {
      if (-not $driver.Name) { continue }
      $driverIndex[$driver.Name] = $driver
    }
  }

  $nonPackagedType3 = @()
  if ($PrintingStatus.Printers -and $PrintingStatus.Drivers) {
    foreach ($printer in $PrintingStatus.Printers) {
      if (-not $printer.DriverName) { continue }
      $portName = $printer.PortName
      $portRole = ''
      if ($portName) {
        $portKey = $portName.ToLowerInvariant()
        if ($portIndex.ContainsKey($portKey)) {
          $portRole = $portIndex[$portKey].Role
        }
      }
      $networkRoles = @('ServerQueue','DirectIP','IPP')
      if ($networkRoles -notcontains $portRole) { continue }
      $driver = $null
      if ($driverIndex.ContainsKey($printer.DriverName)) { $driver = $driverIndex[$printer.DriverName] }
      if (-not $driver) { continue }
      $driverType = $driver.Type
      if ($driverType -eq $null -and $driver.TypeLabel) {
        if ($driver.TypeLabel -match 'type\s*3') { $driverType = 3 }
        elseif ($driver.TypeLabel -match 'type\s*4') { $driverType = 4 }
      }
      $isType3 = ($driverType -eq 3)
      if (-not $isType3 -and $driver.TypeLabel -and $driver.TypeLabel -match 'type\s*3') { $isType3 = $true }
      if (-not $isType3) { continue }
      if ($driver.IsPackaged -eq $true) { continue }
      $nonPackagedType3 += [pscustomobject]@{
        Printer   = $printer.Name
        Driver    = $driver.Name
        PortRole  = $portRole
        TypeLabel = if ($driver.TypeLabel) { $driver.TypeLabel } elseif ($driverType) { "Type$driverType" } else { '' }
      }
    }
  }

  if ($Summary -and $Summary.DomainJoined -eq $true -and $nonPackagedType3.Count -gt 0) {
    $requiresType4 = $false
    $type4Policy = $PrintingStatus.Policies['PackagePointAndPrintOnly']
    if ($type4Policy -eq 1 -or $type4Policy -eq $true) { $requiresType4 = $true }
    $severity = if ($requiresType4) { 'high' } else { 'medium' }
    $driverEvidence = $nonPackagedType3 | ForEach-Object {
      $typeLabelText = if ($_.TypeLabel) { $_.TypeLabel } else { 'Type3' }
      "{0} → {1} ({2})" -f $_.Printer, $_.Driver, $typeLabelText
    }
    $message = 'Non-packaged Type 3 printer drivers detected on this domain-joined device.'
    if ($requiresType4) { $message += ' Policy enforces Type 4 drivers.' }
    Add-Issue $severity 'Printing/Drivers' $message ($driverEvidence -join "`n")
  } elseif ($PrintingStatus.Printers.Count -gt 0 -and $PrintingStatus.Drivers.Count -gt 0 -and $nonPackagedType3.Count -eq 0) {
    $driverSummary = $PrintingStatus.Drivers | Where-Object { $_.Name } | ForEach-Object {
      $typeLabel = if ($_.TypeLabel) { $_.TypeLabel } elseif ($_.Type) { "Type$($_.Type)" } else { 'UnknownType' }
      "{0} ({1}, Packaged={2})" -f $_.Name, $typeLabel, ($_.IsPackaged -eq $true)
    } | Select-Object -First 6
    $driverEvidence = $driverSummary -join "`n"
    Add-Normal 'Printing/Drivers' 'GOOD Printing/Drivers Packaged' $driverEvidence
  }

  $restrictValue = $PrintingStatus.Policies['RestrictDriverInstallationToAdministrators']
  $noWarnInstallValue = $PrintingStatus.Policies['NoWarningNoElevationOnInstall']
  $noWarnUpdateValue = $PrintingStatus.Policies['NoWarningNoElevationOnUpdate']
  $updatePromptValue = $PrintingStatus.Policies['UpdatePromptSettings']
  $restrictEnabled = ($restrictValue -eq 1 -or $restrictValue -eq $true)
  $promptsSuppressed = $false
  if ($noWarnInstallValue -eq 1 -or $noWarnInstallValue -eq $true) { $promptsSuppressed = $true }
  if ($noWarnUpdateValue -eq 1 -or $noWarnUpdateValue -eq $true) { $promptsSuppressed = $true }
  if ($updatePromptValue -is [int]) {
    if ($updatePromptValue -ge 2) { $promptsSuppressed = $true }
  } elseif ($updatePromptValue -eq 2 -or $updatePromptValue -eq $true) {
    $promptsSuppressed = $true
  }
  if (-not $restrictEnabled -and $promptsSuppressed) {
    $policyEvidence = @()
    $policyEvidence += "RestrictDriverInstallationToAdministrators=$restrictValue"
    if ($null -ne $noWarnInstallValue) { $policyEvidence += "NoWarningNoElevationOnInstall=$noWarnInstallValue" }
    if ($null -ne $noWarnUpdateValue) { $policyEvidence += "NoWarningNoElevationOnUpdate=$noWarnUpdateValue" }
    if ($null -ne $updatePromptValue) { $policyEvidence += "UpdatePromptSettings=$updatePromptValue" }
    Add-Issue 'high' 'Printing/Policies' 'Point and Print restrictions are disabled while install/update prompts are suppressed.' ($policyEvidence -join "`n")
  }

  if ($PrintingEventRecords) {
    $adminErrors = @($PrintingEventRecords | Where-Object { $_.LogName -and $_.LogName -match 'PrintService/Admin' -and (($_.Level -eq 2) -or ($_.LevelDisplayName -match '(?i)error')) })
    $adminErrorCount = $adminErrors.Count

    if ($adminErrorCount -gt 5) {
      $samples = $adminErrors | Sort-Object TimeCreated -Descending | Select-Object -First 5
      $evidence = $samples | ForEach-Object {
        $timeLabel = if ($_.TimeCreated) { $_.TimeCreated.ToString('s') } else { 'unknown' }
        "{0} | ID {1} | {2}" -f $timeLabel, $_.EventId, ($_.Message -replace '\r?\n',' ')
      }
      Add-Issue 'medium' 'Printing/Events' ("PrintService/Admin log shows {0} error events in the last 7 days." -f $adminErrorCount) ($evidence -join "`n")
    }

    $driverRelated = @($PrintingEventRecords | Where-Object { $_.Message -and ($_.Message -match '(?i)driver') -and ($_.Message -match '(?i)(failed|fault|crash|stopp|hang)') })
    $driverCrashGroups = @($driverRelated | Group-Object EventId | Where-Object { $_.Count -ge 3 })
    if ($driverCrashGroups.Count -gt 0) {
      $driverEvidence = @()
      foreach ($group in $driverCrashGroups) {
        $latest = $group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $timeLabel = if ($latest.TimeCreated) { $latest.TimeCreated.ToString('s') } else { 'unknown' }
        $driverEvidence += "Event ID {0} occurred {1} times; latest at {2}. Message: {3}" -f $group.Name, $group.Count, $timeLabel, ($latest.Message -replace '\r?\n',' ')
      }
      Add-Issue 'high' 'Printing/Events' 'Repeated print driver crash events detected.' ($driverEvidence -join "`n`n")
    }

    if ($PrintingEventRecords.Count -gt 0 -and $adminErrorCount -eq 0 -and $driverCrashGroups.Count -eq 0) {
      $logsCaptured = ($PrintingEventRecords | Select-Object -ExpandProperty LogName -Unique | Where-Object { $_ } | Sort-Object)
      $logSummary = if ($logsCaptured.Count -gt 0) { $logsCaptured -join ', ' } else { 'PrintService' }
      Add-Normal 'Printing/Events' 'GOOD Printing/Events (no recent errors)' ("Logs analyzed: {0}" -f $logSummary)
    }
  }
}
