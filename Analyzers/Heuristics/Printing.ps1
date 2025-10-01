<#!
.SYNOPSIS
    Printing heuristics that mirror AutoL1 diagnostics for spooler health, queue posture, and event volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-PrintingArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $itemsList = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) { $itemsList.Add($item) | Out-Null }
        return $itemsList.ToArray()
    }
    return @($Value)
}

function Get-PrintingPlatformInfo {
    param($Context)

    $isWindowsServer = $null
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload -and $payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
            $caption = [string]$payload.OperatingSystem.Caption
            if ($caption) {
                $isWindowsServer = ($caption -match '(?i)windows\s+server')
            }
        }
    }

    $isWorkstation = $null
    if ($isWindowsServer -eq $true) { $isWorkstation = $false }
    elseif ($isWindowsServer -eq $false) { $isWorkstation = $true }

    return [pscustomobject]@{
        IsWindowsServer = $isWindowsServer
        IsWorkstation   = $isWorkstation
    }
}

function Normalize-PrintingServiceState {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -like 'run*') { return 'running' }
    if ($lower -like 'stop*') { return 'stopped' }
    return 'other'
}

function Invoke-PrintingHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Printing' -Message 'Starting printing heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Printing'
    $platform = Get-PrintingPlatformInfo -Context $Context
    $isWorkstation = ($platform.IsWorkstation -eq $true)
    Write-HeuristicDebug -Source 'Printing' -Message 'Resolved platform information' -Data ([ordered]@{
        IsServer      = $platform.IsWindowsServer
        IsWorkstation = $platform.IsWorkstation
    })

    $printingArtifact = Get-AnalyzerArtifact -Context $Context -Name 'printing'
    Write-HeuristicDebug -Source 'Printing' -Message 'Resolved printing artifact' -Data ([ordered]@{
        Found = [bool]$printingArtifact
    })
    if (-not $printingArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Printing artifact not collected, so printing security and reliability risks can’t be evaluated.' -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $printingArtifact)
    Write-HeuristicDebug -Source 'Printing' -Message 'Resolved printing payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Printing payload missing, so printing security and reliability risks can’t be evaluated.' -Subcategory 'Collection'
        return $result
    }

    if ($payload.Errors) {
        foreach ($error in $payload.Errors) {
            if ($error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Printing data collection warning, so printing security and reliability risks may be hidden.' -Evidence $error -Subcategory 'Collection'
            }
        }
    }

    if ($payload.Spooler) {
        $spooler = $payload.Spooler
        if ($spooler.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Print Spooler state unavailable, so printing security and reliability risks can’t be evaluated.' -Evidence $spooler.Error -Subcategory 'Spooler Service'
        } else {
            $status = if ($spooler.Status) { [string]$spooler.Status } else { 'Unknown' }
            $startMode = if ($spooler.StartMode) { [string]$spooler.StartMode } else { $spooler.StartType }
            $statusNorm = Normalize-PrintingServiceState -Value $status
            Add-CategoryCheck -CategoryResult $result -Name 'Spooler status' -Status $status -Details ("StartMode: {0}" -f $startMode)
            if ($statusNorm -eq 'running') {
                if ($isWorkstation) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Print Spooler running — disable if this workstation does not need printing (PrintNightmare).' -Evidence ("Status: {0}; StartMode: {1}" -f $status, $startMode) -Subcategory 'Spooler Service'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title 'Print Spooler running' -Evidence ("Status: {0}; StartMode: {1}" -f $status, $startMode) -Subcategory 'Spooler Service'
                }
            } else {
                $note = if ($isWorkstation) { 'PrintNightmare guidance: disable spooler unless required.' } else { 'Printing will remain offline until the spooler is started.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Print Spooler not running, exposing printing security and reliability risks until resolved.' -Evidence ("Status: {0}; StartMode: {1}; Note: {2}" -f $status, $startMode, $note) -Subcategory 'Spooler Service'
            }
        }
    }

    $defaultPrinter = $payload.DefaultPrinter
    $offlinePrintersList = New-Object System.Collections.Generic.List[object]
    $wsdPrintersList = New-Object System.Collections.Generic.List[object]
    $stuckJobsList = New-Object System.Collections.Generic.List[object]
    $printers = ConvertTo-PrintingArray $payload.Printers
    Write-HeuristicDebug -Source 'Printing' -Message 'Analyzing printer inventory' -Data ([ordered]@{
        PrinterCount = $printers.Count
        Default      = $defaultPrinter
    })

    foreach ($printer in $printers) {
        if (-not $printer) { continue }
        $name = [string]$printer.Name
        $status = if ($printer.PrinterStatus) { [string]$printer.PrinterStatus } else { '' }
        $queueStatus = if ($printer.QueueStatus) { [string]$printer.QueueStatus } else { '' }
        $offline = $false
        if ($printer.PSObject.Properties['WorkOffline']) {
            try { if ([bool]$printer.WorkOffline) { $offline = $true } } catch { }
        }
        if (-not $offline -and ($status -match '(?i)offline' -or $queueStatus -match '(?i)offline')) { $offline = $true }
        if ($offline) {
            $offlinePrintersList.Add($name) | Out-Null
            if ($defaultPrinter -and $name -eq $defaultPrinter) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Default printer offline, exposing printing security and reliability risks.' -Evidence $name -Subcategory 'Printers'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Printer offline: {0}, exposing printing security and reliability risks.' -f $name) -Subcategory 'Printers'
            }
        }

        if ($printer.Connection -and $printer.Connection.Kind -eq 'WSD') {
            $wsdPrintersList.Add($name) | Out-Null
        }

        if ($printer.Jobs) {
            foreach ($job in $printer.Jobs) {
                if (-not $job) { continue }
                if ($job.AgeMinutes -and $job.AgeMinutes -gt 60) {
                    $severity = if ($job.AgeMinutes -ge 240) { 'high' } else { 'medium' }
                    $jobName = if ($job.DocumentName) { [string]$job.DocumentName } elseif ($job.PSObject.Properties['Id']) { "Job $($job.Id)" } else { 'Print job' }
                    $ageRounded = [math]::Round($job.AgeMinutes,1)
                    $stuckJobsList.Add(("{0} ({1} min old)" -f $jobName, $ageRounded)) | Out-Null
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ('Stale print job detected on {0}, exposing printing security and reliability risks.' -f $name) -Evidence (("{0} age {1} minutes" -f $jobName, $ageRounded)) -Subcategory 'Queues'
                }
            }
        }
    }

    $offlinePrinters = $offlinePrintersList.ToArray()
    $wsdPrinters = $wsdPrintersList.ToArray()
    $stuckJobs = $stuckJobsList.ToArray()

    Write-HeuristicDebug -Source 'Printing' -Message 'Printer analysis summary' -Data ([ordered]@{
        OfflineCount = $offlinePrinters.Count
        WsdCount     = $wsdPrinters.Count
        StaleJobs    = $stuckJobs.Count
    })

    if ($stuckJobs.Count -gt 0) {
        Add-CategoryCheck -CategoryResult $result -Name 'Stale print jobs' -Status ([string]$stuckJobs.Count) -Details ($stuckJobs -join '; ')
    }

    if ($wsdPrinters.Count -gt 0) {
        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ('Printers using WSD ports: {0}, exposing printing security and reliability risks.' -f ($wsdPrinters -join ', ')) -Evidence 'WSD ports are less reliable for enterprise printing; prefer Standard TCP/IP.' -Subcategory 'Printers'
    }

    if ($payload.Events) {
        $events = $payload.Events
        if ($events.Admin) {
            $admin = $events.Admin
            Add-CategoryCheck -CategoryResult $result -Name 'PrintService/Admin errors' -Status ([string]$admin.ErrorCount)
            if ($admin.ErrorCount -gt 0) {
                $severity = if ($admin.ErrorCount -ge 5) { 'high' } else { 'medium' }
                $driverCrashSummaries = [System.Collections.Generic.List[string]]::new()
                foreach ($entry in $admin.DriverCrashCount.GetEnumerator()) {
                    $null = $driverCrashSummaries.Add(("{0}={1}" -f $entry.Key, $entry.Value))
                }

                $evidence = "Errors: {0}; Driver crash IDs: {1}" -f $admin.ErrorCount, ($driverCrashSummaries -join ', ')
                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'PrintService Admin log reporting errors, exposing printing security and reliability risks.' -Evidence $evidence -Subcategory 'Event Logs'
            }
        }
        if ($events.Operational) {
            $op = $events.Operational
            Add-CategoryCheck -CategoryResult $result -Name 'PrintService/Operational warnings' -Status ([string]$op.WarningCount)
            if ($op.ErrorCount -gt 10) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'PrintService Operational log has frequent errors, exposing printing security and reliability risks.' -Evidence ("Errors: {0}" -f $op.ErrorCount) -Subcategory 'Event Logs'
            }
        }
    }

    if ($payload.NetworkTests) {
        foreach ($testGroup in (ConvertTo-PrintingArray $payload.NetworkTests)) {
            if (-not $testGroup) { continue }
            foreach ($test in (ConvertTo-PrintingArray $testGroup.Tests)) {
                if (-not $test) { continue }
                if ($test.Success -eq $false -or $test.Error) {
                    $evidence = "Host: {0}; Test: {1}; Error: {2}" -f $testGroup.Host, $test.Name, ($test.Error ? $test.Error : 'Connection failure')
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Printer host connectivity test failed ({0}), exposing printing security and reliability risks.' -f $testGroup.Host) -Evidence $evidence -Subcategory 'Network Tests'
                }
            }
        }
    }

    if ($printers.Count -gt 0 -and $offlinePrinters.Count -eq 0) {
        Add-CategoryNormal -CategoryResult $result -Title ('Printers online ({0})' -f $printers.Count) -Subcategory 'Printers'
    }

    return $result
}
