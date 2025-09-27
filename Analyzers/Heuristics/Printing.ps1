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
        $items = @()
        foreach ($item in $Value) { $items += $item }
        return $items
    }
    return @($Value)
}

function Invoke-PrintingHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Printing'

    $printingArtifact = Get-AnalyzerArtifact -Context $Context -Name 'printing'
    if (-not $printingArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Printing artifact not collected' -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $printingArtifact)
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Printing payload missing' -Subcategory 'Collection'
        return $result
    }

    if ($payload.Errors) {
        foreach ($error in $payload.Errors) {
            if ($error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Printing data collection warning' -Evidence $error -Subcategory 'Collection'
            }
        }
    }

    if ($payload.Spooler) {
        $spooler = $payload.Spooler
        if ($spooler.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Print Spooler state unavailable' -Evidence $spooler.Error -Subcategory 'Spooler Service'
        } else {
            $status = if ($spooler.Status) { [string]$spooler.Status } else { 'Unknown' }
            $startMode = if ($spooler.StartMode) { [string]$spooler.StartMode } else { $spooler.StartType }
            Add-CategoryCheck -CategoryResult $result -Name 'Spooler status' -Status $status -Details ("StartMode: {0}" -f $startMode)
            if ($status -notmatch '(?i)running') {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Print Spooler not running' -Evidence ("Status: {0}; StartMode: {1}" -f $status, $startMode) -Subcategory 'Spooler Service'
            } elseif ($startMode -and $startMode -notmatch '(?i)auto') {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Spooler start mode not automatic' -Evidence ("Current mode: {0}" -f $startMode) -Subcategory 'Spooler Service'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Print Spooler running — disable if this workstation does not need printing.' -Subcategory 'Spooler Service'
            }
        }
    }

    $defaultPrinter = $payload.DefaultPrinter
    $offlinePrinters = @()
    $wsdPrinters = @()
    $stuckJobs = @()
    $printers = ConvertTo-PrintingArray $payload.Printers

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
            $offlinePrinters += $name
            if ($defaultPrinter -and $name -eq $defaultPrinter) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Default printer offline' -Evidence $name -Subcategory 'Printers'
            } else {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Printer offline: {0}' -f $name) -Subcategory 'Printers'
            }
        }

        if ($printer.Connection -and $printer.Connection.Kind -eq 'WSD') {
            $wsdPrinters += $name
        }

        if ($printer.Jobs) {
            foreach ($job in $printer.Jobs) {
                if (-not $job) { continue }
                if ($job.AgeMinutes -and $job.AgeMinutes -gt 60) {
                    $severity = if ($job.AgeMinutes -ge 240) { 'high' } else { 'medium' }
                    $jobName = if ($job.DocumentName) { [string]$job.DocumentName } elseif ($job.PSObject.Properties['Id']) { "Job $($job.Id)" } else { 'Print job' }
                    $ageRounded = [math]::Round($job.AgeMinutes,1)
                    $stuckJobs += ("{0} ({1} min old)" -f $jobName, $ageRounded)
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title ('Stale print job detected on {0}' -f $name) -Evidence (("{0} age {1} minutes" -f $jobName, $ageRounded)) -Subcategory 'Queues'
                }
            }
        }
    }

    if ($stuckJobs.Count -gt 0) {
        Add-CategoryCheck -CategoryResult $result -Name 'Stale print jobs' -Status ([string]$stuckJobs.Count) -Details ($stuckJobs -join '; ')
    }

    if ($wsdPrinters.Count -gt 0) {
        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ('Printers using WSD ports: {0}' -f ($wsdPrinters -join ', ')) -Evidence 'WSD ports are less reliable for enterprise printing; prefer Standard TCP/IP.' -Subcategory 'Printers'
    }

    if ($payload.Events) {
        $events = $payload.Events
        if ($events.Admin) {
            $admin = $events.Admin
            Add-CategoryCheck -CategoryResult $result -Name 'PrintService/Admin errors' -Status ([string]$admin.ErrorCount)
            if ($admin.ErrorCount -gt 0) {
                $severity = if ($admin.ErrorCount -ge 5) { 'high' } else { 'medium' }
                $driverCrashEvidence = 'None'
                if ($admin.PSObject.Properties['DriverCrashCount'] -and $null -ne $admin.DriverCrashCount) {
                    if ($admin.DriverCrashCount -is [System.Collections.IDictionary]) {
                        $entries = @()
                        foreach ($kvp in $admin.DriverCrashCount.GetEnumerator()) {
                            if ($kvp) { $entries += ("{0}={1}" -f $kvp.Key, $kvp.Value) }
                        }
                        if ($entries.Count -gt 0) { $driverCrashEvidence = $entries -join ', ' }
                    } else {
                        $driverCrashEvidence = [string]$admin.DriverCrashCount
                    }
                }
                $evidence = "Errors: {0}; Driver crash IDs: {1}" -f $admin.ErrorCount, $driverCrashEvidence
                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'PrintService Admin log reporting errors' -Evidence $evidence -Subcategory 'Event Logs'
            }
        }
        if ($events.Operational) {
            $op = $events.Operational
            Add-CategoryCheck -CategoryResult $result -Name 'PrintService/Operational warnings' -Status ([string]$op.WarningCount)
            if ($op.ErrorCount -gt 10) {
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'PrintService Operational log has frequent errors' -Evidence ("Errors: {0}" -f $op.ErrorCount) -Subcategory 'Event Logs'
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
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ('Printer host connectivity test failed ({0})' -f $testGroup.Host) -Evidence $evidence -Subcategory 'Network Tests'
                }
            }
        }
    }

    if ($printers.Count -gt 0 -and $offlinePrinters.Count -eq 0) {
        Add-CategoryNormal -CategoryResult $result -Title ('Printers online ({0})' -f $printers.Count)
    }

    return $result
}
