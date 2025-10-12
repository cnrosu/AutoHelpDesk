function Invoke-PrinterInventoryChecks {
    param(
        [Parameter(Mandatory)]
        $Result,
        [Parameter(Mandatory)]
        $Payload
    )

    $defaultPrinter = $Payload.DefaultPrinter
    $offlinePrintersList = New-Object System.Collections.Generic.List[object]
    $wsdPrintersList = New-Object System.Collections.Generic.List[object]
    $stuckJobsList = New-Object System.Collections.Generic.List[object]
    $printers = ConvertTo-PrintingArray $Payload.Printers

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
                Add-CategoryIssue -CategoryResult $Result -CardId 'Printing/Inventory/default-printer-offline-exposing-printing-security-and-reliability-risks' -Evidence $name -Data @{
                    PrinterName = $name
                    IsDefault   = $true
                }
            } else {
                Add-CategoryIssue -CategoryResult $Result -CardId 'Printing/Inventory/printer-offline-0-exposing-printing-security-and-reliability-risks-f-name' -Data @{
                    PrinterName = $name
                    IsDefault   = $false
                }
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
                    $ageRounded = [math]::Round($job.AgeMinutes, 1)
                    $stuckJobsList.Add(("{0} ({1} min old)" -f $jobName, $ageRounded)) | Out-Null
                    Add-CategoryIssue -CategoryResult $Result -CardId 'Printing/Inventory/stale-print-job-detected-on-0-exposing-printing-security-and-reliability-risks-f-name' -Severity $severity -Evidence (("{0} age {1} minutes" -f $jobName, $ageRounded)) -Data @{
                        PrinterName   = $name
                        JobName       = $jobName
                        JobAgeMinutes = $ageRounded
                        JobSeverity   = $severity
                    }
                }
            }
        }
    }

    $stuckJobs = $stuckJobsList.ToArray()
    if ($stuckJobs.Count -gt 0) {
        Add-CategoryCheck -CategoryResult $Result -Name 'Stale print jobs' -Status ([string]$stuckJobs.Count) -Details ($stuckJobs -join '; ')
    }

    if ($wsdPrintersList.Count -gt 0) {
        Add-CategoryIssue -CategoryResult $Result -CardId 'Printing/Inventory/printers-using-wsd-ports-0-exposing-printing-security-and-reliability-risks-f-wsdprinterslist-join' -Evidence 'WSD ports are less reliable for enterprise printing; prefer Standard TCP/IP.' -Data @{
            PrinterNames = $wsdPrintersList.ToArray()
        }
    }

    return [pscustomobject]@{
        Printers        = $printers
        OfflinePrinters = $offlinePrintersList.ToArray()
        WsdPrinters     = $wsdPrintersList.ToArray()
        StuckJobs       = $stuckJobs
    }
}
