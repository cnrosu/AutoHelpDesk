<#!
.SYNOPSIS
    Printing heuristics that mirror AutoL1 diagnostics for spooler health, queue posture, and event volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Common.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Platform.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Spooler.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Inventory.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Events.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/NetworkTests.ps1')

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
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title "Printing artifact not collected, so printing security and reliability risks can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $printingArtifact)
    Write-HeuristicDebug -Source 'Printing' -Message 'Resolved printing payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title "Printing payload missing, so printing security and reliability risks can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    if ($payload.Errors) {
        foreach ($error in $payload.Errors) {
            if ($error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Printing data collection warning, so printing security and reliability risks may be hidden.' -Evidence $error -Subcategory 'Collection'
            }
        }
    }

    Invoke-PrintingSpoolerChecks -Result $result -Spooler $payload.Spooler -IsWorkstation $isWorkstation

    $inventorySummary = Invoke-PrinterInventoryChecks -Result $result -Payload $payload

    Invoke-PrinterEventChecks -Result $result -Events $payload.Events
    Invoke-PrinterNetworkTestChecks -Result $result -NetworkTests $payload.NetworkTests

    if ($inventorySummary) {
        Write-HeuristicDebug -Source 'Printing' -Message 'Printer analysis summary' -Data ([ordered]@{
            OfflineCount = $inventorySummary.OfflinePrinters.Count
            WsdCount     = $inventorySummary.WsdPrinters.Count
            StaleJobs    = $inventorySummary.StuckJobs.Count
        })

        if ($inventorySummary.Printers.Count -gt 0 -and $inventorySummary.OfflinePrinters.Count -eq 0) {
            Add-CategoryNormal -CategoryResult $result -Title ('Printers online ({0})' -f $inventorySummary.Printers.Count) -Subcategory 'Printers'
        }

        $printers = ConvertTo-PrintingArray $inventorySummary.Printers
        $offlinePrinters = ConvertTo-PrintingArray $inventorySummary.OfflinePrinters
        $wsdPrinters = ConvertTo-PrintingArray $inventorySummary.WsdPrinters

        $queueEntries = [System.Collections.Generic.List[object]]::new()
        $stuckJobEntries = [System.Collections.Generic.List[object]]::new()
        $driverEntries = [System.Collections.Generic.List[object]]::new()
        $driverMap = @{}

        $offlineSummary = [System.Collections.Generic.List[string]]::new()
        $stuckJobSummary = [System.Collections.Generic.List[string]]::new()
        $driverSummary = [System.Collections.Generic.List[string]]::new()

        $offlineHasHighSeverity = $false
        $offlineHasMediumSeverity = $false
        $stuckHasHighSeverity = $false
        $stuckHasMediumSeverity = $false

        foreach ($printer in $printers) {
            if (-not $printer) { continue }

            $printerName = if ($printer.PSObject.Properties['Name']) { [string]$printer.Name } else { $null }
            if (-not $printerName) { continue }

            $isOffline = ($offlinePrinters -contains $printerName)
            $connection = if ($printer.PSObject.Properties['Connection']) { $printer.Connection } else { $null }
            $connectionKind = $null
            $connectionHosts = @()
            $connectionMonitor = $null
            if ($connection) {
                if ($connection.PSObject.Properties['Kind']) { $connectionKind = [string]$connection.Kind }
                if ($connection.PSObject.Properties['PortMonitor']) { $connectionMonitor = [string]$connection.PortMonitor }
                if ($connection.PSObject.Properties['Hosts'] -and $connection.Hosts) {
                    $connectionHosts = @()
                    foreach ($host in (ConvertTo-PrintingArray $connection.Hosts)) {
                        if ($host) { $connectionHosts += [string]$host }
                    }
                }
            }

            $usesWsd = $false
            if ($wsdPrinters -contains $printerName -or ($connectionKind -and $connectionKind -eq 'WSD')) {
                $usesWsd = $true
            }

            $jobEntriesForPrinter = [System.Collections.Generic.List[object]]::new()
            if ($printer.PSObject.Properties['Jobs'] -and $printer.Jobs) {
                foreach ($job in (ConvertTo-PrintingArray $printer.Jobs)) {
                    if (-not $job) { continue }
                    $age = $null
                    if ($job.PSObject.Properties['AgeMinutes'] -and $job.AgeMinutes) {
                        try { $age = [double]$job.AgeMinutes } catch { $age = $null }
                    }
                    if ($age -and $age -gt 60) {
                        $ageRounded = [math]::Round($age, 1)
                        $jobName = if ($job.PSObject.Properties['DocumentName'] -and $job.DocumentName) { [string]$job.DocumentName }
                                   elseif ($job.PSObject.Properties['Id']) { "Job $($job.Id)" }
                                   else { 'Print job' }
                        $submittedBy = $null
                        if ($job.PSObject.Properties['SubmittedBy'] -and $job.SubmittedBy) {
                            $submittedBy = [string]$job.SubmittedBy
                        } elseif ($job.PSObject.Properties['UserName'] -and $job.UserName) {
                            $submittedBy = [string]$job.UserName
                        }
                        $submittedTime = $null
                        if ($job.PSObject.Properties['SubmittedTime'] -and $job.SubmittedTime) {
                            $submittedTime = [string]$job.SubmittedTime
                        }

                        $jobSeverity = if ($age -ge 240) { 'high' } else { 'medium' }
                        if ($jobSeverity -eq 'high') { $stuckHasHighSeverity = $true } else { $stuckHasMediumSeverity = $true }

                        $jobEntry = [ordered]@{
                            Printer     = $printerName
                            Document    = $jobName
                            AgeMinutes  = $ageRounded
                            Severity    = $jobSeverity
                            SubmittedBy = $submittedBy
                        }
                        if ($submittedTime) { $jobEntry['SubmittedTime'] = $submittedTime }

                        $psJobEntry = [pscustomobject]$jobEntry
                        $jobEntriesForPrinter.Add($psJobEntry) | Out-Null
                        $stuckJobEntries.Add($psJobEntry) | Out-Null
                        $stuckJobSummary.Add(("{0}: {1} ({2} min)" -f $printerName, $jobName, $ageRounded)) | Out-Null
                    }
                }
            }

            $hasIssues = $false
            if ($isOffline) {
                $hasIssues = $true
                $offlineSummary.Add($printerName) | Out-Null
                if ($printer.PSObject.Properties['Default'] -and $printer.Default) { $offlineHasHighSeverity = $true } else { $offlineHasMediumSeverity = $true }
            }
            if ($usesWsd) {
                $hasIssues = $true
            }
            if ($jobEntriesForPrinter.Count -gt 0) { $hasIssues = $true }

            if (-not $hasIssues) { continue }

            $queueEntry = [ordered]@{
                Name          = $printerName
                Default       = if ($printer.PSObject.Properties['Default']) { [bool]$printer.Default } else { $false }
                Offline       = $isOffline
                QueueStatus   = if ($printer.PSObject.Properties['QueueStatus']) { [string]$printer.QueueStatus } else { $null }
                PrinterStatus = if ($printer.PSObject.Properties['PrinterStatus']) { [string]$printer.PrinterStatus } else { $null }
                PortName      = if ($printer.PSObject.Properties['PortName']) { [string]$printer.PortName } else { $null }
                DriverName    = if ($printer.PSObject.Properties['DriverName']) { [string]$printer.DriverName } else { $null }
                Connection    = $null
                Jobs          = if ($jobEntriesForPrinter.Count -gt 0) { $jobEntriesForPrinter.ToArray() } else { @() }
            }

            if ($connectionKind -or $connectionMonitor -or $connectionHosts.Count -gt 0) {
                $connectionEntry = [ordered]@{}
                if ($connectionKind) { $connectionEntry['Kind'] = $connectionKind }
                if ($connectionMonitor) { $connectionEntry['PortMonitor'] = $connectionMonitor }
                if ($connectionHosts.Count -gt 0) { $connectionEntry['Hosts'] = $connectionHosts }
                $queueEntry['Connection'] = [pscustomobject]$connectionEntry
            }

            $queueEntries.Add([pscustomobject]$queueEntry) | Out-Null

            $driverName = if ($printer.PSObject.Properties['DriverName']) { [string]$printer.DriverName } else { $null }
            $driverObject = if ($printer.PSObject.Properties['Driver']) { $printer.Driver } else { $null }

            if ($driverName -or $driverObject) {
                $driverDetails = [ordered]@{
                    Name        = $null
                    Provider    = $null
                    Version     = $null
                    Date        = $null
                    Environment = $null
                    Inf         = $null
                    Queues      = New-Object System.Collections.Generic.List[string]
                }

                if ($driverName) { $driverDetails['Name'] = $driverName }
                if ($driverObject) {
                    if ($driverObject.PSObject.Properties['Name'] -and -not $driverDetails['Name']) { $driverDetails['Name'] = [string]$driverObject.Name }
                    if ($driverObject.PSObject.Properties['DriverProvider']) { $driverDetails['Provider'] = [string]$driverObject.DriverProvider }
                    if ($driverObject.PSObject.Properties['DriverVersion']) { $driverDetails['Version'] = [string]$driverObject.DriverVersion }
                    if ($driverObject.PSObject.Properties['DriverDate']) { $driverDetails['Date'] = [string]$driverObject.DriverDate }
                    if ($driverObject.PSObject.Properties['Environment']) { $driverDetails['Environment'] = [string]$driverObject.Environment }
                    elseif ($driverObject.PSObject.Properties['DriverEnv']) { $driverDetails['Environment'] = [string]$driverObject.DriverEnv }
                    if ($driverObject.PSObject.Properties['InfName']) { $driverDetails['Inf'] = [string]$driverObject.InfName }
                }

                $driverNameValue = if ($driverDetails['Name']) { [string]$driverDetails['Name'] } else { '' }
                $driverProviderValue = if ($driverDetails['Provider']) { [string]$driverDetails['Provider'] } else { '' }
                $driverVersionValue = if ($driverDetails['Version']) { [string]$driverDetails['Version'] } else { '' }
                $driverDateValue = if ($driverDetails['Date']) { [string]$driverDetails['Date'] } else { '' }
                $driverEnvironmentValue = if ($driverDetails['Environment']) { [string]$driverDetails['Environment'] } else { '' }
                $driverInfValue = if ($driverDetails['Inf']) { [string]$driverDetails['Inf'] } else { '' }

                $driverKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f @(
                    $driverNameValue,
                    $driverProviderValue,
                    $driverVersionValue,
                    $driverDateValue,
                    $driverEnvironmentValue,
                    $driverInfValue
                )

                if ($driverMap.ContainsKey($driverKey)) {
                    $existing = $driverMap[$driverKey]
                } else {
                    $existing = $driverDetails
                    $driverMap[$driverKey] = $existing
                }

                if (-not $existing.Queues.Contains($printerName)) {
                    $existing.Queues.Add($printerName) | Out-Null
                }

                $driverDisplayName = $existing['Name']
                if ($driverDisplayName -and -not $driverSummary.Contains($driverDisplayName)) {
                    $driverSummary.Add($driverDisplayName) | Out-Null
                }
            }
        }

        foreach ($driverEntry in $driverMap.Values) {
            $driverObject = [ordered]@{
                Name        = $driverEntry['Name']
                Provider    = $driverEntry['Provider']
                Version     = $driverEntry['Version']
                Date        = $driverEntry['Date']
                Environment = $driverEntry['Environment']
                Inf         = $driverEntry['Inf']
                Queues      = $driverEntry.Queues.ToArray()
            }
            $driverEntries.Add([pscustomobject]$driverObject) | Out-Null
        }

        $queueArray = $queueEntries.ToArray()

        if ($offlineSummary.Count -gt 0) {
            $offlineSeverity = if ($offlineHasHighSeverity) { 'high' } elseif ($offlineHasMediumSeverity) { 'medium' } else { 'low' }
            $offlineEvidence = "Offline queues: {0}" -f ($offlineSummary.ToArray() -join ', ')
            $offlineQueues = @($queueArray | Where-Object { $_.Offline })
            Add-CategoryIssue -CategoryResult $result -Severity $offlineSeverity -Title 'Printer queues offline, so print jobs cannot reach the device.' -Evidence $offlineEvidence -Subcategory 'Printing' -Data @{
                Area = 'Printing'
                Kind = 'PrintQueueOutage'
                Queues = $offlineQueues
            }
        }

        if ($stuckJobEntries.Count -gt 0) {
            $stuckSeverity = if ($stuckHasHighSeverity) { 'high' } elseif ($stuckHasMediumSeverity) { 'medium' } else { 'low' }
            $stuckEvidence = "Stuck jobs: {0}" -f ($stuckJobSummary.ToArray() -join '; ')
            Add-CategoryIssue -CategoryResult $result -Severity $stuckSeverity -Title 'Stuck print jobs delaying documents, so users wait hours for output.' -Evidence $stuckEvidence -Subcategory 'Printing' -Data @{
                Area = 'Printing'
                Kind = 'PrintJobs'
                StuckJobs = $stuckJobEntries.ToArray()
            }
        }

        if ($driverEntries.Count -gt 0 -and ($offlineSummary.Count -gt 0 -or $stuckJobEntries.Count -gt 0)) {
            $driverEvidence = "Drivers linked to affected queues: {0}" -f ($driverSummary.ToArray() -join ', ')
            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Printer driver packages tied to troubled queues, so driver conflicts may disrupt printing.' -Evidence $driverEvidence -Subcategory 'Printing' -Data @{
                Area = 'Printing'
                Kind = 'PrintDrivers'
                Drivers = $driverEntries.ToArray()
                Queues = $queueArray
            }
        }
    }

    return $result
}
