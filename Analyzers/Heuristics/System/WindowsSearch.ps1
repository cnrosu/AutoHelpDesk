function Invoke-SystemWindowsSearchChecks {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Result
    )

    Write-HeuristicDebug -Source 'System/WindowsSearch' -Message 'Evaluating Windows Search indexing signals'

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'windows-search'
    if (-not $artifact) {
        Write-HeuristicDebug -Source 'System/WindowsSearch' -Message 'windows-search artifact not found; skipping checks'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Windows Search snapshot missing, so indexing health is unknown.' -Evidence 'windows-search.json payload was empty or malformed.' -Subcategory 'Windows Search Indexing'
        return
    }

    if ($payload.PSObject.Properties['Error'] -and $payload.Error) {
        $evidence = "Collector reported error: {0}" -f $payload.Error
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Windows Search snapshot failed to collect, so indexing health is unknown.' -Evidence $evidence -Subcategory 'Windows Search Indexing'
        return
    }

    $snapshot = $payload

    if ($snapshot.Index) {
        $indexPath = if ($snapshot.Index.PSObject.Properties['Path']) { [string]$snapshot.Index.Path } else { '(unknown)' }
        Add-CategoryCheck -CategoryResult $Result -Name 'Windows Search index path' -Status $indexPath

        if ($snapshot.Index.PSObject.Properties['SizeBytes'] -and $null -ne $snapshot.Index.SizeBytes) {
            $sizeGb = [math]::Round(($snapshot.Index.SizeBytes / 1GB), 2)
            Add-CategoryCheck -CategoryResult $Result -Name 'Windows Search catalog size (GB)' -Status ([string]$sizeGb)
        }

        if ($snapshot.Index.PSObject.Properties['DriveFreePct'] -and $null -ne $snapshot.Index.DriveFreePct) {
            Add-CategoryCheck -CategoryResult $Result -Name 'Index volume free space (%)' -Status ([string]$snapshot.Index.DriveFreePct)
        }
    }

    if ($snapshot.Events) {
        $errorCount = if ($snapshot.Events.PSObject.Properties['ErrorCount']) { [int]$snapshot.Events.ErrorCount } else { 0 }
        Add-CategoryCheck -CategoryResult $Result -Name 'Windows Search errors (48h)' -Status ([string]$errorCount)
    }

    $serviceStatus = $null
    $startType = $null
    if ($snapshot.Service) {
        if ($snapshot.Service.PSObject.Properties['Status']) { $serviceStatus = [string]$snapshot.Service.Status }
        if ($snapshot.Service.PSObject.Properties['StartType']) { $startType = [string]$snapshot.Service.StartType }
    }

    $sizeBytes = $null
    if ($snapshot.Index -and $snapshot.Index.PSObject.Properties['SizeBytes'] -and $null -ne $snapshot.Index.SizeBytes) {
        try { $sizeBytes = [long]$snapshot.Index.SizeBytes } catch { $sizeBytes = $null }
    }

    $driveFreePct = $null
    if ($snapshot.Index -and $snapshot.Index.PSObject.Properties['DriveFreePct'] -and $null -ne $snapshot.Index.DriveFreePct) {
        try { $driveFreePct = [double]$snapshot.Index.DriveFreePct } catch { $driveFreePct = $null }
    }

    $criticalCatalogThresholdBytes = [long](2 * 1024 * 1024 * 1024)
    $largeCatalogThresholdBytes    = [long](6 * 1024 * 1024 * 1024)

    $serviceRunning = ($serviceStatus -eq 'Running')
    $startDisabled = ($startType -eq 'Disabled')

    if (-not $serviceRunning -or $startDisabled -or -not $snapshot.Service) {
        $title = 'Windows Search indexing is stopped, so Start menu and Outlook searches will miss results.'
        $statusSummary = "Service status: {0}; Startup type: {1}" -f $(if ($serviceStatus) { $serviceStatus } else { 'Unknown' }), $(if ($startType) { $startType } else { 'Unknown' })
        $details = [ordered]@{
            ServiceStatus = $serviceStatus
            StartType     = $startType
        }
        $evidence = @(
            $statusSummary
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Set the Windows Search (WSearch) service startup type to Automatic (Delayed Start).',
            'Start-Service WSearch or reboot the device to restore indexing.',
            'Review Microsoft-Windows-Search/Operational errors and rebuild the index if the service fails to stay running.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    $errorThreshold = 10
    $errorCountValue = if ($snapshot.Events -and $snapshot.Events.PSObject.Properties['ErrorCount']) { [int]$snapshot.Events.ErrorCount } else { 0 }
    if ($errorCountValue -ge $errorThreshold) {
        $title = 'Windows Search index is throwing repeated errors, so catalog corruption or resets are likely.'
        $lookbackHours = if ($snapshot.Events.PSObject.Properties['LookbackHours']) { [int]$snapshot.Events.LookbackHours } else { 48 }
        $summary = "Error events in last {0}h: {1}" -f $lookbackHours, $errorCountValue
        $details = [ordered]@{
            ErrorCount    = $errorCountValue
            LookbackHours = $lookbackHours
        }
        $evidence = @(
            $summary
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Open Event Viewer → Applications and Services Logs → Microsoft → Windows → Search → Operational and inspect recurring IDs.',
            'Use Settings → Search → Searching Windows → Advanced indexing options → Advanced → Rebuild to repair the catalog.',
            'Confirm the index location resides on a healthy, online drive with sufficient space.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    if ($snapshot.Index -and $snapshot.Index.PSObject.Properties['PathExists'] -and $snapshot.Index.PathExists -eq $false) {
        $title = 'Windows Search index path is offline, so the catalog cannot load or answer queries.'
        $indexPathValue = if ($snapshot.Index.PSObject.Properties['Path']) { [string]$snapshot.Index.Path } else { $null }
        $displayPath = if ($indexPathValue) { $indexPathValue } else { '(unknown)' }
        $details = [ordered]@{
            IndexPath = $indexPathValue
        }
        $evidence = @(
            "Configured index path: {0}" -f $displayPath
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Move the Windows Search index back to a healthy local drive (Advanced indexing options → Advanced → Index location).',
            'Restore connectivity to the catalog drive before restarting the WSearch service.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    if ($sizeBytes -ne $null -and $sizeBytes -gt $criticalCatalogThresholdBytes -and $driveFreePct -ne $null -and $driveFreePct -lt 5) {
        $title = 'Windows Search catalog is large and the system drive is nearly full, so indexing failures and crashes are imminent.'
        $summary = "Catalog size: {0:N2} GB; Drive free: {1}%" -f ($sizeBytes / 1GB), $driveFreePct
        $details = [ordered]@{
            IndexSizeBytes   = $sizeBytes
            DriveFreePercent = $driveFreePct
        }
        $evidence = @(
            $summary
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Free disk space on the system volume hosting the Windows Search index.',
            'Relocate the index to a drive with ample capacity and rebuild after the move.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    $pauseReason = if ($snapshot.PSObject.Properties['PauseReason']) { $snapshot.PauseReason } else { $null }
    $indexerStatus = if ($snapshot.PSObject.Properties['IndexerStatus']) { $snapshot.IndexerStatus } else { $null }
    $batterySaver = if ($snapshot.PSObject.Properties['BatterySaver']) { [bool]$snapshot.BatterySaver } else { $false }
    $pauseDetected = ($pauseReason -ne $null -and $pauseReason -ne 0) -or ($indexerStatus -eq 4)
    if ($pauseDetected -and -not $batterySaver) {
        $title = 'Windows Search indexing appears paused, so new files are not being added to results.'
        $summary = "IndexerStatus: {0}; PauseReason: {1}" -f $(if ($indexerStatus -ne $null) { $indexerStatus } else { 'Unknown' }), $(if ($pauseReason -ne $null) { $pauseReason } else { 'None' })
        $details = [ordered]@{
            IndexerStatus = $indexerStatus
            PauseReason   = $pauseReason
            BatterySaver  = $batterySaver
        }
        $evidence = @(
            $summary
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Disable Battery Saver or connected standby throttling and leave the device on AC power.',
            'Avoid heavy I/O workloads so the indexer can resume crawling.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    $urlsToCrawl = 0
    $crawlRate = 0
    if ($snapshot.PSObject.Properties['PerfCounters'] -and $snapshot.PerfCounters) {
        $urlKeys = $snapshot.PerfCounters.Keys | Where-Object { $_ -like '*\\URLs to be crawled*' }
        foreach ($key in $urlKeys) { $urlsToCrawl += [int]$snapshot.PerfCounters[$key] }

        $crawlKeys = $snapshot.PerfCounters.Keys | Where-Object { $_ -like '*\\Crawl rate*' }
        foreach ($key in $crawlKeys) { $crawlRate += [int]$snapshot.PerfCounters[$key] }
    }

    if ($urlsToCrawl -gt 5000 -and $crawlRate -lt 5) {
        $title = 'Windows Search has a large indexing backlog, so users will see stale search results.'
        $summary = "URLs queued: {0}; Crawl rate: {1}" -f $urlsToCrawl, $crawlRate
        $details = [ordered]@{
            UrlsToCrawl = $urlsToCrawl
            CrawlRate   = $crawlRate
        }
        $evidence = @(
            $summary
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Leave the device idle on AC power to let the indexer catch up.',
            'Exclude noisy developer folders or temp data that constantly changes.',
            'Rebuild the index if the backlog never clears.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    if ($snapshot.Policy -and $snapshot.Policy.PSObject.Properties['PreventIndexingUserFolders'] -and $snapshot.Policy.PreventIndexingUserFolders -eq 1) {
        $title = 'User profile folders are excluded from indexing, so Documents/Desktop searches miss files.'
        $details = [ordered]@{
            PreventIndexingUserFolders = 1
        }
        $evidence = @(
            'Group Policy PreventIndexingUserFolders is enabled.'
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Review the PreventIndexingUserFolders policy in Group Policy or Intune.',
            'Allow Documents, Desktop, and Pictures to be indexed when users rely on Windows Search.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    if ($sizeBytes -ne $null -and $sizeBytes -gt $largeCatalogThresholdBytes) {
        $title = 'Windows Search catalog is very large, so it consumes significant disk space.'
        $summary = "Catalog size: {0:N2} GB" -f ($sizeBytes / 1GB)
        $details = [ordered]@{
            IndexSizeBytes = $sizeBytes
        }
        $evidence = @(
            $summary
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = @(
            'Trim noisy folders (build outputs, node_modules, .git) from the index scope.',
            'Compact or rebuild the index during maintenance windows to reclaim space.'
        ) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    if ($snapshot.PSObject.Properties['EnablePerUserCatalog'] -and $snapshot.EnablePerUserCatalog -eq 1) {
        $title = 'Per-user Windows Search catalogs are enabled, so disk usage will grow for each profile.'
        $details = [ordered]@{
            EnablePerUserCatalog = 1
        }
        $evidence = @(
            'EnablePerUserCatalog registry value is 1.'
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = 'No action typically required; monitor disk usage when many profiles share the device.'
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }

    if ($batterySaver) {
        $title = 'Battery Saver is throttling Windows Search, so slower indexing is expected on battery.'
        $details = [ordered]@{
            BatterySaver = $true
        }
        $evidence = @(
            'Battery Saver registry flag indicates throttling is active.'
            'Details:'
            ($details | ConvertTo-Json -Depth 3)
        ) -join "`n"
        $remediation = 'Connect the device to AC power or disable Battery Saver to restore full indexing speed.'
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Windows Search Indexing' -Remediation $remediation
    }
}
