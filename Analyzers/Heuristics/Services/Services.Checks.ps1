$script:CriticalServiceAutostartRemediation = @'
Bring these core network services back online and set them to start automatically so DNS, RPC, SMB, printing, proxy discovery, and background transfers can recover:

```powershell
'Dnscache','NlaSvc','LanmanWorkstation','RpcSs','Spooler','WinHttpAutoProxySvc','BITS' |
  ForEach-Object {
    if (Get-Service $_ -ErrorAction SilentlyContinue) {
      Set-Service $_ -StartupType Automatic -ErrorAction SilentlyContinue
      Start-Service $_ -ErrorAction SilentlyContinue
    }
  }
```

If any service is missing entirely, repair Windows components or reinstall the feature before rerunning the snippet.
'@

$script:BitsJobQueueRemediation = @'
If BITS jobs keep failing after the service is running, review and reset the queue:

```cmd
bitsadmin /list /allusers /verbose
bitsadmin /reset /allusers
```

Requeue managed deployments afterwards through Intune, WSUS, or Windows Update so downloads resume.
'@

$script:BitsJobFailureRemediation = $script:CriticalServiceAutostartRemediation + "`n`n" + $script:BitsJobQueueRemediation

$script:WorkstationSpoolerDisableRemediation = @'
If this workstation does not require printing, disable the Print Spooler to remove the PrintNightmare attack surface:

```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

Re-enable the spooler only when printing is required and the device is patched.
'@

function Invoke-ServiceCheckWindowsSearch {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [bool]$IsWorkstation,
        [bool]$IsServer
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating Windows Search service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'WSearch'

    $windowsSearchRemediationScript = @(
        'Set-Service WSearch -StartupType Automatic',
        'Start-Service WSearch'
    ) -join "`n"
    $workstationMissingRemediation = 'Reinstall Windows Search (Optional Feature) and then set WSearch to Automatic and start it so Windows and Outlook indexing resume.'
    $serverMissingRemediation = 'Install the Windows Search service feature only if this server requires local indexing, and if you enable it set WSearch to Automatic and start it to restore indexing.'
    $workstationRemediation = 'Set Windows Search (WSearch) to Automatic and start it so Windows and Outlook indexing resume.'
    $serverRemediation = 'Only enable Windows Search on servers that need indexing; if this server must index content, set WSearch to Automatic and start it to restore results.'
    if (-not $service.Exists) {
        if ($IsServer) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Windows Search not installed on this server, so interactive sessions cannot index or search local data.' -Evidence 'Service entry not found; install the Search Service feature if this server requires indexing.' -Subcategory 'Windows Search Service' -Remediation $serverMissingRemediation -RemediationScript $windowsSearchRemediationScript
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Windows Search service missing, so local search and Outlook indexing will fail.' -Evidence 'Service entry not found; reinstall the feature to restore indexing.' -Subcategory 'Windows Search Service' -Remediation $workstationMissingRemediation -RemediationScript $windowsSearchRemediationScript
        }
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'Windows Search service running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Windows Search Service'
        return
    }

    $title = "Windows Search service not running (Status: {0}; StartType: {1})." -f $service.Status, $service.StartMode
    if ($service.StartModeNormalized -eq 'manual') {
        if ($IsWorkstation) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Windows Search is set to Manual and stopped, so local search and Outlook indexing are paused.' -Evidence $title -Subcategory 'Windows Search Service' -Remediation $workstationRemediation -RemediationScript $windowsSearchRemediationScript
        } elseif ($IsServer) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Windows Search uses manual start on this server and is stopped, so sessions will not index content until it starts.' -Evidence $title -Subcategory 'Windows Search Service' -Remediation $serverRemediation -RemediationScript $windowsSearchRemediationScript
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Windows Search is set to Manual and stopped, so local search and Outlook indexing are paused.' -Evidence $title -Subcategory 'Windows Search Service' -Remediation $workstationRemediation -RemediationScript $windowsSearchRemediationScript
        }
    } elseif ($service.StartModeNormalized -eq 'disabled') {
        if ($IsServer) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Windows Search disabled on this server, so users cannot search or index local data.' -Evidence $title -Subcategory 'Windows Search Service' -Remediation $serverRemediation -RemediationScript $windowsSearchRemediationScript
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Windows Search disabled, so local search and Outlook indexing will fail.' -Evidence $title -Subcategory 'Windows Search Service' -Remediation $workstationRemediation -RemediationScript $windowsSearchRemediationScript
        }
    } else {
        $remediation = if ($IsServer) { $serverRemediation } else { $workstationRemediation }
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Windows Search not running despite automatic startup, so indexing is broken until the service restarts.' -Evidence $title -Subcategory 'Windows Search Service' -Remediation $remediation -RemediationScript $windowsSearchRemediationScript
    }
}

function Invoke-ServiceCheckDnsClient {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating DNS Client service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'Dnscache'
    if (-not $service.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'DNS Client (Dnscache) service missing' -Evidence 'Service entry not found; DNS resolution will fail.' -Subcategory 'DNS Client Service' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'DNS Client service running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'DNS Client Service'
    } else {
        $evidence = "DNS Client service not running (Status: {0}; StartType: {1})." -f $service.Status, $service.StartMode
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'DNS Client service offline — name resolution will break' -Evidence $evidence -Subcategory 'DNS Client Service' -Remediation $script:CriticalServiceAutostartRemediation
    }
}

function Invoke-ServiceCheckNetworkLocation {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [bool]$IsWorkstation
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating Network Location Awareness service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'NlaSvc'
    if (-not $service.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Network Location Awareness service missing' -Evidence 'Service entry not found; network profile detection will fail.' -Subcategory 'Network Location Awareness' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'Network Location Awareness running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Network Location Awareness'
        return
    }

    $evidence = "Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode
    if ($service.StartModeNormalized -eq 'manual' -and $IsWorkstation) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Network Location Awareness set to Manual and stopped' -Evidence $evidence -Subcategory 'Network Location Awareness' -Remediation $script:CriticalServiceAutostartRemediation
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Network Location Awareness service not running' -Evidence $evidence -Subcategory 'Network Location Awareness' -Remediation $script:CriticalServiceAutostartRemediation
    }
}

function Invoke-ServiceCheckWorkstation {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating Workstation service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'LanmanWorkstation'
    if (-not $service.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Workstation (LanmanWorkstation) service missing' -Evidence 'Service entry not found; SMB client functionality unavailable.' -Subcategory 'Workstation Service' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'Workstation service running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Workstation Service'
        return
    }

    $evidence = "Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode
    $title = if ($service.StartModeNormalized -eq 'disabled') { 'Workstation service disabled — SMB connectivity broken' } else { 'Workstation service stopped — SMB connectivity broken' }
    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title $title -Evidence $evidence -Subcategory 'Workstation Service' -Remediation $script:CriticalServiceAutostartRemediation
}

function Invoke-ServiceCheckPrintSpooler {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [bool]$IsWorkstation
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating Print Spooler service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'Spooler'
    if (-not $service.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Print Spooler service missing' -Evidence 'Service entry not found; printing features unavailable.' -Subcategory 'Print Spooler Service' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        if ($IsWorkstation) {
            $title = 'Print Spooler running — disable if this workstation does not require printing (PrintNightmare risk).'
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title $title -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Print Spooler Service' -Remediation $script:WorkstationSpoolerDisableRemediation
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'Print Spooler running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Print Spooler Service'
        }
        return
    }

    $note = if ($IsWorkstation) { 'PrintNightmare guidance: disable spooler unless required.' } else { 'Printing functionality will be unavailable while stopped.' }
    $evidence = "Status: {0}; StartType: {1}; Note: {2}" -f $service.Status, $service.StartMode, $note
    Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Print Spooler not running' -Evidence $evidence -Subcategory 'Print Spooler Service' -Remediation $script:CriticalServiceAutostartRemediation
}

function Invoke-ServiceCheckRpc {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating RPC services'

    $rpc = Get-ServiceStateInfo -Lookup $Lookup -Name 'RpcSs'
    if (-not $rpc.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC (RpcSs) service missing' -Evidence 'Service entry not found; Windows cannot operate without RPC.' -Subcategory 'RPC Services' -Remediation $script:CriticalServiceAutostartRemediation
    } elseif ($rpc.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'RPC (RpcSs) service running' -Evidence ("Status: {0}; StartType: {1}" -f $rpc.Status, $rpc.StartMode) -Subcategory 'RPC Services'
    } else {
        $evidence = "Status: {0}; StartType: {1}" -f $rpc.Status, $rpc.StartMode
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC (RpcSs) service not running — system instability expected' -Evidence $evidence -Subcategory 'RPC Services' -Remediation $script:CriticalServiceAutostartRemediation
    }

    $mapper = Get-ServiceStateInfo -Lookup $Lookup -Name 'RpcEptMapper'
    if (-not $mapper.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC Endpoint Mapper service missing' -Evidence 'Service entry not found; RPC endpoint resolution unavailable.' -Subcategory 'RPC Services' -Remediation $script:CriticalServiceAutostartRemediation
    } elseif ($mapper.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'RPC Endpoint Mapper running' -Evidence ("Status: {0}; StartType: {1}" -f $mapper.Status, $mapper.StartMode) -Subcategory 'RPC Services'
    } else {
        $evidence = "Status: {0}; StartType: {1}" -f $mapper.Status, $mapper.StartMode
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC Endpoint Mapper not running — RPC clients will fail' -Evidence $evidence -Subcategory 'RPC Services' -Remediation $script:CriticalServiceAutostartRemediation
    }
}

function Invoke-ServiceCheckWinHttpAutoProxy {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [Parameter(Mandatory)]$ProxyInfo
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating WinHTTP Auto Proxy service' -Data ([ordered]@{
        HasProxy = $ProxyInfo.HasSystemProxy
    })

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'WinHttpAutoProxySvc'
    if (-not $service.Exists) {
        if ($ProxyInfo.HasSystemProxy) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'WinHTTP Auto Proxy service missing while a proxy is configured' -Evidence $ProxyInfo.Evidence -Subcategory 'WinHTTP Auto Proxy Service' -Remediation $script:CriticalServiceAutostartRemediation
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'WinHTTP Auto Proxy service missing' -Subcategory 'WinHTTP Auto Proxy Service' -Remediation $script:CriticalServiceAutostartRemediation
        }
        return
    }

    $evidence = "Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode
    if ($service.StatusNormalized -eq 'running') {
        if ($service.StartModeNormalized -eq 'manual' -and -not $ProxyInfo.HasSystemProxy) {
            $evidence = "{0}; Manual trigger start with no system proxy configured." -f $evidence
        }
        Add-CategoryNormal -CategoryResult $Result -Title 'WinHTTP Auto Proxy service running' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
        return
    }

    if ($ProxyInfo.Evidence) {
        $evidence = "{0}`nProxy: {1}" -f $evidence, $ProxyInfo.Evidence
    }

    if ($service.StartModeNormalized -eq 'manual') {
        if ($ProxyInfo.HasSystemProxy) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'WinHTTP Auto Proxy manual start while a proxy is configured' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service' -Remediation $script:CriticalServiceAutostartRemediation
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'WinHTTP Auto Proxy in manual mode with no proxy configured' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
        }
    } elseif ($service.StartModeNormalized -in @('automatic','automatic-delayed')) {
        $severity = if ($ProxyInfo.HasSystemProxy) { 'high' } else { 'medium' }
        Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'WinHTTP Auto Proxy service not running' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service' -Remediation $script:CriticalServiceAutostartRemediation
    } elseif ($service.StartModeNormalized -eq 'disabled') {
        if ($ProxyInfo.HasSystemProxy) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'WinHTTP Auto Proxy disabled while a proxy is configured' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service' -Remediation $script:CriticalServiceAutostartRemediation
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'WinHTTP Auto Proxy disabled' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service' -Remediation $script:CriticalServiceAutostartRemediation
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'WinHTTP Auto Proxy service in unexpected state' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service' -Remediation $script:CriticalServiceAutostartRemediation
    }
}

function Invoke-ServiceCheckBits {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [bool]$IsWorkstation,
        $BitsInfo
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating BITS service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'BITS'
    if (-not $service.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'BITS service is missing, so Windows Update and other background downloads cannot run.' -Evidence 'Service entry not found; background transfers cannot occur.' -Subcategory 'BITS Service' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    $bitsSummary = if ($BitsInfo) { $BitsInfo } else { $null }
    $hasTransferData = $false
    $totalJobs = 0
    $activeJobs = 0
    $errorJobs = 0
    $transientErrors = 0
    $errorDetails = @()
    $activeDetails = @()
    $transferEvidence = $null

    if ($bitsSummary) {
        if ($bitsSummary.PSObject.Properties['HasData']) { $hasTransferData = [bool]$bitsSummary.HasData }
        if ($bitsSummary.PSObject.Properties['TotalJobs']) { try { $totalJobs = [int]$bitsSummary.TotalJobs } catch { $totalJobs = 0 } }
        if ($bitsSummary.PSObject.Properties['ActiveJobs']) { try { $activeJobs = [int]$bitsSummary.ActiveJobs } catch { $activeJobs = 0 } }
        if ($bitsSummary.PSObject.Properties['ErrorJobs']) { try { $errorJobs = [int]$bitsSummary.ErrorJobs } catch { $errorJobs = 0 } }
        if ($bitsSummary.PSObject.Properties['TransientErrorJobs']) { try { $transientErrors = [int]$bitsSummary.TransientErrorJobs } catch { $transientErrors = 0 } }
        if ($bitsSummary.PSObject.Properties['Evidence'] -and $bitsSummary.Evidence) { $transferEvidence = [string]$bitsSummary.Evidence }
        if ($bitsSummary.PSObject.Properties['ErrorDetails'] -and $bitsSummary.ErrorDetails) { $errorDetails = @($bitsSummary.ErrorDetails | Where-Object { $_ }) }
        if ($bitsSummary.PSObject.Properties['ActiveDetails'] -and $bitsSummary.ActiveDetails) { $activeDetails = @($bitsSummary.ActiveDetails | Where-Object { $_ }) }
    }

    Write-HeuristicDebug -Source 'Services/Check' -Message 'BITS transfer summary' -Data ([ordered]@{
        HasData          = $hasTransferData
        TotalJobs        = $totalJobs
        ActiveJobs       = $activeJobs
        ErrorJobs        = $errorJobs
        TransientErrors  = $transientErrors
    })

    $evidenceLines = New-Object System.Collections.Generic.List[string]
    $evidenceLines.Add(("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode)) | Out-Null
    if ($transferEvidence) {
        $evidenceLines.Add(("Transfers: {0}" -f $transferEvidence)) | Out-Null
    } elseif ($hasTransferData) {
        $evidenceLines.Add(("Transfers: Jobs={0}" -f $totalJobs)) | Out-Null
    }

    if ($errorDetails -and $errorDetails.Count -gt 0) {
        $evidenceLines.Add(("Error jobs: {0}" -f ($errorDetails -join '; '))) | Out-Null
    }

    if ($activeDetails -and $activeDetails.Count -gt 0) {
        $evidenceLines.Add(("Active jobs: {0}" -f ($activeDetails -join '; '))) | Out-Null
    }

    $evidence = $evidenceLines -join "`n"
    $pendingJobs = $activeJobs + $errorJobs

    if ($service.StartModeNormalized -eq 'disabled') {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'BITS service is disabled, so Windows Update, Store, and Intune downloads cannot transfer.' -Evidence $evidence -Subcategory 'BITS Service' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    if ($service.StatusNormalized -ne 'running' -and $pendingJobs -gt 0) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'BITS is stopped while background jobs are queued, so Windows downloads stay stuck.' -Evidence $evidence -Subcategory 'BITS Service' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    if ($service.StartModeNormalized -in @('automatic','automatic-delayed') -and $service.StatusNormalized -ne 'running') {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'BITS is set to start automatically but is not running, so background downloads are stalled.' -Evidence $evidence -Subcategory 'BITS Service' -Remediation $script:CriticalServiceAutostartRemediation
        return
    }

    if ($errorJobs -gt 0) {
        $severity = if ($service.StartModeNormalized -eq 'manual') { 'medium' } else { 'high' }
        Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'BITS jobs are failing, so Windows Update and other downloads are erroring out.' -Evidence $evidence -Subcategory 'BITS Service' -Remediation $script:BitsJobFailureRemediation
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'BITS service is running, so background downloads can proceed.' -Evidence $evidence -Subcategory 'BITS Service'
        return
    }

    if ($service.StartModeNormalized -eq 'manual') {
        if ($hasTransferData -and $pendingJobs -eq 0 -and $errorJobs -eq 0) {
            Add-CategoryNormal -CategoryResult $Result -Title 'BITS uses manual trigger start and is idle with no stuck jobs.' -Evidence $evidence -Subcategory 'BITS Service'
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'BITS uses manual trigger start and will run when background downloads are requested.' -Evidence $evidence -Subcategory 'BITS Service'
        }
        return
    }

    Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'BITS service is in an unexpected state, so background downloads may misbehave.' -Evidence $evidence -Subcategory 'BITS Service' -Remediation $script:CriticalServiceAutostartRemediation
}

function Invoke-ServiceCheckOfficeClickToRun {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [bool]$IsWorkstation
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating Office Click-to-Run service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'ClickToRunSvc'
    if (-not $service.Exists) {
        return
    }

    $evidence = "Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode
    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'Office Click-to-Run service running' -Evidence $evidence -Subcategory 'Office Click-to-Run'
    }

    if ($service.StartModeNormalized -in @('automatic','automatic-delayed')) {
        if ($service.StatusNormalized -ne 'running') {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Office Click-to-Run automatic but not running' -Evidence $evidence -Subcategory 'Office Click-to-Run'
        }
    } elseif ($service.StartModeNormalized -in @('manual','disabled')) {
        if ($IsWorkstation) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Office Click-to-Run not set to automatic on workstation' -Evidence $evidence -Subcategory 'Office Click-to-Run'
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Office Click-to-Run manual/disabled on server' -Evidence $evidence -Subcategory 'Office Click-to-Run'
        }
    }
}

function Invoke-ServiceCheckAutomaticInventory {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Services
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating automatic service inventory' -Data ([ordered]@{
        ServiceCount = $Services.Count
    })

    $stoppedAuto = $Services | Where-Object {
        $startNormalized = if ($_.PSObject.Properties['StartModeNormalized']) {
            $_.StartModeNormalized
        } elseif ($_.PSObject.Properties['NormalizedStartType']) {
            $_.NormalizedStartType
        } else {
            Normalize-ServiceStartValue -Value $_.StartMode
        }

        $statusNormalized = if ($_.PSObject.Properties['StatusNormalized']) {
            $_.StatusNormalized
        } elseif ($_.PSObject.Properties['NormalizedStatus']) {
            $_.NormalizedStatus
        } else {
            Normalize-ServiceStateValue -Value $_.Status
        }

        ($startNormalized -in @('automatic','automatic-delayed')) -and ($statusNormalized -ne 'running')
    }

    if ($stoppedAuto.Count -gt 0) {
        $failedServices = $stoppedAuto
        $topStoppedAuto = $failedServices | Select-Object -First 5
        $summary = [System.Collections.Generic.List[string]]::new()
        foreach ($service in $topStoppedAuto) {
            $serviceState = if ($service.State) { $service.State } elseif ($service.Status) { $service.Status } else { 'Unknown' }
            $startMode = if ($service.StartType) { $service.StartType } elseif ($service.StartMode) { $service.StartMode } else { 'Unknown' }
            $null = $summary.Add(("{0} ({1}; StartType={2})" -f $service.DisplayName, $serviceState, $startMode))
        }

        $serviceDataProjection = $failedServices | Select-Object `
            @{ Name = 'Name'; Expression = {
                    if ($_.PSObject.Properties['Name']) { $_.Name }
                    elseif ($_.PSObject.Properties['ServiceName']) { $_.ServiceName }
                    else { $null }
                } },
            @{ Name = 'DisplayName'; Expression = {
                    if ($_.PSObject.Properties['DisplayName']) { $_.DisplayName }
                    else { $null }
                } },
            @{ Name = 'Status'; Expression = {
                    if ($_.PSObject.Properties['Status']) { $_.Status }
                    elseif ($_.PSObject.Properties['State']) { $_.State }
                    else { $null }
                } },
            @{ Name = 'StartType'; Expression = {
                    if ($_.PSObject.Properties['StartType']) { $_.StartType }
                    elseif ($_.PSObject.Properties['StartMode']) { $_.StartMode }
                    else { $null }
                } },
            @{ Name = 'StartName'; Expression = {
                    if ($_.PSObject.Properties['StartName']) { $_.StartName }
                    elseif ($_.PSObject.Properties['LogOnAs']) { $_.LogOnAs }
                    else { $null }
                } },
            @{ Name = 'LastExitCode'; Expression = {
                    if ($_.PSObject.Properties['LastExitCode']) { $_.LastExitCode }
                    elseif ($_.PSObject.Properties['ExitCode']) { $_.ExitCode }
                    else { $null }
                } }

        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Automatic services not running, indicating outages in critical services.' -Evidence ($summary -join "`n") -Subcategory 'Service Inventory' -Data @{
            Area = 'Services'
            Kind = 'ServiceHealth'
            Services = $serviceDataProjection
        }
    } else {
        Add-CategoryNormal -CategoryResult $Result -Title 'Automatic services running' -Subcategory 'Service Inventory'
    }
}
