function Invoke-ServiceCheckWindowsSearch {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [bool]$IsWorkstation,
        [bool]$IsServer
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating Windows Search service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'WSearch'
    if (-not $service.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Windows Search service missing' -Evidence 'Service entry not found; search and Outlook indexing will fail.' -Subcategory 'Windows Search Service'
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'Windows Search service running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Windows Search Service'
        return
    }

    $title = "Windows Search service not running (Status: {0}; StartType: {1})." -f $service.Status, $service.StartMode
    if ($service.StartModeNormalized -eq 'manual') {
        if ($IsWorkstation) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Windows Search set to Manual and stopped' -Evidence $title -Subcategory 'Windows Search Service'
        } elseif ($IsServer) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Windows Search manual start and currently stopped' -Evidence $title -Subcategory 'Windows Search Service'
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Windows Search manual start and currently stopped' -Evidence $title -Subcategory 'Windows Search Service'
        }
    } elseif ($service.StartModeNormalized -eq 'disabled') {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Windows Search disabled' -Evidence $title -Subcategory 'Windows Search Service'
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Windows Search not running' -Evidence $title -Subcategory 'Windows Search Service'
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
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'DNS Client (Dnscache) service missing' -Evidence 'Service entry not found; DNS resolution will fail.' -Subcategory 'DNS Client Service'
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'DNS Client service running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'DNS Client Service'
    } else {
        $evidence = "DNS Client service not running (Status: {0}; StartType: {1})." -f $service.Status, $service.StartMode
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'DNS Client service offline — name resolution will break' -Evidence $evidence -Subcategory 'DNS Client Service'
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
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Network Location Awareness service missing' -Evidence 'Service entry not found; network profile detection will fail.' -Subcategory 'Network Location Awareness'
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'Network Location Awareness running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Network Location Awareness'
        return
    }

    $evidence = "Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode
    if ($service.StartModeNormalized -eq 'manual' -and $IsWorkstation) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Network Location Awareness set to Manual and stopped' -Evidence $evidence -Subcategory 'Network Location Awareness'
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Network Location Awareness service not running' -Evidence $evidence -Subcategory 'Network Location Awareness'
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
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Workstation (LanmanWorkstation) service missing' -Evidence 'Service entry not found; SMB client functionality unavailable.' -Subcategory 'Workstation Service'
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'Workstation service running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Workstation Service'
        return
    }

    $evidence = "Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode
    $title = if ($service.StartModeNormalized -eq 'disabled') { 'Workstation service disabled — SMB connectivity broken' } else { 'Workstation service stopped — SMB connectivity broken' }
    Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title $title -Evidence $evidence -Subcategory 'Workstation Service'
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
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Print Spooler service missing' -Evidence 'Service entry not found; printing features unavailable.' -Subcategory 'Print Spooler Service'
        return
    }

    if ($service.StatusNormalized -eq 'running') {
        if ($IsWorkstation) {
            $title = 'Print Spooler running — disable if this workstation does not require printing (PrintNightmare risk).'
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title $title -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Print Spooler Service'
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'Print Spooler running' -Evidence ("Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode) -Subcategory 'Print Spooler Service'
        }
        return
    }

    $note = if ($IsWorkstation) { 'PrintNightmare guidance: disable spooler unless required.' } else { 'Printing functionality will be unavailable while stopped.' }
    $evidence = "Status: {0}; StartType: {1}; Note: {2}" -f $service.Status, $service.StartMode, $note
    Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Print Spooler not running' -Evidence $evidence -Subcategory 'Print Spooler Service'
}

function Invoke-ServiceCheckRpc {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating RPC services'

    $rpc = Get-ServiceStateInfo -Lookup $Lookup -Name 'RpcSs'
    if (-not $rpc.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC (RpcSs) service missing' -Evidence 'Service entry not found; Windows cannot operate without RPC.' -Subcategory 'RPC Services'
    } elseif ($rpc.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'RPC (RpcSs) service running' -Evidence ("Status: {0}; StartType: {1}" -f $rpc.Status, $rpc.StartMode) -Subcategory 'RPC Services'
    } else {
        $evidence = "Status: {0}; StartType: {1}" -f $rpc.Status, $rpc.StartMode
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC (RpcSs) service not running — system instability expected' -Evidence $evidence -Subcategory 'RPC Services'
    }

    $mapper = Get-ServiceStateInfo -Lookup $Lookup -Name 'RpcEptMapper'
    if (-not $mapper.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC Endpoint Mapper service missing' -Evidence 'Service entry not found; RPC endpoint resolution unavailable.' -Subcategory 'RPC Services'
    } elseif ($mapper.StatusNormalized -eq 'running') {
        Add-CategoryNormal -CategoryResult $Result -Title 'RPC Endpoint Mapper running' -Evidence ("Status: {0}; StartType: {1}" -f $mapper.Status, $mapper.StartMode) -Subcategory 'RPC Services'
    } else {
        $evidence = "Status: {0}; StartType: {1}" -f $mapper.Status, $mapper.StartMode
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'RPC Endpoint Mapper not running — RPC clients will fail' -Evidence $evidence -Subcategory 'RPC Services'
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
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'WinHTTP Auto Proxy service missing while a proxy is configured' -Evidence $ProxyInfo.Evidence -Subcategory 'WinHTTP Auto Proxy Service'
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'WinHTTP Auto Proxy service missing' -Subcategory 'WinHTTP Auto Proxy Service'
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
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'WinHTTP Auto Proxy manual start while a proxy is configured' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'WinHTTP Auto Proxy in manual mode with no proxy configured' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
        }
    } elseif ($service.StartModeNormalized -in @('automatic','automatic-delayed')) {
        $severity = if ($ProxyInfo.HasSystemProxy) { 'high' } else { 'medium' }
        Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title 'WinHTTP Auto Proxy service not running' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
    } elseif ($service.StartModeNormalized -eq 'disabled') {
        if ($ProxyInfo.HasSystemProxy) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'WinHTTP Auto Proxy disabled while a proxy is configured' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'WinHTTP Auto Proxy disabled' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'WinHTTP Auto Proxy service in unexpected state' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
    }
}

function Invoke-ServiceCheckBits {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Lookup,
        [bool]$IsWorkstation
    )

    Write-HeuristicDebug -Source 'Services/Check' -Message 'Evaluating BITS service'

    $service = Get-ServiceStateInfo -Lookup $Lookup -Name 'BITS'
    if (-not $service.Exists) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'BITS service missing' -Evidence 'Background transfers for Windows Update, AV, and Office will fail.' -Subcategory 'BITS Service'
        return
    }

    $evidence = "Status: {0}; StartType: {1}" -f $service.Status, $service.StartMode
    if ($service.StatusNormalized -eq 'running' -and $service.StartModeNormalized -notin @('manual','disabled')) {
        Add-CategoryNormal -CategoryResult $Result -Title 'BITS running' -Evidence $evidence -Subcategory 'BITS Service'
    }

    if ($service.StartModeNormalized -eq 'disabled') {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'BITS disabled — background transfers stopped' -Evidence $evidence -Subcategory 'BITS Service'
    } elseif ($service.StartModeNormalized -in @('automatic','automatic-delayed')) {
        if ($service.StatusNormalized -ne 'running') {
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'BITS automatic but not running' -Evidence $evidence -Subcategory 'BITS Service'
        }
    } elseif ($service.StartModeNormalized -eq 'manual') {
        if ($IsWorkstation) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'BITS configured for manual start on workstation' -Evidence $evidence -Subcategory 'BITS Service'
        } elseif ($service.StatusNormalized -ne 'running') {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'BITS manual start and currently stopped' -Evidence $evidence -Subcategory 'BITS Service'
        }
    }
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
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Office Click-to-Run manual/disabled on server' -Evidence $evidence -Subcategory 'Office Click-to-Run'
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
        $topStoppedAuto = $stoppedAuto | Select-Object -First 5
        $summary = [System.Collections.Generic.List[string]]::new()
        foreach ($service in $topStoppedAuto) {
            $serviceState = if ($service.State) { $service.State } elseif ($service.Status) { $service.Status } else { 'Unknown' }
            $startMode = if ($service.StartType) { $service.StartType } elseif ($service.StartMode) { $service.StartMode } else { 'Unknown' }
            $null = $summary.Add(("{0} ({1}; StartType={2})" -f $service.DisplayName, $serviceState, $startMode))
        }

        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Automatic services not running' -Evidence ($summary -join "`n") -Subcategory 'Service Inventory'
    } else {
        Add-CategoryNormal -CategoryResult $Result -Title 'Automatic services running'
    }
}
